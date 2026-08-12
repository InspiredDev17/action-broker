use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Method, Url, redirect};
use serde::{Deserialize, Serialize};

use crate::capability::{HttpMethod, HttpRequestInput, HttpRequestOutput};
use crate::command::CancellationToken;
use crate::error::{BrokerError, BrokerResult, ErrorCode};

const MAX_DNS_ANSWERS: usize = 16;
const ABSOLUTE_MAX_RESPONSE_BYTES: u64 = 512 * 1024;
const ABSOLUTE_MAX_REQUEST_BYTES: usize = 512 * 1024;
const ABSOLUTE_MAX_TIMEOUT_MILLISECONDS: u64 = 60_000;
const ABSOLUTE_MAX_REDIRECTS: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationRule {
    /// Exact canonical host. Wildcards and suffix matching are intentionally
    /// absent so `example.com.attacker.invalid` can never inherit a grant.
    pub host: String,
    pub schemes: BTreeSet<String>,
    pub ports: BTreeSet<u16>,
    #[serde(default)]
    pub allow_private_addresses: bool,
    #[serde(default)]
    pub allow_loopback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyConfig {
    pub destinations: Vec<DestinationRule>,
    #[serde(default = "default_request_headers")]
    pub allowed_request_headers: BTreeSet<String>,
    #[serde(default = "default_response_headers")]
    pub returned_response_headers: BTreeSet<String>,
    #[serde(default = "default_redirects")]
    pub maximum_redirects: u8,
}

fn default_request_headers() -> BTreeSet<String> {
    BTreeSet::from([
        "accept".to_owned(),
        "content-type".to_owned(),
        "if-match".to_owned(),
        "if-none-match".to_owned(),
        "user-agent".to_owned(),
    ])
}

fn default_response_headers() -> BTreeSet<String> {
    BTreeSet::from([
        "cache-control".to_owned(),
        "content-length".to_owned(),
        "content-type".to_owned(),
        "etag".to_owned(),
        "last-modified".to_owned(),
    ])
}

const fn default_redirects() -> u8 {
    3
}

pub trait DnsResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16, timeout: Duration) -> BrokerResult<Vec<SocketAddr>>;
}

pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16, timeout: Duration) -> BrokerResult<Vec<SocketAddr>> {
        let host = host.to_owned();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.take(MAX_DNS_ANSWERS + 1).collect::<Vec<_>>());
            let _ = sender.send(result);
        });
        let mut addresses = receiver
            .recv_timeout(timeout)
            .map_err(|_| forbidden_destination("DNS resolution timed out"))?
            .map_err(|_| forbidden_destination("DNS resolution failed"))?;
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() || addresses.len() > MAX_DNS_ANSWERS {
            return Err(forbidden_destination(
                "DNS answer count is outside the safe bound",
            ));
        }
        Ok(addresses)
    }
}

#[derive(Debug)]
struct ValidatedDestination {
    url: Url,
    host: String,
    addresses: Vec<SocketAddr>,
}

pub struct SecureHttpClient {
    policy: NetworkPolicyConfig,
    resolver: Arc<dyn DnsResolver>,
}

impl SecureHttpClient {
    pub fn new(policy: NetworkPolicyConfig) -> BrokerResult<Self> {
        Self::with_resolver(policy, Arc::new(SystemDnsResolver))
    }

    pub fn with_resolver(
        mut policy: NetworkPolicyConfig,
        resolver: Arc<dyn DnsResolver>,
    ) -> BrokerResult<Self> {
        if policy.destinations.is_empty() {
            return Err(BrokerError::invalid(
                "network policy requires at least one exact destination",
            ));
        }
        if policy.maximum_redirects > ABSOLUTE_MAX_REDIRECTS {
            return Err(BrokerError::invalid("redirect limit is too large"));
        }
        normalize_header_allowlist(
            &mut policy.allowed_request_headers,
            is_forbidden_request_header,
        )?;
        normalize_header_allowlist(
            &mut policy.returned_response_headers,
            is_forbidden_response_header,
        )?;
        for destination in &mut policy.destinations {
            destination.host = canonical_policy_host(&destination.host)?;
            if destination.ports.is_empty() || destination.schemes.is_empty() {
                return Err(BrokerError::invalid(
                    "destination scheme and port allowlists cannot be empty",
                ));
            }
            for scheme in &destination.schemes {
                if scheme != "http" && scheme != "https" {
                    return Err(BrokerError::invalid(
                        "only http and https destination schemes are supported",
                    ));
                }
            }
        }
        Ok(Self { policy, resolver })
    }

    pub fn execute(
        &self,
        input: &HttpRequestInput,
        cancellation: &CancellationToken,
    ) -> BrokerResult<HttpRequestOutput> {
        let maximum_response_bytes = input.maximum_response_bytes;
        if maximum_response_bytes == 0 || maximum_response_bytes > ABSOLUTE_MAX_RESPONSE_BYTES {
            return Err(BrokerError::invalid(
                "maximum response size is outside the safe bound",
            ));
        }
        let timeout_milliseconds = input.timeout_milliseconds.unwrap_or(10_000);
        if timeout_milliseconds == 0 || timeout_milliseconds > ABSOLUTE_MAX_TIMEOUT_MILLISECONDS {
            return Err(BrokerError::invalid(
                "HTTP timeout is outside the safe bound",
            ));
        }
        let body = decode_optional_body(input.body_base64.as_deref())?;
        let headers = self.validate_request_headers(&input.headers)?;
        let method = method(input.method);
        let deadline = Instant::now() + Duration::from_millis(timeout_milliseconds);
        let mut current_url =
            Url::parse(&input.url).map_err(|_| forbidden_destination("request URL is invalid"))?;
        let mut contacted = Vec::new();

        for redirect_count in 0..=self.policy.maximum_redirects {
            if cancellation.is_cancelled() {
                return Err(BrokerError::new(
                    ErrorCode::Cancelled,
                    "HTTP action was cancelled",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(BrokerError::new(
                    ErrorCode::Timeout,
                    "HTTP action exceeded its total timeout",
                ));
            }
            let destination = self.validate_destination(current_url, remaining)?;
            contacted.push(format_destination(&destination.url)?);
            let client = build_pinned_client(&destination.host, &destination.addresses, remaining)?;
            let mut request = client
                .request(method.clone(), destination.url.clone())
                .headers(headers.clone())
                .timeout(remaining);
            if let Some(bytes) = body.as_ref() {
                request = request.body(bytes.clone());
            }
            let mut response = request.send().map_err(|error| map_request_error(&error))?;

            if response.status().is_redirection() {
                if !matches!(input.method, HttpMethod::Get | HttpMethod::Head) {
                    return Err(forbidden_destination(
                        "redirects for side-effecting HTTP methods are denied",
                    ));
                }
                if redirect_count == self.policy.maximum_redirects {
                    return Err(forbidden_destination("redirect limit exceeded"));
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| forbidden_destination("redirect has no location"))?
                    .to_str()
                    .map_err(|_| forbidden_destination("redirect location is invalid"))?;
                current_url = destination
                    .url
                    .join(location)
                    .map_err(|_| forbidden_destination("redirect location is invalid"))?;
                continue;
            }

            let status_code = response.status().as_u16();
            let returned_headers = self.filter_response_headers(response.headers());
            let (response_body, truncated) = read_bounded(&mut response, maximum_response_bytes)?;
            return Ok(HttpRequestOutput {
                final_url: destination.url.to_string(),
                status_code,
                headers: returned_headers,
                body_base64: base64::engine::general_purpose::STANDARD.encode(response_body),
                truncated,
                contacted_destinations: contacted,
            });
        }

        Err(forbidden_destination("redirect limit exceeded"))
    }

    fn validate_destination(
        &self,
        mut url: Url,
        timeout: Duration,
    ) -> BrokerResult<ValidatedDestination> {
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(forbidden_destination(
                "URL credentials and fragments are forbidden",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| forbidden_destination("URL host is required"))?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| forbidden_destination("URL port is required"))?;
        let rule = self
            .policy
            .destinations
            .iter()
            .find(|rule| {
                rule.host == host
                    && rule.schemes.contains(url.scheme())
                    && rule.ports.contains(&port)
            })
            .ok_or_else(|| forbidden_destination("destination is not allowlisted"))?;

        // Normalize the implicit port before pinning and auditing.
        if url.port().is_none() {
            url.set_port(Some(port))
                .map_err(|()| forbidden_destination("URL port cannot be normalized"))?;
        }
        let mut addresses = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            self.resolver.resolve(&host, port, timeout)?
        };
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() || addresses.len() > MAX_DNS_ANSWERS {
            return Err(forbidden_destination(
                "DNS answer count is outside the safe bound",
            ));
        }
        // Every answer must pass. Accepting one public address beside a private
        // answer would permit resolver-order or rebinding bypasses.
        for address in &addresses {
            validate_ip(address.ip(), rule)?;
        }
        Ok(ValidatedDestination {
            url,
            host,
            addresses,
        })
    }

    fn validate_request_headers(
        &self,
        headers: &BTreeMap<String, String>,
    ) -> BrokerResult<HeaderMap> {
        let mut validated = HeaderMap::new();
        for (name, value) in headers {
            let normalized = name.to_ascii_lowercase();
            if is_forbidden_request_header(&normalized)
                || !self.policy.allowed_request_headers.contains(&normalized)
            {
                return Err(BrokerError::invalid("HTTP request header is not allowed"));
            }
            let header_name = HeaderName::from_bytes(normalized.as_bytes())
                .map_err(|_| BrokerError::invalid("HTTP request header name is invalid"))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|_| BrokerError::invalid("HTTP request header value is invalid"))?;
            validated.insert(header_name, header_value);
        }
        Ok(validated)
    }

    fn filter_response_headers(&self, headers: &HeaderMap) -> BTreeMap<String, String> {
        let mut filtered = BTreeMap::new();
        for name in &self.policy.returned_response_headers {
            if let Some(value) = headers.get(name)
                && let Ok(value) = value.to_str()
            {
                filtered.insert(name.clone(), value.to_owned());
            }
        }
        filtered
    }
}

fn build_pinned_client(
    host: &str,
    addresses: &[SocketAddr],
    timeout: Duration,
) -> BrokerResult<Client> {
    Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .resolve_to_addrs(host, addresses)
        .build()
        .map_err(|_| BrokerError::new(ErrorCode::ExecutionFailure, "HTTP client setup failed"))
}

fn decode_optional_body(body: Option<&str>) -> BrokerResult<Option<Vec<u8>>> {
    let Some(body) = body else {
        return Ok(None);
    };
    if body.len()
        > ABSOLUTE_MAX_REQUEST_BYTES
            .saturating_mul(4)
            .saturating_add(2)
            / 3
            + 4
    {
        return Err(BrokerError::invalid("HTTP request body is too large"));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| BrokerError::invalid("HTTP request body is not canonical base64"))?;
    if decoded.len() > ABSOLUTE_MAX_REQUEST_BYTES
        || base64::engine::general_purpose::STANDARD.encode(&decoded) != body
    {
        return Err(BrokerError::invalid(
            "HTTP request body is not canonical base64",
        ));
    }
    Ok(Some(decoded))
}

fn read_bounded(
    response: &mut reqwest::blocking::Response,
    maximum_bytes: u64,
) -> BrokerResult<(Vec<u8>, bool)> {
    let mut bytes = Vec::with_capacity(usize::try_from(maximum_bytes.min(64 * 1024)).unwrap_or(0));
    response
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BrokerError::new(ErrorCode::ExecutionFailure, "HTTP response read failed"))?;
    let truncated = bytes.len() as u64 > maximum_bytes;
    if truncated {
        bytes.truncate(usize::try_from(maximum_bytes).map_err(|_| BrokerError::internal())?);
    }
    Ok((bytes, truncated))
}

const fn method(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
    }
}

fn format_destination(url: &Url) -> BrokerResult<String> {
    let host = url
        .host_str()
        .ok_or_else(|| forbidden_destination("URL host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| forbidden_destination("URL port is required"))?;
    Ok(format!("{}://{host}:{port}", url.scheme()))
}

fn normalize_header_allowlist(
    headers: &mut BTreeSet<String>,
    is_forbidden: fn(&str) -> bool,
) -> BrokerResult<()> {
    let mut normalized = BTreeSet::new();
    for header in &*headers {
        let name = header.to_ascii_lowercase();
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| BrokerError::invalid("header allowlist contains an invalid name"))?;
        if is_forbidden(&name) {
            return Err(BrokerError::invalid(
                "header allowlist contains a security-sensitive header",
            ));
        }
        normalized.insert(name);
    }
    *headers = normalized;
    Ok(())
}

fn canonical_policy_host(host: &str) -> BrokerResult<String> {
    if host.is_empty() || host.len() > 253 || host.contains(['/', '\\', '@', '#', '?']) {
        return Err(BrokerError::invalid("destination host is invalid"));
    }
    let probe = Url::parse(&format!("https://{host}/"))
        .map_err(|_| BrokerError::invalid("destination host is invalid"))?;
    let canonical = probe
        .host_str()
        .ok_or_else(|| BrokerError::invalid("destination host is invalid"))?
        .to_ascii_lowercase();
    if canonical != host.to_ascii_lowercase() {
        return Err(BrokerError::invalid(
            "destination host must use canonical URL form",
        ));
    }
    Ok(canonical)
}

fn is_forbidden_request_header(header: &str) -> bool {
    matches!(
        header,
        "authorization"
            | "cookie"
            | "host"
            | "connection"
            | "content-length"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_forbidden_response_header(header: &str) -> bool {
    matches!(
        header,
        "authorization"
            | "cookie"
            | "set-cookie"
            | "proxy-authenticate"
            | "connection"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn validate_ip(ip: IpAddr, rule: &DestinationRule) -> BrokerResult<()> {
    if is_metadata_address(ip) {
        return Err(forbidden_destination(
            "cloud metadata destinations are always forbidden",
        ));
    }
    if ip.is_loopback() && !rule.allow_loopback {
        return Err(forbidden_destination("loopback destination is forbidden"));
    }
    if is_non_public(ip) && !ip.is_loopback() && !rule.allow_private_addresses {
        return Err(forbidden_destination(
            "private or special-use destination is forbidden",
        ));
    }
    Ok(())
}

fn is_metadata_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 100 && octets[1] == 100 && octets[2] == 100 && octets[3] == 200)
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_metadata_address(IpAddr::V4(mapped));
            }
            if let Some(embedded) = nat64_embedded_ipv4(address) {
                return is_metadata_address(IpAddr::V4(embedded));
            }
            let segments = address.segments();
            segments[0] & 0xffc0 == 0xfe80
        }
    }
}

fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_non_public_v4(address),
        IpAddr::V6(address) => is_non_public_v6(address),
    }
}

const fn is_non_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _d] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && b & 0xc0 == 64)
        || (a == 169 && b == 254)
        || (a == 172 && b & 0xf0 == 16)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

fn is_non_public_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_non_public_v4(mapped);
    }
    if let Some(embedded) = nat64_embedded_ipv4(address) {
        return is_non_public_v4(embedded);
    }
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xff00 == 0xff00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn nat64_embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = address.segments();
    let well_known = segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0];
    let local_use = segments[..6] == [0x0064, 0xff9b, 1, 0, 0, 0];
    if !well_known && !local_use {
        return None;
    }
    let [first, second] = segments[6].to_be_bytes();
    let [third, fourth] = segments[7].to_be_bytes();
    Some(Ipv4Addr::new(first, second, third, fourth))
}

fn map_request_error(error: &reqwest::Error) -> BrokerError {
    if error.is_timeout() {
        BrokerError::new(ErrorCode::Timeout, "HTTP request timed out")
    } else {
        BrokerError::new(ErrorCode::ExecutionFailure, "HTTP request failed")
    }
}

fn forbidden_destination(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::ForbiddenDestination, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedResolver(Vec<SocketAddr>);

    impl DnsResolver for FixedResolver {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
            _timeout: Duration,
        ) -> BrokerResult<Vec<SocketAddr>> {
            Ok(self.0.clone())
        }
    }

    fn policy() -> NetworkPolicyConfig {
        NetworkPolicyConfig {
            destinations: vec![DestinationRule {
                host: "api.example.com".to_owned(),
                schemes: BTreeSet::from(["https".to_owned()]),
                ports: BTreeSet::from([443]),
                allow_private_addresses: false,
                allow_loopback: false,
            }],
            allowed_request_headers: default_request_headers(),
            returned_response_headers: default_response_headers(),
            maximum_redirects: 3,
        }
    }

    #[test]
    fn mixed_public_and_private_dns_answers_fail_closed() -> BrokerResult<()> {
        let client = SecureHttpClient::with_resolver(
            policy(),
            Arc::new(FixedResolver(vec![
                SocketAddr::from(([93, 184, 216, 34], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
            ])),
        )?;
        assert!(
            client
                .validate_destination(
                    Url::parse("https://api.example.com/v1").map_err(|_| BrokerError::internal())?,
                    Duration::from_secs(1),
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn metadata_address_is_denied_even_when_private_is_allowed() -> BrokerResult<()> {
        let mut config = policy();
        config.destinations[0].host = "169.254.169.254".to_owned();
        config.destinations[0].allow_private_addresses = true;
        let client = SecureHttpClient::with_resolver(config, Arc::new(FixedResolver(Vec::new())))?;
        assert!(
            client
                .validate_destination(
                    Url::parse("https://169.254.169.254/latest")
                        .map_err(|_| BrokerError::internal())?,
                    Duration::from_secs(1),
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn ipv4_mapped_metadata_and_loopback_are_denied() {
        let metadata = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe));
        let loopback = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1));
        assert!(is_metadata_address(metadata));
        assert!(is_non_public(loopback));
    }

    #[test]
    fn nat64_embedded_metadata_and_loopback_are_denied() {
        let metadata = IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe));
        let loopback = IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0x7f00, 1));
        assert!(is_metadata_address(metadata));
        assert!(is_non_public(loopback));
    }

    #[test]
    fn host_suffix_confusion_is_denied() -> BrokerResult<()> {
        let client = SecureHttpClient::with_resolver(
            policy(),
            Arc::new(FixedResolver(vec![SocketAddr::from((
                [93, 184, 216, 34],
                443,
            ))])),
        )?;
        assert!(
            client
                .validate_destination(
                    Url::parse("https://api.example.com.attacker.invalid/")
                        .map_err(|_| BrokerError::internal())?,
                    Duration::from_secs(1),
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn authorization_header_cannot_be_allowlisted() {
        let mut config = policy();
        config
            .allowed_request_headers
            .insert("Authorization".to_owned());
        assert!(
            SecureHttpClient::with_resolver(config, Arc::new(FixedResolver(Vec::new()))).is_err()
        );
    }
}
