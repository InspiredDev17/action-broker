use std::collections::BTreeSet;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{BrokerError, BrokerResult, ErrorCode};

const MAXIMUM_SUPPLEMENTARY_GROUPS: usize = 16;
#[cfg(target_os = "linux")]
const MAXIMUM_STATUS_BYTES: u64 = 32 * 1024;

/// Exact kernel privilege state required for the broker process. The daemon
/// verifies this at readiness and before every action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePrivilegeProfileConfig {
    pub expected_user_id: u32,
    pub expected_group_id: u32,
    pub allowed_supplementary_group_ids: BTreeSet<u32>,
}

#[derive(Debug, Clone)]
pub struct RuntimePrivilegeMonitor {
    config: RuntimePrivilegeProfileConfig,
}

impl RuntimePrivilegeMonitor {
    /// Constructs a fail-closed privilege monitor from trusted configuration.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error for root IDs, group zero, or an
    /// excessive supplementary-group allowlist.
    pub fn from_config(config: RuntimePrivilegeProfileConfig) -> BrokerResult<Self> {
        if config.expected_user_id == 0
            || config.expected_group_id == 0
            || config.allowed_supplementary_group_ids.contains(&0)
            || config.allowed_supplementary_group_ids.len() > MAXIMUM_SUPPLEMENTARY_GROUPS
        {
            return Err(BrokerError::invalid(
                "broker runtime privilege profile is invalid",
            ));
        }
        Ok(Self { config })
    }

    /// Verifies the current thread's complete Linux identity and active
    /// privilege state against the immutable configured profile.
    ///
    /// # Errors
    ///
    /// Returns `unexpected_privilege_elevation` for any identity, group,
    /// capability, or `NoNewPrivs` mismatch. Missing trustworthy procfs
    /// evidence is a sandbox-unavailable failure.
    pub fn verify(&self) -> BrokerResult<()> {
        #[cfg(target_os = "linux")]
        {
            let observed = read_current_status()?;
            validate_parsed_status(&observed, &self.config)?;
            if rustix::process::getuid().as_raw() != self.config.expected_user_id
                || rustix::process::geteuid().as_raw() != self.config.expected_user_id
                || rustix::process::getgid().as_raw() != self.config.expected_group_id
                || rustix::process::getegid().as_raw() != self.config.expected_group_id
            {
                return Err(privilege_error());
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &self.config;
            Err(BrokerError::new(
                ErrorCode::SandboxUnavailable,
                "broker runtime privilege verification is supported only on Linux",
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn read_current_status() -> BrokerResult<ParsedPrivilegeStatus> {
    let pid = rustix::process::getpid().as_raw_nonzero().get();
    let tid = rustix::thread::gettid().as_raw_nonzero().get();
    let path = PathBuf::from(format!("/proc/{pid}/task/{tid}/status"));
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|_| status_unavailable())?;
    verify_procfs(&file)?;
    let first = parse_status(&read_bounded(&mut file)?)?;

    let mut second_file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(format!("/proc/{pid}/task/{tid}/status"))
        .map_err(|_| status_unavailable())?;
    verify_procfs(&second_file)?;
    let second = parse_status(&read_bounded(&mut second_file)?)?;
    if first != second {
        return Err(BrokerError::new(
            ErrorCode::UnexpectedPrivilegeElevation,
            "broker runtime privilege state changed during verification",
        ));
    }
    Ok(first)
}

#[cfg(target_os = "linux")]
fn verify_procfs(file: &File) -> BrokerResult<()> {
    let filesystem = rustix::fs::fstatfs(file).map_err(|_| status_unavailable())?;
    if filesystem.f_type != rustix::fs::PROC_SUPER_MAGIC {
        return Err(status_unavailable());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded(file: &mut File) -> BrokerResult<Vec<u8>> {
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(MAXIMUM_STATUS_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| status_unavailable())?;
    if bytes.len() as u64 > MAXIMUM_STATUS_BYTES {
        return Err(status_unavailable());
    }
    Ok(bytes)
}

#[derive(Debug, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct ParsedPrivilegeStatus {
    user_ids: [u32; 4],
    group_ids: [u32; 4],
    supplementary_groups: BTreeSet<u32>,
    capability_inheritable: u64,
    capability_permitted: u64,
    capability_effective: u64,
    capability_ambient: u64,
    no_new_privileges: u8,
}

#[cfg(test)]
fn validate_status(bytes: &[u8], config: &RuntimePrivilegeProfileConfig) -> BrokerResult<()> {
    let status = parse_status(bytes)?;
    validate_parsed_status(&status, config)
}

#[cfg(any(target_os = "linux", test))]
fn validate_parsed_status(
    status: &ParsedPrivilegeStatus,
    config: &RuntimePrivilegeProfileConfig,
) -> BrokerResult<()> {
    if status.user_ids != [config.expected_user_id; 4]
        || status.group_ids != [config.expected_group_id; 4]
        || status.supplementary_groups != config.allowed_supplementary_group_ids
        || status.capability_inheritable != 0
        || status.capability_permitted != 0
        || status.capability_effective != 0
        || status.capability_ambient != 0
        || status.no_new_privileges != 1
    {
        return Err(privilege_error());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn parse_status(bytes: &[u8]) -> BrokerResult<ParsedPrivilegeStatus> {
    let text = std::str::from_utf8(bytes).map_err(|_| privilege_error())?;
    let mut user_ids = None;
    let mut group_ids = None;
    let mut supplementary_groups = None;
    let mut capability_inheritable = None;
    let mut capability_permitted = None;
    let mut capability_effective = None;
    let mut capability_ambient = None;
    let mut no_new_privileges = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            set_once(&mut user_ids, parse_four_ids(value)?)?;
        } else if let Some(value) = line.strip_prefix("Gid:") {
            set_once(&mut group_ids, parse_four_ids(value)?)?;
        } else if let Some(value) = line.strip_prefix("Groups:") {
            set_once(&mut supplementary_groups, parse_groups(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapInh:") {
            set_once(&mut capability_inheritable, parse_capabilities(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapPrm:") {
            set_once(&mut capability_permitted, parse_capabilities(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapEff:") {
            set_once(&mut capability_effective, parse_capabilities(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapAmb:") {
            set_once(&mut capability_ambient, parse_capabilities(value)?)?;
        } else if let Some(value) = line.strip_prefix("NoNewPrivs:") {
            let parsed = value.trim().parse::<u8>().map_err(|_| privilege_error())?;
            set_once(&mut no_new_privileges, parsed)?;
        }
    }
    Ok(ParsedPrivilegeStatus {
        user_ids: user_ids.ok_or_else(privilege_error)?,
        group_ids: group_ids.ok_or_else(privilege_error)?,
        supplementary_groups: supplementary_groups.ok_or_else(privilege_error)?,
        capability_inheritable: capability_inheritable.ok_or_else(privilege_error)?,
        capability_permitted: capability_permitted.ok_or_else(privilege_error)?,
        capability_effective: capability_effective.ok_or_else(privilege_error)?,
        capability_ambient: capability_ambient.ok_or_else(privilege_error)?,
        no_new_privileges: no_new_privileges.ok_or_else(privilege_error)?,
    })
}

#[cfg(any(target_os = "linux", test))]
fn set_once<T>(slot: &mut Option<T>, value: T) -> BrokerResult<()> {
    if slot.replace(value).is_some() {
        return Err(privilege_error());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn parse_four_ids(value: &str) -> BrokerResult<[u32; 4]> {
    let values = value
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privilege_error())?;
    values.try_into().map_err(|_| privilege_error())
}

#[cfg(any(target_os = "linux", test))]
fn parse_groups(value: &str) -> BrokerResult<BTreeSet<u32>> {
    let values = value
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privilege_error())?;
    if values.len() > MAXIMUM_SUPPLEMENTARY_GROUPS {
        return Err(privilege_error());
    }
    let groups = values.iter().copied().collect::<BTreeSet<_>>();
    if groups.len() != values.len() {
        return Err(privilege_error());
    }
    Ok(groups)
}

#[cfg(any(target_os = "linux", test))]
fn parse_capabilities(value: &str) -> BrokerResult<u64> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(privilege_error());
    }
    u64::from_str_radix(value, 16).map_err(|_| privilege_error())
}

#[cfg(any(target_os = "linux", test))]
fn privilege_error() -> BrokerError {
    BrokerError::new(
        ErrorCode::UnexpectedPrivilegeElevation,
        "broker runtime privilege state does not match the required profile",
    )
}

#[cfg(target_os = "linux")]
fn status_unavailable() -> BrokerError {
    BrokerError::new(
        ErrorCode::SandboxUnavailable,
        "trusted broker runtime privilege evidence is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RuntimePrivilegeProfileConfig {
        RuntimePrivilegeProfileConfig {
            expected_user_id: 1001,
            expected_group_id: 1001,
            allowed_supplementary_group_ids: BTreeSet::from([1001, 2001]),
        }
    }

    fn status(overrides: &[(&str, &str)]) -> Vec<u8> {
        let mut fields = [
            ("Uid", "1001\t1001\t1001\t1001"),
            ("Gid", "1001\t1001\t1001\t1001"),
            ("Groups", "1001 2001"),
            ("CapInh", "0000000000000000"),
            ("CapPrm", "0000000000000000"),
            ("CapEff", "0000000000000000"),
            ("CapAmb", "0000000000000000"),
            ("NoNewPrivs", "1"),
        ];
        for (name, value) in overrides {
            if let Some(field) = fields.iter_mut().find(|(field, _)| field == name) {
                field.1 = value;
            }
        }
        let mut status = String::new();
        for (name, value) in fields {
            status.push_str(name);
            status.push_str(":\t");
            status.push_str(value);
            status.push('\n');
        }
        status.into_bytes()
    }

    #[test]
    fn exact_unprivileged_profile_is_accepted() -> BrokerResult<()> {
        RuntimePrivilegeMonitor::from_config(config())?;
        validate_status(&status(&[]), &config())
    }

    #[test]
    fn invalid_profiles_fail_closed() {
        let mut value = config();
        value.expected_user_id = 0;
        assert!(RuntimePrivilegeMonitor::from_config(value).is_err());
        let mut value = config();
        value.allowed_supplementary_group_ids.insert(0);
        assert!(RuntimePrivilegeMonitor::from_config(value).is_err());
        assert!(
            serde_json::from_str::<RuntimePrivilegeProfileConfig>(
                r#"{"expected_user_id":1001,"expected_group_id":1001,"allowed_supplementary_group_ids":[],"bypass":true}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn every_privilege_elevation_vector_is_rejected() {
        for (field, value) in [
            ("Uid", "1001 1001 0 1001"),
            ("Gid", "1001 0 1001 1001"),
            ("Groups", "0 1001 2001"),
            ("Groups", "1001 2001 3001"),
            ("CapInh", "0000000000000001"),
            ("CapPrm", "0000000000000001"),
            ("CapEff", "0000000000000001"),
            ("CapAmb", "0000000000000001"),
            ("NoNewPrivs", "0"),
        ] {
            assert!(validate_status(&status(&[(field, value)]), &config()).is_err());
        }
    }

    #[test]
    fn malformed_duplicate_missing_and_oversized_status_fail_closed() {
        let valid = status(&[]);
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(b"CapEff:\t0000000000000000\n");
        assert!(parse_status(&duplicate).is_err());
        let missing = String::from_utf8_lossy(&valid).replace("NoNewPrivs:\t1\n", "");
        assert!(parse_status(missing.as_bytes()).is_err());
        assert!(parse_capabilities("00000000000000000").is_err());
        assert!(parse_groups("1001 1001").is_err());
        assert!(parse_four_ids("1001 1001 1001").is_err());
    }
}
