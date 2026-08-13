//! Test-only approval issuer for the disposable Linux lifecycle fixture.
//!
//! Production deployments must never trust this embedded key. This example
//! exists only to exercise the normal signed-approval verifier and replay
//! ledger without adding an issuance or bypass API to the broker daemon.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use action_broker_core::approval::{
    APPROVAL_TOKEN_VERSION, ApprovalClaimsV1, ApprovalError, ApprovalVerifier,
    ApprovalVerifierConfig, InMemoryReplayStore, SignedApprovalTokenV1, TrustedKeyLifecycle,
    TrustedKeyRegistry,
};
use action_broker_core::capability::{
    ApprovalType, CapabilityAction, ExecuteApprovedCommandInput, RootedPath,
};
use action_broker_core::model::{
    ACTION_BROKER_PROTOCOL_VERSION, ActionRequest, ExecutionTarget, RequesterIdentity,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

const KEY_ID: &str = "lifecycle-test-key";
const TEST_SIGNING_SEED: [u8; 32] = [7_u8; 32];
const APPROVAL_LIFETIME_SECONDS: i64 = 60;
const EXPIRED_APPROVAL_AGE_SECONDS: i64 = 120;
const FUTURE_APPROVAL_OFFSET_SECONDS: i64 = 120;

#[derive(Clone, Copy)]
enum RequestProfile {
    CurrentElevated,
    CurrentExplicit,
    ExpiredElevated,
    FutureElevated,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("issue_lifecycle_approval: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let mode = required(&mut arguments, "mode")?;
    match mode.as_str() {
        "public-key" => {
            reject_extra(&mut arguments)?;
            println!("{}", hex::encode(signing_key().verifying_key().as_bytes()));
        }
        "request" => issue_request(&mut arguments, RequestProfile::CurrentElevated)?,
        "insufficient-approval-request" => {
            issue_request(&mut arguments, RequestProfile::CurrentExplicit)?;
        }
        "expired-request" => issue_request(&mut arguments, RequestProfile::ExpiredElevated)?,
        "future-request" => issue_request(&mut arguments, RequestProfile::FutureElevated)?,
        "verify" => verify_request_file(&mut arguments)?,
        _ => {
            return Err(invalid(
                "mode must be public-key, request, insufficient-approval-request, expired-request, future-request, or verify",
            )
            .into());
        }
    }
    Ok(())
}

fn verify_request_file(arguments: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let path = required(arguments, "request_path")?;
    reject_extra(arguments)?;
    let bytes = std::fs::read(path)?;
    let request: ActionRequest = serde_json::from_slice(&bytes)?;
    verify_fixture_request(&request)
}

fn issue_request(
    arguments: &mut impl Iterator<Item = String>,
    profile: RequestProfile,
) -> Result<(), Box<dyn Error>> {
    let request_id = Uuid::parse_str(&required(arguments, "request_id")?)?;
    let program_id = required(arguments, "program_id")?;
    let root_id = required(arguments, "root_id")?;
    let relative_path = required(arguments, "relative_path")?;
    let timeout_milliseconds = required(arguments, "timeout_milliseconds")?.parse::<u64>()?;
    let nonce = required(arguments, "nonce")?;
    reject_extra(arguments)?;

    let mut request = ActionRequest {
        protocol_version: ACTION_BROKER_PROTOCOL_VERSION,
        request_id,
        requester: RequesterIdentity {
            user_id: "lifecycle-user".to_owned(),
            agent_id: "lifecycle-agent".to_owned(),
            task_id: "lifecycle-command-cancellation".to_owned(),
        },
        target: ExecutionTarget::Local,
        action: CapabilityAction::ExecuteApprovedCommand(ExecuteApprovedCommandInput {
            program_id,
            arguments: vec!["30".to_owned()],
            working_directory: RootedPath {
                root_id,
                relative_path,
            },
            environment: BTreeMap::new(),
            timeout_milliseconds: Some(timeout_milliseconds),
        }),
        approval_token: None,
    };
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let issued_at = match profile {
        RequestProfile::CurrentElevated | RequestProfile::CurrentExplicit => now,
        RequestProfile::ExpiredElevated => now.saturating_sub(EXPIRED_APPROVAL_AGE_SECONDS),
        RequestProfile::FutureElevated => now.saturating_add(FUTURE_APPROVAL_OFFSET_SECONDS),
    };
    let approval_type = match profile {
        RequestProfile::CurrentExplicit => ApprovalType::ExplicitUser,
        RequestProfile::CurrentElevated
        | RequestProfile::ExpiredElevated
        | RequestProfile::FutureElevated => ApprovalType::ElevatedUser,
    };
    let claims = ApprovalClaimsV1 {
        version: APPROVAL_TOKEN_VERSION,
        request_id: request.request_id,
        user_id: request.requester.user_id.clone(),
        agent_id: request.requester.agent_id.clone(),
        task_id: request.requester.task_id.clone(),
        capability: request.capability(),
        arguments_digest_sha256: request.arguments_digest()?,
        target_digest_sha256: request.target_digest()?,
        target: request.target.clone(),
        issued_at_unix_seconds: issued_at,
        expires_at_unix_seconds: issued_at.saturating_add(APPROVAL_LIFETIME_SECONDS),
        approval_type,
        nonce,
    };
    let payload = serde_jcs::to_vec(&claims)?;
    let signature = signing_key().sign(&payload);
    request.approval_token = Some(
        SignedApprovalTokenV1 {
            key_id: KEY_ID.to_owned(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
        .to_compact()?,
    );
    match profile {
        RequestProfile::CurrentElevated => verify_fixture_request(&request)?,
        RequestProfile::CurrentExplicit => {
            verify_invalid_fixture_request(&request, ApprovalError::ApprovalTypeMismatch)?;
        }
        RequestProfile::ExpiredElevated => {
            verify_time_invalid_fixture_request(&request, ApprovalError::Expired)?;
        }
        RequestProfile::FutureElevated => {
            verify_time_invalid_fixture_request(&request, ApprovalError::NotYetValid)?;
        }
    }
    serde_json::to_writer(io::stdout().lock(), &request)?;
    io::stdout().lock().write_all(b"\n")?;
    Ok(())
}

fn verify_fixture_request(request: &ActionRequest) -> Result<(), Box<dyn Error>> {
    let verifier = fixture_verifier()?;
    let _verified = verifier.verify_embedded(request, &[ApprovalType::ElevatedUser])?;
    Ok(())
}

fn verify_time_invalid_fixture_request(
    request: &ActionRequest,
    expected: ApprovalError,
) -> Result<(), Box<dyn Error>> {
    let verifier = fixture_verifier()?;
    let result = verifier.verify_embedded(request, &[ApprovalType::ElevatedUser]);
    let matches_expected = matches!(
        (&result, expected),
        (Err(ApprovalError::Expired), ApprovalError::Expired)
            | (Err(ApprovalError::NotYetValid), ApprovalError::NotYetValid)
    );
    if !matches_expected {
        return Err(invalid("time-invalid fixture request had an unexpected result").into());
    }
    Ok(())
}

fn verify_invalid_fixture_request(
    request: &ActionRequest,
    expected: ApprovalError,
) -> Result<(), Box<dyn Error>> {
    let verifier = fixture_verifier()?;
    let result = verifier.verify_embedded(request, &[ApprovalType::ElevatedUser]);
    if !matches!(
        (&result, expected),
        (
            Err(ApprovalError::ApprovalTypeMismatch),
            ApprovalError::ApprovalTypeMismatch
        )
    ) {
        return Err(invalid("invalid fixture request had an unexpected result").into());
    }
    Ok(())
}

fn fixture_verifier() -> Result<ApprovalVerifier, ApprovalError> {
    let mut keys = TrustedKeyRegistry::new();
    keys.insert(
        KEY_ID,
        signing_key().verifying_key(),
        TrustedKeyLifecycle {
            active_from_unix_seconds: 0,
            retire_at_unix_seconds: None,
            revoke_at_unix_seconds: None,
        },
    )?;
    ApprovalVerifier::new(
        keys,
        Arc::new(InMemoryReplayStore::default()),
        ApprovalVerifierConfig::default(),
    )
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_SIGNING_SEED)
}

fn required(
    arguments: &mut impl Iterator<Item = String>,
    name: &'static str,
) -> Result<String, io::Error> {
    arguments
        .next()
        .ok_or_else(|| invalid(&format!("missing {name}")))
}

fn reject_extra(arguments: &mut impl Iterator<Item = String>) -> Result<(), io::Error> {
    if arguments.next().is_some() {
        return Err(invalid("unexpected extra argument"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
