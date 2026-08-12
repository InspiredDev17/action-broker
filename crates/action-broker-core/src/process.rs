use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", test))]
use std::fs::{self, OpenOptions};
#[cfg(any(target_os = "linux", test))]
use std::io::Read;
#[cfg(any(target_os = "linux", test))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "linux", test))]
use crate::capability::{ProcessInformation, ProcessInspectOperation};
use crate::capability::{ProcessInspectInput, ProcessInspectOutput};
use crate::command::CancellationToken;
use crate::error::{BrokerError, BrokerResult, ErrorCode};

const MAXIMUM_CONFIGURED_ENTRIES: u32 = 1_024;
#[cfg(any(target_os = "linux", test))]
const MAXIMUM_PROC_ENTRIES_SCANNED: usize = 65_536;
#[cfg(any(target_os = "linux", test))]
const MAXIMUM_PROC_FILE_BYTES: u64 = 16 * 1024;
#[cfg(any(target_os = "linux", test))]
const INSPECTION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessInspectPolicyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_user_ids: BTreeSet<u32>,
    #[serde(default = "default_maximum_entries")]
    pub maximum_entries: u32,
}

const fn default_maximum_entries() -> u32 {
    256
}

impl Default for ProcessInspectPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_user_ids: BTreeSet::new(),
            maximum_entries: default_maximum_entries(),
        }
    }
}

/// Linux process inspection with no subprocess, shell, command-line, or
/// environment access. The trusted policy selects the only UIDs whose process
/// metadata may be returned.
pub struct ProcessInspectExecutor {
    enabled: bool,
    #[cfg(any(target_os = "linux", test))]
    allowed_user_ids: BTreeSet<u32>,
    #[cfg(any(target_os = "linux", test))]
    maximum_entries: u32,
}

impl ProcessInspectExecutor {
    pub fn from_config(config: ProcessInspectPolicyConfig) -> BrokerResult<Self> {
        if config.maximum_entries == 0 || config.maximum_entries > MAXIMUM_CONFIGURED_ENTRIES {
            return Err(BrokerError::invalid(
                "process inspection entry limit is invalid",
            ));
        }
        if config.allowed_user_ids.contains(&0) {
            return Err(BrokerError::invalid(
                "process inspection of the root UID is forbidden",
            ));
        }
        if config.enabled == config.allowed_user_ids.is_empty() {
            return Err(BrokerError::invalid(
                "enabled process inspection requires a non-empty UID allowlist",
            ));
        }
        Ok(Self {
            enabled: config.enabled,
            #[cfg(any(target_os = "linux", test))]
            allowed_user_ids: config.allowed_user_ids,
            #[cfg(any(target_os = "linux", test))]
            maximum_entries: config.maximum_entries,
        })
    }

    pub fn execute(
        &self,
        input: &ProcessInspectInput,
        cancellation: &CancellationToken,
    ) -> BrokerResult<ProcessInspectOutput> {
        if !self.enabled {
            return Err(BrokerError::new(
                ErrorCode::BackendUnavailable,
                "process inspection backend is disabled",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            self.execute_at(Path::new("/proc"), input, cancellation)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (input, cancellation);
            Err(BrokerError::new(
                ErrorCode::BackendUnavailable,
                "process inspection is supported only on Linux",
            ))
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn execute_at(
        &self,
        proc_root: &Path,
        input: &ProcessInspectInput,
        cancellation: &CancellationToken,
    ) -> BrokerResult<ProcessInspectOutput> {
        let deadline = Instant::now() + INSPECTION_TIMEOUT;
        ensure_active(cancellation, deadline)?;
        match input.operation {
            ProcessInspectOperation::List { maximum_entries } => {
                if maximum_entries == 0 || maximum_entries > self.maximum_entries {
                    return Err(BrokerError::invalid(
                        "process inspection entry limit is outside policy",
                    ));
                }
                self.list(proc_root, maximum_entries, cancellation, deadline)
            }
            ProcessInspectOperation::InspectPid { pid } => {
                if pid == 0 {
                    return Err(BrokerError::invalid("process ID is invalid"));
                }
                let process = self
                    .inspect_allowed(proc_root, pid, cancellation, deadline)?
                    .ok_or_else(process_unavailable)?;
                Ok(ProcessInspectOutput {
                    processes: vec![process],
                    truncated: false,
                })
            }
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn list(
        &self,
        proc_root: &Path,
        maximum_entries: u32,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> BrokerResult<ProcessInspectOutput> {
        let mut pids = Vec::new();
        for (index, entry) in fs::read_dir(proc_root)
            .map_err(|_| process_failure("process table cannot be opened"))?
            .enumerate()
        {
            ensure_active(cancellation, deadline)?;
            if index >= MAXIMUM_PROC_ENTRIES_SCANNED {
                return Err(BrokerError::new(
                    ErrorCode::ResourceLimit,
                    "process table exceeds the scan bound",
                ));
            }
            let entry = entry.map_err(|_| process_failure("process table entry cannot be read"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if pid != 0 {
                pids.push(pid);
            }
        }
        pids.sort_unstable();

        let limit = usize::try_from(maximum_entries)
            .map_err(|_| BrokerError::invalid("process inspection entry limit is invalid"))?;
        let mut processes = Vec::with_capacity(limit.min(64));
        let mut truncated = false;
        for pid in pids {
            ensure_active(cancellation, deadline)?;
            match self.inspect_allowed(proc_root, pid, cancellation, deadline) {
                Ok(Some(process)) if processes.len() < limit => processes.push(process),
                Ok(Some(_)) => {
                    truncated = true;
                    break;
                }
                Err(error) if matches!(error.code, ErrorCode::Cancelled | ErrorCode::Timeout) => {
                    return Err(error);
                }
                Ok(None) | Err(_) => {
                    // Process exit and PID reuse are expected while enumerating.
                    // Individual inspection still reports a generic failure.
                }
            }
        }
        Ok(ProcessInspectOutput {
            processes,
            truncated,
        })
    }

    #[cfg(any(target_os = "linux", test))]
    fn inspect_allowed(
        &self,
        proc_root: &Path,
        pid: u32,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> BrokerResult<Option<ProcessInformation>> {
        ensure_active(cancellation, deadline)?;
        let directory = proc_root.join(pid.to_string());
        let first_status = parse_status(&read_bounded(&directory.join("status"))?)?;
        if first_status.pid != pid || !self.allowed_user_ids.contains(&first_status.user_id) {
            return Ok(None);
        }
        let first_start_time = parse_start_time(&read_bounded(&directory.join("stat"))?)?;
        ensure_active(cancellation, deadline)?;
        let executable = executable_name(&directory.join("exe"));
        let second_status = parse_status(&read_bounded(&directory.join("status"))?)?;
        let second_start_time = parse_start_time(&read_bounded(&directory.join("stat"))?)?;
        if first_status != second_status || first_start_time != second_start_time {
            return Err(process_failure(
                "process identity changed during inspection",
            ));
        }
        Ok(Some(ProcessInformation {
            pid,
            parent_pid: Some(first_status.parent_pid),
            executable,
            // Command lines and environments commonly contain credentials.
            // This backend deliberately never opens cmdline or environ.
            arguments_redacted: Vec::new(),
            user_id: Some(first_status.user_id),
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct ProcessStatus {
    pid: u32,
    parent_pid: u32,
    user_id: u32,
}

#[cfg(any(target_os = "linux", test))]
fn parse_status(bytes: &[u8]) -> BrokerResult<ProcessStatus> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| process_failure("process status is not valid UTF-8"))?;
    let mut pid = None;
    let mut parent_pid = None;
    let mut user_id = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:") {
            pid = parse_first_u32(value);
        } else if let Some(value) = line.strip_prefix("PPid:") {
            parent_pid = parse_first_u32(value);
        } else if let Some(value) = line.strip_prefix("Uid:") {
            user_id = parse_first_u32(value);
        }
    }
    Ok(ProcessStatus {
        pid: pid.ok_or_else(|| process_failure("process status has no PID"))?,
        parent_pid: parent_pid
            .ok_or_else(|| process_failure("process status has no parent PID"))?,
        user_id: user_id.ok_or_else(|| process_failure("process status has no user ID"))?,
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_first_u32(value: &str) -> Option<u32> {
    value.split_ascii_whitespace().next()?.parse().ok()
}

#[cfg(any(target_os = "linux", test))]
fn parse_start_time(bytes: &[u8]) -> BrokerResult<u64> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| process_failure("process stat is not valid UTF-8"))?;
    let close = text
        .rfind(')')
        .ok_or_else(|| process_failure("process stat is malformed"))?;
    let fields = text[close + 1..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| process_failure("process stat has no start time"))?
        .parse::<u64>()
        .map_err(|_| process_failure("process start time is invalid"))
}

#[cfg(any(target_os = "linux", test))]
fn read_bounded(path: &Path) -> BrokerResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| process_failure("process metadata is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(process_failure("process metadata has an invalid type"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|_| process_failure("process metadata cannot be opened"))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAXIMUM_PROC_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| process_failure("process metadata cannot be read"))?;
    if bytes.len() as u64 > MAXIMUM_PROC_FILE_BYTES {
        return Err(BrokerError::new(
            ErrorCode::ResourceLimit,
            "process metadata exceeds the size bound",
        ));
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", test))]
fn executable_name(path: &Path) -> String {
    fs::read_link(path)
        .ok()
        .and_then(|target| target.file_name().map(std::ffi::OsStr::to_os_string))
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty() && name.len() <= 255)
        .unwrap_or_else(|| "unavailable".to_owned())
}

#[cfg(any(target_os = "linux", test))]
fn ensure_active(cancellation: &CancellationToken, deadline: Instant) -> BrokerResult<()> {
    if cancellation.is_cancelled() {
        return Err(BrokerError::new(
            ErrorCode::Cancelled,
            "process inspection was cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(BrokerError::new(
            ErrorCode::Timeout,
            "process inspection exceeded its wall-clock timeout",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn process_failure(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::ExecutionFailure, message)
}

#[cfg(any(target_os = "linux", test))]
fn process_unavailable() -> BrokerError {
    process_failure("process is unavailable under inspection policy")
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;

    use super::*;

    fn executor(uid: u32) -> BrokerResult<ProcessInspectExecutor> {
        ProcessInspectExecutor::from_config(ProcessInspectPolicyConfig {
            enabled: true,
            allowed_user_ids: BTreeSet::from([uid]),
            maximum_entries: 2,
        })
    }

    fn add_process(root: &Path, pid: u32, parent: u32, uid: u32) -> Result<(), Box<dyn Error>> {
        let directory = root.join(pid.to_string());
        fs::create_dir(&directory)?;
        fs::write(
            directory.join("status"),
            format!(
                "Name:\ttest\nPid:\t{pid}\nPPid:\t{parent}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            ),
        )?;
        let mut fields = vec!["S".to_owned(); 20];
        fields[19] = format!("{}", u64::from(pid) * 100);
        fs::write(
            directory.join("stat"),
            format!("{pid} (name with spaces) {}\n", fields.join(" ")),
        )?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            PathBuf::from("/usr/bin/test-process"),
            directory.join("exe"),
        )?;
        Ok(())
    }

    #[test]
    fn validates_fail_closed_policy() {
        assert!(ProcessInspectExecutor::from_config(ProcessInspectPolicyConfig::default()).is_ok());
        assert!(
            ProcessInspectExecutor::from_config(ProcessInspectPolicyConfig {
                enabled: true,
                allowed_user_ids: BTreeSet::new(),
                maximum_entries: 1,
            })
            .is_err()
        );
        assert!(
            ProcessInspectExecutor::from_config(ProcessInspectPolicyConfig {
                enabled: false,
                allowed_user_ids: BTreeSet::from([501]),
                maximum_entries: 1,
            })
            .is_err()
        );
        assert!(
            serde_json::from_str::<ProcessInspectPolicyConfig>(
                r#"{"enabled":false,"allowed_user_ids":[],"maximum_entries":1,"bypass":true}"#,
            )
            .is_err()
        );
        assert!(
            ProcessInspectExecutor::from_config(ProcessInspectPolicyConfig {
                enabled: true,
                allowed_user_ids: BTreeSet::from([0]),
                maximum_entries: 1,
            })
            .is_err()
        );
    }

    #[test]
    fn fixture_inspection_filters_uids_redacts_arguments_and_bounds_output()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        add_process(directory.path(), 10, 1, 501)?;
        add_process(directory.path(), 11, 1, 502)?;
        add_process(directory.path(), 12, 10, 501)?;
        add_process(directory.path(), 13, 10, 501)?;
        let executor = executor(501)?;

        let output = executor.execute_at(
            directory.path(),
            &ProcessInspectInput {
                operation: ProcessInspectOperation::List { maximum_entries: 2 },
            },
            &CancellationToken::new(),
        )?;
        assert_eq!(output.processes.len(), 2);
        assert!(output.truncated);
        assert!(output.processes.iter().all(|process| {
            process.user_id == Some(501)
                && process.arguments_redacted.is_empty()
                && process.executable == "test-process"
        }));

        let denied = executor.execute_at(
            directory.path(),
            &ProcessInspectInput {
                operation: ProcessInspectOperation::InspectPid { pid: 11 },
            },
            &CancellationToken::new(),
        );
        assert!(denied.is_err());
        Ok(())
    }

    #[test]
    fn malformed_symlinked_and_cancelled_inputs_fail_closed() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        add_process(directory.path(), 10, 1, 501)?;
        fs::remove_file(directory.path().join("10/status"))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("elsewhere", directory.path().join("10/status"))?;
        let executor = executor(501)?;
        let input = ProcessInspectInput {
            operation: ProcessInspectOperation::InspectPid { pid: 10 },
        };
        assert!(
            executor
                .execute_at(directory.path(), &input, &CancellationToken::new())
                .is_err()
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            executor.execute_at(directory.path(), &input, &cancellation),
            Err(BrokerError {
                code: ErrorCode::Cancelled,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn deadline_is_enforced() {
        let result = ensure_active(&CancellationToken::new(), Instant::now());
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::Timeout,
                ..
            })
        ));
    }
}
