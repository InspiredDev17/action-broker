use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as StdMetadataExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use base64::Engine;
use regex::Regex;
use rustix::process::{self, Pid, Signal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability::{ExecuteApprovedCommandInput, ExecuteApprovedCommandOutput};
use crate::error::{BrokerError, BrokerResult, ErrorCode};
use crate::filesystem::ScopedFilesystem;

const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_BYTES: usize = 16 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_TIMEOUT_MILLISECONDS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingDirectoryAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsSandboxBackend {
    MacosSandboxExec {
        executable_path: String,
        executable_sha256: String,
    },
    LinuxBubblewrap {
        executable_path: String,
        executable_sha256: String,
        resource_limiter_path: String,
        resource_limiter_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimitConfig {
    pub maximum_memory_bytes: u64,
    pub maximum_processes: u32,
    pub maximum_open_files: u32,
    pub maximum_file_bytes: u64,
    pub maximum_output_bytes: usize,
}

impl Default for ResourceLimitConfig {
    fn default() -> Self {
        Self {
            maximum_memory_bytes: 512 * 1024 * 1024,
            maximum_processes: 16,
            maximum_open_files: 64,
            maximum_file_bytes: 16 * 1024 * 1024,
            maximum_output_bytes: MAX_OUTPUT_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedProgramConfig {
    pub program_id: String,
    pub executable_path: String,
    pub executable_sha256: String,
    /// One anchored Rust regex for each argument. Argument count must match.
    pub argument_patterns: Vec<String>,
    /// Explicit environment variable name to anchored value regex.
    #[serde(default)]
    pub environment_patterns: BTreeMap<String, String>,
    pub working_directory_access: WorkingDirectoryAccess,
    pub maximum_timeout_milliseconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicyConfig {
    pub sandbox_backend: OsSandboxBackend,
    pub programs: Vec<ApprovedProgramConfig>,
    #[serde(default)]
    pub resource_limits: ResourceLimitConfig,
}

struct ApprovedProgram {
    executable_path: String,
    executable_sha256: String,
    argument_patterns: Vec<Regex>,
    environment_patterns: BTreeMap<String, Regex>,
    working_directory_access: WorkingDirectoryAccess,
    maximum_timeout_milliseconds: u64,
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub struct ApprovedCommandExecutor {
    filesystem: Arc<ScopedFilesystem>,
    sandbox_backend: OsSandboxBackend,
    programs: BTreeMap<String, ApprovedProgram>,
    resource_limits: ResourceLimitConfig,
}

impl ApprovedCommandExecutor {
    pub fn from_config(
        filesystem: Arc<ScopedFilesystem>,
        config: CommandPolicyConfig,
    ) -> BrokerResult<Self> {
        validate_backend(&config.sandbox_backend)?;
        validate_resource_limits(&config.resource_limits)?;
        if config.programs.is_empty() {
            return Err(BrokerError::invalid(
                "command policy requires at least one approved program",
            ));
        }
        let mut programs = BTreeMap::new();
        for program in config.programs {
            validate_program_id(&program.program_id)?;
            validate_trusted_executable(
                &program.executable_path,
                &program.executable_sha256,
                true,
            )?;
            if program.argument_patterns.len() > MAX_ARGUMENTS {
                return Err(BrokerError::invalid(
                    "approved program has too many argument patterns",
                ));
            }
            let argument_patterns = program
                .argument_patterns
                .iter()
                .map(|pattern| compile_anchored_pattern(pattern, "argument"))
                .collect::<BrokerResult<Vec<_>>>()?;
            let mut environment_patterns = BTreeMap::new();
            for (name, pattern) in program.environment_patterns {
                validate_environment_name(&name)?;
                environment_patterns
                    .insert(name, compile_anchored_pattern(&pattern, "environment")?);
            }
            if program.maximum_timeout_milliseconds == 0
                || program.maximum_timeout_milliseconds > MAX_TIMEOUT_MILLISECONDS
            {
                return Err(BrokerError::invalid(
                    "approved program timeout is outside the safe bound",
                ));
            }
            if programs
                .insert(
                    program.program_id,
                    ApprovedProgram {
                        executable_path: program.executable_path,
                        executable_sha256: program.executable_sha256,
                        argument_patterns,
                        environment_patterns,
                        working_directory_access: program.working_directory_access,
                        maximum_timeout_milliseconds: program.maximum_timeout_milliseconds,
                    },
                )
                .is_some()
            {
                return Err(BrokerError::invalid("duplicate approved program ID"));
            }
        }
        Ok(Self {
            filesystem,
            sandbox_backend: config.sandbox_backend,
            programs,
            resource_limits: config.resource_limits,
        })
    }

    pub fn execute(
        &self,
        input: &ExecuteApprovedCommandInput,
        cancellation: &CancellationToken,
    ) -> BrokerResult<ExecuteApprovedCommandOutput> {
        let program = self.programs.get(&input.program_id).ok_or_else(|| {
            BrokerError::new(ErrorCode::ForbiddenExecutable, "program ID is not approved")
        })?;
        validate_trusted_executable(&program.executable_path, &program.executable_sha256, true)?;
        validate_arguments(&input.arguments, &program.argument_patterns)?;
        validate_environment(&input.environment, &program.environment_patterns)?;
        let timeout_milliseconds = input
            .timeout_milliseconds
            .unwrap_or(program.maximum_timeout_milliseconds.min(10_000));
        if timeout_milliseconds == 0 || timeout_milliseconds > program.maximum_timeout_milliseconds
        {
            return Err(BrokerError::invalid(
                "command timeout exceeds the approved program limit",
            ));
        }
        if cancellation.is_cancelled() {
            return Err(BrokerError::new(
                ErrorCode::Cancelled,
                "action was cancelled",
            ));
        }
        let working_directory = self
            .filesystem
            .working_directory_path(&input.working_directory)?;
        let plan = SandboxLaunchPlan {
            version: 1,
            backend: self.sandbox_backend.clone(),
            executable_path: program.executable_path.clone(),
            arguments: input.arguments.clone(),
            environment: input.environment.clone(),
            working_directory,
            working_directory_access: program.working_directory_access,
            limits: self.resource_limits.clone(),
            timeout_milliseconds,
        };
        execute_plan(&plan, cancellation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxLaunchPlan {
    version: u8,
    backend: OsSandboxBackend,
    executable_path: String,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    working_directory: String,
    working_directory_access: WorkingDirectoryAccess,
    limits: ResourceLimitConfig,
    timeout_milliseconds: u64,
}

fn execute_plan(
    plan: &SandboxLaunchPlan,
    cancellation: &CancellationToken,
) -> BrokerResult<ExecuteApprovedCommandOutput> {
    let mut command = os_sandbox_command(plan)?;
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let child = command
        .spawn()
        .map_err(|_| BrokerError::new(ErrorCode::SandboxFailure, "OS sandbox could not start"))?;
    supervise_child(
        child,
        plan.limits.maximum_output_bytes,
        Duration::from_millis(plan.timeout_milliseconds),
        cancellation,
    )
}

fn supervise_child(
    mut child: Child,
    maximum_output_bytes: usize,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> BrokerResult<ExecuteApprovedCommandOutput> {
    let stdout = child.stdout.take().ok_or_else(|| {
        BrokerError::new(ErrorCode::SandboxFailure, "launcher stdout is unavailable")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        BrokerError::new(ErrorCode::SandboxFailure, "launcher stderr is unavailable")
    })?;
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let stdout_thread = bounded_reader(stdout, maximum_output_bytes, Arc::clone(&stdout_overflow));
    let stderr_thread = bounded_reader(stderr, maximum_output_bytes, Arc::clone(&stderr_overflow));

    let started = Instant::now();
    let mut timed_out = false;
    let mut cancelled = false;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| execution_error("sandbox process wait failed"))?
        {
            break status;
        }
        if cancellation.is_cancelled() {
            cancelled = true;
            terminate_process_group(child.id());
        } else if started.elapsed() >= timeout {
            timed_out = true;
            terminate_process_group(child.id());
        } else if stdout_overflow.load(Ordering::Acquire) || stderr_overflow.load(Ordering::Acquire)
        {
            terminate_process_group(child.id());
        } else {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        break child
            .wait()
            .map_err(|_| execution_error("sandbox process termination wait failed"))?;
    };
    let stdout_bytes = stdout_thread
        .join()
        .map_err(|_| execution_error("stdout collector failed"))?;
    let stderr_bytes = stderr_thread
        .join()
        .map_err(|_| execution_error("stderr collector failed"))?;

    if cancelled {
        return Err(BrokerError::new(
            ErrorCode::Cancelled,
            "action was cancelled",
        ));
    }
    if timed_out {
        return Err(BrokerError::new(
            ErrorCode::Timeout,
            "command exceeded its approved wall-clock timeout",
        ));
    }
    if stdout_overflow.load(Ordering::Acquire) || stderr_overflow.load(Ordering::Acquire) {
        return Err(BrokerError::new(
            ErrorCode::ResourceLimit,
            "command output exceeded the configured limit",
        ));
    }
    if sandbox_launcher_reported_failure(status, &stderr_bytes) {
        return Err(BrokerError::new(
            ErrorCode::SandboxFailure,
            "OS sandbox launcher failed before approved execution",
        ));
    }
    Ok(ExecuteApprovedCommandOutput {
        exit_code: status.code(),
        stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout_bytes),
        stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr_bytes),
        stdout_truncated: false,
        stderr_truncated: false,
        timed_out: false,
    })
}

fn sandbox_launcher_reported_failure(status: ExitStatus, stderr: &[u8]) -> bool {
    !status.success()
        && [b"bwrap:".as_slice(), b"prlimit:".as_slice()]
            .iter()
            .any(|prefix| stderr.starts_with(prefix))
}

fn bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut result = Vec::with_capacity(limit.min(64 * 1024));
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let remaining = limit.saturating_sub(result.len());
                    result.extend_from_slice(&buffer[..read.min(remaining)]);
                    if read > remaining {
                        overflow.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        }
        result
    })
}

fn terminate_process_group(child_id: u32) {
    let Some(raw_pid) = i32::try_from(child_id).ok() else {
        return;
    };
    let Some(pid) = Pid::from_raw(raw_pid) else {
        return;
    };
    let _ = process::kill_process_group(pid, Signal::KILL);
}

fn os_sandbox_command(plan: &SandboxLaunchPlan) -> BrokerResult<Command> {
    let OsSandboxBackend::LinuxBubblewrap {
        executable_path,
        executable_sha256: _,
        resource_limiter_path,
        resource_limiter_sha256: _,
    } = &plan.backend
    else {
        return Err(BrokerError::new(
            ErrorCode::SandboxUnavailable,
            "approved command execution has no supported macOS isolation backend",
        ));
    };
    if !["/usr/", "/bin/", "/sbin/"]
        .iter()
        .any(|prefix| plan.executable_path.starts_with(prefix))
    {
        return Err(sandbox_error(
            "Linux approved executable is outside the read-only runtime roots",
        ));
    }
    let cpu_seconds = plan.timeout_milliseconds.div_ceil(1_000).saturating_add(1);
    let mut command = Command::new(resource_limiter_path);
    command.args([
        format!("--cpu={cpu_seconds}"),
        format!("--fsize={}", plan.limits.maximum_file_bytes),
        "--core=0".to_owned(),
        format!("--nofile={}", plan.limits.maximum_open_files),
        format!("--nproc={}", plan.limits.maximum_processes),
        format!("--as={}", plan.limits.maximum_memory_bytes),
        "--".to_owned(),
        executable_path.clone(),
    ]);
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--clearenv",
        "--dir",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/work",
    ]);
    for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            command.args(["--ro-bind", path, path]);
        }
    }
    match plan.working_directory_access {
        WorkingDirectoryAccess::ReadOnly => {
            command.args(["--ro-bind", &plan.working_directory, "/work"]);
        }
        WorkingDirectoryAccess::ReadWrite => {
            command.args(["--bind", &plan.working_directory, "/work"]);
        }
    }
    for (name, value) in &plan.environment {
        command.args(["--setenv", name, value]);
    }
    command
        .args(["--chdir", "/work", "--", &plan.executable_path])
        .args(&plan.arguments);
    Ok(command)
}

fn validate_arguments(arguments: &[String], patterns: &[Regex]) -> BrokerResult<()> {
    if arguments.len() != patterns.len()
        || arguments.len() > MAX_ARGUMENTS
        || total_string_bytes(arguments) > MAX_ARGUMENT_BYTES
    {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "command argument shape is not approved",
        ));
    }
    if arguments
        .iter()
        .zip(patterns)
        .any(|(argument, pattern)| argument.contains('\0') || !pattern.is_match(argument))
    {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "command argument is not approved",
        ));
    }
    Ok(())
}

fn validate_environment(
    environment: &BTreeMap<String, String>,
    patterns: &BTreeMap<String, Regex>,
) -> BrokerResult<()> {
    let total = environment
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum::<usize>();
    if total > MAX_ENVIRONMENT_BYTES
        || environment.iter().any(|(name, value)| {
            validate_environment_name(name).is_err()
                || value.contains('\0')
                || patterns
                    .get(name)
                    .is_none_or(|pattern| !pattern.is_match(value))
        })
    {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "command environment is not approved",
        ));
    }
    Ok(())
}

fn validate_backend(backend: &OsSandboxBackend) -> BrokerResult<()> {
    match backend {
        OsSandboxBackend::MacosSandboxExec {
            executable_path,
            executable_sha256,
        } => {
            let _ = (executable_path, executable_sha256);
            Err(BrokerError::new(
                ErrorCode::SandboxUnavailable,
                "approved command execution is disabled on macOS because no current backend satisfies the required isolation and resource guarantees",
            ))
        }
        OsSandboxBackend::LinuxBubblewrap {
            executable_path,
            executable_sha256,
            resource_limiter_path,
            resource_limiter_sha256,
        } => {
            if !cfg!(target_os = "linux") {
                return Err(sandbox_error("Linux sandbox backend is unavailable"));
            }
            validate_trusted_executable(executable_path, executable_sha256, false)?;
            validate_trusted_executable(resource_limiter_path, resource_limiter_sha256, false)
        }
    }
}

fn validate_trusted_executable(
    value: &str,
    expected_sha256: &str,
    forbid_interpreter: bool,
) -> BrokerResult<()> {
    let path = Path::new(value);
    if !path.is_absolute() || value.contains('\0') {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable path is invalid",
        ));
    }
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BrokerError::invalid(
            "approved executable digest is invalid",
        ));
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| {
        BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable cannot be canonicalized",
        )
    })?;
    if canonical != path {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable path contains a link or non-canonical component",
        ));
    }
    validate_secure_executable_parents(path)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable cannot be inspected",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable must be a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o6000 != 0
        || metadata.uid() == process::geteuid().as_raw()
    {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable permissions are unsafe",
        ));
    }
    if forbid_interpreter && is_forbidden_dispatcher(path) {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "shells, interpreters, and generic dispatchers are forbidden",
        ));
    }
    let file = std::fs::File::open(path).map_err(|_| {
        BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable cannot be opened",
        )
    })?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            BrokerError::new(
                ErrorCode::ForbiddenExecutable,
                "approved executable cannot be hashed",
            )
        })?;
    if bytes.len() > 64 * 1024 * 1024 || hex::encode(Sha256::digest(&bytes)) != expected_sha256 {
        return Err(BrokerError::new(
            ErrorCode::ForbiddenExecutable,
            "approved executable digest does not match policy",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_secure_executable_parents(path: &Path) -> BrokerResult<()> {
    let broker_uid = process::geteuid().as_raw();
    for parent in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| {
            BrokerError::new(
                ErrorCode::ForbiddenExecutable,
                "approved executable parent cannot be inspected",
            )
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.mode() & 0o022 != 0
            || metadata.uid() == broker_uid
        {
            return Err(BrokerError::new(
                ErrorCode::ForbiddenExecutable,
                "approved executable parent directory is not immutable to the broker",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secure_executable_parents(_path: &Path) -> BrokerResult<()> {
    Err(BrokerError::new(
        ErrorCode::SandboxUnavailable,
        "approved executable validation is unsupported on this platform",
    ))
}

fn is_forbidden_dispatcher(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "fish"
            | "ksh"
            | "csh"
            | "tcsh"
            | "env"
            | "xargs"
            | "osascript"
            | "perl"
            | "ruby"
            | "node"
            | "php"
            | "lua"
            | "sudo"
            | "doas"
            | "su"
    ) || name.starts_with("python")
}

fn validate_resource_limits(limits: &ResourceLimitConfig) -> BrokerResult<()> {
    if limits.maximum_memory_bytes < 16 * 1024 * 1024
        || limits.maximum_memory_bytes > 4 * 1024 * 1024 * 1024
        || limits.maximum_processes == 0
        || limits.maximum_processes > 64
        || limits.maximum_open_files < 8
        || limits.maximum_open_files > 256
        || limits.maximum_file_bytes > 64 * 1024 * 1024
        || limits.maximum_output_bytes == 0
        || limits.maximum_output_bytes > MAX_OUTPUT_BYTES
    {
        return Err(BrokerError::invalid(
            "command resource limits are outside safe bounds",
        ));
    }
    Ok(())
}

fn compile_anchored_pattern(pattern: &str, kind: &'static str) -> BrokerResult<Regex> {
    if pattern.len() > 512 || !pattern.starts_with('^') || !pattern.ends_with('$') {
        return Err(BrokerError::invalid(format!(
            "{kind} validation pattern must be short and anchored"
        )));
    }
    Regex::new(pattern)
        .map_err(|_| BrokerError::invalid(format!("{kind} validation pattern is invalid")))
}

fn validate_program_id(value: &str) -> BrokerResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(BrokerError::invalid("approved program ID is invalid"));
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> BrokerResult<()> {
    let forbidden = name == "PATH"
        || name == "IFS"
        || name == "ENV"
        || name == "BASH_ENV"
        || name.starts_with("LD_")
        || name.starts_with("DYLD_");
    let syntax = !name.is_empty()
        && name.len() <= 64
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        });
    if forbidden || !syntax {
        return Err(BrokerError::invalid(
            "command environment variable name is forbidden",
        ));
    }
    Ok(())
}

fn total_string_bytes(values: &[String]) -> usize {
    values.iter().map(String::len).sum()
}

fn sandbox_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::SandboxFailure, message)
}

fn execution_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::ExecutionFailure, message)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::Cursor;

    use super::*;

    #[cfg(unix)]
    fn spawn_test_process(program: &str, arguments: &[&str]) -> Result<Child, Box<dyn Error>> {
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        Ok(command.spawn()?)
    }

    fn first_existing(candidates: &[&'static str]) -> Option<&'static str> {
        candidates
            .iter()
            .copied()
            .find(|candidate| Path::new(candidate).is_file())
    }

    #[test]
    fn shell_and_interpreters_are_forbidden() {
        assert!(is_forbidden_dispatcher(Path::new("/bin/sh")));
        assert!(is_forbidden_dispatcher(Path::new("/usr/bin/python3")));
        assert!(is_forbidden_dispatcher(Path::new("/usr/bin/env")));
        assert!(!is_forbidden_dispatcher(Path::new("/usr/bin/git")));
    }

    #[test]
    fn shell_metacharacters_fail_an_exact_argument_rule() -> BrokerResult<()> {
        let rules = vec![compile_anchored_pattern(r"^status$", "argument")?];
        let arguments = vec!["status; rm -rf /".to_owned()];
        assert!(validate_arguments(&arguments, &rules).is_err());
        Ok(())
    }

    #[test]
    fn option_injection_fails_a_positional_argument_rule() -> BrokerResult<()> {
        let rules = vec![compile_anchored_pattern(
            r"^[a-z0-9][a-z0-9._-]{0,31}$",
            "argument",
        )?];
        let arguments = vec!["--upload-pack=evil".to_owned()];
        assert!(validate_arguments(&arguments, &rules).is_err());
        Ok(())
    }

    #[test]
    fn loader_and_path_environment_injection_are_always_forbidden() {
        for name in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PATH", "BASH_ENV"] {
            assert!(validate_environment_name(name).is_err());
        }
    }

    #[test]
    fn linux_sandbox_exposes_an_empty_proc_directory() -> BrokerResult<()> {
        let plan = SandboxLaunchPlan {
            version: 1,
            backend: OsSandboxBackend::LinuxBubblewrap {
                executable_path: "/usr/bin/bwrap".to_owned(),
                executable_sha256: "00".repeat(32),
                resource_limiter_path: "/usr/bin/prlimit".to_owned(),
                resource_limiter_sha256: "00".repeat(32),
            },
            executable_path: "/usr/bin/sleep".to_owned(),
            arguments: vec!["1".to_owned()],
            environment: BTreeMap::new(),
            working_directory: "/tmp".to_owned(),
            working_directory_access: WorkingDirectoryAccess::ReadOnly,
            limits: ResourceLimitConfig::default(),
            timeout_milliseconds: 1_000,
        };

        let command = os_sandbox_command(&plan)?;
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(arguments.windows(2).any(|pair| pair == ["--dir", "/proc"]));
        assert!(!arguments.iter().any(|argument| argument == "--proc"));
        Ok(())
    }

    #[test]
    fn cancellation_token_is_monotonic() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn bounded_reader_retains_only_the_approved_prefix() -> Result<(), Box<dyn Error>> {
        let overflow = Arc::new(AtomicBool::new(false));
        let handle = bounded_reader(
            Cursor::new(vec![b'x'; 1024 * 1024]),
            1_024,
            Arc::clone(&overflow),
        );
        let retained = handle.join().map_err(|_| "bounded reader thread failed")?;

        assert_eq!(retained.len(), 1_024);
        assert!(retained.iter().all(|byte| *byte == b'x'));
        assert!(overflow.load(Ordering::Acquire));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn wall_clock_timeout_terminates_the_process_group() -> Result<(), Box<dyn Error>> {
        let Some(sleep) = first_existing(&["/bin/sleep", "/usr/bin/sleep"]) else {
            return Ok(());
        };
        let child = spawn_test_process(sleep, &["5"])?;
        let started = Instant::now();
        let result = supervise_child(
            child,
            1_024,
            Duration::from_millis(25),
            &CancellationToken::new(),
        );

        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::Timeout,
                ..
            })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn output_flooding_is_bounded_and_terminates_the_process() -> Result<(), Box<dyn Error>> {
        let Some(yes) = first_existing(&["/usr/bin/yes", "/bin/yes"]) else {
            return Ok(());
        };
        let child = spawn_test_process(yes, &[])?;
        let started = Instant::now();
        let result = supervise_child(
            child,
            4_096,
            Duration::from_secs(5),
            &CancellationToken::new(),
        );

        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::ResourceLimit,
                ..
            })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_terminates_an_in_flight_process() -> Result<(), Box<dyn Error>> {
        let Some(sleep) = first_existing(&["/bin/sleep", "/usr/bin/sleep"]) else {
            return Ok(());
        };
        let child = spawn_test_process(sleep, &["5"])?;
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            trigger.cancel();
        });
        let started = Instant::now();
        let result = supervise_child(child, 1_024, Duration::from_secs(5), &cancellation);
        canceller
            .join()
            .map_err(|_| "cancellation trigger thread failed")?;

        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::Cancelled,
                ..
            })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_launcher_diagnostic_fails_closed() -> Result<(), Box<dyn Error>> {
        let Some(shell) = first_existing(&["/bin/sh", "/usr/bin/sh"]) else {
            return Ok(());
        };
        let child = spawn_test_process(
            shell,
            &["-c", "printf 'bwrap: setup failed\\n' >&2; exit 1"],
        )?;
        let result = supervise_child(
            child,
            1_024,
            Duration::from_secs(1),
            &CancellationToken::new(),
        );

        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::SandboxFailure,
                ..
            })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn approved_program_nonzero_exit_remains_structured_output() -> Result<(), Box<dyn Error>> {
        let Some(shell) = first_existing(&["/bin/sh", "/usr/bin/sh"]) else {
            return Ok(());
        };
        let child = spawn_test_process(shell, &["-c", "printf 'ordinary failure\\n' >&2; exit 1"])?;
        let output = supervise_child(
            child,
            1_024,
            Duration::from_secs(1),
            &CancellationToken::new(),
        )?;

        assert_eq!(output.exit_code, Some(1));
        Ok(())
    }

    #[test]
    fn process_fanout_limits_reject_fork_bomb_profiles() {
        let mut limits = ResourceLimitConfig::default();
        assert!(limits.maximum_processes <= 16);

        limits.maximum_processes = 0;
        assert!(validate_resource_limits(&limits).is_err());
        limits.maximum_processes = 65;
        assert!(validate_resource_limits(&limits).is_err());
        limits.maximum_processes = 64;
        assert!(validate_resource_limits(&limits).is_ok());
    }
}
