use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use git2::{
    Config, ConfigLevel, DiffFormat, DiffOptions, ObjectType, Oid, Repository, RepositoryOpenFlags,
    Sort, Status, StatusOptions,
};

use crate::capability::{GitReadInput, GitReadOperation, GitReadOutput};
use crate::command::CancellationToken;
use crate::error::{BrokerError, BrokerResult, ErrorCode};
use crate::filesystem::ScopedFilesystem;

const MAXIMUM_OUTPUT_BYTES: usize = 512 * 1024;
const MAXIMUM_DIFF_FILE_BYTES: i64 = 512 * 1024;
const MAXIMUM_LOG_ENTRIES: u32 = 1_000;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const MAXIMUM_GIT_METADATA_ENTRIES: usize = 100_000;
const MAXIMUM_GIT_CONFIG_BYTES: u64 = 64 * 1024;

/// Local, read-only Git implementation. It uses libgit2 in process and never
/// invokes a command, hook, remote transport, credential helper, or shell.
pub struct GitReadExecutor {
    filesystem: Arc<ScopedFilesystem>,
}

impl GitReadExecutor {
    #[must_use]
    pub fn new(filesystem: Arc<ScopedFilesystem>) -> Self {
        Self { filesystem }
    }

    pub fn execute(
        &self,
        input: &GitReadInput,
        cancellation: &CancellationToken,
    ) -> BrokerResult<GitReadOutput> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        ensure_active(cancellation, deadline)?;
        self.filesystem
            .with_repository_directory(&input.repository_path, |path| {
                let repository = open_scoped_repository(path, cancellation, deadline)?;
                ensure_active(cancellation, deadline)?;

                let (output, resolved_object_id) = match &input.operation {
                    GitReadOperation::Status => {
                        let head = head_id(&repository);
                        (status(&repository, cancellation, deadline)?, head)
                    }
                    GitReadOperation::Diff { revision } => {
                        diff(&repository, revision.as_deref(), cancellation, deadline)?
                    }
                    GitReadOperation::Log { maximum_entries } => (
                        log(&repository, *maximum_entries, cancellation, deadline)?,
                        head_id(&repository),
                    ),
                    GitReadOperation::Show { object_id } => {
                        show(&repository, object_id, cancellation, deadline)?
                    }
                    GitReadOperation::ResolveRevision { revision } => {
                        resolve(&repository, revision, cancellation, deadline)?
                    }
                };
                ensure_active(cancellation, deadline)?;
                Ok(GitReadOutput {
                    repository_path: input.repository_path.clone(),
                    text_base64: base64::engine::general_purpose::STANDARD.encode(output.bytes),
                    truncated: output.truncated,
                    resolved_object_id,
                })
            })
    }
}

fn open_scoped_repository(
    path: &Path,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> BrokerResult<Repository> {
    validate_secure_directory(path, "repository directory is not securely owned")?;
    let git_directory = path.join(".git");
    validate_secure_directory(
        &git_directory,
        "Git metadata directory is not securely owned",
    )?;
    for forbidden in [
        "commondir",
        "gitdir",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ] {
        if fs::symlink_metadata(git_directory.join(forbidden)).is_ok() {
            return Err(BrokerError::new(
                ErrorCode::PathEscape,
                "Git metadata indirection is forbidden",
            ));
        }
    }
    validate_git_metadata_tree(&git_directory, cancellation, deadline)?;
    let config_path = git_directory.join("config");
    validate_local_git_config(&config_path)?;

    let repository = Repository::open_ext(
        path,
        RepositoryOpenFlags::NO_SEARCH,
        std::iter::empty::<&std::ffi::OsStr>(),
    )
    .map_err(|_| git_failure("repository could not be opened"))?;
    let mut isolated_config = Config::new()
        .map_err(|_| git_failure("isolated Git configuration could not be created"))?;
    isolated_config
        .add_file(&config_path, ConfigLevel::Local, false)
        .map_err(|_| git_failure("local Git configuration could not be loaded"))?;
    repository
        .set_config(&isolated_config)
        .map_err(|_| git_failure("isolated Git configuration could not be installed"))?;
    if repository.is_bare() || repository.is_worktree() {
        return Err(git_failure(
            "bare and linked-worktree repositories are forbidden",
        ));
    }
    let expected_worktree = canonical(path)?;
    let actual_worktree = repository
        .workdir()
        .ok_or_else(|| git_failure("repository has no worktree"))
        .and_then(canonical)?;
    let expected_git = canonical(&git_directory)?;
    let actual_git = canonical(repository.path())?;
    let common_git = canonical(repository.commondir())?;
    if actual_worktree != expected_worktree
        || actual_git != expected_git
        || common_git != expected_git
    {
        return Err(BrokerError::new(
            ErrorCode::PathEscape,
            "Git repository metadata escaped the selected root",
        ));
    }
    Ok(repository)
}

fn validate_git_metadata_tree(
    git_directory: &Path,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> BrokerResult<()> {
    let metadata_device = fs::symlink_metadata(git_directory)
        .map_err(|_| git_failure("Git metadata root could not be inspected"))?
        .dev();
    let mut pending = vec![git_directory.to_path_buf()];
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        ensure_active(cancellation, deadline)?;
        for entry in fs::read_dir(&directory)
            .map_err(|_| git_failure("Git metadata tree could not be inspected"))?
        {
            let entry = entry.map_err(|_| git_failure("Git metadata entry could not be read"))?;
            entries = entries.saturating_add(1);
            if entries > MAXIMUM_GIT_METADATA_ENTRIES {
                return Err(BrokerError::new(
                    ErrorCode::ResourceLimit,
                    "Git metadata tree exceeds the safe entry bound",
                ));
            }
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path)
                .map_err(|_| git_failure("Git metadata entry could not be inspected"))?;
            if metadata.dev() != metadata_device {
                return Err(BrokerError::new(
                    ErrorCode::PathEscape,
                    "cross-filesystem Git metadata is forbidden",
                ));
            }
            if metadata.file_type().is_symlink() {
                return Err(BrokerError::new(
                    ErrorCode::PathEscape,
                    "symbolic links are forbidden in Git metadata",
                ));
            }
            if metadata.is_dir() {
                validate_owner_and_mode(&metadata, "Git metadata directory is not securely owned")?;
                pending.push(entry_path);
            } else if metadata.is_file() && metadata.nlink() == 1 {
                validate_owner_and_mode(&metadata, "Git metadata file is not securely owned")?;
            } else {
                return Err(BrokerError::new(
                    ErrorCode::PathEscape,
                    "hard links and special files are forbidden in Git metadata",
                ));
            }
        }
    }
    Ok(())
}

fn validate_local_git_config(path: &Path) -> BrokerResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| git_failure("local Git configuration could not be inspected"))?;
    if metadata.len() > MAXIMUM_GIT_CONFIG_BYTES {
        return Err(BrokerError::new(
            ErrorCode::ResourceLimit,
            "local Git configuration exceeds the safe size bound",
        ));
    }
    let bytes =
        fs::read(path).map_err(|_| git_failure("local Git configuration could not be read"))?;
    if bytes.contains(&0) {
        return Err(git_failure("local Git configuration contains invalid data"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| git_failure("local Git configuration must be UTF-8"))?;
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            if section.starts_with("include") {
                return Err(BrokerError::new(
                    ErrorCode::PathEscape,
                    "Git configuration includes are forbidden",
                ));
            }
            continue;
        }
        let key = line
            .split_once('=')
            .map_or(line, |(key, _value)| key)
            .trim()
            .to_ascii_lowercase();
        let path_bearing_core_key = section == "core"
            && matches!(
                key.as_str(),
                "worktree" | "excludesfile" | "attributesfile" | "hookspath" | "fsmonitor"
            );
        let external_program_key = matches!(
            key.as_str(),
            "textconv" | "external" | "command" | "driver" | "smudge" | "clean" | "process"
        );
        if path_bearing_core_key
            || external_program_key
            || section == "extensions" && key == "worktreeconfig"
        {
            return Err(BrokerError::new(
                ErrorCode::PathEscape,
                "path-bearing or executable Git configuration is forbidden",
            ));
        }
    }
    Ok(())
}

fn validate_secure_directory(path: &Path, message: &'static str) -> BrokerResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| git_failure(message))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BrokerError::new(ErrorCode::PathEscape, message));
    }
    validate_owner_and_mode(&metadata, message)
}

fn validate_owner_and_mode(metadata: &fs::Metadata, message: &'static str) -> BrokerResult<()> {
    let effective_uid = rustix::process::geteuid().as_raw();
    if !matches!(metadata.uid(), 0) && metadata.uid() != effective_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(BrokerError::new(ErrorCode::PermissionDenied, message));
    }
    Ok(())
}

fn canonical(path: &Path) -> BrokerResult<PathBuf> {
    fs::canonicalize(path).map_err(|_| git_failure("repository path could not be canonicalized"))
}

fn status(
    repository: &Repository,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> BrokerResult<CappedOutput> {
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(false)
        .include_ignored(false)
        .exclude_submodules(true);
    let statuses = repository
        .statuses(Some(&mut options))
        .map_err(|_| git_failure("Git status failed"))?;
    let mut output = CappedOutput::new();
    for entry in statuses.iter() {
        ensure_active(cancellation, deadline)?;
        let line = format!(
            "{} {}\n",
            status_code(entry.status()),
            escape_bytes(entry.path_bytes())
        );
        if !output.append(line.as_bytes()) {
            break;
        }
    }
    Ok(output)
}

fn diff(
    repository: &Repository,
    revision: Option<&str>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> BrokerResult<(CappedOutput, Option<String>)> {
    let object = match revision {
        Some(revision) => Some(resolve_object(repository, revision)?),
        None => repository
            .head()
            .ok()
            .and_then(|head| head.peel(ObjectType::Commit).ok()),
    };
    let resolved_object_id = object.as_ref().map(|object| object.id().to_string());
    let tree = match object.as_ref() {
        Some(object) => Some(
            object
                .peel_to_tree()
                .map_err(|_| git_failure("Git diff revision is not tree-like"))?,
        ),
        None => None,
    };
    let mut options = DiffOptions::new();
    options
        .include_untracked(false)
        .recurse_untracked_dirs(false)
        .ignore_submodules(true)
        .show_binary(false)
        .context_lines(3)
        .max_size(MAXIMUM_DIFF_FILE_BYTES);
    let diff = repository
        .diff_tree_to_workdir_with_index(tree.as_ref(), Some(&mut options))
        .map_err(|_| git_failure("Git diff failed"))?;
    ensure_active(cancellation, deadline)?;
    let mut output = CappedOutput::new();
    let print_result = diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        if ensure_active(cancellation, deadline).is_err() {
            return false;
        }
        let origin = line.origin();
        if matches!(origin, ' ' | '+' | '-') {
            let prefix = [origin as u8];
            if !output.append(&prefix) {
                return false;
            }
        }
        output.append(line.content())
    });
    if print_result.is_err() && !output.truncated {
        ensure_active(cancellation, deadline)?;
        return Err(git_failure("Git diff formatting failed"));
    }
    Ok((output, resolved_object_id))
}

fn log(
    repository: &Repository,
    maximum_entries: u32,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> BrokerResult<CappedOutput> {
    if maximum_entries == 0 || maximum_entries > MAXIMUM_LOG_ENTRIES {
        return Err(BrokerError::invalid("Git log entry limit is invalid"));
    }
    let mut walk = repository
        .revwalk()
        .map_err(|_| git_failure("Git history could not be opened"))?;
    if walk.push_head().is_err() {
        return Ok(CappedOutput::new());
    }
    walk.set_sorting(Sort::TOPOLOGICAL | Sort::TIME)
        .map_err(|_| git_failure("Git history ordering failed"))?;
    let mut output = CappedOutput::new();
    for result in walk.take(maximum_entries as usize) {
        ensure_active(cancellation, deadline)?;
        let oid = result.map_err(|_| git_failure("Git history traversal failed"))?;
        let commit = repository
            .find_commit(oid)
            .map_err(|_| git_failure("Git history object could not be read"))?;
        let summary = commit.summary_bytes().unwrap_or_default();
        let line = format!(
            "{} {} {}\n",
            oid,
            commit.time().seconds(),
            escape_bytes(summary)
        );
        if !output.append(line.as_bytes()) {
            break;
        }
    }
    Ok(output)
}

fn show(
    repository: &Repository,
    object_id: &str,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> BrokerResult<(CappedOutput, Option<String>)> {
    let oid = parse_full_oid(object_id)?;
    let object = repository
        .find_object(oid, None)
        .map_err(|_| git_failure("Git object was not found"))?;
    ensure_active(cancellation, deadline)?;
    let mut output = CappedOutput::new();
    match object.kind() {
        Some(ObjectType::Blob) => {
            let blob = object
                .as_blob()
                .ok_or_else(|| git_failure("Git blob could not be read"))?;
            output.append(blob.content());
        }
        Some(ObjectType::Commit) => {
            let commit = object
                .as_commit()
                .ok_or_else(|| git_failure("Git commit could not be read"))?;
            output.append(commit.raw_header_bytes());
            output.append(b"\n");
            output.append(commit.message_bytes());
        }
        Some(ObjectType::Tree) => {
            let tree = object
                .as_tree()
                .ok_or_else(|| git_failure("Git tree could not be read"))?;
            for entry in tree {
                ensure_active(cancellation, deadline)?;
                let line = format!(
                    "{:06o} {:?} {}\t{}\n",
                    entry.filemode_raw(),
                    entry.kind(),
                    entry.id(),
                    escape_bytes(entry.name_bytes())
                );
                if !output.append(line.as_bytes()) {
                    break;
                }
            }
        }
        Some(ObjectType::Tag) => {
            let tag = object
                .as_tag()
                .ok_or_else(|| git_failure("Git tag could not be read"))?;
            let header = format!(
                "object {}\ntag {}\n\n",
                tag.target_id(),
                escape_bytes(tag.name_bytes())
            );
            output.append(header.as_bytes());
            output.append(tag.message_bytes().unwrap_or_default());
        }
        _ => return Err(git_failure("Git object type is unsupported")),
    }
    Ok((output, Some(oid.to_string())))
}

fn resolve(
    repository: &Repository,
    revision: &str,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> BrokerResult<(CappedOutput, Option<String>)> {
    let object = resolve_object(repository, revision)?;
    ensure_active(cancellation, deadline)?;
    let oid = object.id().to_string();
    let mut output = CappedOutput::new();
    output.append(oid.as_bytes());
    output.append(b"\n");
    Ok((output, Some(oid)))
}

fn resolve_object<'repository>(
    repository: &'repository Repository,
    revision: &str,
) -> BrokerResult<git2::Object<'repository>> {
    validate_revision(revision)?;
    repository
        .revparse_single(revision)
        .map_err(|_| git_failure("Git revision could not be resolved"))
}

fn validate_revision(revision: &str) -> BrokerResult<()> {
    if revision.is_empty()
        || revision.len() > 255
        || revision.starts_with('-')
        || revision.starts_with('/')
        || revision.ends_with('/')
        || revision.contains("..")
        || revision.contains("//")
        || revision.contains("@{")
        || revision
            .get(revision.len().saturating_sub(5)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".lock"))
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(BrokerError::invalid("Git revision syntax is forbidden"));
    }
    Ok(())
}

fn parse_full_oid(value: &str) -> BrokerResult<Oid> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BrokerError::invalid(
            "Git object ID must be a full SHA-1 object ID",
        ));
    }
    Oid::from_str(value).map_err(|_| BrokerError::invalid("Git object ID is invalid"))
}

fn head_id(repository: &Repository) -> Option<String> {
    repository
        .head()
        .ok()
        .and_then(|head| head.target())
        .map(|oid| oid.to_string())
}

fn status_code(status: Status) -> &'static str {
    if status.is_conflicted() {
        return "UU";
    }
    if status.is_ignored() {
        return "!!";
    }
    if status.is_wt_new() && !status.is_index_new() {
        return "??";
    }
    let index = if status.is_index_new() {
        'A'
    } else if status.is_index_modified() {
        'M'
    } else if status.is_index_deleted() {
        'D'
    } else if status.is_index_renamed() {
        'R'
    } else if status.is_index_typechange() {
        'T'
    } else {
        ' '
    };
    let worktree = if status.is_wt_modified() {
        'M'
    } else if status.is_wt_deleted() {
        'D'
    } else if status.is_wt_renamed() {
        'R'
    } else if status.is_wt_typechange() {
        'T'
    } else if status.is_wt_new() {
        '?'
    } else {
        ' '
    };
    match (index, worktree) {
        ('A', ' ') => "A ",
        ('M', ' ') => "M ",
        ('D', ' ') => "D ",
        ('R', ' ') => "R ",
        ('T', ' ') => "T ",
        (' ', 'M') => " M",
        (' ', 'D') => " D",
        (' ', 'R') => " R",
        (' ', 'T') => " T",
        ('A', 'M') => "AM",
        ('A', 'D') => "AD",
        ('M', 'M') => "MM",
        ('M', 'D') => "MD",
        ('D', 'M') => "DM",
        ('R', 'M') => "RM",
        ('T', 'M') => "TM",
        _ => "??",
    }
}

fn escape_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

fn ensure_active(cancellation: &CancellationToken, deadline: Instant) -> BrokerResult<()> {
    if cancellation.is_cancelled() {
        return Err(BrokerError::new(
            ErrorCode::Cancelled,
            "Git read was cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(BrokerError::new(ErrorCode::Timeout, "Git read timed out"));
    }
    Ok(())
}

fn git_failure(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::ExecutionFailure, message)
}

struct CappedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CappedOutput {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            truncated: false,
        }
    }

    fn append(&mut self, bytes: &[u8]) -> bool {
        let remaining = MAXIMUM_OUTPUT_BYTES.saturating_sub(self.bytes.len());
        let accepted = remaining.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..accepted]);
        if accepted < bytes.len() {
            self.truncated = true;
        }
        !self.truncated
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::capability::RootedPath;
    use crate::filesystem::{FilesystemPolicyConfig, FilesystemRootConfig};

    fn executor_for(path: &Path) -> BrokerResult<GitReadExecutor> {
        let filesystem = Arc::new(ScopedFilesystem::from_config(FilesystemPolicyConfig {
            roots: vec![FilesystemRootConfig {
                root_id: "repo".to_owned(),
                path: path.to_string_lossy().into_owned(),
                readable: true,
                writable: false,
                deletable: false,
            }],
            forbidden_components: Vec::new(),
        })?);
        Ok(GitReadExecutor::new(filesystem))
    }

    fn fixture() -> Result<(tempfile::TempDir, Repository, GitReadExecutor), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let repository = Repository::init(directory.path())?;
        fs::write(directory.path().join("tracked.txt"), b"first\n")?;
        let mut index = repository.index()?;
        index.add_path(Path::new("tracked.txt"))?;
        let tree_id = index.write_tree()?;
        index.write()?;
        let tree = repository.find_tree(tree_id)?;
        let signature = git2::Signature::now("Broker Test", "broker@example.invalid")?;
        repository.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])?;
        drop(tree);
        let executor = executor_for(directory.path())?;
        Ok((directory, repository, executor))
    }

    fn input(operation: GitReadOperation) -> GitReadInput {
        GitReadInput {
            repository_path: RootedPath {
                root_id: "repo".to_owned(),
                relative_path: ".".to_owned(),
            },
            operation,
        }
    }

    #[test]
    fn status_diff_log_show_and_resolve_are_read_only() -> Result<(), Box<dyn Error>> {
        let (directory, repository, executor) = fixture()?;
        fs::write(directory.path().join("tracked.txt"), b"second\n")?;
        let cancellation = CancellationToken::new();

        let status = executor.execute(&input(GitReadOperation::Status), &cancellation)?;
        let status_text = base64::engine::general_purpose::STANDARD.decode(status.text_base64)?;
        assert!(
            status_text
                .windows(11)
                .any(|window| window == b"tracked.txt")
        );

        let diff = executor.execute(
            &input(GitReadOperation::Diff { revision: None }),
            &cancellation,
        )?;
        let diff_text = base64::engine::general_purpose::STANDARD.decode(diff.text_base64)?;
        assert!(
            diff_text.windows(7).any(|window| window == b"+second"),
            "{}",
            String::from_utf8_lossy(&diff_text)
        );

        let log = executor.execute(
            &input(GitReadOperation::Log { maximum_entries: 1 }),
            &cancellation,
        )?;
        let log_text = base64::engine::general_purpose::STANDARD.decode(log.text_base64)?;
        assert!(log_text.windows(7).any(|window| window == b"initial"));

        let head = repository.head()?.target().ok_or("missing HEAD")?;
        let show = executor.execute(
            &input(GitReadOperation::Show {
                object_id: head.to_string(),
            }),
            &cancellation,
        )?;
        let show_text = base64::engine::general_purpose::STANDARD.decode(show.text_base64)?;
        assert!(show_text.windows(7).any(|window| window == b"initial"));

        let resolved = executor.execute(
            &input(GitReadOperation::ResolveRevision {
                revision: "HEAD".to_owned(),
            }),
            &cancellation,
        )?;
        assert_eq!(resolved.resolved_object_id, Some(head.to_string()));
        Ok(())
    }

    #[test]
    fn metadata_indirection_and_revision_operators_are_rejected() -> Result<(), Box<dyn Error>> {
        let (_directory, repository, executor) = fixture()?;
        fs::write(
            repository.path().join("objects/info/alternates"),
            b"/tmp/elsewhere\n",
        )?;
        let result = executor.execute(
            &input(GitReadOperation::ResolveRevision {
                revision: "HEAD".to_owned(),
            }),
            &CancellationToken::new(),
        );
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::PathEscape,
                ..
            })
        ));
        fs::remove_file(repository.path().join("objects/info/alternates"))?;
        let result = executor.execute(
            &input(GitReadOperation::ResolveRevision {
                revision: "HEAD^{tree}".to_owned(),
            }),
            &CancellationToken::new(),
        );
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::InvalidRequest,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn local_config_cannot_include_external_files() -> Result<(), Box<dyn Error>> {
        let (_directory, repository, executor) = fixture()?;
        let config_path = repository.path().join("config");
        let mut config = fs::read_to_string(&config_path)?;
        config.push_str("\n[include]\npath = /tmp/forbidden-config\n");
        fs::write(config_path, config)?;
        let result = executor.execute(&input(GitReadOperation::Status), &CancellationToken::new());
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::PathEscape,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn writable_git_metadata_is_rejected() -> Result<(), Box<dyn Error>> {
        let (_directory, repository, executor) = fixture()?;
        fs::set_permissions(repository.path(), fs::Permissions::from_mode(0o775))?;
        let result = executor.execute(&input(GitReadOperation::Status), &CancellationToken::new());
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::PermissionDenied,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn cancellation_fails_before_repository_access() -> Result<(), Box<dyn Error>> {
        let (_directory, _repository, executor) = fixture()?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = executor.execute(&input(GitReadOperation::Status), &cancellation);
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::Cancelled,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn symlinked_git_directory_is_rejected() -> Result<(), Box<dyn Error>> {
        let outside = tempfile::tempdir()?;
        Repository::init(outside.path())?;
        let selected = tempfile::tempdir()?;
        std::os::unix::fs::symlink(outside.path().join(".git"), selected.path().join(".git"))?;
        let executor = executor_for(selected.path())?;
        let result = executor.execute(&input(GitReadOperation::Status), &CancellationToken::new());
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::PathEscape,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn object_output_is_bounded_and_marked_truncated() -> Result<(), Box<dyn Error>> {
        let (_directory, repository, executor) = fixture()?;
        let oid = repository.blob(&vec![b'x'; MAXIMUM_OUTPUT_BYTES + 1])?;
        let output = executor.execute(
            &input(GitReadOperation::Show {
                object_id: oid.to_string(),
            }),
            &CancellationToken::new(),
        )?;
        assert!(output.truncated);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(output.text_base64)?
                .len(),
            MAXIMUM_OUTPUT_BYTES
        );
        Ok(())
    }
}
