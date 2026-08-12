use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Component, Path};

use base64::Engine;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, MetadataExt, OpenOptions, OpenOptionsExt, Permissions, PermissionsExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::capability::{
    CreateFileInput, DeleteFileInput, DeleteFileOutput, DirectoryEntry, DirectoryEntryKind,
    FileMutationOutput, ListDirectoryInput, ListDirectoryOutput, MoveFileInput, MoveFileOutput,
    ReadFileInput, ReadFileOutput, RootedPath, WriteFileInput,
};
use crate::error::{BrokerError, BrokerResult, ErrorCode};

const MAX_FILE_BYTES: usize = 512 * 1024;
const MAX_DIRECTORY_ENTRIES: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRootConfig {
    pub root_id: String,
    pub path: String,
    #[serde(default)]
    pub readable: bool,
    #[serde(default)]
    pub writable: bool,
    #[serde(default)]
    pub deletable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicyConfig {
    pub roots: Vec<FilesystemRootConfig>,
    #[serde(default = "default_forbidden_components")]
    pub forbidden_components: Vec<String>,
}

fn default_forbidden_components() -> Vec<String> {
    [
        ".aws",
        ".config/gcloud",
        ".docker",
        ".git",
        ".gnupg",
        ".kube",
        ".netrc",
        ".npmrc",
        ".pki",
        ".ssh",
        "Library/Keychains",
        "secrets",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

struct FilesystemRoot {
    dir: Dir,
    ambient_path: std::path::PathBuf,
    mutation_lock: Mutex<()>,
    readable: bool,
    writable: bool,
    deletable: bool,
}

/// Directory-capability filesystem. Requests never receive or recover the
/// ambient absolute root path after initialization.
pub struct ScopedFilesystem {
    roots: BTreeMap<String, FilesystemRoot>,
    forbidden_components: Vec<Vec<String>>,
}

impl ScopedFilesystem {
    pub fn from_config(config: FilesystemPolicyConfig) -> BrokerResult<Self> {
        if config.roots.is_empty() {
            return Err(BrokerError::invalid(
                "filesystem policy requires at least one root",
            ));
        }
        let mut roots = BTreeMap::new();
        for root in config.roots {
            validate_id(&root.root_id)?;
            if !Path::new(&root.path).is_absolute() {
                return Err(BrokerError::invalid(
                    "configured filesystem root must be absolute",
                ));
            }
            let ambient_path = std::fs::canonicalize(&root.path).map_err(|_| {
                BrokerError::new(
                    ErrorCode::SandboxUnavailable,
                    "configured filesystem root cannot be canonicalized",
                )
            })?;
            reject_forbidden_ambient_root(&ambient_path)?;
            let dir = Dir::open_ambient_dir(&ambient_path, ambient_authority()).map_err(|_| {
                BrokerError::new(
                    ErrorCode::SandboxUnavailable,
                    "configured filesystem root cannot be opened",
                )
            })?;
            if roots
                .insert(
                    root.root_id,
                    FilesystemRoot {
                        dir,
                        ambient_path,
                        mutation_lock: Mutex::new(()),
                        readable: root.readable,
                        writable: root.writable,
                        deletable: root.deletable,
                    },
                )
                .is_some()
            {
                return Err(BrokerError::invalid("duplicate filesystem root ID"));
            }
        }
        let forbidden_components = config
            .forbidden_components
            .into_iter()
            .map(|path| {
                path.split('/')
                    .filter(|component| !component.is_empty())
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            })
            .filter(|components| !components.is_empty())
            .collect();
        Ok(Self {
            roots,
            forbidden_components,
        })
    }

    pub fn read_file(&self, input: &ReadFileInput) -> BrokerResult<ReadFileOutput> {
        let (root, path) = self.resolve(&input.path, Access::Read)?;
        let maximum_bytes = usize::try_from(input.maximum_bytes)
            .map_err(|_| BrokerError::invalid("read limit is outside the safe bound"))?;
        if maximum_bytes == 0 || maximum_bytes > MAX_FILE_BYTES {
            return Err(BrokerError::invalid("read limit is outside the safe bound"));
        }
        let metadata = root.dir.symlink_metadata(&path).map_err(map_fs_error)?;
        validate_regular_file(&metadata)?;
        let mut file = root.dir.open(&path).map_err(map_fs_error)?;
        validate_opened_file(&file)?;
        let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
        Read::by_ref(&mut file)
            .take(input.maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| execution_error("file read failed"))?;
        let truncated = bytes.len() as u64 > input.maximum_bytes;
        if truncated {
            bytes.truncate(maximum_bytes);
        }
        Ok(ReadFileOutput {
            path: input.path.clone(),
            bytes_read: bytes.len() as u64,
            sha256: digest(&bytes),
            content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            truncated,
        })
    }

    pub fn write_file(&self, input: &WriteFileInput) -> BrokerResult<FileMutationOutput> {
        let bytes = decode_content(&input.content_base64)?;
        let (root, path) = self.resolve(&input.path, Access::Write)?;
        let _guard = root.mutation_lock.lock();
        reject_symlink_components(&root.dir, &path)?;
        let existing = read_existing_regular(&root.dir, &path)?;
        if existing.is_none() && !input.create_if_missing {
            return Err(execution_error("target file does not exist"));
        }
        verify_expected_digest(
            existing.as_deref(),
            input.expected_prechange_sha256.as_deref(),
        )?;
        atomic_write(
            &root.dir,
            &path,
            &bytes,
            existing.is_none(),
            input.path.clone(),
            existing.as_deref(),
        )
    }

    pub fn create_file(&self, input: &CreateFileInput) -> BrokerResult<FileMutationOutput> {
        let bytes = decode_content(&input.content_base64)?;
        let (root, path) = self.resolve(&input.path, Access::Write)?;
        let _guard = root.mutation_lock.lock();
        reject_symlink_components(&root.dir, &path)?;
        let existing = read_existing_regular(&root.dir, &path)?;
        if existing.is_some() && input.fail_if_exists {
            return Err(execution_error("target file already exists"));
        }
        if existing.is_some() {
            return Err(BrokerError::invalid(
                "CreateFile cannot replace an existing file; use WriteFile",
            ));
        }
        atomic_write(&root.dir, &path, &bytes, true, input.path.clone(), None)
    }

    pub fn move_file(&self, input: &MoveFileInput) -> BrokerResult<MoveFileOutput> {
        if input.source.root_id != input.destination.root_id {
            return Err(BrokerError::new(
                ErrorCode::SandboxFailure,
                "cross-root moves are forbidden",
            ));
        }
        let (root, source) = self.resolve(&input.source, Access::Write)?;
        let (_, destination) = self.resolve(&input.destination, Access::Write)?;
        let _guard = root.mutation_lock.lock();
        reject_symlink_components(&root.dir, &source)?;
        reject_symlink_components(&root.dir, &destination)?;
        let source_bytes = read_existing_regular(&root.dir, &source)?
            .ok_or_else(|| execution_error("source file does not exist"))?;
        verify_expected_digest(Some(&source_bytes), input.expected_source_sha256.as_deref())?;
        let destination_bytes = read_existing_regular(&root.dir, &destination)?;
        if destination_bytes.is_some() && !input.replace_existing {
            return Err(execution_error("destination file already exists"));
        }
        let replaced_backup_reference = destination_bytes
            .as_deref()
            .map(|bytes| write_recovery_copy(&root.dir, &destination, bytes))
            .transpose()?;
        if input.replace_existing {
            root.dir
                .rename(&source, &root.dir, &destination)
                .map_err(map_fs_error)?;
        } else {
            rename_no_replace(&root.dir, &source, &destination)?;
        }
        Ok(MoveFileOutput {
            source: input.source.clone(),
            destination: input.destination.clone(),
            moved_sha256: digest(&source_bytes),
            replaced_sha256: destination_bytes.as_deref().map(digest),
            replaced_backup_reference,
            used_atomic_rename: true,
        })
    }

    pub fn delete_file(&self, input: &DeleteFileInput) -> BrokerResult<DeleteFileOutput> {
        if !input.require_regular_file {
            return Err(BrokerError::invalid(
                "DeleteFile must require a regular file",
            ));
        }
        let (root, path) = self.resolve(&input.path, Access::Delete)?;
        let _guard = root.mutation_lock.lock();
        reject_symlink_components(&root.dir, &path)?;
        let bytes = read_existing_regular(&root.dir, &path)?
            .ok_or_else(|| execution_error("target file does not exist"))?;
        verify_expected_digest(Some(&bytes), input.expected_sha256.as_deref())?;

        // Move into a same-root owner-only trash directory. This is recoverable
        // until an operator applies retention; no recursive deletion exists.
        ensure_private_recovery_directory(&root.dir, ".action-broker-trash")?;
        let backup_reference = format!(
            ".action-broker-trash/{}-{}",
            Uuid::new_v4(),
            sanitized_basename(&path)
        );
        root.dir
            .rename(&path, &root.dir, &backup_reference)
            .map_err(map_fs_error)?;
        Ok(DeleteFileOutput {
            path: input.path.clone(),
            previous_sha256: digest(&bytes),
            backup_reference: Some(backup_reference),
            removed: true,
        })
    }

    pub fn list_directory(&self, input: &ListDirectoryInput) -> BrokerResult<ListDirectoryOutput> {
        if input.maximum_entries == 0 || input.maximum_entries > MAX_DIRECTORY_ENTRIES {
            return Err(BrokerError::invalid(
                "directory entry limit is outside the safe bound",
            ));
        }
        let (root, path) = self.resolve(&input.path, Access::Read)?;
        if path != Path::new(".") {
            let metadata = root.dir.symlink_metadata(&path).map_err(map_fs_error)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(BrokerError::new(
                    ErrorCode::PathEscape,
                    "directory path is not a real directory",
                ));
            }
        }
        let mut entries = Vec::new();
        let mut truncated = false;
        for entry in root.dir.read_dir(&path).map_err(map_fs_error)? {
            let entry = entry.map_err(map_fs_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if self.is_forbidden_path(&path.join(&name)) {
                continue;
            }
            if !input.include_hidden && name.starts_with('.') {
                continue;
            }
            if entries.len() >= input.maximum_entries as usize {
                truncated = true;
                break;
            }
            let metadata = entry.metadata().map_err(map_fs_error)?;
            let file_type = metadata.file_type();
            let kind = if file_type.is_file() {
                DirectoryEntryKind::File
            } else if file_type.is_dir() {
                DirectoryEntryKind::Directory
            } else if file_type.is_symlink() {
                DirectoryEntryKind::Symlink
            } else {
                DirectoryEntryKind::Other
            };
            entries.push(DirectoryEntry {
                name,
                kind,
                byte_len: file_type.is_file().then_some(metadata.len()),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(ListDirectoryOutput {
            path: input.path.clone(),
            entries,
            truncated,
        })
    }

    /// Opens a broker-rooted working directory for process execution. The
    /// returned absolute path remains inside the trusted executor boundary.
    pub(crate) fn working_directory_path(&self, rooted: &RootedPath) -> BrokerResult<String> {
        self.directory_path(rooted)
    }

    /// Runs a trusted repository operation while holding the root mutation
    /// lock. Generic filesystem capabilities cannot access `.git` directly.
    pub(crate) fn with_repository_directory<T>(
        &self,
        rooted: &RootedPath,
        operation: impl FnOnce(&Path) -> BrokerResult<T>,
    ) -> BrokerResult<T> {
        let (root, path) = self.resolve(rooted, Access::Read)?;
        let _guard = root.mutation_lock.lock();
        let directory = validated_directory_path(root, &path)?;
        operation(&directory)
    }

    fn directory_path(&self, rooted: &RootedPath) -> BrokerResult<String> {
        let (root, path) = self.resolve(rooted, Access::Read)?;
        Ok(validated_directory_path(root, &path)?
            .to_string_lossy()
            .into_owned())
    }

    fn resolve<'a>(
        &'a self,
        rooted: &RootedPath,
        access: Access,
    ) -> BrokerResult<(&'a FilesystemRoot, std::path::PathBuf)> {
        validate_id(&rooted.root_id)?;
        let root = self.roots.get(&rooted.root_id).ok_or_else(|| {
            BrokerError::new(
                ErrorCode::PermissionDenied,
                "filesystem root is not allowed",
            )
        })?;
        match access {
            Access::Read if !root.readable => {
                return Err(BrokerError::new(
                    ErrorCode::PermissionDenied,
                    "filesystem root is not readable",
                ));
            }
            Access::Write if !root.writable => {
                return Err(BrokerError::new(
                    ErrorCode::PermissionDenied,
                    "filesystem root is not writable",
                ));
            }
            Access::Delete if !root.deletable => {
                return Err(BrokerError::new(
                    ErrorCode::PermissionDenied,
                    "filesystem root does not allow deletion",
                ));
            }
            _ => {}
        }
        let path = validate_relative_path(&rooted.relative_path)?;
        if self.is_forbidden_path(&path) {
            return Err(BrokerError::new(
                ErrorCode::SecretAccess,
                "secret or credential path is forbidden",
            ));
        }
        reject_symlink_components(&root.dir, &path)?;
        Ok((root, path))
    }

    fn is_forbidden_path(&self, path: &Path) -> bool {
        let components: Vec<_> = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        self.forbidden_components.iter().any(|forbidden| {
            forbidden.len() <= components.len()
                && components
                    .windows(forbidden.len())
                    .any(|window| window == forbidden)
        })
    }
}

fn reject_forbidden_ambient_root(path: &Path) -> BrokerResult<()> {
    let normalized = path.to_string_lossy();
    if normalized == "/" {
        return Err(BrokerError::new(
            ErrorCode::SandboxUnavailable,
            "the host filesystem root cannot be configured as an action root",
        ));
    }
    if normalized == "/proc"
        || normalized.starts_with("/proc/")
        || normalized == "/sys"
        || normalized.starts_with("/sys/")
        || normalized == "/dev"
        || normalized.starts_with("/dev/")
    {
        return Err(BrokerError::new(
            ErrorCode::SandboxUnavailable,
            "pseudo-filesystem and device roots are forbidden",
        ));
    }
    let secret_components = [
        ".aws",
        ".docker",
        ".git",
        ".gnupg",
        ".kube",
        ".ssh",
        "keychains",
        "secrets",
    ];
    if path.components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        let value = value.to_string_lossy().to_ascii_lowercase();
        secret_components.contains(&value.as_str())
    }) {
        return Err(BrokerError::new(
            ErrorCode::SecretAccess,
            "secret or credential directory cannot be configured as a root",
        ));
    }
    Ok(())
}

fn validated_directory_path(
    root: &FilesystemRoot,
    path: &Path,
) -> BrokerResult<std::path::PathBuf> {
    reject_symlink_components(&root.dir, path)?;
    let canonical = root.dir.canonicalize(path).map_err(map_fs_error)?;
    let metadata = root
        .dir
        .symlink_metadata(&canonical)
        .map_err(map_fs_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(path_error("working directory is not a real directory"));
    }
    Ok(root.ambient_path.join(canonical))
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
    Delete,
}

fn validate_relative_path(value: &str) -> BrokerResult<std::path::PathBuf> {
    if value.is_empty() || value.contains('\0') {
        return Err(path_error("filesystem path is invalid"));
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(path_error("absolute filesystem paths are forbidden"));
    }
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir if normalized.as_os_str().is_empty() => normalized.push("."),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(path_error("parent traversal is forbidden"));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    Ok(normalized)
}

fn reject_symlink_components(root: &Dir, path: &Path) -> BrokerResult<()> {
    let components: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_owned()),
            _ => None,
        })
        .collect();
    let mut current = std::path::PathBuf::new();
    for component in components {
        current.push(component);
        match root.symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(path_error("symbolic links are forbidden"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(path_error("filesystem path inspection failed")),
        }
    }
    Ok(())
}

fn read_existing_regular(dir: &Dir, path: &Path) -> BrokerResult<Option<Vec<u8>>> {
    let metadata = match dir.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_fs_error(error)),
    };
    validate_regular_file(&metadata)?;
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(BrokerError::new(
            ErrorCode::ResourceLimit,
            "file exceeds the safe size bound",
        ));
    }
    let mut file = dir.open(path).map_err(map_fs_error)?;
    validate_opened_file(&file)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        BrokerError::new(
            ErrorCode::ResourceLimit,
            "file exceeds the platform addressable size",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| execution_error("file read failed"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(BrokerError::new(
            ErrorCode::ResourceLimit,
            "file changed beyond the safe size bound while reading",
        ));
    }
    Ok(Some(bytes))
}

fn atomic_write(
    dir: &Dir,
    target: &Path,
    bytes: &[u8],
    create: bool,
    rooted: RootedPath,
    existing: Option<&[u8]>,
) -> BrokerResult<FileMutationOutput> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    if parent != Path::new("") && parent != Path::new(".") {
        let metadata = dir.symlink_metadata(parent).map_err(map_fs_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(path_error("target parent is not a real directory"));
        }
    }
    let temporary = parent.join(format!(".action-broker-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = dir.open_with(&temporary, &options).map_err(map_fs_error)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(map_fs_error)?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    if write_result.is_err() {
        let _ = dir.remove_file(&temporary);
        return Err(execution_error("atomic file write failed"));
    }
    drop(file);
    let backup_reference = if let Some(previous) = existing {
        Some(write_recovery_copy(dir, target, previous)?)
    } else {
        None
    };
    let rename_result = if create {
        rename_no_replace(dir, &temporary, target)
    } else {
        dir.rename(&temporary, dir, target).map_err(map_fs_error)
    };
    if let Err(error) = rename_result {
        let _ = dir.remove_file(&temporary);
        return Err(error);
    }
    Ok(FileMutationOutput {
        path: rooted,
        previous_sha256: existing.map(digest),
        current_sha256: digest(bytes),
        bytes_written: bytes.len() as u64,
        backup_reference,
        used_atomic_rename: true,
    })
}

fn rename_no_replace(dir: &Dir, source: &Path, destination: &Path) -> BrokerResult<()> {
    rustix::fs::renameat_with(
        dir,
        source,
        dir,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|_| execution_error("atomic no-replace rename failed"))
}

fn ensure_private_recovery_directory(dir: &Dir, path: &str) -> BrokerResult<()> {
    match dir.symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(path_error("recovery path is not a real directory"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            dir.create_dir(path).map_err(map_fs_error)?;
        }
        Err(error) => return Err(map_fs_error(error)),
    }
    dir.set_permissions(path, Permissions::from_mode(0o700))
        .map_err(map_fs_error)
}

fn write_recovery_copy(dir: &Dir, target: &Path, bytes: &[u8]) -> BrokerResult<String> {
    const BACKUP_DIRECTORY: &str = ".action-broker-backups";
    ensure_private_recovery_directory(dir, BACKUP_DIRECTORY)?;
    let backup_reference = format!(
        "{BACKUP_DIRECTORY}/{}-{}",
        Uuid::new_v4(),
        sanitized_basename(target)
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut backup = dir
        .open_with(&backup_reference, &options)
        .map_err(map_fs_error)?;
    if backup
        .write_all(bytes)
        .and_then(|()| backup.flush())
        .and_then(|()| backup.sync_all())
        .is_err()
    {
        let _ = dir.remove_file(&backup_reference);
        return Err(execution_error("recovery copy write failed"));
    }
    Ok(backup_reference)
}

fn decode_content(encoded: &str) -> BrokerResult<Vec<u8>> {
    if encoded.len() > MAX_FILE_BYTES.saturating_mul(4).saturating_add(2) / 3 + 4 {
        return Err(BrokerError::new(
            ErrorCode::ResourceLimit,
            "file content exceeds the safe size bound",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| BrokerError::invalid("file content is not canonical base64"))?;
    if bytes.len() > MAX_FILE_BYTES
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != encoded
    {
        return Err(BrokerError::invalid("file content is not canonical base64"));
    }
    Ok(bytes)
}

fn verify_expected_digest(bytes: Option<&[u8]>, expected: Option<&str>) -> BrokerResult<()> {
    if let Some(expected) = expected {
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(BrokerError::invalid("expected digest is invalid"));
        }
        let actual = bytes.map_or_else(|| digest(&[]), digest);
        if !constant_time_equal(actual.as_bytes(), expected.to_ascii_lowercase().as_bytes()) {
            return Err(BrokerError::new(
                ErrorCode::ExecutionFailure,
                "pre-change digest does not match",
            ));
        }
    }
    Ok(())
}

fn validate_regular_file(metadata: &cap_std::fs::Metadata) -> BrokerResult<()> {
    if metadata.file_type().is_symlink() {
        return Err(path_error("symbolic links are forbidden"));
    }
    if !metadata.is_file() {
        return Err(path_error("device and special files are forbidden"));
    }
    if metadata.nlink() != 1 {
        return Err(path_error("hard-linked files are forbidden"));
    }
    Ok(())
}

fn validate_opened_file(file: &cap_std::fs::File) -> BrokerResult<()> {
    let metadata = file
        .metadata()
        .map_err(|_| execution_error("opened file metadata failed"))?;
    validate_regular_file(&metadata)
}

fn validate_id(value: &str) -> BrokerResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(BrokerError::invalid("filesystem root ID is invalid"));
    }
    Ok(())
}

fn sanitized_basename(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map_or_else(|| "file".to_owned(), str::to_owned)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[allow(clippy::needless_pass_by_value)]
fn map_fs_error(error: std::io::Error) -> BrokerError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
    ) {
        path_error("filesystem capability denied the path")
    } else {
        execution_error("filesystem operation failed")
    }
}

fn path_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::PathEscape, message)
}

fn execution_error(message: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::ExecutionFailure, message)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn filesystem(path: &Path) -> BrokerResult<ScopedFilesystem> {
        ScopedFilesystem::from_config(FilesystemPolicyConfig {
            roots: vec![FilesystemRootConfig {
                root_id: "workspace".to_owned(),
                path: path.to_string_lossy().into_owned(),
                readable: true,
                writable: true,
                deletable: true,
            }],
            forbidden_components: default_forbidden_components(),
        })
    }

    fn rooted(relative_path: &str) -> RootedPath {
        RootedPath {
            root_id: "workspace".to_owned(),
            relative_path: relative_path.to_owned(),
        }
    }

    #[test]
    fn traversal_is_rejected() -> BrokerResult<()> {
        let directory = tempfile::tempdir().map_err(|_| BrokerError::internal())?;
        let fs = filesystem(directory.path())?;
        let result = fs.read_file(&ReadFileInput {
            path: rooted("../secret"),
            maximum_bytes: 10,
        });
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::PathEscape,
                ..
            })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("secret"), b"secret")?;
        std::os::unix::fs::symlink(outside.path(), directory.path().join("link"))?;
        let fs = filesystem(directory.path())?;
        let result = fs.read_file(&ReadFileInput {
            path: rooted("link/secret"),
            maximum_bytes: 10,
        });
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
    fn secret_path_is_rejected() -> BrokerResult<()> {
        let directory = tempfile::tempdir().map_err(|_| BrokerError::internal())?;
        let fs = filesystem(directory.path())?;
        let result = fs.read_file(&ReadFileInput {
            path: rooted("profile/.ssh/id_ed25519"),
            maximum_bytes: 10,
        });
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::SecretAccess,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn generic_filesystem_capability_cannot_read_git_metadata() -> BrokerResult<()> {
        let directory = tempfile::tempdir().map_err(|_| BrokerError::internal())?;
        fs::create_dir(directory.path().join(".git")).map_err(|_| BrokerError::internal())?;
        fs::write(directory.path().join(".git/config"), b"sensitive")
            .map_err(|_| BrokerError::internal())?;
        let fs = filesystem(directory.path())?;
        let result = fs.read_file(&ReadFileInput {
            path: rooted(".git/config"),
            maximum_bytes: 64,
        });
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::SecretAccess,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn host_filesystem_root_is_rejected() {
        let result = reject_forbidden_ambient_root(Path::new("/"));
        assert!(matches!(
            result,
            Err(BrokerError {
                code: ErrorCode::SandboxUnavailable,
                ..
            })
        ));
    }

    #[test]
    fn writes_are_atomic_and_digest_bound() -> BrokerResult<()> {
        let directory = tempfile::tempdir().map_err(|_| BrokerError::internal())?;
        fs::write(directory.path().join("note"), b"before").map_err(|_| BrokerError::internal())?;
        let fs = filesystem(directory.path())?;
        let output = fs.write_file(&WriteFileInput {
            path: rooted("note"),
            content_base64: base64::engine::general_purpose::STANDARD.encode(b"after"),
            expected_prechange_sha256: Some(digest(b"before")),
            create_if_missing: false,
        })?;
        assert!(output.used_atomic_rename);
        let backup = output.backup_reference.ok_or_else(BrokerError::internal)?;
        assert_eq!(
            std::fs::read(directory.path().join(backup)).map_err(|_| BrokerError::internal())?,
            b"before"
        );
        assert_eq!(
            std::fs::read(directory.path().join("note")).map_err(|_| BrokerError::internal())?,
            b"after"
        );
        Ok(())
    }

    #[test]
    fn deletion_moves_to_recovery_area() -> BrokerResult<()> {
        let directory = tempfile::tempdir().map_err(|_| BrokerError::internal())?;
        fs::write(directory.path().join("note"), b"data").map_err(|_| BrokerError::internal())?;
        let fs = filesystem(directory.path())?;
        let output = fs.delete_file(&DeleteFileInput {
            path: rooted("note"),
            expected_sha256: Some(digest(b"data")),
            require_regular_file: true,
        })?;
        assert!(output.backup_reference.is_some());
        assert!(!directory.path().join("note").exists());
        Ok(())
    }
}
