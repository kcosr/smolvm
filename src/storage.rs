//! Persistent storage management.
//!
//! This module provides [`StorageDisk`] for managing persistent storage.
//! Each VM (default or named) gets its own sparse ext4 disk image that stores
//! OCI layers, container overlays, and cached manifests.
//!
//! # Storage Locations
//!
//! - Default VM: `~/Library/Application Support/smolvm/storage.raw` (macOS)
//! - Named VMs: `~/Library/Caches/smolvm/vms/{name}/storage.raw` (macOS)
//!
//! # Architecture
//!
//! The storage disk is a sparse raw disk image formatted with ext4.
//! It's mounted inside the agent VM which handles OCI layer extraction
//! and overlay filesystem management.

use crate::data::consts::BYTES_PER_GIB;
pub use crate::data::disk::{DiskFormat, DiskType, Overlay, Storage};
pub use crate::data::storage::{
    DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB, OVERLAY_DISK_FILENAME,
    STORAGE_DISK_FILENAME,
};
use crate::disk_utils;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};

/// Seed a VM-mode machine's overlay+storage disks from extracted pack templates so
/// it boots the source VM's filesystem rather than a freshly-mkfs'd empty overlay.
///
/// VM-mode (`--from-vm`) packs carry the source VM's rootfs DISKS, but the packed
/// template has its trailing zero extent stripped, so the disk must be grown back to
/// its logical size before boot. Create paths call this before constructing their
/// [`AgentManager`], allowing the manager to open the final artifact disks directly.
/// Any stale default overlays from an interrupted/older create are removed first.
/// On Linux, a shared extraction with an artifact SHA-256 creates one immutable,
/// normalized raw base per artifact/disk/size and gives every machine a tiny qcow2
/// overlay. macOS keeps using APFS clonefile, while unsupported qcow2 hosts retain
/// the sparse-copy path.
/// A `.formatted` marker stops the host from reformatting the inherited filesystem;
/// the guest still grows it with resize2fs.
///
/// The template → disk copy uses [`crate::disk_utils::clone_or_copy_file`] (clonefile
/// CoW on macOS, `SEEK_HOLE` sparse copy on Linux), NOT a dense `fs::copy`: the
/// templates are sparse (~25 MiB of real data in a multi-GiB logical file), so a dense
/// copy would balloon every machine to its full logical size (~28 GiB) on disk.
///
/// `disk_dir` is the machine's prepared data directory.
/// Shared by both the serve API create path and the `smolvm machine create --from`
/// CLI path so a VM-mode pack restores identically through either entry point.
///
/// [`AgentManager`]: crate::agent::AgentManager
/// [`resolve_disk_image`]: crate::agent::manager::resolve_disk_image
#[derive(Debug, Clone, Copy)]
pub struct VmModeDiskSeedSpec<'a> {
    /// SHA-256 of the source pack, used to key immutable Linux COW bases.
    pub artifact_sha256: Option<&'a str>,
    /// Relative path to the packed root overlay template.
    pub overlay_template: Option<&'a str>,
    /// Relative path to the packed persistent storage template.
    pub storage_template: Option<&'a str>,
    /// Logical byte length to restore for the root overlay.
    pub overlay_logical_size: Option<u64>,
    /// Logical byte length to restore for persistent storage.
    pub storage_logical_size: Option<u64>,
    /// Requested root overlay size when the manifest lacks a logical length.
    pub overlay_gb: Option<u64>,
    /// Requested storage size when the manifest lacks a logical length.
    pub storage_gb: Option<u64>,
}

/// Manifest-backed disk information used by an operator-installed VM base.
///
/// Unlike [`VmModeDiskSeedSpec`], this includes each packed template's declared
/// byte length so an unprivileged consumer can validate the installed metadata
/// without extracting the artifact.
#[derive(Debug, Clone, Copy)]
pub struct InstalledVmModeDiskSeedSpec<'a> {
    /// Relative path of the packed root overlay template.
    pub overlay_template: Option<&'a str>,
    /// Declared packed byte length of the root overlay template.
    pub overlay_source_size: Option<u64>,
    /// Relative path of the packed persistent storage template.
    pub storage_template: Option<&'a str>,
    /// Declared packed byte length of the persistent storage template.
    pub storage_source_size: Option<u64>,
    /// Logical byte length restored for the root overlay.
    pub overlay_logical_size: Option<u64>,
    /// Logical byte length restored for persistent storage.
    pub storage_logical_size: Option<u64>,
    /// Requested root overlay size when larger than the artifact default.
    pub overlay_gb: Option<u64>,
    /// Requested storage size when larger than the artifact default.
    pub storage_gb: Option<u64>,
}

/// Environment variable pointing at operator-installed immutable VM bases.
pub const SHARED_VM_BASE_DIR_ENV: &str = "SMOLVM_SHARED_VM_BASE_DIR";

/// Resolve the optional operator base root used by direct, per-user CLI calls.
pub fn shared_vm_base_root_from_env() -> std::io::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(SHARED_VM_BASE_DIR_ENV).filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{SHARED_VM_BASE_DIR_ENV} must be an absolute path"),
        ));
    }
    Ok(Some(path))
}

/// Seeds one VM-mode machine from the extracted pack disk templates.
pub fn seed_vm_mode_disks(
    disk_dir: &Path,
    cache_dir: &Path,
    seed: VmModeDiskSeedSpec<'_>,
) -> std::io::Result<()> {
    // Drop the manager's default qcow2 overlays (backed by the empty default
    // template) so the seeded raw disks below are what start resolves.
    for raw_filename in [STORAGE_DISK_FILENAME, OVERLAY_DISK_FILENAME] {
        let stem = Path::new(raw_filename);
        let _ = std::fs::remove_file(disk_dir.join(stem.with_extension("qcow2")));
    }

    #[cfg(target_os = "linux")]
    if let Some(artifact_sha256) = seed.artifact_sha256 {
        // `.pack-shared` is the durable lease used by reference-aware pruning.
        // Never publish a qcow2 backing dependency that has no matching lease.
        crate::artifact_cache::validate_cow_lease(disk_dir, cache_dir, artifact_sha256)?;
        if try_seed_vm_mode_disks_cow(
            disk_dir,
            cache_dir,
            &cow_base_cache_root(),
            artifact_sha256,
            seed,
            crate::agent::create_disk_overlays,
        )? {
            return Ok(());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = seed.artifact_sha256;

    seed_vm_mode_disks_by_copy(disk_dir, cache_dir, seed)
}

/// Portable sparse-copy fallback for VM-mode disks.
fn seed_vm_mode_disks_by_copy(
    disk_dir: &Path,
    cache_dir: &Path,
    seed: VmModeDiskSeedSpec<'_>,
) -> std::io::Result<()> {
    seed_one_disk(
        cache_dir,
        seed.overlay_template,
        &disk_dir.join(OVERLAY_DISK_FILENAME),
        seed.overlay_logical_size,
        seed.overlay_gb,
    )?;
    seed_one_disk(
        cache_dir,
        seed.storage_template,
        &disk_dir.join(STORAGE_DISK_FILENAME),
        seed.storage_logical_size,
        seed.storage_gb,
    )
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CowBaseMetadata {
    artifact_sha256: String,
    disk_type: String,
    source_template: String,
    source_size: u64,
    logical_size: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct InstalledVmBaseRelease {
    version: u32,
    artifact_sha256: String,
    disks: Vec<CowBaseMetadata>,
}

#[cfg(target_os = "linux")]
static COW_BASE_STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Root for immutable VM-mode disk bases. Keep it outside the root-only shared
/// pack extraction tree: each VMM drops to a distinct uid before libkrun opens
/// its qcow2 backing files, so those uids must be able to traverse the base
/// path. Directories below this root are execute-only to other uids and the VMM
/// is still Landlock-confined to its exact backing chain.
#[cfg(target_os = "linux")]
pub(crate) fn cow_base_cache_root() -> PathBuf {
    crate::agent::vm_cache_root().join("_cow-bases")
}

/// Install immutable VM-mode disk bases from one extracted artifact.
///
/// This is an operator action. The caller extracts the artifact into
/// `extracted_pack`, passes its full SHA-256, and publishes into a root-owned
/// absolute directory. Ordinary machine lifecycle never writes this store.
#[cfg(target_os = "linux")]
pub fn install_vm_mode_disk_bases(
    base_root: &Path,
    extracted_pack: &Path,
    artifact_sha256: &str,
    seed: InstalledVmModeDiskSeedSpec<'_>,
) -> std::io::Result<Vec<PathBuf>> {
    validate_artifact_sha256(artifact_sha256)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "installing shared VM bases requires root",
        ));
    }
    prepare_operator_base_root(base_root)?;
    let release = expected_installed_release(artifact_sha256, seed)?;

    let mut installed = Vec::with_capacity(2);
    for definition in installed_disk_definitions(seed) {
        let Some((template, declared_size)) = definition.template.zip(definition.source_size)
        else {
            if definition.template.is_some() != definition.source_size.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} template path and source size must both be present",
                        definition.disk_type
                    ),
                ));
            }
            continue;
        };
        let source = resolve_template_in_cache(extracted_pack, template)?;
        let actual_size = std::fs::symlink_metadata(&source)?.len();
        if !std::fs::symlink_metadata(&source)?.file_type().is_file()
            || actual_size != declared_size
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{} template does not match manifest size: {}",
                    definition.disk_type,
                    source.display()
                ),
            ));
        }
        let logical_size = disk_target_size(
            declared_size,
            definition.logical_size,
            definition.size_gb_override,
        )?;
        let base = prepare_cow_base(
            base_root,
            artifact_sha256,
            definition.disk_type,
            template,
            &source,
            declared_size,
            logical_size,
        )?;
        let base_dir = base.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "installed VM base has no parent directory",
            )
        })?;
        let expected = CowBaseMetadata {
            artifact_sha256: artifact_sha256.to_string(),
            disk_type: definition.disk_type.to_string(),
            source_template: template.to_string(),
            source_size: declared_size,
            logical_size,
        };
        validate_operator_base_path(base_root, base_dir, 0)?;
        installed.push(validate_cow_base_owned(base_dir, &expected, 0)?);
    }
    if installed.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "VM-mode artifact contains no disk templates",
        ));
    }
    publish_installed_release(base_root, &release, 0)?;
    Ok(installed)
}

/// Prepare the operator-owned shared base root and create private installation
/// staging on the same filesystem. Keeping the artifact snapshot and extracted
/// sparse disks here avoids exhausting a separate system temporary filesystem
/// and allows the final base publication to use filesystem clones.
#[cfg(target_os = "linux")]
pub fn create_vm_base_install_staging(base_root: &Path) -> std::io::Result<tempfile::TempDir> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "preparing shared VM base installation requires root",
        ));
    }
    create_vm_base_install_staging_owned(base_root, 0)
}

#[cfg(target_os = "linux")]
fn create_vm_base_install_staging_owned(
    base_root: &Path,
    required_owner: u32,
) -> std::io::Result<tempfile::TempDir> {
    prepare_operator_base_root_owned(base_root, required_owner)?;
    let staging = tempfile::Builder::new()
        .prefix(".smolvm-vm-base-install-")
        .tempdir_in(base_root)?;
    std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(staging)
}

/// Create private qcow2 disks backed by one operator-installed VM base release.
///
/// Missing, writable, mismatched, symlinked, or non-root-owned bases fail
/// closed. There is deliberately no sparse-copy fallback: that would silently
/// restore per-user duplication and violate the shared-base contract.
#[cfg(target_os = "linux")]
pub fn seed_vm_mode_disks_from_installed_bases(
    disk_dir: &Path,
    base_root: &Path,
    artifact_sha256: &str,
    seed: InstalledVmModeDiskSeedSpec<'_>,
) -> std::io::Result<()> {
    seed_vm_mode_disks_from_installed_bases_with(
        disk_dir,
        base_root,
        artifact_sha256,
        seed,
        crate::agent::create_disk_overlays,
        0,
    )
}

/// Operator-installed qcow2 backing bases require Linux filesystem ownership
/// and permission guarantees.
#[cfg(not(target_os = "linux"))]
pub fn seed_vm_mode_disks_from_installed_bases(
    _disk_dir: &Path,
    _base_root: &Path,
    _artifact_sha256: &str,
    _seed: InstalledVmModeDiskSeedSpec<'_>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "operator-installed VM bases are supported only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn seed_vm_mode_disks_from_installed_bases_with<F>(
    disk_dir: &Path,
    base_root: &Path,
    artifact_sha256: &str,
    seed: InstalledVmModeDiskSeedSpec<'_>,
    create_overlays: F,
    required_owner: u32,
) -> std::io::Result<()>
where
    F: FnOnce(&[crate::agent::DiskOverlaySpec]) -> crate::Result<()>,
{
    validate_artifact_sha256(artifact_sha256)?;
    validate_operator_base_root(base_root, required_owner)?;
    let release = expected_installed_release(artifact_sha256, seed)?;
    validate_installed_release(base_root, &release, required_owner)?;

    let mut overlay_specs = Vec::with_capacity(2);
    let mut overlay_paths = Vec::with_capacity(2);
    let sequence = COW_BASE_STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    for definition in installed_disk_definitions(seed) {
        let Some((template, source_size)) = definition.template.zip(definition.source_size) else {
            if definition.template.is_some() != definition.source_size.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} template path and source size must both be present",
                        definition.disk_type
                    ),
                ));
            }
            continue;
        };
        let logical_size = disk_target_size(
            source_size,
            definition.logical_size,
            definition.size_gb_override,
        )?;
        let expected = CowBaseMetadata {
            artifact_sha256: artifact_sha256.to_string(),
            disk_type: definition.disk_type.to_string(),
            source_template: template.to_string(),
            source_size,
            logical_size,
        };
        let base_dir = base_root
            .join(artifact_sha256)
            .join(format!("{}-{logical_size}", definition.disk_type));
        validate_operator_base_path(base_root, &base_dir, required_owner)?;
        let base = validate_cow_base_owned(&base_dir, &expected, required_owner)?;
        let destination = disk_dir.join(definition.destination);
        let final_overlay = destination.with_extension("qcow2");
        let staging_overlay = disk_dir.join(format!(
            ".{}.installing-{}-{sequence}",
            final_overlay
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("disk.qcow2"),
            std::process::id()
        ));
        let _ = std::fs::remove_file(&staging_overlay);
        overlay_specs.push((staging_overlay.clone(), base, DiskFormat::Raw));
        overlay_paths.push((staging_overlay, final_overlay, destination));
    }
    if overlay_specs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "VM-mode artifact contains no installed disk templates",
        ));
    }
    if let Err(error) = create_overlays(&overlay_specs) {
        for (staging, _, _) in &overlay_paths {
            let _ = std::fs::remove_file(staging);
        }
        return Err(std::io::Error::other(format!(
            "create private overlays from installed VM bases: {error}"
        )));
    }
    for (staging, final_overlay, destination) in overlay_paths {
        let _ = std::fs::remove_file(&destination);
        let _ = std::fs::remove_file(destination.with_extension("formatted"));
        let _ = std::fs::remove_file(&final_overlay);
        std::fs::rename(staging, final_overlay)?;
        std::fs::write(destination.with_extension("formatted"), b"1")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct InstalledDiskDefinition<'a> {
    disk_type: &'static str,
    destination: &'static str,
    template: Option<&'a str>,
    source_size: Option<u64>,
    logical_size: Option<u64>,
    size_gb_override: Option<u64>,
}

#[cfg(target_os = "linux")]
fn installed_disk_definitions(
    seed: InstalledVmModeDiskSeedSpec<'_>,
) -> [InstalledDiskDefinition<'_>; 2] {
    [
        InstalledDiskDefinition {
            disk_type: "overlay",
            destination: OVERLAY_DISK_FILENAME,
            template: seed.overlay_template,
            source_size: seed.overlay_source_size,
            logical_size: seed.overlay_logical_size,
            size_gb_override: seed.overlay_gb,
        },
        InstalledDiskDefinition {
            disk_type: "storage",
            destination: STORAGE_DISK_FILENAME,
            template: seed.storage_template,
            source_size: seed.storage_source_size,
            logical_size: seed.storage_logical_size,
            size_gb_override: seed.storage_gb,
        },
    ]
}

#[cfg(target_os = "linux")]
fn expected_installed_release(
    artifact_sha256: &str,
    seed: InstalledVmModeDiskSeedSpec<'_>,
) -> std::io::Result<InstalledVmBaseRelease> {
    let mut disks = Vec::with_capacity(2);
    for definition in installed_disk_definitions(seed) {
        let Some((template, source_size)) = definition.template.zip(definition.source_size) else {
            if definition.template.is_some() != definition.source_size.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} template path and source size must both be present",
                        definition.disk_type
                    ),
                ));
            }
            continue;
        };
        disks.push(CowBaseMetadata {
            artifact_sha256: artifact_sha256.to_string(),
            disk_type: definition.disk_type.to_string(),
            source_template: template.to_string(),
            source_size,
            logical_size: disk_target_size(
                source_size,
                definition.logical_size,
                definition.size_gb_override,
            )?,
        });
    }
    if disks.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "VM-mode artifact contains no disk templates",
        ));
    }
    Ok(InstalledVmBaseRelease {
        version: 1,
        artifact_sha256: artifact_sha256.to_string(),
        disks,
    })
}

#[cfg(target_os = "linux")]
fn installed_release_path(base_root: &Path, release: &InstalledVmBaseRelease) -> PathBuf {
    let variants = release
        .disks
        .iter()
        .map(|disk| format!("{}-{}", disk.disk_type, disk.logical_size))
        .collect::<Vec<_>>()
        .join("-");
    base_root
        .join(&release.artifact_sha256)
        .join(format!("release-{variants}.json"))
}

/// Build all immutable bases first, then create both private overlays in one
/// libkrun load. A missing/corrupt base is a hard error; only an unavailable
/// qcow2 implementation falls back to the existing sparse-copy behavior.
#[cfg(target_os = "linux")]
fn try_seed_vm_mode_disks_cow<F>(
    disk_dir: &Path,
    cache_dir: &Path,
    base_cache_root: &Path,
    artifact_sha256: &str,
    seed: VmModeDiskSeedSpec<'_>,
    create_overlays: F,
) -> std::io::Result<bool>
where
    F: FnOnce(&[crate::agent::DiskOverlaySpec]) -> crate::Result<()>,
{
    validate_artifact_sha256(artifact_sha256)?;
    let definitions = [
        (
            "overlay",
            seed.overlay_template,
            disk_dir.join(OVERLAY_DISK_FILENAME),
            seed.overlay_logical_size,
            seed.overlay_gb,
        ),
        (
            "storage",
            seed.storage_template,
            disk_dir.join(STORAGE_DISK_FILENAME),
            seed.storage_logical_size,
            seed.storage_gb,
        ),
    ];

    let mut overlay_specs = Vec::with_capacity(2);
    let mut overlay_paths = Vec::with_capacity(2);
    for (disk_type, template, dest, logical_size, size_gb_override) in &definitions {
        let Some(template) = template else {
            continue;
        };
        let source = resolve_template_in_cache(cache_dir, template)?;
        let source_size = std::fs::metadata(&source)
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("VM-mode template {}: {error}", source.display()),
                )
            })?
            .len();
        let target_size = disk_target_size(source_size, *logical_size, *size_gb_override)?;
        let base = prepare_cow_base(
            base_cache_root,
            artifact_sha256,
            disk_type,
            template,
            &source,
            source_size,
            target_size,
        )?;
        let overlay = dest.with_extension("qcow2");
        let _ = std::fs::remove_file(dest);
        let _ = std::fs::remove_file(dest.with_extension("formatted"));
        let _ = std::fs::remove_file(&overlay);
        overlay_specs.push((overlay.clone(), base, DiskFormat::Raw));
        overlay_paths.push(overlay);
    }

    if overlay_specs.is_empty() {
        return Ok(false);
    }

    if let Err(error) = create_overlays(&overlay_specs) {
        for overlay in &overlay_paths {
            let _ = std::fs::remove_file(overlay);
        }
        tracing::warn!(
            %error,
            "VM-mode qcow2 overlay creation unavailable; falling back to sparse disk copies"
        );
        return Ok(false);
    }

    for (_, template, dest, _, size_gb_override) in definitions {
        if template.is_some() {
            std::fs::write(dest.with_extension("formatted"), b"1")?;
        } else {
            seed_one_disk(cache_dir, None, &dest, None, size_gb_override)?;
        }
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn validate_artifact_sha256(digest: &str) -> std::io::Result<()> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "artifact SHA-256 must be 64 lowercase hexadecimal characters",
    ))
}

#[cfg(target_os = "linux")]
fn disk_target_size(
    source_size: u64,
    logical_size: Option<u64>,
    size_gb_override: Option<u64>,
) -> std::io::Result<u64> {
    let requested_size = size_gb_override
        .map(|gb| {
            gb.checked_mul(BYTES_PER_GIB).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "disk size overflow")
            })
        })
        .transpose()?;
    Ok([Some(source_size), logical_size, requested_size]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(source_size))
}

/// Return one immutable normalized raw base, creating it atomically on the
/// first request. The final directory is the completion marker: readers can
/// never observe a base without matching metadata.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn prepare_cow_base(
    base_cache_root: &Path,
    artifact_sha256: &str,
    disk_type: &str,
    source_template: &str,
    source: &Path,
    source_size: u64,
    logical_size: u64,
) -> std::io::Result<PathBuf> {
    validate_artifact_sha256(artifact_sha256)?;
    std::fs::create_dir_all(base_cache_root)?;
    std::fs::set_permissions(base_cache_root, std::fs::Permissions::from_mode(0o711))?;
    let digest_dir = base_cache_root.join(artifact_sha256);
    std::fs::create_dir_all(&digest_dir)?;
    std::fs::set_permissions(&digest_dir, std::fs::Permissions::from_mode(0o711))?;

    let key = format!("{disk_type}-{logical_size}");
    let final_dir = digest_dir.join(&key);
    let lock_path = digest_dir.join(format!("{key}.lock"));
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("open COW base lock {}: {error}", lock_path.display()),
            )
        })?;
    lock_file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("secure COW base lock {}: {error}", lock_path.display()),
            )
        })?;
    let lock_result = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if lock_result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let expected = CowBaseMetadata {
        artifact_sha256: artifact_sha256.to_string(),
        disk_type: disk_type.to_string(),
        source_template: source_template.to_string(),
        source_size,
        logical_size,
    };
    if final_dir.exists() {
        return validate_cow_base(&final_dir, &expected);
    }

    let sequence = COW_BASE_STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staging_dir = digest_dir.join(format!(".{key}.tmp-{}-{sequence}", std::process::id()));
    let result = (|| {
        std::fs::create_dir(&staging_dir)?;
        let base = staging_dir.join("base.raw");
        crate::disk_utils::clone_or_copy_file(source, &base)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let file = std::fs::OpenOptions::new().write(true).open(&base)?;
        file.set_len(logical_size)?;
        file.sync_all()?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o444))?;

        let metadata_bytes = serde_json::to_vec_pretty(&expected)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let metadata_path = staging_dir.join("metadata.json");
        let mut metadata_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&metadata_path)?;
        use std::io::Write as _;
        metadata_file.write_all(&metadata_bytes)?;
        metadata_file.sync_all()?;
        std::fs::set_permissions(&metadata_path, std::fs::Permissions::from_mode(0o444))?;
        std::fs::set_permissions(&staging_dir, std::fs::Permissions::from_mode(0o555))?;
        std::fs::rename(&staging_dir, &final_dir)?;
        validate_cow_base(&final_dir, &expected)
    })();
    if result.is_err() && staging_dir.exists() {
        let _ = std::fs::set_permissions(&staging_dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&staging_dir);
    }
    result
}

#[cfg(target_os = "linux")]
fn validate_cow_base(base_dir: &Path, expected: &CowBaseMetadata) -> std::io::Result<PathBuf> {
    let base = base_dir.join("base.raw");
    let metadata_path = base_dir.join("metadata.json");
    let metadata_bytes = std::fs::read(&metadata_path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "read COW base metadata {} for {}-{}: {error}",
                metadata_path.display(),
                expected.disk_type,
                expected.logical_size
            ),
        )
    })?;
    let actual: CowBaseMetadata = serde_json::from_slice(&metadata_bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "corrupt COW base metadata {}: {error}",
                metadata_path.display()
            ),
        )
    })?;
    if &actual != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("COW base metadata mismatch: {}", base_dir.display()),
        ));
    }
    let file_metadata = std::fs::metadata(&base).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "inspect COW base {} for {}-{}: {error}",
                base.display(),
                expected.disk_type,
                expected.logical_size
            ),
        )
    })?;
    if !file_metadata.is_file() || file_metadata.len() != expected.logical_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("COW base has an unsafe size or type: {}", base.display()),
        ));
    }
    if file_metadata.permissions().mode() & 0o222 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("COW base is writable: {}", base.display()),
        ));
    }
    base.canonicalize().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("canonicalize COW base {}: {error}", base.display()),
        )
    })
}

#[cfg(target_os = "linux")]
fn prepare_operator_base_root(base_root: &Path) -> std::io::Result<()> {
    prepare_operator_base_root_owned(base_root, 0)
}

#[cfg(target_os = "linux")]
fn prepare_operator_base_root_owned(base_root: &Path, required_owner: u32) -> std::io::Result<()> {
    if !base_root.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "shared VM base directory must be absolute",
        ));
    }
    validate_operator_base_ancestors(base_root, required_owner)?;

    // Find the nearest existing ancestor without following a symlink. The
    // complete existing chain was validated above; retaining the missing
    // components lets us publish them one at a time with a private create mode.
    let mut missing = Vec::new();
    let mut cursor = base_root;
    loop {
        match std::fs::symlink_metadata(cursor) {
            Ok(_) => {
                if cursor == base_root {
                    // Reject an existing symlink or unsafe root before chmod
                    // could follow it and mutate a different target.
                    validate_operator_base_node(cursor, true, required_owner)?;
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "shared VM base directory has no existing ancestor: {}",
                            base_root.display()
                        ),
                    )
                })?;
            }
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "inspect shared VM base directory {}: {error}",
                        cursor.display()
                    ),
                ));
            }
        }
    }

    for path in missing.iter().rev() {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            // Another trusted installer may have won this component. Validate
            // it exactly as an existing node before applying publication mode.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "create shared VM base directory component {}: {error}",
                        path.display()
                    ),
                ));
            }
        }
        validate_operator_base_node(path, true, required_owner)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o711)).map_err(
            |error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "publish shared VM base directory component {}: {error}",
                        path.display()
                    ),
                )
            },
        )?;
        validate_operator_base_node(path, true, required_owner)?;
    }

    if missing.is_empty() {
        std::fs::set_permissions(base_root, std::fs::Permissions::from_mode(0o711)).map_err(
            |error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "publish shared VM base directory {}: {error}",
                        base_root.display()
                    ),
                )
            },
        )?;
    }
    validate_operator_base_root(base_root, required_owner)
}

#[cfg(target_os = "linux")]
fn publish_installed_release(
    base_root: &Path,
    release: &InstalledVmBaseRelease,
    required_owner: u32,
) -> std::io::Result<()> {
    let path = installed_release_path(base_root, release);
    if path.exists() {
        return validate_installed_release(base_root, release, required_owner);
    }
    let digest_dir = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed VM release marker has no parent",
        )
    })?;
    let sequence = COW_BASE_STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staging = digest_dir.join(format!(".release.tmp-{}-{sequence}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(release)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staging)?;
        use std::io::Write as _;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o444))?;
        match std::fs::hard_link(&staging, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        std::fs::remove_file(&staging)?;
        validate_installed_release(base_root, release, required_owner)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    result
}

#[cfg(target_os = "linux")]
fn validate_installed_release(
    base_root: &Path,
    expected: &InstalledVmBaseRelease,
    required_owner: u32,
) -> std::io::Result<()> {
    let path = installed_release_path(base_root, expected);
    let variant = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown release variant");
    let digest_dir = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installed VM release marker has no parent",
        )
    })?;
    let digest_metadata =
        validate_operator_base_node(digest_dir, true, required_owner).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "validate digest directory {} for VM base release {variant}: {error}",
                    digest_dir.display()
                ),
            )
        })?;
    if !digest_metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid VM base digest directory: {}", digest_dir.display()),
        ));
    }
    validate_operator_base_node(&path, false, required_owner).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "validate VM base release marker {variant} at {}: {error}",
                path.display()
            ),
        )
    })?;
    let marker_bytes = std::fs::read(&path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "read VM base release marker {variant} at {}: {error}",
                path.display()
            ),
        )
    })?;
    let actual: InstalledVmBaseRelease =
        serde_json::from_slice(&marker_bytes).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("corrupt VM base release marker {}: {error}", path.display()),
            )
        })?;
    if &actual != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "VM base release marker mismatch for {variant}: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_operator_base_root(base_root: &Path, required_owner: u32) -> std::io::Result<()> {
    if !base_root.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "shared VM base directory must be absolute",
        ));
    }
    validate_operator_base_ancestors(base_root, required_owner)?;
    let metadata = validate_operator_base_node(base_root, true, required_owner)?;
    if !metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "shared VM base root is not a directory: {}",
                base_root.display()
            ),
        ));
    }
    let canonical = base_root.canonicalize().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "canonicalize shared VM base root {}: {error}",
                base_root.display()
            ),
        )
    })?;
    if canonical != base_root {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "shared VM base root must be canonical and may not be a symlink: {}",
                base_root.display()
            ),
        ));
    }
    Ok(())
}

/// Validate every existing directory above the operator store. A root-owned
/// sticky directory (for example `/tmp`) is the sole writable ancestor that is
/// safe: sticky semantics prevent another uid from replacing the store entry.
#[cfg(target_os = "linux")]
fn validate_operator_base_ancestors(base_root: &Path, required_owner: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    for ancestor in base_root.ancestors().skip(1) {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "inspect shared VM base ancestor {}: {error}",
                        ancestor.display()
                    ),
                ));
            }
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "shared VM base ancestor is not a real directory: {}",
                    ancestor.display()
                ),
            ));
        }
        let mode = metadata.permissions().mode();
        let trusted_owner = metadata.uid() == required_owner || metadata.uid() == 0;
        if !trusted_owner {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "shared VM base ancestor has uid {}, expected {required_owner} or root: {}",
                    metadata.uid(),
                    ancestor.display()
                ),
            ));
        }
        let safe_sticky_directory = metadata.uid() == 0 && mode & 0o1000 != 0;
        if mode & 0o022 != 0 && !safe_sticky_directory {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "shared VM base ancestor has unsafe write permissions: {}",
                    ancestor.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_operator_base_path(
    base_root: &Path,
    base_dir: &Path,
    required_owner: u32,
) -> std::io::Result<()> {
    let digest_dir = base_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "base directory has no parent",
        )
    })?;
    for path in [digest_dir, base_dir] {
        let metadata = validate_operator_base_node(path, true, required_owner)?;
        if !metadata.file_type().is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("shared VM base path is not a directory: {}", path.display()),
            ));
        }
    }
    let canonical = base_dir.canonicalize().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "canonicalize shared VM base path {}: {error}",
                base_dir.display()
            ),
        )
    })?;
    if !canonical.starts_with(base_root) || canonical != base_dir {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("shared VM base escapes its root: {}", base_dir.display()),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_operator_base_node(
    path: &Path,
    directory: bool,
    required_owner: u32,
) -> std::io::Result<std::fs::Metadata> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("inspect shared VM base node {}: {error}", path.display()),
        )
    })?;
    let expected_type = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !expected_type || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsafe shared VM base node type: {}", path.display()),
        ));
    }
    if metadata.uid() != required_owner {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "shared VM base node has uid {}, expected {required_owner}: {}",
                metadata.uid(),
                path.display()
            ),
        ));
    }
    let forbidden_write_bits = if directory { 0o022 } else { 0o222 };
    if metadata.permissions().mode() & forbidden_write_bits != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "shared VM base node has unsafe write permissions: {}",
                path.display()
            ),
        ));
    }
    Ok(metadata)
}

#[cfg(target_os = "linux")]
fn validate_cow_base_owned(
    base_dir: &Path,
    expected: &CowBaseMetadata,
    required_owner: u32,
) -> std::io::Result<PathBuf> {
    let metadata_path = base_dir.join("metadata.json");
    let base = base_dir.join("base.raw");
    validate_operator_base_node(&metadata_path, false, required_owner)?;
    validate_operator_base_node(&base, false, required_owner)?;
    validate_cow_base(base_dir, expected)
}

/// Sparse-copy one packed template into `dest`, grow it to the largest of its copied
/// size / the source's logical size / any requested size, and mark it formatted
/// (the copy carries the source's ext4; the guest grows it with resize2fs). With no
/// template, write an empty sparse disk for the guest to format (no formatted marker).
fn seed_one_disk(
    cache_dir: &Path,
    template: Option<&str>,
    dest: &Path,
    logical_size: Option<u64>,
    size_gb_override: Option<u64>,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(dest);
    let formatted_marker = dest.with_extension("formatted");

    let Some(rel) = template else {
        // No template (rare for VM mode): an empty sparse disk the guest formats.
        let _ = std::fs::remove_file(&formatted_marker);
        let size = size_gb_override
            .map(|gb| gb * BYTES_PER_GIB)
            .unwrap_or(512 * 1024 * 1024);
        std::fs::File::create(dest)?.set_len(size)?;
        return Ok(());
    };

    let src = resolve_template_in_cache(cache_dir, rel)?;
    if !src.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("VM-mode template not found: {}", src.display()),
        ));
    }
    crate::disk_utils::clone_or_copy_file(&src, dest)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Grow back to the logical/requested size (set_len extends sparsely; the guest
    // resize2fs expands the ext4 to fill it at boot).
    let copied = std::fs::metadata(dest)?.len();
    let target = [
        Some(copied),
        logical_size,
        size_gb_override.map(|gb| gb * BYTES_PER_GIB),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(copied);
    if target > copied {
        std::fs::OpenOptions::new()
            .write(true)
            .open(dest)?
            .set_len(target)?;
    }

    std::fs::write(&formatted_marker, b"")?;
    Ok(())
}

/// Resolve a pack template's relative path within `cache_dir`, rejecting anything
/// that isn't a plain in-tree path (no `..`, absolute, or other escaping component)
/// so a hostile pack manifest can't redirect the copy outside the cache.
fn resolve_template_in_cache(cache_dir: &Path, rel: &str) -> std::io::Result<PathBuf> {
    let rel_path = Path::new(rel);
    let safe = !rel.is_empty()
        && rel_path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
    if !safe {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid VM-mode template path: {rel:?}"),
        ));
    }
    Ok(cache_dir.join(rel_path))
}

/// Disk format version info (stored at `/.smolvm/version.json` in ext4 disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskVersion {
    /// Format version (currently: 1).
    pub format_version: u32,

    /// Timestamp when the disk was created.
    pub created_at: String,

    /// Digest of the base rootfs image.
    pub base_digest: String,

    /// smolvm version that created this disk.
    pub smolvm_version: String,
}

impl DiskVersion {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new disk version with current settings.
    pub fn new(base_digest: impl Into<String>) -> Self {
        Self {
            format_version: Self::CURRENT_VERSION,
            created_at: crate::util::current_timestamp().to_string(),
            base_digest: base_digest.into(),
            smolvm_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Check if this version is compatible with the current smolvm.
    pub fn is_compatible(&self) -> bool {
        self.format_version <= Self::CURRENT_VERSION
    }
}

/// Shared disk implementation for storage and overlay disks.
#[derive(Debug, Clone)]
pub struct VmDisk<K> {
    path: PathBuf,
    size_bytes: u64,
    format: DiskFormat,
    _kind: PhantomData<K>,
}

impl<K: DiskType> VmDisk<K> {
    /// Get the default path for the disk.
    pub fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| {
                Error::storage(
                    format!("resolve {} path", K::NAME),
                    "could not determine data directory",
                )
            })?;

        Ok(data_dir.join("smolvm").join(K::DEFAULT_FILENAME))
    }

    /// Open or create the disk of the default size at the default location.
    pub fn open_or_create() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_or_create_at(&path, K::DEFAULT_SIZE_GIB)
    }

    /// Open or create the disk of the custom size at a custom path.
    pub fn open_or_create_at(path: &Path, size_gb: u64) -> Result<Self> {
        if size_gb == 0 {
            return Err(Error::config(
                format!("validate {} size", K::NAME),
                "disk size must be greater than 0 GiB",
            ));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let size_bytes = size_gb * BYTES_PER_GIB;

        if path.exists() {
            // An existing disk keeps whatever size it was created at, so a
            // machine whose data dir outlived a delete would boot the previous,
            // smaller disk while its record reports the requested size. Grow it
            // to the request instead (sparse, so it costs nothing); the guest's
            // resize2fs expands the filesystem into the new space at boot. A
            // disk that is already larger is left alone — callers that open with
            // the default size must not shrink a machine's storage.
            let mut on_disk = std::fs::metadata(path)?.len();
            if on_disk < size_bytes {
                expand_disk::<K>(path, size_gb)?;
                on_disk = std::fs::metadata(path)?.len();
            }
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes: on_disk,
                format: DiskFormat::Raw,
                _kind: PhantomData,
            })
        } else {
            disk_utils::create_sparse_disk::<K>(path, size_bytes)?;
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes,
                format: DiskFormat::Raw,
                _kind: PhantomData,
            })
        }
    }

    /// Open an existing disk image with an explicit on-disk format, without
    /// creating or formatting it. Used for fork-clone qcow2 overlays, which are
    /// created up front by the fork path and inherit the backing disk's
    /// already-formatted filesystem.
    pub fn open_existing_with_format(path: &Path, format: DiskFormat) -> Result<Self> {
        let metadata = std::fs::metadata(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            size_bytes: metadata.len(),
            format,
            _kind: PhantomData,
        })
    }

    /// Open the disk for a fresh (non-clone) VM. On Linux at this disk type's
    /// DEFAULT size, when the shipped template has already been sized to the
    /// default virtual size **at install time**, create an instant qcow2
    /// copy-on-write overlay over the read-only template (O(metadata), no byte
    /// copy) — so N concurrent boots don't thrash the host disk the way N full
    /// template copies do. Anything else (a custom size, a pre-existing disk, a
    /// not-yet-sized legacy template, non-Linux, or an overlay-create failure)
    /// falls back to the raw create + format-time copy. The template is treated
    /// as immutable here: sizing it is an install-time concern (see
    /// `scripts/install.sh`), never a per-boot mutation of a shared file.
    pub fn open_or_overlay_at(raw_path: &Path, size_gb: u64) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if !raw_path.exists() && size_gb == K::DEFAULT_SIZE_GIB {
            let size_bytes = size_gb * BYTES_PER_GIB;
            // Only overlay when the template already presents the full virtual
            // size. A legacy/too-small template would make the overlay inherit an
            // undersized device, so degrade to the copy path rather than mutate
            // the shared template.
            if Self::template_at_least(size_bytes) {
                let overlay_path = raw_path.with_extension(DiskFormat::Qcow2.extension());
                match Self::create_overlay_from_template(&overlay_path, size_bytes) {
                    Ok(disk) => return Ok(disk),
                    Err(error) => {
                        tracing::warn!(
                            disk_type = K::NAME, %error,
                            "qcow2 overlay create failed; falling back to raw template copy"
                        );
                    }
                }
            }
        }
        Self::open_or_create_at(raw_path, size_gb)
    }

    /// True if a disk template exists and already presents at least `size_bytes`
    /// of virtual size (sized at install). Used to decide whether the fast qcow2
    /// overlay path is safe without ever mutating the shared template.
    #[cfg(target_os = "linux")]
    fn template_at_least(size_bytes: u64) -> bool {
        Self::template_path()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len() >= size_bytes)
            .unwrap_or(false)
    }

    /// Create a `.qcow2` CoW overlay backed by the read-only template instead of
    /// copying it. The overlay inherits the backing file's VIRTUAL size; the
    /// template is sized to the default at install time (see
    /// `scripts/install.sh`) while its ext4 stays 512 MiB, so the guest grows the
    /// inherited filesystem with resize2fs at boot, exactly as on the copy path.
    /// The template is opened read-only and never mutated — if it is not yet
    /// sized to `size_bytes`, this refuses (the caller falls back to the copy
    /// path) rather than truncate a shared file under concurrent boots. Marks the
    /// disk formatted so it is never reformatted (the overlay shares the
    /// template's filesystem). Linux only; called only via [`Self::open_or_overlay_at`].
    #[cfg(target_os = "linux")]
    fn create_overlay_from_template(overlay_path: &Path, size_bytes: u64) -> Result<Self> {
        let template = Self::template_path()
            .ok_or_else(|| Error::storage("overlay from template", "no disk template found"))?;

        // The template must already present the full virtual size (install-time
        // sizing). Refuse rather than mutate a shared file under concurrent boots.
        let template_len = std::fs::metadata(&template)
            .map_err(|e| Error::storage("read template size", e.to_string()))?
            .len();
        if template_len < size_bytes {
            return Err(Error::storage(
                "overlay from template",
                format!("template virtual size {template_len} < required {size_bytes}; not sized at install"),
            ));
        }

        if let Some(parent) = overlay_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // The backing path is written verbatim into the overlay header, so it
        // must be absolute (canonicalized).
        let base = template
            .canonicalize()
            .map_err(|e| Error::storage("canonicalize template", e.to_string()))?;
        crate::agent::create_disk_overlays(&[(overlay_path.to_path_buf(), base, DiskFormat::Raw)])?;

        let disk = Self {
            path: overlay_path.to_path_buf(),
            size_bytes,
            format: DiskFormat::Qcow2,
            _kind: PhantomData,
        };
        disk.mark_formatted()?;
        Ok(disk)
    }

    /// Pre-format the disk with ext4 on the host.
    ///
    /// This tries multiple approaches in order:
    /// 1. Copy from pre-formatted template (no dependencies, fastest)
    /// 2. Format with mkfs.ext4 (requires e2fsprogs)
    ///
    /// The template approach eliminates the e2fsprogs dependency for end users.
    pub fn ensure_formatted(&self) -> Result<()> {
        if self.format == DiskFormat::Qcow2 {
            // A qcow2 CoW overlay inherits its backing disk's already-formatted
            // filesystem; formatting it would write a fresh fs into the overlay
            // and diverge from the backing image.
            return Ok(());
        }

        if !self.needs_format() {
            tracing::debug!(
                path = %self.path.display(),
                disk_type = K::NAME,
                "disk already formatted"
            );
            return Ok(());
        }

        if let Some(template_path) = Self::template_path() {
            disk_utils::copy_disk_from_template::<K>(&self.path, self.size_bytes, &template_path)?;
        } else {
            disk_utils::format_disk_with_mkfs::<K>(&self.path)?;
        }

        self.mark_formatted()
    }

    /// Get the path to the disk image.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the on-disk image format (raw, or qcow2 for fork-clone overlays).
    pub fn format(&self) -> DiskFormat {
        self.format
    }

    /// Get the disk size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Get the disk size in GiB.
    pub fn size_gib(&self) -> u64 {
        self.size_bytes / BYTES_PER_GIB
    }

    /// Check if the disk needs to be formatted.
    ///
    /// Fast path: if the format marker and the disk file both exist, the disk
    /// was formatted successfully, so skip the expensive `file` command check.
    pub fn needs_format(&self) -> bool {
        if !self.disk_marker_path().exists() {
            return true;
        }

        if !self.path.exists() {
            let marker_path = self.disk_marker_path();
            if let Err(error) = std::fs::remove_file(&marker_path) {
                tracing::warn!(
                    path = %marker_path.display(),
                    disk_type = K::NAME,
                    %error,
                    "failed to remove stale disk marker"
                );
            }
            return true;
        }

        false
    }

    /// Mark a disk as formatted by creating its marker file.
    pub fn mark_formatted(&self) -> Result<()> {
        std::fs::write(self.disk_marker_path(), "1")?;
        Ok(())
    }

    /// Delete a disk image and its marker file.
    pub fn delete(&self) -> Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }

        let marker_path = self.disk_marker_path();
        if marker_path.exists() {
            std::fs::remove_file(marker_path)?;
        }
        Ok(())
    }

    /// Find a pre-formatted disk template.
    ///
    /// Searches `~/.smolvm/` then the executable's directory, accepting either
    /// the plain file or a `.zst` archive that is expanded to a sparse file on
    /// first use — releases ship the compressed form. Shared with the pack
    /// crate so both paths agree on where templates live and how they expand.
    fn template_path() -> Option<PathBuf> {
        let found = smolvm_pack::assets::find_existing_template(K::TEMPLATE_FILENAME);
        if let Some(path) = &found {
            tracing::debug!(
                path = %path.display(),
                disk_type = K::NAME,
                "found disk template"
            );
        }
        found
    }

    /// Get the path to the format marker file for a disk.
    fn disk_marker_path(&self) -> PathBuf {
        self.path.with_extension("formatted")
    }
}

impl VmDisk<Storage> {
    /// Open or create the storage disk at the default location with a custom size.
    pub fn open_or_create_with_size(size_gb: u64) -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_or_create_at(&path, size_gb)
    }
}

// ============================================================================
// Storage Disk
// ============================================================================

/// Shared storage disk for OCI layers.
///
/// This is a sparse raw disk image that the helper VM mounts to store
/// OCI image layers and overlay filesystems.
///
/// # Directory Structure (inside ext4)
///
/// ```text
/// /
/// ├── .smolvm_formatted    # Marker file
/// ├── layers/              # Extracted OCI layers (content-addressed)
/// │   └── sha256:{digest}/ # Each layer as a directory
/// ├── configs/             # OCI image configs
/// │   └── {digest}.json
/// ├── overlays/            # Workload overlay directories
/// │   └── {workload_id}/
/// │       ├── upper/       # Writable layer
/// │       ├── work/        # Overlay work directory
/// │       └── merged/      # Mount point (optional)
/// └── manifests/           # Cached image manifests
///     └── {image_ref}.json
/// ```
pub type StorageDisk = VmDisk<Storage>;

// ============================================================================
// Overlay Disk
// ============================================================================

/// Persistent rootfs overlay disk.
///
/// A sparse ext4 disk image used as the upper layer of an overlayfs
/// on top of the initramfs. Changes to the root filesystem (e.g.,
/// `apk add git`) persist across VM reboots.
///
/// The overlay is set up by the agent's `setup_persistent_rootfs()`
/// function early in boot, before the vsock listener starts.
pub type OverlayDisk = VmDisk<Overlay>;

/// Expand a disk image at an arbitrary path for a specific disk type.
pub fn expand_disk<D: DiskType>(path: &Path, new_size_gb: u64) -> Result<()> {
    disk_utils::expand_sparse_disk::<D>(path, new_size_gb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    const TEST_ARTIFACT_SHA256: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[cfg(target_os = "linux")]
    fn write_sparse_template(path: &Path, logical_size: u64, marker: &[u8]) {
        let mut file = std::fs::File::create(path).unwrap();
        use std::io::Write as _;
        file.write_all(marker).unwrap();
        file.set_len(logical_size).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn private_test_tempdir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vm_base_install_staging_is_private_and_inside_base_root() {
        let temp = private_test_tempdir();
        let base_root = temp.path().join("installed-bases");
        let owner = unsafe { libc::geteuid() };
        let staging = create_vm_base_install_staging_owned(&base_root, owner).unwrap();

        assert_eq!(staging.path().parent(), Some(base_root.as_path()));
        assert!(staging
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".smolvm-vm-base-install-")));
        assert_eq!(
            std::fs::metadata(staging.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&base_root).unwrap().permissions().mode() & 0o777,
            0o711
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn operator_base_creation_publishes_each_missing_component_as_0711() {
        let temp = private_test_tempdir();
        let existing = temp.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = existing.join("operator");
        let base_root = first.join("installed-bases");
        let owner = unsafe { libc::geteuid() };

        prepare_operator_base_root_owned(&base_root, owner).unwrap();

        assert_eq!(
            std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777,
            0o700,
            "the already-trusted ancestor is not republished"
        );
        for created in [&first, &base_root] {
            assert_eq!(
                std::fs::metadata(created).unwrap().permissions().mode() & 0o777,
                0o711,
                "every created component must be traversable independent of umask"
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn make_fake_overlays(specs: &[crate::agent::DiskOverlaySpec]) -> crate::Result<()> {
        for (overlay, _, _) in specs {
            let mut file = std::fs::File::create(overlay)?;
            use std::io::Write as _;
            file.write_all(b"QFI\xfb")?;
            file.set_len(256 * 1024)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn make_tree_removable(root: &Path) {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    make_tree_removable(&entry.path());
                }
            }
        }
        let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700));
    }

    #[cfg(target_os = "linux")]
    fn prepare_test_installed_release(
        temp: &tempfile::TempDir,
    ) -> (PathBuf, InstalledVmBaseRelease, u32) {
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let extracted = temp.path().join("operator-staging");
        let base_root = temp.path().join("installed-bases");
        std::fs::create_dir_all(&extracted).unwrap();
        write_sparse_template(&extracted.join("overlay.raw"), 1024 * 1024, b"root");
        prepare_cow_base(
            &base_root,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &extracted.join("overlay.raw"),
            1024 * 1024,
            2 * 1024 * 1024,
        )
        .unwrap();
        let release = expected_installed_release(
            TEST_ARTIFACT_SHA256,
            InstalledVmModeDiskSeedSpec {
                overlay_template: Some("overlay.raw"),
                overlay_source_size: Some(1024 * 1024),
                storage_template: None,
                storage_source_size: None,
                overlay_logical_size: Some(2 * 1024 * 1024),
                storage_logical_size: None,
                overlay_gb: None,
                storage_gb: None,
            },
        )
        .unwrap();
        (base_root, release, unsafe { libc::geteuid() })
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn operator_base_rejects_symlinked_and_untrusted_paths() {
        use std::os::unix::fs::symlink;

        let temp = private_test_tempdir();
        let owner = unsafe { libc::geteuid() };
        let real_parent = temp.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = temp.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let through_symlink = linked_parent.join("bases");
        let error = prepare_operator_base_root_owned(&through_symlink, owner).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("ancestor"));
        assert!(error
            .to_string()
            .contains(&linked_parent.display().to_string()));

        let real_root = temp.path().join("real-root");
        std::fs::create_dir(&real_root).unwrap();
        std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let linked_root = temp.path().join("linked-root");
        symlink(&real_root, &linked_root).unwrap();
        let error = prepare_operator_base_root_owned(&linked_root, owner).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error
            .to_string()
            .contains(&linked_root.display().to_string()));
        assert_eq!(
            std::fs::metadata(&real_root).unwrap().permissions().mode() & 0o777,
            0o700,
            "rejecting a symlinked root must not chmod its target"
        );

        let trusted_root = temp.path().join("owned-root");
        std::fs::create_dir(&trusted_root).unwrap();
        let wrong_owner = if owner == u32::MAX {
            owner - 1
        } else {
            owner + 1
        };
        let error = validate_operator_base_root(&trusted_root, wrong_owner).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("expected"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn installed_release_errors_identify_variant_and_marker_path() {
        let temp = private_test_tempdir();
        let (base_root, release, owner) = prepare_test_installed_release(&temp);
        publish_installed_release(&base_root, &release, owner).unwrap();

        let different_size = expected_installed_release(
            TEST_ARTIFACT_SHA256,
            InstalledVmModeDiskSeedSpec {
                overlay_template: Some("overlay.raw"),
                overlay_source_size: Some(1024 * 1024),
                storage_template: None,
                storage_source_size: None,
                overlay_logical_size: Some(3 * 1024 * 1024),
                storage_logical_size: None,
                overlay_gb: None,
                storage_gb: None,
            },
        )
        .unwrap();
        let missing_path = installed_release_path(&base_root, &different_size);
        let error = validate_installed_release(&base_root, &different_size, owner).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains("release-overlay-3145728.json"));
        assert!(error
            .to_string()
            .contains(&missing_path.display().to_string()));

        let marker = installed_release_path(&base_root, &release);
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mismatched = InstalledVmBaseRelease {
            version: release.version + 1,
            artifact_sha256: release.artifact_sha256.clone(),
            disks: release.disks.clone(),
        };
        std::fs::write(&marker, serde_json::to_vec_pretty(&mismatched).unwrap()).unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o444)).unwrap();
        let error = validate_installed_release(&base_root, &release, owner).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("release marker mismatch"));
        assert!(error.to_string().contains(&marker.display().to_string()));
        make_tree_removable(&base_root);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn installed_release_publication_is_idempotent_and_concurrent() {
        use std::sync::{Arc, Barrier};

        let temp = private_test_tempdir();
        let (base_root, release, owner) = prepare_test_installed_release(&temp);
        let release = Arc::new(release);
        let barrier = Arc::new(Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let base_root = base_root.clone();
            let release = Arc::clone(&release);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                publish_installed_release(&base_root, &release, owner)
            }));
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        publish_installed_release(&base_root, &release, owner).unwrap();
        let marker = installed_release_path(&base_root, &release);
        assert_eq!(
            serde_json::from_slice::<InstalledVmBaseRelease>(&std::fs::read(&marker).unwrap())
                .unwrap(),
            *release
        );
        assert_eq!(
            std::fs::read_dir(marker.parent().unwrap())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".release.tmp-")))
                .count(),
            0
        );
        make_tree_removable(&base_root);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vm_mode_cow_uses_tiny_private_disks_and_one_immutable_base() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("shared-pack");
        let base_cache = temp.path().join("cow-bases");
        let first = temp.path().join("machine-a");
        let second = temp.path().join("machine-b");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        write_sparse_template(&cache.join("overlay.raw"), 2 * 1024 * 1024, b"root-a");
        write_sparse_template(&cache.join("storage.raw"), 1024 * 1024, b"data-a");

        for machine in [&first, &second] {
            assert!(try_seed_vm_mode_disks_cow(
                machine,
                &cache,
                &base_cache,
                TEST_ARTIFACT_SHA256,
                VmModeDiskSeedSpec {
                    artifact_sha256: Some(TEST_ARTIFACT_SHA256),
                    overlay_template: Some("overlay.raw"),
                    storage_template: Some("storage.raw"),
                    overlay_logical_size: Some(4 * 1024 * 1024),
                    storage_logical_size: Some(3 * 1024 * 1024),
                    overlay_gb: None,
                    storage_gb: None,
                },
                make_fake_overlays,
            )
            .unwrap());
            for disk in ["overlay.qcow2", "storage.qcow2"] {
                let metadata = std::fs::metadata(machine.join(disk)).unwrap();
                assert_eq!(metadata.len(), 256 * 1024, "private disk must stay tiny");
            }
            assert!(!machine.join(OVERLAY_DISK_FILENAME).exists());
            assert!(!machine.join(STORAGE_DISK_FILENAME).exists());
            assert!(machine.join("overlay.formatted").exists());
            assert!(machine.join("storage.formatted").exists());
        }

        assert_eq!(
            std::fs::metadata(&base_cache).unwrap().permissions().mode() & 0o777,
            0o711,
            "the uid-dropped VMM must be able to traverse the shared base store"
        );
        let base_root = base_cache.join(TEST_ARTIFACT_SHA256);
        assert_eq!(
            std::fs::metadata(&base_root).unwrap().permissions().mode() & 0o777,
            0o711,
            "the artifact digest directory must be traversable but non-listable"
        );
        let bases: Vec<_> = std::fs::read_dir(&base_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .collect();
        assert_eq!(bases.len(), 2, "one normalized base per disk type");
        for entry in &bases {
            let base = entry.path().join("base.raw");
            let metadata = std::fs::metadata(base).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o222, 0);
            use std::os::unix::fs::MetadataExt as _;
            assert!(
                metadata.blocks() * 512 < metadata.len() / 2,
                "restoring the logical tail must keep the immutable base sparse"
            );
        }

        std::fs::write(first.join("overlay.qcow2"), b"first-private").unwrap();
        assert_eq!(
            std::fs::read(second.join("overlay.qcow2")).unwrap()[..4],
            *b"QFI\xfb"
        );
        assert_eq!(
            std::fs::read(base_root.join("overlay-4194304/base.raw")).unwrap()[..6],
            *b"root-a"
        );

        std::fs::remove_dir_all(&first).unwrap();
        assert!(second.join("overlay.qcow2").exists());
        assert!(
            bases.iter().all(|entry| entry.path().exists()),
            "deleting a sibling must retain shared bases"
        );
        make_tree_removable(&cache);
        make_tree_removable(&base_cache);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn installed_vm_bases_back_two_private_user_stores_without_extraction() {
        use std::os::unix::fs::MetadataExt as _;

        let temp = private_test_tempdir();
        let extracted = temp.path().join("operator-staging");
        let base_root = temp.path().join("installed-bases");
        let first = temp.path().join("user-a");
        let second = temp.path().join("user-b");
        for path in [&extracted, &base_root, &first, &second] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::set_permissions(&base_root, std::fs::Permissions::from_mode(0o711)).unwrap();
        write_sparse_template(&extracted.join("overlay.raw"), 1024 * 1024, b"root");
        write_sparse_template(&extracted.join("storage.raw"), 512 * 1024, b"storage");
        let seed = InstalledVmModeDiskSeedSpec {
            overlay_template: Some("overlay.raw"),
            overlay_source_size: Some(1024 * 1024),
            storage_template: Some("storage.raw"),
            storage_source_size: Some(512 * 1024),
            overlay_logical_size: Some(4 * 1024 * 1024),
            storage_logical_size: Some(3 * 1024 * 1024),
            overlay_gb: None,
            storage_gb: None,
        };
        let expected_overlay = prepare_cow_base(
            &base_root,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &extracted.join("overlay.raw"),
            1024 * 1024,
            4 * 1024 * 1024,
        )
        .unwrap();
        let expected_storage = prepare_cow_base(
            &base_root,
            TEST_ARTIFACT_SHA256,
            "storage",
            "storage.raw",
            &extracted.join("storage.raw"),
            512 * 1024,
            3 * 1024 * 1024,
        )
        .unwrap();
        let owner = unsafe { libc::geteuid() };
        let release = expected_installed_release(TEST_ARTIFACT_SHA256, seed).unwrap();
        publish_installed_release(&base_root, &release, owner).unwrap();

        for machine in [&first, &second] {
            seed_vm_mode_disks_from_installed_bases_with(
                machine,
                &base_root,
                TEST_ARTIFACT_SHA256,
                seed,
                |specs| {
                    assert_eq!(specs.len(), 2);
                    assert_eq!(specs[0].1, expected_overlay);
                    assert_eq!(specs[1].1, expected_storage);
                    make_fake_overlays(specs)
                },
                owner,
            )
            .unwrap();
        }
        assert_ne!(
            std::fs::metadata(first.join("overlay.qcow2"))
                .unwrap()
                .ino(),
            std::fs::metadata(second.join("overlay.qcow2"))
                .unwrap()
                .ino()
        );
        assert!(!first.join("pack").exists());
        assert!(!second.join("pack").exists());
        std::fs::remove_dir_all(&first).unwrap();
        assert!(expected_overlay.exists());
        assert!(expected_storage.exists());
        make_tree_removable(&base_root);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn installed_vm_base_missing_or_writable_fails_without_copy_fallback() {
        let temp = private_test_tempdir();
        let extracted = temp.path().join("operator-staging");
        let base_root = temp.path().join("installed-bases");
        let machine = temp.path().join("user");
        for path in [&extracted, &base_root, &machine] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::set_permissions(&base_root, std::fs::Permissions::from_mode(0o711)).unwrap();
        write_sparse_template(&extracted.join("overlay.raw"), 1024 * 1024, b"root");
        let seed = InstalledVmModeDiskSeedSpec {
            overlay_template: Some("overlay.raw"),
            overlay_source_size: Some(1024 * 1024),
            storage_template: None,
            storage_source_size: None,
            overlay_logical_size: Some(2 * 1024 * 1024),
            storage_logical_size: None,
            overlay_gb: None,
            storage_gb: None,
        };
        let owner = unsafe { libc::geteuid() };
        let missing = seed_vm_mode_disks_from_installed_bases_with(
            &machine,
            &base_root,
            TEST_ARTIFACT_SHA256,
            seed,
            make_fake_overlays,
            owner,
        )
        .unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
        assert!(!machine.join("overlay.qcow2").exists());
        assert!(!machine.join(OVERLAY_DISK_FILENAME).exists());

        let base = prepare_cow_base(
            &base_root,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &extracted.join("overlay.raw"),
            1024 * 1024,
            2 * 1024 * 1024,
        )
        .unwrap();
        let release = expected_installed_release(TEST_ARTIFACT_SHA256, seed).unwrap();
        publish_installed_release(&base_root, &release, owner).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o644)).unwrap();
        let writable = seed_vm_mode_disks_from_installed_bases_with(
            &machine,
            &base_root,
            TEST_ARTIFACT_SHA256,
            seed,
            make_fake_overlays,
            owner,
        )
        .unwrap_err();
        assert_eq!(writable.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!machine.join("overlay.qcow2").exists());
        make_tree_removable(&base_root);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn installed_vm_base_validates_every_disk_before_mutating_machine_state() {
        let temp = private_test_tempdir();
        let extracted = temp.path().join("operator-staging");
        let base_root = temp.path().join("installed-bases");
        let machine = temp.path().join("user");
        for path in [&extracted, &base_root, &machine] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::set_permissions(&base_root, std::fs::Permissions::from_mode(0o711)).unwrap();
        write_sparse_template(&extracted.join("overlay.raw"), 1024 * 1024, b"root");
        write_sparse_template(&extracted.join("storage.raw"), 512 * 1024, b"storage");
        let seed = InstalledVmModeDiskSeedSpec {
            overlay_template: Some("overlay.raw"),
            overlay_source_size: Some(1024 * 1024),
            storage_template: Some("storage.raw"),
            storage_source_size: Some(512 * 1024),
            overlay_logical_size: Some(2 * 1024 * 1024),
            storage_logical_size: Some(3 * 1024 * 1024),
            overlay_gb: None,
            storage_gb: None,
        };
        prepare_cow_base(
            &base_root,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &extracted.join("overlay.raw"),
            1024 * 1024,
            2 * 1024 * 1024,
        )
        .unwrap();
        let storage = prepare_cow_base(
            &base_root,
            TEST_ARTIFACT_SHA256,
            "storage",
            "storage.raw",
            &extracted.join("storage.raw"),
            512 * 1024,
            3 * 1024 * 1024,
        )
        .unwrap();
        let owner = unsafe { libc::geteuid() };
        let release = expected_installed_release(TEST_ARTIFACT_SHA256, seed).unwrap();
        publish_installed_release(&base_root, &release, owner).unwrap();

        let storage_dir = storage.parent().unwrap();
        std::fs::set_permissions(storage_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(&storage).unwrap();
        std::fs::set_permissions(storage_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::write(machine.join("overlay.qcow2"), b"original-overlay").unwrap();
        std::fs::write(machine.join("storage.qcow2"), b"original-storage").unwrap();

        let error = seed_vm_mode_disks_from_installed_bases_with(
            &machine,
            &base_root,
            TEST_ARTIFACT_SHA256,
            seed,
            make_fake_overlays,
            owner,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            std::fs::read(machine.join("overlay.qcow2")).unwrap(),
            b"original-overlay"
        );
        assert_eq!(
            std::fs::read(machine.join("storage.qcow2")).unwrap(),
            b"original-storage"
        );
        make_tree_removable(&base_root);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn concurrent_first_cow_base_creation_is_atomic() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("shared-pack");
        let base_cache = temp.path().join("cow-bases");
        std::fs::create_dir_all(&cache).unwrap();
        let source = cache.join("overlay.raw");
        write_sparse_template(&source, 1024 * 1024, b"root");
        let barrier = Arc::new(Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let base_cache = base_cache.clone();
            let source = source.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                prepare_cow_base(
                    &base_cache,
                    TEST_ARTIFACT_SHA256,
                    "overlay",
                    "overlay.raw",
                    &source,
                    1024 * 1024,
                    4 * 1024 * 1024,
                )
                .unwrap()
            }));
        }
        let paths: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(paths.iter().all(|path| path == &paths[0]));
        assert_eq!(std::fs::metadata(&paths[0]).unwrap().len(), 4 * 1024 * 1024);
        let digest_dir = base_cache.join(TEST_ARTIFACT_SHA256);
        assert_eq!(
            std::fs::read_dir(&digest_dir)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().is_dir())
                .count(),
            1
        );
        assert_eq!(
            std::fs::metadata(digest_dir.join("overlay-4194304.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        make_tree_removable(&cache);
        make_tree_removable(&base_cache);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn corrupt_cow_base_is_rejected_without_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("shared-pack");
        let base_cache = temp.path().join("cow-bases");
        std::fs::create_dir_all(&cache).unwrap();
        let source = cache.join("overlay.raw");
        write_sparse_template(&source, 1024 * 1024, b"root");
        let base = prepare_cow_base(
            &base_cache,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &source,
            1024 * 1024,
            2 * 1024 * 1024,
        )
        .unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = prepare_cow_base(
            &base_cache,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &source,
            1024 * 1024,
            2 * 1024 * 1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("writable"));
        assert_eq!(std::fs::metadata(&base).unwrap().len(), 2 * 1024 * 1024);
        make_tree_removable(&cache);
        make_tree_removable(&base_cache);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn missing_file_in_completed_cow_base_fails_without_rebuilding() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("shared-pack");
        let base_cache = temp.path().join("cow-bases");
        std::fs::create_dir_all(&cache).unwrap();
        let source = cache.join("overlay.raw");
        write_sparse_template(&source, 1024 * 1024, b"root");
        let base = prepare_cow_base(
            &base_cache,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &source,
            1024 * 1024,
            2 * 1024 * 1024,
        )
        .unwrap();
        let base_dir = base.parent().unwrap();
        std::fs::set_permissions(base_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(&base).unwrap();
        std::fs::set_permissions(base_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let error = prepare_cow_base(
            &base_cache,
            TEST_ARTIFACT_SHA256,
            "overlay",
            "overlay.raw",
            &source,
            1024 * 1024,
            2 * 1024 * 1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(
            !base.exists(),
            "a completed but broken base is never replaced"
        );
        make_tree_removable(&cache);
        make_tree_removable(&base_cache);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unavailable_qcow_support_leaves_no_partial_overlay_and_copy_fallback_works() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("shared-pack");
        let base_cache = temp.path().join("cow-bases");
        let machine = temp.path().join("machine");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&machine).unwrap();
        write_sparse_template(&cache.join("overlay.raw"), 1024 * 1024, b"root");
        let used_cow = try_seed_vm_mode_disks_cow(
            &machine,
            &cache,
            &base_cache,
            TEST_ARTIFACT_SHA256,
            VmModeDiskSeedSpec {
                artifact_sha256: Some(TEST_ARTIFACT_SHA256),
                overlay_template: Some("overlay.raw"),
                storage_template: None,
                overlay_logical_size: None,
                storage_logical_size: None,
                overlay_gb: None,
                storage_gb: None,
            },
            |specs| {
                std::fs::write(&specs[0].0, b"partial")?;
                Err(Error::agent("create disk overlay", "unsupported"))
            },
        )
        .unwrap();
        assert!(!used_cow);
        assert!(!machine.join("overlay.qcow2").exists());
        seed_vm_mode_disks_by_copy(
            &machine,
            &cache,
            VmModeDiskSeedSpec {
                artifact_sha256: None,
                overlay_template: Some("overlay.raw"),
                storage_template: None,
                overlay_logical_size: Some(2 * 1024 * 1024),
                storage_logical_size: None,
                overlay_gb: None,
                storage_gb: None,
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(machine.join(OVERLAY_DISK_FILENAME))
                .unwrap()
                .len(),
            2 * 1024 * 1024
        );
        assert!(machine.join("overlay.formatted").exists());
        make_tree_removable(&cache);
        make_tree_removable(&base_cache);
    }

    #[test]
    fn test_disk_version_compatibility() {
        let version = DiskVersion::new("sha256:abc123");
        assert!(version.is_compatible());

        let future_version = DiskVersion {
            format_version: 999,
            created_at: "0".to_string(),
            base_digest: "sha256:abc123".to_string(),
            smolvm_version: "99.0.0".to_string(),
        };
        assert!(!future_version.is_compatible());
    }

    #[test]
    fn test_disk_version_serialization() {
        let version = DiskVersion::new("sha256:abc123");
        let json = serde_json::to_string(&version).unwrap();
        let deserialized: DiskVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.format_version, version.format_version);
        assert_eq!(deserialized.base_digest, version.base_digest);
    }

    #[test]
    fn test_storage_disk_create_and_delete() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_basic");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("test_storage.raw");

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        let disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();

        assert!(disk_path.exists());
        assert_eq!(disk.size_gib(), 1);
        assert!(disk.needs_format());

        write_ext4_magic(&disk_path);

        disk.mark_formatted().unwrap();
        assert!(!disk.needs_format());

        disk.delete().unwrap();
        assert!(!disk_path.exists());

        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_default_paths_use_expected_filenames() {
        assert_eq!(
            StorageDisk::default_path().unwrap().file_name().unwrap(),
            STORAGE_DISK_FILENAME
        );
        assert_eq!(
            OverlayDisk::default_path().unwrap().file_name().unwrap(),
            OVERLAY_DISK_FILENAME
        );
    }

    #[test]
    fn test_corruption_detection() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_corrupt");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("corrupt_storage.raw");
        let marker_path = disk_path.with_extension("formatted");

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(&marker_path);

        let disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        write_ext4_magic(&disk_path);
        disk.mark_formatted().unwrap();

        assert!(!disk.needs_format());
        assert!(disk_appears_valid_ext4(&disk_path));

        corrupt_ext4_magic(&disk_path);

        assert!(!disk_appears_valid_ext4(&disk_path));

        let disk2 = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        assert!(!disk2.needs_format());

        let _ = std::fs::remove_file(&disk_path);
        assert!(disk2.needs_format());
        assert!(!marker_path.exists());

        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_overlay_disk_create_and_delete() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("test_overlay.raw");

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        let disk = OverlayDisk::open_or_create_at(&disk_path, 1).unwrap();

        assert!(disk_path.exists());
        assert!(disk.needs_format());

        write_ext4_magic(&disk_path);

        disk.mark_formatted().unwrap();
        assert!(!disk.needs_format());

        disk.delete().unwrap();
        assert!(!disk_path.exists());

        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_overlay_disk_zero_size_rejected() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay_zero");
        let disk_path = temp_dir.join("zero_overlay.raw");
        assert!(OverlayDisk::open_or_create_at(&disk_path, 0).is_err());
    }

    #[test]
    fn test_overlay_disk_ensure_formatted() {
        if disk_utils::find_e2fsprogs_tool("mkfs.ext4").is_none() {
            eprintln!("skipping test_overlay_disk_ensure_formatted: mkfs.ext4 not found");
            return;
        }

        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay_fmt");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("fmt_overlay.raw");

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        let disk = OverlayDisk::open_or_create_at(&disk_path, 1).unwrap();
        assert!(disk.needs_format());

        disk.ensure_formatted().unwrap();
        assert!(!disk.needs_format());

        disk.ensure_formatted().unwrap();

        disk.delete().unwrap();
        assert!(!disk_path.exists());
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_typed_expand_updates_cached_size() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_typed_expand");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("typed_expand_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let _disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        expand_disk::<Storage>(&disk_path, 2).unwrap();

        let disk = StorageDisk::open_or_create_at(&disk_path, 2).unwrap();
        assert_eq!(disk.size_gib(), 2);
        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), 2 * BYTES_PER_GIB);

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn open_or_create_at_grows_an_existing_smaller_disk() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_open_grows");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("grow_test.raw");
        let _ = std::fs::remove_file(&disk_path);

        // A disk left behind at the old size (a data dir that outlived a
        // delete) must present the newly requested size, not the stale one.
        disk_utils::create_sparse_disk::<Storage>(&disk_path, BYTES_PER_GIB).unwrap();
        let disk = StorageDisk::open_or_create_at(&disk_path, 2).unwrap();
        assert_eq!(disk.size_gib(), 2);
        assert_eq!(
            std::fs::metadata(&disk_path).unwrap().len(),
            2 * BYTES_PER_GIB
        );

        // Opening with a smaller size never shrinks an existing disk.
        let disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        assert_eq!(disk.size_gib(), 2);
        assert_eq!(
            std::fs::metadata(&disk_path).unwrap().len(),
            2 * BYTES_PER_GIB
        );

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_expand_disk_basic() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_expand");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("expand_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let initial_size = BYTES_PER_GIB;
        disk_utils::create_sparse_disk::<Storage>(&disk_path, initial_size).unwrap();

        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), initial_size);

        expand_disk::<Storage>(&disk_path, 2).unwrap();

        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), 2 * BYTES_PER_GIB);

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_expand_disk_reject_shrink() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_shrink");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("shrink_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let initial_size = 10 * BYTES_PER_GIB;
        disk_utils::create_sparse_disk::<Storage>(&disk_path, initial_size).unwrap();

        let result = expand_disk::<Storage>(&disk_path, 5);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must be larger"));

        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), initial_size);

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_expand_disk_same_size_is_idempotent() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_same");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("same_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let initial_size = 10 * BYTES_PER_GIB;
        disk_utils::create_sparse_disk::<Storage>(&disk_path, initial_size).unwrap();

        // Same size is a no-op (idempotent for retry after partial failure)
        let result = expand_disk::<Storage>(&disk_path, 10);
        assert!(result.is_ok());

        // Shrink is still rejected
        let result = expand_disk::<Storage>(&disk_path, 5);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    /// Write ext4 magic bytes to make `file` command recognize it as ext4.
    /// ext4 superblock is at offset 1024, magic number 0xEF53 is at offset 56.
    fn write_ext4_magic(path: &std::path::Path) {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

        file.seek(SeekFrom::Start(1080)).unwrap();
        file.write_all(&[0x53, 0xEF]).unwrap();
        file.sync_all().unwrap();
    }

    /// Corrupt the ext4 magic bytes by zeroing them.
    fn corrupt_ext4_magic(path: &std::path::Path) {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

        file.seek(SeekFrom::Start(1080)).unwrap();
        file.write_all(&[0x00, 0x00]).unwrap();
        file.sync_all().unwrap();
    }

    /// Check if a disk file appears to be a valid ext4 filesystem.
    fn disk_appears_valid_ext4(disk_path: &Path) -> bool {
        let output = std::process::Command::new("file")
            .arg("-b")
            .arg(disk_path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let desc = String::from_utf8_lossy(&output.stdout);
                let is_ext4 =
                    desc.contains("ext4") || desc.contains("ext2") || desc.contains("ext3");
                if !is_ext4 {
                    tracing::debug!(
                        path = %disk_path.display(),
                        file_type = %desc.trim(),
                        "disk is not ext4"
                    );
                }
                is_ext4
            }
            _ => {
                tracing::debug!(path = %disk_path.display(), "could not verify disk type, assuming valid");
                true
            }
        }
    }
}
