//! Shared from-VM pack export: turn a stopped machine into `.smolmachine`
//! assets.
//!
//! This is the single implementation behind every CLI's `pack create
//! --from-vm` (and the cloud export path). It lives in the lib — not a CLI —
//! so front-ends cannot fork-and-drift the export semantics: the bare-VM /
//! image-machine / artifact-sourced dispatch, the manifest seeding, and the
//! layer flattening below are all decided here.
//!
//! Image-based exports produce ONE flattened layer. Multi-layer packs cannot
//! overlay-mount virtiofs-backed lowers at import time, so the guest falls
//! back to physically merging every layer file-by-file through virtiofs —
//! pathologically slow for file-heavy layers (a node_modules-scale overlay
//! reads as a boot hang). The from-image pack path already pre-merges for
//! exactly this reason; flattening here gives from-VM exports the same
//! import-time behavior: a single lowerdir that mounts instantly.

use crate::agent::{
    machine_layers_cache_dir, read_shared_pack_pointer, resolve_disk_image, vm_data_dir,
    AgentClient, AgentManager, LaunchFeatures, VmResources,
};
use crate::config::VmRecord;
use crate::data::disk::DiskFormat;
use crate::storage::{OVERLAY_DISK_FILENAME, STORAGE_DISK_FILENAME};
use crate::Error;
use sha2::{Digest, Sha256};
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::format::{PackManifest, PackMode};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Options for a from-VM export.
#[derive(Debug, Default, Clone)]
pub struct FromVmExportOptions {
    /// HTTP(S) proxy for the in-VM registry pull (registry-image machines).
    pub proxy: Option<String>,
    /// NO_PROXY for the in-VM registry pull.
    pub no_proxy: Option<String>,
    /// For artifact-sourced machines: rebuild base layers from `vm.image`
    /// (re-pull from the registry) instead of preserving imported layers.
    pub rebase_from_image: bool,
}

/// What the export decided about the machine, for the caller's manifest.
#[derive(Debug, Clone)]
pub struct FromVmAssets {
    /// `Container` for image-based machines, `Vm` for bare machines.
    pub mode: PackMode,
    /// The machine's image reference (image-based machines only).
    pub image: Option<String>,
}

/// Collect a stopped machine's pack assets into `collector` and report the
/// pack mode. The caller has already: loaded the record, verified the machine
/// is stopped, and collected its base assets (runtime libs, agent rootfs,
/// templates). `staging_dir` hosts temporary extractions and must live until
/// the pack is finalized.
pub fn collect_from_vm_assets(
    collector: &mut AssetCollector,
    vm_name: &str,
    vm: &VmRecord,
    staging_dir: &Path,
    opts: &FromVmExportOptions,
) -> crate::Result<FromVmAssets> {
    // A fork clone's disks are CoW qcow2 overlays that only the fork/resume
    // machinery can assemble — the export helper cold-boots them and libkrun
    // rejects the stack with an opaque -22 EINVAL (same class as clone
    // auto-standby wake). Refuse with the real story until overlay-chain boot
    // is supported.
    if let Some(ref golden) = vm.golden {
        return Err(Error::agent(
            "pack from VM",
            format!(
                "machine '{vm_name}' is a fork clone of '{golden}'; its copy-on-write \
                 disks cannot be exported directly. Export the golden instead, or \
                 recreate the state in a non-clone machine and export that."
            ),
        ));
    }

    let vm_dir = vm_data_dir(vm_name);
    let _source_lock = SourceVmLock::acquire(&vm_dir, vm_name)?;
    if source_vm_process_is_alive(&vm_dir) {
        return Err(Error::agent(
            "pack from VM",
            format!(
                "machine '{vm_name}' is running. Stop it first with: \
                 smolvm machine stop --name {vm_name}"
            ),
        ));
    }
    let (overlay_disk, overlay_fmt) = resolve_disk_image(&vm_dir, OVERLAY_DISK_FILENAME);
    let is_image_based = vm.image.is_some();
    let is_artifact_sourced = is_image_based && vm.source_smolmachine.is_some();

    if !is_image_based && !overlay_disk.exists() {
        return Err(Error::agent(
            "pack from VM",
            format!(
                "overlay disk not found at {}. The VM may not have been started yet.",
                overlay_disk.display()
            ),
        ));
    }

    if is_image_based {
        let image = vm.image.clone().unwrap();
        match image_export_source(&image, is_artifact_sourced, opts.rebase_from_image) {
            ImageExportSource::Artifact => {
                export_flattened_from_artifact_sourced(collector, vm_name, &vm_dir, staging_dir)?;
            }
            ImageExportSource::LocalArchive => {
                export_flattened_from_local_archive(collector, vm_name, &vm_dir, &image)?;
            }
            ImageExportSource::LocalDirectory => {
                return Err(Error::agent(
                    "pack from VM",
                    format!(
                        "VM '{vm_name}' was created from a local image ({image}). \
                         `pack create --from-vm` cannot snapshot machines created from \
                         rootfs directories. Recreate the machine from an image archive, \
                         registry reference, or .smolmachine artifact to pack it."
                    ),
                ));
            }
            ImageExportSource::UnsupportedLocalRebase => {
                return Err(Error::agent(
                    "pack from VM",
                    format!(
                        "VM '{vm_name}' came from a .smolmachine whose recorded image is \
                         local ({image}); `--rebase-from-image` cannot recover that original \
                         host archive. Export without `--rebase-from-image` to preserve the \
                         artifact's imported layers."
                    ),
                ));
            }
            ImageExportSource::Registry => {
                export_flattened_from_registry_image(collector, vm_name, &vm_dir, &image, opts)?;
            }
        }
    } else {
        // Bare VM: its state is the rootfs overlay disk. VM-mode restores boot
        // from the template; a default-size overlay is a qcow2 CoW image and
        // must be flattened to a raw before it can be a template.
        let overlay_for_pack = match overlay_fmt {
            DiskFormat::Raw => overlay_disk.clone(),
            DiskFormat::Qcow2 => {
                let flat = staging_dir.join("overlay-flat.raw");
                flatten_qcow2_to_raw(&overlay_disk, &flat)?;
                flat
            }
        };
        println!("Copying overlay disk ({})...", overlay_for_pack.display());
        collector
            .add_overlay_template(&overlay_for_pack)
            .map_err(|e| Error::agent("collect overlay", e.to_string()))?;
    }

    Ok(FromVmAssets {
        mode: if is_image_based {
            PackMode::Container
        } else {
            PackMode::Vm
        },
        image: vm.image.clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImageExportSource {
    Artifact,
    LocalArchive,
    LocalDirectory,
    UnsupportedLocalRebase,
    Registry,
}

fn image_export_source(
    image: &str,
    is_artifact_sourced: bool,
    rebase_from_image: bool,
) -> ImageExportSource {
    if is_artifact_sourced && !rebase_from_image {
        return ImageExportSource::Artifact;
    }
    if image.starts_with("local:") {
        return if is_artifact_sourced {
            ImageExportSource::UnsupportedLocalRebase
        } else {
            ImageExportSource::LocalArchive
        };
    }
    if crate::data::image_source::is_local_ref(image) {
        ImageExportSource::LocalDirectory
    } else {
        ImageExportSource::Registry
    }
}

/// Seed a pack manifest with the source machine's runtime identity. CLI /
/// Smolfile overrides layer on top of this baseline at the call site.
pub fn seed_manifest_from_vm(manifest: &mut PackManifest, vm: &VmRecord, assets: &FromVmAssets) {
    manifest.mode = assets.mode.clone();
    if let Some(ref image) = assets.image {
        manifest.image = image.clone();
    }
    manifest.network = vm.network;
    manifest.gpu = vm.gpu.unwrap_or(false);
    manifest.cuda = vm.cuda;
    manifest.entrypoint = if !vm.entrypoint.is_empty() {
        vm.entrypoint.clone()
    } else {
        vec!["/bin/sh".to_string()]
    };
    manifest.cmd = vm.cmd.clone();
    manifest.env = vm.env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
    manifest.workdir = vm.workdir.clone();
    manifest.secret_refs = vm.secret_refs.clone();
}

/// A helper VM used to read the source machine's disks and flatten layers.
/// Stops the VM and removes its scratch data dir on drop.
struct ExportVm {
    manager: AgentManager,
    data_dir: PathBuf,
}

#[derive(Debug)]
struct SourceVmLock {
    _file: std::fs::File,
}

impl SourceVmLock {
    fn acquire(vm_dir: &Path, vm_name: &str) -> crate::Result<Self> {
        std::fs::create_dir_all(vm_dir)
            .map_err(|error| Error::agent("prepare source VM lock", error.to_string()))?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(vm_dir.join("vm.lock"))
            .map_err(|error| Error::agent("lock source VM", error.to_string()))?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            let message = if error.kind() == std::io::ErrorKind::WouldBlock {
                format!(
                    "machine '{vm_name}' is starting, running, or already being exported; \
                     stop it and retry"
                )
            } else {
                error.to_string()
            };
            Error::agent("lock source VM", message)
        })?;
        Ok(Self { _file: file })
    }
}

fn source_vm_process_is_alive(vm_dir: &Path) -> bool {
    let content = match std::fs::read_to_string(vm_dir.join("agent.pid")) {
        Ok(content) => content,
        Err(_) => return false,
    };
    let Some((pid, start_time)) = parse_pid_identity(&content) else {
        return false;
    };
    if let Some(start_time) = start_time {
        crate::process::is_our_process_strict(pid, Some(start_time))
    } else {
        crate::process::is_alive(pid)
            && crate::process::cmdline_contains(
                pid,
                &vm_dir.join("boot-config.json").to_string_lossy(),
            )
    }
}

fn parse_pid_identity(content: &str) -> Option<(i32, Option<u64>)> {
    let mut lines = content.lines();
    let pid = lines.next()?.trim().parse::<i32>().ok()?;
    let start_time = lines
        .next()
        .and_then(|line| line.trim().parse::<u64>().ok());
    Some((pid, start_time))
}

impl ExportVm {
    /// Boot a scratch agent VM with the source machine's storage disk attached
    /// read-only as `/dev/vdc`, plus (optionally) a host layer dir shared as
    /// `/packed_layers`.
    fn start(
        vm_name: &str,
        source_vm_dir: &Path,
        packed_layers_dir: Option<PathBuf>,
        network: bool,
    ) -> crate::Result<Self> {
        let (storage_disk, storage_fmt) = resolve_disk_image(source_vm_dir, STORAGE_DISK_FILENAME);
        // A machine that has never been started has no disks yet — attaching
        // the nonexistent image would boot the helper into a cryptic libkrun
        // EINVAL. Fail with the actionable story instead.
        if !storage_disk.exists() {
            return Err(Error::agent(
                "pack from VM",
                format!(
                    "machine '{vm_name}' has no storage disk yet ({}) — it has \
                     never been started. Start it once so its state exists, or \
                     pack the image directly with `pack create -I <image>`.",
                    storage_disk.display()
                ),
            ));
        }
        let scratch_name = format!(
            "pack-fromvm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let data_dir = vm_data_dir(&scratch_name);

        println!("Starting agent VM to export machine state...");
        let manager = AgentManager::for_vm(&scratch_name)?;
        let features = LaunchFeatures {
            // Attach writable so ext4 can replay a pending journal. The
            // filesystem itself is mounted read-only below, and SourceVmLock
            // excludes a concurrent machine start.
            extra_disks: vec![(storage_disk, false, storage_fmt)],
            packed_layers_dir,
            // Under per-VM uid isolation the source VM's dir is 0700/its-own-uid;
            // this helper's whole job is reading that VM's disks, so run it as
            // the source's uid (a fresh sibling uid can't open the disk and the
            // boot dies configuring virtio-blk).
            uid_share_dir: Some(source_vm_dir.to_path_buf()),
            ..Default::default()
        };
        if let Err(e) = manager.start_with_full_config(
            Vec::new(),
            Vec::new(),
            VmResources {
                cpus: 4,
                memory_mib: 8192,
                network,
                network_backend: None,
                dns: None,
                gpu: false,
                cuda: false,
                gpu_vram_mib: None,
                rosetta: false,
                storage_gib: None,
                overlay_gib: None,
                allowed_cidrs: None,
                tcp_egress: None,
            },
            features,
        ) {
            // The Drop cleanup only arms once Self exists — a failed boot must
            // clean its own scratch dir or every failed export leaks one.
            let _ = std::fs::remove_dir_all(&data_dir);
            return Err(e);
        }
        Ok(Self { manager, data_dir })
    }

    fn connect(&self) -> crate::Result<AgentClient> {
        self.manager.connect()
    }

    /// Mount the source machine's storage disk at `/mnt/source-storage`.
    fn mount_source_storage(&self, client: &mut AgentClient) -> crate::Result<()> {
        let (exit_code, _, stderr) = client.vm_exec(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "mkdir -p /mnt/source-storage && \
                 mount -o ro /dev/vdc /mnt/source-storage"
                    .to_string(),
            ],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "mount source storage in temp VM",
                format!(
                    "mount failed (exit {}): {}",
                    exit_code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        Ok(())
    }
}

impl Drop for ExportVm {
    fn drop(&mut self) {
        if let Err(e) = self.manager.stop() {
            warn!(error = %e, "failed to stop pack temp VM");
        }
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Local-archive machine: reuse the exact flattened rootfs on the source
/// storage disk, then layer the machine's persistent container changes on top.
fn export_flattened_from_local_archive(
    collector: &mut AssetCollector,
    vm_name: &str,
    vm_dir: &Path,
    image: &str,
) -> crate::Result<()> {
    let hash = local_archive_hash(image).ok_or_else(|| {
        Error::agent(
            "pack from VM",
            format!("VM '{vm_name}' has an invalid local image reference: {image}"),
        )
    })?;

    let export_vm = ExportVm::start(vm_name, vm_dir, None, false)?;
    let mut client = export_vm.connect()?;
    export_vm.mount_source_storage(&mut client)?;

    let archive_dir = "/mnt/source-storage/image-archives/packed_layers";
    let lower = format!("{archive_dir}/0000_rootfs");
    let marker = format!("{archive_dir}/.extracted");
    let expected_marker = format!("sha256={hash}");
    let (exit_code, _, _) = client.vm_exec(
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "test -d '{lower}' && test ! -L '{lower}' && \
                 test -f '{marker}' && grep -Fqx '{expected_marker}' '{marker}'"
            ),
        ],
        vec![],
        None,
        None,
        None,
    )?;
    if exit_code != 0 {
        return Err(Error::agent(
            "pack from VM",
            format!(
                "VM '{vm_name}' is missing a completed flattened rootfs for {image}. \
                 Run `smolvm machine exec --name {vm_name} -- true` to reconstruct it, \
                 then retry the export."
            ),
        ));
    }

    flatten_and_export(collector, &mut client, vm_name, &[lower])
}

fn local_archive_hash(image: &str) -> Option<&str> {
    image.strip_prefix("local:").filter(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Registry-image machine: pull the base image inside the helper VM (layers
/// extract to its local disk), then flatten base layers + the machine's
/// persistent container overlay into a single exported layer.
fn export_flattened_from_registry_image(
    collector: &mut AssetCollector,
    vm_name: &str,
    vm_dir: &Path,
    image: &str,
    opts: &FromVmExportOptions,
) -> crate::Result<()> {
    let export_vm = ExportVm::start(vm_name, vm_dir, None, true)?;
    let mut client = export_vm.connect()?;
    export_vm.mount_source_storage(&mut client)?;

    eprintln!("Pulling {} in export VM...", image);
    let image_info = client.pull_with_registry_config_and_progress(
        image,
        None,
        opts.proxy.as_deref(),
        opts.no_proxy.as_deref(),
        |_, _, _| {},
    )?;

    // Lower dirs on the helper's own disk, bottom -> top as pulled.
    let lowers: Vec<String> = image_info
        .layers
        .iter()
        .map(|d| {
            let id = d.strip_prefix("sha256:").unwrap_or(d);
            format!("/storage/layers/{}", id)
        })
        .collect();

    flatten_and_export(collector, &mut client, vm_name, &lowers)
}

/// Artifact-sourced machine: its extracted layer dirs live in the host-side
/// machine layers cache; share them into the helper VM, stage them onto its
/// local disk (overlayfs cannot use virtiofs-backed lowers), and flatten with
/// the current container overlay.
fn export_flattened_from_artifact_sourced(
    collector: &mut AssetCollector,
    vm_name: &str,
    vm_dir: &Path,
    _staging_dir: &Path,
) -> crate::Result<()> {
    let cache_dir = machine_layers_cache_dir(vm_name);
    let pack_content_dir = read_shared_pack_pointer(&cache_dir).unwrap_or(cache_dir);
    let layer_ids = ordered_cached_layer_ids(&pack_content_dir).ok_or_else(|| {
        Error::agent(
            "pack from VM",
            format!(
                "VM '{vm_name}' was created from a .smolmachine artifact, but its \
                 imported layer cache is missing ({}). Start the machine once to \
                 re-extract it, then re-run the export.",
                pack_content_dir.display()
            ),
        )
    })?;

    let export_vm = ExportVm::start(vm_name, vm_dir, Some(pack_content_dir.clone()), false)?;
    let mut client = export_vm.connect()?;
    export_vm.mount_source_storage(&mut client)?;

    // Stage each virtiofs layer dir onto the helper's local disk. A tar pipe
    // preserves overlayfs whiteout devices and opaque-dir xattrs, which a
    // later overlay mount needs intact.
    println!(
        "Staging {} imported layer(s) for flatten...",
        layer_ids.len()
    );
    let mut lowers = Vec::new();
    for (i, id) in layer_ids.iter().enumerate() {
        let src = format!("/packed_layers/{}", id);
        let dst = format!("/storage/stage/{}", i);
        let (exit_code, _, stderr) = client.vm_exec(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!(
                    "mkdir -p '{dst}' && (cd '{src}' && tar cf - .) | (cd '{dst}' && tar xf -)"
                ),
            ],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "stage imported layer",
                format!(
                    "layer {} stage failed (exit {}): {}",
                    id,
                    exit_code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        lowers.push(dst);
    }

    flatten_and_export(collector, &mut client, vm_name, &lowers)
}

/// The extracted layer dirs of an imported pack, bottom -> top, as short ids.
/// `None` when the cache (or its ordering) is gone.
fn ordered_cached_layer_ids(pack_content_dir: &Path) -> Option<Vec<String>> {
    let layers_dir = pack_content_dir.join("layers");
    let order_path = layers_dir.join("layer-order");
    let ids: Vec<String> = if let Ok(contents) = std::fs::read_to_string(&order_path) {
        contents
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        // No order file: only unambiguous for a single extracted layer dir.
        let mut dirs: Vec<String> = std::fs::read_dir(&layers_dir)
            .ok()?
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        if dirs.len() != 1 {
            return None;
        }
        vec![dirs.pop().unwrap()]
    };
    if ids.is_empty() || !ids.iter().all(|id| layers_dir.join(id).is_dir()) {
        return None;
    }
    Some(ids.iter().map(|id| format!("layers/{}", id)).collect())
}

/// Overlay-mount `lowers` (bottom -> top, helper-local paths) with the source
/// machine's persistent container overlay on top, tar the merged view, and
/// register the stream as the pack's single layer. The overlay mount applies
/// whiteouts/opaque markers exactly as the runtime would, so the flattened
/// tree is byte-equivalent to what the machine's container saw.
fn flatten_and_export(
    collector: &mut AssetCollector,
    client: &mut AgentClient,
    vm_name: &str,
    lowers: &[String],
) -> crate::Result<()> {
    if lowers.is_empty() {
        return Err(Error::agent("flatten layers", "no layers to flatten"));
    }
    let upper = format!("/mnt/source-storage/overlays/persistent-{}/upper", vm_name);
    // overlayfs wants topmost-first in `lowerdir=`.
    let base_chain: Vec<&str> = lowers.iter().rev().map(String::as_str).collect();
    let base_chain = base_chain.join(":");

    println!(
        "Flattening {} layer(s) + container overlay...",
        lowers.len()
    );
    let script = format!(
        "set -e\n\
         low='{base_chain}'\n\
         n={n}\n\
         if [ -d '{upper}' ] && [ -n \"$(ls -A '{upper}' 2>/dev/null)\" ]; then\n\
           low=\"{upper}:$low\"; n=$((n+1))\n\
         fi\n\
         if [ \"$n\" -eq 1 ]; then\n\
           tar cf /storage/flat-export.tar -C \"${{low%%:*}}\" .\n\
         else\n\
           mkdir -p /tmp/flatview\n\
           mount -t overlay overlay -o lowerdir=\"$low\" /tmp/flatview\n\
           tar cf /storage/flat-export.tar -C /tmp/flatview .\n\
           umount /tmp/flatview\n\
         fi\n\
         echo FLAT_OK\n",
        n = lowers.len(),
    );
    let (exit_code, stdout, stderr) = client.vm_exec(
        vec!["sh".to_string(), "-c".to_string(), script],
        vec![],
        None,
        None,
        None,
    )?;
    let stdout_str = String::from_utf8_lossy(&stdout);
    if exit_code != 0 || !stdout_str.contains("FLAT_OK") {
        return Err(Error::agent(
            "flatten layers",
            format!(
                "flatten failed (exit {}): {}",
                exit_code,
                String::from_utf8_lossy(&stderr)
            ),
        ));
    }

    // Stream the flattened tar to disk (never buffered whole in memory), then
    // content-address it. Stage in the layers dir so the final rename is
    // atomic on the same filesystem.
    let tmp_file = collector
        .layer_staging_path(&format!("sha256:{}", "0".repeat(64)))
        .with_file_name("flat-export.tmp");
    let total = client
        .read_file_to_path("/storage/flat-export.tar", &tmp_file, |_| {})
        .map_err(|e| Error::agent("export flattened layer", e.to_string()))?;
    if total == 0 {
        let _ = std::fs::remove_file(&tmp_file);
        return Err(Error::agent(
            "export flattened layer",
            "flattened layer tar is empty",
        ));
    }

    let mut hasher = Sha256::new();
    {
        use std::io::Read;
        let mut f = std::fs::File::open(&tmp_file)
            .map_err(|e| Error::agent("read flattened layer", e.to_string()))?;
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| Error::agent("hash flattened layer", e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    let layer_file = collector.layer_staging_path(&digest);
    std::fs::rename(&tmp_file, &layer_file)
        .map_err(|e| Error::agent("write flattened layer", e.to_string()))?;
    collector
        .register_layer(&digest)
        .map_err(|e| Error::agent("register flattened layer", e.to_string()))?;
    println!("  Flattened layer: {} bytes", total);
    Ok(())
}

/// Flatten a qcow2 CoW overlay into a standalone raw disk image (bare VMs).
///
/// There is no host-side qcow2 reader (smolvm deliberately takes no qemu-img
/// dependency), so the conversion runs inside a throwaway agent VM: the source
/// qcow2 is attached read-only (libkrun resolves its backing chain) as
/// `/dev/vdc` alongside a fresh raw output as `/dev/vdd`, and the guest `dd`s
/// one into the other.
fn flatten_qcow2_to_raw(qcow2_path: &Path, dest_raw: &Path) -> crate::Result<()> {
    let virtual_size = read_qcow2_virtual_size(qcow2_path)?;
    let dest = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dest_raw)
        .map_err(|e| Error::agent("create flat overlay", e.to_string()))?;
    dest.set_len(virtual_size)
        .map_err(|e| Error::agent("size flat overlay", e.to_string()))?;
    drop(dest);

    let scratch_name = format!(
        "pack-flatten-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let data_dir = vm_data_dir(&scratch_name);
    println!("Flattening qcow2 overlay to raw...");
    let manager = AgentManager::for_vm(&scratch_name)?;
    let features = LaunchFeatures {
        extra_disks: vec![
            (qcow2_path.to_path_buf(), true, DiskFormat::Qcow2),
            (dest_raw.to_path_buf(), false, DiskFormat::Raw),
        ],
        ..Default::default()
    };
    manager.start_with_full_config(
        Vec::new(),
        Vec::new(),
        VmResources {
            cpus: 2,
            memory_mib: 2048,
            network: false,
            network_backend: None,
            dns: None,
            gpu: false,
            cuda: false,
            gpu_vram_mib: None,
            rosetta: false,
            storage_gib: None,
            overlay_gib: None,
            allowed_cidrs: None,
            tcp_egress: None,
        },
        features,
    )?;

    let result: crate::Result<()> = (|| {
        let mut client = manager.connect()?;
        let (exit_code, _, stderr) = client.vm_exec(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                // busybox dd lacks GNU `conv=sparse`, so do a plain full copy
                // and `sync`. The output is dense on the temp disk, but
                // `add_overlay_template` strips trailing zeros so the pack stays
                // small; the imported overlay is re-sparsified on extraction.
                "dd if=/dev/vdc of=/dev/vdd bs=1M && sync".to_string(),
            ],
            vec![],
            None,
            None,
            None,
        )?;
        if exit_code != 0 {
            return Err(Error::agent(
                "flatten overlay qcow2",
                format!(
                    "dd failed (exit {}): {}",
                    exit_code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        Ok(())
    })();

    if let Err(e) = manager.stop() {
        warn!(error = %e, "failed to stop flatten temp VM");
    }
    let _ = std::fs::remove_dir_all(&data_dir);
    result
}

/// Read a qcow2 header's virtual size (big-endian u64 at offset 24).
fn read_qcow2_virtual_size(path: &Path) -> crate::Result<u64> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| Error::agent("open qcow2", e.to_string()))?;
    let mut header = [0u8; 32];
    f.read_exact(&mut header)
        .map_err(|e| Error::agent("read qcow2 header", e.to_string()))?;
    if &header[0..4] != b"QFI\xfb" {
        return Err(Error::agent(
            "read qcow2 header",
            format!("{} is not a qcow2 image", path.display()),
        ));
    }
    Ok(u64::from_be_bytes(header[24..32].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn validates_canonical_local_archive_references() {
        assert_eq!(local_archive_hash(&format!("local:{HASH}")), Some(HASH));
        for invalid in [
            "local:",
            "local:../archive",
            "local:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "local:0123",
            "registry.example/image:tag",
        ] {
            assert_eq!(local_archive_hash(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn classifies_image_export_sources_and_local_rebase() {
        assert_eq!(
            image_export_source(&format!("local:{HASH}"), false, false),
            ImageExportSource::LocalArchive
        );
        assert_eq!(
            image_export_source("local-dir:/tmp/rootfs", false, false),
            ImageExportSource::LocalDirectory
        );
        assert_eq!(
            image_export_source("alpine:latest", false, false),
            ImageExportSource::Registry
        );
        assert_eq!(
            image_export_source("alpine:latest", true, false),
            ImageExportSource::Artifact
        );
        assert_eq!(
            image_export_source(&format!("local:{HASH}"), true, true),
            ImageExportSource::UnsupportedLocalRebase
        );
    }

    #[test]
    fn source_vm_lock_excludes_a_second_export_or_start() {
        let directory = tempfile::tempdir().unwrap();
        let vm_dir = directory.path().join("not-created-yet");
        let first = SourceVmLock::acquire(&vm_dir, "test-vm").unwrap();
        let error = SourceVmLock::acquire(&vm_dir, "test-vm").unwrap_err();
        assert!(error.to_string().contains("already being exported"));
        drop(first);
        SourceVmLock::acquire(&vm_dir, "test-vm").unwrap();
    }

    #[test]
    fn parses_current_and_legacy_pid_files() {
        assert_eq!(parse_pid_identity("123\n456\n"), Some((123, Some(456))));
        assert_eq!(parse_pid_identity("123"), Some((123, None)));
        assert_eq!(parse_pid_identity("not-a-pid\n456"), None);
        assert_eq!(parse_pid_identity(""), None);
    }
}
