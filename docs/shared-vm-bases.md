# Shared full-disk VM bases on Linux

SmolVM can keep machine state private to each host user while sharing the
immutable disks from a VM-mode `.smolmachine` artifact. This is a block-image
feature; container-mode and flattened-rootfs artifacts are intentionally not
accepted.

An operator installs each version once:

```console
sudo smolvm machine install-base \
  --from /opt/smolvm/images/development-v1.smolmachine \
  --base-dir /var/lib/smolvm/vm-bases
```

The source artifact must itself be a root-owned, non-writable regular file.
Every ancestor directory leading to the installed base root must also be
trusted, root-owned, and not writable by group or other users (a root-owned
sticky directory such as `/tmp` is permitted). The installer snapshots the
artifact through one open file descriptor,
hashes and extracts that snapshot in private staging, publishes root-owned
read-only `base.raw` files and a complete release marker below the artifact
SHA-256, then removes staging. Normal failures also clean up staging, but
`SIGKILL` or host power loss can leave root-only
`.smolvm-vm-base-install-*`, per-digest `.*.tmp-*`, or `.release.tmp-*`
staging for the operator to inspect and remove after confirming no installation
is active. No SmolVM daemon is involved.

If consumers need disks larger than the artifact defaults, install that exact
variant with `--overlay GIB` and/or `--storage GIB`, then use the same values at
`machine create`. Uninstalled variants fail closed.

Each user sets the same installed-base root while retaining their normal XDG
directories:

```console
SMOLVM_SHARED_VM_BASE_DIR=/var/lib/smolvm/vm-bases \
  smolvm machine create --name workspace \
  --from /opt/smolvm/images/development-v1.smolmachine
```

Creation verifies the root-owned release and creates only private qcow2
overlays in that user's machine directory. Missing or mismatched metadata,
symlinks, unsafe permissions, and unavailable qcow2 support fail closed; the
runtime never falls back to copying a full disk into the user's cache.

Operational requirements:

- The artifact and installed base tree must be immutable and readable or
  traversable by consumers, but writable only by the operator.
- Keep an installed artifact version while any user overlay references it.
- Install a new content-addressed version for upgrades. Existing machines stay
  pinned to their backing paths; newly created machines use the new artifact.
- There is no automatic base pruning or provenance index. Retain old versions
  unless a reference-aware audit of every user's private qcow2 backing paths
  proves that no overlay depends on them. If `qemu-img` is installed,
  `qemu-img info --backing-chain --output=json PRIVATE_OVERLAY.qcow2` can help
  inspect each chain; compare resolved backing paths before removing a base.
- Do not place user records, sockets, locks, or writable overlays in the shared
  directory.
