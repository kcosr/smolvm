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

The source artifact must itself be a root-owned, non-writable regular file. The
installer snapshots it through one open file descriptor, hashes and extracts
that snapshot in private staging, publishes root-owned read-only `base.raw`
files and a complete release marker below the artifact SHA-256, then removes
staging. No SmolVM daemon is involved.

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
- Do not place user records, sockets, locks, or writable overlays in the shared
  directory.
