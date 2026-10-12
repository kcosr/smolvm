# Named machine layer lifetime on macOS

Named `.smolmachine` imports keep their extracted case-sensitive APFS volume
after the start CLI exits. A dead start-CLI PID must not let the standalone pack
orphan sweeper detach that volume. Each independent import has its own volume;
starting, stopping or deleting another import must preserve its UUID and bytes.

Fork children share the source's immutable layers through their existing `pack`
symlinks. The source volume stays attached while any child directory references
it, including a stopped child that may restart. Stopping a continuing source
therefore preserves its children's filesystem handles. Restarting the source
while children remain is a separate lifecycle issue. Remove children
with stock `machine delete`, then stop/delete the source to reclaim its volume.
Frozen-source stop restrictions remain unchanged. An unreadable reference
inventory conservatively retains the mount. No process watcher or daemon-PID
handoff is involved; standalone pack process-lease cleanup remains separate.

Portable ownership controls and explicit native APFS controls:

```sh
cargo test --locked -p smolvm-pack
cargo test --locked -p smolvm-pack orphan_reap_tests::native_ -- --ignored --test-threads=1
```

The ignored tests create private sparse images with `hdiutil`: they verify
standalone orphan reclamation, named-volume exclusion and child-reference
pinning/reclamation. Their cleanup only detaches the images they created.

For actual VM regression, supply two offline arm64 Container packs. Each needs
guest Python 3 and `/opt/revision-fixture/{payload.bin,revision}`.
Give the packs different root contents. A trusted local Ubuntu tools archive can
be used to prepare each source with stock `machine create --image`, write the
fixture files, stop, and `pack create --from-vm` with a
`net=false` Smolfile. Do this in a disposable account, without host mounts.
The test initializes each imported workspace itself, so it does not depend on
saved-workspace restoration. It restarts a stopped source only after deleting
its children; restarting while children remain is a separate regression.

```sh
SMOLVM=/absolute/runtime/smolvm \
SMOLVM_TEST_PACK_A=/absolute/a.smolmachine \
SMOLVM_TEST_PACK_B=/absolute/b.smolmachine \
SMOLVM_TEST_OUTPUT=/absolute/new-evidence-directory \
SMOLVM_TEST_E2FSPROGS_DIR=/absolute/isolated/sbin \
python3 tests/test_macos_machine_layers.py
```

The five controls cover independent imports in both deletion orders and cold
restart; a failed boot followed by exact named recovery; explicit frozen and
multiple continuing children; API explicit/implicit starts against existing
records; and standalone pack run/prune alongside a live named import. Prune is
restricted to that test's disposable account. Reads drop only guest caches and
compare packed-layer, root and workspace bytes. Host observations require
distinct attached volume UUIDs. A temporary
loopback API server uses the same disposable account and is stopped afterward.
No personal machine registry, profile, network image pull or host mount is used.

The test refuses to delete its private account until exact named stop/delete
leaves no records, disk images, scoped processes or attachments. Evidence remains
outside the account on both success and failure. A remaining account is recovery
state, not permission to unmount unrelated host volumes.
