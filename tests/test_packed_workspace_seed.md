# Packed workspace seed regression

`test_packed_workspace_seed.py` exercises saved Container-mode packs offline in
a fresh, short account HOME/XDG registry. It requires Python 3.11+, a complete
native smolvm distribution, disk resizing tools, and an arm64 Linux tools image
with `/usr/bin/python3` when running on Apple Silicon. It does not use the user's
registry, mounts, credentials or network. Do not run the ordinary test suite's
global orphan cleanup before this fixture.

Prepare the input once in a disposable account, using stock CLI commands:

1. `machine create --name seed-editor --image /absolute/tools-image.tar --cpus 2 --mem 1024 --storage 2 --overlay 1`
2. `machine start --name seed-editor --branchable`
3. Run the following Python in that machine with `machine exec --name seed-editor -- /usr/bin/python3 -c ...`:

```python
from pathlib import Path
import os

for base in (Path('/opt/revision-fixture'), Path('/workspace/revision-fixture')):
    base.mkdir(parents=True)
    with (base / 'payload.bin').open('wb') as stream:
        for _ in range(64):
            stream.write(os.urandom(1024 * 1024))
    (base / 'hardlink.bin').hardlink_to(base / 'payload.bin')
    (base / 'relative-link').symlink_to('payload.bin')
    (base / 'Case').write_text('upper\n')
    (base / 'case').write_text('lower\n')
    (base / 'revision').write_text('A\n')
    for path in (base, base / 'payload.bin', base / 'Case', base / 'case', base / 'revision'):
        os.chown(path, 123, 456)
        os.chmod(path, 0o750 if path == base else 0o640)
        os.utime(path, (1700000000, 1700000000))
    os.chmod(base / 'Case', 0o751)
os.sync()
```

4. Execute the fixture's `CONTENTS` Python string inside the source VM and save
   its stdout as `baseline.json`. Obtain the string with
   `runpy.run_path('tests/test_packed_workspace_seed.py')['CONTENTS']`; importing
   the script does not start machines.
5. Stop `seed-editor`. Export with `pack create --from-vm seed-editor
   --include-workspace --smolfile /absolute/Smolfile --output /absolute/revision-a`.
   The Smolfile contains `cpus=2`, `memory=1024`, `storage=2`, `overlay=1`, `net=false`.
6. Inspect the pack: Container mode, Linux/arm64, no network or mounts, and a
   `layers/workspace-seed/workspace.tar` member. Record the pack digest, retain
   `baseline.json`, and stop/delete the editor with the stock CLI.

Run the fixture against an **unused** evidence output directory:

```sh
python3 tests/test_packed_workspace_seed.py \
  --smolvm /absolute/distribution/smolvm \
  --pack /absolute/revision-a.smolmachine \
  --baseline /absolute/baseline.json \
  --e2fsprogs-dir /absolute/isolated-tools/sbin \
  --output /absolute/private-evidence/new-run
```

The script checks two independent imports, exact hashes and metadata, later
workspace edits surviving cold restart, frozen reviewer isolation, deletion and
survivor recovery. It records staged and mounted seed hashes and scoped layer
attachments before deletion. Every command has a timeout. Cleanup uses only
the three fixture names, with children first; uncertain cleanup retains the
entire private account directory for recovery.

Full metadata and immediate sibling reads remain acceptance gates. If only
symlink timestamps differ during restoration, the fixture records that failure
and continues so the remaining lifecycle controls are still measured. Likewise,
a sibling-read failure after deleting its peer is recorded before attempting
cold recovery. Neither exception produces a successful overall verdict: inspect
`checks.json` and `result.json`, and expect exit 1 if either gate fails.

Focused source checks (no VM needed):

```sh
cargo test --locked -p smolvm-pack
cargo test --locked -p smolvm-agent storage::tests
```

On macOS the focused APFS extraction regression requires `hdiutil` and must be
requested explicitly; it fails rather than silently skipping an unavailable mount:

```sh
cargo test --locked -p smolvm-pack macos_workspace_seed -- --ignored
```

The host uses a case-sensitive layer volume, while Linux can share `layers/`
directly. The fix preserves the workspace archive intact on that guest-visible
volume; the guest still performs the one-time workspace extraction. The reserved
seed directory is never a rootfs layer, with or without a layer-order index.
