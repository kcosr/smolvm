#!/usr/bin/env python3
"""Offline native acceptance for an existing --include-workspace fixture pack.

The pack must contain /opt/revision-fixture and /workspace/revision-fixture,
each with payload.bin, hardlink.bin, relative-link, Case, case and revision.
--baseline is the JSON emitted by CONTENTS below in the original source VM.
Uses a fresh account registry, no host mounts/network and exact-name CLI cleanup.
It never removes its account directory if machines, attachments or processes
remain. Evidence is written outside that directory and is retained on failure.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time


CONTENTS = r"""
import os,stat,json,hashlib
from pathlib import Path
result={}
for label,base in [('root',Path('/opt/revision-fixture')),('workspace',Path('/workspace/revision-fixture'))]:
 d={}
 for name in ['payload.bin','hardlink.bin','relative-link','Case','case','revision']:
  p=base/name
  try:s=p.lstat()
  except FileNotFoundError:d[name]={'missing':True};continue
  v={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtime':int(s.st_mtime),'size':s.st_size}
  if stat.S_ISLNK(s.st_mode):v['target']=os.readlink(p)
  else:
   h=hashlib.sha256()
   with p.open('rb') as f:
    for b in iter(lambda:f.read(1048576),b''):h.update(b)
   v['sha256']=h.hexdigest()
  d[name]=v
 d['hardlinkSameInode']=(base/'payload.bin').exists() and (base/'hardlink.bin').exists() and (base/'payload.bin').stat().st_ino==(base/'hardlink.bin').stat().st_ino
 result[label]=d
print(json.dumps(result))
"""


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("smolvm", "pack", "baseline", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--e2fsprogs-dir", type=Path)
    args = parser.parse_args()
    args.smolvm = args.smolvm.resolve(strict=True)
    args.pack = args.pack.resolve(strict=True)
    expected = json.loads(args.baseline.read_text())
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = args.output.resolve()
    root = Path(tempfile.mkdtemp(prefix="ws-", dir="/private/tmp" if sys.platform == "darwin" else "/tmp")).resolve()
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"}
    if args.e2fsprogs_dir:
        env["PATH"] += ":" + str(args.e2fsprogs_dir.resolve(strict=True))
    for key, leaf in {"HOME": "h", "XDG_CONFIG_HOME": "c", "XDG_CACHE_HOME": "x", "XDG_DATA_HOME": "d", "XDG_STATE_HOME": "s", "XDG_RUNTIME_DIR": "r", "TMPDIR": "t"}.items():
        path = root / leaf
        path.mkdir(mode=0o700)
        env[key] = str(path)
    config = root / "config.toml"
    config.write_text("")
    env["SMOLVM_CONFIG"] = str(config)
    commands, checks, observations = [], [], []
    initial = {}
    names = ["workspace-first", "workspace-second", "workspace-reviewer"]
    pack_sha = digest(args.pack)
    result = {"fixtureRoot": str(root), "packSha256": pack_sha, "passed": False}

    def save(name, value):
        (output / name).write_text(json.dumps(value, indent=2) + "\n")

    def command(arguments, timeout=180, required=True):
        start = time.monotonic()
        argv = [str(args.smolvm), *arguments]
        try:
            process = subprocess.run(argv, env=env, cwd=root, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
            record = {"argv": argv, "exit": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
        except subprocess.TimeoutExpired:
            record = {"argv": argv, "exit": 124, "stdout": "", "stderr": "fixture timeout"}
        record["seconds"] = round(time.monotonic() - start, 3)
        commands.append(record)
        save("commands.json", commands)
        print(json.dumps({"command": arguments[:5], "exit": record["exit"]}), flush=True)
        if required and record["exit"]:
            raise RuntimeError(record)
        return record["stdout"]

    def check(label, actual, wanted, required=True):
        checks.append({"label": label, "passed": actual == wanted, "actual": actual, "expected": wanted})
        save("checks.json", checks)
        if required:
            assert actual == wanted, label

    def contents(name):
        return json.loads(command(["machine", "exec", "--name", name, "--", "/usr/bin/python3", "-c", CONTENTS]))

    def shell(name, script):
        return command(["machine", "exec", "--name", name, "--", "/bin/sh", "-c", script])

    def attachments():
        if sys.platform != "darwin":
            return []
        listing = subprocess.check_output(["/usr/bin/hdiutil", "info", "-plist"], timeout=20)
        return [item for item in plistlib.loads(listing).get("images", []) if str(root) in str(item)]

    def observe(label):
        # Inspect both staging and the actual mounted share, without recursively
        # counting a mounted image's files as additional host disk allocations.
        seeds, disks = [], []
        for current, directories, files in os.walk(root, followlinks=False):
            parent = Path(current)
            if parent.name in ("layers", "layers-cs"):
                seed = parent / "workspace-seed/workspace.tar"
                seeds.append({"path": str(seed.relative_to(root)), "exists": seed.is_file(), "sha256": digest(seed) if seed.is_file() else None})
                if parent.name == "layers-cs":
                    directories[:] = []
            for name in files:
                path = parent / name
                if path.suffix in (".raw", ".qcow2", ".sparseimage") and not path.is_symlink():
                    info = path.stat()
                    disks.append({"path": str(path.relative_to(root)), "size": info.st_size, "allocated": info.st_blocks * 512})
        observation = {"label": label, "machines": json.loads(command(["machine", "ls", "--json"])), "attachments": attachments(), "seeds": seeds, "disks": disks}
        observations.append(observation)
        save("observations.json", observations)
        return observation

    def stop_delete(name):
        command(["machine", "stop", "--name", name])
        command(["machine", "delete", "--name", name, "--force"])

    save("inputs.json", {"runtime": str(args.smolvm), "runtimeSha256": digest(args.smolvm), "pack": str(args.pack), "packSha256": pack_sha, "baselineSha256": digest(args.baseline), "environment": env})
    try:
        check("empty disposable account", json.loads(command(["machine", "ls", "--json"])), [])
        for name in names[:2]:
            command(["machine", "create", "--name", name, "--from", str(args.pack), "--cpus", "2", "--mem", "1024", "--storage", "2", "--overlay", "1"])
            command(["machine", "start", "--name", name, "--branchable"])
            observe(name + " started")
            actual = contents(name)
            initial[name] = actual
            # Keep a full metadata verdict, but continue the remaining controls
            # if the guest tar's known symlink-mtime difference is the only one.
            check(name + " restored hashes and metadata", actual, expected, required=False)
            comparable = json.loads(json.dumps(actual))
            baseline = json.loads(json.dumps(expected))
            for data in (comparable, baseline):
                for tree in data.values():
                    tree["relative-link"].pop("mtime", None)
            check(name + " restored content, links and other metadata", comparable, baseline)
        # Later edits on the independent second import must survive cold boot,
        # rather than being replaced by the initial workspace tar again.
        shell(names[1], "printf later > /workspace/revision-fixture/revision; rm /workspace/revision-fixture/Case; sync")
        second = contents(names[1])
        command(["machine", "stop", "--name", names[1]])
        command(["machine", "start", "--name", names[1], "--branchable"])
        check("cold restart does not reseed", contents(names[1]), second)
        check("other import unchanged", contents(names[0]), initial[names[0]])
        # Divergent root and workspace writes; explicit frozen snapshot reviewer.
        shell(names[0], "printf first > /opt/revision-fixture/revision; printf first > /workspace/revision-fixture/revision; sync")
        first = contents(names[0])
        command(["machine", "branch", "--from", names[0], "--name", names[2], "--freeze-source"])
        check("reviewer inherits root and workspace", contents(names[2]), first)
        shell(names[2], "printf reviewer > /opt/revision-fixture/revision; printf reviewer > /workspace/revision-fixture/revision; sync")
        check("reviewer writes stay independent", contents(names[1]), second)
        observe("reviewer mutated")
        stop_delete(names[2])
        command(["machine", "stop", "--name", names[0]])
        command(["machine", "start", "--name", names[0], "--branchable"])
        check("reviewer did not change its source", contents(names[0]), first)
        stop_delete(names[0])
        observe("first import deleted")
        # Read the surviving import immediately, then after a cold restart.
        try:
            surviving = contents(names[1])
        except RuntimeError as error:
            surviving = {"commandError": str(error)}
        check("sibling reads after peer deletion", surviving, second, required=False)
        command(["machine", "stop", "--name", names[1]])
        command(["machine", "start", "--name", names[1], "--branchable"])
        check("survivor cold restart", contents(names[1]), second)
        check("immutable revision unchanged", digest(args.pack), pack_sha)
        result["lifecycleCompleted"] = True
        result["passed"] = all(item["passed"] for item in checks)
    except Exception as error:
        result["error"] = str(error)
    finally:
        failures = []
        try:
            observe("before cleanup")
            remaining = json.loads(command(["machine", "ls", "--json"]))
            present = {item["name"] for item in remaining}
            for name in reversed(names):
                if name in present:
                    try:
                        stop_delete(name)
                    except Exception as error:
                        failures.append(str(error))
            final = observe("after cleanup")
            processes = [line for line in subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid=,command="], text=True, timeout=20).splitlines() if str(root) in line]
            clean = not failures and not final["machines"] and not final["attachments"] and not final["disks"] and not processes
            result.update(clean=clean, cleanupErrors=failures, remainingProcesses=processes)
            if clean:
                shutil.rmtree(root)
        except Exception as error:
            result.update(clean=False, cleanupError=str(error))
        save("result.json", result)
        print(json.dumps(result), flush=True)
    return 0 if result["passed"] and result.get("clean") else 1


if __name__ == "__main__":
    raise SystemExit(main())
