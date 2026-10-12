#!/usr/bin/env python3
"""Offline Darwin packed-layer lifetime regression (no personal registry access).

SMOLVM=/path/to/smolvm SMOLVM_TEST_PACK_A=/path/to/a.smolmachine \
SMOLVM_TEST_PACK_B=/path/to/b.smolmachine SMOLVM_TEST_OUTPUT=/new/evidence/dir \
python3 tests/test_macos_machine_layers.py

Both Container packs need /opt/revision-fixture/{payload.bin,revision}, with
different root contents. Workspace files are initialized after each import;
saved-workspace restoration is outside this regression. Guest python3/sha256sum/sh
are required. Optional
SMOLVM_TEST_E2FSPROGS_DIR appends an isolated trusted directory to fixed PATH.
Each test uses a short private account, no network/host mounts, bounded commands,
and stock named cleanup. Evidence survives failures; uncertain cleanup retains
the account. The API test uses a disposable loopback server, never a service.
"""

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


CONTENTS = """
import hashlib,json
from pathlib import Path
print(json.dumps({str(p):{'marker':(p/'revision').read_text(),
 'sha256':hashlib.sha256((p/'payload.bin').read_bytes()).hexdigest()}
 for p in [Path('/opt/revision-fixture'),Path('/workspace/revision-fixture')]}))
"""
PACKED = """
set -e
sync; echo 3 > /proc/sys/vm/drop_caches
cat /packed_layers/layer-order
sha256sum /packed_layers/*/opt/revision-fixture/payload.bin
cat /packed_layers/*/opt/revision-fixture/revision
"""


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("SMOLVM"),
                     "requires Darwin and explicit native runtime/pack inputs")
class MachineLayers(unittest.TestCase):
    def setUp(self):
        self.binary = str(Path(os.environ["SMOLVM"]).resolve(strict=True))
        self.packs = [Path(os.environ[f"SMOLVM_TEST_PACK_{x}"]).resolve(strict=True)
                      for x in ["A", "B"]]
        self.output = Path(os.environ["SMOLVM_TEST_OUTPUT"]) / self._testMethodName
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root = Path(tempfile.mkdtemp(prefix="ml-", dir="/private/tmp")).resolve()
        self.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"}
        if os.environ.get("SMOLVM_TEST_E2FSPROGS_DIR"):
            self.env["PATH"] += ":" + str(Path(os.environ["SMOLVM_TEST_E2FSPROGS_DIR"]).resolve(strict=True))
        for key, leaf in {"HOME": "h", "XDG_CONFIG_HOME": "c", "XDG_CACHE_HOME": "x",
                          "XDG_DATA_HOME": "d", "XDG_STATE_HOME": "s",
                          "XDG_RUNTIME_DIR": "r", "TMPDIR": "t"}.items():
            path = self.root / leaf
            path.mkdir(mode=0o700)
            self.env[key] = str(path)
        config = self.root / "config.toml"
        config.write_text("")
        self.env["SMOLVM_CONFIG"] = str(config)
        self.names, self.commands, self.observations = [], [], []
        self.server = None
        self.standalone_used = False
        self.directories, self.original = {}, {}
        self.addCleanup(self.cleanup)
        self.save("inputs.json", {"binary": self.binary, "packs": [
            {"path": str(p), "sha256": digest(p)}
            for p in self.packs],
                                  "environment": self.env})
        self.assertEqual(json.loads(self.cli("machine", "ls", "--json").stdout), [])

    def save(self, name, value):
        (self.output / name).write_text(json.dumps(value, indent=2) + "\n")

    def cli(self, *args, success=True, extra_env=None):
        env = dict(self.env, **(extra_env or {}))
        result = subprocess.run([self.binary, *args], cwd=self.root, env=env,
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=120)
        self.commands.append({"args": args, "exit": result.returncode,
                              "stdout": result.stdout, "stderr": result.stderr,
                              "testEnvironmentOverride": extra_env or {}})
        self.save("commands.json", self.commands)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def create(self, name, pack):
        self.names.append(name)
        self.cli("machine", "create", "--name", name, "--from", str(pack),
                 "--cpus", "2", "--mem", "1024", "--storage", "2", "--overlay", "1")
        self.directories[name] = Path(self.cli("machine", "data-dir", "--name", name).stdout.strip()).resolve()
        self.assertTrue(self.directories[name].is_relative_to(self.root))

    def start(self, name):
        self.cli("machine", "start", "--name", name, "--branchable")

    def initialize_workspace(self, name):
        # Exercise each VM's private disk independently of packed seed restore.
        self.cli("machine", "exec", "--name", name, "--timeout", "15s", "--",
                 "/bin/sh", "-c", "mkdir -p /workspace/revision-fixture && "
                 "cp /opt/revision-fixture/payload.bin /opt/revision-fixture/revision "
                 "/workspace/revision-fixture/")

    def stop(self, name):
        self.cli("machine", "stop", "--name", name)

    def delete(self, name):
        self.cli("machine", "delete", "--name", name, "--force")
        self.names.remove(name)

    def direct(self, name, script):
        request = json.dumps({"method": "vm_exec", "command": ["/bin/sh", "-c", script],
                              "timeout_ms": 15000}).encode()
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(20)
            connection.connect(str(self.directories[name] / "agent.sock"))
            connection.sendall(struct.pack(">I", len(request)) + request)
            def exact(size):
                data = b""
                while len(data) < size:
                    part = connection.recv(size - len(data))
                    self.assertTrue(part, "agent EOF")
                    data += part
                return data
            size = struct.unpack(">I", exact(4))[0]
            self.assertLessEqual(size, 4 * 1024 * 1024)
            result = json.loads(exact(size))
        self.assertEqual(result.get("exit_code"), 0, result)
        return base64.b64decode(result["stdout"]).decode()

    def read(self, name):
        packed = self.direct(name, PACKED)
        result = self.cli("machine", "exec", "--name", name, "--timeout", "15s",
                          "--", "/usr/bin/python3", "-c", CONTENTS)
        value = {"packed": packed, "contents": json.loads(result.stdout)}
        self.observations.append({"read": name, **value})
        self.save("observations.json", self.observations)
        return value

    def unchanged(self, name, expected=None):
        self.assertEqual(self.read(name), expected or self.original[name])

    def mounts(self, expected=None):
        info = plistlib.loads(subprocess.check_output(["/usr/bin/hdiutil", "info", "-plist"], timeout=20))
        images = [image for image in info.get("images", []) if str(self.root) in str(image)]
        volumes = {}
        for image in images:
            for entity in image.get("system-entities", []):
                if not entity.get("mount-point"):
                    continue
                disk = plistlib.loads(subprocess.check_output(
                    ["/usr/sbin/diskutil", "info", "-plist", entity["dev-entry"]], timeout=20))
                volumes[image["image-path"]] = disk["VolumeUUID"]
        self.observations.append({"images": images, "volumeUUIDs": volumes})
        self.save("observations.json", self.observations)
        if expected is not None:
            self.assertEqual(len(volumes), expected, volumes)
            self.assertEqual(len(set(volumes.values())), expected, volumes)
        return volumes

    def prepare_pair(self):
        for name, pack in zip(["first", "second"], self.packs):
            self.create(name, pack)
            self.start(name)
            self.initialize_workspace(name)
            self.original[name] = self.read(name)
            self.stop(name)
            self.mounts(0)
        self.assertNotEqual(self.original["first"]["packed"], self.original["second"]["packed"])

    def test_independent_imports_stop_delete_and_cold_restart(self):
        self.prepare_pair()
        self.start("first")
        first = self.mounts(1)
        self.start("second")
        both = self.mounts(2)
        self.assertTrue(first.items() <= both.items())
        for name in ["first", "second"]:
            self.unchanged(name)
        self.stop("first")
        self.mounts(1)
        self.unchanged("second")
        self.delete("first")
        self.unchanged("second")
        self.create("first", self.packs[0])
        self.start("first")
        self.initialize_workspace("first")
        self.mounts(2)
        self.unchanged("first")
        self.stop("second")
        self.delete("second")
        self.mounts(1)
        self.unchanged("first")
        self.stop("first")
        self.mounts(0)
        self.start("first")
        self.unchanged("first")

    def test_failed_start_keeps_peer_and_named_cleanup_reclaims_mount(self):
        self.prepare_pair()
        self.start("first")
        failed = self.cli("machine", "start", "--name", "second", success=False,
                          extra_env={"SMOLVM_BOOT_BINARY": "/usr/bin/false"})
        self.assertNotEqual(failed.returncode, 0)
        self.unchanged("first")
        self.stop("second")
        self.mounts(1)
        self.start("second")
        self.mounts(2)
        self.unchanged("first")
        self.unchanged("second")

    def test_standalone_pack_cleanup_preserves_named_volume(self):
        self.create("first", self.packs[0])
        self.start("first")
        self.initialize_workspace("first")
        self.original["first"] = self.read("first")
        original_mount = self.mounts(1)
        self.standalone_used = True
        self.cli("pack", "run", "--sidecar", str(self.packs[1]), "--",
                 "/bin/sh", "-c", "test -s /opt/revision-fixture/payload.bin")
        self.assertEqual(self.mounts(1), original_mount)
        self.unchanged("first")
        self.cli("pack", "prune", "--all")  # this disposable account only
        self.assertEqual(self.mounts(1), original_mount)
        self.unchanged("first")

    def branch(self, name, frozen=False):
        self.names.append(name)
        self.cli("machine", "branch", "--from", "first", "--name", name,
                 *(["--freeze-source"] if frozen else []))
        self.directories[name] = Path(self.cli("machine", "data-dir", "--name", name).stdout.strip()).resolve()

    def test_frozen_and_continuing_source_children_share_volume(self):
        self.prepare_pair()
        self.start("first")
        self.start("second")
        self.branch("frozen", frozen=True)
        self.unchanged("frozen", self.original["first"])
        self.assertNotEqual(self.cli("machine", "stop", "--name", "first", success=False).returncode, 0)
        self.stop("frozen")
        self.mounts(2)
        self.unchanged("second")
        self.delete("frozen")
        self.stop("first")
        self.start("first")
        self.branch("child-one")
        self.branch("child-two")
        self.stop("first")
        self.mounts(2)
        self.unchanged("child-one", self.original["first"])
        self.unchanged("child-two", self.original["first"])
        self.stop("child-one")
        self.delete("child-one")
        self.unchanged("child-two", self.original["first"])
        self.stop("child-two")
        self.mounts(2)  # stopped children retain the reference until deletion
        self.delete("child-two")
        self.stop("first")
        self.mounts(1)
        self.unchanged("second")
        # Source restart with retained children is a separate lifecycle issue.
        self.start("first")
        self.mounts(2)
        self.unchanged("first")
        self.unchanged("second")

    def api(self, method, suffix, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        try:
            connection.request(method, "/api/v1/machines" + suffix,
                               json.dumps(body or {}) if method == "POST" else None,
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read()
            result = json.loads(data) if data else None
            self.assertLess(response.status, 300, result)
            return result
        finally:
            connection.close()

    def test_api_explicit_and_implicit_start(self):
        self.prepare_pair()
        with socket.socket() as port:
            port.bind(("127.0.0.1", 0))
            self.port = port.getsockname()[1]
        self.server_log = (self.output / "server.log").open("w")
        self.server = subprocess.Popen([self.binary, "serve", "start", "--listen",
                                       f"127.0.0.1:{self.port}"], env=self.env,
                                      cwd=self.root, stdin=subprocess.DEVNULL,
                                      stdout=self.server_log, stderr=subprocess.STDOUT)
        for _ in range(100):
            self.assertIsNone(self.server.poll())
            try:
                self.api("GET", "")
                break
            except OSError:
                time.sleep(0.1)
        else:
            self.fail("API readiness timeout")
        self.api("POST", "/first/start")
        implicit = self.api("POST", "/second/exec", {"command": ["/bin/sh", "-c", "printf implicit"], "autoStart": True})
        self.assertEqual(implicit["exitCode"], 0)
        self.assertEqual(implicit["stdout"], "implicit")
        self.mounts(2)
        self.unchanged("first")
        self.unchanged("second")
        self.api("POST", "/first/stop")
        self.mounts(1)
        self.unchanged("second")
        self.api("DELETE", "/first?force=true")
        self.names.remove("first")
        self.unchanged("second")
        self.api("POST", "/second/stop")
        self.mounts(0)

    def cleanup(self):
        failures = []
        if self.server:
            self.server.terminate()
            try:
                self.server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)
                failures.append("API fixture needed forced shutdown")
            self.server_log.close()
        records = json.loads(self.cli("machine", "ls", "--json").stdout)
        for name in reversed(self.names):
            if not any(row["name"] == name for row in records):
                continue
            try:
                self.cli("machine", "stop", "--name", name, success=False)
                if self.cli("machine", "delete", "--name", name, "--force", success=False).returncode:
                    failures.append(name)
            except Exception as error:
                failures.append(f"{name}: {error}")
        records = json.loads(self.cli("machine", "ls", "--json").stdout)
        if self.standalone_used and not failures and not records:
            if self.cli("pack", "prune", "--all", success=False).returncode:
                failures.append("disposable standalone pack cache cleanup")
        volumes = self.mounts()
        processes = [line for line in subprocess.check_output(["/bin/ps", "-axo", "pid=,command="], text=True).splitlines()
                     if str(self.root) in line]
        disks = [str(p) for p in self.root.rglob("*") if p.suffix in (".raw", ".qcow2", ".sparseimage") and p.is_file() and not p.is_symlink()]
        clean = not (failures or records or volumes or processes or disks)
        self.save("cleanup.json", {"clean": clean, "root": str(self.root), "failures": failures,
                                   "records": records, "volumes": volumes, "processes": processes, "disks": disks})
        if clean:
            shutil.rmtree(self.root)
        self.assertTrue(clean, f"recovery state retained: {self.root}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
