#!/usr/bin/env python3
"""Native regression for restarting a source with continuing-fork children.

    SMOLVM=/path/to/smolvm python3 tests/test_continuing_source_restart.py

Requires a branch-capable Linux or macOS runtime with its normal guest assets.
Set SMOLVM_TEST_IMAGE to a local OCI archive to also cover container workloads;
otherwise uses the bundled bare guest. No networking or host mounts are used.
All machines live in a disposable account registry, removed only after successful
named cleanup. Failures retain that directory for stock CLI recovery.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get("SMOLVM"), "set SMOLVM to a native runtime")
class ContinuingSourceRestart(unittest.TestCase):
    def setUp(self):
        self.binary = str(Path(os.environ["SMOLVM"]).resolve(strict=True))
        image = os.environ.get("SMOLVM_TEST_IMAGE")
        self.image = str(Path(image).resolve(strict=True)) if image else None
        # Short canonical HOME also keeps Darwin's Unix sockets within bounds.
        self.root = Path(tempfile.mkdtemp(prefix="sv-restart-", dir="/tmp")).resolve()
        self.env = dict(os.environ)
        self.env.pop("SMOLVM_DATA_DIR", None)
        self.env.pop("SMOLVM_MACHINE_NAME", None)
        self.env.update(
            HOME=str(self.root),
            XDG_DATA_HOME=str(self.root / "data"),
            XDG_CACHE_HOME=str(self.root / "cache"),
            XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_STATE_HOME=str(self.root / "state"),
            XDG_RUNTIME_DIR=str(self.root / "runtime"),
            SMOLVM_CONFIG=str(self.root / "settings.toml"),
        )
        (self.root / "runtime").mkdir(mode=0o700)
        self.machines = []
        self.addCleanup(self.cleanup)

    def run_vm(self, *args, success=True):
        result = subprocess.run(
            [self.binary, *args], env=self.env, cwd=self.root,
            text=True, capture_output=True, timeout=120,
        )
        with (self.root / "commands.jsonl").open("a") as log:
            log.write(json.dumps({
                "args": args, "code": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr,
            }) + "\n")
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def cleanup(self):
        failures = []
        for name in reversed(self.machines):
            try:
                self.run_vm("machine", "stop", "--name", name, success=False)
                result = self.run_vm(
                    "machine", "delete", "--name", name, "--force", success=False,
                )
                if result.returncode:
                    failures.append(name)
            except Exception as error:
                failures.append(f"{name}: {error}")
        records = json.loads(self.run_vm("machine", "ls", "--json").stdout)
        self.assertFalse(failures or records, f"Recovery state retained at {self.root}: {failures}")
        shutil.rmtree(self.root)

    def create(self, name):
        self.machines.append(name)
        image_args = ["--image", self.image] if self.image else []
        self.run_vm(
            "machine", "create", "--name", name, "--cpus", "1", "--mem", "1024",
            "--storage", "2", "--overlay", "1", *image_args,
        )
        self.start(name)

    def start(self, name):
        self.run_vm("machine", "start", "--name", name, "--branchable")

    def branch(self, name, freeze=False):
        self.machines.append(name)
        self.run_vm(
            "machine", "branch", "--from", "source", "--name", name,
            "--branchable", *(["--freeze-source"] if freeze else []),
        )

    def execute(self, name, script):
        return self.run_vm(
            "machine", "exec", "--name", name, "--timeout", "10s",
            "--", "/bin/sh", "-c", script,
        ).stdout

    def assert_state(self, name, state):
        records = json.loads(self.run_vm("machine", "ls", "--json").stdout)
        self.assertEqual(next(row for row in records if row["name"] == name)["state"], state)

    def test_continue_restart_preserves_running_and_stopped_children(self):
        self.create("source")
        self.execute("source", "printf original > /workspace/value")
        self.branch("child")
        self.execute("child", "printf child > /workspace/value")
        for child_running in [True, False]:
            if not child_running:
                self.run_vm("machine", "stop", "--name", "child")
            for _ in range(2):
                self.run_vm("machine", "stop", "--name", "source")
                self.start("source")
                self.assert_state("source", "running")
                self.execute("source", "printf parent > /workspace/value")
                if child_running:
                    self.assertEqual(self.execute("child", "cat /workspace/value"), "child")
        self.run_vm("machine", "stop", "--name", "source")
        self.start("child")
        self.assertEqual(self.execute("child", "cat /workspace/value"), "child")
        self.start("source")
        self.assertEqual(self.execute("source", "cat /workspace/value"), "parent")
        # A new branch must capture the restarted source, not its old snapshot.
        self.branch("new-child")
        self.assertEqual(self.execute("new-child", "cat /workspace/value"), "parent")

    def test_explicit_frozen_source_remains_protected(self):
        self.create("source")
        self.execute("source", "printf frozen > /workspace/value")
        self.branch("child", freeze=True)
        for child_running in [True, False]:
            if not child_running:
                self.run_vm("machine", "stop", "--name", "child")
            self.assert_state("source", "frozen")
            result = self.run_vm("machine", "stop", "--name", "source", success=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fork base", result.stdout + result.stderr)
        self.start("child")
        self.assertEqual(self.execute("child", "cat /workspace/value"), "frozen")


if __name__ == "__main__":
    unittest.main()
