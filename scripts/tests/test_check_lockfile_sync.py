"""check-lockfile-sync.py: the installed-entry half warns instead of failing
while the release in flight is not on npm yet (T11), and fails again the
moment it is. Registry lookups are stubbed; nothing here touches the network.

Run: python3 -m unittest discover -s scripts/tests -t .
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-lockfile-sync.py"


def load_script():
    spec = importlib.util.spec_from_file_location("check_lockfile_sync", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_tree(root: Path, core_version: str, declared: str, installed: str):
    (root / "packages" / "core").mkdir(parents=True)
    (root / "packages" / "core" / "Cargo.toml").write_text(
        f'[package]\nname = "treeship-core"\nversion = "{core_version}"\n\n[dependencies]\nserde = "1"\n'
    )
    pkg = root / "packages" / "demo"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(
        json.dumps({"name": "demo", "dependencies": {"@treeship/verify": declared}})
    )
    (pkg / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"@treeship/verify": declared}},
                    "node_modules/@treeship/verify": {"version": installed},
                }
            }
        )
    )


class InFlightRelease(unittest.TestCase):
    def setUp(self):
        self.mod = load_script()
        self.mod.RELEASE_WINDOW = False
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, lookup):
        return self.mod.main(root=self.root, lookup=lookup)

    def test_in_flight_version_reads_the_core_crate(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.9")
        self.assertEqual(self.mod.in_flight_version(self.root), "0.31.10")
        self.assertIsNone(self.mod.in_flight_version(self.root / "nowhere"))

    def test_unpublished_release_in_flight_warns_and_passes(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.9")
        asked = []

        def lookup(name, version):
            asked.append((name, version))
            return False

        self.assertEqual(self.run_check(lookup), 0)
        self.assertEqual(asked, [("@treeship/verify", "0.31.10")])

    def test_published_release_fails_until_the_refresh(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.9")
        self.assertEqual(self.run_check(lambda n, v: True), 1)

    def test_registry_unreachable_keeps_failing(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.9")
        self.assertEqual(self.run_check(lambda n, v: None), 1)

    def test_only_the_release_in_flight_is_relaxed(self):
        # The declared pin is not the crate version: plain drift, whatever npm says.
        make_tree(self.root, "0.31.10", "0.31.11", "0.31.9")
        self.assertEqual(self.run_check(lambda n, v: False), 1)

    def test_declared_range_drift_still_fails(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.10")
        lock = self.root / "packages" / "demo" / "package-lock.json"
        d = json.loads(lock.read_text())
        d["packages"][""]["dependencies"]["@treeship/verify"] = "0.31.9"
        lock.write_text(json.dumps(d))
        self.assertEqual(self.run_check(lambda n, v: False), 1)

    def test_a_tree_in_sync_never_asks_the_registry(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.10")

        def lookup(name, version):
            raise AssertionError("registry asked for a tree in sync")

        self.assertEqual(self.run_check(lookup), 0)

    def test_release_branch_window_is_unchanged(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.9")
        self.mod.RELEASE_WINDOW = True

        def lookup(name, version):
            raise AssertionError("registry asked inside the release window")

        self.assertEqual(self.run_check(lookup), 0)


class RootVersion(unittest.TestCase):
    """The lockfile's own version fields track package.json."""

    def setUp(self):
        self.mod = load_script()
        self.mod.RELEASE_WINDOW = False
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_stale_root_version_fails(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.10")
        pkg = self.root / "packages" / "demo"
        (pkg / "package.json").write_text(
            json.dumps({"name": "demo", "version": "0.31.10", "dependencies": {"@treeship/verify": "0.31.10"}})
        )
        lock = json.loads((pkg / "package-lock.json").read_text())
        lock["version"] = "0.10.3"
        lock["packages"][""]["version"] = "0.10.3"
        (pkg / "package-lock.json").write_text(json.dumps(lock))
        self.assertEqual(self.mod.main(root=self.root, lookup=lambda n, v: False), 1)
        lock["version"] = "0.31.10"
        lock["packages"][""]["version"] = "0.31.10"
        (pkg / "package-lock.json").write_text(json.dumps(lock))
        self.assertEqual(self.mod.main(root=self.root, lookup=lambda n, v: False), 0)

    def test_a_lockfile_without_root_versions_is_not_judged(self):
        make_tree(self.root, "0.31.10", "0.31.10", "0.31.10")
        self.assertEqual(self.mod.main(root=self.root, lookup=lambda n, v: False), 0)


class RegistryAnswers(unittest.TestCase):
    """`npm view` output shapes, with subprocess stubbed."""

    def setUp(self):
        self.mod = load_script()

    def stub(self, returncode, stdout="", stderr=""):
        class R:
            pass

        r = R()
        r.returncode, r.stdout, r.stderr = returncode, stdout, stderr
        self.mod.subprocess.run = lambda *a, **k: r

    def test_shapes(self):
        self.stub(0, '"0.31.9"\n')
        self.assertIs(self.mod.npm_published("@treeship/verify", "0.31.9"), True)
        self.stub(0, "")
        self.assertIs(self.mod.npm_published("@treeship/verify", "0.31.10"), False)
        self.stub(1, "", "npm error code E404\nnpm error 404 Not Found")
        self.assertIs(self.mod.npm_published("@treeship/verify", "0.31.10"), False)
        self.stub(1, "", "npm error code ENOTFOUND\nnpm error network")
        self.assertIsNone(self.mod.npm_published("@treeship/verify", "0.31.10"))

        def boom(*a, **k):
            raise OSError("npm: command not found")

        self.mod.subprocess.run = boom
        self.assertIsNone(self.mod.npm_published("@treeship/verify", "0.31.10"))


if __name__ == "__main__":
    unittest.main()
