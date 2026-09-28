"""check-release-versions.py --write: every site's writer runs and stamps.

The writers only run on release day, so a broken one (0.31.11's hub
`const Release` writer called an undefined helper) surfaced at
`release.sh prepare`, after everything else had merged. This copies every
version site into a temp tree, stamps it, and requires the check to pass.

Run: python3 -m unittest discover -s scripts/tests -t .
"""

import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check-release-versions.py"


def load_script():
    spec = importlib.util.spec_from_file_location("check_release_versions", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # dataclasses resolves the module through sys.modules at class creation.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class StampEverySite(unittest.TestCase):
    def test_write_mode_stamps_every_site_and_the_check_passes(self):
        mod = load_script()
        sites = mod.collect_sites()
        self.assertTrue(any(s.write for s in sites), "no writable sites found")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for s in sites:
                src = REPO / s.path
                if src.exists():
                    dst = root / s.path
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
            mod.REPO_ROOT = root
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = mod.main(["check-release-versions.py", "--write", "99.88.77"])
            self.assertEqual(rc, 0, out.getvalue() + err.getvalue())
            for s in mod.collect_sites():
                if s.write is not None:
                    self.assertEqual(s.found, "99.88.77", f"{s.path} ({s.label}) not stamped")


if __name__ == "__main__":
    unittest.main()
