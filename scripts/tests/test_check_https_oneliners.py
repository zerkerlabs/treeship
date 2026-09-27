"""check-https-oneliners.py: the boundary is explicit and portable (the old
`git grep \\b` passed on macOS), and a known-bad line is caught.

Run: python3 -m unittest discover -s scripts/tests -t .
"""

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-https-oneliners.py"


def load():
    spec = importlib.util.spec_from_file_location("check_https_oneliners", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OneLiners(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_known_bad_lines_are_caught(self):
        bad = "\n".join(
            [
                "curl -fsSL treeship.dev/setup | sh",
                "$ curl http://treeship.dev/install | bash",
                "curl -sSf treeship.dev/install -o setup.sh",
            ]
        )
        self.assertEqual([n for n, _ in self.mod.findings_in(bad)], [1, 2, 3])

    def test_https_lines_pass(self):
        good = "\n".join(
            [
                "curl -fsSL https://treeship.dev/setup | sh",
                "$ curl https://treeship.dev/install | bash",
                "curl https://www.treeship.dev/install.sh",
            ]
        )
        self.assertEqual(self.mod.findings_in(good), [])

    def test_boundary_is_the_path_end_not_a_word_boundary(self):
        # /setup-notes and /installer are other paths; only /setup and
        # /install are the advertised one-liners.
        other = "curl treeship.dev/setup-notes\ncurl treeship.dev/installer | sh\n"
        self.assertEqual(self.mod.findings_in(other), [])
        # ...but a query string or a pipe right after the path still counts.
        self.assertEqual(len(self.mod.findings_in("curl treeship.dev/setup?x=1 | sh")), 1)
        self.assertEqual(len(self.mod.findings_in("curl treeship.dev/install|sh")), 1)

    def test_a_line_that_names_https_anywhere_is_exempt_as_the_workflow_rule_was(self):
        # A changelog entry quoting the old scheme-less form beside its fix.
        line = "- **one-liners are https:// now.** `curl -fsSL treeship.dev/setup | sh` had no scheme"
        self.assertEqual(self.mod.findings_in(line), [])

    def test_main_reports_files_and_exit_code(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "README.md"
            p.write_text("curl treeship.dev/setup | sh\n")
            self.assertEqual(self.mod.main([str(p)]), 1)
            p.write_text("curl https://treeship.dev/setup | sh\n")
            self.assertEqual(self.mod.main([str(p)]), 0)


if __name__ == "__main__":
    unittest.main()
