"""check-claims.py: a marker only backs the exact wording its own claim
disclaims if the line actually negates it too (N-31, final 0.31.11
re-test) -- README.md's "The Hub stores immutable bytes" passed under
`hub-storage-write-once` even though that claim's own `says` field
negates "immutable" ("write-once ... not immutable"). Also covers two
bugs found while fixing that: a claim id cited inside another claim's
`says` text (`checkpoint-not-witnessed`) must not itself count as a
negated occurrence of the substring it contains, and the marker syntax
and link URLs on a scanned line must not count as banned-phrase hits.

Run: python3 -m unittest discover -s scripts/tests -t .
"""

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-claims.py"


def load():
    spec = importlib.util.spec_from_file_location("check_claims", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class NegationRequired(unittest.TestCase):
    """The `not:`-list-vs-`says` derivation `main()` does, isolated from
    file I/O: build it by hand the same way and feed it straight to
    unbacked_phrases()."""

    def setUp(self):
        self.mod = load()

    def negation_required_from(self, says: str, not_list: list[str]) -> dict[str, set[str]]:
        return {"claim": {p for p in not_list if self.mod.negated_nearby(says, p)}}

    def test_bare_disclaimed_word_is_unbacked(self):
        # hub-storage-write-once's real says text and README's real line.
        says = "The Hub's own storage is write-once and edit-free, not immutable: ..."
        nr = self.negation_required_from(says, ["immutable"])
        unbacked = self.mod.unbacked_phrases(
            "The Hub stores immutable bytes, serves lookup indices and proofs.",
            ["immutable"],
            {"claim"},
            nr,
        )
        self.assertEqual(unbacked, ["immutable"])

    def test_negated_usage_is_backed(self):
        says = "The Hub's own storage is write-once and edit-free, not immutable: ..."
        nr = self.negation_required_from(says, ["immutable"])
        unbacked = self.mod.unbacked_phrases(
            "The Hub stores write-once bytes -- not immutable -- and serves proofs.",
            ["immutable"],
            {"claim"},
            nr,
        )
        self.assertEqual(unbacked, [])

    def test_affirmed_word_needs_no_negation(self):
        # rekor-artifact-anchoring's real style: the word is qualified, not negated.
        says = "verify counts an anchor as witnessed only if the stapled entry verifies offline"
        nr = self.negation_required_from(says, ["witnessed"])
        self.assertEqual(nr["claim"], set())
        unbacked = self.mod.unbacked_phrases(
            "Pushed artifacts are witnessed by Rekor.", ["witnessed"], {"claim"}, nr
        )
        self.assertEqual(unbacked, [])

    def test_hyphenated_claim_id_citation_is_not_a_negation(self):
        # transparency-log-client-reverified's real says text cites
        # checkpoint-not-witnessed by name; that "not" belongs to the id,
        # not a sentence negating "witnessed" for THIS claim.
        says = (
            "audit additionally witnesses checkpoints across runs, distinct from "
            "checkpoint-not-witnessed (whether a checkpoint is externally corroborated)"
        )
        nr = self.negation_required_from(says, ["witnessed"])
        self.assertEqual(nr["claim"], set())

    def test_real_negator_next_to_a_hyphenated_word_still_counts(self):
        # The hyphen-adjacency guard must only exclude a negator that is
        # ITSELF hyphen-joined into a compound -- a real "not" a word
        # away from a hyphenated banned phrase still negates it.
        says = "This is not machine-bound in any way."
        nr = self.negation_required_from(says, ["machine-bound"])
        self.assertEqual(nr["claim"], {"machine-bound"})


class ProseOnly(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_marker_text_itself_is_not_a_hit(self):
        # The claim id checkpoint-not-witnessed contains "witnessed" as a
        # name component; the marker syntax naming it is not a claim.
        line = "{/* claims:checkpoint-not-witnessed */}"
        self.assertNotIn("witnessed", self.mod.prose_only(line).lower())

    def test_link_url_is_not_a_hit(self):
        # A never-renamed blog slug in a link URL is a path, not prose.
        line = "See [the post](/blog/agentic-commerce-tamper-proof-receipts) for background."
        self.assertNotIn("tamper-proof", self.mod.prose_only(line).lower())
        # The visible link text is still scanned.
        line2 = "See [the tamper-proof post](/blog/x) for background."
        self.assertIn("tamper-proof", self.mod.prose_only(line2).lower())

    def test_inline_code_and_fences_still_stripped(self):
        self.assertNotIn("witnessed", self.mod.prose_only("`--max-unwitnessed`").lower())
        text = "```bash\nimmutable\n```\nprose immutable"
        cleaned = self.mod.prose_only(text).lower()
        self.assertEqual(cleaned.count("immutable"), 1)


class LineFindingsEndToEnd(unittest.TestCase):
    """The N-31 regression, through the real end-to-end line_findings()."""

    def setUp(self):
        self.mod = load()

    def test_n31_regression(self):
        text = (
            "<!-- claims:hub-storage-write-once -->\n"
            "The Hub stores immutable bytes, serves lookup indices and proofs.\n"
        )
        valid_ids = {"hub-storage-write-once"}
        says = "The Hub's own storage is write-once and edit-free, not immutable: ..."
        negation_required = {
            "hub-storage-write-once": {
                p for p in ["immutable"] if self.mod.negated_nearby(says, p)
            }
        }
        findings = self.mod.line_findings("README.md", text, valid_ids, negation_required)
        self.assertEqual(len(findings), 1)
        self.assertIn("immutable", findings[0])

    def test_fixed_wording_passes(self):
        text = (
            "<!-- claims:hub-storage-write-once -->\n"
            "The Hub stores write-once bytes -- not immutable -- and serves proofs.\n"
        )
        valid_ids = {"hub-storage-write-once"}
        says = "The Hub's own storage is write-once and edit-free, not immutable: ..."
        negation_required = {
            "hub-storage-write-once": {
                p for p in ["immutable"] if self.mod.negated_nearby(says, p)
            }
        }
        findings = self.mod.line_findings("README.md", text, valid_ids, negation_required)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
