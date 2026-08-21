"""Unit tests for treeship_sdk.client.

Run with: python -m unittest discover -s packages/sdk-python/tests

Tests stub subprocess.run so they pass without a real treeship CLI.
"""

import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from treeship_sdk import (
    SessionReportResult,
    Treeship,
    TreeshipError,
)
from treeship_sdk.client import _OPTION_LIKE, _reject_option_like


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Helper to build a mock subprocess.CompletedProcess."""
    cp = subprocess.CompletedProcess(
        args=["treeship"], returncode=returncode, stdout=stdout, stderr=stderr
    )
    return cp


class VersionDerivationTests(unittest.TestCase):
    def test_version_resolves_from_metadata_or_fallback(self) -> None:
        from treeship_sdk import __version__

        self.assertIsInstance(__version__, str)
        self.assertTrue(__version__)
        # Either a real semver-ish string from the installed package, or
        # the explicit fallback when running from an uninstalled source.
        self.assertTrue(
            __version__[0].isdigit() or __version__ == "0.0.0+unknown",
            f"unexpected version shape: {__version__!r}",
        )


class OptionInjectionTests(unittest.TestCase):
    def test_rejects_dash_dash_format(self) -> None:
        with self.assertRaises(TreeshipError):
            _reject_option_like("actor", "--format")

    def test_rejects_short_option(self) -> None:
        with self.assertRaises(TreeshipError):
            _reject_option_like("actor", "-x")

    def test_allows_uri_with_dashes_inside(self) -> None:
        # Common actor URI: agent://my-agent
        self.assertEqual(
            _reject_option_like("actor", "agent://my-agent"),
            "agent://my-agent",
        )

    def test_allows_artifact_id(self) -> None:
        self.assertEqual(
            _reject_option_like("artifact_id", "art_abc123"),
            "art_abc123",
        )

    def test_attest_action_rejects_option_like_actor(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError):
            ts.attest_action(actor="--format", action="x")

    def test_verify_rejects_option_like_artifact(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError):
            ts.verify("--help")


class WrapBehaviorTests(unittest.TestCase):
    def test_wrap_str_preserves_quoted_args_via_shlex(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"id": "art_1"}),
            )
            ts.wrap("python -c 'print(1)'")

            argv = mock_run.call_args.args[0]
            # Find the position after "--" -- everything after is the wrapped argv.
            split_at = argv.index("--")
            wrapped = argv[split_at + 1:]
            self.assertEqual(wrapped, ["python", "-c", "print(1)"])

    def test_wrap_sequence_passes_argv_exactly(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"id": "art_1"}),
            )
            ts.wrap(["python", "-c", "print('hi mom')"])

            argv = mock_run.call_args.args[0]
            split_at = argv.index("--")
            wrapped = argv[split_at + 1:]
            self.assertEqual(wrapped, ["python", "-c", "print('hi mom')"])

    def test_wrap_empty_raises(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError):
            ts.wrap("")
        with self.assertRaises(TreeshipError):
            ts.wrap([])


class BinaryResolutionTests(unittest.TestCase):
    def test_default_uses_treeship_on_path(self) -> None:
        ts = Treeship()
        self.assertEqual(ts.binary, "treeship")

    def test_cli_path_overrides(self) -> None:
        ts = Treeship(cli_path="/opt/treeship/bin/treeship")
        self.assertEqual(ts.binary, "/opt/treeship/bin/treeship")

    def test_explicit_cli_path_threaded_through_to_subprocess(self) -> None:
        ts = Treeship(cli_path="/opt/treeship/bin/treeship")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"id": "art_1"}),
            )
            ts.attest_action(actor="agent://test", action="x")

            argv = mock_run.call_args.args[0]
            self.assertEqual(argv[0], "/opt/treeship/bin/treeship")

    def test_timeout_override_threaded_through(self) -> None:
        ts = Treeship(cli_path="/treeship", timeout=42)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"id": "art_1"}),
            )
            ts.attest_action(actor="agent://t", action="x")
            self.assertEqual(mock_run.call_args.kwargs["timeout"], 42)


class ArtifactIdHandlingTests(unittest.TestCase):
    def test_empty_artifact_id_raises(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(stdout=json.dumps({}))
            with self.assertRaises(TreeshipError) as ctx:
                ts.attest_action(actor="agent://t", action="x")
            self.assertIn("no artifact id", str(ctx.exception))

    def test_artifact_id_under_id_key(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(stdout=json.dumps({"id": "art_aaa"}))
            r = ts.attest_action(actor="agent://t", action="x")
            self.assertEqual(r.artifact_id, "art_aaa")

    def test_artifact_id_under_artifact_id_key(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"artifact_id": "art_bbb"}),
            )
            r = ts.attest_action(actor="agent://t", action="x")
            self.assertEqual(r.artifact_id, "art_bbb")


class SessionReportTests(unittest.TestCase):
    def test_session_report_uses_json_format(self) -> None:
        ts = Treeship()
        json_payload = json.dumps({
            "schema": "treeship/share-result/v1",
            "session_id": "ssn_01",
            "receipt_url": "https://treeship.dev/r/abc",
            "verification_status": "ok",
            "warnings": [],
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(stdout=json_payload)
            r = ts.session_report()

            argv = mock_run.call_args.args[0]
            self.assertIn("--format", argv)
            self.assertIn("json", argv)
            self.assertEqual(r.session_id, "ssn_01")
            self.assertEqual(r.receipt_url, "https://treeship.dev/r/abc")

    def test_session_report_falls_back_to_text_when_json_missing(self) -> None:
        ts = Treeship()
        # First call: simulate older CLI returning non-JSON text.
        # Second call (text fallback): regex-parsed text.
        text_output = (
            "session: ssn_old\n"
            "receipt: https://treeship.dev/r/legacy\n"
            "agents: 2\n"
            "events: 17\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _completed(stdout="not json", returncode=0),
                _completed(stdout=text_output, returncode=0),
            ]
            r = ts.session_report()
            self.assertEqual(r.session_id, "ssn_old")
            self.assertEqual(r.receipt_url, "https://treeship.dev/r/legacy")
            self.assertEqual(r.agents, 2)
            self.assertEqual(r.events, 17)

    def test_session_report_raises_when_neither_format_works(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _completed(stdout="not json", returncode=0),
                _completed(stdout="garbage", returncode=0),
            ]
            with self.assertRaises(TreeshipError):
                ts.session_report()


class LengthAndRangeValidationTests(unittest.TestCase):
    def test_actor_too_long_raises(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError) as ctx:
            ts.attest_action(actor="a" * 257, action="x")
        self.assertIn("actor", str(ctx.exception))
        self.assertIn("max is 256", str(ctx.exception))

    def test_summary_too_long_raises(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError) as ctx:
            ts.attest_decision(actor="agent://t", summary="x" * 4097)
        self.assertIn("summary", str(ctx.exception))

    def test_confidence_out_of_range_raises(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError) as ctx:
            ts.attest_decision(actor="agent://t", confidence=1.5)
        self.assertIn("confidence", str(ctx.exception))

        with self.assertRaises(TreeshipError):
            ts.attest_decision(actor="agent://t", confidence=-0.1)

    def test_confidence_nan_raises(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError):
            ts.attest_decision(actor="agent://t", confidence=float("nan"))

    def test_confidence_in_range_passes(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(stdout=json.dumps({"id": "art_1"}))
            # All four boundary values must pass.
            for c in (0.0, 0.5, 1.0):
                ts.attest_decision(actor="agent://t", confidence=c)

    def test_negative_tokens_raises(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError):
            ts.attest_decision(actor="agent://t", tokens_in=-1)
        with self.assertRaises(TreeshipError):
            ts.attest_decision(actor="agent://t", tokens_out=-5)

    def test_artifact_id_too_long_raises(self) -> None:
        ts = Treeship()
        with self.assertRaises(TreeshipError):
            ts.verify("a" * 257)


class CLIMissingErrorTests(unittest.TestCase):
    def test_file_not_found_carries_actionable_message(self) -> None:
        ts = Treeship(cli_path="/does/not/exist/treeship")
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(TreeshipError) as ctx:
                ts.attest_action(actor="agent://t", action="x")
            self.assertIn("/does/not/exist/treeship", str(ctx.exception))
            self.assertIn("bot_mode=True", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


class ApprovalScopeTests(unittest.TestCase):
    """attest_approval sent no scope, so every call failed at the CLI.

    The CLI refuses an approval that constrains nothing: an unscoped approval
    is a bearer token, and minting one by omission rather than by choice is
    how blanket authority gets created accidentally. The SDK exposed no way to
    pass a scope, so there was no workaround from inside it.

    These assert on the argv the SDK builds rather than on a live CLI, so they
    fail on a wrong flag name rather than only on a wrong outcome.
    """

    def test_no_scope_is_refused_by_the_sdk_not_the_cli(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            with self.assertRaises(ValueError) as ctx:
                ts.attest_approval(approver="me", description="d")
            self.assertIn("scope", str(ctx.exception))
            # Refused before spawning: a failing subprocess would be a worse
            # error for the same mistake.
            mock_run.assert_not_called()

    def test_scope_flags_reach_the_cli(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"id": "art_1", "nonce": "n"}),
            )
            ts.attest_approval(
                approver="me",
                description="d",
                allowed_actions=["deploy.*", "build.*"],
                allowed_actors=["agent://ci"],
                max_uses=3,
            )
            argv = mock_run.call_args.args[0]
            self.assertEqual(argv.count("--allowed-action"), 2)
            self.assertIn("deploy.*", argv)
            self.assertIn("build.*", argv)
            self.assertIn("--allowed-actor", argv)
            self.assertIn("agent://ci", argv)
            self.assertIn("--max-uses", argv)
            self.assertIn("3", argv)
            self.assertNotIn("--unscoped", argv)

    def test_unscoped_is_explicit_and_reaches_the_cli(self) -> None:
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"id": "art_1", "nonce": "n"}),
            )
            ts.attest_approval(approver="me", description="d", unscoped=True)
            self.assertIn("--unscoped", mock_run.call_args.args[0])

    def test_scope_and_unscoped_together_is_refused(self) -> None:
        """Silently preferring one would make the caller's intent unknowable."""
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            with self.assertRaises(ValueError):
                ts.attest_approval(
                    approver="me",
                    description="d",
                    allowed_actions=["x"],
                    unscoped=True,
                )
            mock_run.assert_not_called()

    def test_expires_at_is_a_timestamp_not_a_duration(self) -> None:
        """The parameter was `expires_in`, which invites `1h`.

        The CLI used to accept that verbatim, sign it, then compare it as a
        string -- producing an approval that was born expired. The CLI rejects
        it now; the SDK stops inviting it.
        """
        ts = Treeship()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _completed(
                stdout=json.dumps({"id": "art_1", "nonce": "n"}),
            )
            ts.attest_approval(
                approver="me",
                description="d",
                unscoped=True,
                expires_at="2030-12-31T23:59:59Z",
            )
            argv = mock_run.call_args.args[0]
            self.assertIn("--expires", argv)
            self.assertIn("2030-12-31T23:59:59Z", argv)
