"""Unit tests for the SHA-256 verification path in treeship_sdk.bootstrap.

These tests exercise ``_install_via_github_release`` without ever
touching the network: ``urllib.request.urlopen`` is patched to return a
fake response whose bytes we control. ``platform_release_asset`` is
patched so the test is deterministic across host OS/arch.

The hardening contract under test:

  1. Happy path: matching SHA-256 → target binary exists at
     ``<cache>/treeship`` with mode 0755 and no ``.partial`` left over.
  2. Hash mismatch: ``TreeshipBootstrapError`` raised, ``.partial``
     is deleted, the final ``treeship`` path does NOT exist.
  3. Missing checksum file: ``TreeshipBootstrapError`` raised with
     reason ``checksum-missing`` BEFORE any network call.

Each test isolates filesystem state under a ``tempfile.TemporaryDirectory``
and never writes outside it.
"""

from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from treeship_sdk.bootstrap import (
    TreeshipBootstrapError,
    _install_via_github_release,
)


# Fake binary bytes — small enough to keep test fast, big enough to
# exercise the streaming chunk loop (default chunk size is 64KiB).
_FAKE_BINARY = b"#!/bin/sh\necho 'treeship 0.0.0-test'\n" * 4096
_FAKE_SHA256 = hashlib.sha256(_FAKE_BINARY).hexdigest()

# Asset name we'll pretend the host platform maps to. The
# ``_install_via_github_release`` flow consults
# ``platform_release_asset`` exactly once at the top; we override that.
_ASSET = "treeship-test-asset"


class _FakeResponse:
    """Minimal stand-in for the object urllib.request.urlopen yields."""

    def __init__(self, payload: bytes):
        self._buf = io.BytesIO(payload)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._buf.close()
        return False


def _fake_urlopen_ok(_url, timeout=30):  # noqa: ARG001 — match urllib signature
    return _FakeResponse(_FAKE_BINARY)


def _fake_urlopen_mutated(_url, timeout=30):  # noqa: ARG001
    # Returns different bytes than _FAKE_BINARY → hash will not match
    # the expected _FAKE_SHA256.
    return _FakeResponse(_FAKE_BINARY + b"tampered")


class GithubReleaseChecksumTests(unittest.TestCase):
    """Cover the verify-before-chmod contract."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self._tmp.name) / "cache"
        # _install_via_github_release will mkdir this itself, but we
        # leave the parent in place so cleanup is unambiguous.

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    def test_matching_hash_installs_binary_and_clears_partial(self) -> None:
        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,
        ), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
            side_effect=_fake_urlopen_ok,
        ), patch(
            "treeship_sdk.bootstrap._probe_binary",
            return_value="treeship 0.0.0-test",
        ):
            result = _install_via_github_release(self.cache_dir, version="0.0.0-test")

        self.assertIsNotNone(result)
        assert result is not None  # narrow for type-checker
        self.assertTrue(result.ok)
        self.assertEqual(result.source, "github-release")

        target = self.cache_dir / "treeship"
        partial = self.cache_dir / "treeship.partial"

        # The binary lives at the final path with the expected bytes.
        self.assertTrue(target.is_file(), "expected target binary to exist")
        self.assertEqual(target.read_bytes(), _FAKE_BINARY)

        # No .partial leftover.
        self.assertFalse(partial.exists(), "partial file should be cleaned up")

        # Mode 0755 (or compatible) — we explicitly chmod'd it.
        mode = target.stat().st_mode & 0o777
        self.assertEqual(mode, 0o755, f"expected mode 0755, got {oct(mode)}")

    # ------------------------------------------------------------------
    # Hash mismatch — the load-bearing security check
    # ------------------------------------------------------------------

    def test_hash_mismatch_raises_and_deletes_partial_and_target(self) -> None:
        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,  # expected hash
        ), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
            side_effect=_fake_urlopen_mutated,  # different bytes → bad hash
        ):
            with self.assertRaises(TreeshipBootstrapError) as ctx:
                _install_via_github_release(self.cache_dir, version="0.0.0-test")

        err = ctx.exception
        self.assertEqual(err.reason, "binary-checksum-mismatch")
        # The error message must surface both hashes so an operator can
        # diagnose without scraping debug logs.
        self.assertIn(_FAKE_SHA256, str(err))
        self.assertIn(
            hashlib.sha256(_FAKE_BINARY + b"tampered").hexdigest(),
            str(err),
        )

        target = self.cache_dir / "treeship"
        partial = self.cache_dir / "treeship.partial"

        # The final binary must NOT exist. If it did, a retry could run it.
        self.assertFalse(target.exists(), "tampered binary must not land at final path")
        # The partial must also be gone — bad bytes deleted, not stranded.
        self.assertFalse(partial.exists(), "partial file must be removed on mismatch")

    def test_hash_mismatch_does_not_chmod_partial(self) -> None:
        """A stronger version of the above: prove we don't even touch chmod.

        Patches ``os.chmod`` and asserts it is never called when the
        hash doesn't match. Catches a regression where someone reorders
        the steps and chmods before verify.
        """
        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,
        ), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
            side_effect=_fake_urlopen_mutated,
        ), patch(
            "treeship_sdk.bootstrap.os.chmod",
        ) as mock_chmod:
            with self.assertRaises(TreeshipBootstrapError):
                _install_via_github_release(self.cache_dir, version="0.0.0-test")

            mock_chmod.assert_not_called()

    # ------------------------------------------------------------------
    # Missing checksum file — fail before talking to the network
    # ------------------------------------------------------------------

    def test_missing_checksum_raises_with_clear_message(self) -> None:
        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=None,  # simulates malformed/missing data file
        ), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
        ) as mock_urlopen:
            with self.assertRaises(TreeshipBootstrapError) as ctx:
                _install_via_github_release(self.cache_dir, version="0.0.0-test")

            # The download must never have been attempted.
            mock_urlopen.assert_not_called()

        err = ctx.exception
        self.assertEqual(err.reason, "checksum-missing")
        self.assertIn(_ASSET, str(err))
        # Message guides the user toward a real recovery, not a vague error.
        self.assertIn("reinstall", str(err).lower())

    # ------------------------------------------------------------------
    # Network failure mid-download — partial cleanup, fail-loud
    # ------------------------------------------------------------------

    def test_download_io_error_raises_and_cleans_up(self) -> None:
        class _BoomResponse:
            def __enter__(self): return self
            def __exit__(self, *_a): return False
            def read(self, _n=-1):
                raise IOError("simulated network drop")

        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,
        ), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
            return_value=_BoomResponse(),
        ):
            with self.assertRaises(TreeshipBootstrapError) as ctx:
                _install_via_github_release(self.cache_dir, version="0.0.0-test")

        self.assertEqual(ctx.exception.reason, "binary-download-failed")
        # No partial or target file stranded.
        self.assertFalse((self.cache_dir / "treeship").exists())
        self.assertFalse((self.cache_dir / "treeship.partial").exists())


class ReadExpectedChecksumTests(unittest.TestCase):
    """Direct tests of the checksum-loading helper."""

    def test_returns_none_when_data_file_absent(self) -> None:
        # Pick an asset name we know there is no data file for. The
        # release pipeline writes specific ones; this is a made-up
        # name that won't have a corresponding file.
        from treeship_sdk.bootstrap import _read_expected_checksum

        result = _read_expected_checksum("treeship-nonexistent-asset-xyz")
        self.assertIsNone(result)

    def test_rejects_malformed_hex(self) -> None:
        # Stub the importlib.resources lookup so we can inject a
        # malformed payload without writing a real file.
        from treeship_sdk import bootstrap

        class _StubResource:
            def is_file(self): return True
            def read_text(self, encoding="utf-8"):  # noqa: ARG002
                return "not-hex-not-64-chars\n"

        class _StubRoot:
            def joinpath(self, _name): return _StubResource()

        with patch(
            "importlib.resources.files",
            return_value=_StubRoot(),
        ):
            self.assertIsNone(bootstrap._read_expected_checksum("anything"))

    def test_accepts_valid_lowercase_hex(self) -> None:
        from treeship_sdk import bootstrap

        good = "a" * 64

        class _StubResource:
            def is_file(self): return True
            def read_text(self, encoding="utf-8"):  # noqa: ARG002
                return good + "\n"

        class _StubRoot:
            def joinpath(self, _name): return _StubResource()

        with patch(
            "importlib.resources.files",
            return_value=_StubRoot(),
        ):
            self.assertEqual(bootstrap._read_expected_checksum("anything"), good)

    def test_normalizes_uppercase_hex_to_lowercase(self) -> None:
        from treeship_sdk import bootstrap

        upper = "A" * 64

        class _StubResource:
            def is_file(self): return True
            def read_text(self, encoding="utf-8"):  # noqa: ARG002
                return upper + "\n"

        class _StubRoot:
            def joinpath(self, _name): return _StubResource()

        with patch(
            "importlib.resources.files",
            return_value=_StubRoot(),
        ):
            self.assertEqual(
                bootstrap._read_expected_checksum("anything"),
                "a" * 64,
            )


if __name__ == "__main__":
    unittest.main()
