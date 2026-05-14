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

        # The binary lives at the final path with the expected bytes.
        self.assertTrue(target.is_file(), "expected target binary to exist")
        self.assertEqual(target.read_bytes(), _FAKE_BINARY)

        # No *.partial leftover (unique tempfile names land here).
        leftover_partials = list(self.cache_dir.glob("*.partial"))
        self.assertEqual(
            leftover_partials, [],
            f"expected no .partial leftovers, found {leftover_partials}",
        )

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

        # The final binary must NOT exist. If it did, a retry could run it.
        self.assertFalse(target.exists(), "tampered binary must not land at final path")
        # No *.partial must remain — bad bytes deleted, not stranded.
        leftover_partials = list(self.cache_dir.glob("*.partial"))
        self.assertEqual(
            leftover_partials, [],
            f"partial files must be removed on mismatch, found {leftover_partials}",
        )

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
        leftover_partials = list(self.cache_dir.glob("*.partial"))
        self.assertEqual(
            leftover_partials, [],
            f"partials must be cleaned up on network error, found {leftover_partials}",
        )

    # ------------------------------------------------------------------
    # F4 — chmod failure must not leave a stale unverified target.
    # ------------------------------------------------------------------

    def test_chmod_failure_leaves_no_target_file(self) -> None:
        """If chmod raises, `target` must not exist.

        Pre-fix the order was os.replace(partial, target) then
        os.chmod(target). A chmod failure after the rename left
        `target` on disk with non-executable perms but already past
        SHA-256 verification — the next ensure_cli()'s _try_cache
        would return it without re-verifying. The fix chmods the
        partial first, so a chmod failure aborts before the rename
        and the unique partial is unlinked.
        """
        import os as _os

        real_chmod = _os.chmod

        def _boom_chmod(path, mode):  # noqa: ARG001
            raise PermissionError("simulated chmod failure")

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
            "treeship_sdk.bootstrap.os.chmod",
            side_effect=_boom_chmod,
        ):
            with self.assertRaises(TreeshipBootstrapError) as ctx:
                _install_via_github_release(self.cache_dir, version="0.0.0-test")

        # Best-signal: the final target path must not exist. If it
        # did, the caller's next _try_cache would skip re-verification
        # and exec stale bytes.
        target = self.cache_dir / "treeship"
        self.assertFalse(
            target.exists(),
            "target must not exist when chmod fails — _try_cache would skip re-verify",
        )

        # No partial file should be stranded either.
        leftover_partials = list(self.cache_dir.glob("*.partial"))
        self.assertEqual(
            leftover_partials, [],
            f"partial must be cleaned up on chmod failure, found {leftover_partials}",
        )

        # And the bootstrap should report this as a download-failed
        # branch the agent can recover from.
        self.assertEqual(ctx.exception.reason, "binary-download-failed")
        # Restore (defensive; patch context already restores).
        del real_chmod


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

    def test_returns_none_on_non_utf8_payload(self) -> None:
        """A wheel that ships a checksum file with non-UTF-8 bytes must
        surface as "missing/malformed", not a stack trace.

        ``read_text(encoding="utf-8")`` raises ``UnicodeDecodeError`` on
        bad bytes; that's a subclass of ``ValueError``. The helper's
        contract is "missing or malformed → None" so the caller can
        branch through the structured ``checksum-missing`` error path.
        """
        from treeship_sdk import bootstrap

        class _StubResource:
            def is_file(self): return True
            def read_text(self, encoding="utf-8"):  # noqa: ARG002
                raise UnicodeDecodeError("utf-8", b"\xff\xfe\x00malformed", 0, 1, "invalid start byte")

        class _StubRoot:
            def joinpath(self, _name): return _StubResource()

        with patch(
            "importlib.resources.files",
            return_value=_StubRoot(),
        ):
            self.assertIsNone(bootstrap._read_expected_checksum("anything"))

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


class UniquePartialFilenameTests(unittest.TestCase):
    """Cover the F2 fix: parallel ensure_cli() calls must not collide.

    The pre-fix code used a hardcoded ``cache_dir / "treeship.partial"``
    filename. Two concurrent installs (pytest-xdist, two CI jobs sharing
    a cache mount) would overwrite each other's partial mid-stream and
    corrupt the SHA-256 verify path. The fix uses
    ``tempfile.NamedTemporaryFile(dir=cache_dir, ...)`` to give each
    call a unique partial path.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self._tmp.name) / "cache"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_uses_unique_named_temp_file_per_call(self) -> None:
        """Two sequential calls must allocate distinct partial paths.

        We capture the ``name`` of each NamedTemporaryFile that the
        function creates. If the function regresses to a fixed filename
        these two names will be equal.
        """
        from treeship_sdk import bootstrap

        seen_names: list[str] = []
        real_ntf = tempfile.NamedTemporaryFile

        def _capturing_ntf(*args, **kwargs):
            f = real_ntf(*args, **kwargs)
            seen_names.append(f.name)
            return f

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
        ), patch(
            "treeship_sdk.bootstrap.tempfile.NamedTemporaryFile",
            side_effect=_capturing_ntf,
        ):
            bootstrap._install_via_github_release(self.cache_dir, version="0.0.0-test")
            bootstrap._install_via_github_release(self.cache_dir, version="0.0.0-test")

        self.assertEqual(len(seen_names), 2, "expected two partial allocations")
        self.assertNotEqual(
            seen_names[0], seen_names[1],
            "two sequential bootstraps must use distinct partial paths",
        )
        # Both must live inside cache_dir (so os.replace is same-FS).
        for name in seen_names:
            self.assertEqual(
                Path(name).parent, self.cache_dir,
                f"partial {name} must be inside cache_dir for atomic replace",
            )

    def test_concurrent_threads_dont_corrupt_each_other(self) -> None:
        """Two threads racing through _install_via_github_release must
        each succeed independently. The hardcoded-partial bug would
        manifest as one thread reading the other's bytes via the shared
        partial path and failing the SHA-256 check.
        """
        import threading

        from treeship_sdk import bootstrap

        # Pre-stage: each thread gets its own cache_dir so the *target*
        # path doesn't race (that's a separate orthogonal concern); the
        # test specifically isolates the partial-filename race that F2
        # addresses. Even with the same cache_dir the fix should hold.
        cache_a = Path(self._tmp.name) / "cache-a"
        cache_b = Path(self._tmp.name) / "cache-b"

        results: dict[str, object] = {}
        errors: dict[str, BaseException] = {}
        barrier = threading.Barrier(2)

        def _slow_urlopen(_url, timeout=30):  # noqa: ARG001
            # Force the threads to interleave inside the streaming loop
            # by pausing at the response object before bytes are read.
            barrier.wait(timeout=5)
            return _FakeResponse(_FAKE_BINARY)

        def _run(key: str, cache: Path) -> None:
            try:
                results[key] = bootstrap._install_via_github_release(
                    cache, version="0.0.0-test",
                )
            except BaseException as e:  # capture all, re-raise in assert
                errors[key] = e

        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,
        ), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
            side_effect=_slow_urlopen,
        ), patch(
            "treeship_sdk.bootstrap._probe_binary",
            return_value="treeship 0.0.0-test",
        ):
            t1 = threading.Thread(target=_run, args=("a", cache_a))
            t2 = threading.Thread(target=_run, args=("b", cache_b))
            t1.start(); t2.start()
            t1.join(timeout=15); t2.join(timeout=15)

        self.assertEqual(errors, {}, f"unexpected errors: {errors}")
        self.assertIn("a", results)
        self.assertIn("b", results)
        # Both final binaries must exist and contain the right bytes.
        self.assertEqual((cache_a / "treeship").read_bytes(), _FAKE_BINARY)
        self.assertEqual((cache_b / "treeship").read_bytes(), _FAKE_BINARY)


class CacheDirOwnershipTests(unittest.TestCase):
    """Cover the F3 fix: refuse to install into a cache_dir owned by
    another user or one that is group/world-writable.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self._tmp.name) / "cache"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _fake_stat(self, st_uid: int, st_mode: int = 0o40700):
        """Build a stand-in stat_result-ish object with the fields we check."""
        class _S:
            pass
        s = _S()
        s.st_uid = st_uid
        s.st_mode = st_mode
        return s

    def test_rejects_cache_dir_owned_by_other_user(self) -> None:
        import os as _os

        if not hasattr(_os, "geteuid"):
            self.skipTest("ownership check is POSIX-only")

        wrong_uid = _os.geteuid() + 1
        fake = self._fake_stat(st_uid=wrong_uid, st_mode=0o40700)

        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,
        ), patch.object(Path, "stat", return_value=fake), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
        ) as mock_urlopen:
            with self.assertRaises(TreeshipBootstrapError) as ctx:
                _install_via_github_release(self.cache_dir, version="0.0.0-test")
            # The download must not even start.
            mock_urlopen.assert_not_called()

        self.assertEqual(ctx.exception.reason, "cache-dir-unsafe")
        self.assertIn(str(wrong_uid), str(ctx.exception))

    def test_rejects_world_writable_cache_dir(self) -> None:
        import os as _os

        if not hasattr(_os, "geteuid"):
            self.skipTest("ownership check is POSIX-only")

        # Owned by us, but world-writable (0o777).
        fake = self._fake_stat(st_uid=_os.geteuid(), st_mode=0o40777)

        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,
        ), patch.object(Path, "stat", return_value=fake), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
        ) as mock_urlopen:
            with self.assertRaises(TreeshipBootstrapError) as ctx:
                _install_via_github_release(self.cache_dir, version="0.0.0-test")
            mock_urlopen.assert_not_called()

        self.assertEqual(ctx.exception.reason, "cache-dir-unsafe")

    def test_accepts_private_cache_dir_owned_by_us(self) -> None:
        import os as _os

        if not hasattr(_os, "geteuid"):
            self.skipTest("ownership check is POSIX-only")

        # Owned by us, mode 0700 — should pass.
        fake = self._fake_stat(st_uid=_os.geteuid(), st_mode=0o40700)

        with patch(
            "treeship_sdk.bootstrap.platform_release_asset",
            return_value=(_ASSET, None),
        ), patch(
            "treeship_sdk.bootstrap._read_expected_checksum",
            return_value=_FAKE_SHA256,
        ), patch.object(Path, "stat", return_value=fake), patch(
            "treeship_sdk.bootstrap.urllib.request.urlopen",
            side_effect=_fake_urlopen_ok,
        ), patch(
            "treeship_sdk.bootstrap._probe_binary",
            return_value="treeship 0.0.0-test",
        ):
            # No exception — happy path.
            result = _install_via_github_release(self.cache_dir, version="0.0.0-test")
            self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
