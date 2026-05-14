"""
Treeship CLI bootstrap — agent-native install resolution.

The Treeship Python SDK shells out to the `treeship` CLI binary. When
that binary isn't on PATH (a fresh AI-agent environment, a sandboxed
CI, a brand-new dev machine), the SDK should resolve it without
asking the human a clarifying question.

This module implements the resolution order:

  1. ``$TREESHIP_BIN`` env var, if set and pointing at an executable.
  2. ``treeship`` on PATH, if it's a working binary.
  3. Sibling install via npm in a per-user cache dir, if ``npx`` is
     available. (``npx -p treeship -c 'treeship --version'`` works
     today; we copy the resolved binary out to the cache.)
  4. Direct download from the matching GitHub Release asset for the
     current platform, into the same cache dir.

Each step is safe to run inside a sandbox: the cache dir defaults to
``$HOME/.cache/treeship/bin`` (or the platform equivalent); the
``--config`` path the caller passes elsewhere is respected; nothing
runs ``sudo``; nothing modifies ``$PATH``.

The ``ensure_cli()`` function returns the path to a working binary or
raises :class:`TreeshipBootstrapError` with a structured ``reason``
suitable for an AI agent to branch on. Use ``ensure_cli(json=True)``
to get a dict result instead of a path; ``Treeship(bot_mode=True)``
calls this internally so an agent can do:

    from treeship_sdk import Treeship

    ts = Treeship(bot_mode=True)
    # Treeship now has a working CLI even on a fresh machine; no prompt.

There is also a ``python -m treeship_sdk.bootstrap_cli`` entry point
that prints the JSON result and exits — useful for shell scripts and
agents that want to bootstrap without instantiating the SDK first.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


__all__ = [
    "BootstrapResult",
    "TreeshipBootstrapError",
    "ensure_cli",
    "default_cache_dir",
    "platform_release_asset",
]


# ---------------------------------------------------------------------------
# Binary integrity (SHA-256) — supply-chain hardening
# ---------------------------------------------------------------------------
#
# When we fall back to downloading the CLI binary from a GitHub Release,
# we must verify the bytes before we ever chmod +x and exec them.
#
# Trust roots:
#   1. The expected SHA-256 ships with the wheel via PyPI. The release
#      pipeline writes it into ``treeship_sdk/_data/expected-checksum-<asset>.txt``
#      at build time (see .github/workflows/release.yml). It is never
#      committed to the repo and never fetched at runtime.
#   2. The binary arrives via GitHub Releases.
#
# Because the hash arrives via PyPI and the binary via GitHub, an
# attacker would have to compromise both registries to slip a tampered
# binary past install. If either is tampered, the hashes disagree and
# we abort — loudly. No silent fallback.
#
# Earlier versions (<= 0.10.2) downloaded the binary, chmod +x'd it,
# and executed it with zero integrity check. This module is the
# Python-side mirror of the npm postinstall hardening from PR #72.

_CHECKSUM_DATA_PACKAGE = "treeship_sdk._data"
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _read_expected_checksum(asset: str) -> Optional[str]:
    """Return the expected SHA-256 hex for ``asset``, or None if missing/malformed.

    Reads from the data file that the release pipeline embedded in the
    wheel. Format: a single line, lowercase hex, 64 characters. An
    absent or malformed file means the install is unverifiable; the
    caller must refuse to proceed.
    """
    filename = f"expected-checksum-{asset}.txt"
    try:
        # importlib.resources.files() is available on Python >= 3.9.
        from importlib.resources import files

        data_root = files(_CHECKSUM_DATA_PACKAGE)
        resource = data_root.joinpath(filename)
        if not resource.is_file():
            return None
        raw = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError, ValueError):
        # ValueError catches UnicodeDecodeError (a subclass) — a wheel
        # that ships a checksum file with non-UTF-8 bytes must surface
        # as "missing/malformed" (None) so the caller routes through the
        # structured ``checksum-missing`` error path, not a stack trace.
        return None
    hex_str = raw.strip().lower()
    if not _HEX_SHA256_RE.match(hex_str):
        return None
    return hex_str


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TreeshipBootstrapError(Exception):
    """Raised when ensure_cli() can't resolve a working binary.

    The ``reason`` attribute is a stable kebab-case identifier that AI
    agents can branch on; the message is a human-readable summary.
    """

    def __init__(self, reason: str, message: str, attempted: list[str]) -> None:
        super().__init__(message)
        self.reason: str = reason
        self.attempted: list[str] = attempted

    def to_dict(self) -> dict:
        return {
            "ok":         False,
            "reason":     self.reason,
            "message":    str(self),
            "attempted":  self.attempted,
        }


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------


@dataclass
class BootstrapResult:
    """Result of a successful ensure_cli() resolution.

    The ``source`` enum tells a downstream consumer how the binary was
    found, so an AI agent can decide whether to surface that to a
    human ("I installed Treeship from the GitHub Release") vs treat it
    as already-present.
    """

    ok: bool
    binary: str            # absolute path to the working binary
    version: str           # the version the binary reports
    source: str            # "env" | "path" | "npm-cache" | "github-release"
    cache_dir: Optional[str] = None  # only set for the cache-based sources

    def to_dict(self) -> dict:
        return {**asdict(self), "schema": "treeship/bootstrap-result/v1"}


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def default_cache_dir() -> Path:
    """Return the per-user cache directory used for fallback installs.

    Honors ``$TREESHIP_CACHE`` if set. Otherwise picks the platform
    convention: ``$XDG_CACHE_HOME/treeship/bin`` on Linux,
    ``~/Library/Caches/treeship/bin`` on macOS, ``%LOCALAPPDATA%/treeship/bin``
    on Windows.
    """
    override = os.environ.get("TREESHIP_CACHE")
    if override:
        return Path(override).expanduser() / "bin"

    sys_platform = sys.platform
    if sys_platform == "darwin":
        return Path.home() / "Library" / "Caches" / "treeship" / "bin"
    if sys_platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(local) / "treeship" / "bin"
    # linux / *bsd
    xdg = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(xdg) / "treeship" / "bin"


def platform_release_asset() -> tuple[str, Optional[str]]:
    """Return ``(asset_name, error)`` for the current platform.

    Returns ``("", reason)`` when the platform isn't supported by the
    GitHub Release publisher. The first element is the asset filename
    (e.g. ``treeship-darwin-aarch64``) on supported platforms.
    """
    sys_platform = sys.platform
    machine = platform.machine().lower()
    if sys_platform == "darwin":
        if machine in ("arm64", "aarch64"):
            return ("treeship-darwin-aarch64", None)
        if machine in ("x86_64", "amd64"):
            return ("treeship-darwin-x86_64", None)
        return ("", f"unsupported macOS arch {machine}")
    if sys_platform.startswith("linux"):
        if machine in ("x86_64", "amd64"):
            return ("treeship-linux-x86_64", None)
        return ("", f"unsupported Linux arch {machine}")
    if sys_platform == "win32":
        return ("", "Windows install must use `npm install -g treeship` (no Windows binary on the GitHub Release)")
    return ("", f"unsupported platform {sys_platform}")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


def _probe_binary(path: str) -> Optional[str]:
    """Return the version string if `path` is a working treeship binary.

    A working binary responds to ``--version`` with output like
    ``treeship 0.9.11`` on stdout within a few seconds. Anything else
    is treated as not-a-binary.
    """
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        return None
    out = (proc.stdout or "").strip()
    # Expected format: "treeship X.Y.Z"
    if out.startswith("treeship "):
        return out
    return None


def _try_env() -> Optional[BootstrapResult]:
    bin_env = os.environ.get("TREESHIP_BIN")
    if not bin_env:
        return None
    p = Path(bin_env).expanduser()
    if not p.is_file():
        return None
    v = _probe_binary(str(p))
    if v is None:
        return None
    return BootstrapResult(ok=True, binary=str(p), version=v, source="env")


def _try_path() -> Optional[BootstrapResult]:
    found = shutil.which("treeship")
    if not found:
        return None
    v = _probe_binary(found)
    if v is None:
        return None
    return BootstrapResult(ok=True, binary=found, version=v, source="path")


def _try_cache(cache_dir: Path) -> Optional[BootstrapResult]:
    cached = cache_dir / "treeship"
    if not cached.is_file():
        return None
    v = _probe_binary(str(cached))
    if v is None:
        return None
    return BootstrapResult(
        ok=True, binary=str(cached), version=v,
        source="cache", cache_dir=str(cache_dir),
    )


# ---------------------------------------------------------------------------
# Installers
# ---------------------------------------------------------------------------


def _install_via_github_release(
    cache_dir: Path,
    version: Optional[str] = None,
) -> Optional[BootstrapResult]:
    """Download the matching platform binary from the GitHub Release.

    No `sudo`; writes only into ``cache_dir``. Uses the "latest"
    release by default; pass ``version`` (e.g. ``"0.9.11"``) to pin.

    Integrity:
        Before the downloaded bytes are ever made executable, this
        function verifies their SHA-256 against the expected hash that
        the release pipeline embedded in the wheel (see
        :func:`_read_expected_checksum`). On mismatch — or if the
        expected hash is missing from the install — it raises
        :class:`TreeshipBootstrapError`. Never falls back silently.

    Returns:
        ``BootstrapResult`` on success, ``None`` if the current
        platform has no published release asset.

    Raises:
        :class:`TreeshipBootstrapError`: when the expected checksum is
            missing, the download fails, or the hash disagrees. The
            ``reason`` is one of ``checksum-missing``,
            ``binary-download-failed``, ``binary-checksum-mismatch``.
    """
    asset, err = platform_release_asset()
    if err:
        return None

    expected = _read_expected_checksum(asset)
    if expected is None:
        raise TreeshipBootstrapError(
            "checksum-missing",
            (
                "treeship-sdk install is missing the expected SHA-256 for "
                f"'{asset}'. The wheel was published without a binary "
                "integrity hash and cannot install the CLI safely. "
                "Recover: reinstall the SDK (`pip install --force-reinstall "
                "treeship-sdk`); if that doesn't help, file an issue at "
                "https://github.com/zerkerlabs/treeship/issues so we can "
                "re-publish it. Alternatively, install the CLI directly: "
                "`npm install -g treeship` or download from "
                "https://github.com/zerkerlabs/treeship/releases."
            ),
            [f"checksum:{asset}"],
        )

    cache_dir.mkdir(parents=True, exist_ok=True)

    # Cache-dir ownership/perms check. A pre-existing cache_dir owned
    # by another user (multi-user macOS box, shared dev VM, mounted
    # volume, a sibling agent's home) means whoever owns it can
    # pre-stage a malicious binary at the target path. The mkdir
    # above is a no-op when the directory already exists, so we MUST
    # validate the inode we got. On Windows there's no euid concept
    # and `platform_release_asset` already refuses to serve Windows,
    # so we skip the check there.
    if hasattr(os, "geteuid"):
        try:
            st = cache_dir.stat()
        except OSError as exc:
            raise TreeshipBootstrapError(
                "cache-dir-unsafe",
                (
                    f"could not stat cache_dir {cache_dir} to verify "
                    f"ownership: {exc}. Refusing to install into a "
                    "directory we can't inspect. Recover: set "
                    "$TREESHIP_CACHE to a path you own, or remove the "
                    "existing cache directory."
                ),
                [f"cache:{cache_dir}"],
            ) from exc
        euid = os.geteuid()
        if st.st_uid != euid:
            raise TreeshipBootstrapError(
                "cache-dir-unsafe",
                (
                    f"cache_dir {cache_dir} is owned by uid {st.st_uid}, "
                    f"not the current user (uid {euid}). Refusing to "
                    "install — another user could pre-stage a malicious "
                    "binary here. Recover: set $TREESHIP_CACHE to a path "
                    "you own (e.g. under your home directory), or remove "
                    "the existing cache directory and let treeship "
                    "recreate it."
                ),
                [f"cache:{cache_dir}"],
            )
        if st.st_mode & 0o022 != 0:
            raise TreeshipBootstrapError(
                "cache-dir-unsafe",
                (
                    f"cache_dir {cache_dir} is group- or world-writable "
                    f"(mode {oct(st.st_mode & 0o777)}). Refusing to "
                    "install — another user could overwrite the binary "
                    "between download and exec. Recover: `chmod 700 "
                    f"{cache_dir}` or move the cache to a private path "
                    "via $TREESHIP_CACHE."
                ),
                [f"cache:{cache_dir}"],
            )

    target = cache_dir / "treeship"
    url = (
        f"https://github.com/zerkerlabs/treeship/releases/download/v{version}/{asset}"
        if version
        else f"https://github.com/zerkerlabs/treeship/releases/latest/download/{asset}"
    )

    # Use a unique partial filename so two parallel ensure_cli() calls
    # (pytest-xdist, two CI jobs sharing a cache mount, two Treeship
    # SDK instances in the same process) can't overwrite each other's
    # mid-stream bytes. The earlier fixed-name "treeship.partial"
    # silently raced. tempfile.NamedTemporaryFile guarantees uniqueness
    # within cache_dir.
    partial = tempfile.NamedTemporaryFile(
        dir=str(cache_dir),
        prefix="treeship-",
        suffix=".partial",
        delete=False,
    )
    partial_path = partial.name

    def _cleanup_partial() -> None:
        """Best-effort removal of the in-progress partial file."""
        try:
            os.unlink(partial_path)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    # Stream the download into the unique partial, computing SHA-256
    # incrementally so we never hold the full binary in memory.
    hasher = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # nosec B310 (vetted https GitHub URL)
            try:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    partial.write(chunk)
            finally:
                partial.close()
    except Exception as exc:
        # Clean up the partial so a retry can't pick up bad bytes.
        _cleanup_partial()
        raise TreeshipBootstrapError(
            "binary-download-failed",
            (
                f"could not download {asset} from {url}: {exc}. "
                "Recover: re-run the install (transient network/CDN "
                "issues clear up), or download the binary directly from "
                "https://github.com/zerkerlabs/treeship/releases and "
                "place it on PATH."
            ),
            [f"download:{url}"],
        ) from exc

    got = hasher.hexdigest()
    if got != expected:
        # Delete the partial BEFORE we abort. A retry must not be able
        # to chmod the bad bytes that are sitting on disk.
        _cleanup_partial()
        raise TreeshipBootstrapError(
            "binary-checksum-mismatch",
            (
                "SHA-256 mismatch on downloaded binary. Do not run it. "
                f"url={url} expected={expected} got={got}. "
                "This means either the GitHub Release was tampered with, "
                "a CDN cached a stale or malicious binary, or the PyPI "
                "wheel and the release are out of sync. Recover: "
                "re-run the install in case it's a CDN race; if the "
                "mismatch persists, file an issue at "
                "https://github.com/zerkerlabs/treeship/issues."
            ),
            [f"download:{url}", f"expected:{expected}", f"got:{got}"],
        )

    # Hash matched. Chmod the partial BEFORE the atomic rename so that
    # `target` only ever appears on disk in its final, executable
    # state. If we chmodded AFTER os.replace, a chmod failure (read-
    # only FS, exotic perms, NFS race) would leave the bytes at
    # `target` without the executable bit but already past
    # verification — the next ensure_cli()'s _try_cache would happily
    # return that path because it doesn't re-verify the SHA. By
    # ordering chmod first, any chmod failure causes us to abort with
    # the bytes still under the unique partial name, which we then
    # unlink — so `target` never exists in an unverified state.
    try:
        os.chmod(partial_path, 0o755)
    except OSError as exc:
        _cleanup_partial()
        raise TreeshipBootstrapError(
            "binary-download-failed",
            f"could not set executable bit on {asset}: {exc}",
            [f"download:{url}", f"finalize:{partial_path}"],
        ) from exc

    try:
        os.replace(partial_path, target)
    except OSError as exc:
        # The bytes were correct and chmodded; rename failed (rare:
        # cross-device, permission, target locked). Clean up the
        # partial so we don't leave verified-but-orphaned bytes that
        # a future _try_cache might pick up if a symlink shuffle
        # happened.
        _cleanup_partial()
        raise TreeshipBootstrapError(
            "binary-download-failed",
            f"could not finalize {asset}: {exc}",
            [f"download:{url}", f"finalize:{target}"],
        ) from exc

    v = _probe_binary(str(target))
    if v is None:
        return None
    return BootstrapResult(
        ok=True, binary=str(target), version=v,
        source="github-release", cache_dir=str(cache_dir),
    )


def _install_via_npm_global(cache_dir: Path) -> Optional[BootstrapResult]:
    """Install via npm into a per-user prefix, then symlink the binary.

    Uses ``npm install --prefix <cache_dir>/.npm treeship`` so the
    install is fully isolated from any system-wide npm setup. The
    resolved binary lives at ``<cache_dir>/.npm/node_modules/.bin/treeship``;
    we symlink it to ``cache_dir/treeship`` for consistency with the
    GitHub Release path.
    """
    if shutil.which("npm") is None:
        return None
    npm_prefix = cache_dir / ".npm"
    npm_prefix.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            ["npm", "install", "--prefix", str(npm_prefix), "treeship", "--silent"],
            capture_output=True, text=True, timeout=180,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    inner_bin = npm_prefix / "node_modules" / ".bin" / "treeship"
    if not inner_bin.is_file():
        return None
    # Stable path that matches the cached-binary probe.
    target = cache_dir / "treeship"
    try:
        if target.exists() or target.is_symlink():
            target.unlink()
        target.symlink_to(inner_bin.resolve())
    except OSError:
        # Fallback: copy the binary if symlinks aren't allowed (Windows
        # without dev-mode, sandboxes that block symlink creation).
        try:
            shutil.copyfile(inner_bin, target)
            target.chmod(0o755)
        except OSError:
            return None
    v = _probe_binary(str(target))
    if v is None:
        return None
    return BootstrapResult(
        ok=True, binary=str(target), version=v,
        source="npm-cache", cache_dir=str(cache_dir),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ensure_cli(
    *,
    cache_dir: Optional[Path] = None,
    pinned_version: Optional[str] = None,
    allow_install: bool = True,
) -> BootstrapResult:
    """Resolve a working ``treeship`` binary.

    Order: env var → PATH → cache → npm install → GitHub Release.
    Each step is fast and idempotent; the function exits at the first
    success.

    Args:
        cache_dir: Override the default cache location. Useful in
            tests and sandboxes.
        pinned_version: When the GitHub Release fallback fires, pin
            to this version (e.g. ``"0.9.11"``). Defaults to ``latest``.
        allow_install: Set to ``False`` to disable the npm-install and
            GitHub-Release fallbacks. Useful when the agent should
            fail loudly rather than reach out to the network.

    Returns:
        :class:`BootstrapResult` describing the resolved binary.

    Raises:
        :class:`TreeshipBootstrapError` if every probe failed.
    """
    cache = cache_dir or default_cache_dir()
    attempted: list[str] = []

    # 1. Env var (explicit user override).
    attempted.append("env:TREESHIP_BIN")
    r = _try_env()
    if r is not None:
        return r

    # 2. PATH.
    attempted.append("path:treeship")
    r = _try_path()
    if r is not None:
        return r

    # 3. Cache directory from a prior bootstrap.
    attempted.append(f"cache:{cache}")
    r = _try_cache(cache)
    if r is not None:
        return r

    if not allow_install:
        raise TreeshipBootstrapError(
            "no-binary-found-and-install-disabled",
            "treeship binary not found in env, PATH, or cache; install fallbacks are disabled",
            attempted,
        )

    # 4. Try npm install into the cache.
    attempted.append("install:npm")
    r = _install_via_npm_global(cache)
    if r is not None:
        return r

    # 5. Direct GitHub Release download for the current platform.
    attempted.append("install:github-release")
    r = _install_via_github_release(cache, version=pinned_version)
    if r is not None:
        return r

    raise TreeshipBootstrapError(
        "all-resolution-paths-failed",
        "could not resolve a working treeship binary via env, PATH, cache, npm, or GitHub Release",
        attempted,
    )
