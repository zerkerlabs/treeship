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

import json
import os
import platform
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

    No `sudo`; writes only into ``cache_dir``. Returns None if the
    download fails or the platform isn't supported. Uses the "latest"
    release by default; pass ``version`` (e.g. ``"0.9.11"``) to pin.
    """
    asset, err = platform_release_asset()
    if err:
        return None
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / "treeship"
    base = (
        f"https://github.com/zerkerlabs/treeship/releases/download/v{version}/{asset}"
        if version
        else f"https://github.com/zerkerlabs/treeship/releases/latest/download/{asset}"
    )
    # Stream into a temp file in the same dir so the final move is atomic.
    tmp = tempfile.NamedTemporaryFile(dir=str(cache_dir), prefix=".treeship-", suffix=".part", delete=False)
    tmp_path = Path(tmp.name)
    try:
        with urllib.request.urlopen(base, timeout=30) as resp:  # nosec B310 (vetted https GitHub URL)
            shutil.copyfileobj(resp, tmp)
        tmp.close()
        # Mark executable.
        tmp_path.chmod(0o755)
        tmp_path.replace(target)
    except Exception:
        try:
            tmp.close()
        except Exception:
            pass
        try:
            tmp_path.unlink()
        except Exception:
            pass
        return None

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
