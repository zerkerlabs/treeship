#!/usr/bin/env python3
"""Fail when a supported prebuilt platform is missing from a release surface."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PLATFORMS = {
    "linux-x64": {
        "artifact": "treeship-linux-x86_64",
        "npm": "@treeship/cli-linux-x64",
        "manifest": "npm/@treeship/cli-linux-x64/package.json",
        "python_machine": "x86_64",
    },
    "linux-arm64": {
        "artifact": "treeship-linux-aarch64",
        "npm": "@treeship/cli-linux-arm64",
        "manifest": "npm/@treeship/cli-linux-arm64/package.json",
        "python_machine": "aarch64",
    },
    "darwin-arm64": {
        "artifact": "treeship-darwin-aarch64",
        "npm": "@treeship/cli-darwin-arm64",
        "manifest": "npm/@treeship/cli-darwin-arm64/package.json",
        "python_machine": "arm64",
    },
    "darwin-x64": {
        "artifact": "treeship-darwin-x86_64",
        "npm": "@treeship/cli-darwin-x64",
        "manifest": "npm/@treeship/cli-darwin-x64/package.json",
        "python_machine": "x86_64",
    },
}


def require(source: str, needle: str, label: str, errors: list[str]) -> None:
    if needle not in source:
        errors.append(f"{label}: missing {needle!r}")


def main() -> int:
    errors: list[str] = []
    release = (ROOT / ".github/workflows/release.yml").read_text()
    wrapper = (ROOT / "npm/treeship/bin/treeship.js").read_text()
    bootstrap = (ROOT / "packages/sdk-python/treeship_sdk/bootstrap.py").read_text()
    docs = (ROOT / "docs/content/docs/guides/install.mdx").read_text()
    wrapper_manifest = json.loads((ROOT / "npm/treeship/package.json").read_text())
    optional = wrapper_manifest.get("optionalDependencies", {})

    for key, platform in PLATFORMS.items():
        manifest_path = ROOT / platform["manifest"]
        if not manifest_path.is_file():
            errors.append(f"{key}: missing platform manifest {platform['manifest']}")
            continue
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("name") != platform["npm"]:
            errors.append(f"{key}: manifest name is {manifest.get('name')!r}, want {platform['npm']!r}")

        require(wrapper, f"'{key}':", "npm wrapper map", errors)
        require(wrapper, platform["npm"], "npm wrapper map", errors)
        if optional.get(platform["npm"]) != wrapper_manifest["version"]:
            errors.append(f"{key}: wrapper optional dependency does not match wrapper version")

        require(release, platform["artifact"], "release workflow", errors)
        require(release, platform["npm"], "release workflow", errors)
        require(bootstrap, platform["artifact"], "Python bootstrap", errors)
        require(docs, platform["artifact"], "install docs", errors)
        require(docs, platform["npm"], "install docs", errors)

    if errors:
        print("Release platform topology is inconsistent:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(f"Release platform topology: {len(PLATFORMS)} platforms agree across CI, npm, Python, and docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
