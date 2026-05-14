# Binary integrity data shipped with the wheel.
#
# The release pipeline writes one ``expected-checksum-<asset>.txt`` per
# supported platform into this directory at wheel-build time (see
# .github/workflows/release.yml). The bootstrap loads them via
# importlib.resources and uses them to verify GitHub Release binaries
# before they are made executable.
#
# These files are intentionally NOT committed to the repo — the
# .gitignore at the repo root excludes them. They exist only inside
# the published wheel, so the hash arrives via PyPI (one trust root)
# while the binary arrives via GitHub Releases (a separate trust
# root). Compromising one without the other yields a hash mismatch
# and a hard install failure.
