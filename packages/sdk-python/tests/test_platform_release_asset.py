"""Platform-to-release-asset contract for the Python bootstrapper."""

import unittest
from unittest.mock import patch

from treeship_sdk.bootstrap import platform_release_asset


class PlatformReleaseAssetTests(unittest.TestCase):
    def test_linux_aarch64_uses_published_arm64_asset(self):
        with patch("treeship_sdk.bootstrap.sys.platform", "linux"), patch(
            "treeship_sdk.bootstrap.platform.machine", return_value="aarch64"
        ):
            self.assertEqual(platform_release_asset(), ("treeship-linux-aarch64", None))

    def test_linux_arm64_alias_uses_published_arm64_asset(self):
        with patch("treeship_sdk.bootstrap.sys.platform", "linux"), patch(
            "treeship_sdk.bootstrap.platform.machine", return_value="arm64"
        ):
            self.assertEqual(platform_release_asset(), ("treeship-linux-aarch64", None))


if __name__ == "__main__":
    unittest.main()
