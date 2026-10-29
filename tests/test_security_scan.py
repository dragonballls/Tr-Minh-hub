import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.security_scan import scan_text


class SecurityScanTests(unittest.TestCase):
    def test_detects_dynamic_remote_loader(self):
        # Build suspicious examples from fragments so the scanner does not flag its own test source.
        sample = "local fn = load" + "string(game:Http" + "Get(url))"
        labels = {item["rule"] for item in scan_text(sample)}
        self.assertIn("dynamic code execution", labels)
        self.assertIn("remote fetch or loader", labels)

    def test_detects_webhook_and_post(self):
        sample = "url = 'dis" + "cord.com/api/webhooks/secret'\nhttp." + "post(url, payload)"
        labels = {item["rule"] for item in scan_text(sample)}
        self.assertIn("Discord webhook endpoint", labels)

    def test_detects_credential_access(self):
        sample = "value = 'ROBLO" + "XCookie'"
        labels = {item["rule"] for item in scan_text(sample)}
        self.assertIn("credential or session-cookie access", labels)

    def test_normal_text_is_not_flagged(self):
        sample = "local level = player.Data.Level.Value\nprint(level)"
        self.assertEqual(scan_text(sample), [])


if __name__ == "__main__":
    unittest.main()
