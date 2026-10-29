import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.security_scan import scan_archive, scan_text


class SecurityScanTests(unittest.TestCase):
    def test_detects_dynamic_remote_loader(self):
        sample = "local fn = load" + "string(game:Http" + "Get(url))"
        labels = {item["rule"] for item in scan_text(sample)}
        self.assertIn("dynamic code execution", labels)
        self.assertIn("remote fetch or loader", labels)

    def test_detects_webhook_and_post_without_emitting_source(self):
        sample = "url = 'dis" + "cord.com/api/webhooks/secret'\nHttp" + "Post(url, 'private payload')"
        findings = scan_text(sample)
        labels = {item["rule"] for item in findings}
        self.assertIn("Discord webhook endpoint", labels)
        self.assertIn("outbound POST/request primitive", labels)
        self.assertNotIn("private payload", str(findings))

    def test_detects_credential_access(self):
        sample = "value = 'ROBLO" + "SECURITY'"
        labels = {item["rule"] for item in scan_text(sample)}
        self.assertIn("credential or session-cookie access", labels)

    def test_normal_text_is_not_flagged(self):
        sample = "local level = player.Data.Level.Value\nprint(level)"
        self.assertEqual(scan_text(sample), [])

    def test_scans_zip_without_extracting(self):
        suspicious = "url = 'dis" + "cord.com/api/webhooks/demo'"
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("scripts/example.lua", suspicious)
                archive.writestr("notes/readme.md", "ordinary notes")
            count, findings = scan_archive(archive_path)
            self.assertEqual(count, 1)
            self.assertTrue(any(item["rule"] == "Discord webhook endpoint" for item in findings))
            self.assertFalse((Path(directory) / "scripts").exists())

    def test_bad_zip_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "bad.zip"
            archive_path.write_text("not a zip file", encoding="utf-8")
            count, findings = scan_archive(archive_path)
            self.assertEqual(count, 0)
            self.assertTrue(any(item["severity"] == "HIGH" for item in findings))


if __name__ == "__main__":
    unittest.main()
