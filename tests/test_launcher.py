import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


LAUNCHER = Path(__file__).resolve().parents[1] / "run.sh"


class LauncherTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="relay launcher ")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def launch(self, *args, show_key=True):
        return subprocess.run([str(LAUNCHER), *args], cwd=self.directory,
                              capture_output=True, text=True, timeout=30,
                              env={**os.environ, "RELAY_PRINT_API_KEY": "1" if show_key else "0"})

    def prepare_key(self, *args, show_key=True):
        # Stop at address validation so these tests never open network listeners.
        result = self.launch("--listen", "invalid", *args, show_key=show_key)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Relay could not start:", result.stderr)
        return result

    def test_default_key_is_private_and_reused(self):
        result = self.prepare_key()
        key_file = self.directory / "api.key"
        key = key_file.read_text()
        self.assertRegex(key, r"\A[0-9a-f]{64}\n\Z")
        self.assertEqual(stat.S_IMODE(key_file.stat().st_mode), 0o600)
        self.assertEqual(result.stdout, f"API key: {key.strip()}\n")
        result = self.prepare_key()
        self.assertEqual(key_file.read_text(), key)

    def test_custom_paths_are_created_without_overwriting_existing_keys(self):
        for args, path in ((["--api-key-file", "custom key"], "custom key"),
                           (["--api-key-file=another key"], "another key")):
            with self.subTest(args=args):
                self.prepare_key(*args)
                key_file = self.directory / path
                self.assertRegex(key_file.read_text(), r"\A[0-9a-f]{64}\n\Z")
                self.assertEqual(stat.S_IMODE(key_file.stat().st_mode), 0o600)
                key_file.write_text("existing-key-" + "a" * 32)
                result = self.prepare_key(*args)
                self.assertEqual(key_file.read_text(), "existing-key-" + "a" * 32)
                self.assertEqual(result.stdout, "API key: existing-key-" + "a" * 32 + "\n")
        self.assertFalse((self.directory / "api.key").exists())

    def test_key_output_can_be_suppressed(self):
        result = self.prepare_key(show_key=False)
        key = (self.directory / "api.key").read_text().strip()
        self.assertNotIn(key, result.stdout + result.stderr)
        self.assertNotIn("API key:", result.stdout + result.stderr)

    def test_help_does_not_create_a_key(self):
        for args in (("--help",), ("-h",), ("--api-key-file", "custom key", "--help")):
            with self.subTest(args=args):
                result = self.launch(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--listen", result.stdout)
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_missing_key_argument_reports_usage_without_creating_files(self):
        result = self.launch("--api-key-file")
        self.assertEqual(result.returncode, 2)
        self.assertIn("expected one argument", result.stderr)
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
