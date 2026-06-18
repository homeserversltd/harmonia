import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "cli.py"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class InstallerCliTests(unittest.TestCase):
    def test_root_cli_prints_full_help_by_default(self) -> None:
        result = run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Harmonia repo-local control face", result.stdout)
        self.assertIn("install", result.stdout)
        self.assertIn("uninstall", result.stdout)
        self.assertIn("status", result.stdout)

    def test_menu_lists_operator_commands(self) -> None:
        result = run_cli("menu")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("build", result.stdout)
        self.assertIn("install", result.stdout)
        self.assertIn("uninstall", result.stdout)

    def test_install_default_is_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_cli(
                "install",
                "--bin-path",
                str(root / "bin" / "harmonia"),
                "--config-dir",
                str(root / "etc" / "harmonia"),
                "--state-dir",
                str(root / "var" / "lib" / "harmonia"),
                "--log-dir",
                str(root / "var" / "log" / "harmonia"),
                "--receipt-dir",
                str(root / "var" / "lib" / "harmonia" / "receipts"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("schema=harmonia.installer.install_plan.v1", result.stdout)
            self.assertIn("apply=false", result.stdout)
            self.assertFalse((root / "bin" / "harmonia").exists())

    def test_status_emits_json_for_custom_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_cli(
                "status",
                "--bin-path",
                str(root / "bin" / "harmonia"),
                "--config-dir",
                str(root / "etc" / "harmonia"),
                "--state-dir",
                str(root / "var" / "lib" / "harmonia"),
                "--log-dir",
                str(root / "var" / "log" / "harmonia"),
                "--receipt-dir",
                str(root / "var" / "lib" / "harmonia" / "receipts"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["schema"], "harmonia.installer.status.v1")
            self.assertFalse(payload["binary"]["exists"])


if __name__ == "__main__":
    unittest.main()
