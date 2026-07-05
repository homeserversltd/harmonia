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

    def test_systemd_units_are_profile_correct(self) -> None:
        from installer.harmonia_installer import InstallPaths, install_systemd_units

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = InstallPaths(
                bin_path=root / "bin" / "harmonia",
                config_dir=root / "etc" / "harmonia",
                state_dir=root / "var" / "lib" / "harmonia",
                log_dir=root / "var" / "log" / "harmonia",
                receipt_dir=root / "var" / "lib" / "harmonia" / "receipts",
                systemd_dir=root / "systemd",
            )
            install_systemd_units(paths, profile="tv")
            service = (paths.systemd_dir / "harmonia-tv.service").read_text()
            timer = (paths.systemd_dir / "harmonia-tv.timer").read_text()
            self.assertIn("run-profile", service)
            self.assertIn("profiles/tv/index.json", service)
            self.assertIn("tv-update-latest", service)
            self.assertIn("Unit=harmonia-tv.service", timer)
            self.assertNotIn("homeconsole-update", service)


    def test_uninstall_apply_preserves_state_dir_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_path = root / "bin" / "harmonia"
            config_dir = root / "etc" / "harmonia"
            state_dir = root / "var" / "lib" / "harmonia"
            log_dir = root / "var" / "log" / "harmonia"
            receipt_dir = state_dir / "receipts"
            systemd_dir = root / "systemd"
            for path in [bin_path.parent, config_dir, state_dir, log_dir, receipt_dir, systemd_dir]:
                path.mkdir(parents=True, exist_ok=True)
            bin_path.write_text("binary")
            (state_dir / "ledger.jsonl").write_text("{}\n")
            result = run_cli(
                "uninstall",
                "--apply",
                "--bin-path", str(bin_path),
                "--config-dir", str(config_dir),
                "--state-dir", str(state_dir),
                "--log-dir", str(log_dir),
                "--receipt-dir", str(receipt_dir),
                "--systemd-dir", str(systemd_dir),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("state_preserved=true", result.stdout)
            self.assertTrue(state_dir.exists())
            self.assertTrue((state_dir / "ledger.jsonl").exists())
            self.assertTrue(log_dir.exists())
            self.assertFalse(bin_path.exists())

    def test_uninstall_apply_purge_state_removes_state_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_path = root / "bin" / "harmonia"
            config_dir = root / "etc" / "harmonia"
            state_dir = root / "var" / "lib" / "harmonia"
            log_dir = root / "var" / "log" / "harmonia"
            receipt_dir = state_dir / "receipts"
            systemd_dir = root / "systemd"
            for path in [bin_path.parent, config_dir, state_dir, log_dir, receipt_dir, systemd_dir]:
                path.mkdir(parents=True, exist_ok=True)
            bin_path.write_text("binary")
            result = run_cli(
                "uninstall",
                "--apply",
                "--purge-state",
                "--bin-path", str(bin_path),
                "--config-dir", str(config_dir),
                "--state-dir", str(state_dir),
                "--log-dir", str(log_dir),
                "--receipt-dir", str(receipt_dir),
                "--systemd-dir", str(systemd_dir),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("purge_state=true", result.stdout)
            self.assertFalse(state_dir.exists())
            self.assertFalse(log_dir.exists())


if __name__ == "__main__":
    unittest.main()
