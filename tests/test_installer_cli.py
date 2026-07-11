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

    def test_matrix_converger_asserts_floor_without_installation_lifts(self) -> None:
        helper = ROOT / "profiles/homeserver/modules/matrix/files_root/usr/local/libexec/harmonia-matrix-converge"
        source = helper.read_text(encoding="utf-8")
        rejected = [
            "install_matrix_apt_source",
            "install_element_web_fallback",
            "apt-get update",
            "apt-get install",
            "curl -fsSL",
            "matrix_key_sha256",
            "element_sha256=",
        ]
        for needle in rejected:
            self.assertNotIn(needle, source)
        for package in [
            "matrix-synapse-py3",
            "nginx",
            "postgresql-client",
            "logrotate",
            "openssl",
            "unbound",
            "ca-certificates",
        ]:
            self.assertIn(f'assert_dpkg_package "$package"', source)
        self.assertIn("matrix-floor-missing:${package} (born-incomplete — floor belongs to the deployables birth module)", source)
        self.assertIn("assert_floor_file /usr/share/element-web/index.html element-web-index", source)
        self.assertIn("assert_floor_file /usr/share/element-web/.artifact-sha256 element-web-artifact-sha256", source)

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
            install_systemd_units(paths, profile="homeserver")
            homeserver_service = (paths.systemd_dir / "harmonia-homeserver.service").read_text()
            self.assertIn("homeserver-update", homeserver_service)
            self.assertNotIn("run-profile", homeserver_service)

            install_systemd_units(paths, profile="tv")
            service = (paths.systemd_dir / "harmonia-tv.service").read_text()
            timer = (paths.systemd_dir / "harmonia-tv.timer").read_text()
            self.assertIn("tv-update", service)
            self.assertNotIn("run-profile", service)
            self.assertIn("profiles/tv/index.json", service)
            self.assertIn("tv-update-latest", service)
            self.assertIn("Unit=harmonia-tv.service", timer)
            self.assertNotIn("homeconsole-update", service)

    def test_seed_engine_config_writes_kernel_owned_plane_outside_profile(self) -> None:
        from installer.harmonia_installer import seed_engine_config

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "etc" / "harmonia" / "engine.json"
            seed_engine_config(
                engine,
                source="https://git.home.arpa/HOMESERVERSLTD/harmonia.git",
                ref="8e0611322d5bd4dc4e16c16cab2ea9aeaaaed8d6",
                source_dir=root / "opt" / "harmonia",
                install_bin=root / "bin" / "harmonia",
                enabled=True,
            )
            payload = json.loads(engine.read_text())
            self.assertEqual(payload["source_repo_url"], "https://git.home.arpa/HOMESERVERSLTD/harmonia.git")
            self.assertEqual(payload["branch"], "main")
            self.assertEqual(payload["source_dir"], str(root / "opt" / "harmonia"))
            self.assertEqual(payload["install_bin"], str(root / "bin" / "harmonia"))
            self.assertEqual(payload["ratchet_lock"], str(engine.parent / "engine-ratchet-lock.json"))
            self.assertTrue(payload["enabled"])
            self.assertNotIn("profiles", str(engine.relative_to(root)))

    def test_seed_engine_config_can_wire_blessed_artifact_transport(self) -> None:
        from installer.harmonia_installer import seed_engine_config

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "etc" / "harmonia" / "engine.json"
            lock = root / "etc" / "harmonia" / "locks" / "engine.json"
            cache = root / "var" / "lib" / "harmonia" / "engine-artifacts"
            seed_engine_config(
                engine,
                source="ssh://git@git.home.arpa/HOMESERVERSLTD/harmonia.git",
                ref="main",
                source_dir=root / "opt" / "harmonia",
                install_bin=root / "bin" / "harmonia",
                enabled=True,
                ratchet_lock=lock,
                artifact_repo="ssh://git@git.home.arpa/HOMESERVERSLTD/blessed-artifacts.git",
                artifact_branch="main",
                artifact_cache_dir=cache,
            )
            payload = json.loads(engine.read_text())
            self.assertEqual(payload["ratchet_lock"], str(lock))
            self.assertNotIn("artifact_transport", payload)
            self.assertEqual(payload["artifact_transports"][0]["name"], "estate-forge")
            self.assertEqual(payload["artifact_transports"][0]["repo_url"], "ssh://git@git.home.arpa/HOMESERVERSLTD/blessed-artifacts.git")
            self.assertEqual(payload["artifact_transports"][0]["cache_dir"], str(cache / "estate-forge"))
            self.assertEqual(payload["artifact_transports"][1]["name"], "github-canonical")
            self.assertEqual(payload["artifact_transports"][1]["repo_url"], "https://github.com/homeserversltd/blessed-artifacts.git")

    def test_seed_engine_config_accepts_custom_artifact_chain(self) -> None:
        from installer.harmonia_installer import seed_engine_config

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "etc" / "harmonia" / "engine.json"
            chain = [
                {"name": "one", "repo_url": "file:///one", "branch": "main", "cache_dir": str(root / "one")},
                {"name": "two", "repo_url": "https://example.invalid/two.git", "branch": "stable", "cache_dir": str(root / "two")},
            ]
            seed_engine_config(
                engine,
                source="https://git.home.arpa/HOMESERVERSLTD/harmonia.git",
                ref="main",
                source_dir=root / "opt" / "harmonia",
                install_bin=root / "bin" / "harmonia",
                enabled=True,
                artifact_transport_chain=chain,
            )
            payload = json.loads(engine.read_text())
            self.assertEqual(payload["artifact_transports"], chain)
            self.assertNotIn("artifact_transport", payload)

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
            (state_dir / "subscription.json").write_text('{"schema":"harmonia.subscription.v1"}\n')
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
            self.assertTrue((state_dir / "subscription.json").exists())
            self.assertTrue(log_dir.exists())
            self.assertFalse(bin_path.exists())

    def test_seed_subscription_record_preserves_machine_local_fields(self) -> None:
        from installer.harmonia_installer import seed_subscription_record

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capsule = root / "capsule.json"
            subscription = root / "state" / "subscription.json"
            capsule.write_text(json.dumps({
                "schema": "harmonia.capsule.v1",
                "profile_id": "tv",
                "identity": "arch-tv",
                "engine_version": "0.1.0",
                "created_from": "abc123",
                "modules": [{"id": "alpha", "version": "1.0.0", "tree_sha256": "aaa"}],
            }))
            subscription.parent.mkdir(parents=True)
            subscription.write_text(json.dumps({
                "schema": "harmonia.subscription.v1",
                "machine_local_divergence": "keep",
                "modules": {"beta": {"version": "0.9.0", "tree_sha256": "bbb", "received_at_run_id": "old"}},
            }))
            seed_subscription_record(
                subscription,
                capsule,
                lane="owner",
                source="fixture://capsule",
                ref="ref-a",
                selected_profile="tv",
            )
            payload = json.loads(subscription.read_text())
            self.assertEqual(payload["schema"], "harmonia.subscription.v1")
            self.assertEqual(payload["lane"], "owner")
            self.assertEqual(payload["source"], "fixture://capsule")
            self.assertEqual(payload["ref"], "ref-a")
            self.assertEqual(payload["selected_profile"], "tv")
            self.assertEqual(payload["engine_version_received"], "0.1.0")
            self.assertEqual(payload["machine_local_divergence"], "keep")
            self.assertIn("alpha", payload["modules"])
            self.assertIn("beta", payload["modules"])
            self.assertFalse(subscription.with_suffix(".json.harmonia-new").exists())

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
