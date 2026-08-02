from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "profiles/homeserver/modules/caduceus"
CADUCEUS_MODULES = (
    MODULE,
    ROOT / "profiles/tv/modules/caduceus-public-lever",
    ROOT / "profiles/homeconsole/modules/homeconsole-caduceus-public-lever",
)


class CaduceusStaffShelfManifestTests(unittest.TestCase):
    def test_staff_shelf_and_launchers_are_installed_from_the_synced_source_tree(self) -> None:
        for module in CADUCEUS_MODULES:
            with self.subTest(module=module):
                manifest = json.loads((module / "manifest.json").read_text(encoding="utf-8"))
                ladder = manifest["ladder"]
                runtime_index = next(
                    index for index, step in enumerate(ladder) if step["tool"] == "service-runtime"
                )
                staff_index = next(
                    index
                    for index, step in enumerate(ladder)
                    if step["step_id"] == "caduceus-staff-shelf-from-synced-source"
                )
                staff = ladder[staff_index]

                if module.name == "homeconsole-caduceus-public-lever":
                    bootstrap_source_index = next(
                        index
                        for index, step in enumerate(ladder)
                        if step["step_id"] == "caduceus-bootstrap-source-from-declared-profile"
                    )
                    bootstrap_source = ladder[bootstrap_source_index]
                    self.assertLess(bootstrap_source_index, staff_index)
                    self.assertLess(staff_index, runtime_index)
                    self.assertEqual(
                        (bootstrap_source["tool"], bootstrap_source["permutation"]),
                        ("git-artifact", "sync"),
                    )
                    self.assertEqual(
                        bootstrap_source["args"],
                        {
                            "component": "caduceus",
                            "path": "/opt/caduceus/source",
                            "source_dir": "/opt/caduceus/source",
                        },
                    )
                else:
                    self.assertGreater(staff_index, runtime_index)
                self.assertEqual(staff["tool"], "files")
                self.assertEqual(staff["permutation"], "source-shelf-sweep")
                self.assertEqual(
                    staff["args"],
                    {
                        "source_root": "/opt/caduceus/source/data/staff-actuators",
                        "shelf_source": "caduceus_staff",
                        "target_shelf": "/usr/local/sbin/caduceus_staff",
                        "launcher_source_root": "/opt/caduceus/source/data/staff-actuators",
                        "launcher_target_root": "/usr/local/sbin",
                        "launcher_pattern": "caduceus-*",
                        "shelf_owner": "root",
                        "shelf_group": "root",
                        "shelf_directory_mode": 0o755,
                        "shelf_file_mode": 0o644,
                        "launcher_mode": 0o755,
                        "prune": True,
                    },
                )
                self.assertNotIn("program", staff["args"])
                self.assertNotIn("args", staff["args"])

    def test_homeconsole_lifts_the_canonical_console_profile_without_a_command_fork(self) -> None:
        module = ROOT / "profiles/homeconsole/modules/homeconsole-caduceus-public-lever"
        manifest = json.loads((module / "manifest.json").read_text(encoding="utf-8"))
        runtime = next(step for step in manifest["ladder"] if step["tool"] == "service-runtime")
        source_profile = runtime["args"]["caduceus_profile_source"]

        self.assertEqual(source_profile["source"], "profiles/console/index.yaml")
        self.assertEqual(source_profile["path"], "/etc/caduceus/profile.yaml")
        self.assertEqual(source_profile["mode"], 0o644)
        self.assertEqual(source_profile["append"], "")
        self.assertFalse(
            any(
                entry["path"] in {"/etc/caduceus/profile.json", "/etc/caduceus/policies/update.json"}
                for entry in runtime["args"]["managed_files"]
            )
        )
        service = next(
            entry["content"]
            for entry in runtime["args"]["managed_files"]
            if entry["path"] == "/etc/systemd/system/caduceus.service"
        )
        self.assertIn("Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/bin", service)
        self.assertIn("Environment=PYTHONPATH=/usr/local/sbin", service)

    def test_homeconsole_carriage_contains_no_certificate_material_or_handler(self) -> None:
        module = ROOT / "profiles/homeconsole/modules/homeconsole-caduceus-public-lever"
        text = (module / "manifest.json").read_text(encoding="utf-8").lower()
        for forbidden in (
            "begin certificate",
            "private key",
            "ca.pem",
            "cert.pem",
            "openssl",
            "cryptography",
            "sslkey.sh",
            "createcertbundle",
            "certificate parsing",
            "certificate installation",
            "csr",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_homeconsole_bootstrap_has_no_protected_action_or_secret_carrier(self) -> None:
        module = ROOT / "profiles/homeconsole/modules/homeconsole-caduceus-public-lever"
        manifest = json.loads((module / "manifest.json").read_text(encoding="utf-8"))
        bootstrap_steps = manifest["ladder"][1:3]
        self.assertEqual(
            [step["step_id"] for step in bootstrap_steps],
            [
                "caduceus-bootstrap-source-from-declared-profile",
                "caduceus-staff-shelf-from-synced-source",
            ],
        )
        bootstrap_bytes = json.dumps(bootstrap_steps, sort_keys=True).lower()
        for forbidden in (
            "update now",
            "trust-install",
            "private key",
            "signing seed",
            "skeleton",
            "pin",
            "bearer",
            "cookie",
            "authorization",
            "certificate",
            "csr",
            "openssl",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, bootstrap_bytes)

    def test_manifests_do_not_embed_caduceus_staff_programs(self) -> None:
        for module in CADUCEUS_MODULES:
            with self.subTest(module=module):
                manifest = json.loads((module / "manifest.json").read_text(encoding="utf-8"))
                runtime = next(step for step in manifest["ladder"] if step["tool"] == "service-runtime")
                managed = runtime["args"]["managed_files"]
                self.assertFalse(
                    any(entry["path"].startswith("/usr/local/sbin/") for entry in managed)
                )
                self.assertFalse(
                    any(
                        marker in entry.get("content", "")
                        for entry in managed
                        for marker in ("def ", "import ", "#!")
                    )
                )

    def test_files_root_retains_only_the_sudoers_policy_not_staff_python(self) -> None:
        manifest = json.loads((MODULE / "manifest.json").read_text(encoding="utf-8"))
        runtime = next(step for step in manifest["ladder"] if step["tool"] == "service-runtime")
        managed = {entry["path"] for entry in runtime["args"]["managed_files"]}
        files_root = MODULE / "files_root"
        remaining = [path.relative_to(files_root) for path in files_root.rglob("*") if path.is_file()]

        self.assertEqual(remaining, [Path("etc/sudoers.d/caduceus-keyman")])
        self.assertFalse(any(path.suffix == ".py" for path in remaining))
        self.assertFalse(any(path.startswith("/usr/local/sbin/") for path in managed))
        self.assertNotIn("/etc/sudoers.d/caduceus-keyman", managed)
        self.assertTrue(
            any(step["step_id"] == "caduceus-sudoers-policy-files-root" for step in manifest["ladder"])
        )


if __name__ == "__main__":
    unittest.main()
