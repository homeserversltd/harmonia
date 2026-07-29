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
