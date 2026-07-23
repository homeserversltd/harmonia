from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "profiles/homeserver/modules/caduceus"


class CaduceusStaffShelfManifestTests(unittest.TestCase):
    def test_staff_shelf_and_launchers_are_installed_from_the_synced_source_tree(self) -> None:
        manifest = json.loads((MODULE / "manifest.json").read_text(encoding="utf-8"))
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
        self.assertEqual(staff["tool"], "command")
        self.assertEqual(staff["args"]["program"], "/usr/bin/sh")
        rendered = "\n".join(staff["args"]["args"])
        self.assertIn("/opt/caduceus/source/data/staff-actuators", rendered)
        self.assertIn("caduceus_staff", rendered)
        self.assertIn('find "$source_root" -maxdepth 1 -type f -name "caduceus-*"', rendered)
        self.assertIn("/usr/local/sbin", rendered)

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
