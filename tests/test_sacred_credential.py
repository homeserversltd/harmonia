from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SBIN = ROOT / "profiles/homeserver/modules/caduceus/files_root/usr/local/sbin"
sys.path.insert(0, str(SBIN))
from caduceus_staff import bind_derived, sacred_credential

SKELETON = b"caduceus-fixture-skeleton-v1\x00bytes\nraw-tail"
IDENTITY = hashlib.sha256(SKELETON).hexdigest()
PIN = "2468"
NEW_PIN = "9753"


class SacredCredentialShelfTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.keys = root / "key"
        self.vault = root / "vault/.keys"
        runtime = root / "runtime"
        self.keys.mkdir(parents=True)
        self.vault.mkdir(parents=True)
        runtime.mkdir()
        (self.keys / "skeleton.key").write_bytes(SKELETON)
        crypto = runtime / "keyman-crypto"
        crypto.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os, re, sys
                from pathlib import Path
                vault = Path(os.environ["CADUCEUS_KEYMAN_VAULT_DIR"])
                operation, input_path = sys.argv[1:3]
                fields = dict(line.split("=", 1) for line in Path(input_path).read_text().splitlines() if "=" in line)
                target = vault / (fields.get("service", "caduceus") + ".key")
                if operation == "create":
                    target.write_text('username="%s"\\npassword="%s"\\n' % (fields["username"], fields["password"]))
                elif operation == "decrypt":
                    Path(sys.argv[3]).write_bytes(target.read_bytes())
                elif operation == "reencrypt":
                    record = target.read_text()
                    username = re.search(r'^username="([^"\\n]+)"$', record, re.M).group(1)
                    target.write_text('username="%s"\\npassword="%s"\\n' % (username, fields["new_password"]))
                else:
                    raise SystemExit(4)
                """
            ),
            encoding="utf-8",
        )
        crypto.chmod(0o700)
        self.patch = mock.patch.dict(
            os.environ,
            {
                "CADUCEUS_KEYMAN_KEY_DIR": str(self.keys),
                "CADUCEUS_KEYMAN_VAULT_DIR": str(self.vault),
                "CADUCEUS_KEYMAN_CRYPTO": str(crypto),
                "CADUCEUS_KEYMAN_TEMP_DIR": str(runtime),
            },
            clear=False,
        )
        self.patch.start()
        self.root = mock.patch.object(sacred_credential, "_require_root")
        self.root.start()
        bind_derived._BOUND = None
        sacred_credential.provision_caduceus(PIN)

    def tearDown(self) -> None:
        bind_derived._BOUND = None
        self.root.stop()
        self.patch.stop()
        self.temp.cleanup()

    def test_keyman_only_sacred_credential_binds_verifies_and_rotates(self) -> None:
        seated = bind_derived.bind_derived()
        self.assertTrue(seated["ok"])
        self.assertEqual(seated["identity"], IDENTITY)
        self.assertTrue(bind_derived.verify_derived(PIN)["ok"])
        self.assertFalse(bind_derived.verify_derived("wrong")["ok"])
        changed = bind_derived.atomic_change_pin(PIN, NEW_PIN)
        self.assertTrue(changed["ok"])
        self.assertTrue(changed["rotated"])
        self.assertFalse(bind_derived.verify_derived(PIN)["ok"])
        self.assertTrue(bind_derived.verify_derived(NEW_PIN)["ok"])

    def test_shelf_and_manifest_install_the_admitted_surface_without_legacy_lineage(self) -> None:
        manifest = json.loads((ROOT / "profiles/homeserver/modules/caduceus/manifest.json").read_text(encoding="utf-8"))
        runtime = next(step for step in manifest["ladder"] if step["tool"] == "service-runtime")
        managed = {entry["path"]: entry for entry in runtime["args"]["managed_files"]}
        for relative in (
            "atomic-change-pin",
            "bind",
            "verify",
            "caduceus_staff/bind_derived.py",
            "caduceus_staff/sacred_credential.py",
        ):
            path = SBIN / relative
            installed = managed["/usr/local/sbin/" + relative]
            self.assertEqual(installed["content"], path.read_text(encoding="utf-8"))
        shelf = "\n".join(str(path.relative_to(SBIN)) for path in SBIN.rglob("*") if path.is_file())
        rendered = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("household_capability", shelf)
        self.assertNotIn("caduceus-keyman-sign-capability", shelf)
        self.assertNotIn("caduceus-keyman-rotate-capability", shelf)
        self.assertNotIn("caduceus-skeleton-sha", shelf)
        self.assertFalse(any("household_capability" in path for path in managed))
        self.assertNotIn("/usr/local/sbin/caduceus-skeleton-sha", managed)
        retirement = next(step for step in manifest["ladder"] if step["step_id"] == "retire-caduceus-keyman-legacy-launchers")
        self.assertEqual(retirement["args"]["program"], "/usr/bin/rm")
        self.assertIn("/usr/local/sbin/caduceus-keyman-sign-capability", retirement["args"]["args"])
        self.assertIn("/usr/local/sbin/caduceus-keyman-rotate-capability", retirement["args"]["args"])


if __name__ == "__main__":
    unittest.main()
