from __future__ import annotations

import base64
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
SBIN = ROOT / "profiles/homeserver/modules/caduceus/files_root/usr/local/sbin"
MODULE = SBIN / "caduceus_staff/household_capability/index.py"
import sys
sys.path.insert(0, str(SBIN))
import caduceus_staff.household_capability as household
from caduceus_staff.household_capability import index as household_index
from caduceus_staff.household_capability import skeleton_sha


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class HouseholdCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.seed_file = root / "seed"
        self.key_file = root / "vault/.keys/caduceus_household.key"
        self.exchange = root / "run/caduceus_household"
        self.profile = root / "etc/caduceus/profile.yaml"
        self.newkey = root / "newkey.sh"
        self.exportkey = root / "exportkey.sh"
        self.profile.parent.mkdir(parents=True)
        self.profile.write_text("schema: caduceus.profile.v1\nprofile: tv\nmode: tv\n", encoding="utf-8")
        self.newkey.write_text(f'''#!/bin/sh
set -eu
[ "$1" = caduceus_household ]
[ "$2" = signing ]
mkdir -p "{self.key_file.parent}"
printf '%s' "$3" > "{self.seed_file}"
printf encrypted > "{self.key_file}"
''', encoding="utf-8")
        self.exportkey.write_text(f'''#!/bin/sh
set -eu
[ "$1" = caduceus_household ]
mkdir -p "{self.exchange.parent}"
cp "{self.seed_file}" "{self.exchange}"
''', encoding="utf-8")
        self.newkey.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        self.exportkey.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        self.environment = mock.patch.dict(os.environ, {
            "CADUCEUS_KEYMAN_NEWKEY": str(self.newkey),
            "CADUCEUS_KEYMAN_EXPORTKEY": str(self.exportkey),
            "CADUCEUS_KEYMAN_KEY": str(self.key_file),
            "CADUCEUS_KEYMAN_EXCHANGE": str(self.exchange),
            "CADUCEUS_PROFILE_PATH": str(self.profile),
            "CADUCEUS_TEST_SKELETON_PATH": str(root / "skeleton.key"),
        })
        (root / "skeleton.key").write_bytes(b"household skeleton fixture")
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def test_ensure_is_idempotent_and_writes_profile_public_key(self) -> None:
        first = household.ensure_signing_key()
        seed = bytes.fromhex(self.seed_file.read_text())
        expected = household_index._public_hex(seed)
        self.assertTrue(first["changed"])
        self.assertIn(f"household_verifying_key: {expected}", self.profile.read_text())
        second = household.ensure_signing_key()
        self.assertFalse(second["changed"])
        self.assertTrue(second["profile_match"])

    def test_sign_roundtrip_matches_ed25519_public_hex(self) -> None:
        household.ensure_signing_key()
        token = household.sign_capability("update now", "tv", actor="coronatio", ttl_seconds=60)
        payload_part, signature_part = token.split(".")
        payload = _decode(payload_part)
        signature = _decode(signature_part)
        public_hex = household.status()["public_key"]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, payload)
        value = json.loads(payload)
        self.assertEqual(value["actor"], "coronatio")
        self.assertEqual(value["action"], "update now")
        self.assertEqual(value["target"], "tv")
        self.assertIsInstance(value["exp"], int)

    def test_sign_cli_accepts_launcher_flags(self) -> None:
        with mock.patch("builtins.print") as emit:
            self.assertEqual(
                household.main(["sign", "--action", "staff intent", "--target", "/api/admin/updates/apply"]),
                0,
            )
        token = emit.call_args.args[0]
        envelope = json.loads(token)
        self.assertTrue(envelope["ok"])
        self.assertEqual(envelope["firstMissingSignal"], "none")
        payload = json.loads(_decode(envelope["capability"].split(".", 1)[0]))
        self.assertEqual(payload["action"], "staff intent")
        self.assertEqual(payload["target"], "/api/admin/updates/apply")

    def test_export_parser_accepts_raw_hex_and_keyman_password_forms(self) -> None:
        seed = bytes(range(32))
        encoded = seed.hex()
        self.assertEqual(household_index._parse_exported_seed(seed), seed)
        self.assertEqual(household_index._parse_exported_seed(encoded.encode()), seed)
        self.assertEqual(
            household_index._parse_exported_seed(f"username: alice\npassword: '{encoded}'\n".encode()),
            seed,
        )
        self.assertEqual(
            household_index._parse_exported_seed(f"username=alice\npassword={encoded}\n".encode()),
            seed,
        )

    def test_exportkey_stdout_is_discarded_before_json_envelope(self) -> None:
        self.exportkey.write_text(
            self.exportkey.read_text(encoding="utf-8")
            + "printf 'Acquired key for caduceus_household\\n'\n",
            encoding="utf-8",
        )
        with mock.patch.object(household_index.subprocess, "run", wraps=subprocess.run) as run, mock.patch(
            "builtins.print"
        ):
            result = household.main(["sign", "--action", "update now", "--target", "local"])
        self.assertEqual(result, 0)
        export_calls = [call for call in run.call_args_list if call.args[0][0] == str(self.exportkey)]
        self.assertGreaterEqual(len(export_calls), 1)
        self.assertTrue(all(call.kwargs["stdout"] is subprocess.DEVNULL for call in export_calls))

    def test_sign_cli_emits_failure_envelope_and_nonzero_status(self) -> None:
        with mock.patch.object(household_index, "sign_capability", side_effect=ValueError("bad seed")), mock.patch(
            "builtins.print"
        ) as emit:
            self.assertEqual(
                household.main(["sign", "--action", "staff intent", "--target", "/api/admin/updates/apply"]),
                1,
            )
        self.assertEqual(json.loads(emit.call_args.args[0]), {"firstMissingSignal": "bad seed", "ok": False})

    def test_rotate_replaces_seed_and_profile_key(self) -> None:
        household.ensure_signing_key()
        before = self.seed_file.read_text()
        result = household.rotate_signing_key()
        self.assertNotEqual(before, self.seed_file.read_text())
        self.assertTrue(result["rotated"])
        self.assertTrue(household.status()["profile_match"])

    def test_skeleton_sha_is_digest_only_and_rejects_path_arguments(self) -> None:
        expected = __import__("hashlib").sha256(b"household skeleton fixture").hexdigest()
        receipt = skeleton_sha.skeleton_sha_receipt()
        self.assertEqual(receipt, {"ok": True, "digest": expected, "algorithm": "sha256", "firstMissingSignal": "none"})
        with self.assertRaises(SystemExit):
            skeleton_sha.main(["/tmp/other-key"])

    def test_band_shape_and_hoist(self) -> None:
        metadata = json.loads((MODULE.parent / "index.json").read_text())
        self.assertEqual(metadata["children"], ["skeleton-sha"])
        self.assertTrue(callable(household.sign_capability))
        with mock.patch("builtins.print"):
            self.assertEqual(household.main(["status"]), 0)

    def test_homeserver_and_tv_manifests_install_identical_signer(self) -> None:
        manifests = [
            ROOT / "profiles/homeserver/modules/caduceus/manifest.json",
            ROOT / "profiles/tv/modules/caduceus-public-lever/manifest.json",
        ]
        expected = MODULE.read_text(encoding="utf-8")
        for path in manifests:
            managed = json.loads(path.read_text(encoding="utf-8"))["ladder"][0]["args"]["managed_files"]
            by_path = {entry["path"]: entry for entry in managed}
            self.assertEqual(by_path["/usr/local/sbin/caduceus_staff/household_capability/index.py"]["content"], expected)
            self.assertEqual(by_path["/usr/local/sbin/caduceus-skeleton-sha"]["mode"], 493)
            self.assertEqual(by_path["/usr/local/sbin/caduceus-keyman-sign-capability"]["mode"], 493)
            self.assertEqual(by_path["/usr/local/sbin/caduceus-keyman-rotate-capability"]["mode"], 493)
            if path.name == "manifest.json" and "homeserver/modules/caduceus" in str(path):
                profile_source = json.loads(path.read_text(encoding="utf-8"))["ladder"][0]["args"]["caduceus_profile_source"]
                self.assertEqual(profile_source["source"], "profiles/homeserver/index.yaml")
                self.assertEqual(profile_source["path"], "/etc/caduceus/profile.yaml")
                self.assertIn("capability:\n  household_verifying_key:\n  default_ttl_seconds: 60", profile_source["insert_after_profile"])
                self.assertNotIn("- staff intent", profile_source["append"])
            else:
                profile = by_path["/etc/caduceus/profile.yaml"]["content"]
                self.assertIn("capability:\n  household_verifying_key:\n  default_ttl_seconds: 60", profile)
                self.assertIn("- staff intent", profile)


if __name__ == "__main__":
    unittest.main()
