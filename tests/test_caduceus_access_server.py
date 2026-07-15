from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "profiles/homeserver/modules/caduceus/files_root/usr/local/sbin/caduceus_staff/access_server.py"


class Refused(Exception):
    pass


class Derived:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.identity_sha256 = "fixture-identity"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def private_key(self):
        return self.key


def load_module():
    keyman = types.ModuleType("keyman_caduceus_access")
    keyman.CaduceusAccessRefused = Refused
    keyman.verify_and_derive_caduceus = lambda pin: Derived() if pin in {"good", "next"} else (_ for _ in ()).throw(Refused("caduceus-pin-invalid"))
    keyman.change_caduceus_pin = lambda old, new: None if old == "good" and new else (_ for _ in ()).throw(Refused("caduceus-pin-invalid"))
    keyman.provision_caduceus = lambda *_: None
    with mock.patch.dict(sys.modules, {"keyman_caduceus_access": keyman}):
        spec = importlib.util.spec_from_file_location("access_server_fixture", SOURCE)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module


class AccessServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.now = 1_000
        self.tokens = iter(["session", "capability", "next-session", "next-capability"])
        self.staff = self.module.AccessStaff(now=lambda: self.now, token=lambda _: next(self.tokens))

    def mint(self) -> str:
        response = self.staff.mint_session("good")
        self.assertTrue(response["ok"])
        self.assertEqual(response["ttl_seconds"], 1800)
        return response["ticket"]

    def test_bind_wrong_pin_and_lockout_unlock(self) -> None:
        self.assertEqual(self.staff.dispatch({"op": "status"})["state"], "UNBOUND")
        for _ in range(5):
            self.assertFalse(self.staff.mint_session("bad")["ok"])
        self.assertEqual(self.staff.mint_session("good")["code"], "caduceus-access-locked")
        self.now += 15 * 60
        self.assertTrue(self.staff.mint_session("good")["ok"])

    def test_session_prove_refresh_clear_expiry_and_restart_invalidation(self) -> None:
        ticket = self.mint()
        self.assertTrue(self.staff.prove_session(ticket)["ok"])
        self.now += 1
        self.assertEqual(self.staff.refresh_session(ticket)["ttl_seconds"], 1800)
        self.assertTrue(self.staff.clear_session(ticket)["cleared"])
        self.assertFalse(self.staff.prove_session(ticket)["ok"])
        ticket = self.mint()
        self.now += 1800
        self.assertFalse(self.staff.prove_session(ticket)["ok"])
        restarted = self.module.AccessStaff(now=lambda: self.now, token=lambda _: "fresh")
        self.assertFalse(restarted.prove_session(ticket)["ok"])

    def test_capability_is_60_seconds_and_signature_has_projection_grammar(self) -> None:
        ticket = self.mint()
        response = self.staff.mint_capability(ticket, "update now", "local", "homeserver")
        self.assertTrue(response["ok"])
        self.assertEqual(response["ttl_seconds"], 60)
        payload = json.loads(self.module.base64.urlsafe_b64decode(response["ticket"].split(".")[0] + "=="))
        self.assertEqual(set(payload), {"action", "epoch", "exp", "id", "profile", "target"})
        self.assertEqual(payload["profile"], "homeserver")

    def test_pin_change_rotates_epoch_and_invalidates_session(self) -> None:
        ticket = self.mint()
        changed = self.staff.change_pin(ticket, "good", "next")
        self.assertTrue(changed["ok"])
        self.assertEqual(changed["epoch"], 1)
        self.assertFalse(self.staff.prove_session(ticket)["ok"])
        self.assertEqual(self.staff.dispatch({"op": "status"})["epoch"], 1)

    def test_malformed_scope_and_private_material_never_persist(self) -> None:
        ticket = self.mint()
        self.assertEqual(self.staff.mint_capability(ticket, "", "local", "homeserver")["code"], "caduceus-capability-scope")
        self.assertEqual(self.staff.dispatch({"op": "unknown"})["code"], "caduceus-access-operation-invalid")
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("Path.write", source)
        self.assertNotIn("open(", source)
        self.assertNotIn("/mnt/keyexchange", source)
        self.assertNotIn("exportkey", source)

    def test_peer_uid_refusal_shape(self) -> None:
        class Connection:
            def getsockopt(self, *_):
                import struct
                return struct.pack("3i", 1, 1000, 1000)
        self.assertFalse(self.module._peer_is_root(Connection()))

    def test_manifest_owns_private_runtime_and_keyman_dependency(self) -> None:
        manifest = json.loads((ROOT / "profiles/homeserver/modules/caduceus/manifest.json").read_text())
        managed = {item["path"]: item["content"] for item in manifest["ladder"][0]["args"]["managed_files"]}
        unit = managed["/etc/systemd/system/caduceus-access.service"]
        self.assertIn("keyman_caduceus_access.py", unit)
        self.assertIn("/run/caduceus/access.sock", unit)
        self.assertIn("Requires=caduceus-access.service", managed["/etc/systemd/system/caduceus.service"])
        self.assertEqual(managed["/usr/local/sbin/caduceus_staff/access_server.py"], SOURCE.read_text())


if __name__ == "__main__":
    unittest.main()
