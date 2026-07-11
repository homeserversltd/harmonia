"""Keyman-backed Ed25519 household capability signer for Caduceus."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SERVICE_NAME = "caduceus_household"
KEYMAN_NEWKEY = Path("/vault/keyman/newkey.sh")
KEYMAN_EXPORTKEY = Path("/vault/keyman/exportkey.sh")
KEYMAN_KEY = Path("/vault/.keys/caduceus_household.key")
KEYMAN_EXCHANGE = Path("/mnt/keyexchange/caduceus_household")
PROFILE_PATH = Path("/etc/caduceus/profile.yaml")
DEFAULT_TTL_SECONDS = 60


def _path(env: str, default: Path) -> Path:
    return Path(os.environ.get(env, str(default)))


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True, text=True, stdout=subprocess.DEVNULL)


def _public_hex(seed: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()


def _new_seed() -> bytes:
    return os.urandom(32)


def _write_profile_key(public_hex: str) -> None:
    path = _path("CADUCEUS_PROFILE_PATH", PROFILE_PATH)
    text = path.read_text(encoding="utf-8") if path.is_file() else "schema: caduceus.profile.v1\n"
    lines = text.splitlines()
    capability_index = next((i for i, line in enumerate(lines) if line.strip() == "capability:" and not line.startswith((" ", "\t"))), None)
    if capability_index is None:
        insert_at = next((i for i, line in enumerate(lines) if line.startswith("mode:")), len(lines))
        lines[insert_at:insert_at] = ["capability:", f"  household_verifying_key: {public_hex}", f"  default_ttl_seconds: {DEFAULT_TTL_SECONDS}"]
    else:
        end = capability_index + 1
        while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t"))):
            end += 1
        key_index = next((i for i in range(capability_index + 1, end) if lines[i].lstrip().startswith("household_verifying_key:")), None)
        if key_index is None:
            lines.insert(capability_index + 1, f"  household_verifying_key: {public_hex}")
        else:
            lines[key_index] = f"  household_verifying_key: {public_hex}"
        if not any(lines[i].lstrip().startswith("default_ttl_seconds:") for i in range(capability_index + 1, end)):
            lines.insert(capability_index + 2, f"  default_ttl_seconds: {DEFAULT_TTL_SECONDS}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _store_seed(seed: bytes) -> str:
    newkey = _path("CADUCEUS_KEYMAN_NEWKEY", KEYMAN_NEWKEY)
    _run([str(newkey), SERVICE_NAME, "signing", seed.hex()])
    public_hex = _public_hex(seed)
    _write_profile_key(public_hex)
    return public_hex


def ensure_signing_key() -> dict[str, Any]:
    key_path = _path("CADUCEUS_KEYMAN_KEY", KEYMAN_KEY)
    if key_path.is_file():
        public_hex = _public_hex(_read_exported_seed())
        profile_changed = _profile_key() != public_hex
        if profile_changed:
            _write_profile_key(public_hex)
        return {
            "ok": True,
            "service": SERVICE_NAME,
            "changed": profile_changed,
            **status(),
        }
    public_hex = _store_seed(_new_seed())
    return {"ok": True, "service": SERVICE_NAME, "changed": True, "public_key": public_hex}


def _decode_exported_secret(raw: bytes) -> bytes:
    text = raw.decode("utf-8").strip()
    if "password=" in text:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("password="):
                value = stripped.split("=", 1)[1].strip().strip('"')
                return bytes.fromhex(value)
        raise ValueError("caduceus-household-exported-password-missing")
    try:
        decoded = bytes.fromhex(text)
    except ValueError:
        decoded = raw
    if len(decoded) != 32:
        raise ValueError("caduceus-household-exported-seed-invalid")
    return decoded


def _read_exported_seed() -> bytes:
    exportkey = _path("CADUCEUS_KEYMAN_EXPORTKEY", KEYMAN_EXPORTKEY)
    exchange = _path("CADUCEUS_KEYMAN_EXCHANGE", KEYMAN_EXCHANGE)
    exchange.parent.mkdir(parents=True, exist_ok=True)
    _run([str(exportkey), SERVICE_NAME])
    if not exchange.is_file():
        raise ValueError("caduceus-household-exported-missing")
    return _decode_exported_secret(exchange.read_bytes().strip())


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sign_capability(action: str, target: str, actor: str = "coronatio", ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    ensure_signing_key()
    seed = _read_exported_seed()
    payload = json.dumps(
        {"actor": actor, "action": action, "target": target, "exp": int(time.time()) + ttl_seconds},
        separators=(",", ":"),
    ).encode("utf-8")
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(payload)
    return f"{_b64url(payload)}.{_b64url(signature)}"


def rotate_signing_key() -> dict[str, Any]:
    public_hex = _store_seed(_new_seed())
    return {"ok": True, "service": SERVICE_NAME, "changed": True, "rotated": True, "public_key": public_hex}


def _profile_key() -> str | None:
    path = _path("CADUCEUS_PROFILE_PATH", PROFILE_PATH)
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("household_verifying_key:"):
            return line.split(":", 1)[1].strip() or None
    return None


def status() -> dict[str, Any]:
    key_exists = _path("CADUCEUS_KEYMAN_KEY", KEYMAN_KEY).is_file()
    profile_key = _profile_key()
    public_key = None
    if key_exists:
        try:
            public_key = _public_hex(_read_exported_seed())
        except (OSError, ValueError, subprocess.CalledProcessError):
            public_key = None
    return {
        "key_exists": key_exists,
        "public_key": public_key,
        "public_fingerprint": hashlib.sha256(bytes.fromhex(public_key)).hexdigest() if public_key else None,
        "profile_key": profile_key,
        "profile_match": bool(public_key and profile_key == public_key),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-household-capability")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ensure")
    sign = commands.add_parser("sign")
    sign.add_argument("--action", required=True)
    sign.add_argument("--target", required=True)
    sign.add_argument("--actor", default="coronatio")
    sign.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    commands.add_parser("rotate")
    commands.add_parser("status")
    args = parser.parse_args(argv)
    if args.command == "sign":
        print(sign_capability(args.action, args.target, args.actor, args.ttl_seconds))
    else:
        result = {"ensure": ensure_signing_key, "rotate": rotate_signing_key, "status": status}[args.command]()
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
