"""Root-owned, private Keyman-backed Caduceus access staff server.

The server is intentionally long-lived: session, lockout, signer, and epoch
state never cross a filesystem, subprocess, environment, or public receipt.
It accepts one newline-delimited JSON request per root-owned Unix-domain socket
connection. Requests are transient process memory; responses never contain a
PIN, seed, Keyman ticket, session ticket, or capability ticket in audit data.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keyman_caduceus_access import (
    CaduceusAccessRefused,
    change_caduceus_pin,
    provision_caduceus,
    verify_and_derive_caduceus,
)

SESSION_SECONDS = 1800
CAPABILITY_SECONDS = 60
LOCKOUT_FAILURES = 5
LOCKOUT_WINDOW_SECONDS = 15 * 60
LOCKOUT_SECONDS = 15 * 60
MAX_LINE_BYTES = 8192
SOCKET_PATH = Path("/run/caduceus/access.sock")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _redacted(code: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "code": code, **extra}


@dataclass
class _Session:
    ticket: str
    expires_at: int


class AccessStaff:
    """In-memory state machine; time and entropy are injectable for deterministic tests."""

    def __init__(self, *, now: Callable[[], int] | None = None, token: Callable[[int], str] | None = None) -> None:
        self._now = now or (lambda: int(time.time()))
        self._token = token or (lambda n: secrets.token_urlsafe(n))
        self._state = "UNBOUND"
        self._signer: Ed25519PrivateKey | None = None
        self._identity: str | None = None
        self._session: _Session | None = None
        self._epoch = 0
        self._failures: list[int] = []
        self._locked_until = 0

    def _clear_session(self) -> None:
        self._session = None

    def _lockout(self, now: int) -> bool:
        self._failures = [stamp for stamp in self._failures if stamp > now - LOCKOUT_WINDOW_SECONDS]
        return now < self._locked_until

    def _record_failure(self, now: int) -> None:
        self._failures.append(now)
        self._failures = [stamp for stamp in self._failures if stamp > now - LOCKOUT_WINDOW_SECONDS]
        if len(self._failures) >= LOCKOUT_FAILURES:
            self._locked_until = now + LOCKOUT_SECONDS
            self._clear_session()
            self._state = "STALE"

    def _session_valid(self, ticket: str, now: int) -> bool:
        return bool(self._session and self._session.expires_at > now and hmac.compare_digest(self._session.ticket, ticket))

    def bind(self, pin: str) -> dict[str, Any]:
        now = self._now()
        if self._lockout(now):
            return _redacted("caduceus-access-locked")
        try:
            with verify_and_derive_caduceus(pin) as derived:
                self._signer = derived.private_key()
                self._identity = derived.identity_sha256
                self._state = "MINT_READY"
                self._clear_session()
                self._failures.clear()
                return {"ok": True, "state": self._state, "epoch": self._epoch, "public_key": self._signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}
        except CaduceusAccessRefused as error:
            self._record_failure(now)
            return _redacted(str(error))

    def mint_session(self, pin: str) -> dict[str, Any]:
        bound = self.bind(pin)
        if not bound.get("ok"):
            return bound
        now = self._now()
        ticket = self._token(32)
        self._session = _Session(ticket=ticket, expires_at=now + SESSION_SECONDS)
        return {"ok": True, "ticket": ticket, "expires_at": self._session.expires_at, "ttl_seconds": SESSION_SECONDS, "epoch": self._epoch}

    def prove_session(self, ticket: str) -> dict[str, Any]:
        now = self._now()
        if not self._session_valid(ticket, now):
            return _redacted("caduceus-session-invalid")
        assert self._session is not None
        return {"ok": True, "expires_at": self._session.expires_at, "ttl_seconds": self._session.expires_at - now, "epoch": self._epoch}

    def refresh_session(self, ticket: str) -> dict[str, Any]:
        now = self._now()
        if not self._session_valid(ticket, now):
            return _redacted("caduceus-session-invalid")
        assert self._session is not None
        self._session.expires_at = now + SESSION_SECONDS
        return {"ok": True, "expires_at": self._session.expires_at, "ttl_seconds": SESSION_SECONDS, "epoch": self._epoch}

    def clear_session(self, ticket: str | None) -> dict[str, Any]:
        if ticket and self._session and hmac.compare_digest(ticket, self._session.ticket):
            self._clear_session()
        return {"ok": True, "cleared": True}

    def mint_capability(self, ticket: str, action: str, target: str, profile: str) -> dict[str, Any]:
        now = self._now()
        if not self._session_valid(ticket, now) or self._state != "MINT_READY" or self._signer is None:
            return _redacted("caduceus-session-invalid")
        if not action or not target or not profile:
            return _redacted("caduceus-capability-scope")
        capability_id = self._token(18)
        payload = json.dumps({"id": capability_id, "action": action, "target": target, "profile": profile, "epoch": self._epoch, "exp": now + CAPABILITY_SECONDS}, separators=(",", ":"), sort_keys=True).encode()
        return {"ok": True, "ticket": f"{_b64(payload)}.{_b64(self._signer.sign(payload))}", "expires_at": now + CAPABILITY_SECONDS, "ttl_seconds": CAPABILITY_SECONDS, "epoch": self._epoch}

    def change_pin(self, session_ticket: str, old_pin: str, new_pin: str) -> dict[str, Any]:
        now = self._now()
        if not self._session_valid(session_ticket, now):
            return _redacted("caduceus-session-invalid")
        # Six rungs: valid session; old proof; atomic Keyman rewrite; derive fresh signer;
        # rotate epoch; invalidate the old session.
        try:
            change_caduceus_pin(old_pin, new_pin)
            with verify_and_derive_caduceus(new_pin) as derived:
                self._signer = derived.private_key()
                self._identity = derived.identity_sha256
            self._epoch += 1
            self._clear_session()
            self._state = "MINT_READY"
            return {"ok": True, "operation": "pin-changed", "epoch": self._epoch, "session_invalidated": True}
        except CaduceusAccessRefused as error:
            self._record_failure(now)
            return _redacted(str(error))

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        op = request.get("op")
        if op == "session.mint": return self.mint_session(str(request.get("pin", "")))
        if op == "session.prove": return self.prove_session(str(request.get("ticket", "")))
        if op == "session.refresh": return self.refresh_session(str(request.get("ticket", "")))
        if op == "session.clear": return self.clear_session(request.get("ticket"))
        if op == "capability.mint": return self.mint_capability(str(request.get("session_ticket", "")), str(request.get("action", "")), str(request.get("target", "")), str(request.get("profile", "")))
        if op == "pin.change": return self.change_pin(str(request.get("session_ticket", "")), str(request.get("old_pin", "")), str(request.get("new_pin", "")))
        if op == "status": return {"ok": True, "state": self._state, "epoch": self._epoch, "locked": self._lockout(self._now())}
        return _redacted("caduceus-access-operation-invalid")


def _peer_is_root(connection: socket.socket) -> bool:
    if not hasattr(socket, "SO_PEERCRED"):
        return False
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _pid, uid, _gid = __import__("struct").unpack("3i", raw)
    return uid == 0


def serve(socket_path: Path = SOCKET_PATH) -> None:
    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR)
    server.listen(16)
    staff = AccessStaff()
    while True:
        connection, _ = server.accept()
        with connection:
            if not _peer_is_root(connection):
                connection.sendall(b'{"ok":false,"code":"caduceus-staff-peer-refused"}\n')
                continue
            raw = connection.makefile("rb").readline(MAX_LINE_BYTES + 1)
            if not raw or len(raw) > MAX_LINE_BYTES:
                response = _redacted("caduceus-access-request-invalid")
            else:
                try:
                    response = staff.dispatch(json.loads(raw))
                except (TypeError, ValueError, json.JSONDecodeError):
                    response = _redacted("caduceus-access-request-invalid")
            connection.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")


def main() -> int:
    serve(Path(os.environ.get("CADUCEUS_ACCESS_SOCKET", str(SOCKET_PATH))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
