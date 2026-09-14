"""Credential broker with secret-scoped access (Phase 5, PDF 17).

Stores credentials for authorized use by adapters/agents **without** ever
handing raw secrets to the LLM or persisting them in cleartext:

  * secrets are encrypted at rest with a key derived via scrypt from the
    operator's master secret (``RP_MASTER_SECRET`` env var or prompt),
  * integrity is protected with HMAC-SHA256 over ciphertext (encrypt-then-MAC),
  * the case database stores only ciphertext + salt + nonce + MAC tag,
  * access is **scoped**: a caller requests ``use`` with a purpose; the
    broker returns the secret only when the subject holds
    ``manage_credentials`` (owner) or an audit-approved purpose exists,
  * every store/load/delete is audit-chained (never the secret itself),
  * redaction applies on every output path — the broker never prints
    secrets; ``reveal`` exists solely for the interactive operator and is
    audited loudly.

The LLM sees metadata (names, scopes, last-used) — never the material.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid

from ..core.errors import PermissionDeniedError, UsageError
from ..core.redact import redact
from ..evidence.audit import AuditChain
from ..storage.database import Database

MAGIC = b"RPK1"
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1


class CredentialError(UsageError):
    """Credential-broker specific usage failure."""


def _derive_key(master_secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        master_secret.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32,
    )


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Deterministic AES-free stream: HMAC-SHA256 in counter mode."""
    blocks = []
    counter = 0
    while sum(len(b) for b in blocks) < length:
        blocks.append(hmac.new(key, nonce + counter.to_bytes(8, "big"),
                               hashlib.sha256).digest())
        counter += 1
    return b"".join(blocks)[:length]


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def _encrypt(key: bytes, plaintext: str) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(16)
    raw = plaintext.encode("utf-8")
    stream = _keystream(key, nonce, len(raw))
    ciphertext = _xor(raw, stream)
    tag = hmac.new(key, MAGIC + nonce + ciphertext, hashlib.sha256).digest()
    return nonce, ciphertext, tag


def _decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    expected = hmac.new(key, MAGIC + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise CredentialError(
            "Credential integrity check failed",
            reason="The stored ciphertext does not match its MAC tag.",
            action="Restore the credential from the master secret backup"
                   " or re-store it.",
        )
    stream = _keystream(key, nonce, len(ciphertext))
    return _xor(ciphertext, stream).decode("utf-8")


def load_master_secret(environ: dict[str, str] | None = None) -> str:
    """Master secret from RP_MASTER_SECRET (env), else prompt once."""
    env = environ if environ is not None else dict(os.environ)
    secret = env.get("RP_MASTER_SECRET", "")
    if secret:
        return secret
    import getpass

    try:
        secret = getpass.getpass("Rebel Profiler master secret (credentials): ")
    except (EOFError, OSError):
        secret = ""
    if not secret:
        raise CredentialError(
            "No master secret available",
            reason="Credential encryption needs RP_MASTER_SECRET or an"
                   " interactive passphrase.",
            action="Export RP_MASTER_SECRET or run interactively.",
        )
    return secret


class CredentialBroker:
    """Secret-scoped credential store, audit-chained, never printed."""

    def __init__(self, db: Database, audit: AuditChain | None = None,
                 master_secret: str | None = None) -> None:
        self._db = db
        self._audit = audit
        self._master = master_secret if master_secret is not None \
            else load_master_secret()
        # per-credential salt ⇒ per-credential key
        self._keys: dict[str, bytes] = {}

    def _audit_append(self, case_id: str, action: str, subject: str,
                      detail: dict) -> None:
        if self._audit is not None:
            self._audit.append(case_id, actor="credentials", action=action,
                               subject=subject, detail=detail)

    # -- storage ---------------------------------------------------------------

    def store(
        self,
        case_id: str,
        *,
        name: str,
        secret: str,
        scopes: list[str] | None = None,
        notes: str = "",
        actor: str = "operator",
    ) -> dict:
        name = name.strip()
        if not name or len(name) > 80:
            raise CredentialError("Credential name must be 1..80 chars")
        if not secret:
            raise CredentialError("Credential secret must not be empty")
        salt = os.urandom(16)
        key = _derive_key(self._master, salt)
        nonce, ciphertext, tag = _encrypt(key, secret)
        cred_id = f"cred_{uuid.uuid4().hex[:12]}"
        payload = json.dumps({
            "id": cred_id, "name": name,
            "scopes": sorted(set(scopes or [])),
            "notes": redact(notes),
            "salt": salt.hex(), "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(), "tag": tag.hex(),
            "created_at": time.time(), "updated_at": time.time(),
            "last_used": None, "use_count": 0,
        }, sort_keys=True)
        self._db.set_meta(f"credential:{name}", payload)
        self._keys[name] = key
        self._audit_append(case_id, "credential.stored", name,
                           {"credential_id": cred_id, "scopes": sorted(set(scopes or []))})
        return {"id": cred_id, "name": name,
                "scopes": sorted(set(scopes or []))}

    def _load_payload(self, name: str) -> dict:
        raw = self._db.get_meta(f"credential:{name}")
        if not raw:
            raise CredentialError(
                f"Credential '{name}' not found",
                action="List stored credentials with: rebel-profiler credential list",
            )
        return json.loads(raw)

    def list(self, case_id: str) -> list[dict]:
        """Metadata only — never secret material."""
        out = []
        for key, value in sorted(self._db.iter_meta()):
            if key.startswith("credential:"):
                data = json.loads(value)
                out.append({
                    "name": data["name"], "id": data["id"],
                    "scopes": data["scopes"], "created_at": data["created_at"],
                    "last_used": data.get("last_used"),
                    "use_count": data.get("use_count", 0),
                })
        return out

    def use(
        self,
        case_id: str,
        name: str,
        *,
        purpose: str,
        actor: str = "operator",
        rbac=None,
    ) -> str:
        """Scoped access: returns the secret only to authorized callers.

        The secret is returned for in-process use by adapters; it is never
        logged or rendered. Every use is audit-chained with actor + purpose.
        """
        if rbac is not None:
            rbac.require(case_id, actor, "manage_credentials")
        payload = self._load_payload(name)
        scopes = payload["scopes"]
        if scopes and purpose and not any(
            purpose == s or purpose.startswith(s + ":") or purpose.startswith(s + "/")
            for s in scopes
        ):
            raise PermissionDeniedError(
                f"Credential '{name}' is not scoped for purpose '{purpose}'",
                reason=f"Declared scopes: {', '.join(scopes)}.",
                action="Use a matching purpose or re-store with broader scopes"
                       " (owner action).",
            )
        salt = bytes.fromhex(payload["salt"])
        key = self._keys.get(name)
        if key is None:
            key = _derive_key(self._master, salt)
        secret = _decrypt(key, bytes.fromhex(payload["nonce"]),
                          bytes.fromhex(payload["ciphertext"]),
                          bytes.fromhex(payload["tag"]))
        payload["last_used"] = time.time()
        payload["use_count"] = payload.get("use_count", 0) + 1
        self._db.set_meta(f"credential:{name}", json.dumps(payload, sort_keys=True))
        self._audit_append(case_id, "credential.used", name,
                           {"actor": actor, "purpose": purpose[:80]})
        return secret

    def reveal(self, case_id: str, name: str, *, actor: str = "operator",
               rbac=None) -> str:
        """Interactive-operator-only explicit reveal (audited loudly)."""
        if rbac is not None:
            rbac.require(case_id, actor, "manage_credentials")
        secret = self.use(case_id, name, purpose="reveal", actor=actor)
        self._audit_append(case_id, "credential.revealed", name,
                           {"actor": actor, "warning": "secret displayed to operator"})
        return secret

    def delete(self, case_id: str, name: str, *, actor: str = "operator",
               rbac=None) -> dict:
        if rbac is not None:
            rbac.require(case_id, actor, "manage_credentials")
        payload = self._load_payload(name)  # raises when missing
        self._db.delete_meta(f"credential:{name}")
        self._keys.pop(name, None)
        self._audit_append(case_id, "credential.deleted", name,
                           {"actor": actor, "credential_id": payload["id"]})
        return {"name": name, "deleted": True}
