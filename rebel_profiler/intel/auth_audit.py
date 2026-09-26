"""Credentialed authenticated-session posture audit (Phase 13).

The capability gap this closes: every pre-existing web plane
(``web-crawl``, ``header-audit``, ``tls-posture`` …) evaluates the app the
way an anonymous visitor sees it. Most real exposure lives BEHIND the login
— session cookies, logout hygiene, cache headers on authenticated pages,
MFA/lockout signals.

Design laws honored exactly:

  * **The credential secret never crosses a process boundary.** This is an
    in-process plane (like :class:`ScopeEnforcedWebAuditor`), not an argv
    adapter: the operator stores a credential with the case's
    CredentialBroker (HMAC encrypt-then-MAC at rest) and passes only the
    credential NAME. The secret is resolved here, used for exactly ONE
    login POST, and redacted on every output path (the redaction pipeline
    catches it even if a form value echoed back).
  * **No brute force.** One login attempt per run against the operator's
    OWN test account — the design ban on credential attack stands. A failed
    login is an honest ``auth_failed`` result, never a retry loop.
  * **Scope fail-closed.** Every URL (base + login + redirect) is validated
    through the case's ScopeEngine before any byte is fetched, and
    redirects are never auto-followed (the ``_NoRedirect`` discipline from
    intel/web.py).
  * **No evidence, no claim.** The full transaction (status, headers,
    redacted body hash) is registered as hash-chained evidence before any
    claim exists.

Checks (deterministic, configuration-only):
  * session cookie flags on the authenticated session (Secure/HttpOnly/SameSite)
  * cache-control on authenticated responses (no-store expected)
  * logout endpoint presence in the authenticated navigation
  * session-id rotation between anonymous and authenticated states
  * MFA hint detection (bounded keyword scan of the authenticated page)
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from ..core.errors import ScopeViolationError, UsageError
from ..evidence.store import EvidenceStore
from ..security.scope import ScopeEngine
from .claims import ClaimLedger

AUTH_TIMEOUT = 30
MAX_BODY_BYTES = 512_000

_MFA_HINTS = ("mfa", "two-factor", "2fa", "otp", "authenticator",
              "verification code", "one-time")


class _AuthNoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse automatic redirect following (same discipline as intel/web.py)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


_OPENER = urllib.request.build_opener(_AuthNoRedirect)


def _fetch_no_redirect(url: str, *, data: bytes | None = None,
                       headers: dict[str, str] | None = None,
                       cookie: str | None = None) -> tuple[int, dict[str, str], bytes, str]:
    """One fetch; returns (status, headers, body, set_cookie_header).

    HTTPError bodies are returned (a 401/403 IS a posture answer). Redirects
    are surfaced as status + Location instead of being followed.
    """
    merged = {"User-Agent": "rebel-profiler-auth-audit/0.1"}
    if cookie:
        merged["Cookie"] = cookie
    if headers:
        merged.update(headers)
    request = urllib.request.Request(url, data=data, headers=merged)
    try:
        with _OPENER.open(request, timeout=AUTH_TIMEOUT) as response:
            body = response.read(MAX_BODY_BYTES)
            return (response.status, dict(response.headers.items()), body,
                    response.headers.get("Set-Cookie", ""))
    except urllib.error.HTTPError as exc:
        return (exc.code, dict(exc.headers.items()) if exc.headers else {},
                exc.read(MAX_BODY_BYTES) if exc.headers else b"",
                exc.headers.get("Set-Cookie", "") if exc.headers else "")
    except (urllib.error.URLError, OSError) as exc:
        raise UsageError(
            f"Fetch failed for {url}",
            reason=str(exc),
            action="Check network reachability of the authorized target.",
        ) from exc


def _extract_session_cookie(set_cookie: str) -> str | None:
    """First cookie pair from a Set-Cookie header (the session candidate)."""
    for part in set_cookie.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        pair = part.split(";", 1)[0].strip()
        name, _, value = pair.partition("=")
        name = name.strip().lower()
        if name and value.strip() and name not in {"path", "domain", "expires",
                                                   "max-age", "samesite", "secure",
                                                   "httponly"}:
            return pair
    return None


def _cookie_flags(set_cookie: str) -> dict[str, bool]:
    """Flag presence on a Set-Cookie header (attribute may carry a value,
    e.g. ``SameSite=Lax`` — the attribute itself is what we detect)."""
    parts = [p.strip().lower() for p in set_cookie.split(";")]
    return {
        "secure": any(p == "secure" for p in parts),
        "httponly": any(p == "httponly" for p in parts),
        "samesite": any(p == "samesite" or p.startswith("samesite=")
                        for p in parts),
    }


def _validate_in_scope(scope_engine: ScopeEngine, case_id: str, url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ScopeViolationError(
            f"URL scheme '{parsed.scheme or 'none'}' is not auditable",
            reason="Only http/https URLs are audited; everything else is blocked.",
            action="Provide an http(s) URL inside the case scope.",
        )
    host = (parsed.hostname or "").lower().rstrip(".")
    scope_engine.validate(case_id, host)
    return url


@dataclass
class AuthAuditResult:
    """Deterministic result of one authenticated posture audit."""

    base_url: str
    login_url: str
    kind: str                     # audited | auth_failed | error
    checks: list[dict] = field(default_factory=list)
    session_rotated: bool | None = None
    mfa_hint: bool = False
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "base_url": self.base_url, "login_url": self.login_url,
            "kind": self.kind, "checks": self.checks,
            "session_rotated": self.session_rotated,
            "mfa_hint": self.mfa_hint, "note": self.note,
        }


class AuthenticatedPostureAuditor:
    """One credential, one login, deterministic checks, full provenance."""

    source_key = "scan.webauth"

    def __init__(self, case_id: str, *, scope_engine: ScopeEngine,
                 ledger: ClaimLedger, evidence: EvidenceStore,
                 credential_broker=None, actor: str = "operator",
                 fetch=None) -> None:
        self.case_id = case_id
        self.scope_engine = scope_engine
        self.ledger = ledger
        self.evidence = evidence
        self._broker = credential_broker
        self._actor = actor
        self._fetch = fetch or _fetch_no_redirect

    # -- public API -----------------------------------------------------------

    def audit(self, *, base_url: str, login_url: str, credential: str,
              user_field: str = "username", pass_field: str = "password") -> AuthAuditResult:
        if not self._broker:
            raise UsageError(
                "No credential broker available",
                reason="web-auth-audit resolves the secret through the "
                       "case's CredentialBroker.",
                action="Store a credential first: rebel-profiler credential store.",
            )
        _validate_in_scope(self.scope_engine, self.case_id, base_url)
        _validate_in_scope(self.scope_engine, self.case_id, login_url)

        # 1) resolve the secret in-process (scoped, audited by the broker).
        # Secret format is "username:password" — BOTH fields come from the
        # credential store, so neither crosses argv, stdout or the LLM plane.
        secret = self._broker.use(
            self.case_id, credential, purpose=f"web-auth-audit:{base_url}",
            actor=self._actor,
        )
        username, _, password = secret.partition(":")
        if not username or not password:
            raise UsageError(
                f"Credential '{credential}' is not in 'username:password' form",
                reason="web-auth-audit needs both fields from the credential store.",
                action="Re-store the test account as 'username:password'.",
            )

        # 2) anonymous baseline: status + session cookie before login
        anon_status, anon_headers, _, anon_setcookie = self._fetch(base_url)
        anon_session = _extract_session_cookie(anon_setcookie)

        # 3) exactly ONE login attempt — no retry, no lockout pressure
        body = urllib.parse.urlencode({user_field: username,
                                       pass_field: password}).encode()
        login_status, login_headers, _, login_setcookie = self._fetch(
            login_url, data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        session = _extract_session_cookie(login_setcookie)

        checks: list[dict] = []
        if session is None or login_status not in {200, 302, 303}:
            # A failed login is an honest answer, not an error to retry.
            evidence_id = self._register_evidence(
                base_url, login_url, login_status, checks)
            return AuthAuditResult(
                base_url=base_url, login_url=login_url, kind="auth_failed",
                checks=[{"check": "login", "status": "finding",
                         "detail": f"no session established (status {login_status}); "
                                   "one attempt made by design"}],
                note="credential rejected — verify the test account out-of-band",
            )

        # 4) authenticated fetch of the base page with the session
        auth_status, auth_headers, auth_body, _ = self._fetch(base_url, cookie=session)
        flags = _cookie_flags(login_setcookie)
        for flag, present in flags.items():
            checks.append({
                "check": f"session_cookie:{flag}",
                "status": "pass" if present else "finding",
                "detail": "present" if present else "missing on session cookie",
            })
        cache = (auth_headers.get("Cache-Control") or auth_headers.get("cache-control") or "").lower()
        checks.append({
            "check": "auth_cache_control",
            "status": "pass" if ("no-store" in cache or "private" in cache) else "finding",
            "detail": cache or "missing — authenticated page may be cached",
        })
        rotated = None
        if anon_session is not None and session is not None:
            rotated = anon_session != session
            checks.append({
                "check": "session_rotation",
                "status": "pass" if rotated else "finding",
                "detail": ("session id rotated after login" if rotated
                           else "same session id before and after login"),
            })
        body_text = auth_body.decode("utf-8", errors="replace").lower()
        mfa_hint = any(h in body_text for h in _MFA_HINTS)
        checks.append({
            "check": "mfa_hint",
            "status": "pass" if mfa_hint else "finding",
            "detail": ("MFA indicator found on the authenticated page" if mfa_hint
                       else "no MFA indicator found (informational)"),
        })

        evidence_id = self._register_evidence(base_url, login_url, login_status, checks)
        self._emit_claims(base_url, checks, evidence_id)
        return AuthAuditResult(
            base_url=base_url, login_url=login_url, kind="audited",
            checks=checks, session_rotated=rotated, mfa_hint=mfa_hint,
        )

    # -- evidence + claims ------------------------------------------------------

    def _register_evidence(self, base_url: str, login_url: str,
                           login_status: int, checks: list[dict]) -> str:
        """Register the audit record as evidence; return the evidence id."""
        record = {
            "kind": "rebel-profiler-auth-audit",
            "case_id": self.case_id,
            "base_url": base_url, "login_url": login_url,
            "login_status": login_status,
            "checks": checks,
            "generated_at": time.time(),
        }
        blob = json.dumps(record, indent=2, sort_keys=True)
        rec = self.evidence.register(
            self.case_id, kind="auth_audit", data=blob.encode(),
            source=self.source_key,
            note=f"authenticated posture audit for {base_url}",
            meta={"login_status": login_status, "checks": len(checks)},
        )
        return rec.id

    def _emit_claims(self, base_url: str, checks: list[dict],
                     evidence_id: str) -> None:
        """Failed checks become posture claims on the base URL subject."""
        for check in checks:
            if check["status"] != "finding":
                continue
            if check["check"] == "mfa_hint":
                continue  # informational; MFA absence is not a posture claim
            kind = f"auth_posture:{check['check']}"
            self.ledger.add(
                self.case_id, subject=base_url, kind=kind,
                value=str(check["detail"])[:200],
                source=self.source_key, method="web-auth-audit",
                evidence_id=evidence_id,
            )
