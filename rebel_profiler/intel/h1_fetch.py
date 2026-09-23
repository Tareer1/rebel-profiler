"""HackerOne program scope, fetched directly — no manual CSV downloads.

``bounty fetch <handle>`` pulls the program's structured scope from the
HackerOne Hacker API and hands the same normalized document
:func:`rebel_profiler.intel.program.parse_scope_document` already accepts,
so the authorization chain is identical to a manual import: published
scope → scope entries → fail-closed enforcement.

Honesty rules:

  * the fetch is a plain authenticated GET (basic auth) over urllib — the
    same stdlib-only discipline as every other network path in this tool;
  * credentials come from, in order: an explicit ``--api-identity`` /
    ``--api-token`` pair, the case's credential broker (names
    ``hackerone-api-identity`` / ``hackerone-api-token``), or
    ``H1_API_USERNAME`` / ``H1_API_TOKEN`` env. With none of those, the
    command fails closed with a fix hint — it never scrapes, never guesses,
    and never logs the token;
  * the token is redacted from every output path (the broker's ``use`` is
    audited; a failed fetch prints no credential material).
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

API_BASE = "https://api.hackerone.com/v1/hackers"

CREDENTIAL_NAMES = ("hackerone-api-identity", "hackerone-api-token")
ENV_NAMES = ("H1_API_USERNAME", "H1_API_TOKEN")

PAGE_SIZE = 100          # the API's documented maximum
MAX_PAGES = 10           # 1000 scope rows is generous for one program
TIMEOUT_S = 30.0


@dataclass(frozen=True)
class ScopeRow:
    """One structured-scope asset, already shaped for the importer."""

    asset_identifier: str
    asset_type: str
    eligible: bool
    instruction: str

    def as_row(self) -> dict:
        return {
            "asset_identifier": self.asset_identifier,
            "asset_type": self.asset_type,
            "eligible_for_submission": self.eligible,
            "instruction": self.instruction,
        }


def resolve_credentials(environ: dict | None = None, *, ctx=None,
                        db=None, case_id: str = "") -> tuple[str, str] | None:
    """Find H1 API credentials, or return None (fail closed, no guessing).

    Order: env → case credential broker. Never prints the secret.
    """
    import os

    env = dict(environ) if environ is not None else dict(os.environ)
    identity = env.get(ENV_NAMES[0], "").strip()
    token = env.get(ENV_NAMES[1], "").strip()
    if identity and token:
        return identity, token
    if ctx is not None and db is not None and case_id:
        try:
            from ..security.credentials import CredentialBroker

            broker = CredentialBroker(db)
            got_identity = broker.use(case_id, CREDENTIAL_NAMES[0],
                                      purpose="bounty-fetch", actor="system")
            got_token = broker.use(case_id, CREDENTIAL_NAMES[1],
                                   purpose="bounty-fetch", actor="system")
            if got_identity and got_token:
                return str(got_identity), str(got_token)
        except Exception:
            pass   # broker miss → fall through to the honest failure
    if identity or token:
        # half-configured is a specific, actionable error
        raise ValueError(
            f"incomplete HackerOne credentials: {'identity' if identity else 'token'} "
            f"missing — set both {ENV_NAMES[0]} and {ENV_NAMES[1]}, or store both "
            f"in the case credential broker as {CREDENTIAL_NAMES[0]} / {CREDENTIAL_NAMES[1]}")
    return None


def _auth_header(identity: str, token: str) -> str:
    raw = f"{identity}:{token}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _get(url: str, auth: str) -> dict:
    request = urllib.request.Request(
        url, headers={
            "Authorization": auth,
            "Accept": "application/json",
            "User-Agent": "rebel-profiler (authorized bounty workflow)",
        }, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")[:200]
        except Exception:
            pass
        raise RuntimeError(
            f"HackerOne API returned HTTP {exc.code} {detail}".rstrip()) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"could not reach the HackerOne API: {type(exc).__name__}: {exc}") from exc


def fetch_program(handle: str, identity: str, token: str) -> dict:
    """One program's metadata + every structured-scope page."""
    handle = str(handle).strip().lstrip("@").strip("/")
    if not handle or "/" in handle or any(c.isspace() for c in handle):
        raise ValueError(f"invalid program handle '{handle}'")
    auth = _auth_header(identity, token)

    program = _get(f"{API_BASE}/programs/{handle}", auth)
    if program.get("errors"):
        raise RuntimeError(f"program lookup failed: {program['errors'][:1]}")

    rows: list[ScopeRow] = []
    page = 1
    while page <= MAX_PAGES:
        payload = _get(
            f"{API_BASE}/programs/{handle}/structured_scopes"
            f"?page[number]={page}&page[size]={PAGE_SIZE}", auth)
        data = payload.get("data") or []
        for item in data:
            attrs = item.get("attributes") or {}
            identifier = str(attrs.get("asset_identifier") or "").strip()
            if not identifier:
                continue
            rows.append(ScopeRow(
                asset_identifier=identifier,
                asset_type=str(attrs.get("asset_type") or "").strip(),
                eligible=bool(attrs.get("eligible_for_submission", True)),
                instruction=str(attrs.get("instruction") or "").strip(),
            ))
        if len(data) < PAGE_SIZE:
            break
        page += 1
        time.sleep(0.2)   # polite pacing between pages

    return {
        "handle": handle,
        "name": (program.get("data") or {}).get("attributes", {}).get("name", handle),
        "url": f"https://hackerone.com/{handle}",
        "rows": [r.as_row() for r in rows],
        "fetched_at": time.time(),
    }


def fetch_program_document(handle: str, identity: str, token: str) -> dict:
    """Fetch + normalize into the scope document the importer accepts."""
    from .program import parse_scope_document

    program = fetch_program(handle, identity, token)
    document = parse_scope_document(
        json.dumps({"data": [{"attributes": row} for row in program["rows"]]}),
        program=program["handle"])
    document["program_name"] = program["name"]
    document["program_url"] = program["url"]
    return document
