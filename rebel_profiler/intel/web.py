"""Scope-enforced web surface audit (Phase 3, PDF 7).

The :class:`ScopeEnforcedWebAuditor` walks a bounded set of same-domain URLs
and evaluates four deterministic check families on every page:

  * **Headers** — security-header presence (CSP, HSTS, X-Frame-Options, …)
    and cleartext redirect targets,
  * **Cookies/session** — Secure/HttpOnly/SameSite flags on Set-Cookie,
  * **Forms** — password fields submitted over cleartext http,
  * **TLS posture** — protocol version reported by a pluggable TLS prober.

Scope enforcement is mechanical, not advisory: **every** URL (seed and
discovered) is validated through the case's :class:`ScopeEngine` before any
fetch, and non-HTML content types are never parsed. Crawl bounds (max pages,
max depth) keep sessions bounded. Every fetched page is registered as
hash-chained evidence; the fetcher is injectable so tests and deployments can
swap the transport without touching the audit logic.

This module evaluates *configuration*, never exploits anything.
"""

from __future__ import annotations

import html.parser
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..core.errors import ScopeViolationError, UsageError
from ..evidence.store import EvidenceStore
from ..security.scope import ScopeEngine
from .claims import ClaimLedger

MAX_PAGES_DEFAULT = 20
MAX_DEPTH_DEFAULT = 2
MAX_BODY_BYTES = 512_000

_FETCH_TIMEOUT = 30
# Politeness floor: minimum seconds between two fetches of the SAME host.
# A crawl is an active interaction with the target; the tool's own discipline
# ("polite timing, no denial-of-service") applies to it too.
MIN_HOST_DELAY_SECONDS = 1.0

_SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

_TLS_RECOMMENDED_MIN = (1, 2)


class _PageParser(html.parser.HTMLParser):
    """Collects links, forms and password inputs from an HTML page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "password_fields": [],
            }
        elif tag == "input" and self._current_form is not None:
            if (a.get("type") or "").lower() == "password":
                self._current_form["password_fields"].append(a.get("name") or "unnamed")

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


@dataclass
class PageAudit:
    """Result of auditing one URL."""

    url: str
    status: int | None
    kind: str                     # audited | blocked | error | non_html
    checks: list[dict] = field(default_factory=list)
    links_found: int = 0
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "kind": self.kind,
            "checks": self.checks,
            "links_found": self.links_found,
            "note": self.note,
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse automatic redirect following.

    urllib follows redirects by default — including to hosts OUTSIDE the case
    scope, which would make the mechanical scope gate a lie: the bytes of an
    out-of-scope host would still enter the evidence ledger. Redirects are
    instead surfaced as a header finding (``redirect_cleartext`` handles the
    http:// case; ``redirect_off_scope`` the cross-host case handled by the
    auditor) and never auto-followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _default_fetch(url: str) -> tuple[int, dict[str, str], bytes]:
    """Fetch ONE URL, never following redirects (scope-safe)."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "rebel-profiler-auditor/0.1"},
    )
    try:
        with _OPENER.open(request, timeout=_FETCH_TIMEOUT) as response:
            body = response.read(MAX_BODY_BYTES)
            return response.status, dict(response.headers.items()), body
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, b""
    except (urllib.error.URLError, OSError) as exc:
        raise UsageError(
            f"Fetch failed for {url}",
            reason=str(exc),
            action="Check network reachability or skip this URL.",
        ) from exc


def _default_tls_probe(host: str, port: int) -> dict:
    """Probe TLS protocol version via stdlib ssl (no target-side interaction)."""
    import socket
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version() or "unknown"
    except (OSError, ssl.SSLError) as exc:
        raise UsageError(
            f"TLS probe failed for {host}:{port}",
            reason=str(exc),
            action="Confirm the service speaks TLS on this port.",
        ) from exc
    return {"protocol": version}


def _parse_protocol(version: str) -> tuple[int, int] | None:
    match = re.fullmatch(r"TLSv?(\d+)\.(\d+)", version)
    if match:
        return int(match.group(1)), int(match.group(2))
    if version == "SSLv3":
        return (3, 0)
    return None


class ScopeEnforcedWebAuditor:
    """Crawls a bounded, scope-validated URL set and audits each page."""

    source_key = "scan.web"

    def __init__(
        self,
        case_id: str,
        *,
        scope_engine: ScopeEngine,
        ledger: ClaimLedger,
        evidence: EvidenceStore,
        fetch=None,
        tls_probe=None,
        max_pages: int = MAX_PAGES_DEFAULT,
        max_depth: int = MAX_DEPTH_DEFAULT,
        db=None,
    ) -> None:
        self.case_id = case_id
        self.scope_engine = scope_engine
        self.ledger = ledger
        self.evidence = evidence
        self.fetch = fetch or _default_fetch
        self.tls_probe = tls_probe or _default_tls_probe
        self.max_pages = max_pages
        self.max_depth = max_depth
        self._db = db
        self._last_fetch_at: dict[str, float] = {}

    # -- scope gate ---------------------------------------------------------

    def _validate_url(self, url: str) -> str:
        """Validate a URL's host against the case scope (fail closed)."""
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeViolationError(
                f"URL scheme '{parsed.scheme or 'none'}' is not auditable",
                reason="Only http/https URLs are audited; everything else is blocked.",
                action="Provide an http(s) URL inside the case scope.",
            )
        host = (parsed.hostname or "").lower().rstrip(".")
        try:
            self.scope_engine.validate(self.case_id, host)
        except ScopeViolationError:
            raise
        return url

    # -- audit families -------------------------------------------------------

    def _audit_headers(self, url: str, headers: dict[str, str]) -> list[dict]:
        checks: list[dict] = []
        lower = {k.lower(): v for k, v in headers.items()}
        for header, name in _SECURITY_HEADERS.items():
            present = header in lower
            checks.append({
                "check": f"header:{name}", "status": "pass" if present else "finding",
                "detail": lower.get(header, "missing"),
            })
        location = lower.get("location", "")
        if location.startswith("http://"):
            checks.append({
                "check": "redirect_cleartext", "status": "finding",
                "detail": f"redirects to {location}",
            })
        # Redirects are never followed (see _NoRedirect) — but a Location
        # header pointing OUTSIDE the case scope is itself a finding worth
        # recording: it exposes an off-scope trust relationship.
        if location and self._host_out_of_scope(location):
            checks.append({
                "check": "redirect_off_scope", "status": "finding",
                "detail": f"redirects to out-of-scope host {location}",
            })
        return checks

    def _host_out_of_scope(self, location: str) -> bool:
        """True when a Location header target's host fails the case scope."""
        host = (urlparse(location).hostname or "").lower().rstrip(".")
        if not host:
            return False
        try:
            self.scope_engine.validate(self.case_id, host)
        except ScopeViolationError:
            return True
        return False

    def _audit_cookies(self, headers: dict[str, str]) -> list[dict]:
        checks: list[dict] = []
        for key, value in headers.items():
            if key.lower() != "set-cookie":
                continue
            cookie_name = value.split("=", 1)[0].strip()
            low = value.lower()
            for flag, label in (
                ("secure", "Secure"),
                ("httponly", "HttpOnly"),
                ("samesite", "SameSite"),
            ):
                if flag not in low:
                    checks.append({
                        "check": f"cookie:{label}", "status": "finding",
                        "detail": f"cookie '{cookie_name}' lacks {label}",
                    })
        return checks

    def _audit_forms(self, url: str, forms: list[dict]) -> list[dict]:
        checks: list[dict] = []
        if urlparse(url).scheme != "http":
            return checks
        for form in forms:
            if form["password_fields"]:
                action = form["action"] or "(self)"
                checks.append({
                    "check": "cleartext_password_form", "status": "finding",
                    "detail": (
                        f"password field(s) {', '.join(form['password_fields'])} "
                        f"submitted over http to {action}"
                    ),
                })
        return checks

    def _audit_tls(self, url: str) -> list[dict]:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return []
        try:
            result = self.tls_probe(parsed.hostname, parsed.port or 443)
        except UsageError as exc:
            return [{
                "check": "tls:protocol", "status": "error", "detail": exc.message,
            }]
        version = result.get("protocol", "unknown")
        parsed_version = _parse_protocol(version)
        if parsed_version is None:
            status, detail = "error", f"unrecognized protocol '{version}'"
        elif parsed_version >= _TLS_RECOMMENDED_MIN:
            status, detail = "pass", version
        else:
            status, detail = "finding", f"legacy protocol {version} in use"
        return [{"check": "tls:protocol", "status": status, "detail": detail}]

    # -- crawl -----------------------------------------------------------------

    def crawl(self, seed_urls: list[str], *, collect_claims: bool = True) -> dict:
        """Bounded BFS crawl with scope validation on every discovered URL."""
        seeds = [self._validate_url(u) for u in seed_urls]
        queue: list[tuple[str, int]] = [(u, 0) for u in seeds]
        seen: set[str] = set()
        pages: list[PageAudit] = []
        started = time.time()

        while queue and len(pages) < self.max_pages:
            url, depth = queue.pop(0)
            normalized = url.rstrip("/")
            if normalized in seen:
                continue
            seen.add(normalized)
            # Politeness: never hit the same host faster than the floor.
            host = (urlparse(url).hostname or "").lower()
            now = time.time()
            wait = self._last_fetch_at.get(host, 0.0) + MIN_HOST_DELAY_SECONDS - now
            if wait > 0:
                time.sleep(wait)
            self._last_fetch_at[host] = time.time()
            try:
                status, headers, body = self.fetch(url)
            except UsageError as exc:
                pages.append(PageAudit(url=url, status=None, kind="error", note=exc.message))
                continue

            content_type = ""
            for key, value in headers.items():
                if key.lower() == "content-type":
                    content_type = value
                    break
            if "text/html" not in content_type.lower():
                pages.append(PageAudit(url=url, status=status, kind="non_html",
                                       note=content_type))
                continue

            parser = _PageParser()
            try:
                parser.feed(body.decode("utf-8", errors="replace"))
            except Exception:  # malformed HTML must never kill the crawl
                parser = _PageParser()

            checks = (
                self._audit_headers(url, headers)
                + self._audit_cookies(headers)
                + self._audit_forms(url, parser.forms)
                + self._audit_tls(url)
            )

            # evidence: exact bytes fetched, hash-chained per case
            blob = f"url: {url}\nstatus: {status}\n\n{body}".encode(
                "utf-8", errors="replace"
            )
            rec = self.evidence.register(
                self.case_id, kind="web_page", data=blob, source=self.source_key,
                note=f"crawl of {url}",
                meta={"status": status, "content_type": content_type},
            )

            if collect_claims:
                self._emit_claims(url, status, checks, rec.id)

            links_found = len(parser.links)
            pages.append(PageAudit(url=url, status=status, kind="audited",
                                   checks=checks, links_found=links_found))

            if depth < self.max_depth:
                for href in parser.links:
                    absolute = urljoin(url, href)
                    parsed = urlparse(absolute)
                    if parsed.scheme not in {"http", "https"}:
                        continue
                    try:
                        self._validate_url(absolute)
                    except ScopeViolationError:
                        continue   # out-of-scope link: skipped silently, by design
                    if absolute.rstrip("/") not in seen:
                        queue.append((absolute, depth + 1))

        findings_count = sum(
            1 for page in pages for check in page.checks if check["status"] == "finding"
        )
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "pages": [p.as_dict() for p in pages],
            "stats": {
                "pages_audited": sum(1 for p in pages if p.kind == "audited"),
                "pages_blocked_or_errored": sum(
                    1 for p in pages if p.kind in {"error", "blocked", "non_html"}
                ),
                "findings": findings_count,
                "wall_seconds": round(time.time() - started, 2),
            },
        }

    def _emit_claims(self, url: str, status: int, checks: list[dict], evidence_id: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        now = time.time()
        emitted = []
        for check in checks:
            if check["status"] != "finding":
                continue
            emitted.append(self.ledger.add(
                self.case_id,
                subject=host,
                kind="web_finding",
                value=f"{check['check']}:{check['detail'][:180]}",
                source=self.source_key,
                method="web-audit",
                observed_at=now,
                evidence_id=evidence_id,
                notes=f"url={url}",
            ))
        if self._db is not None:
            from .collection import CollectionPipeline

            CollectionPipeline(self.ledger, self.evidence, db=self._db)._persist(
                emitted, self.case_id,
            )
