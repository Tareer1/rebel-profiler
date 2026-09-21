"""Search-engine dorking as a first-class, evidenced collection action.

Dorking = querying search engines with targeted operators (``site:``,
``filetype:``, ``intitle:index.of`` …) to surface exposed assets, documents,
login portals and misconfigurations *from the outside* — the classic passive
recon step between cert-transparency and a web crawl.

Design (same law as the rest of the tool):

* **Local + opt-in network.** Queries go through curl, like cert-transparency;
  nothing is scraped interactively. Tor support routes the same argv through
  ``torsocks`` when the operator asks for it (and it must be installed).
* **Validated templates only.** A dork is a *named template* from
  :data:`DORK_TEMPLATES` plus the operator's target — no free-form query ever
  reaches argv. HTML/JSON is parsed defensively; engine markup is untrusted.
* **Tor = transport, not authorization.** ``torsocks`` changes where packets
  go, not what the case may touch. Scope/policy gates still decide.
* **Engine courtesy.** One page per query, no pagination loops, explicit
  single-shot curl timeouts — this is recon, not load generation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..core.errors import UsageError

_DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_TLD = r"[A-Za-z0-9-]{1,24}"


@dataclass(frozen=True)
class DorkTemplate:
    """One named dork: a query template plus what its hits mean."""

    name: str
    query: str                      # {} is substituted with the target
    kind: str                       # claim kind for each parsed hit
    description: str

    def build(self, target: str) -> str:
        if "{}" not in self.query:
            return self.query
        return self.query.replace("{}", target)


DORK_TEMPLATES: dict[str, DorkTemplate] = {
    t.name: t for t in (
        # --- exposure of documents and directories -------------------------
        DorkTemplate(
            "site-files", 'site:{} (filetype:pdf OR filetype:doc OR '
            'filetype:xls OR filetype:csv)', "document",
            "Indexed documents on the target domain"),
        DorkTemplate(
            "open-directories", 'intitle:"index.of" site:{}', "directory",
            "Open directory listings on the target domain"),
        DorkTemplate(
            "config-files", 'site:{} (ext:conf OR ext:cnf OR ext:cfg OR '
            'ext:env OR ext:ini)', "config",
            "Possible configuration files indexed for the domain"),
        DorkTemplate(
            "backup-files", 'site:{} (ext:bak OR ext:old OR ext:swp OR '
            'ext:sql OR ext:dump)', "backup",
            "Possible backup/dump files indexed for the domain"),
        # --- portals and auth surfaces --------------------------------------
        DorkTemplate(
            "login-portals", 'site:{} (inurl:login OR inurl:signin OR '
            'inurl:wp-admin OR inurl:admin)', "portal",
            "Login/admin portals surfaced by the engine"),
        DorkTemplate(
            "staging-sites", 'site:{} (inurl:staging OR inurl:dev OR '
            'inurl:test OR inurl:uat OR inurl:beta)', "staging",
            "Staging/dev/test hosts surfaced by the engine"),
        # --- cloud and mail leakage -----------------------------------------
        DorkTemplate(
            "cloud-buckets", 'site:s3.amazonaws.com OR site:blob.core.windows.'
            'net OR site:storage.googleapis.com "{}"', "bucket",
            "Cloud storage buckets matching the target name"),
        DorkTemplate(
            "exposed-emails", 'site:{} intext:"@{}"', "email_domain",
            "Pages on the domain exposing @-addresses of the same domain"),
        # --- technology fingerprints ----------------------------------------
        DorkTemplate(
            "tech-stack", 'site:{} (inurl:wp-content OR inurl:jenkins OR '
            'inurl:phpmyadmin OR inurl:.git)', "tech",
            "Technology indicators indexed for the domain"),
    )
}


@dataclass(frozen=True)
class DorkProvider:
    """One search backend: curl argv template + a result parser id."""

    key: str
    argv_builder: str              # "html" engines | "ddg_json" | "ahmia"
    needs_tor: bool

    def argv(self, query: str) -> list[str]:
        q = _url_quote(query)
        if self.key == "google":
            # No JS engine renders this; the plain HTML endpoint is the only
            # polite machine-readable surface. One page, one shot.
            return ["curl", "-fsS", "--max-time", "30",
                    "-A", _UA, f"https://www.google.com/search?q={q}&num=20&hl=en"]
        if self.key == "duckduckgo":
            # The JSON instant-answer API: stable, no scraping ambiguity.
            return ["curl", "-fsS", "--max-time", "30",
                    "-A", _UA, f"https://api.duckduckgo.com/?q={q}&format=json&no_html=1"]
        if self.key == "ahmia":
            # Ahmia indexes .onion services; reachable only via Tor.
            return ["torsocks", "curl", "-fsS", "--max-time", "60",
                    "-A", _UA, f"https://ahmia.fi/search/?q={q}"]
        raise UsageError(f"Unknown dork provider '{self.key}'")


_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


PROVIDERS: dict[str, DorkProvider] = {
    p.key: p for p in (
        DorkProvider("google", "html", False),
        DorkProvider("duckduckgo", "ddg_json", False),
        DorkProvider("ahmia", "ahmia", True),
    )
}


def _url_quote(query: str) -> str:
    from urllib.parse import quote_plus

    return quote_plus(query, safe="")


def build_dork_argv(*, engine: str, dork: str, target: str,
                    tld: str | None = None, pages: int = 1) -> list[str]:
    """Validate inputs and return the whitelisted curl/torsocks argv.

    ``target`` is a domain (validated). ``tld`` (for the onion TLD) is a
    short token appended inside the query template when given.
    """
    provider = PROVIDERS.get(engine)
    if provider is None:
        raise UsageError(
            f"Unknown dork engine '{engine}'",
            reason="Dorking supports google, duckduckgo and ahmia (tor).",
            action="Pick an engine from: google, duckduckgo, ahmia.")
    template = DORK_TEMPLATES.get(dork)
    if template is None:
        raise UsageError(
            f"Unknown dork '{dork}'",
            reason="Free-form queries never reach the shell; only named "
                   "templates are allowed.",
            action="Pick a dork from: " + ", ".join(sorted(DORK_TEMPLATES)) + ".")
    subject = _single_target(target, tld=tld)
    query = template.build(subject)
    argv = provider.argv(query)
    if provider.needs_tor:
        import shutil

        if shutil.which("torsocks") is None:
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                "torsocks is not installed",
                reason="The ahmia (.onion) engine routes curl through "
                       "torsocks; Tor must be running on this machine.",
                action="Install torsocks (apt install torsocks) and start "
                       "tor, then retry.")
    return argv


def _single_target(target: str, *, tld: str | None) -> str:
    """Validate the dork subject: a domain, or a bare name when tld is given.

    ``tld='onion'`` builds ``<name>.onion`` subjects for ahmia; the bare name
    form exists because onion hosts rarely have a public registrable domain.
    """
    from .normalize import canonical_hostname

    host = canonical_hostname(str(target))
    if not host:
        raise UsageError(
            f"Invalid dork target '{target}'",
            reason="Dorking needs a domain (example.test) as its subject.",
            action="Pass a plain domain — the dork templates add operators.")
    if tld is not None:
        if not re.fullmatch(_TLD, tld):
            raise UsageError(
                f"Invalid tld token '{tld}'",
                reason="The tld suffix is appended inside the query string.",
                action="Use a short alphanumeric token, e.g. tld=onion.")
        host = f"{host}.{tld}"
    elif "." not in host:
        raise UsageError(
            f"Invalid dork target '{target}'",
            reason="A dork subject must look like a domain (with a dot), "
                   "or use tld=onion for bare onion names.",
            action="Pass a plain domain, or pass tld=onion for onion names.")
    return host


# ---------------------------------------------------------------------------
# result parsing — engine markup is UNTRUSTED data; parse defensively.


# Google wraps result URLs as /url?q=<percent-encoded>&amp;sa=… inside the
# href; the encoded part ends at the first & (entity or param). Everything
# after it is engine bookkeeping (sa=, ved=, usg=) — dropped in decode.
_URL_RE = re.compile(r'href="(?:/url\?q=|/search\?q=|)(https?%3A%2F%2F[^"]+)"')


def _decode_google_href(raw: str) -> str | None:
    """Decode one percent-encoded result URL; strip engine params at ``&``."""
    from urllib.parse import unquote

    candidate = unquote(raw.split("&", 1)[0])
    if candidate.startswith("http"):
        return candidate
    return None


from urllib.parse import urlparse


def parse_dork_stdout(engine: str, stdout: str) -> list[dict]:
    """Extract structured hits for one query result page.

    Returns ``[{url, title, engine}]`` — every value is treated as untrusted
    and bounded. Never raises on engine markup changes: an unreadable page
    parses to zero hits.
    """
    if engine == "duckduckgo":
        return _parse_ddg_json(stdout)
    if engine == "ahmia":
        return _parse_ahmia(stdout)
    return _parse_google(stdout)


def _bounded(text: str, limit: int = 300) -> str:
    return text[:limit]


def _hit(url: str, title: str, engine: str) -> dict | None:
    if not url.startswith("http"):
        return None
    return {"url": _bounded(url, 500),
            "title": _bounded(title.strip()), "engine": engine}


def _parse_google(stdout: str) -> list[dict]:
    hits: list[dict] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(stdout):
        candidate = _decode_google_href(match.group(1))
        if candidate is None or candidate in seen:
            continue
        seen.add(candidate)
        hit = _hit(candidate, "", "google")
        if hit:
            hits.append(hit)
    return hits[:30]


def _parse_ddg_json(stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    hits: list[dict] = []
    seen: set[str] = set()

    def push(url: str, title: str) -> None:
        if not url or url in seen or not url.startswith("http"):
            return
        seen.add(url)
        hit = _hit(url, title, "duckduckgo")
        if hit:
            hits.append(hit)

    for topic in data.get("RelatedTopics", []) or []:
        if isinstance(topic, dict):
            push(str(topic.get("FirstURL", "")), str(topic.get("Text", "")))
            for nested in topic.get("Topics", []) or []:
                if isinstance(nested, dict):
                    push(str(nested.get("FirstURL", "")),
                         str(nested.get("Text", "")))
    abstract_url = str(data.get("AbstractURL", ""))
    push(abstract_url, str(data.get("Heading", "")))
    return hits[:30]


def _parse_ahmia(stdout: str) -> list[dict]:
    """Ahmia result pages list onion URLs directly (result divs or bare
    ``<a href="http://….onion/…">`` anchors, depending on their template
    revision). Accept onion URLs from any anchor; relative /result links
    are resolved against ahmia.fi. Junk (about/privacy/directory nav
    links) is filtered by requiring an .onion host or a result anchor."""
    from urllib.parse import urljoin

    hits: list[dict] = []
    seen: set[str] = set()
    for match in re.finditer(r'<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                             stdout, re.DOTALL):
        raw, label = match.group(1), re.sub(r"<[^>]+>", "", match.group(2))
        url = urljoin("https://ahmia.fi/", raw)
        host = (urlparse(url).hostname or "")
        if not host.endswith(".onion"):
            continue
        if url in seen:
            continue
        seen.add(url)
        hit = _hit(url, label, "ahmia")
        if hit:
            hits.append(hit)
    return hits[:30]
