"""JavaScript intelligence: endpoints, secrets and cloud URLs from JS source.

Modern web applications leak their *real* attack surface through the
JavaScript they ship: API route templates, config blobs, S3/GCS buckets,
Firebase projects, API keys. This module is the deterministic extractor the
``js-intel`` adapter runs over fetched JS — the bug-bounty recon step that
turns "what pages exist" into "what the app actually talks to".

Laws (same as the rest of the tool):

* **Bounded input.** Files are truncated before scanning; regexes are
  compiled once; every candidate is length-capped. A minified 5MB bundle
  cannot wedge the pipeline.
* **Untrusted by default.** A JS file is data from a third party — extractor
  output feeds claims, not execution. Findings are *candidates*: each carries
  a confidence tag and a kind that downstream humans/LLMs must verify before
  any reportable claim.
* **No fetching here.** This module parses text it is given. Network access
  lives in the adapter (curl, one URL, broker-gated).
"""

from __future__ import annotations

import re

MAX_JS_BYTES = 2 * 1024 * 1024          # refuse to scan beyond 2MB of text
MAX_FINDINGS_PER_FILE = 200             # per-kind cap keeps claims sane
MAX_TOKEN_LEN = 300                     # any single extracted token

# ---------------------------------------------------------------------------
# compiled once

# Absolute and root-relative paths inside JS. The quote anchor keeps us out
# of regex literals and plain prose; the path charset excludes whitespace
# and control characters.
_PATH_RE = re.compile(
    r"[\"'`](/(?:api|v[0-9]{1,2}|rest|graphql|gql|auth|admin|internal|"
    r"private|debug|actuator|wp-json|_next|service|svc|rpc|ws)?"
    r"/[A-Za-z0-9_./{}$:-]{1,180})[\"'`]")
_URL_RE = re.compile(
    r"[\"'`](https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]{4,300})[\"'`]")

# Keys/secrets: name = "value" shapes, JSON or JS assignment.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id",
     re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_s3_url",
     re.compile(r"\b([A-Za-z0-9][A-Za-z0-9-]{0,62}\.s3(?:[.-][a-z0-9-]{2,20})?"
                r"\.amazonaws\.com)\b", re.I)),
    ("google_api_key",
     re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("firebase_url",
     re.compile(r"\b([A-Za-z0-9-]{3,40}\.firebaseio\.com)\b", re.I)),
    ("firebase_project",
     re.compile(r"\b([A-Za-z0-9-]{3,40}\.firebaseapp\.com)\b", re.I)),
    ("supabase_url",
     re.compile(r"\b([A-Za-z0-9-]{3,60}\.supabase\.co)\b", re.I)),
    ("jwt_secret_name",
     re.compile(r"[\"'`](JWT[_A-Za-z0-9]*SECRET[_A-Za-z0-9]*)[\"'`]",
                re.I)),
    ("private_key_marker",
     re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    ("slack_token",
     re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,60})\b")),
    ("github_token",
     re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{20,60})\b")),
    ("generic_api_key",
     re.compile(r"[\"'`]?(api[_-]?key|apikey|access[_-]?token|"
                r"auth[_-]?token|client[_-]?secret)[\"'`]?\s*[:=]\s*"
                r"[\"'`]([A-Za-z0-9_./+=-]{8,120})[\"'`]", re.I)),
    ("bearer_token_literal",
     re.compile(r"[Bb]earer\s+[\"'`]([A-Za-z0-9_./+=-]{16,200})[\"'`]")),
)

# Domains worth flagging even outside the scope — exposed-service hints.
# The host label left of the service suffix must not itself be a bare AWS
# region (``eu-west-1.amazonaws.com`` is an endpoint fragment, not a host).
_INTERESTING_HOST_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\."
    r"(?:s3\.amazonaws\.com|s3-[a-z0-9-]{2,20}\.amazonaws\.com|"
    r"[a-z0-9-]{2,20}\.amazonaws\.com|"
    r"azurewebsites\.net|cloudfront\.net|azure-api\.net|herokuapp\.com|"
    r"vercel\.app|netlify\.app|pages\.dev|workers\.dev|firebaseapp\.com|"
    r"firebaseio\.com|supabase\.co|r2\.dev|backblazeb2\.com|"
    r"digitaloceanspaces\.com))\b", re.I)
_REGION_LABEL_RE = re.compile(
    r"^(?:us|eu|ap|sa|ca|me|af|cn)-[a-z]+-\d+$", re.I)


def _add(bucket: list, seen: set, kind: str, value: str,
         confidence: str, note: str = "") -> None:
    value = value.strip()[:MAX_TOKEN_LEN]
    if not value:
        return
    key = (kind, value.lower())
    if key in seen:
        return
    seen.add(key)
    bucket.append({"kind": kind, "value": value,
                   "confidence": confidence, "note": note})


def extract(text: str) -> dict:
    """Extract candidate intelligence from one JS document.

    Returns ``{"endpoints": [...], "secrets": [...], "hosts": [...]}`` with
    bounded, deduplicated, confidence-tagged candidates. Never raises on
    malformed content: garbage in, structured (possibly empty) findings out.
    """
    text = text[:MAX_JS_BYTES]
    endpoints: list[dict] = []
    secrets: list[dict] = []
    hosts: list[dict] = []
    seen: set = set()

    for match in _PATH_RE.finditer(text):
        _add(endpoints, seen, "api_path", match.group(1), "candidate",
             "route template embedded in JS")
    for match in _URL_RE.finditer(text):
        _add(endpoints, seen, "url", match.group(1), "candidate",
             "absolute URL embedded in JS")

    for kind, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() and match.group(1) \
                else match.group(0)
            conf = "high" if kind in {
                "aws_access_key_id", "google_api_key", "slack_token",
                "github_token", "private_key_marker", "firebase_url",
            } else "candidate"
            _add(secrets, seen, kind, value, conf, f"pattern match: {kind}")
            if len(secrets) >= MAX_FINDINGS_PER_FILE:
                break

    for match in _INTERESTING_HOST_RE.finditer(text):
        host = match.group(1)
        labels = host.split(".")
        if any(_REGION_LABEL_RE.match(lb) for lb in labels[:-2]):
            continue   # region endpoint fragment (s3.<region>.…), not a host
        _add(hosts, seen, "cloud_host", host, "candidate",
             "hosted-service domain referenced in JS")

    return {
        "endpoints": endpoints[:MAX_FINDINGS_PER_FILE],
        "secrets": secrets[:MAX_FINDINGS_PER_FILE],
        "hosts": hosts[:MAX_FINDINGS_PER_FILE],
    }


def summarize(report: dict) -> str:
    """One-line human summary for CLI/LLM consumers."""
    e, s, h = (len(report.get("endpoints", ())),
               len(report.get("secrets", ())),
               len(report.get("hosts", ())))
    return f"{e} endpoint(s), {s} secret candidate(s), {h} cloud host(s)"
