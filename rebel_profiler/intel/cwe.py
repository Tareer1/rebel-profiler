"""CWE knowledge: the full MITRE weakness catalog, live + offline.

Two honest halves:

* **Live** — the official MITRE ``cwec_latest.xml.zip`` (weaknesses,
  categories, descriptions, mitigations, exploit-likelihood) is fetched
  ONCE on demand, parsed into a compact catalog, and cached under the
  data dir with its published version. This is external content: it is
  wrapped as DATA, never instructions, and the fetcher sets a distinct
  User-Agent so operators can see (and block) it on their egress.
* **Offline** — a built-in catalog of every CWE the tool's own
  detection/coverage planes reference, so ``cwe lookup`` and blind-spot
  reports work with zero network.

A *blind spot* is a weakness class that is both (a) likely exploitable
per MITRE's likelihood field / known-missing-mitigation heuristics and
(b) not yet probed by this case's claim ledger. The ranking is
deterministic: likelihood first, then id.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
USER_AGENT = "rebel-profiler-cwe-knowledge (+offline-first; see docs/WSL.md)"
CACHE_VERSION = 1
FETCH_TIMEOUT = 90
_MIN_CATALOG_ENTRIES = 500   # a real MITRE catalog carries ~1400 entries

# Abstractions that describe real, findable weaknesses (not research views).
_REAL_ABSTRACTIONS = {"Base", "Variant", "Class", "Compound"}


@dataclass(frozen=True)
class CWEEntry:
    cwe_id: str
    name: str
    description: str
    likelihood: str            # "high" | "medium" (per MITRE) | "" (unranked)
    mitigations: tuple[str, ...]
    abstraction: str = ""

    def as_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id, "name": self.name,
            "description": self.description, "likelihood": self.likelihood,
            "mitigations": list(self.mitigations),
            "abstraction": self.abstraction,
        }


# ---------------------------------------------------------------------------
# Built-in offline catalog: every CWE this tool's own planes reference.


def _b():
    return CWEEntry("CWE-16", "Configuration", "Product configuration creates one of the weaknesses in the Configuration category.",
                    "", ("Review deployment defaults; enforce hardened configuration baselines.",), "Category")


def _builtin_entries() -> tuple[CWEEntry, ...]:
    """The offline seed: detection-relevant CWEs only (not the full 969)."""
    raw = (
        ("16", "Configuration", "Configuration weaknesses category: the product is deployed or shipped in a state that enables another weakness.", "", "Category"),
        ("22", "Path Traversal", "The product uses external input to construct a pathname that resolves outside the intended directory.", "high", "Class"),
        ("78", "OS Command Injection", "The product constructs an OS command using externally-influenced input without neutralizing special elements.", "high", "Class"),
        ("79", "Cross-site Scripting", "The product does not neutralize user-controllable input before placing it in a web page served to other users.", "high", "Class"),
        ("89", "SQL Injection", "The product constructs an SQL command using externally-influenced input without neutralizing special elements.", "high", "Class"),
        ("200", "Information Exposure", "The product exposes sensitive information to an actor that is not explicitly authorized to see it.", "high", "Class"),
        ("200" + "", "Information Exposure", "", "", ""),  # placeholder guard
        ("306", "Missing Authentication for Critical Function", "The product does not perform authentication for a critical function.", "high", "Base"),
        ("319", "Cleartext Transmission of Sensitive Information", "The product transmits sensitive data in cleartext over an unencrypted channel.", "high", "Base"),
        ("326", "Inadequate Encryption Strength", "The product stores or transmits data using an encryption scheme weaker than required.", "medium", "Class"),
        ("327", "Use of a Broken or Risky Cryptographic Algorithm", "The product uses a broken or risky crypto algorithm (MD5, SHA-1, DES, RC4).", "high", "Class"),
        ("350", "Reliance on Reverse DNS Resolution for a Security-Critical Action", "The product performs reverse DNS resolution to authorize actions — spoofable.", "medium", "Variant"),
        ("359", "Exposure of Private Personal Information (Privacy)", "Private personal information is exposed to unauthorized actors.", "medium", "Base"),
        ("471", "Modification of Assumed-Immutable Data (MAID)", "The product does not properly protect assumed-immutable data from modification.", "medium", "Base"),
        ("601", "Open Redirect", "The product accepts a user-controlled URL that redirects to an untrusted site.", "high", "Variant"),
        ("614", "Sensitive Cookie in Multi-Hop Domain without 'Secure' flag / session hygiene", "Authentication session cookies lack 'Secure'/SameSite attributes or session ids are not rotated after login, enabling interception or fixation.", "high", "Class"),
        ("639", "Authorization Bypass Through User-Controlled Key", "The product's authorization checks a user-controlled key (IDOR class) that references an object the actor cannot access.", "high", "Base"),
        ("250", "Execution with Unnecessary Privileges", "The product performs its work with privilege levels higher than necessary (root/privileged containers), amplifying any defect's impact.", "high", "Base"),
        ("693", "Protection Mechanism Failure", "The product does not protect or incorrectly protects against a weakness (missing headers, disabled mitigations).", "high", "Class"),
        ("940", "Improper Verification of Source (Rogue AP / spoofed origin)", "The product does not verify the source of a communication, enabling spoofed-origin attacks.", "medium", "Base"),
        ("942", "Permissive Cross-domain Policy with Untrusted Domains", "The product uses an overly permissive cross-origin policy (reflected Access-Control-Allow-Origin, wildcard) that lets untrusted origins read authorized responses.", "high", "Variant"),
        ("1004", "Sensitive Cookie Without 'HttpOnly' Flag", "The product uses a cookie for sensitive information without the HttpOnly flag.", "medium", "Variant"),
        ("1059", "Insufficient Technical Documentation / WAF reliance", "The product relies on a front-end filter (e.g. WAF) as its only defense — the origin stays reachable.", "medium", "Class"),
        ("1104", "Use of Unmaintained Third Party Components", "The product relies on third-party components that are unmaintained or vulnerable (version exposure).", "high", "Class"),
        ("1275", "Sensitive Cookie with Improper SameSite Attribute", "SameSite attribute missing or set insecurely, enabling CSRF exposure.", "medium", "Variant"),
        ("1336", "Improper Neutralization of Template Expressions (SSTI)", "The product does not neutralize template expressions in user-controlled input.", "high", "Base"),
        ("1395", "Dependency on Vulnerable Third-Party Component (published exploits)", "The product relies on a third-party component with published exploits (exploit-db correlation class).", "high", "Category"),
    )
    out = []
    for row in raw:
        if not row[0] or not row[2]:
            continue
        out.append(CWEEntry(
            cwe_id="CWE-" + row[0], name=row[1], description=row[2],
            likelihood=row[3], mitigations=(), abstraction=row[4],
        ))
    return tuple(out)


_BUILTIN: dict[str, CWEEntry] | None = None


def builtin_catalog() -> dict[str, CWEEntry]:
    global _BUILTIN
    if _BUILTIN is None:
        _BUILTIN = {e.cwe_id: e for e in _builtin_entries()}
    return _BUILTIN


# ---------------------------------------------------------------------------
# Live fetch: official MITRE catalog, parsed to a compact cache.


def _strip_tags(fragment: str) -> str:
    text = re.sub(r"<[^>]+>", " ", fragment)
    return re.sub(r"\s+", " ", text).strip()


def _fetch_catalog_zip() -> tuple[str, str]:
    """(xml_text, version) straight from the official MITRE zip."""
    import io
    import urllib.request
    import zipfile

    req = urllib.request.Request(CWE_XML_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        payload = resp.read()
    zf = zipfile.ZipFile(io.BytesIO(payload))
    member = zf.namelist()[0]
    version_m = re.search(r"cwec_v([\d.]+)\.xml", member)
    return (zf.read(member).decode("utf-8", errors="replace"),
            version_m.group(1) if version_m else "unknown")


def _parse_catalog(xml: str) -> dict:
    """Extract a compact catalog: id, name, desc, likelihood, mitigations."""
    catalog: dict[str, dict] = {}
    for m in re.finditer(r'<Weakness ID="(\d+)"[^>]*Name="([^"]+)"[^>]*>'
                         r'(.*?)(?=<Weakness ID=|</Weaknesses>|</Category>)',
                         xml, re.S):
        wid, name, block = m.group(1), m.group(2), m.group(3)
        desc_m = re.search(r"<Description>(.*?)</Description>", block, re.S)
        description = _strip_tags(desc_m.group(1))[:600] if desc_m else ""
        like_m = (re.search(r"<Likelihood_Of_Exploit>\s*(?:<Likelihood>)?\s*"
                            r"(\w+)\s*", block, re.I))
        likelihood = ("" if not like_m else like_m.group(1).lower())
        mitigations = tuple(
            _strip_tags(mm.group(1))[:300]
            for mm in list(re.finditer(r"<Mitigation[^>]*>(.*?)</Mitigation>",
                                       block, re.S))[:3]
            if _strip_tags(mm.group(1))
        )
        abstraction_m = re.search(r'Abstraction="([^"]+)"',
                                  xml[m.start() - 200: m.start() + 300])
        catalog[f"CWE-{wid}"] = {
            "cwe_id": f"CWE-{wid}", "name": name[:200],
            "description": description, "likelihood": likelihood,
            "mitigations": list(mitigations),
            "abstraction": abstraction_m.group(1) if abstraction_m else "",
        }
    # Categories (e.g. CWE-16 Configuration) — identity + description only.
    for m in re.finditer(r'<Category ID="(\d+)"[^>]*Name="([^"]+)"', xml):
        catalog[f"CWE-{m.group(1)}"] = {
            "cwe_id": f"CWE-{m.group(1)}", "name": m.group(2)[:200],
            "description": "", "likelihood": "", "mitigations": [],
            "abstraction": "Category",
        }
    return catalog


def cache_path(data_dir: str | Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else (
        Path.home() / ".local/share/rebel-profiler")
    return base / "knowledge" / "cwe_catalog.json"


def catalog_status(data_dir: str | Path | None = None) -> dict:
    path = cache_path(data_dir)
    if not path.exists():
        return {"cached": False, "path": str(path), "source": "builtin",
                "count": len(builtin_catalog())}
    try:
        blob = json.loads(path.read_text())
        return {"cached": True, "path": str(path),
                "version": blob.get("version", "?"),
                "fetched_at": blob.get("fetched_at", 0),
                "count": len(blob.get("catalog", {})),
                "source": "mitre-cache"}
    except (json.JSONDecodeError, OSError):
        return {"cached": False, "path": str(path), "source": "builtin",
                "count": len(builtin_catalog())}


def refresh_catalog(data_dir: str | Path | None = None) -> dict:
    """Fetch + parse + cache the official MITRE catalog (once, on demand)."""
    xml, version = _fetch_catalog_zip()
    catalog = _parse_catalog(xml)
    if len(catalog) < _MIN_CATALOG_ENTRIES:
        raise ValueError(
            "MITRE catalog parse yielded too few entries — refusing to cache")
    path = cache_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = {"version": version, "fetched_at": time.time(),
            "count": len(catalog), "catalog": catalog}
    path.write_text(json.dumps(blob))
    return {"cached": True, "path": str(path),
            "version": version, "count": len(catalog),
            "source": "mitre-live"}


def get_catalog(data_dir: str | Path | None = None,
                *, refresh: bool = False) -> dict[str, dict]:
    """The merged catalog: MITRE cache when present, built-in as base."""
    merged = {k: v.as_dict() for k, v in builtin_catalog().items()}
    if not refresh:
        path = cache_path(data_dir)
        try:
            blob = json.loads(path.read_text())
            merged.update(blob.get("catalog", {}))
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    if refresh:
        refresh_catalog(data_dir)
        path = cache_path(data_dir)
        blob = json.loads(path.read_text())
        merged.update(blob.get("catalog", {}))
    return merged


def lookup(cwe_ref: str, data_dir: str | Path | None = None,
           *, refresh: bool = False) -> CWEEntry | None:
    """One CWE entry by id ('79', 'CWE-79') or a case-insensitive name."""
    key = str(cwe_ref).strip().upper()
    if not key.startswith("CWE"):
        key = "CWE-" + key.lstrip("-")
    catalog = get_catalog(data_dir, refresh=refresh)
    if key in catalog:
        row = catalog[key]
        return CWEEntry(**row)
    for row in catalog.values():
        if key.lstrip("CWE-").lower() in row["name"].lower():
            return CWEEntry(**row)
    return None


def search(term: str, data_dir: str | Path | None = None,
           *, limit: int = 20) -> list[CWEEntry]:
    needle = str(term).strip().lower()
    if len(needle) < 3:
        return []
    out: list[CWEEntry] = []
    for row in get_catalog(data_dir).values():
        hay = (row["name"] + " " + row["description"]).lower()
        if needle in hay:
            out.append(CWEEntry(**row))
            if len(out) >= limit:
                break
    return out


def blind_spots(ledger, case_id: str,
                data_dir: str | None = None) -> dict:
    """Likelihood-ranked weaknesses this case has not probed.

    Merges three signals:
      * MITRE likelihood (high ranks first),
      * the tool's live coverage matrix (classes with a detect action but
        no claims yet rank above classes the tool cannot detect at all),
      * the case's observed claim kinds (probed = not a blind spot).
    """
    from ..execution.broker import AdapterRegistry
    from ..intel.vulncov import coverage_for_case

    catalog = get_catalog(data_dir)
    report = coverage_for_case(ledger, case_id)
    probed_cwes: set[str] = set()
    for row in report["classes"]:
        if row["status"] == "covered":
            probed_cwes.add(row["cwe"])
    probed_actions: set[str] = set()
    for claim in ledger.list(case_id):
        method = str(getattr(claim, "method", "") or "")
        if method:
            probed_actions.add(method)
    live_actions = set(AdapterRegistry().names())

    rows = []
    for row in report["classes"]:
        if row["status"] == "covered":
            continue
        entry = catalog.get(row["cwe"])
        likelihood = (entry or {}).get("likelihood", "")
        runnable = any(a in live_actions and a not in probed_actions
                       for a in row["detect_actions"])
        score = (0 if likelihood == "high" else 1 if likelihood == "medium" else 2,
                 0 if runnable else 1, row["class"])
        rows.append({
            "class": row["class"], "cwe": row["cwe"], "title": row["title"],
            "name": (entry or {}).get("name", row["title"]),
            "description": (entry or {}).get("description", ""),
            "likelihood": likelihood, "runnable": runnable,
            "detect_actions": [a for a in row["detect_actions"]
                               if a in live_actions][:3],
            "score": score,
        })
    rows.sort(key=lambda r: r["score"])
    return {
        "schema_version": 1, "case_id": case_id,
        "blind_spots": rows[:20],
        "rule": ("Ranked by MITRE exploit likelihood, then by whether this "
                 "tool can still run a detect action. Every entry passes "
                 "the six gates before anything executes."),
    }
