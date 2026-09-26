"""Unknown-vulnerability detection: anomalies the signature lists miss.

Known-CVE matching answers "is this version vulnerable?". This plane
answers the harder question: *"kya yahan kuch aisa badla / hai jo hona
nahi chahiye?"* — weaknesses nobody has published yet show up first as
CHANGES and OUTLIERS:

* **first_seen** — a claim kind/value pair observed for the first time in
  the case (new host, new path, new tech) is surfaced, not silently mixed;
* **drift** — the same subject observed twice with differing values for
  the same kind (tech changed, version dropped, a header disappeared) is
  a baseline deviation, and baseline deviations are where zero-days and
  supply-chain surprises surface first;
* **rare** — across many subjects, a value held by exactly one subject
  while every peer differs (one host with an odd header set, one admin
  panel on a fleet of shops) is an outlier worth a human look.

Every rule is deterministic, computed over the case's own claim ledger —
no scoring opinions, no network. An anomaly is a CANDIDATE for analysis
with provenance to the claims that produced it; verification still goes
through the gated probe/payload plane.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.errors import UsageError


def detect_anomalies(ledger, case_id: str, *,
                     min_subjects_for_rare: int = 4) -> dict:
    """Compute first-seen, drift and rare-value anomalies for one case.

    Deterministic ordering: drift (highest signal) → rare → first_seen,
    then by subject/kind for stable output. Every finding carries the
    claim ids that evidence it.
    """
    # kind -> subject -> set of values; and value -> claim ids
    values: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    value_claims: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    first_seen: dict[tuple[str, str, str], float] = {}
    subjects: set[str] = set()

    for claim in ledger.list(case_id):
        kind = str(getattr(claim, "kind", "") or "")
        subject = str(getattr(claim, "subject", "") or "")
        value = str(getattr(claim, "value", "") or "").strip()
        observed = float(getattr(claim, "observed_at", 0.0) or 0.0)
        if not kind or not subject or not value:
            continue
        subjects.add(subject)
        values[kind].setdefault(subject, set()).add(value)
        key = (kind, subject, value.lower())
        value_claims[key].append(str(getattr(claim, "id", "")))
        prev = first_seen.get(key)
        if prev is None or observed < prev:
            first_seen[key] = observed

    findings: list[dict] = []

    # --- drift: same subject+kind, multiple distinct values over time ----
    for kind, per_subject in sorted(values.items()):
        for subject, vals in sorted(per_subject.items()):
            if len(vals) < 2:
                continue
            ordered = sorted(vals, key=lambda v: first_seen.get((kind, subject, v.lower()), 0.0))
            older, newer = ordered[0], ordered[-1]
            claim_ids: list[str] = []
            for v in (older, newer):
                claim_ids.extend(value_claims.get((kind, subject, v.lower()), []))
            findings.append({
                "type": "drift",
                "kind": kind,
                "subject": subject,
                "detail": f"{older!r} -> {newer!r}",
                "claim_ids": claim_ids[:8],
                "why": ("the same attribute changed between collections — "
                        "unknown-change signal: deploy, misconfiguration, "
                        "or something else changed it"),
            })

    # --- rare: one subject holds a value no peer holds --------------------
    for kind, per_subject in sorted(values.items()):
        if len(per_subject) < min_subjects_for_rare:
            continue
        value_owners: dict[str, set[str]] = defaultdict(set)
        for subject, vals in per_subject.items():
            for v in vals:
                value_owners[v.lower()].add(subject)
        for subject, vals in sorted(per_subject.items()):
            for v in sorted(vals):
                owners = value_owners.get(v.lower(), set())
                if len(owners) != 1:
                    continue
                # unique value held by this subject while peers differ
                claim_ids = list(value_claims.get((kind, subject, v.lower()), []))
                findings.append({
                    "type": "rare",
                    "kind": kind,
                    "subject": subject,
                    "detail": f"{v[:120]} (unique across {len(per_subject)} subjects)",
                    "claim_ids": claim_ids[:8],
                    "why": ("one host carries what no peer carries — outlier "
                            "config or unintended exposure"),
                })

    # --- first-seen: kinds/subjects newly observed in the case ------------
    # (deterministic: the earliest observation per kind+subject, only when
    # the subject has exactly one observation of that kind — a true first
    # contact, not a drift event)
    for kind, per_subject in sorted(values.items()):
        for subject, vals in sorted(per_subject.items()):
            if len(vals) != 1:
                continue
            v = next(iter(vals))
            claim_ids = list(value_claims.get((kind, subject, v.lower()), []))
            findings.append({
                "type": "first_seen",
                "kind": kind,
                "subject": subject,
                "detail": f"{v[:120]}",
                "claim_ids": claim_ids[:8],
                "why": "first observation of this attribute — new surface",
            })

    order = {"drift": 0, "rare": 1, "first_seen": 2}
    findings.sort(key=lambda f: (order[f["type"]], f["subject"], f["kind"]))
    return {
        "schema_version": 1,
        "case_id": case_id,
        "subjects_analyzed": len(subjects),
        "anomalies": findings[:80],
        "counts": {
            "drift": sum(1 for f in findings if f["type"] == "drift"),
            "rare": sum(1 for f in findings if f["type"] == "rare"),
            "first_seen": sum(1 for f in findings if f["type"] == "first_seen"),
        },
        "rule": (
            "Unknown-vulnerability candidates are CHANGES and OUTLIERS over "
            "the case's own claims — deterministic, no opinions. An anomaly "
            "is a candidate for analysis; verification still passes the six "
            "gates."
        ),
    }


def require_case(case_id: str) -> str:
    if not case_id or not str(case_id).strip():
        raise UsageError("anomaly analysis needs a case id",
                         action="Pass an active case id.")
    return str(case_id).strip()
