"""Tamper-evident audit chain.

Distinct from evidence: the audit chain records *who did what* to the case
(system actions, approvals, denials). Events are hash-linked: each event's
hash covers its content plus the previous event's hash, so any modification,
removal or reordering of past events is detectable by :meth:`AuditChain.verify`
(PDF 17 audit integrity).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from ..storage.database import Database


def _event_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    case_id: str
    at: float
    actor: str
    action: str
    subject: str
    detail: dict
    hash: str
    prev_hash: str

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "case_id": self.case_id,
            "at": self.at,
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "detail": self.detail,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
        }


class AuditChain:
    """Append-only, hash-linked audit trail per case."""

    GENESIS = "GENESIS"

    def __init__(self, db: Database) -> None:
        self._db = db

    def append(
        self,
        case_id: str,
        *,
        actor: str,
        action: str,
        subject: str = "",
        detail: dict | None = None,
        at: float | None = None,
    ) -> AuditEvent:
        with self._db.conn:
            prev = self._head_hash_locked(case_id)
            ts = time.time() if at is None else at
            payload = {
                "case_id": case_id,
                "at": ts,
                "actor": actor,
                "action": action,
                "subject": subject,
                "detail": detail or {},
                "prev_hash": prev,
            }
            h = _event_hash(payload)
            cur = self._db.conn.execute(
                "INSERT INTO audit_events (case_id, at, actor, action, subject, detail_json, prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    ts,
                    actor,
                    action,
                    subject,
                    json.dumps(detail or {}, sort_keys=True),
                    prev,
                    h,
                ),
            )
            seq = int(cur.lastrowid)
        return AuditEvent(
            seq=seq, case_id=case_id, at=ts, actor=actor, action=action,
            subject=subject, detail=detail or {}, hash=h, prev_hash=prev,
        )

    def _head_hash_locked(self, case_id: str) -> str:
        row = self._db.conn.execute(
            "SELECT hash FROM audit_events WHERE case_id = ? ORDER BY seq DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        return row["hash"] if row else self.GENESIS

    def head_hash(self, case_id: str) -> str:
        with self._db.conn:
            return self._head_hash_locked(case_id)

    def events(self, case_id: str) -> list[AuditEvent]:
        rows = self._db.conn.execute(
            "SELECT * FROM audit_events WHERE case_id = ? ORDER BY seq",
            (case_id,),
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def verify(self, case_id: str) -> dict:
        """Validate the full chain: linkage + content hashes + continuity."""
        rows = self._db.conn.execute(
            "SELECT * FROM audit_events WHERE case_id = ? ORDER BY seq",
            (case_id,),
        ).fetchall()
        problems: list[str] = []
        expected_prev = self.GENESIS
        expected_seq = 1
        for row in rows:
            seq = row["seq"]
            if seq != expected_seq:
                problems.append(f"sequence discontinuity at {seq} (expected {expected_seq})")
            if row["prev_hash"] != expected_prev:
                problems.append(f"event {seq}: chain break (prev_hash mismatch)")
            recomputed = _event_hash({
                "case_id": row["case_id"],
                "at": row["at"],
                "actor": row["actor"],
                "action": row["action"],
                "subject": row["subject"],
                "detail": json.loads(row["detail_json"]),
                "prev_hash": row["prev_hash"],
            })
            if recomputed != row["hash"]:
                problems.append(f"event {seq}: content hash mismatch")
            expected_prev = row["hash"]
            expected_seq = seq + 1
        return {
            "case_id": case_id,
            "events": len(rows),
            "chain_ok": not problems,
            "problems": problems,
        }

    @staticmethod
    def _row_to_event(row) -> AuditEvent:
        return AuditEvent(
            seq=row["seq"],
            case_id=row["case_id"],
            at=row["at"],
            actor=row["actor"],
            action=row["action"],
            subject=row["subject"],
            detail=json.loads(row["detail_json"]),
            hash=row["hash"],
            prev_hash=row["prev_hash"],
        )
