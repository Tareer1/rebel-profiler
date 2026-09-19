"""Evidence store: hashing, provenance, verification.

Every artifact that supports a factual claim must be registered here. An
evidence record is content-addressed (SHA-256) and chained to the previous
record, giving the case ledger tamper-evidence (PDF 12).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..core.errors import EvidenceError
from ..storage.database import Database


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    case_id: str
    kind: str
    sha256: str
    size: int
    created_at: float
    source: str
    note: str
    prev_hash: str
    meta: dict

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "size": self.size,
            "created_at": self.created_at,
            "source": self.source,
            "note": self.note,
            "prev_hash": self.prev_hash,
            "meta": self.meta,
        }


class EvidenceStore:
    """Registers evidence records with chain-of-custody linkage."""

    def __init__(self, db: Database, blobs_dir: Path | None = None) -> None:
        self._db = db
        self._blobs = blobs_dir if blobs_dir is not None else db.path.parent / "blobs"
        self._blobs.mkdir(parents=True, exist_ok=True)

    @property
    def blobs_dir(self) -> Path:
        return self._blobs

    def register(
        self,
        case_id: str,
        *,
        kind: str,
        data: bytes,
        source: str = "",
        note: str = "",
        meta: dict | None = None,
    ) -> EvidenceRecord:
        digest = compute_sha256(data)
        ev_id = f"ev_{uuid.uuid4().hex[:12]}"
        prev = self.head_hash(case_id)
        now = time.time()
        blob_path = self._blob_path(digest)
        if not blob_path.exists():
            blob_path.parent.mkdir(parents=True, exist_ok=True)
            blob_path.write_bytes(data)
        with self._db.transaction():
            self._db.conn.execute(
                "INSERT INTO evidence_records"
                " (id, case_id, kind, sha256, size, created_at, source, note, prev_hash, meta_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ev_id, case_id, kind, digest, len(data), now, source, note,
                    prev, json.dumps(meta or {}, sort_keys=True),
                ),
            )
        return EvidenceRecord(
            id=ev_id, case_id=case_id, kind=kind, sha256=digest, size=len(data),
            created_at=now, source=source, note=note, prev_hash=prev,
            meta=meta or {},
        )

    def _blob_path(self, digest: str) -> Path:
        return self._blobs / digest[:2] / digest

    def head_hash(self, case_id: str) -> str:
        row = self._db.conn.execute(
            "SELECT sha256 FROM evidence_records WHERE case_id = ?"
            " ORDER BY created_at DESC, id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        return row["sha256"] if row else "GENESIS"

    def get(self, case_id: str, ev_id: str) -> EvidenceRecord | None:
        row = self._db.conn.execute(
            "SELECT * FROM evidence_records WHERE case_id = ? AND id = ?",
            (case_id, ev_id),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def list_records(self, case_id: str) -> list[EvidenceRecord]:
        rows = self._db.conn.execute(
            "SELECT * FROM evidence_records WHERE case_id = ? ORDER BY created_at, id",
            (case_id,),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def read_bytes(self, record: EvidenceRecord) -> bytes:
        path = self._blob_path(record.sha256)
        if not path.exists():
            raise EvidenceError(
                f"Missing blob for evidence {record.id}",
                reason=f"Expected content-addressed blob at {path}.",
                action="Restore the blob from backup or re-register the evidence.",
            )
        data = path.read_bytes()
        if compute_sha256(data) != record.sha256:
            raise EvidenceError(
                f"Integrity failure for evidence {record.id}",
                reason="Blob content no longer matches its registered SHA-256.",
                action="Treat the case evidence as compromised and escalate.",
            )
        return data

    def verify_case(self, case_id: str) -> dict:
        """Verify hashes and chain linkage for every record of a case."""
        records = self.list_records(case_id)
        problems: list[str] = []
        expected_prev = "GENESIS"
        for rec in records:
            if rec.prev_hash != expected_prev:
                problems.append(f"{rec.id}: chain break (expected prev {expected_prev[:12]}…, got {rec.prev_hash[:12]}…)")
            expected_prev = rec.sha256
            blob = self._blob_path(rec.sha256)
            if not blob.exists():
                problems.append(f"{rec.id}: blob missing for registered hash")
            elif compute_sha256(blob.read_bytes()) != rec.sha256:
                problems.append(f"{rec.id}: content hash mismatch")
        return {
            "case_id": case_id,
            "records": len(records),
            "chain_ok": not problems,
            "problems": problems,
        }

    @staticmethod
    def _row_to_record(row) -> EvidenceRecord:
        return EvidenceRecord(
            id=row["id"],
            case_id=row["case_id"],
            kind=row["kind"],
            sha256=row["sha256"],
            size=row["size"],
            created_at=row["created_at"],
            source=row["source"],
            note=row["note"],
            prev_hash=row["prev_hash"],
            meta=json.loads(row["meta_json"]),
        )
