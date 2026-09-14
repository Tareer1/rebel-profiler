"""CLI application context: config, workspace index, per-case stores."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from ..core.config import get, load_config
from ..core.errors import ConfigError, StateError, UsageError
from ..evidence.audit import AuditChain
from ..evidence.store import EvidenceStore
from ..execution.broker import ExecutionBroker
from ..security.scope import Scope, ScopeEngine, ScopeStatus
from ..storage.database import Database

DEFAULT_DATA_DIR = Path.home() / ".local/share/rebel-profiler"
INDEX_FILE = "index.json"


class AppContext:
    """Holds resolved configuration and provides workspace accessors."""

    def __init__(self, *, data_dir: Path | None = None, assume_yes: bool = False,
                 actor: str | None = None, rbac_enabled: bool = False,
                 queue_on_approval_refusal: bool = False) -> None:
        self.config = load_config()
        configured = get(self.config, "paths.data_dir", str(DEFAULT_DATA_DIR))
        self.data_dir = Path(data_dir if data_dir is not None else configured).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.assume_yes = assume_yes
        self._actor = actor
        self.rbac_enabled = rbac_enabled
        self.queue_on_approval_refusal = queue_on_approval_refusal

    # -- index ---------------------------------------------------------------

    @property
    def index_path(self) -> Path:
        return self.data_dir / INDEX_FILE

    def _load_index(self) -> dict:
        if not self.index_path.exists():
            return {"cases": []}
        try:
            return json.loads(self.index_path.read_text())
        except json.JSONDecodeError as exc:
            raise StateError(
                "Workspace index is corrupt",
                reason=f"{self.index_path} is not valid JSON: {exc}",
                action="Restore the index from backup or re-create the case registry.",
            ) from exc

    def _save_index(self, index: dict) -> None:
        self.index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")

    # -- cases -----------------------------------------------------------------

    def case_dir(self, case_id: str) -> Path:
        return self.data_dir / "cases" / case_id

    def create_case(self, name: str, description: str = "") -> dict:
        record = {
            "id": _new_case_id(),
            "name": name,
            "status": "draft",
            "created_at": time.time(),
            "description": description,
        }
        db = self.open_case(record["id"])
        db.create_case(name, description, case_id=record["id"])
        db.close()
        index = self._load_index()
        index["cases"].append(record)
        self._save_index(index)
        return record

    def list_cases(self) -> list[dict]:
        return sorted(self._load_index()["cases"], key=lambda c: c["created_at"])

    def find_case(self, case_id: str) -> dict:
        for rec in self.list_cases():
            if rec["id"] == case_id or rec["id"].startswith(case_id):
                return rec
        raise UsageError(
            f"Case '{case_id}' not found",
            reason="No case with this id exists in the workspace.",
            action="List cases with: rebel-profiler case list",
        )

    def set_case_status(self, case_id: str, status: str) -> dict:
        rec = self.find_case(case_id)
        index = self._load_index()
        for r in index["cases"]:
            if r["id"] == rec["id"]:
                r["status"] = status
        self._save_index(index)
        db = self.open_case(rec["id"])
        db.set_case_status(rec["id"], status)
        db.close()
        rec["status"] = status
        return rec

    # -- stores -----------------------------------------------------------------

    def open_case(self, case_id: str) -> Database:
        cdir = self.case_dir(case_id)
        cdir.mkdir(parents=True, exist_ok=True)
        db = Database(cdir / "case.db")
        db.migrate()
        return db

    def scope_engine(self) -> ScopeEngine:
        """Build the scope engine from the workspace index (fail closed)."""
        engine = ScopeEngine()
        for rec in self.list_cases():
            scope = Scope(case_id=rec["id"], status=ScopeStatus(rec["status"]))
            db = self.open_case(rec["id"])
            for row in db.scope_entries(rec["id"]):
                expires = row["expires_at"]
                scope.add(
                    row["value"],
                    excluded=bool(row["excluded"]),
                    expires_at=None if expires is None else _from_ts(expires),
                    note=row["note"],
                )
            db.close()
            engine.register(scope)
        return engine

    # -- broker --------------------------------------------------------------------

    def evidence_store(self, db: Database, case_id: str) -> EvidenceStore:
        return EvidenceStore(db, blobs_dir=self.case_dir(case_id) / "blobs")

    def broker(self, db: Database) -> ExecutionBroker:
        audit = AuditChain(db)
        evidence = EvidenceStore(db, blobs_dir=self.case_dir(str(db.path.parent.name)) / "blobs")
        role_engine = None
        if self.rbac_enabled:
            from ..security.rbac import RoleEngine

            role_engine = RoleEngine(db)
        return ExecutionBroker(
            db, scope_engine=self.scope_engine(), evidence=evidence, audit=audit,
            confirm=self._interactive_confirm,
            approve=self._interactive_approve,
            queue_on_approval_refusal=self.queue_on_approval_refusal,
            role_engine=role_engine,
        )

    @property
    def actor(self) -> str:
        """The acting subject: --actor flag or RP_ACTOR env (default operator)."""
        import os

        return self._actor or os.environ.get("RP_ACTOR", "operator")

    # -- interactive gates ---------------------------------------------------------------

    def _interactive_confirm(self, request, gate) -> bool:
        if self.assume_yes:
            return True
        if not sys.stdin.isatty():
            return False
        print(f"\nPolicy requires CONFIRMATION for '{request.action}' on '{request.target}' "
              f"(risk: {gate.decision.risk.level}).")
        answer = input("Proceed? [y/N] ").strip().lower()
        return answer in {"y", "yes"}

    def _interactive_approve(self, request, gate) -> bool:
        if self.assume_yes:
            return True
        if not sys.stdin.isatty():
            return False
        print(f"\nPolicy requires APPROVAL for '{request.action}' on '{request.target}' "
              f"(risk: {gate.decision.risk.level}).")
        print("Reasons: " + "; ".join(gate.decision.reasons))
        answer = input("Approve execution? [y/N] ").strip().lower()
        return answer in {"y", "yes"}


def _new_case_id() -> str:
    import uuid

    return uuid.uuid4().hex[:12]


def _from_ts(ts: float):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, tz=timezone.utc)
