"""SQLite persistence: schema, migrations, case isolation.

Design (PDF 16):
  * One database file per case directory — physical case isolation.
  * Migrations are ordered, versioned and idempotent; schema version is
    recorded in the database itself.
  * All writes go through explicit, tested functions — no ad-hoc SQL from
    callers, and never SQL constructed from LLM output.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

from ..core.errors import StateError, UsageError

CURRENT_SCHEMA_VERSION = 4

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE cases (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            status       TEXT NOT NULL CHECK (status IN
                ('draft','active','suspended','closed')),
            created_at   REAL NOT NULL,
            updated_at   REAL NOT NULL,
            description  TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE scope_entries (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            value      TEXT NOT NULL,
            excluded   INTEGER NOT NULL DEFAULT 0,
            expires_at REAL,
            note       TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE TABLE targets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            canonical  TEXT NOT NULL,
            kind       TEXT NOT NULL,
            first_seen REAL NOT NULL,
            UNIQUE (case_id, canonical, kind)
        );
        CREATE TABLE observations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id      TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            target_id    INTEGER REFERENCES targets(id) ON DELETE SET NULL,
            kind         TEXT NOT NULL,
            value        TEXT NOT NULL,
            confidence   REAL NOT NULL DEFAULT 0.0,
            source       TEXT NOT NULL DEFAULT '',
            method       TEXT NOT NULL DEFAULT '',
            observed_at  REAL NOT NULL,
            evidence_id  TEXT,
            UNIQUE (case_id, kind, value, source, method, observed_at)
        );
        CREATE TABLE evidence_records (
            id          TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            kind        TEXT NOT NULL,
            sha256      TEXT NOT NULL,
            size        INTEGER NOT NULL,
            created_at  REAL NOT NULL,
            source      TEXT NOT NULL DEFAULT '',
            note        TEXT NOT NULL DEFAULT '',
            prev_hash   TEXT NOT NULL DEFAULT '',
            meta_json   TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE audit_events (
            seq        INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    TEXT NOT NULL,
            at         REAL NOT NULL,
            actor      TEXT NOT NULL,
            action     TEXT NOT NULL,
            subject    TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            prev_hash  TEXT NOT NULL DEFAULT '',
            hash       TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE tasks (
            id          TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            workflow    TEXT NOT NULL DEFAULT '',
            capability  TEXT NOT NULL,
            target      TEXT NOT NULL,
            state       TEXT NOT NULL CHECK (state IN
                ('pending','confirmed','approved','running','succeeded','failed','cancelled')),
            risk        TEXT NOT NULL DEFAULT '',
            outcome     TEXT NOT NULL DEFAULT '',
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        );
        CREATE INDEX idx_targets_case ON targets(case_id);
        CREATE INDEX idx_observations_case ON observations(case_id);
        CREATE INDEX idx_evidence_case ON evidence_records(case_id);
        CREATE INDEX idx_audit_case ON audit_events(case_id);
        CREATE INDEX idx_tasks_case ON tasks(case_id);
        """,
    ),
    (
        2,
        """
        CREATE TABLE claims (
            id          TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            subject     TEXT NOT NULL,
            kind        TEXT NOT NULL,
            value       TEXT NOT NULL,
            source      TEXT NOT NULL DEFAULT '',
            method      TEXT NOT NULL DEFAULT '',
            observed_at REAL NOT NULL,
            confidence  REAL NOT NULL DEFAULT 0.0,
            evidence_id TEXT,
            state       TEXT NOT NULL DEFAULT 'open'
                        CHECK (state IN ('open','corroborated','contradicted','stale')),
            notes       TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX idx_claims_case ON claims(case_id);
        CREATE INDEX idx_claims_subject ON claims(case_id, subject);
        """,
    ),
    (
        3,
        """
        CREATE TABLE graph_nodes (
            id          TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            kind        TEXT NOT NULL,
            label       TEXT NOT NULL,
            confidence  REAL NOT NULL DEFAULT 0.0,
            meta_json   TEXT NOT NULL DEFAULT '{}',
            updated_at  REAL NOT NULL,
            UNIQUE (case_id, kind, label)
        );
        CREATE TABLE graph_edges (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            src_id      TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
            relation    TEXT NOT NULL,
            dst_id      TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
            confidence  REAL NOT NULL DEFAULT 0.0,
            meta_json   TEXT NOT NULL DEFAULT '{}',
            updated_at  REAL NOT NULL,
            UNIQUE (case_id, src_id, relation, dst_id)
        );
        CREATE INDEX idx_graph_nodes_case ON graph_nodes(case_id);
        CREATE INDEX idx_graph_edges_case ON graph_edges(case_id);
        CREATE INDEX idx_graph_edges_src ON graph_edges(src_id);
        CREATE INDEX idx_graph_edges_dst ON graph_edges(dst_id);
        """,
    ),
    (
        4,
        """
        CREATE TABLE case_members (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            subject    TEXT NOT NULL,
            role       TEXT NOT NULL CHECK (role IN ('owner','operator','viewer')),
            created_at REAL NOT NULL,
            UNIQUE (case_id, subject)
        );
        CREATE INDEX idx_members_case ON case_members(case_id);
        CREATE TABLE approvals (
            id          TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            task_id     TEXT NOT NULL,
            action      TEXT NOT NULL,
            target      TEXT NOT NULL,
            risk        TEXT NOT NULL DEFAULT '',
            reasons     TEXT NOT NULL DEFAULT '',
            requested_by TEXT NOT NULL DEFAULT 'operator',
            state       TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending','approved','denied','cancelled')),
            decided_by  TEXT NOT NULL DEFAULT '',
            decided_at  REAL,
            created_at  REAL NOT NULL
        );
        CREATE INDEX idx_approvals_case ON approvals(case_id);
        CREATE INDEX idx_approvals_state ON approvals(case_id, state);
        CREATE TABLE hypotheses (
            id          TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            statement   TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','supported','refuted','untestable')),
            rationale   TEXT NOT NULL DEFAULT '',
            criteria_json TEXT NOT NULL DEFAULT '[]',
            result_json TEXT NOT NULL DEFAULT '{}',
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        );
        CREATE INDEX idx_hypotheses_case ON hypotheses(case_id);
        CREATE TABLE workflows (
            id          TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            name        TEXT NOT NULL,
            spec_json   TEXT NOT NULL,
            state       TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending','running','paused','completed','failed','cancelled')),
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        );
        CREATE INDEX idx_workflows_case ON workflows(case_id);
        CREATE TABLE workflow_steps (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id      TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            workflow_id  TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
            step_key     TEXT NOT NULL,
            kind         TEXT NOT NULL,
            spec_json    TEXT NOT NULL,
            state        TEXT NOT NULL DEFAULT 'pending'
                         CHECK (state IN ('pending','ready','running','succeeded','failed','skipped','blocked','awaiting_approval','cancelled')),
            outcome      TEXT NOT NULL DEFAULT '',
            detail_json  TEXT NOT NULL DEFAULT '{}',
            attempt      INTEGER NOT NULL DEFAULT 0,
            started_at   REAL,
            finished_at  REAL,
            UNIQUE (workflow_id, step_key)
        );
        CREATE INDEX idx_workflow_steps_wf ON workflow_steps(workflow_id);
        CREATE TABLE schedules (
            id           TEXT PRIMARY KEY,
            case_id      TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            workflow_id  TEXT,
            action       TEXT NOT NULL,
            target       TEXT NOT NULL,
            params_json  TEXT NOT NULL DEFAULT '{}',
            cron         TEXT NOT NULL DEFAULT '',
            not_before   REAL,
            not_after    REAL,
            state        TEXT NOT NULL DEFAULT 'active'
                         CHECK (state IN ('active','paused','expired','cancelled')),
            last_run_at  REAL,
            last_state   TEXT NOT NULL DEFAULT '',
            next_due_at  REAL,
            created_at   REAL NOT NULL
        );
        CREATE INDEX idx_schedules_case ON schedules(case_id);
        CREATE TABLE search_index (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id   TEXT NOT NULL,
            title       TEXT NOT NULL DEFAULT '',
            body        TEXT NOT NULL DEFAULT '',
            ts          TEXT NOT NULL DEFAULT '',
            UNIQUE (case_id, entity_type, entity_id)
        );
        CREATE INDEX idx_search_case ON search_index(case_id);
        CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
            title, body, case_id UNINDEXED, entity_type UNINDEXED, entity_id UNINDEXED
        );
        """,
    ),
)


class Database:
    """A per-case (or per-workspace) SQLite store with migrations applied."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = FULL")

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    # -- migrations ----------------------------------------------------------

    def migrate(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        current = self.schema_version()
        for version, sql in MIGRATIONS:
            if version > current:
                with self._conn:
                    self._conn.executescript(sql)
                self._conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)"
                    " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    (str(version),),
                )
                self._conn.commit()

    def schema_version(self) -> int:
        try:
            row = self._conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.OperationalError:
            return 0
        return int(row["value"]) if row else 0

    # -- cases ---------------------------------------------------------------

    def create_case(self, name: str, description: str = "", *, case_id: str | None = None) -> str:
        case_id = case_id or uuid.uuid4().hex[:12]
        now = time.time()
        with self._conn:
            self._conn.execute(
                "INSERT INTO cases (id, name, status, created_at, updated_at, description)"
                " VALUES (?, ?, 'draft', ?, ?, ?)",
                (case_id, name, now, now, description),
            )
        return case_id

    def get_case(self, case_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM cases WHERE id = ?", (case_id,)
        ).fetchone()

    def list_cases(self) -> list[sqlite3.Row]:
        return list(
            self._conn.execute("SELECT * FROM cases ORDER BY created_at")
        )

    def set_case_status(self, case_id: str, status: str) -> None:
        if status not in {"draft", "active", "suspended", "closed"}:
            raise UsageError(f"Unknown case status '{status}'")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
                (status, time.time(), case_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Case {case_id} not found")

    # -- scope ---------------------------------------------------------------

    def add_scope_entry(
        self,
        case_id: str,
        value: str,
        *,
        excluded: bool = False,
        expires_at: float | None = None,
        note: str = "",
    ) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO scope_entries (case_id, value, excluded, expires_at, note, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (case_id, value, int(excluded), expires_at, note, time.time()),
            )
        return cur.lastrowid

    def scope_entries(self, case_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM scope_entries WHERE case_id = ? ORDER BY id",
                (case_id,),
            )
        )

    # -- targets & observations ------------------------------------------------

    def record_target(self, case_id: str, canonical: str, kind: str) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO targets (case_id, canonical, kind, first_seen)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT (case_id, canonical, kind) DO NOTHING",
                (case_id, canonical, kind, time.time()),
            )
            if cur.lastrowid:
                return cur.lastrowid
        row = self._conn.execute(
            "SELECT id FROM targets WHERE case_id = ? AND canonical = ? AND kind = ?",
            (case_id, canonical, kind),
        ).fetchone()
        return int(row["id"])

    def record_observation(
        self,
        case_id: str,
        kind: str,
        value: str,
        *,
        target_id: int | None = None,
        confidence: float = 0.0,
        source: str = "",
        method: str = "",
        evidence_id: str | None = None,
        observed_at: float | None = None,
    ) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO observations (case_id, target_id, kind, value, confidence,"
                " source, method, observed_at, evidence_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (case_id, kind, value, source, method, observed_at) DO NOTHING",
                (
                    case_id,
                    target_id,
                    kind,
                    value,
                    confidence,
                    source,
                    method,
                    observed_at if observed_at is not None else time.time(),
                    evidence_id,
                ),
            )
            if cur.lastrowid:
                return cur.lastrowid
        row = self._conn.execute(
            "SELECT id FROM observations WHERE case_id = ? AND kind = ? AND value = ?"
            " AND source = ? AND method = ? AND observed_at = ?",
            (case_id, kind, value, source, method, observed_at if observed_at is not None else time.time()),
        ).fetchone()
        return int(row["id"])

    def observations_for(self, case_id: str, target_id: int | None = None) -> list[sqlite3.Row]:
        if target_id is None:
            return list(
                self._conn.execute(
                    "SELECT * FROM observations WHERE case_id = ? ORDER BY observed_at",
                    (case_id,),
                )
            )
        return list(
            self._conn.execute(
                "SELECT * FROM observations WHERE case_id = ? AND target_id = ? ORDER BY observed_at",
                (case_id, target_id),
            )
        )

    # -- tasks -----------------------------------------------------------------

    def record_task(
        self,
        task_id: str,
        case_id: str,
        capability: str,
        target: str,
        *,
        workflow: str = "",
        risk: str = "",
        state: str = "pending",
    ) -> None:
        now = time.time()
        with self._conn:
            self._conn.execute(
                "INSERT INTO tasks (id, case_id, workflow, capability, target, state, risk, outcome, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?)"
                " ON CONFLICT (id) DO UPDATE SET state = excluded.state,"
                " risk = excluded.risk, updated_at = excluded.updated_at",
                (task_id, case_id, workflow, capability, target, state, risk, now, now),
            )

    def set_task_state(self, task_id: str, state: str, outcome: str = "") -> None:
        if state not in {
            "pending", "confirmed", "approved", "running", "succeeded", "failed", "cancelled",
        }:
            raise UsageError(f"Unknown task state '{state}'")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE tasks SET state = ?, outcome = ?, updated_at = ? WHERE id = ?",
                (state, outcome, time.time(), task_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Task {task_id} not found")

    def get_task(self, task_id: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()

    # -- claims ------------------------------------------------------------------

    def record_claim(
        self,
        claim_id: str,
        case_id: str,
        *,
        subject: str,
        kind: str,
        value: str,
        source: str = "",
        method: str = "",
        observed_at: float,
        confidence: float = 0.0,
        evidence_id: str | None = None,
        state: str = "open",
        notes: str = "",
    ) -> None:
        if state not in {"open", "corroborated", "contradicted", "stale"}:
            raise UsageError(f"Unknown claim state '{state}'")
        with self._conn:
            self._conn.execute(
                "INSERT INTO claims (id, case_id, subject, kind, value, source, method,"
                " observed_at, confidence, evidence_id, state, notes)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (id) DO UPDATE SET state = excluded.state,"
                " confidence = excluded.confidence, notes = excluded.notes",
                (
                    claim_id, case_id, subject, kind, value, source, method,
                    observed_at, confidence, evidence_id, state, notes,
                ),
            )

    def set_claim_state(self, claim_id: str, state: str) -> None:
        if state not in {"open", "corroborated", "contradicted", "stale"}:
            raise UsageError(f"Unknown claim state '{state}'")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE claims SET state = ? WHERE id = ?", (state, claim_id)
            )
        if cur.rowcount == 0:
            raise StateError(f"Claim {claim_id} not found")

    def claims_for(self, case_id: str, subject: str | None = None) -> list[sqlite3.Row]:
        if subject is None:
            return list(
                self._conn.execute(
                    "SELECT * FROM claims WHERE case_id = ? ORDER BY subject, kind, confidence DESC",
                    (case_id,),
                )
            )
        return list(
            self._conn.execute(
                "SELECT * FROM claims WHERE case_id = ? AND subject = ?"
                " ORDER BY kind, confidence DESC",
                (case_id, subject.strip().lower()),
            )
        )

    # -- relationship graph (migration v3) ---------------------------------------

    def upsert_graph_node(
        self,
        node_id: str,
        case_id: str,
        *,
        kind: str,
        label: str,
        confidence: float = 0.0,
        meta: dict | None = None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO graph_nodes (id, case_id, kind, label, confidence, meta_json, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (id) DO UPDATE SET confidence = MAX(confidence, excluded.confidence),"
                " meta_json = excluded.meta_json, updated_at = excluded.updated_at",
                (node_id, case_id, kind, label, confidence,
                 json.dumps(meta or {}, sort_keys=True), time.time()),
            )

    def upsert_graph_edge(
        self,
        case_id: str,
        *,
        src_id: str,
        relation: str,
        dst_id: str,
        confidence: float = 0.0,
        meta: dict | None = None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO graph_edges (case_id, src_id, relation, dst_id, confidence, meta_json, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (case_id, src_id, relation, dst_id) DO UPDATE SET"
                " confidence = MAX(confidence, excluded.confidence), updated_at = excluded.updated_at",
                (case_id, src_id, relation, dst_id, confidence,
                 json.dumps(meta or {}, sort_keys=True), time.time()),
            )

    def graph_nodes(self, case_id: str, kind: str | None = None) -> list[sqlite3.Row]:
        if kind is None:
            return list(self._conn.execute(
                "SELECT * FROM graph_nodes WHERE case_id = ? ORDER BY kind, label",
                (case_id,),
            ))
        return list(self._conn.execute(
            "SELECT * FROM graph_nodes WHERE case_id = ? AND kind = ? ORDER BY label",
            (case_id, kind),
        ))

    def graph_edges(self, case_id: str) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM graph_edges WHERE case_id = ? ORDER BY src_id, relation, dst_id",
            (case_id,),
        ))

    def graph_neighbors(
        self, case_id: str, node_id: str, relation: str | None = None, *,
        direction: str = "out",
    ) -> list[sqlite3.Row]:
        if direction == "out":
            sql = ("SELECT e.relation, n.* FROM graph_edges e"
                   " JOIN graph_nodes n ON n.id = e.dst_id"
                   " WHERE e.case_id = ? AND e.src_id = ?")
        else:
            sql = ("SELECT e.relation, n.* FROM graph_edges e"
                   " JOIN graph_nodes n ON n.id = e.src_id"
                   " WHERE e.case_id = ? AND e.dst_id = ?")
        params: list = [case_id, node_id]
        if relation is not None:
            sql += " AND e.relation = ?"
            params.append(relation)
        return list(self._conn.execute(sql, params))

    def clear_graph(self, case_id: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM graph_edges WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM graph_nodes WHERE case_id = ?", (case_id,))

    # -- case membership (RBAC, migration v4) --------------------------------------

    def add_member(self, case_id: str, subject: str, role: str, *, created_at: float | None = None) -> int:
        if role not in {"owner", "operator", "viewer"}:
            raise UsageError(f"Unknown member role '{role}'")
        subject = subject.strip().lower()
        if not subject:
            raise UsageError("Member subject must be a non-empty identifier")
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO case_members (case_id, subject, role, created_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT (case_id, subject) DO UPDATE SET role = excluded.role",
                (case_id, subject, role, created_at if created_at is not None else time.time()),
            )
        return int(cur.lastrowid)

    def remove_member(self, case_id: str, subject: str) -> None:
        subject = subject.strip().lower()
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM case_members WHERE case_id = ? AND subject = ?",
                (case_id, subject),
            )
        if cur.rowcount == 0:
            raise StateError(f"Member '{subject}' not found in case {case_id}")

    def members(self, case_id: str) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM case_members WHERE case_id = ? ORDER BY role, subject",
            (case_id,),
        ))

    def member_role(self, case_id: str, subject: str) -> str:
        row = self._conn.execute(
            "SELECT role FROM case_members WHERE case_id = ? AND subject = ?",
            (case_id, subject.strip().lower()),
        ).fetchone()
        return row["role"] if row else ""

    def has_owner(self, case_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM case_members WHERE case_id = ? AND role = 'owner' LIMIT 1",
            (case_id,),
        ).fetchone()
        return row is not None

    # -- approvals queue (migration v4) ---------------------------------------------

    def record_approval(
        self,
        approval_id: str,
        case_id: str,
        *,
        task_id: str,
        action: str,
        target: str,
        risk: str = "",
        reasons: str = "",
        requested_by: str = "operator",
        created_at: float | None = None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO approvals (id, case_id, task_id, action, target, risk,"
                " reasons, requested_by, state, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
                (approval_id, case_id, task_id, action, target, risk, reasons,
                 requested_by, created_at if created_at is not None else time.time()),
            )

    def get_approval(self, approval_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,),
        ).fetchone()

    def find_pending_approval_by_task(self, task_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM approvals WHERE task_id = ? AND state = 'pending'"
            " ORDER BY created_at DESC LIMIT 1",
            (task_id,),
        ).fetchone()

    def approvals_for(self, case_id: str, state: str | None = None) -> list[sqlite3.Row]:
        if state is None:
            return list(self._conn.execute(
                "SELECT * FROM approvals WHERE case_id = ? ORDER BY created_at",
                (case_id,),
            ))
        if state not in {"pending", "approved", "denied", "cancelled"}:
            raise UsageError(f"Unknown approval state '{state}'")
        return list(self._conn.execute(
            "SELECT * FROM approvals WHERE case_id = ? AND state = ? ORDER BY created_at",
            (case_id, state),
        ))

    def set_approval_state(
        self, approval_id: str, state: str, *, decided_by: str = "", decided_at: float | None = None,
    ) -> None:
        if state not in {"pending", "approved", "denied", "cancelled"}:
            raise UsageError(f"Unknown approval state '{state}'")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE approvals SET state = ?, decided_by = ?, decided_at = ? WHERE id = ?",
                (state, decided_by, decided_at if decided_at is not None else time.time(), approval_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Approval {approval_id} not found")

    # -- hypotheses (migration v4) -----------------------------------------------------

    def add_hypothesis(
        self,
        hyp_id: str,
        case_id: str,
        *,
        statement: str,
        rationale: str = "",
        criteria: list[dict] | None = None,
        created_at: float | None = None,
    ) -> None:
        now = created_at if created_at is not None else time.time()
        with self._conn:
            self._conn.execute(
                "INSERT INTO hypotheses (id, case_id, statement, status, rationale,"
                " criteria_json, result_json, created_at, updated_at)"
                " VALUES (?, ?, ?, 'open', ?, ?, '{}', ?, ?)",
                (hyp_id, case_id, statement, rationale,
                 json.dumps(criteria or [], sort_keys=True), now, now),
            )

    def get_hypothesis(self, hyp_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM hypotheses WHERE id = ?", (hyp_id,),
        ).fetchone()

    def hypotheses_for(self, case_id: str) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM hypotheses WHERE case_id = ? ORDER BY created_at",
            (case_id,),
        ))

    def set_hypothesis_status(self, hyp_id: str, status: str) -> None:
        if status not in {"open", "supported", "refuted", "untestable"}:
            raise UsageError(f"Unknown hypothesis status '{status}'")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE hypotheses SET status = ?, updated_at = ? WHERE id = ?",
                (status, time.time(), hyp_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Hypothesis {hyp_id} not found")

    def set_hypothesis_result(self, hyp_id: str, result: dict) -> None:
        with self._conn:
            cur = self._conn.execute(
                "UPDATE hypotheses SET result_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(result, sort_keys=True), time.time(), hyp_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Hypothesis {hyp_id} not found")

    # -- workflows (migration v4) --------------------------------------------------------

    def record_workflow(
        self,
        wf_id: str,
        case_id: str,
        *,
        name: str,
        spec: dict,
        state: str = "pending",
        created_at: float | None = None,
    ) -> None:
        if state not in {"pending", "running", "paused", "completed", "failed", "cancelled"}:
            raise UsageError(f"Unknown workflow state '{state}'")
        now = created_at if created_at is not None else time.time()
        with self._conn:
            self._conn.execute(
                "INSERT INTO workflows (id, case_id, name, spec_json, state, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (wf_id, case_id, name, json.dumps(spec, sort_keys=True), state, now, now),
            )

    def get_workflow(self, wf_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM workflows WHERE id = ?", (wf_id,),
        ).fetchone()

    def workflows_for(self, case_id: str) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM workflows WHERE case_id = ? ORDER BY created_at",
            (case_id,),
        ))

    def set_workflow_state(self, wf_id: str, state: str) -> None:
        if state not in {"pending", "running", "paused", "completed", "failed", "cancelled"}:
            raise UsageError(f"Unknown workflow state '{state}'")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE workflows SET state = ?, updated_at = ? WHERE id = ?",
                (state, time.time(), wf_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Workflow {wf_id} not found")

    def record_workflow_step(
        self,
        case_id: str,
        workflow_id: str,
        step_key: str,
        *,
        kind: str,
        spec: dict,
        state: str = "pending",
    ) -> None:
        if state not in {"pending", "ready", "running", "succeeded", "failed",
                         "skipped", "blocked", "awaiting_approval", "cancelled"}:
            raise UsageError(f"Unknown workflow step state '{state}'")
        with self._conn:
            self._conn.execute(
                "INSERT INTO workflow_steps (case_id, workflow_id, step_key, kind,"
                " spec_json, state) VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (workflow_id, step_key) DO UPDATE SET"
                " kind = excluded.kind, spec_json = excluded.spec_json",
                (case_id, workflow_id, step_key, kind,
                 json.dumps(spec, sort_keys=True), state),
            )

    def workflow_steps(self, workflow_id: str) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM workflow_steps WHERE workflow_id = ? ORDER BY id",
            (workflow_id,),
        ))

    def get_workflow_step(self, workflow_id: str, step_key: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM workflow_steps WHERE workflow_id = ? AND step_key = ?",
            (workflow_id, step_key),
        ).fetchone()

    def set_workflow_step_state(
        self, workflow_id: str, step_key: str, state: str, *,
        outcome: str = "", detail: dict | None = None, attempt: int | None = None,
    ) -> None:
        if state not in {"pending", "ready", "running", "succeeded", "failed",
                         "skipped", "blocked", "awaiting_approval", "cancelled"}:
            raise UsageError(f"Unknown workflow step state '{state}'")
        sets = ["state = ?", "outcome = ?", "detail_json = ?"]
        params: list = [state, outcome, json.dumps(detail or {}, sort_keys=True)]
        if attempt is not None:
            sets.append("attempt = ?")
            params.append(attempt)
        if state == "running":
            sets.append("started_at = ?")
            params.append(time.time())
        if state in {"succeeded", "failed", "skipped", "cancelled"}:
            sets.append("finished_at = ?")
            params.append(time.time())
        params.extend([workflow_id, step_key])
        with self._conn:
            cur = self._conn.execute(
                f"UPDATE workflow_steps SET {', '.join(sets)}"
                " WHERE workflow_id = ? AND step_key = ?",
                params,
            )
        if cur.rowcount == 0:
            raise StateError(f"Workflow step {workflow_id}/{step_key} not found")

    # -- schedules (migration v4) ----------------------------------------------------------

    def record_schedule(
        self,
        sched_id: str,
        case_id: str,
        *,
        action: str,
        target: str,
        params: dict | None = None,
        workflow_id: str = "",
        cron: str = "",
        not_before: float | None = None,
        not_after: float | None = None,
        next_due_at: float | None = None,
        created_at: float | None = None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO schedules (id, case_id, workflow_id, action, target,"
                " params_json, cron, not_before, not_after, state, next_due_at, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (sched_id, case_id, workflow_id, action, target,
                 json.dumps(params or {}, sort_keys=True), cron, not_before, not_after,
                 next_due_at, created_at if created_at is not None else time.time()),
            )

    def get_schedule(self, sched_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM schedules WHERE id = ?", (sched_id,),
        ).fetchone()

    def schedules_for(self, case_id: str, state: str | None = None) -> list[sqlite3.Row]:
        if state is None:
            return list(self._conn.execute(
                "SELECT * FROM schedules WHERE case_id = ? ORDER BY created_at",
                (case_id,),
            ))
        if state not in {"active", "paused", "expired", "cancelled"}:
            raise UsageError(f"Unknown schedule state '{state}'")
        return list(self._conn.execute(
            "SELECT * FROM schedules WHERE case_id = ? AND state = ? ORDER BY created_at",
            (case_id, state),
        ))

    def active_schedules(self) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM schedules WHERE state = 'active' ORDER BY next_due_at",
        ))

    def set_schedule_state(self, sched_id: str, state: str) -> None:
        if state not in {"active", "paused", "expired", "cancelled"}:
            raise UsageError(f"Unknown schedule state '{state}'")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE schedules SET state = ? WHERE id = ?", (state, sched_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Schedule {sched_id} not found")

    def set_schedule_run(
        self, sched_id: str, *, last_run_at: float, last_state: str, next_due_at: float | None,
    ) -> None:
        with self._conn:
            cur = self._conn.execute(
                "UPDATE schedules SET last_run_at = ?, last_state = ?, next_due_at = ?"
                " WHERE id = ?",
                (last_run_at, last_state, next_due_at, sched_id),
            )
        if cur.rowcount == 0:
            raise StateError(f"Schedule {sched_id} not found")

    # -- search index (migration v4) --------------------------------------------------------

    def index_search_doc(
        self,
        case_id: str,
        entity_type: str,
        entity_id: str,
        *,
        title: str = "",
        body: str = "",
        ts: str = "",
    ) -> None:
        doc = (title, body, case_id, entity_type, entity_id)
        with self._conn:
            self._conn.execute(
                "INSERT INTO search_index (case_id, entity_type, entity_id, title, body, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (case_id, entity_type, entity_id) DO UPDATE SET"
                " title = excluded.title, body = excluded.body, ts = excluded.ts",
                (case_id, entity_type, entity_id, title, body, ts),
            )
            self._conn.execute(
                "DELETE FROM search_fts WHERE entity_id = ? AND case_id = ?"
                " AND entity_type = ?",
                (entity_id, case_id, entity_type),
            )
            self._conn.execute(
                "INSERT INTO search_fts (title, body, case_id, entity_type, entity_id)"
                " VALUES (?, ?, ?, ?, ?)",
                doc,
            )

    def search_docs(self, case_id: str, query: str, *, limit: int = 50) -> list[dict]:
        """Search via FTS5, falling back to LIKE when FTS is unavailable."""
        query = query.strip()
        if not query:
            return []
        results: list[dict] = []
        try:
            rows = self._conn.execute(
                "SELECT case_id, entity_type, entity_id, title, body FROM search_fts"
                " WHERE search_fts MATCH ? AND search_fts.case_id = ?"
                " ORDER BY rank LIMIT ?",
                (query, case_id, limit),
            ).fetchall()
            fts_ok = True
        except sqlite3.OperationalError:
            fts_ok = False
        if not fts_ok:
            like = f"%{query}%"
            rows = self._conn.execute(
                "SELECT case_id, entity_type, entity_id, title, body FROM search_index"
                " WHERE case_id = ? AND (title LIKE ? OR body LIKE ?) LIMIT ?",
                (case_id, like, like, limit),
            ).fetchall()
        for row in rows:
            results.append({
                "case_id": row["case_id"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "title": row["title"],
                "body": row["body"][:300],
            })
        return results

    def rebuild_search_index(self, case_id: str) -> int:
        """Deterministic rebuild of the search docs for one case from claims."""
        count = 0
        for row in self.claims_for(case_id):
            self.index_search_doc(
                case_id, "claim", row["id"],
                title=f"{row['subject']} {row['kind']}",
                body=f"{row['kind']} {row['value']} source={row['source']}"
                     f" method={row['method']} notes={row['notes']}",
                ts=str(row["observed_at"]),
            )
            count += 1
        for row in self.observations_for(case_id):
            self.index_search_doc(
                case_id, "observation", str(row["id"]),
                title=f"{row['kind']}",
                body=f"{row['kind']} {row['value']} source={row['source']}",
                ts=str(row["observed_at"]),
            )
            count += 1
        return count

    def clear_search_index(self, case_id: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM search_index WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM search_fts WHERE case_id = ?", (case_id,))

    # -- generic JSON helper ------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES (?, ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def delete_meta(self, key: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM schema_meta WHERE key = ?", (key,))

    def iter_meta(self) -> list[tuple[str, str]]:
        rows = self._conn.execute(
            "SELECT key, value FROM schema_meta ORDER BY key"
        ).fetchall()
        return [(row["key"], row["value"]) for row in rows]
