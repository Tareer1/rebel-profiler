"""Tests: coverage-driven planning — blind spots become gated proposals.

The vuln-coverage matrix stays honest (validated against the live
AdapterRegistry); coverage_plan() turns only the AVAILABLE rows into
proposals naming live actions and real case subjects, never re-proposes a
covered class, and exposes a ready ``agent run --plan`` payload.
"""

from __future__ import annotations

import pytest

from rebel_profiler.execution.broker import AdapterRegistry
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.intel.vulncov import URL_TARGET_ACTIONS, coverage_for_case, coverage_plan


def _live_actions() -> set[str]:
    return set(AdapterRegistry().names())


def _ledger_with_subjects() -> tuple[ClaimLedger, str]:
    """Ledger with one URL + one host subject and one covered class."""
    ledger = ClaimLedger(SourceRegistry())
    case = "covplan"
    ledger.add(case, subject="h1.lab.example.test", kind="ip",
               value="10.0.0.9", source="scan.nmap", method="host-discovery",
               observed_at=1000.0)
    ledger.add(case, subject="https://h1.lab.example.test", kind="web_tech",
               value="nginx", source="scan.web", method="tech-fingerprint",
               observed_at=1000.0)
    return ledger, case


class TestCoveragePlanHonesty:
    def test_every_proposed_action_is_live(self):
        """No fake adapters in the planner either."""
        ledger, case = _ledger_with_subjects()
        plan = coverage_plan(ledger, case)
        live = _live_actions()
        assert plan["proposals"], "a fresh case must have blind spots to propose"
        for p in plan["proposals"]:
            assert p["action"] in live
            assert p["action"] not in p.get("probed", ())

    def test_targets_come_from_case_subjects(self):
        ledger, case = _ledger_with_subjects()
        plan = coverage_plan(ledger, case)
        for p in plan["proposals"]:
            if p["action"] in URL_TARGET_ACTIONS:
                assert p["target"].startswith(("http://", "https://"))
            else:
                assert not p["target"].startswith("http")

    def test_no_duplicate_action_target_pairs(self):
        ledger, case = _ledger_with_subjects()
        plan = coverage_plan(ledger, case)
        keys = [(p["action"], p["target"]) for p in plan["proposals"]]
        assert len(keys) == len(set(keys))

    def test_max_actions_caps_the_plan(self):
        ledger, case = _ledger_with_subjects()
        plan = coverage_plan(ledger, case, max_actions=3)
        assert len(plan["proposals"]) <= 3

    def test_covered_classes_are_not_reproposed(self):
        ledger, case = _ledger_with_subjects()
        # tech-fingerprint already produced claims → tech_exposure is covered
        report = coverage_for_case(ledger, case)
        covered = {r["class"] for r in report["classes"] if r["status"] == "covered"}
        assert "tech_exposure" in covered
        plan = coverage_plan(ledger, case)
        proposed = {p["reason"].split(":", 1)[1] for p in plan["proposals"]
                    if p["reason"].startswith("coverage:")}
        assert not (proposed & covered)

    def test_plan_text_is_parseable_by_the_deterministic_planner(self):
        """The emitted plan_text feeds agent run --plan without edits."""
        from rebel_profiler.cli.main import _parse_plan

        ledger, case = _ledger_with_subjects()
        plan = coverage_plan(ledger, case)
        if not plan["plan_text"]:
            pytest.skip("no host/URL proposals for this fixture")
        proposals = _parse_plan(plan["plan_text"])
        assert proposals
        registry = AdapterRegistry()
        for p in proposals:
            assert registry.get(p.action) is not None

    def test_empty_case_skips_url_classes(self):
        """A case with no URL subjects cannot propose URL actions."""
        ledger = ClaimLedger(SourceRegistry())
        ledger.add("empty1", subject="plain.lab.example.test", kind="ip",
                   value="10.0.0.2", source="scan.nmap", method="host-discovery",
                   observed_at=1000.0)
        plan = coverage_plan(ledger, "empty1")
        for p in plan["proposals"]:
            assert p["action"] not in URL_TARGET_ACTIONS
        for s in plan["skipped"]:
            assert "URL subject" in s["why"] or "host subject" in s["why"]


class TestCliWiring:
    def test_vuln_coverage_has_plan_flag(self):
        from rebel_profiler.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["intel", "vuln-coverage", "c1", "--plan"])
        assert args.plan is True
        assert args.max_plan == 8
        args2 = parser.parse_args(["intel", "vuln-coverage", "c1"])
        assert args2.plan is False

    def test_agent_run_has_coverage_flag(self):
        from rebel_profiler.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["agent", "run", "c1", "audit what you have not covered yet",
                                  "--coverage"])
        assert args.coverage is True
        args2 = parser.parse_args(["agent", "run", "c1", "map example.com"])
        assert args2.coverage is False

    def test_coverage_planner_returns_valid_proposals(self, tmp_path):
        """End to end through the ledger → planner path (no execution)."""
        from rebel_profiler.cli.main import _make_coverage_planner

        ctx_dir = tmp_path / "data"
        ledger = ClaimLedger(SourceRegistry())
        ledger.add("cc1", subject="h1.lab.example.test", kind="ip",
                   value="10.0.0.9", source="scan.nmap", method="host-discovery",
                   observed_at=1000.0)
        # persist the claim so load_from_db sees it
        import sqlite3

        ctx_dir.mkdir(parents=True)
        from rebel_profiler.storage.database import Database

        db = Database(ctx_dir / "case.db")
        db.migrate()
        db.create_case("cov-case", "fixture", case_id="cc1")
        for c in ledger.list("cc1"):
            db.record_claim(
                c.id, "cc1", subject=c.subject, kind=c.kind, value=c.value,
                source=c.source, method=c.method, observed_at=c.observed_at,
                confidence=c.confidence, evidence_id=c.evidence_id,
                state=c.state, notes=c.notes,
            )
        planner = _make_coverage_planner("cc1", db)
        from rebel_profiler.agent import PlannerView

        view = PlannerView("cc1", "audit blind spots", AdapterRegistry())
        proposals = planner(view)
        live = _live_actions()
        assert proposals
        for p in proposals:
            assert p.action in live
        db.close()
