"""Execution broker: the single controlled path from plan to action.

The broker accepts *structured action requests* — never raw commands. Every
request passes through the full gate sequence before any external tooling is
touched:

  1. Case and scope validation (security/scope.py — fail closed)
  2. Risk classification (security/risk.py — versioned, deterministic)
  3. Policy decision (security/policy.py — allow / confirm / approve / deny)
  4. Confirmation/approval collection (interactive or supplied callbacks)
  5. Structured, argument-validated execution via a registered adapter
  6. Evidence registration + audit chain append for everything that happened

The LLM may construct action requests. It can never bypass the gates, and
there is no API here that executes a raw shell string.
"""

from __future__ import annotations

import shlex
import uuid
from dataclasses import dataclass, field
from typing import Callable

from ..core.errors import (
    DependencyUnavailableError,
    PermissionDeniedError,
    ScopeViolationError,
    UsageError,
)
from ..core.redact import redact
from ..evidence.audit import AuditChain
from ..evidence.store import EvidenceStore
from ..security.policy import PolicyDecision, PolicyEngine, PolicyOutcome
from ..security.risk import RiskEngine
from ..security.scope import ScopeEngine
from ..storage.database import Database


@dataclass(frozen=True)
class ActionRequest:
    """A structured request to run one capability against one target."""

    case_id: str
    capability: str            # capability class, e.g. "discovery"
    action: str                # action name, e.g. "port-scan"
    target: str                # target the action will touch
    params: dict = field(default_factory=dict)
    requested_by: str = "operator"
    reason: str = ""

    def validate(self) -> None:
        if not self.case_id or not self.action or not self.target:
            raise UsageError(
                "ActionRequest requires case_id, action and target",
                reason="Incomplete structured request.",
                action="Construct the request with all required fields.",
            )
        if not isinstance(self.params, dict):
            raise UsageError("ActionRequest params must be a dict")


@dataclass
class GateResult:
    decision: PolicyDecision
    scope_status: str
    task_id: str
    state: str                 # pending | confirmed | approved | denied


@dataclass
class ExecutionResult:
    task_id: str
    action: str
    target: str
    outcome: str               # succeeded | failed | denied
    returncode: int | None
    stdout: str
    stderr: str
    evidence_id: str | None
    decision: PolicyDecision

    def as_dict(self, *, redacted: bool = True) -> dict:
        out = {
            "task_id": self.task_id,
            "action": self.action,
            "target": self.target,
            "outcome": self.outcome,
            "returncode": self.returncode,
            "evidence_id": self.evidence_id,
            "policy_outcome": self.decision.outcome.value,
            "risk": self.decision.risk.level,
        }
        if redacted:
            out["stdout"] = redact(self.stdout)
            out["stderr"] = redact(self.stderr)
        else:
            out["stdout"] = self.stdout
            out["stderr"] = self.stderr
        return out


# -- adapters ------------------------------------------------------------------


class Adapter:
    """Base class for structured tool adapters.

    An adapter declares the exact arguments it accepts; the broker validates
    the request params against this contract before execution. Adapters never
    receive free-form strings from the planner.
    """

    name: str = ""
    binary: str = ""
    capability_class: str = ""

    allowed_params: tuple[str, ...] = ()
    required_params: tuple[str, ...] = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        raise NotImplementedError

    def validate_params(self, request: ActionRequest) -> None:
        unknown = set(request.params) - set(self.allowed_params)
        if unknown:
            raise UsageError(
                f"Adapter '{self.name}' does not accept params: {sorted(unknown)}",
                reason="Structured actions may only use declared parameters.",
                action=f"Allowed params: {', '.join(self.allowed_params)}",
            )
        missing = set(self.required_params) - set(request.params)
        if missing:
            raise UsageError(
                f"Adapter '{self.name}' missing required params: {sorted(missing)}",
                reason="The action contract requires these parameters.",
                action=f"Supply: {', '.join(self.required_params)}",
            )


class EchoAdapter(Adapter):
    """Reference adapter for tests and demos; produces deterministic output."""

    name = "echo"
    binary = "echo"
    capability_class = "info"
    allowed_params = ("message",)
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        message = str(request.params.get("message", "rebel-profiler"))
        return [self.binary, message]


class PassiveDnsAdapter(Adapter):
    """DNS record collection (dig). Passive: touches resolvers, not targets."""

    name = "dns-lookup"
    binary = "dig"
    capability_class = "passive_recon"
    allowed_params = ("record_type",)
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        rtype = str(request.params.get("record_type", "A"))
        if not rtype.replace("_", "").isalnum():
            raise UsageError(f"Invalid record type '{rtype}'")
        return [self.binary, "+short", "-t", rtype, request.target]


class NmapDiscoveryAdapter(Adapter):
    """Authorized host/port discovery (nmap) with a fixed safe flag set."""

    name = "host-discovery"
    binary = "nmap"
    capability_class = "discovery"
    allowed_params = ("ports", "mode")
    required_params = ()

    _MODES = {
        "discover": ("-sn",),
        "connect": ("-sT", "-Pn"),
    }

    def build_argv(self, request: ActionRequest) -> list[str]:
        mode = str(request.params.get("mode", "discover"))
        if mode not in self._MODES:
            raise UsageError(
                f"Unknown nmap mode '{mode}'",
                reason="Only whitelisted flag sets are executable.",
                action=f"Choose one of: {', '.join(self._MODES)}",
            )
        argv = [self.binary, *self._MODES[mode]]
        ports = request.params.get("ports")
        if ports is not None:
            ports = str(ports)
            if not ports.replace(",", "").replace("-", "").isdigit():
                raise UsageError(f"Invalid port specification '{ports}'")
            argv += ["-p", ports]
        argv.append(request.target)
        return argv


BUILTIN_ADAPTERS: tuple[type[Adapter], ...] = (
    EchoAdapter,
    PassiveDnsAdapter,
    NmapDiscoveryAdapter,
)


def _default_adapter_classes() -> tuple[type[Adapter], ...]:
    """Built-ins plus the extended set (when importable)."""
    classes: list[type[Adapter]] = list(BUILTIN_ADAPTERS)
    try:
        from .adapters import EXTENDED_ADAPTERS

        classes.extend(EXTENDED_ADAPTERS)
    except ImportError:  # pragma: no cover - extended set is stdlib-only
        pass
    try:
        from .discovery import DISCOVERY_ADAPTERS

        classes.extend(DISCOVERY_ADAPTERS)
    except ImportError:  # pragma: no cover
        pass
    try:
        from .tool_exec import TOOL_EXEC_ADAPTERS

        classes.extend(TOOL_EXEC_ADAPTERS)
    except ImportError:  # pragma: no cover
        pass
    return tuple(classes)


class AdapterRegistry:
    def __init__(self, *, include_extended: bool = True) -> None:
        self._adapters: dict[str, Adapter] = {}
        for cls in _default_adapter_classes() if include_extended else BUILTIN_ADAPTERS:
            self.register(cls())

    def register(self, adapter: Adapter) -> None:
        if not adapter.name:
            raise UsageError("Adapter must declare a name")
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> Adapter | None:
        return self._adapters.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

    def list(self) -> list[Adapter]:
        return [self._adapters[n] for n in self.names()]


# -- confirmation/approval callbacks --------------------------------------------

Confirmer = Callable[[ActionRequest, GateResult], bool]
Approver = Callable[[ActionRequest, GateResult], bool]


def _always_true(request: ActionRequest, gate: GateResult) -> bool:
    return True


def _always_false(request: ActionRequest, gate: GateResult) -> bool:
    return False


# -- broker -----------------------------------------------------------------------


class ExecutionBroker:
    """The only path by which capability execution happens."""

    def __init__(
        self,
        db: Database,
        *,
        scope_engine: ScopeEngine | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        evidence: EvidenceStore | None = None,
        audit: AuditChain | None = None,
        adapters: AdapterRegistry | None = None,
        confirm: Confirmer | None = None,
        approve: Approver | None = None,
        runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
        queue_on_approval_refusal: bool = False,
        role_engine=None,
    ) -> None:
        self._db = db
        self._scope = scope_engine or ScopeEngine()
        self._risk = risk_engine or RiskEngine()
        self._policy = policy_engine or PolicyEngine()
        self._evidence = evidence or EvidenceStore(db)
        self._audit = audit or AuditChain(db)
        self._adapters = adapters or AdapterRegistry()
        self._confirm = confirm
        self._approve = approve
        self._runner = runner or self._default_runner
        self._queue_on_refusal = queue_on_approval_refusal
        self._roles = role_engine

    # -- introspection ----------------------------------------------------

    @property
    def adapters(self) -> AdapterRegistry:
        return self._adapters

    @property
    def scope_engine(self) -> ScopeEngine:
        """The live scope engine this broker gates with (shared instance)."""
        return self._scope

    def plan(self, request: ActionRequest) -> GateResult:
        """Run all gates up to (but not including) confirmation.

        This is what ``rebel-profiler plan`` shows: exactly what would run and
        what the policy layer decided — with no execution.
        """
        request.validate()
        if self._roles is not None:
            # RBAC precedes every other gate: viewers never reach the tools.
            self._roles.require(request.case_id, request.requested_by, "execute")
        adapter = self._adapters.get(request.action)
        if adapter is None:
            raise UsageError(
                f"No adapter for action '{request.action}'",
                reason="The no-fake-adapter policy forbids pretending an action exists.",
                action=f"Available actions: {', '.join(self._adapters.names())}",
            )
        adapter.validate_params(request)

        # Gate 1+2: scope (fail closed) + canonical target
        try:
            self._scope.validate(request.case_id, request.target)
        except ScopeViolationError:
            raise
        risk = self._risk.classify(adapter.capability_class)
        status = self._scope.evaluate(request.case_id, request.target)
        decision = self._policy.evaluate(scope_status="in_scope", risk=risk)
        task_id = f"task_{uuid.uuid4().hex[:10]}"
        state = {
            PolicyOutcome.ALLOW: "pending",
            PolicyOutcome.ALLOW_WITH_CONFIRMATION: "pending",
            PolicyOutcome.ALLOW_WITH_APPROVAL: "pending",
            PolicyOutcome.DENY: "denied",
        }[decision.outcome]
        return GateResult(decision=decision, scope_status=status, task_id=task_id, state=state)

    def execute(self, request: ActionRequest, *, dry_run: bool = False,
                _pre_approved: bool = False) -> ExecutionResult:
        """Full gate sequence, then structured execution.

        ``_pre_approved`` is reserved for :meth:`execute_approved`: the
        decision already came from the durable approval queue, so the
        interactive approver prompt is skipped (every other gate still runs).
        """
        gate = self.plan(request)
        adapter = self._adapters.get(request.action)  # plan() validated existence
        assert adapter is not None
        decision = gate.decision
        task_id = gate.task_id

        self._audit.append(
            request.case_id,
            actor=request.requested_by,
            action="action.requested",
            subject=request.action,
            detail={"target": request.target, "risk": decision.risk.level},
        )

        if decision.outcome is PolicyOutcome.DENY:
            self._db.record_task(
                task_id, request.case_id, request.action, request.target,
                risk=decision.risk.level, state="pending",
            )
            self._db.set_task_state(task_id, "cancelled", outcome="policy_denied")
            self._audit.append(
                request.case_id, actor="policy", action="action.denied",
                subject=request.action, detail={"reasons": list(decision.reasons)},
            )
            raise PermissionDeniedError(
                f"Policy denied '{request.action}' on '{request.target}'",
                reason="; ".join(decision.reasons) or "risk exceeds permitted level",
                action="Request a policy exception through the approval process.",
            )

        self._db.record_task(
            task_id, request.case_id, request.action, request.target,
            risk=decision.risk.level, state="pending",
        )

        # Gate 4: confirmation / approval collection
        if decision.outcome is PolicyOutcome.ALLOW_WITH_CONFIRMATION:
            if self._confirm is None or not self._confirm(request, gate):
                return self._cancelled(task_id, request, decision, "confirmation_refused")
            self._db.set_task_state(task_id, "confirmed")
            self._audit.append(request.case_id, actor=request.requested_by,
                               action="action.confirmed", subject=request.action)
        if decision.outcome is PolicyOutcome.ALLOW_WITH_APPROVAL and not _pre_approved:
            if self._approve is None or not self._approve(request, gate):
                if self._queue_on_refusal:
                    return self._queued_approval(request, gate, task_id)
                return self._cancelled(task_id, request, decision, "approval_refused")
            self._db.set_task_state(task_id, "approved")
            self._audit.append(request.case_id, actor=request.requested_by,
                               action="action.approved", subject=request.action)

        argv = adapter.build_argv(request)
        self._audit.append(request.case_id, actor="broker",
                           action="action.dispatched", subject=request.action,
                           detail={"argv": argv})

        if dry_run:
            self._db.set_task_state(task_id, "cancelled", outcome="dry_run")
            return ExecutionResult(
                task_id=task_id, action=request.action, target=request.target,
                outcome="dry_run", returncode=None, stdout=" ".join(shlex.quote(a) for a in argv),
                stderr="", evidence_id=None, decision=decision,
            )

        self._db.set_task_state(task_id, "running")
        returncode, stdout, stderr = self._runner(argv)
        outcome = "succeeded" if returncode == 0 else "failed"
        self._db.set_task_state(task_id, outcome, outcome=f"rc={returncode}")

        rec = self._evidence.register(
            request.case_id,
            kind="tool_output",
            data=f"argv: {' '.join(shlex.quote(a) for a in argv)}\nrc: {returncode}\n\n{stdout}\n{stderr}".encode(),
            source=adapter.name,
            note=f"task {task_id} on {request.target}",
            meta={"task_id": task_id, "action": request.action, "returncode": returncode},
        )
        self._audit.append(request.case_id, actor="broker", action="action.completed",
                           subject=request.action, detail={"outcome": outcome, "evidence": rec.id})

        return ExecutionResult(
            task_id=task_id, action=request.action, target=request.target,
            outcome=outcome, returncode=returncode,
            stdout=redact(stdout), stderr=redact(stderr),
            evidence_id=rec.id, decision=decision,
        )

    # -- helpers ------------------------------------------------------------

    def _queued_approval(self, request: ActionRequest, gate: GateResult, task_id: str) -> ExecutionResult:
        """Headless approval-gated action → durable approval queue entry."""
        from ..security.approvals import ApprovalQueue

        self._db.set_task_state(task_id, "cancelled", outcome="queued_for_approval")
        try:
            argv = self._adapters.get(request.action).build_argv(request)
        except UsageError:
            argv = []
        queue = ApprovalQueue(self._db, self._audit)
        record = queue.enqueue(
            request.case_id, task_id=task_id, action=request.action,
            target=request.target, argv=argv, params=dict(request.params),
            risk=gate.decision.risk.level,
            reasons=list(gate.decision.reasons),
            requested_by=request.requested_by,
        )
        return ExecutionResult(
            task_id=task_id, action=request.action, target=request.target,
            outcome="cancelled", returncode=None, stdout="", stderr="",
            evidence_id=None, decision=gate.decision,
        )

    def execute_approved(self, approval_id: str, *, decided_by: str) -> ExecutionResult:
        """Execute an approved queue entry: re-validate gates, then run.

        The approval grants the *decision*, never the authorization: scope,
        risk and policy are re-evaluated on the stored request at decision
        time, so a scope change between request and approval still blocks.
        """
        from ..security.approvals import ApprovalQueue

        queue = ApprovalQueue(self._db, self._audit)
        record = queue.get(approval_id)
        if record["state"] != "approved":
            raise PermissionDeniedError(
                f"Approval '{approval_id}' is '{record['state']}', not approved",
                action="Decide the approval first: rebel-profiler approval decide.")
        argv = queue.load_argv(approval_id)
        params = queue.load_params(approval_id)
        adapter = self._adapters.get(record["action"])
        if adapter is None:
            raise UsageError(f"No adapter for action '{record['action']}'")
        request = ActionRequest(
            case_id=record["case_id"], capability=adapter.capability_class,
            action=record["action"], target=record["target"],
            params=params, requested_by=decided_by,
            reason=f"approval {approval_id}",
        )
        gate = self.plan(request)   # re-runs every gate on live state
        if not gate.decision.allowed:
            self._audit.append(request.case_id, actor="broker",
                               action="action.denied_after_approval",
                               subject=request.action,
                               detail={"approval_id": approval_id,
                                       "reasons": list(gate.decision.reasons)})
            raise PermissionDeniedError(
                f"Re-validation denied '{request.action}' on '{request.target}'",
                reason="; ".join(gate.decision.reasons),
                action="The approval cannot override live scope/policy.")
        return self.execute(request, _pre_approved=True)

    def _cancelled(self, task_id: str, request: ActionRequest, decision: PolicyDecision, why: str) -> ExecutionResult:
        self._db.set_task_state(task_id, "cancelled", outcome=why)
        self._audit.append(request.case_id, actor="broker", action="action.cancelled",
                           subject=request.action, detail={"reason": why})
        return ExecutionResult(
            task_id=task_id, action=request.action, target=request.target,
            outcome="cancelled", returncode=None, stdout="", stderr="",
            evidence_id=None, decision=decision,
        )

    @staticmethod
    def _default_runner(argv: list[str]) -> tuple[int, str, str]:
        import subprocess

        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=300, check=False,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError as exc:
            raise DependencyUnavailableError(
                f"Required binary '{argv[0]}' is not installed",
                reason="Adapters only run tools that exist on this system.",
                action="Install the tool (e.g. via apt on Kali) or choose another action.",
            ) from exc
