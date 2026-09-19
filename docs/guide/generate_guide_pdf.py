#!/usr/bin/env python3
"""Generate Rebel Profiler Interface Guide PDF.

Usage (from the repository root):

    pip install fpdf2
    python docs/guide/generate_guide_pdf.py [output.pdf]

Without an argument the PDF lands next to this script as
``Rebel_Profiler_Hermes_Interface_Guide.pdf``.
"""

from fpdf import FPDF
import os
import sys

_OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = (sys.argv[1] if len(sys.argv) > 1 else
          os.path.join(_OUTPUT_DIR, "Rebel_Profiler_Hermes_Interface_Guide.pdf"))

class GuidePDF(FPDF):
    # fpdf2 core fonts are latin-1 only: transliterate the few decorative
    # characters the source uses and flag anything else that slips through.
    _TRANSLIT = str.maketrans({
        "\u2014": "-", "\u2013": "-", "\u2500": "-", "\u2502": "|",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u2022": "*", "\u25b8": ">", "\u2192": "->",
    })

    @staticmethod
    def _latin(text) -> str:
        out = str(text).translate(GuidePDF._TRANSLIT)
        return "".join(ch if ord(ch) < 128 else "?" for ch in out)

    def cell(self, w=0, h=0, txt="", **kwargs):
        return super().cell(w, h, self._latin(txt), **kwargs)

    def multi_cell(self, w=0, h=None, txt="", **kwargs):
        return super().multi_cell(w, h, self._latin(txt), **kwargs)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100,100,100)
        self.cell(0, 5, "Rebel Profiler  v1.3.1  —  Hermes-Style Interface Guide", align="R")
        self.ln(2)
        self.set_draw_color(50,50,50)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica","I",7)
        self.set_text_color(130,130,130)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, txt):
        self.set_font("Helvetica","B",13)
        self.set_text_color(20,80,160)
        self.cell(0, 8, txt)
        self.ln(5)
        self.set_draw_color(20,80,160)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def sub_title(self, txt):
        self.set_font("Helvetica","B",10)
        self.set_text_color(60,60,60)
        self.cell(0, 6, txt)
        self.ln(5)

    def body(self, txt):
        self.set_font("Helvetica","",9.5)
        self.set_text_color(40,40,40)
        self.multi_cell(0, 4.8, txt)
        self.ln(1)

    def code(self, txt):
        self.set_font("Courier","",7.5)
        self.set_text_color(30,30,30)
        self.set_fill_color(245,245,240)
        self.multi_cell(0, 3.8, txt, fill=True)
        self.ln(1)

    def bullet(self, txt, indent=8):
        x = self.get_x()
        self.set_x(x + indent)
        self.set_font("Helvetica","",9.5)
        self.set_text_color(40,40,40)
        self.cell(3, 4.8, chr(8226))
        self.multi_cell(self.w - self.l_margin - self.r_margin - indent - 3, 4.8, txt)
        self.ln(0.5)

    def mono_bullet(self, txt):
        self.bullet(txt, indent=6)
        self.set_font("Courier","",7.5)

    def note(self, txt):
        self.set_fill_color(255, 248, 220)
        self.set_font("Helvetica","I",9)
        self.set_text_color(100,80,0)
        self.multi_cell(0, 4.8, "  " + txt, fill=True, border=1)
        self.ln(2)

    def table_header(self, cols, widths):
        self.set_fill_color(20,80,160)
        self.set_text_color(255,255,255)
        self.set_font("Helvetica","B",8.5)
        for c,w in zip(cols,widths):
            self.cell(w, 6, c, border=1, fill=True, align="C")
        self.ln()

    def table_row(self, cells, widths, align="L"):
        self.set_text_color(40,40,40)
        self.set_font("Helvetica","",8.5)
        for c,w in zip(cells,widths):
            self.cell(w, 5.5, c, border=1, align=align)
        self.ln()


pdf = GuidePDF()
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=18)
pdf.add_page()

# ── COVER ────────────────────────────────────────────────────────────────
pdf.ln(20)
pdf.set_font("Helvetica","B",28)
pdf.set_text_color(20,80,160)
pdf.multi_cell(0, 12, "REBEL PROFILER")
pdf.ln(3)
pdf.set_font("Helvetica","",14)
pdf.set_text_color(80,80,80)
pdf.cell(0, 8, "Hermes-Style Interface Guide")
pdf.ln(14)
pdf.set_draw_color(20,80,160)
pdf.set_line_width(0.5)
pdf.line(pdf.l_margin, pdf.get_y(), pdf.w-pdf.r_margin, pdf.get_y())
pdf.ln(8)
pdf.set_font("Helvetica","",10)
pdf.set_text_color(60,60,60)
pdf.multi_cell(0, 5.5,
    "Kali Linux Cybersecurity Intelligence &\n"
    "Authorized Security Operations Framework\n\n"
    "Version 1.3.1  |  705 tests passing  |  MIT License\n"
    "Made by REBEL")
pdf.ln(5)

pdf.set_font("Helvetica","I",9)
pdf.set_text_color(100,100,100)
pdf.multi_cell(0, 4.8,
    "Use only on systems you are explicitly authorized to assess.\n"
    "The tool enforces scope and policy mechanically; authorization\n"
    "documents, legal review, and operational competence remain your responsibility.")
pdf.ln(10)

pdf.set_font("Helvetica","B",10)
pdf.set_text_color(20,80,160)
pdf.cell(0, 7, "Core Design Law (one line, memorized):")
pdf.ln(8)
pdf.set_font("Helvetica","B",11)
pdf.set_fill_color(230,240,255)
pdf.set_text_color(20,60,140)
pdf.multi_cell(0, 7,
    "   The LLM proposes. The system decides. Nothing runs without authorization,\n"
    "   and nothing is claimed without evidence.",
    fill=True)
pdf.ln(12)

pdf.set_font("Helvetica","B",9)
pdf.set_text_color(60,60,60)
pdf.cell(0, 6, "This guide covers:")
pdf.ln(7)
for t in [
    "1.  What this tool is and why it exists",
    "2.  The six design laws (enforced in code, not by prompt)",
    "3.  Full architecture: seven planes + request lifecycle",
    "4.  The six-gate sequence (every run passes through all six)",
    "5.  Hermes-agent-style conversation interface  (the main goal of this guide)",
    "6.  Complete command reference, organized the way you will actually use it",
    "7.  LLM plane: AirLLM-mode, five engines, script authoring",
    "8.  Agent workflow: agent run / agent chat / agent auto / agent work",
    "9.  Intel plane: collection, claims, fusion, surface, bug-bounty",
    "10. Knowledge layer, RBAC, workflows, scheduler, transports",
    "11. Integrity: evidence, audit, verify, backup/restore",
    "12. Folder map: every directory and what it owns",
    "13. Quick-start checklist  (first 5 minutes)",
]:
    pdf.bullet(t)

pdf.add_page()

# ── SECTION 1: OVERVIEW ─────────────────────────────────────────────────
pdf.section_title("1.  What Is Rebel Profiler?")
pdf.body(
    "Rebel Profiler turns natural-language investigation goals into controlled, "
    "authorized, evidence-backed security operations on Kali Linux. It is not a "
    "hacking tool that you point at targets and hope for the best. It is a "
    "framework that enforces authorization, scope, and evidence at every step "
    "through deterministic code — not through the LLM's goodwill."
)
pdf.body(
    "The LLM's job is to propose actions: which tool to run, on which target, with "
    "which parameters. The system's job is to decide whether that proposal is "
    "allowed, gate it through six mechanical checks, run it only if every gate "
    "passes, register the output as hashed evidence, and append an audit event. "
    "If any gate denies, nothing runs — and the denial itself is audit-logged."
)
pdf.body(
    "This means you can give it a goal in plain English — \"map example.com's passive "
    "footprint\" — and it will plan, execute, repair failures, extend itself when "
    "a capability is missing, and return an evidenced report. You never get a raw "
    "shell, never get an unexecuted claim, and never get a result with no hash-chain "
    "behind it."
)
pdf.sub_title("Who built it and under what license")
pdf.bullet("Author: REBEL")
pdf.bullet("License: MIT — see LICENSE in the project root")
pdf.bullet("Python: >= 3.11, stdlib-only core — no third-party runtime dependencies")
pdf.bullet("Tests: pytest (dev-only); 705 passing as of v1.3.1")
pdf.bullet("CI: GitHub Actions workflow at .github/workflows/ci.yml")
pdf.ln(2)

pdf.sub_title("What it deliberately is NOT")
pdf.bullet("Not a raw shell — execution/broker.py rejects anything that would invoke a shell interpreter")
pdf.bullet("Not a demo generator — every claim must have hash-chained evidence; no evidence, no claim")
pdf.bullet("Not an exploit builder — the malware domain is analysis-only")
pdf.bullet("Not credential brute-forcing — absent from the tool's action set entirely")
pdf.bullet("Not functional malware generation — detection engineering produces only benign artifacts (EICAR, canaries, IoC bundles, YARA rules)")
pdf.bullet("Not a substitute for legal review — the tool enforces scope, but you are responsible for the authorization documents")
pdf.ln(3)

pdf.note(
    "REMEMBER: Use only on targets you are explicitly authorized to assess. "
    "A published bug-bounty program scope IS authorization — it becomes ordinary "
    "scope entries in the tool. Nothing is special-cased or bypassable."
)
pdf.add_page()

# ── SECTION 2: DESIGN LAWS ───────────────────────────────────────────────
pdf.section_title("2.  The Design Laws (Enforced in Code)")
pdf.body(
    "These are not aspirations or documentation promises. Each law has a concrete "
    "module that enforces it mechanically. If you read one thing before using the "
    "tool, read this table."
)
pdf.ln(2)

laws = [
    ("LLM proposes, never decides",
     "security/policy.py",
     "Deterministic, versioned policy engine. The LLM fills ActionRequest fields; it cannot create adapters, alter scope, or influence risk/policy."),
    ("Scope fails closed",
     "security/scope.py",
     "Unknown target => blocked. Exclusions always win. Evaluation is from the live case store at execution time, not from whatever the planner believed."),
    ("No raw shell, ever",
     "execution/broker.py + execution/tool_exec.py",
     "Structured actions + whitelisted params only. A binary whitelist excludes shells, interpreters, and download-execute tools. No shell interpreter exists anywhere in the execution path."),
    ("No fake adapters",
     "execution/broker.py",
     "Unknown action is a hard error, never simulated. The adapter registry is the only code path that may talk to external binaries, and only via argv lists."),
    ("No evidence, no claim",
     "evidence/store.py",
     "SHA-256 content-addressed, hash-chained ledger. Every blob is hashed before storage; every record links to its predecessor. integrity is verifiable offline."),
    ("Tamper-evident audit",
     "evidence/audit.py",
     "Every decision and action is hash-linked. evidence verify and audit verify recompute hashes and chain linkage; any edit, deletion, or reordering is detected (exit 11)."),
    ("Secrets never leak",
     "core/redact.py",
     "Conservative redaction on every output path — CLI, JSON, JSONL, CSV, reports."),
    ("Config can only tighten",
     "core/config.py",
     "Protected security keys (scope.fail_closed, evidence.redaction_enabled, evidence.audit_chain_enabled, policy.risk_to_outcome_mapping) reject any attempt to weaken them, at any layer."),
    ("Claims are not facts",
     "intel/claims.py",
     "Confidence is computed from deterministic source scoring, never an LLM opinion. Independent corroboration upgrades; contradictions demote the lower-confidence side. Both sides stay in the ledger."),
    ("External content is data",
     "intel/injection.py",
     "Deterministic prompt-injection scan + sanitization wraps every external blob as clearly-delimited untrusted data before it can reach any planner context."),
]

cols = ["Law", "Where it lives", "What it does"]
widths = [46, 38, 106]
pdf.table_header(cols, widths)
for name, loc, desc in laws:
    y = pdf.get_y()
    if y > pdf.h - 30:
        pdf.add_page()
        pdf.table_header(cols, widths)
        y = pdf.get_y()
    pdf.set_font("Helvetica","B",8)
    pdf.set_text_color(20,60,140)
    pdf.set_fill_color(240,244,250)
    x0 = pdf.get_x()
    pdf.cell(widths[0], 10, name, border=1, fill=True)
    pdf.set_font("Courier","",7)
    pdf.set_text_color(40,40,40)
    pdf.cell(widths[1], 10, loc, border=1)
    pdf.set_font("Helvetica","",8)
    pdf.set_text_color(40,40,40)
    x2 = pdf.get_x()
    pdf.multi_cell(widths[2], 5, desc, border=1)
    y2 = pdf.get_y()
    if y2 < y + 10:
        pdf.set_y(y + 10)
    else:
        pdf.set_y(y2)
pdf.ln(3)

pdf.note(
    "These laws are self-enforcing: you can tighten policy overrides, swap in "
    "ticketing-based approvers, or add webhook confirmers. You cannot weaken them. "
    "The protected config keys reject weakening at every layer, including "
    "job profiles (--config-file)."
)
pdf.add_page()

# ── SECTION 3: ARCHITECTURE ───────────────────────────────────────────────
pdf.section_title("3.  Architecture: Seven Planes")
pdf.body(
    "Rebel Profiler implements a seven-plane model. Each plane owns a clear slice "
    "of responsibility, and the trust boundaries between planes are enforced "
    "mechanically. The LLM lives in one plane and can only produce data structures "
    "— never commands, never decisions."
)
pdf.ln(2)

planes = [
    ("Intelligence Plane", "knowledge/  +  intel/",
     "15 domains, 81 topics, 109 techniques, 121 glossary terms. Capability classes, Kali tool map, and planner context. Source scoring (admiralty-style A-E grades, 30-day freshness half-life, independence), claim ledger with computed confidence, entity resolution, injection defense, collection pipeline, findings/report generator, cross-domain fusion (noisy-OR corroboration, contradiction engine), persistent relationship graph store (SQLite v3 tables), surface graph, program scope import (bug-bounty CSV/JSON -> ordinary scope entries), bounty triage (claim ledger -> severity/CWE/repro), and the full bounty session (one goal -> scope/recon/assess/author/execute/repair/report, each stage bounded and evidenced). Emits planner context; contains no authority of any kind."),
    ("Agent Plane", "agent/",
     "Goal -> planner proposals -> broker gates -> claims -> report. The planner sees only declared actions and params (PlannerView). Denials come back as feedback, not failures. Sessions are capped (--max-turns, default 8) and every executed call is hash-chained evidence. Ships with a deterministic passive-first planner today; any LLM can plug in by emitting the same Proposal objects. This is the 10x lever: the operator states a goal, the harness does the chained work in minutes with every step audited."),
    ("LLM Plane (Planner)", "llm/",
     "Five engines, one interface: gguf (single-file llama.cpp checkpoints), native (layer-wise streaming over on-disk safetensors), airllm (layer streaming, AutoModel across families), external (opt-in remote, OpenAI-compatible), and tiny (deterministic fallback — never hallucinates, reason always recorded). All are local-first, CPU/MPS-friendly, and wrapped by the hardware budget guard. The script plane lets the LLM write a code file -> static AST gate -> subprocess sandbox -> real result, hash-chained as evidence. A resident daemon unloads the model after every job so the machine goes quiet again. Produces ActionRequest structures — never commands, never decisions. Same input is available to any frontend."),
    ("Security / Policy Plane", "security/",
     "scope.py: fail-closed authorization boundary. risk.py: versioned, deterministic classification (low / moderate / high / critical). policy.py: allow -> confirm -> approve -> deny. Deployment overrides may only tighten the risk-to-outcome mapping; weaker is rejected."),
    ("Execution Plane", "execution/broker.py",
     "Adapter registry (declared params, whitelisted flag sets). Six-gate sequence on every run. Structured results. No raw shell anywhere. Dry-run (rebel-profiler plan, run --dry-run) stops before the runner and still shows the exact argv and policy outcome."),
    ("Evidence / Data Plane", "evidence/  +  storage/",
     "Content-addressed evidence ledger (SHA-256, hash-chained). Hash-linked audit chain. SQLite per case (physical isolation — one database per case, no shared tables). workspace/cases/<case-id>/case.db plus blobs/ (sha256[:2]/sha256 layout)."),
    ("Operations Plane", "cli/  +  core/config.py",
     "Human / JSON / JSONL / CSV output on every command. doctor health check. Layered config with protected security keys (tighten-only). Exit codes: 0 ok, 2 usage, 3 config, 4 permission/policy, 5 scope, 7 dependency, 11 evidence tamper, 12 state, 15 model budget."),
]

for i, (name, loc, desc) in enumerate(planes, 1):
    if pdf.get_y() > pdf.h - 60:
        pdf.add_page()
    pdf.sub_title(f"Plane {i}: {name}   [{loc}]")
    pdf.body(desc)
    pdf.ln(2)

pdf.add_page()

pdf.sub_title("Request Lifecycle (how a single action flows)")
pdf.code(
    "operator / LLM\n"
    "    |  ActionRequest { case_id, capability, action, target, params }\n"
    "    v\n"
    "ExecutionBroker.plan()\n"
    "    ... six gates ...\n"
    "    v\n"
    "ExecutionBroker.execute()  --ExecutionResult-->  intel.collection\n"
    "                                                +- evidence.register()   (SHA-256, hash-chained)\n"
    "                                                +- injection scan + sanitize\n"
    "                                                +- parse -> claims (scored, provenance)\n"
    "                                                +- persist claims + observations\n"
    "    |\n"
    "    +- adapter lookup         -> UsageError if absent (no fake adapters)\n"
    "    +- param contract check   -> UsageError on undeclared params\n"
    "    +- ScopeEngine.validate() -> ScopeViolationError unless ACTIVE + in_scope\n"
    "    +- RiskEngine.classify()  -> low / moderate / high / critical\n"
    "    +- PolicyEngine.evaluate()-> allow / confirm / approve / deny\n"
    "    v\n"
    "DENY  -> PermissionDeniedError + audit('action.denied')   [nothing ran]\n"
    "confirm/approve callbacks (interactive CLI prompt, or programmatic/ticketing)\n"
    "adapter.build_argv()    -> whitelisted argv only\n"
    "runner(argv)            -> subprocess with timeout, no shell\n"
    "EvidenceStore.register()-> SHA-256 blob + chain linkage\n"
    "AuditChain.append()     -> hash-linked event (requested / completed / denied)\n"
)
pdf.ln(1)
pdf.note("Dry-run (rebel-profiler plan, or run --dry-run) stops before the runner and still shows the exact argv and policy outcome. Use it to preview before you commit.")
pdf.add_page()

# ── SECTION 4: SIX GATES ──────────────────────────────────────────────────
pdf.section_title("4.  The Six-Gate Sequence")
pdf.body(
    "Every run — whether you trigger it directly, through agent auto, or through "
    "bounty auto — passes through all six gates, in order, before any tool executes. "
    "A denial at any gate means nothing runs, and the denial itself is audited."
)
pdf.ln(3)

gates = [
    ("Gate 1", "Adapter exists?",
     "The broker looks up the requested action in the adapter registry. If no adapter is registered for that action, the request is rejected with a UsageError. There are no fake adapters, no simulated results, no fallback to a different tool. Unknown action = hard error. This is the no-fake-adapter law in practice."),
    ("Gate 2", "Params match declared contract?",
     "Every adapter declares its allowed_params. The broker validates that the request's params are a subset of the declared contract. Undeclared params are rejected. This prevents the LLM from passing arbitrary flags into a tool — only the flags the adapter explicitly allows can be used."),
    ("Gate 3", "Target in ACTIVE scope? (fail closed)",
     "ScopeEngine.validate() checks the target against the case's live scope entries. The case must be ACTIVE (case activate). Unknown targets are blocked. Exclusions always win. Scope is evaluated at execution time from the live case store — not from whatever the planner believed at plan time. This is the fail-closed law."),
    ("Gate 4", "Risk classified (versioned rules, not opinions)",
     "RiskEngine.classify() assigns low / moderate / high / critical based on a versioned rules table. The classification depends on the action type and parameters, not on the LLM's judgment. Deployment overrides may only tighten the mapping."),
    ("Gate 5", "Policy: allow -> confirm -> approve -> deny",
     "PolicyEngine.evaluate() maps the classified risk to an outcome. Low risk may be allowed automatically. Higher risk may require an interactive confirmation prompt, a programmatic approval (ticketing/webhook), or be denied outright. Approvals for headless runs land in a durable queue (approval list / decide / run); the stored argv is re-validated against live scope and policy at decision time."),
    ("Gate 6", "Execute -> evidence -> audit",
     "Only if all five gates pass does the runner dispatch the tool via subprocess (with timeout, no shell). The output is registered as a SHA-256 content-addressed blob in the evidence store, hash-linked to its predecessor. An audit event is appended describing the request, the decision, and the completion. If the tool fails, the failure is recorded as evidence — not silently dropped."),
]

cols2 = ["Gate", "Check", "What it enforces"]
widths2 = [12, 38, 140]
pdf.table_header(cols2, widths2)
for g, chk, desc in gates:
    y0 = pdf.get_y()
    if y0 > pdf.h - 40:
        pdf.add_page()
        pdf.table_header(cols2, widths2)
        y0 = pdf.get_y()
    pdf.set_font("Helvetica","B",8)
    pdf.set_text_color(20,60,140)
    pdf.set_fill_color(240,244,250)
    pdf.cell(widths2[0], 7, g, border=1, fill=True, align="C")
    pdf.set_font("Helvetica","B",8.5)
    pdf.set_text_color(40,40,40)
    pdf.cell(widths2[1], 7, chk, border=1)
    pdf.set_font("Helvetica","",8)
    pdf.multi_cell(widths2[2], 4.5, desc, border=1)
    y1 = pdf.get_y()
    if y1 < y0 + 7:
        pdf.set_y(y0 + 7)
    else:
        pdf.set_y(y1)
pdf.ln(3)

pdf.note(
    "A denial at any gate is not a soft error. It is a structured, audit-logged event: "
    "what was requested, which gate denied it, and why. You can inspect every denial "
    "through audit show <case-id>. Scope and policy blocks are never auto-retried by "
    "the agent — the LLM gets the denial as feedback and decides what to do next; the "
    "tool never silently walks around a blocked gate."
)
pdf.add_page()

# ── SECTION 5: HERMES-STYLE INTERFACE ─────────────────────────────────────
pdf.section_title("5.  Hermes-Agent-Style Conversation Interface")
pdf.body(
    "This is the main reason this guide exists. Rebel Profiler already has the pieces "
    "of a Hermes-agent-style interaction loop. The goal of this section is to show you "
    "exactly how the pieces fit together so that when you come back to this folder later "
    "and ask the AI to read sub-folders and start working, it can orient itself from "
    "this document instead of re-discovering the architecture every time."
)
pdf.ln(2)

pdf.sub_title("5a. The Hermes Chat Loop (agent chat)")
pdf.body(
    "The agentic chat pattern — the one popularized by the Hermes fine-tunes — is "
    "built into Rebel Profiler's agent plane. Here is exactly how a turn works:"
)
pdf.ln(1)
pdf.code(
    "SYSTEM MESSAGE (ChatML):\n"
    "  <|im_start|>system\n"
    "  You are Rebel Profiler's operator assistant.\n"
    "  You see your tools in the <tools> block below.\n"
    "  To use one, emit exactly one <tool_call> per turn:\n"
    "    <tool_call>{\"name\": \"<action>\", \"arguments\": {...}}</tool_call>\n"
    "  Wait for the <tool_response> before your next call.\n"
    "  When you have enough, answer in plain text.\n"
    "  <|im_end|>\n"
    "\n"
    "TURN LOOP (repeated until you answer or --max-turns hits):\n"
    "  1. <|im_start|>user  <goal + prior context>  <|im_end|>\n"
    "  2. Model sees <tools> block + history\n"
    "  3. Model emits ONE <tool_call>{name, arguments}\n"
    "  4. broker receives ActionRequest — runs the six gates\n"
    "  5. If denied: <tool_response> carries the denial as feedback\n"
    "  6. If allowed and executed: <tool_response> carries the\n"
    "     redacted, structured result as a tool-role message\n"
    "  7. Every executed call is hash-chained evidence\n"
    "  8. Loop repeats (bounded by --max-turns, default 8)\n"
    "  9. Model answers in plain text when done\n"
    "\n"
    "If no LLM engine with real weights is loaded, the session says so\n"
    "and returns a structured refusal — never a hallucinated session."
)
pdf.ln(2)

pdf.sub_title("5b. What the tool block looks like (PlannerView)")
pdf.body(
    "The LLM never sees the full codebase. It sees a PlannerView: a declarative list "
    "of every action it is allowed to propose, each with its name, description, and "
    "declared parameters. This is the same contract the broker uses for Gate 1 "
    "(adapter exists?) and Gate 2 (params match contract?). Unknown actions and "
    "undeclared params are rejected before they ever leave the model's output."
)
pdf.code(
    "<tools>\n"
    "  <tool>\n"
    "    <name>host-discovery</name>\n"
    "    <description>Run an nmap host-discovery scan on an in-scope target.</description>\n"
    "    <parameters>\n"
    "      <param name=\"target\" type=\"string\" scope-checked=\"true\"/>\n"
    "      <param name=\"mode\" type=\"string\" enum=\"discover,safe,stealth\"/>\n"
    "      <param name=\"_ports\" type=\"string\" optional=\"true\"/>\n"
    "    </parameters>\n"
    "  </tool>\n"
    "  <tool>\n"
    "    <name>passive-dns</name>\n"
    "    <description>Query passive DNS for a domain, record-type aware.</description>\n"
    "    <parameters>\n"
    "      <param name=\"domain\" type=\"string\"/>\n"
    "      <param name=\"record_type\" type=\"string\" enum=\"A,MX,NS,PTR,TXT\"/>\n"
    "    </parameters>\n"
    "  </tool>\n"
    "  ... (every declared action appears here)\n"
    "</tools>"
)
pdf.ln(2)

pdf.sub_title("5c. How this maps to actual Rebel Profiler commands")
pdf.body(
    "The chat loop is not a separate interface — it is one path into the same agent "
    "plane that the CLI commands use. Here is the mapping:"
)
pdf.ln(1)
mapping = [
    ("agent chat <case-id> \"<goal>\"",
     "The Hermes loop. One tool_call per turn, bounded by --max-turns (default 8). The model drives itself until it answers."),
    ("agent run <case-id> \"<goal>\" --llm <model>",
     "The LLM plans once (emits a validated work list of ActionRequest proposals), then the broker executes each through the six gates. Failures become structured error-log entries with deterministic fix hints."),
    ("agent run <case-id> \"<goal>\" --plan \"passive-dns:...;whois-lookup:...\"",
     "You provide the plan explicitly. The broker still gates every step. Useful when you know what you want and want to skip the planner."),
    ("agent work <case-id> \"<goal>\" --plan \"...\"",
     "Agent run plus a repair loop: the LLM reviser reads each failure + fix hint and returns a corrected proposal. Bounded retries; scope/policy blocks are never auto-retried. Ends with concrete suggestions for the operator."),
    ("agent auto <case-id> \"<goal>\" --llm <model>",
     "The full Autonomous Engineer: PLAN (LLM planner reads goal + live action contract) -> EXECUTE (work list through six gates) -> REPAIR (LLM reviser, bounded) -> EXTEND (when the error log says the capability is missing, the LLM writes a new adapter and Feature Forge's gates decide: static AST gate -> subprocess sandbox -> HMAC signature -> live registration, with bounded rewrite rounds). Every phase is gated, evidenced, and audited."),
    ("bounty auto <case-id> \"<goal>\" --llm <model>",
     "The bug-bounty version of agent auto: SCOPE (re-validate against live scope) -> RECON (scope-enforced web audit of every in-scope asset) -> ASSESS (triage into reportable findings) -> AUTHOR (the model decides which scripts the goal still needs and writes them, stored not executed) -> EXECUTE (script plane's static gate + sandbox run them, record the real outcome) -> REPAIR (failures and gate rejections go back to the model, bounded) -> REPORT (severity + CWE + reproduction + remediation, evidence-backed)."),
]

for cmd, desc in mapping:
    y0 = pdf.get_y()
    if y0 > pdf.h - 30:
        pdf.add_page()
    pdf.set_font("Courier","B",7.5)
    pdf.set_text_color(20,80,160)
    pdf.set_fill_color(240,244,250)
    pdf.cell(68, 5.5, cmd, border=1, fill=True)
    pdf.set_font("Helvetica","",8.5)
    pdf.set_text_color(40,40,40)
    pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin - 68, 4.5, desc, border=1)
    pdf.ln(1.5)
pdf.ln(2)

pdf.sub_title("5d. Why this is Hermes-like (and where it differs)")
pdf.body(
    "Same pattern: the model sees its tools in a structured block, emits one call at "
    "a time, reads the gated result, adapts, and answers in plain text when done. "
    "Same discipline: every call is hash-chained evidence; denials are feedback, not "
    "silent failures; the model never gets a raw shell or an unexecuted claim."
)
pdf.body(
    "Differences you should know about: Rebel Profiler adds a deterministic policy "
    "layer between the model's call and the tool — six mechanical gates that the model "
    "cannot bypass. Hermes-agent's tool calls go directly to the tool; here they go "
    "through scope, risk, and policy first. This means the model can propose an action "
    "that gets denied, and that denial is a real, auditable event — not a conversational "
    " refusal. The model learns from denials the same way it learns from tool responses."
)
pdf.body(
    "Also different: the tool can extend itself. When the model hits a capability that "
    "does not exist yet, Feature Forge lets it write its own adapter module — through "
    "a deterministic static gate (no subprocess/socket/os/eval/open reach), a "
    "subprocess sandbox test of the argv builder, and HMAC signing before registration. "
    "The model grows the tool; the system stays in control."
)
pdf.add_page()

# ── SECTION 6: COMMAND REFERENCE ──────────────────────────────────────────
pdf.section_title("6.  Command Reference (the way you will actually use it)")
pdf.body(
    "Organized by workflow order, not by code layout. Every command accepts "
    "-o human|json|jsonl|csv. Replace <case-id> with your case id (case list shows "
    "them). All paths below assume you are in the project root or have rebel-profiler "
    "on your PATH after pip install -e ."
)
pdf.ln(2)

pdf.sub_title("0. First time (one-time setup)")
pdf.code(
    "pip install -e .                              # core — stdlib-only, no runtime deps\n"
    "rebel-profiler doctor                         # health check\n"
    "\n"
    "# LLM engines — pick what fits your checkpoints (see docs/SETUP.md):\n"
    "pip install 'rebel-profiler[gguf]'            # GGUF files (llama.cpp / Ollama / LM Studio)\n"
    "pip install 'rebel-profiler[native]'          # HF safetensors already on disk\n"
    "pip install 'rebel-profiler[airllm]'          # airllm layer streaming (GPU optional)\n"
    "\n"
    "rebel-profiler llm setup                      # hardware-aware install guidance\n"
    "rebel-profiler llm local                      # checkpoints on disk + run commands\n"
    "rebel-profiler llm status                     # what can THIS machine run?\n"
    "rebel-profiler llm models                     # which models fit?\n"
    "\n"
    "# Shell completion + alias (bash or zsh, once):\n"
    "source <repo>/completions/rebel-profiler.bash  # bash\n"
    "echo \"alias rp='rebel-profiler'\" >> ~/.zshrc   # then: rp doctor\n"
    "# zsh: copy completions/_rebel-profiler to a dir on your $fpath"
)
pdf.ln(2)

pdf.sub_title("1. Case lifecycle (every job starts here)")
pdf.code(
    "rebel-profiler case create \"Job Name\" \"description\"\n"
    "rebel-profiler case scope add <case-id> \"*.target.com\" --note \"authorized\"\n"
    "rebel-profiler case scope add <case-id> \"admin.target.com\" --exclude\n"
    "rebel-profiler case activate <case-id>          # scope enforcement goes live\n"
    "rebel-profiler scope-check <case-id> host.target.com\n"
    "rebel-profiler case list                        # ids + status\n"
    "rebel-profiler case show <case-id>\n"
    "rebel-profiler case close <case-id>"
)
pdf.ln(2)

pdf.sub_title("2. The daily driver — Autonomous Engineer")
pdf.code(
    "# State the goal. The LLM plans, runs (six gates), repairs, forges missing\n"
    "# adapters through the safety gates. You read the report.\n"
    "rebel-profiler agent auto <case-id> \"map target.com passive footprint\" \\\n"
    "    --llm Qwen/Qwen3-4B\n"
    "\n"
    "# Variants:\n"
    "rebel-profiler agent auto <case-id> \"<goal>\" \\\n"
    "    --llm Qwen/Qwen3-4B --max-actions 20 --max-repair-attempts 3\n"
    "RP_LLM__ENGINE=external RP_LLM__API_KEY=sk-... \\\n"
    "    rebel-profiler agent auto <case-id> \"<goal>\"     # remote brain (opt-in only)\n"
    "\n"
    "# Manual / surgical modes:\n"
    "rebel-profiler agent chat <case-id> \"<goal>\"                      # Hermes loop\n"
    "rebel-profiler agent chat <case-id> \"<goal>\" --max-turns 12\n"
    "rebel-profiler agent run <case-id> \"<goal>\" --llm Qwen/Qwen3-4B   # LLM plans once\n"
    "rebel-profiler agent run <case-id> \"<goal>\" \\\n"
    "    --plan \"passive-dns:target.com:record_type=A;whois-lookup:target.com\"\n"
    "rebel-profiler agent work <case-id> \"<goal>\" --plan \"...\"          # + repair loop"
)
pdf.ln(2)

pdf.sub_title("3. LLM plane (AirLLM-mode)")
pdf.code(
    "rebel-profiler llm status                       # budget, tier, caps\n"
    "rebel-profiler llm status --tier low            # pretend to be a smaller box\n"
    "rebel-profiler llm models                       # fits-this-machine shortlist\n"
    "rebel-profiler llm generate \"summarize: ...\" \\\n"
    "    --model Qwen/Qwen3-4B --max-tokens 200      # one shot; loads then unloads\n"
    "rebel-profiler llm generate \"...\" --model /path/to/model.gguf   # a local GGUF file\n"
    "rebel-profiler llm generate \"...\" --local         # best local model that fits\n"
    "rebel-profiler llm plan <case-id> \"find subdomains\" --model Qwen/Qwen3-4B\n"
    "\n"
    "# The LLM writes and repairs its own scripts:\n"
    "rebel-profiler llm script author \"<goal>\"       # model writes run(payload)\n"
    "rebel-profiler llm script run --once            # static gate -> sandbox -> result\n"
    "rebel-profiler llm script result <script-id>    # the ACTUAL returned value\n"
    "rebel-profiler llm script retry <script-id>     # feed the failure back to the model\n"
    "rebel-profiler llm script list\n"
    "\n"
    "# Stored, never executed at submit time; idempotent; a script gets exactly\n"
    "# the reach the static gate allows — no more than a human-written one.\n"
    "\n"
    "# Unattended (job files — the CLI stays tiny, the daemon gets heavy):\n"
    "rebel-profiler llm submit \"long analysis prompt\" --model Qwen/Qwen3-4B\n"
    "rebel-profiler llm daemon                       # resident; UNLOADS after every job\n"
    "rebel-profiler llm result <job-id>              # read the ACK\n"
    "rebel-profiler llm data <case-id> \"what is exposed and why?\"   # case analysis\n"
    "rebel-profiler llm data <case-id> \"question\" --pack-only       # data pack, no model"
)
pdf.ln(2)

pdf.note(
    "Local-first rule: without RP_LLM__ENGINE=external, nothing leaves the machine. "
    "The engine order is always airllm -> tiny (honest fallback, reason recorded), "
    "never a silent substitution. The LLM never opens the case database — llm data "
    "writes a checksummed job file, the daemon builds a bounded, redacted data pack, "
    "and the pack is delimited DATA, never instructions."
)
pdf.add_page()

pdf.sub_title("4. One-shot collection (each = run + evidence + claims)")
pdf.code(
    "rebel-profiler intel collect <case-id> passive-dns target.com -p record_type MX\n"
    "rebel-profiler intel collect <case-id> whois-lookup target.com\n"
    "rebel-profiler intel collect <case-id> cert-transparency target.com\n"
    "rebel-profiler intel collect <case-id> port-scan h1.target.com -p ports 22,80,443\n"
    "rebel-profiler intel crawl <case-id> https://h1.target.com/ --max-pages 20\n"
    "rebel-profiler run <case-id> <action> <target> -p key value --dry-run   # preview\n"
    "rebel-profiler intel claims <case-id> [subject]\n"
    "rebel-profiler intel sources [source-key]\n"
    "rebel-profiler intel sanitize \"<untrusted text>\"\n"
    "rebel-profiler intel fusion <case-id> [subject]"
)
pdf.ln(2)

pdf.sub_title("5. Surface, graph & reports")
pdf.code(
    "rebel-profiler surface build <case-id>          # graph from claims (persisted)\n"
    "rebel-profiler surface show <case-id>\n"
    "rebel-profiler surface map <case-id>\n"
    "rebel-profiler surface exposure <case-id>\n"
    "rebel-profiler surface paths <case-id> host:h1 port:80/tcp\n"
    "rebel-profiler surface related <case-id> host:h1\n"
    "rebel-profiler report <case-id>                 # human; -o json for machine\n"
    "rebel-profiler search query <case-id> terms...  # FTS over claims\n"
    "rebel-profiler search rebuild <case-id>"
)
pdf.ln(2)

pdf.sub_title("6. Approvals, RBAC, workflows, hypotheses, scheduler")
pdf.code(
    "rebel-profiler approval list <case-id>          # pending approval-gated actions\n"
    "rebel-profiler approval decide <case-id> <approval-id> approve\n"
    "rebel-profiler approval run <case-id> <approval-id>\n"
    "rebel-profiler member add <case-id> alice owner\n"
    "rebel-profiler workflow create <case-id> flow.dsl\n"
    "rebel-profiler workflow run <case-id> [workflow-id]     # resumable DAG\n"
    "rebel-profiler workflow approve <case-id> <wf-id> <step-key>\n"
    "rebel-profiler schedule add <case-id> --action port-scan --target h1 \\\n"
    "    --cron \"interval=60\" --not-before <epoch> --not-after <epoch>\n"
    "rebel-profiler schedule tick <case-id>\n"
    "rebel-profiler hypothesis add <case-id> \"statement\" \\\n"
    "    --criteria '[{\"kind\":\"exists\",...}]'\n"
    "rebel-profiler hypothesis evaluate <hypothesis-id>"
)
pdf.ln(2)

pdf.sub_title("7. Transports: worker plane & browser bridge")
pdf.code(
    "# File-based jobs (3-way handshake over job files): submit -> daemon -> result\n"
    "rebel-profiler worker submit <case-id> <action> <target> -p k v\n"
    "rebel-profiler worker run <case-id> --interval 5\n"
    "rebel-profiler worker status <job-id>\n"
    "\n"
    "# The operator's own browser (load extension/ unpacked in Chrome first):\n"
    "rebel-profiler browser serve <case-id>          # 127.0.0.1:8765, token-gated\n"
    "rebel-profiler browser submit <case-id> https://in.scope/ \\\n"
    "    --extract title,links,forms\n"
    "rebel-profiler browser submit <case-id> <url> \\\n"
    "    --actions '[{\"op\":\"click\",\"selector\":\"#id\"}]' --approved\n"
    "rebel-profiler browser result <job-id>"
)
pdf.ln(2)

pdf.sub_title("8. Self-extension, privileged jobs, detection, complaints")
pdf.code(
    "rebel-profiler forge propose adapter.py \\\n"
    "    --test-cases '[{\"target\":\"h1\",...}]'\n"
    "rebel-profiler forge list\n"
    "rebel-profiler forge register                   # load accepted modules live\n"
    "rebel-profiler system templates                 # whitelisted sudo jobs only\n"
    "rebel-profiler system submit <case-id> pkg-install -p package nmap\n"
    "rebel-profiler detection generate <case-id> canary --name tripwire1\n"
    "rebel-profiler complaint build <case-id> --agency ic3 --targets h1.target.com"
)
pdf.ln(2)

pdf.sub_title("9. Integrity & maintenance (run before trusting anything)")
pdf.code(
    "rebel-profiler evidence list <case-id>\n"
    "rebel-profiler evidence verify <case-id>        # exit 11 on ANY tamper\n"
    "rebel-profiler audit show <case-id>\n"
    "rebel-profiler audit verify <case-id>\n"
    "rebel-profiler ops backup <case-id> out.zip\n"
    "rebel-profiler ops restore out.zip dest/\n"
    "rebel-profiler ops check <case-id> --repair\n"
    "rebel-profiler ops package rebel-profiler.pyz   # offline zipapp\n"
    "rebel-profiler doctor"
)
pdf.ln(2)

pdf.sub_title("10. Authorized bug-bounty workflow")
pdf.code(
    "# A published program scope IS the authorization document:\n"
    "rebel-profiler bounty import <case-id> scope.csv --program acme\n"
    "rebel-profiler bounty import <case-id> scope.json --program acme --activate\n"
    "rebel-profiler case scope show <case-id>          # what was imported\n"
    "rebel-profiler bounty run <case-id>               # PLAN ONLY (default)\n"
    "rebel-profiler bounty run <case-id> --execute     # scope-enforced web audit\n"
    "rebel-profiler bounty assess <case-id>            # severity + CWE + repro + fix\n"
    "rebel-profiler bounty report <case-id> -o json    # submission-ready\n"
    "\n"
    "# One stated goal runs the whole chain:\n"
    "rebel-profiler bounty auto <case-id> \\\n"
    "    \"find what you can in this scope, test it, and give me a report with real results, no demos\" \\\n"
    "    --verbose --save\n"
    "\n"
    "# Flags:\n"
    "  --no-author       deterministic audit + report only (no LLM script authoring)\n"
    "  --max-scripts N   cap on model-written scripts (default 3; 0 disables)\n"
    "  --max-repair-rounds N  how many times a failing script goes back to the model\n"
    "  --max-assets N / --max-pages N  bounds on the audit\n"
    "  --scheme http|https  scheme used to build seed URLs (default https)\n"
    "  --model <id>      model id for authoring\n"
    "  --save            write the full session JSON into the case's reports/\n"
    "  --verbose         stream each stage to stderr as it runs\n"
    "\n"
    "# Exit 0 when there is at least one reportable finding, 1 when the report is empty,\n"
    "# 2 on a usage/authorization error (e.g. the case is not ACTIVE)."
)
pdf.add_page()

pdf.sub_title("11. Job profiles (--config-file) — pin settings once, reuse forever")
pdf.code(
    "# nightly.toml\n"
    "[llm]\n"
    "tier = \"low\"                 # tier pin (may be tightened by env, never loosened)\n"
    "model = \"Qwen/Qwen3-4B\"      # default model for llm generate/plan/agent auto\n"
    "max_new_tokens = 128         # tighten-only cap\n"
    "\n"
    "[core]\n"
    "actor = \"nightly-agent\"      # audit subject for the job\n"
    "\n"
    "# Usage:\n"
    "rebel-profiler --config-file nightly.toml agent auto <case-id> \"<goal>\"\n"
    "rebel-profiler --config-file nightly.toml llm status\n"
    "\n"
    "# Precedence: built-in tier defaults < profile [llm] < RP_LLM__* env < explicit --tier\n"
    "# Protected security keys stay tighten-only in profiles too."
)
pdf.ln(2)

pdf.sub_title("12. Environment variables")
pdf.code(
    "RP_LLM__TIER              tiny / low / mid / high          default: auto from RAM\n"
    "RP_LLM__MAX_RSS_MB        plane memory ceiling (tighten-only)  per tier\n"
    "RP_LLM__MAX_CONTEXT_TOKENS input cap                         per tier\n"
    "RP_LLM__MAX_NEW_TOKENS    output cap                        per tier\n"
    "RP_LLM__MAX_MODEL_B       model size cap (billions)         per tier\n"
    "RP_LLM__ALLOW_GPU         false = CPU/MPS placement only    default: true\n"
    "RP_LLM__REQUIRE_COMPRESSION true = only compressed loads     per tier\n"
    "RP_LLM__ENGINE            tiny / gguf / native / airllm / external pin  default: auto\n"
    "RP_LLM__MODEL             default model id (or local .gguf path)\n"
    "RP_LLM__GGUF_DIRS         extra directories to search for GGUF files\n"
    "RP_LLM__API_KEY / _FILE   remote provider key (opt-in only)\n"
    "RP_LLM__API_BASE          any OpenAI-compatible /v1 endpoint   default: api.openai.com\n"
    "RP_ACTOR                  acting subject in audit            default: operator\n"
    "RP_API_TOKEN              token for serve gateway"
)
pdf.ln(2)

pdf.sub_title("13. Exit codes worth memorizing")
pdf.code(
    "0   ok\n"
    "2   usage\n"
    "3   config\n"
    "4   permission / policy\n"
    "5   scope\n"
    "7   dependency\n"
    "11  evidence tamper\n"
    "12  state\n"
    "15  model budget"
)
pdf.ln(3)

pdf.note(
    "The one rule (memorize it): The LLM proposes; the system decides. Scope fails "
    "closed; nothing runs without authorization; nothing is claimed without evidence. "
    "Use only on targets you are explicitly authorized to assess."
)
pdf.add_page()

# ── SECTION 7: KNOWLEDGE LAYER ────────────────────────────────────────────
pdf.section_title("7.  Knowledge Layer")
pdf.body(
    "The knowledge layer is the structured context the LLM planner consumes. It is "
    "not a documentation dump — it is wired to capability classes, authorization "
    "gates, Kali tooling, and defensive counterparts. Content is original to this "
    "project; it mirrors standard curriculum coverage without reproducing any external "
    "text."
)
pdf.ln(1)
pdf.code(
    "rebel-profiler knowledge domains                # list all 15 domains\n"
    "rebel-profiler knowledge search \"zone transfer\"  # find topics by keyword\n"
    "rebel-profiler knowledge tools scanning          # Kali tools mapped to capabilities\n"
    "rebel-profiler knowledge planner-context --output json  # machine-readable context"
)
pdf.ln(2)
pdf.body("The 15 domains:")
pdf.ln(1)
domains = [
    "1.  Foundations", "2.  Networking", "3.  Security fundamentals",
    "4.  Footprinting", "5.  Scanning", "6.  Enumeration",
    "7.  System access", "8.  Malware analysis", "9.  Sniffing / spoofing",
    "10. Social engineering", "11. Wireless", "12. Attack & defense",
    "13. Cryptography", "14. Architecture", "15. Cloud / IoT",
]
for d in domains:
    pdf.bullet(d)
pdf.ln(2)
pdf.body("Each domain carries topics, techniques, and glossary terms. The planner context emits all of this machine-readably so any LLM frontend can consume it without needing to read the source tree.")
pdf.add_page()

# ── SECTION 8: INTEL PLANE ─────────────────────────────────────────────────
pdf.section_title("8.  Intel Plane (Phase 2+)")
pdf.body(
    "The intel/ plane turns executed, policy-gated collection into claims with "
    "provenance — never bare facts. Every claim carries: the source it came from, "
    "a confidence score computed from that source's deterministic score, and the "
    "evidence blob that backs it."
)
pdf.ln(1)

pdf.sub_title("Source registry")
pdf.body(
    "Every source carries a deterministic admiralty-style score: reliability grade "
    "(A-E), freshness decay (30-day half-life), and independence. The combined score "
    "uses a versioned weighted mean — not an LLM opinion. You can score one source "
    "or list them all."
)
pdf.code(
    "rebel-profiler intel sources                     # list all registered sources\n"
    "rebel-profiler intel sources dns.authoritative   # score one source"
)
pdf.ln(2)

pdf.sub_title("Claim ledger")
pdf.body(
    "Confidence is computed, not asserted. Independent corroboration from separate "
    "sources upgrades a claim to corroborated. Cross-domain contradictions demote the "
    "lower-confidence side to contradicted — but both sides stay in the ledger, never "
    "deleted. You can query claims by case and optionally by subject."
)
pdf.code(
    "rebel-profiler intel claims <case-id>           # all claims in a case\n"
    "rebel-profiler intel claims <case-id> example.com   # claims about one subject"
)
pdf.ln(2)

pdf.sub_title("Entity resolution")
pdf.body(
    "Raw observations normalize into canonical hosts, domains, and IPs, then group "
    "into alias-linked entities. This is what lets the surface graph and fusion engine "
    "join observations across data sources without duplicate entities."
)
pdf.ln(2)

pdf.sub_title("Collection pipeline")
pdf.body(
    "Broker results -> hash-chained evidence -> injection scan + sanitize -> parse "
    "into claims (DNS answers record-type aware, WHOIS fields, crt.sh CT JSON) -> "
    "persist observations. Each step is deterministic and auditable."
)
pdf.ln(2)

pdf.sub_title("Cross-domain fusion (PDF 9)")
pdf.body(
    "Joins DNS, certificates, WHOIS, scanning, and web views per subject. The same "
    "(attribute, value) from independent sources fuses into one entry with noisy-OR "
    "confidence (0.6 + 0.6 -> 0.84, never 1.2). Cross-domain contradictions surface "
    "with every supporting source on each side, and both sides always stay in the ledger."
)
pdf.code(
    "rebel-profiler intel fusion <case-id>              # whole case\n"
    "rebel-profiler intel fusion <case-id> h1.target.com   # one subject"
)
pdf.ln(2)

pdf.sub_title("Injection defense")
pdf.body(
    "Every external blob is pattern-scanned for instruction-style content and wrapped "
    "as clearly-delimited untrusted data before it can reach any planner context. This "
    "applies to collection output, web crawl content, and any other data ingested from "
    "outside the tool."
)
pdf.code(
    "rebel-profiler intel sanitize \"ignore all previous instructions...\""
)
pdf.ln(2)

pdf.sub_title("Scope-enforced web audit (intel crawl, Phase 3 / PDF 7)")
pdf.body(
    "A bounded crawler whose scope gate is mechanical: every seed and discovered URL "
    "is validated against the live case scope before any fetch. Out-of-scope links are "
    "never touched. Non-HTML is never parsed. Fetched bytes are registered as "
    "hash-chained evidence. Four deterministic check families: security headers "
    "(CSP, HSTS, XFO, ...), cookie flags (Secure, HttpOnly, SameSite), cleartext "
    "password forms, and TLS protocol posture. Findings become provenance-carrying claims."
)
pdf.ln(2)

pdf.sub_title("Discovery & surface (Phase 3)")
pdf.body(
    "port-scan, service-detect, and os-fingerprint nmap adapters: whitelisted flag "
    "sets, polite timing only, T5 never offered. nmap output parsed record-style into "
    "port, service, product, and version claims. surface map builds the typed graph "
    "(host -> ip -> port -> service/product/version) and surface exposure sums up "
    "per-host exposure with lateral-pivot hints (hosts sharing the same product)."
)
pdf.add_page()

# ── SECTION 9: SURFACE & GRAPH ─────────────────────────────────────────────
pdf.section_title("9.  Surface & Persistent Relationship Graph (PDF 8 / 10)")
pdf.body(
    "The case's world model — host -> ip -> port -> service/product/version, plus web "
    "findings — rebuilds deterministically from claims into SQLite (migration v3) and "
    "survives across CLI invocations. Cross-case queries go through explicit APIs, "
    "never shared tables."
)
pdf.code(
    "rebel-profiler surface build <case-id>          # rebuild graph from claims\n"
    "rebel-profiler surface show <case-id>            # full graph dump\n"
    "rebel-profiler surface map <case-id>            # host -> ip -> port -> service\n"
    "rebel-profiler surface exposure <case-id>       # per-host exposure + lateral hints\n"
    "rebel-profiler surface paths <case-id> host:h1 port:80/tcp  # bounded BFS paths\n"
    "rebel-profiler surface related <case-id> host:h1 # shared-neighbor peers"
)
pdf.ln(2)
pdf.body(
    "Queries cover neighbors in both directions, bounded BFS paths, and "
    "shared-neighbor peers for lateral movement analysis. The graph is rebuilt from "
    "claims every time — it is a view, not a separate store, so it stays consistent "
    "with the claim ledger by construction."
)
pdf.add_page()

# ── SECTION 10: RBAC, WORKFLOWS, SCHEDULER, TRANSPORTS ────────────────────
pdf.section_title("10.  Operations Stack (Phases 4-6)")
pdf.body(
    "Beyond the six-gate broker and intel plane, the tool ships the full operations "
    "stack. Each piece is gated, evidenced, and auditable. Nothing here bypasses the "
    "six gates — it orchestrates them."
)
pdf.ln(1)

ops = [
    ("RBAC & approvals",
     "Per-case owner/operator/viewer roles enforced in the broker before every other "
     "gate. Headless approval-gated actions land in a durable queue (approval list / "
     "decide / run) whose stored argv is re-validated against live scope and policy at "
     "decision time."),
    ("Hypotheses",
     "State testable statements with deterministic criteria (hypothesis add / evaluate). "
     "Checked against the claim ledger; supported / refuted / untestable verdicts with "
     "per-check provenance."),
    ("Workflows",
     "A human-writable DSL with a resumable DAG runner (workflow create / run / approve / "
     "status). Human approval gates pause the run; every finished step is a checkpoint; "
     "nothing re-executes."),
    ("Scheduler",
     "Authorization-windowed schedules (schedule add / tick). Outside the window nothing "
     "fires; expired windows auto-expire."),
    ("Self-repair agent (agent work)",
     "The LLM keeps a persisted work list; every failure becomes a structured error-log "
     "entry with a fix hint; the planner revises and retries (bounded); scope/policy "
     "blocks are never auto-retried; the session ends with concrete suggestions awaiting "
     "the operator's decision."),
    ("File-based worker plane (worker submit / run / list)",
     "TCP-style three-way handshake over job files: SYN (job envelope with checksum) -> "
     "SYN-ACK (ack file, state=running) -> ACK (result file). The LLM writes job files "
     "and goes quiet (freeing RAM/GPU) while the 5-second daemon executes everything "
     "through the same six gates; results are idempotent and tamper-verified."),
    ("Browser bridge + extension (browser submit / serve / result)",
     "The LLM uses the operator's own browser: scope-checked, token-gated localhost "
     "bridge (127.0.0.1:8765). Read-only extraction AND user-like interaction "
     "(click/type/scroll/submit — form submission is approval-gated) with per-step "
     "action logs; failures produce structured error logs the LLM reads, fixes, and "
     "re-submits."),
    ("Privileged system jobs (system submit / run / templates)",
     "whitelisted sudo job templates only: install a package, start/stop a service, "
     "monitor mode. Validated params, approval-queued, audited, evidence-captured. "
     "There is no free-form shell path anywhere."),
    ("Feature Forge (forge propose / list / register)",
     "vibe-coding inside the law: when the tool lacks a capability, the LLM writes its "
     "own adapter module. A deterministic static gate rejects shell/os/socket/eval/open "
     "reach; a subprocess sandbox test exercises the argv builder; accepted modules are "
     "HMAC-signed and registerable. The LLM grows the tool itself; the system stays in "
     "control."),
    ("Detection engineering (detection generate / kinds / list)",
     "Benign, industry-standard artifacts only: EICAR AV test files, canary tripwires, "
     "IoC bundles, and deterministic YARA rulesets — all hash-chained as evidence. No "
     "functional malware is ever generated; the module is the blue-team counterpart of "
     "the malware-analysis domain."),
    ("Complaint packages (complaint build / list)",
     "FIA CCW / IC3 / CERT-ready bundles: re-verified evidence chain, IoC set, audit "
     "timeline, narrative, and a verifiable bundle hash. Built for handing a case to "
     "the authorities."),
    ("Search, events, API, ops",
     "FTS5 search over claims and observations; structured events with HMAC-signed "
     "webhooks; a read-only token-gated API gateway (serve); manifest-verified "
     "backup/restore, offline .pyz packaging, and self-check with deterministic repair "
     "(ops)."),
]

for title, desc in ops:
    pdf.sub_title(title)
    pdf.body(desc)
    pdf.ln(1)
pdf.add_page()

# ── SECTION 11: FOLDER MAP ─────────────────────────────────────────────────
pdf.section_title("11.  Folder Map: Every Directory and What It Owns")
pdf.body(
    "When you come back to this folder and ask the AI to read sub-folders, this is the "
    "map it should use to orient itself. The top-level layout:"
)
pdf.ln(1)
pdf.code(
    "rebel profiler/\n"
    "  ARCHITECTURE.md          Full seven-plane model + request lifecycle + trust boundaries\n"
    "  CHEATSHEET.md            Every daily-use command on one page\n"
    "  README.md                Overview, quickstart, full feature list, AirLLM-mode, engines\n"
    "  ROADMAP.md               Shipped checklist + future phases\n"
    "  RELEASE_NOTES_v1.x.x.md  Release history (v1.1.0 -> v1.3.1)\n"
    "  LICENSE                  MIT\n"
    "  pyproject.toml           Build config: name, version, optional deps, CLI entry point\n"
    "  .git/                    Git history\n"
    "  .github/                 CI workflow + templates\n"
    "  docs/\n"
    "  |   SETUP.md             One-time setup end-to-end on a fresh machine\n"
    "  completions/\n"
    "  |   rebel-profiler.bash  Bash completion script\n"
    "  |   _rebel-profiler      Zsh completion script\n"
    "  extension/               Chrome extension for the browser bridge (load unpacked)\n"
    "  dphn/                    (sub-module)\n"
    "  rebel_profiler/          Main Python package\n"
    "  |   __init__.py          Version + app name/description\n"
    "  |   cli/\n"
    "  |   |   main.py          CLI entry point: rebel-profiler -> main()\n"
    "  |   |   context.py       Shared CLI context (case loading, output mode, config)\n"
    "  |   |   __init__.py\n"
    "  |   core/\n"
    "  |   |   config.py        Layered config; protected security keys (tighten-only)\n"
    "  |   |   redact.py        Conservative redaction on every output path\n"
    "  |   |   ...\n"
    "  |   security/\n"
    "  |   |   scope.py         Fail-closed authorization boundary\n"
    "  |   |   risk.py          Versioned, deterministic risk classification\n"
    "  |   |   policy.py          Allow -> confirm -> approve -> deny\n"
    "  |   |   ...\n"
    "  |   execution/\n"
    "  |   |   broker.py        Execution broker: adapter registry + six-gate sequence\n"
    "  |   |   tool_exec.py     Whitelisted binaries, validated argv, scope-checked args,\n"
    "  |   |                     approval-gated dispatch\n"
    "  |   |   ...\n"
    "  |   evidence/\n"
    "  |   |   store.py         Content-addressed evidence ledger (SHA-256, hash-chained)\n"
    "  |   |   audit.py         Hash-linked audit chain; verify recomputes hashes\n"
    "  |   |   ...\n"
    "  |   intel/\n"
    "  |   |   claims.py        Claim ledger: confidence computed, not asserted\n"
    "  |   |   injection.py     Deterministic injection scan + sanitization\n"
    "  |   |   sources.py       Source registry with admiralty-style scoring\n"
    "  |   |   fusion.py        Cross-domain fusion: noisy-OR corroboration, contradictions\n"
    "  |   |   collection.py    Broker results -> evidence -> parsed claims -> observations\n"
    "  |   |   crawl.py         Scope-enforced web audit (security headers, cookies,\n"
    "  |   |                     cleartext forms, TLS posture)\n"
    "  |   |   ...\n"
    "  |   agent/\n"
    "  |   |   (agent plane: goal -> proposals -> broker gates -> claims -> report)\n"
    "  |   |   forge.py         Feature Forge: LLM writes its own adapter modules\n"
    "  |   |   repair.py         Self-repair: LLM reviser reads errors + fix hints\n"
    "  |   |   ...\n"
    "  |   llm/\n"
    "  |   |   (LLM plane: 5 engines, AirLLM-mode, script authoring, daemon)\n"
    "  |   |   ...\n"
    "  |   knowledge/\n"
    "  |   |   15 domains, 81 topics, 109 techniques, 121 glossary terms\n"
    "  |   |   capability classes, Kali tool map, planner context\n"
    "  |   |   ...\n"
    "  |   storage/\n"
    "  |   |   SQLite per case (physical isolation)\n"
    "  |   |   ...\n"
    "  |   browser/\n"
    "  |   |   Browser bridge: submit / serve / result\n"
    "  |   |   ...\n"
    "  |   __pycache__/         Compiled bytecode (regenerate after edits)\n"
    "  rebel_profiler.egg-info/  pip install metadata\n"
    "  .venv/                   Virtualenv (dev + optional engine deps)\n"
    "  .pytest_cache/           pytest cache\n"
    "  tests/                   Full test suite (pytest tests/ -q)\n"
    "  tools/                   Development / helper scripts\n"
    "  pdf 1 .. pdf 20          Build specification PDFs (25MB+ each, binary)\n"
)
pdf.ln(2)
pdf.note(
    "For Hermes-agent-style orientation, the AI should read these first (in order):\n"
    "  1. README.md (what the tool is + full feature list)\n"
    "  2. ARCHITECTURE.md (seven planes + request lifecycle + trust boundaries)\n"
    "  3. CHEATSHEET.md (every command, one page)\n"
    "  4. pyproject.toml (version, entry point, optional deps)\n"
    "  5. rebel_profiler/__init__.py (app name + version)\n"
    "  6. Then dive into the plane directories that match the task at hand."
)
pdf.add_page()

# ── SECTION 12: QUICK START CHECKLIST ─────────────────────────────────────
pdf.section_title("12.  Quick-Start Checklist (first 5 minutes)")
pdf.body("Run these in order. They take you from zero to a working case with scope enforced.")
pdf.ln(1)
pdf.code(
    "# 1. Install (from the project root):\n"
    "cd <repo-root>\n"
    "pip install -e .\n"
    "rebel-profiler doctor                     # verify everything is healthy\n"
    "\n"
    "# 2. (Optional) install an LLM engine if you have checkpoints:\n"
    "pip install 'rebel-profiler[gguf]'        # or [native], or [airllm]\n"
    "rebel-profiler llm setup                  # hardware-aware guidance\n"
    "rebel-profiler llm local                  # what is already on disk\n"
    "\n"
    "# 3. Create a case:\n"
    "rebel-profiler case create \"Lab Assessment\" \"internal authorized test\"\n"
    "#    -> note the case-id it prints\n"
    "\n"
    "# 4. Define authorized scope (include + exclusions):\n"
    "rebel-profiler case scope add <case-id> \"*.lab.example.test\" --note \"authorized lab\"\n"
    "rebel-profiler case scope add <case-id> \"admin.lab.example.test\" --exclude\n"
    "\n"
    "# 5. Activate the case (scope enforcement goes live):\n"
    "rebel-profiler case activate <case-id>\n"
    "\n"
    "# 6. Verify scope is working:\n"
    "rebel-profiler scope-check <case-id> host1.lab.example.test\n"
    "rebel-profiler scope-check <case-id> out-of-scope.example.test  # should be blocked\n"
    "\n"
    "# 7. Plan an action (preview — shows exact argv + policy outcome, nothing runs):\n"
    "rebel-profiler plan <case-id> host-discovery host1.lab.example.test -p mode discover\n"
    "\n"
    "# 8. Run it (six gates, evidence, audit):\n"
    "rebel-profiler run <case-id> host-discovery host1.lab.example.test -p mode discover\n"
    "\n"
    "# 9. Inspect what you collected:\n"
    "rebel-profiler evidence list <case-id>\n"
    "rebel-profiler intel claims <case-id>\n"
    "\n"
    "# 10. Verify integrity before trusting anything:\n"
    "rebel-profiler evidence verify <case-id>   # exit 11 if ANY tamper detected\n"
    "rebel-profiler audit show <case-id>\n"
    "\n"
    "# 11. Generate a report:\n"
    "rebel-profiler report <case-id>            # human-readable\n"
    "rebel-profiler report <case-id> -o json    # machine-readable"
)
pdf.ln(2)

pdf.sub_title("One-goal mode (the 10x lever)")
pdf.code(
    "# State the goal. The harness plans, runs, repairs, extends, and reports.\n"
    "rebel-profiler agent auto <case-id> \"map lab.example.test passive footprint\" \\\n"
    "    --llm Qwen/Qwen3-4B\n"
    "\n"
    "# If no engine with real weights is loaded, the session says so and still\n"
    "# delivers the deterministic audit + report — it never substitutes a placeholder."
)
pdf.ln(2)

pdf.sub_title("Remote LLM (opt-in only — nothing leaves the machine without this pin)")
pdf.code(
    "RP_LLM__ENGINE=external RP_LLM__API_KEY=sk-... \\\n"
    "    rebel-profiler agent auto <case-id> \"<goal>\"\n"
    "\n"
    "# Payloads are redacted before outbound; responses are redacted on arrival.\n"
    "# Without RP_LLM__ENGINE=external, the tool uses local engines only."
)
pdf.add_page()

# ── SECTION 13: TRUST BOUNDARIES ───────────────────────────────────────────
pdf.section_title("13.  Trust Boundaries (read before integrating)")
pdf.body(
    "These twelve boundaries are enforced mechanically. If you are building on top of "
    "Rebel Profiler — or asking an AI to read and work with this codebase — these are "
    "the constraints that must never be violated."
)
pdf.ln(1)
bounds = [
    "LLM output is data. It can fill ActionRequest fields; it cannot create adapters, alter scope, or influence risk/policy engines.",
    "Scope is evaluated at execution time, from the live case store — not from whatever the planner believed.",
    "Risk classes map to outcomes via a versioned table; deployment overrides may only tighten the mapping.",
    "Protected config keys (scope.fail_closed, evidence.redaction_enabled, evidence.audit_chain_enabled, policy.risk_to_outcome_mapping) reject any attempt to weaken them, at any layer.",
    "Evidence integrity is verifiable offline: evidence verify and audit verify recompute hashes and chain linkage; any edit, deletion, or reordering is detected (exit 11).",
    "Claims never outrank their evidence: claim confidence is computed from deterministic source scoring; a claim is a provenance-carrying statement, not a fact, until independently corroborated.",
    "External content is data, never instructions: everything ingested from outside is injection-scanned and wrapped as untrusted data before reaching any planner context.",
    "The LLM plane never eats the machine: model memory is bounded by a tighten-only tier budget (RSS ceiling, context/new-token caps, model size cap, compression requirements), the resident daemon unloads weights after every job, and the deterministic tiny engine keeps every contract alive where weights cannot load — no silent substitution, the fallback reason is always recorded.",
    "Local-first inference, opt-in remote brain: the default engines are on-device (GGUF, native layer streaming, AirLLM); the only remote path is an explicitly pinned, OpenAI-compatible provider whose payloads and responses are redacted. Case data reaches any model exclusively through bounded, redacted data packs delivered over the checksummed job-file handshake — the LLM never opens the database. No engine ever downloads a model uninvited.",
    "One goal never widens authority: bounty auto orchestrates existing gated steps, it does not bypass them. The case must be ACTIVE, every asset is re-validated against live scope before it is touched, scripts pass the same gate as anything a human submits, and no finding is reported without hash-chained evidence behind it. A stage that cannot run honestly (no engine with real weights) is reported as skipped, never faked.",
    "Model-written code is data, not authority: a script the LLM authors passes the same deterministic static gate and subprocess sandbox as a human-written one, reaches no more than an adapter may, and lands as hash-chained evidence. Nothing a model writes can widen its own reach.",
    "A program's published scope is authorization: bug-bounty scope import writes ordinary scope entries — the same fail-closed engine gates every subsequent check. Ineligible assets become exclusions, non-host assets are skipped with a reason, and nothing is special-cased.",
]

for i, b in enumerate(bounds, 1):
    pdf.set_font("Helvetica","B",9)
    pdf.set_text_color(20,80,160)
    pdf.cell(8, 4.8, f"{i}.")
    pdf.set_font("Helvetica","",9)
    pdf.set_text_color(40,40,40)
    pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin - 8, 4.8, b)
    pdf.ln(1)
pdf.ln(2)
pdf.add_page()

# ── SECTION 14: AIRLLM DEEP DIVE ───────────────────────────────────────────
pdf.section_title("14.  AirLLM-Mode Deep Dive (LLM plane)")
pdf.body(
    "AirLLM-mode is what lets Rebel Profiler run 70B-class models on low-end hardware. "
    "It wraps the full AirLLM feature set behind a tighten-only hardware budget guard. "
    "GPU is optional — CPU-only and Apple-silicon (MPS) placement both work."
)
pdf.ln(1)

pdf.sub_title("How layer-wise streaming keeps RAM tiny")
pdf.body(
    "One transformer layer is resident at a time. The rest are streamed from disk as "
    "needed. Combined with 4/8-bit block-wise compression (CUDA only — on CPU-only boxes "
    "the guard refuses compression up front because AirLLM's bitsandbytes path quantizes "
    "on-device; uncompressed layer streaming already keeps RAM tiny), this means a model "
    "that would normally need tens of gigabytes of RAM can run on a machine with a "
    "fraction of that. Verified live: Qwen2.5-0.5B, ~816MB peak RSS, coherent generation, "
    "clean unload."
)
pdf.ln(1)

pdf.sub_title("What AirLLM supports")
pdf.code(
    "AutoModel across: Llama / Qwen / DeepSeek / Mistral / Phi / Gemma\n"
    "Prefetching, profiling, layer-shards path, delete_original, hf_token\n"
    "GPU optional — CPU / MPS placement automatic (AirLLM's device= is set explicitly,\n"
    "  never the cuda:0 default)\n"
    "Tighten-only env caps: RP_LLM__TIER, RP_LLM__MAX_RSS_MB,\n"
    "  RP_LLM__MAX_CONTEXT_TOKENS, RP_LLM__MAX_NEW_TOKENS,\n"
    "  RP_LLM__MAX_MODEL_B, RP_LLM__ALLOW_GPU, RP_LLM__REQUIRE_COMPRESSION\n"
    "  (any of these can never loosen a tier)"
)
pdf.ln(2)

pdf.sub_title("The hardware budget guard")
pdf.body(
    "Before any model loads, the guard checks the machine's tier (auto-derived from RAM "
    "by default, or pinned via RP_LLM__TIER or --tier). Each tier has caps on RSS, "
    "context tokens, new tokens, and model size. If a model would exceed the tier's "
    "caps, the guard refuses to load it and records the reason. The deterministic tiny "
    "engine keeps every downstream contract alive in that case — no hallucinated output, "
    "ever. The planner only emits proposals through the same no-fake-adapter gate as every "
    "other source, and the resident daemon unloads the model after every job so the machine "
    "goes quiet again."
)
pdf.ln(2)

pdf.sub_title("The five engines (one interface, none downloads uninvited)")
pdf.code(
    "gguf      one GGUF file (llama.cpp / Ollama / LM Studio exports)  needs: llama-cpp-python\n"
    "native    HF safetensors checkpoints already in the local cache           needs: torch\n"
    "airllm    AirLLM layer streaming, AutoModel across families                needs: airllm + torch\n"
    "external  an OpenAI-compatible endpoint, explicitly pinned                needs: API key\n"
    "tiny      nothing — deterministic fallback, never hallucinates            built in\n"
    "\n"
    "rebel-profiler llm setup   prints this machine's tier + exact install command for each\n"
    "rebel-profiler llm local   lists what is already on disk\n"
    "rebel-profiler llm generate \"...\" --model /path/to/model.gguf   use a specific GGUF\n"
    "rebel-profiler llm generate \"...\" --local                       best local model that fits"
)
pdf.ln(2)

pdf.sub_title("GGUF discovery")
pdf.body(
    "Bounded and offline. Searches RP_LLM__GGUF_DIRS, the project tree, and the usual "
    "llama.cpp / Ollama / LM Studio / HF roots. The quantization tag is read from the "
    "filename (Q4_K_S -> 4-bit compressed, F16 -> uncompressed) so the budget guard sees "
    "the model's real weight format. Name matching is deliberately conservative: a local "
    "checkpoint is never silently substituted for a different model you asked for."
)
pdf.ln(2)

pdf.sub_title("Script authoring (llm script)")
pdf.body(
    "llm script author <goal> has the model write a run(payload) script. The file is "
    "stored, not executed. The daemon then runs it through the static AST gate and a "
    "subprocess sandbox, and writes the actual returned value plus stdout as evidence. "
    "When a script fails or is rejected, llm script retry <id> feeds the error and the "
    "tool's fix hint back to the model and re-submits the corrected source — through the "
    "same gate. Nothing a model writes ever gets more reach than a human-written script."
)
pdf.add_page()

# ── SECTION 15: HOW TO COME BACK ───────────────────────────────────────────
pdf.section_title("15.  How to Come Back to This Folder Later")
pdf.body(
    "This is the part that matters for the Hermes-agent-style workflow. When you return "
    "to this folder days or weeks later and ask an AI to read the sub-folders and start "
    "working, this is the sequence it should follow to orient itself without re-reading "
    "the entire codebase every time."
)
pdf.ln(1)

pdf.sub_title("Step 1 — Read the guide first")
pdf.body(
    "This PDF (Rebel_Profiler_Hermes_Interface_Guide.pdf) is the orientation document. "
    "If it exists in the folder, read it first. It covers the architecture, every command, "
    "the six gates, the Hermes-style interface, and the folder map. After reading it, the "
    "AI knows what the tool is, how it works, and where to look for specific things."
)
pdf.ln(1)

pdf.sub_title("Step 2 — If the guide is missing, fall back to the documented order")
pdf.body("Read these files in this exact order. They are the canonical orientation sequence:")
pdf.ln(1)
pdf.code(
    "1. README.md            — what the tool is, full feature list, quickstart, AirLLM-mode, engines\n"
    "2. ARCHITECTURE.md      — seven planes, request lifecycle, trust boundaries, data model\n"
    "3. CHEATSHEET.md        — every command in daily-use order, one page\n"
    "4. pyproject.toml       — version (1.3.1), CLI entry point (rebel_profiler.cli.main:main),\n"
    "                          optional deps (gguf / native / airllm / airllm-compression)\n"
    "5. rebel_profiler/__init__.py  — APP_NAME, APP_DESCRIPTION, __version__\n"
    "6. docs/SETUP.md        — one-time setup end-to-end on a fresh machine\n"
    "7. RELEASE_NOTES_v1.3.1.md  — what changed in the current release"
)
pdf.ln(2)

pdf.sub_title("Step 3 — Pick the plane that matches the task")
pdf.body(
    "Once oriented, the AI should go directly to the plane directory that owns the task:"
)
pdf.ln(1)
pdf.code(
    "Task: run a security operation, gate actions, execute tools\n"
    "  -> execution/broker.py  (six-gate sequence, adapter registry)\n"
    "  -> security/            (scope.py, risk.py, policy.py)\n"
    "  -> core/redact.py       (secrets never leak)\n"
    "\n"
    "Task: plan with an LLM, run an agent session, repair failures\n"
    "  -> agent/              (forge.py, repair.py, agent plane)\n"
    "  -> llm/                (five engines, AirLLM-mode, script authoring, daemon)\n"
    "\n"
    "Task: collect intel, build claims, fuse across sources, surface graph\n"
    "  -> intel/              (claims.py, sources.py, fusion.py, collection.py, crawl.py,\n"
    "                          injection.py)\n"
    "  -> knowledge/          (15 domains, topics, techniques, glossary, capability classes)\n"
    "  -> storage/            (SQLite per case, graph tables)\n"
    "\n"
    "Task: bug-bounty workflow, bounty auto, scope import\n"
    "  -> intel/              (bounty triage, scope import from CSV/JSON)\n"
    "  -> agent/              (agent auto / bounty auto share the same pipeline)\n"
    "\n"
    "Task: CLI commands, output modes, config, doctor\n"
    "  -> cli/main.py         (entry point)\n"
    "  -> cli/context.py      (shared CLI context)\n"
    "  -> core/config.py      (layered config, protected keys)\n"
    "\n"
    "Task: evidence integrity, audit trail, backup/restore\n"
    "  -> evidence/           (store.py, audit.py)\n"
    "  -> ops                 (backup, restore, check, package)\n"
    "\n"
    "Task: browser bridge, extension\n"
    "  -> browser/            (submit, serve, result)\n"
    "  -> extension/          (Chrome extension, load unpacked)"
)
pdf.ln(2)

pdf.sub_title("Step 4 — Use the CLI to verify, not just read")
pdf.body(
    "After reading the code, the AI should use rebel-profiler doctor and the relevant "
    "CLI commands to verify its understanding against the live tool. The CLI is the "
    "ground truth — the code explains how it works, but the CLI shows what it actually "
    "does. Example: after reading execution/broker.py, run rebel-profiler plan <case-id> "
    "<action> <target> --dry-run to see the six-gate output and the exact argv."
)
pdf.ln(2)

pdf.sub_title("Step 5 — What to do when the task needs a capability that does not exist")
pdf.body(
    "This is where Feature Forge matters. If the AI finds that the tool lacks a capability "
    "needed for the task, it should not invent a shell escape hatch. It should use "
    "forge propose to write a new adapter module, then forge register to load it after "
    "the static gate and sandbox pass. The LLM grows the tool; the system stays in control. "
    "If the AI does not have an LLM engine loaded, it should say so and skip authoring — "
    "the deterministic half of the tool still works for everything else."
)
pdf.add_page()

# ── APPENDIX ───────────────────────────────────────────────────────────────
pdf.section_title("Appendix A: Output Modes (PDF 3 contract)")
pdf.body("Every command supports --output human|json|jsonl|csv.")
pdf.code(
    "rebel-profiler case list -o json     # pretty JSON\n"
    "rebel-profiler case list -o jsonl    # one JSON object per line\n"
    "rebel-profiler case list -o csv      # flattened CSV\n"
    "\n"
    "Errors are structured in every mode: what happened / why / next action,\n"
    "with a documented exit code."
)
pdf.ln(2)

pdf.section_title("Appendix B: Accepted Scope Input Formats")
pdf.body(
    "HackerOne-style JSON ({\"data\": [{\"attributes\": ...}]}), CSV export, or a plain "
    "one-target-per-line list. Prefix with ! or - for exclusions, # for comments. "
    "Non-host assets (source repos, app-store IDs, ASNs) are skipped with a reason. "
    "Assets the program marks ineligible are imported as exclusions."
)
pdf.ln(2)

pdf.section_title("Appendix C: Deterministic Planner (what happens when no LLM is loaded)")
pdf.body(
    "The agent plane ships with a deterministic passive-first planner today. It emits "
    "validated proposals through the same no-fake-adapter gate as any LLM. Any LLM can "
    "plug in by emitting the same Proposal objects. When no engine with real weights is "
    "loaded, the session says so and returns a structured refusal — never a hallucinated "
    "session. The deterministic audit and report still work in that case."
)
pdf.ln(2)

pdf.section_title("Appendix D: Spellings and Conventions to Remember")
pdf.code(
    " keiseu    = case     (case create, case activate, case scope add, case list, case close)\n"
    " mokpyo    = goal     (agent auto <case-id> \"<goal>\")\n"
    " beomwi    = scope    (case scope add, scope-check, scope fails closed)\n"
    " jeunggeo  = evidence (SHA-256, hash-chained, evidence verify -> exit 11 on tamper)\n"
    " gamsa     = audit    (hash-linked audit chain, audit verify)\n"
    " jujang    = claims   (confidence computed, not asserted; provenance-carrying)\n"
    " seungin   = approval (allow -> confirm -> approve -> deny; headless queue)\n"
    " eodeopteo = adapter  (declared params, whitelisted flag sets, no shell)\n"
    " riseukeu  = risk     (low / moderate / high / critical, versioned rules)\n"
    " eo-el-el  = AirLLM   (layer-wise streaming, CPU/MPS, hardware budget guard)\n"
    " geiteu    = gate     (six gates, all must pass before execution)\n"
)
pdf.ln(3)

pdf.set_font("Helvetica","I",9)
pdf.set_text_color(100,100,100)
pdf.multi_cell(0, 4.8,
    "End of guide. Version 1.3.1. MIT License. Made by REBEL.\n"
    "Use only on systems you are explicitly authorized to assess."
)

pdf.output(OUTPUT)
print(f"PDF written: {OUTPUT}")
print(f"Pages: {pdf.page_no()}")
print(f"Size: {os.path.getsize(OUTPUT)} bytes")
