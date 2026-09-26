"""Intelligence layer (Phase 2): sources, claims, normalization, injection defense.

This layer turns raw OSINT/recon output into *claims with provenance and
confidence*. It never executes anything and never authorizes anything:

  * :mod:`rebel_profiler.intel.sources`     — source registry + reliability scoring
  * :mod:`rebel_profiler.intel.normalize`   — target/entity normalization + resolution
  * :mod:`rebel_profiler.intel.injection`   — prompt-injection defenses for external content
  * :mod:`rebel_profiler.intel.claims`      — claim ledger: confidence propagation
  * :mod:`rebel_profiler.intel.collection`  — evidence-backed collection pipeline

Design laws carried over from Phase 1:
  * unknowns stay unknown (a claim is never a fact),
  * every observation carries source, method, time and evidence linkage,
  * untrusted external content is data, never instructions.
"""

from .claims import Claim, ClaimLedger, Conflict, fuse_conflicts
from .collection import CollectionPipeline, collect_from_adapter
from .findings import CaseReport, Finding, build_findings, generate_report
from .fusion import FusionConflict, FusionEngine, FusedAttribute, SubjectProfile, noisy_or
from .graphstore import GraphEdge, GraphNode, RelationshipGraphStore
from .injection import injection_report, sanitize_external, scan_injection
from .surface import (
    ExposureMapper,
    SurfaceEdge,
    SurfaceGraph,
    SurfaceNode,
)
from .web import PageAudit, ScopeEnforcedWebAuditor
from .normalize import (
    Entity,
    EntityResolver,
    canonical_domain,
    canonical_hostname,
    normalize_target,
    resolve_entities,
)
from .sources import (
    DEFAULT_SOURCES,
    Source,
    SourceRegistry,
    score_source,
    source_contract,
)

__all__ = [
    "DEFAULT_SOURCES",
    "Claim",
    "ClaimLedger",
    "CollectionPipeline",
    "Conflict",
    "Entity",
    "EntityResolver",
    "Finding",
    "CaseReport",
    "build_findings",   # re-export: cli/main + operator_tools import from here
    "generate_report",  # re-export: cli/main + operator_tools import from here
    "ExposureMapper",
    "SurfaceEdge",
    "SurfaceGraph",
    "SurfaceNode",
    "PageAudit",
    "ScopeEnforcedWebAuditor",
    "FusionConflict",
    "FusionEngine",
    "FusedAttribute",
    "SubjectProfile",
    "GraphEdge",
    "GraphNode",
    "RelationshipGraphStore",
    "noisy_or",
    "Source",
    "SourceRegistry",
    "canonical_domain",
    "canonical_hostname",
    "collect_from_adapter",
    "fuse_conflicts",
    "injection_report",
    "normalize_target",
    "resolve_entities",
    "sanitize_external",
    "scan_injection",
    "score_source",
    "source_contract",
    "collection",
    "findings",
]
