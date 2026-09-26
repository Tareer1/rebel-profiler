"""Persistent relationship graph store (PDF 8/10).

Builds the case's relationship graph from the claim ledger — including web
findings, resolved IPs, ports, services/products/versions and organizational
attributes — persists it into the case's SQLite database (migration v3), and
serves graph queries from storage afterwards:

  * :meth:`RelationshipGraphStore.build` — deterministic rebuild from claims
    (clear + upsert), so the graph is always reproducible from the ledger,
  * :meth:`neighbors` — one-hop relations of a node (out or in),
  * :meth:`paths` — bounded BFS paths between two nodes,
  * :meth:`related` — nodes related by a shared neighbor kind (e.g. hosts
    sharing a product),
  * :meth:`stats` — node/edge counts by kind/relation.

Persistence keeps graphs across CLI invocations and lets future planes
(reporting, workflow) query the case's world model without re-fusing.
"""

from __future__ import annotations

from dataclasses import dataclass

from .claims import ClaimLedger
from .surface import (
    NODE_IP,
    NODE_PORT,
    NODE_VERSION,
    OPEN_PORT,
    RESOLVES_TO,
    RUNS,
    VERSIONED_AS,
)

NODE_WEB_FINDING = "web_finding"
REPORTED_ON = "reported_on"

# single-valued claim kinds that map to graph node kinds
_KIND_TO_NODE = {"ip": NODE_IP}


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: str
    label: str
    confidence: float

    def as_dict(self) -> dict:
        return {"node_id": self.node_id, "kind": self.kind, "label": self.label,
                "confidence": round(self.confidence, 4)}


@dataclass(frozen=True)
class GraphEdge:
    src_id: str
    relation: str
    dst_id: str
    confidence: float

    def as_dict(self) -> dict:
        return {"src": self.src_id, "relation": self.relation, "dst": self.dst_id,
                "confidence": round(self.confidence, 4)}


def _split_port_value(value: str) -> tuple[str, str] | None:
    if ":" in value:
        port, label = value.split(":", 1)
        return port.strip().lower(), label.strip()
    return None


class RelationshipGraphStore:
    """Persists and queries the case relationship graph."""

    def __init__(self, ledger: ClaimLedger, case_id: str, db) -> None:
        self.ledger = ledger
        self.case_id = case_id
        self.db = db

    # -- build -----------------------------------------------------------------

    def build(self) -> dict:
        """Rebuild the persisted graph from the claim ledger (deterministic)."""
        self.db.clear_graph(self.case_id)
        claims = [
            c for c in self.ledger.list(self.case_id)
            if c.state in {"open", "corroborated"}
        ]
        for claim in claims:
            subject = claim.subject
            host_id = f"host:{subject}"
            self.db.upsert_graph_node(
                host_id, self.case_id, kind="host", label=subject,
                confidence=claim.confidence, meta={"claims": [claim.id]},
            )

            if claim.kind == "ip":
                self._attach_ip(host_id, claim)
            elif claim.kind == "port":
                port_id = f"port:{claim.value.strip().lower()}"
                self._ensure_port(port_id, claim)
                self.db.upsert_graph_edge(
                    self.case_id, src_id=host_id, relation=OPEN_PORT,
                    dst_id=port_id, confidence=claim.confidence,
                    meta={"claims": [claim.id]},
                )
            elif claim.kind in {"service", "product"}:
                self._attach_port_child(host_id, claim, claim.kind)
            elif claim.kind == "version":
                self._attach_version(host_id, claim)
            elif claim.kind == "web_finding":
                finding_id = f"{NODE_WEB_FINDING}:{abs(hash(claim.value)) % 10**12:012d}"
                self.db.upsert_graph_node(
                    finding_id, self.case_id, kind=NODE_WEB_FINDING,
                    label=claim.value[:120], confidence=claim.confidence,
                    meta={"claims": [claim.id], "url": claim.notes},
                )
                self.db.upsert_graph_edge(
                    self.case_id, src_id=finding_id, relation=REPORTED_ON,
                    dst_id=host_id, confidence=claim.confidence,
                    meta={"claims": [claim.id]},
                )

        return self.stats()

    def _attach_ip(self, host_id: str, claim) -> None:
        ip_id = f"{NODE_IP}:{claim.value}"
        self.db.upsert_graph_node(
            ip_id, self.case_id, kind=NODE_IP, label=claim.value,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )
        self.db.upsert_graph_edge(
            self.case_id, src_id=host_id, relation=RESOLVES_TO, dst_id=ip_id,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )

    def _ensure_port(self, port_id: str, claim) -> None:
        self.db.upsert_graph_node(
            port_id, self.case_id, kind=NODE_PORT, label=claim.value.strip().lower(),
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )

    def _attach_port_child(self, host_id: str, claim, kind: str) -> None:
        parts = _split_port_value(claim.value)
        if parts is None:
            return
        port_value, label = parts
        port_id = f"{NODE_PORT}:{port_value}"
        self._ensure_port(port_id, claim)
        self.db.upsert_graph_edge(
            self.case_id, src_id=host_id, relation=OPEN_PORT, dst_id=port_id,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )
        child_id = f"{kind}:{label}"
        self.db.upsert_graph_node(
            child_id, self.case_id, kind=kind, label=label,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )
        self.db.upsert_graph_edge(
            self.case_id, src_id=port_id, relation=RUNS, dst_id=child_id,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )

    def _attach_version(self, host_id: str, claim) -> None:
        parts = _split_port_value(claim.value)
        if parts is None:
            return
        port_value, label = parts
        port_id = f"{NODE_PORT}:{port_value}"
        self._ensure_port(port_id, claim)
        self.db.upsert_graph_edge(
            self.case_id, src_id=host_id, relation=OPEN_PORT, dst_id=port_id,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )
        version_id = f"{NODE_VERSION}:{label}"
        self.db.upsert_graph_node(
            version_id, self.case_id, kind=NODE_VERSION, label=label,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )
        self.db.upsert_graph_edge(
            self.case_id, src_id=port_id, relation=VERSIONED_AS, dst_id=version_id,
            confidence=claim.confidence, meta={"claims": [claim.id]},
        )

    # -- queries -----------------------------------------------------------------

    def nodes(self, kind: str | None = None) -> list[GraphNode]:
        rows = self.db.graph_nodes(self.case_id, kind)
        return [
            GraphNode(row["id"], row["kind"], row["label"], row["confidence"])
            for row in rows
        ]

    def edges(self) -> list[GraphEdge]:
        return [
            GraphEdge(row["src_id"], row["relation"], row["dst_id"], row["confidence"])
            for row in self.db.graph_edges(self.case_id)
        ]

    def neighbors(self, node_id: str, relation: str | None = None, *,
                  direction: str = "out") -> list[dict]:
        rows = self.db.graph_neighbors(self.case_id, node_id, relation, direction=direction)
        return [
            {"relation": row["relation"], "node": GraphNode(
                row["id"], row["kind"], row["label"], row["confidence"]).as_dict()}
            for row in rows
        ]

    def paths(self, src_id: str, dst_id: str, *, max_depth: int = 4) -> list[list[str]]:
        """Bounded BFS paths between two persisted nodes."""
        adjacency: dict[str, list[str]] = {}
        for edge in self.edges():
            adjacency.setdefault(edge.src_id, []).append(edge.dst_id)
        results: list[list[str]] = []
        queue: list[tuple[str, list[str]]] = [(src_id, [src_id])]
        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            if current == dst_id and len(path) > 1:
                results.append(path)
                continue
            for nxt in adjacency.get(current, []):
                if nxt in path:
                    continue
                queue.append((nxt, [*path, nxt]))
        return results[:10]

    def related(self, node_id: str, *, via_kind: str | None = None) -> list[dict]:
        """Nodes that share an out-neighbor with *node_id* (peer hosts etc.)."""
        mine = {n["node"]["node_id"] for n in self.neighbors(node_id)}
        peers: dict[str, list[str]] = {}
        for edge in self.edges():
            if edge.dst_id in mine and edge.src_id != node_id:
                src_kind = edge.src_id.split(":", 1)[0]
                if via_kind and src_kind != via_kind:
                    continue
                peers.setdefault(edge.src_id, []).append(edge.dst_id)
        return [{"node_id": peer, "shared": shared} for peer, shared in sorted(peers.items())]

    def stats(self) -> dict:
        node_rows = self.db.graph_nodes(self.case_id)
        edge_rows = self.db.graph_edges(self.case_id)
        by_kind: dict[str, int] = {}
        for row in node_rows:
            by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
        by_relation: dict[str, int] = {}
        for row in edge_rows:
            by_relation[row["relation"]] = by_relation.get(row["relation"], 0) + 1
        return {
            "case_id": self.case_id,
            "nodes": len(node_rows),
            "edges": len(edge_rows),
            "nodes_by_kind": by_kind,
            "edges_by_relation": by_relation,
        }

    def as_dict(self) -> dict:
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "nodes": [n.as_dict() for n in self.nodes()],
            "edges": [e.as_dict() for e in self.edges()],
        }
