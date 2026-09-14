"""Attack-surface construction (Phase 3).

Two pieces:

  * :class:`SurfaceGraph` — a minimal typed node/edge graph over the case's
    claims: ``host -RESOLVES_TO→ ip -OPEN_PORT→ port -RUNS→ service``. Nodes
    are typed, edges directed, and the whole graph is rebuildable from the
    claim ledger at any time (claims are the source of truth; the graph is a
    view).
  * :class:`ExposureMapper` — builds the graph from a ledger and produces an
    exposure summary (per host: open ports, services, products, exposure
    density) plus simple lateral paths (which hosts share services/products —
    the pivot-relevance signal).

Nothing here executes or authorizes; it is a deterministic view over claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .claims import Claim, ClaimLedger

NODE_HOST = "host"
NODE_IP = "ip"
NODE_PORT = "port"
NODE_SERVICE = "service"
NODE_PRODUCT = "product"
NODE_VERSION = "version"

RESOLVES_TO = "resolves_to"
OPEN_PORT = "open_port"
RUNS = "runs"
VERSIONED_AS = "versioned_as"


@dataclass
class SurfaceNode:
    node_id: str
    kind: str
    label: str
    confidence: float = 0.0
    claims: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "kind": self.kind,
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "claims": list(self.claims),
        }


@dataclass(frozen=True)
class SurfaceEdge:
    src: str
    relation: str
    dst: str

    def as_dict(self) -> dict:
        return {"src": self.src, "relation": self.relation, "dst": self.dst}


class SurfaceGraph:
    """Typed directed graph over claim-derived surface elements."""

    def __init__(self) -> None:
        self._nodes: dict[str, SurfaceNode] = {}
        self._edges: list[SurfaceEdge] = []
        self._edge_keys: set[tuple[str, str, str]] = set()

    def add_node(self, kind: str, label: str, *, confidence: float = 0.0,
                 claim_id: str = "") -> SurfaceNode:
        node_id = f"{kind}:{label}"
        node = self._nodes.get(node_id)
        if node is None:
            node = SurfaceNode(node_id=node_id, kind=kind, label=label)
            self._nodes[node_id] = node
        if confidence > node.confidence:
            node.confidence = confidence
        if claim_id and claim_id not in node.claims:
            node.claims.append(claim_id)
        return node

    def add_edge(self, src_id: str, relation: str, dst_id: str) -> None:
        key = (src_id, relation, dst_id)
        if key not in self._edge_keys and src_id in self._nodes and dst_id in self._nodes:
            self._edge_keys.add(key)
            self._edges.append(SurfaceEdge(*key))

    def node(self, node_id: str) -> SurfaceNode | None:
        return self._nodes.get(node_id)

    def nodes(self) -> list[SurfaceNode]:
        return [self._nodes[k] for k in sorted(self._nodes)]

    def edges(self) -> list[SurfaceEdge]:
        return list(self._edges)

    def neighbors(self, node_id: str, relation: str | None = None) -> list[SurfaceNode]:
        out = []
        for edge in self._edges:
            if edge.src == node_id and (relation is None or edge.relation == relation):
                node = self._nodes.get(edge.dst)
                if node:
                    out.append(node)
        return out

    def as_dict(self) -> dict:
        return {
            "nodes": [n.as_dict() for n in self.nodes()],
            "edges": [e.as_dict() for e in self.edges()],
        }


def _port_value(value: str) -> str:
    """Normalize '80/tcp' style values."""
    return value.strip().lower()


def _service_parts(value: str) -> tuple[str, str] | None:
    """Split '80/tcp:http' into ('80/tcp', 'http')."""
    if ":" not in value:
        return None
    port, service = value.split(":", 1)
    return _port_value(port), service.strip()


class ExposureMapper:
    """Builds a SurfaceGraph and exposure summary from a claim ledger."""

    def __init__(self, ledger: ClaimLedger, case_id: str) -> None:
        self.ledger = ledger
        self.case_id = case_id

    def build_graph(self) -> SurfaceGraph:
        graph = SurfaceGraph()
        claims = [
            c for c in self.ledger.list(self.case_id)
            if c.state in {"open", "corroborated"}
        ]
        hosts: dict[str, SurfaceNode] = {}
        ips: dict[str, SurfaceNode] = {}
        ports: dict[str, SurfaceNode] = {}

        def host_node(claim: Claim) -> SurfaceNode:
            node = hosts.get(claim.subject)
            if node is None:
                node = graph.add_node(NODE_HOST, claim.subject,
                                      confidence=claim.confidence, claim_id=claim.id)
                hosts[claim.subject] = node
            else:
                node.claims.append(claim.id)
            return node

        for claim in claims:
            if claim.kind == "ip":
                node = graph.add_node(NODE_IP, claim.value,
                                      confidence=claim.confidence, claim_id=claim.id)
                ips[claim.value] = node
                host = host_node(claim)
                graph.add_edge(host.node_id, RESOLVES_TO, node.node_id)
            elif claim.kind == "port":
                node = graph.add_node(NODE_PORT, _port_value(claim.value),
                                      confidence=claim.confidence, claim_id=claim.id)
                ports[claim.value] = node
                host = host_node(claim)
                graph.add_edge(host.node_id, OPEN_PORT, node.node_id)
            elif claim.kind in {"service", "product"}:
                parts = _service_parts(claim.value)
                if parts is None:
                    continue
                port_value, label = parts
                port_node = graph.add_node(
                    NODE_PORT, _port_value(port_value),
                    confidence=claim.confidence, claim_id=claim.id,
                )
                ports.setdefault(port_value, port_node)
                service_node = graph.add_node(
                    NODE_SERVICE if claim.kind == "service" else NODE_PRODUCT,
                    label, confidence=claim.confidence, claim_id=claim.id,
                )
                host = host_node(claim)
                graph.add_edge(host.node_id, OPEN_PORT, port_node.node_id)
                graph.add_edge(port_node.node_id, RUNS, service_node.node_id)
            elif claim.kind == "version":
                parts = _service_parts(claim.value)
                if parts is None:
                    continue
                port_value, label = parts
                host = host_node(claim)
                port_node = graph.add_node(
                    NODE_PORT, _port_value(port_value),
                    confidence=claim.confidence, claim_id=claim.id,
                )
                graph.add_edge(host.node_id, OPEN_PORT, port_node.node_id)
                version_node = graph.add_node(
                    NODE_VERSION, label, confidence=claim.confidence,
                    claim_id=claim.id,
                )
                graph.add_edge(port_node.node_id, VERSIONED_AS, version_node.node_id)

        # link ports to the ip nodes when we know the resolved ip
        if ips:
            for host_label, host_node in hosts.items():
                ip_node = next((n for ip, n in ips.items()), None)
                if ip_node is not None and ip_node.node_id not in {
                    e.dst for e in graph.edges() if e.src == host_node.node_id
                } and host_label in {c.subject for c in claims if c.kind == "ip"}:
                    graph.add_edge(host_node.node_id, RESOLVES_TO, ip_node.node_id)
        return graph

    def summary(self) -> dict:
        """Per-host exposure summary + lateral-path hints."""
        claims = [
            c for c in self.ledger.list(self.case_id)
            if c.state in {"open", "corroborated"}
        ]
        hosts: dict[str, dict] = {}
        for claim in claims:
            slot = hosts.setdefault(claim.subject, {
                "ips": set(), "ports": set(), "services": {}, "products": {},
                "versions": {},
            })
            if claim.kind == "ip":
                slot["ips"].add(claim.value)
            elif claim.kind == "port":
                slot["ports"].add(_port_value(claim.value))
            elif claim.kind in {"service", "product"}:
                parts = _service_parts(claim.value)
                if parts:
                    port, label = parts
                    bucket = slot["services" if claim.kind == "service" else "products"]
                    bucket.setdefault(port, set()).add(label)
            elif claim.kind == "version":
                parts = _service_parts(claim.value)
                if parts:
                    port, label = parts
                    slot["versions"].setdefault(port, set()).add(label)

        # product → hosts index for lateral paths
        product_hosts: dict[str, set[str]] = {}
        for host, slot in hosts.items():
            for port, labels in slot["products"].items():
                for label in labels:
                    product_hosts.setdefault(label.lower(), set()).add(host)

        summary_rows = []
        for host, slot in sorted(hosts.items()):
            open_ports = sorted(slot["ports"])
            services = {
                port: sorted(labels) for port, labels in sorted(slot["services"].items())
            }
            products = {
                port: sorted(labels) for port, labels in sorted(slot["products"].items())
            }
            versions = {
                port: sorted(labels) for port, labels in sorted(slot["versions"].items())
            }
            # lateral hint: other hosts sharing the same products
            shared: dict[str, list[str]] = {}
            for port, labels in products.items():
                for label in labels:
                    peers = product_hosts.get(label.lower(), set()) - {host}
                    if peers:
                        shared.setdefault(port, sorted(peers))
            summary_rows.append({
                "host": host,
                "ips": sorted(slot["ips"]),
                "open_ports": open_ports,
                "services": services,
                "products": products,
                "versions": versions,
                "exposure_density": len(open_ports),
                "lateral_hints": shared,
            })
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "hosts": summary_rows,
            "stats": {
                "hosts": len(summary_rows),
                "distinct_open_ports": len({p for r in summary_rows for p in r["open_ports"]}),
                "products_seen": len(product_hosts),
            },
        }

    def build(self) -> dict:
        """Full machine-readable view: graph + exposure summary."""
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "graph": self.build_graph().as_dict(),
            "exposure": self.summary(),
        }
