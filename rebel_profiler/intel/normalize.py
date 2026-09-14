"""Target normalization and entity resolution (PDF 4).

Raw observations arrive as messy strings: hostnames with case/trailing-dot
noise, URLs with schemes and ports, bare IPs, CIDR ranges. Normalization
produces canonical forms so identical targets collapse to one identity, and
entity resolution links aliases (a domain, its wildcard scope entry and an
observed host) into one entity group.

Everything here is pure string logic — deterministic and testable. Nothing in
this module talks to the network or makes authorization decisions.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


def canonical_hostname(value: str) -> str:
    """Canonicalize a hostname/IP string: lowercase, strip scheme/port/path/dot."""
    text = value.strip()
    # strip scheme
    if "://" in text:
        text = text.split("://", 1)[1]
    # strip path
    for sep in ("/", "?", "#"):
        text = text.split(sep, 1)[0]
    # strip port (but not the colon inside an IPv6 literal)
    if text.count(":") == 1:
        text = text.rsplit(":", 1)[0]
    # strip trailing dot
    text = text.rstrip(".").lower()
    return text


def canonical_domain(value: str) -> str:
    """ registrable-domain best effort: last two labels for common TLDs.

    Deliberately simple: this is a labeling helper, not a full PSL
    implementation. Multi-label public suffixes fall back to the last two
    labels, which is fine for grouping.
    """
    host = canonical_hostname(value)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host  # IPs are their own canonical form
    except ValueError:
        pass
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def target_kind(value: str) -> str:
    """Classify a raw target string: ip, cidr, hostname, url or unknown."""
    text = value.strip()
    if "://" in text:
        return "url"
    try:
        ipaddress.ip_address(text.rstrip("."))
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(text, strict=False)
        return "cidr"
    except ValueError:
        pass
    host = canonical_hostname(text)
    if host and _HOST_RE.match(host) and "." in host:
        return "hostname"
    return "unknown"


def normalize_target(value: str) -> dict:
    """Full normalization record for one raw target string."""
    kind = target_kind(value)
    host = canonical_hostname(value)
    return {
        "raw": value,
        "kind": kind,
        "canonical": host,
        "domain": canonical_domain(host) if kind in {"hostname", "url"} else "",
        "valid": kind in {"ip", "cidr", "hostname", "url"},
    }


@dataclass
class Entity:
    """A resolved entity: one canonical identity plus its aliases."""

    entity_id: str
    kind: str                       # hostname | ip | domain | url | unknown
    canonical: str
    aliases: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "kind": self.kind,
            "canonical": self.canonical,
            "aliases": sorted(self.aliases),
            "sources": sorted(self.sources),
        }


class EntityResolver:
    """Groups normalized observations into entities.

    Grouping rules (deterministic):
      * identical canonical form ⇒ same entity,
      * hostname and its registrable domain are linked as aliases of the
        domain entity,
      * a raw string seen again adds an alias, never a new entity.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._by_canonical: dict[str, str] = {}
        self._counter = 0

    def observe(self, raw: str, *, source: str = "") -> Entity:
        """Record one raw observation and return its resolved entity."""
        norm = normalize_target(raw)
        canonical = norm["canonical"] or norm["raw"].strip().lower()
        entity_id = self._by_canonical.get(canonical)
        if entity_id is None:
            self._counter += 1
            entity_id = f"ent_{self._counter:04d}"
            entity = Entity(entity_id=entity_id, kind=norm["kind"], canonical=canonical)
            self._entities[entity_id] = entity
            self._by_canonical[canonical] = entity_id
        entity = self._entities[entity_id]
        if norm["raw"] != canonical:
            entity.aliases.add(norm["raw"])
        if source:
            entity.sources.add(source)
        # link domain ↔ host
        if norm["domain"] and norm["domain"] != canonical:
            dom_entity = self.observe(norm["domain"], source=source)
            entity.aliases.add(dom_entity.canonical)
            dom_entity.aliases.add(canonical)
        return entity

    def get(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def find_canonical(self, canonical: str) -> Entity | None:
        eid = self._by_canonical.get(canonical.strip().lower())
        return self._entities.get(eid) if eid else None

    def list(self) -> list[Entity]:
        return [self._entities[k] for k in sorted(self._entities)]

    def merge(self, entity_id: str, other_id: str) -> Entity:
        """Merge two entities (e.g. after manual alias confirmation)."""
        a = self._entities.get(entity_id)
        b = self._entities.get(other_id)
        if a is None or b is None:
            raise KeyError("unknown entity id")
        if a is b:
            return a
        a.aliases |= b.aliases | {b.canonical}
        a.sources |= b.sources
        self._by_canonical[b.canonical] = a.entity_id
        del self._entities[other_id]
        return a


def resolve_entities(raw_targets: list[str]) -> list[Entity]:
    """Convenience: resolve a batch of raw target strings."""
    resolver = EntityResolver()
    for raw in raw_targets:
        resolver.observe(raw)
    return resolver.list()
