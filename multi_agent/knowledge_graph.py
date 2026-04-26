# Copyright (c) 2026 - OpenEnv Hackathon Submission
# DAMCS Hierarchical Knowledge Graph Memory
# BSD-3-Clause License

"""
DAMCS-inspired Agent Memory Graph (arXiv 2502.05453).

Each SOC agent maintains a personal knowledge graph of discovered evidence.
Only high-priority nodes are published to the shared board.

Key design: the KG is NOT an island — it feeds into:
  1. ToM belief states (what does my partner believe?)
  2. EUREKA trajectory analysis (what patterns does the KG reveal?)
  3. Red Team observation (what has been discovered vs hidden?)
  4. Report generation (evidence chain from KG)
  5. Communication decisions (what to share with teammates)
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class KGNode:
    """A node in the agent's knowledge graph."""
    entity: str                      # The entity (IP, hostname, hash, user, etc.)
    entity_type: str                 # ip, hostname, hash, user, domain, file, process
    confidence: float = 0.5          # 0.0-1.0, increases with corroborating evidence
    discovered_by: str = ""          # Agent ID that discovered this
    step_discovered: int = 0         # Step when first discovered
    source_log: str = ""             # Log source where found
    is_ioc: bool = False             # Is this an Indicator of Compromise?
    is_decoy: bool = False           # Flagged as potential decoy (by ToM-2 agent)
    corroborating_sources: int = 1   # Number of independent sources confirming
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KGEdge:
    """A relationship edge in the knowledge graph."""
    from_entity: str
    relation: str       # contacted, spawned, downloaded, authenticated_as, etc.
    to_entity: str
    weight: float = 1.0
    step_created: int = 0
    source: str = ""    # Which log/action revealed this relationship


class AgentMemoryGraph:
    """
    Hierarchical knowledge graph for persistent agent memory.

    Connected to all other systems:
    - ToM: provides belief state about what evidence is known
    - EUREKA: exports graph stats for trajectory analysis
    - Red Team: enables comparison of discovered vs hidden evidence
    - Reports: generates evidence chains for incident reports
    - Communication: determines what to publish to teammates
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.nodes: Dict[str, KGNode] = {}
        self.edges: List[KGEdge] = []
        self._entity_index: Dict[str, Set[str]] = {}  # type -> entities

    def add_evidence(
        self,
        entity: str,
        entity_type: str,
        source_log: str = "",
        confidence: float = 0.5,
        is_ioc: bool = False,
        step: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> KGNode:
        """
        Add a new evidence node. If entity exists, increase confidence.
        Auto-connects to related entities.
        """
        entity_lower = entity.lower()

        if entity_lower in self.nodes:
            # Corroborate existing evidence
            existing = self.nodes[entity_lower]
            existing.corroborating_sources += 1
            existing.confidence = min(1.0, existing.confidence + 0.15)
            if is_ioc:
                existing.is_ioc = True
            return existing

        node = KGNode(
            entity=entity,
            entity_type=entity_type,
            confidence=confidence,
            discovered_by=self.agent_id,
            step_discovered=step,
            source_log=source_log,
            is_ioc=is_ioc,
            metadata=metadata or {},
        )
        self.nodes[entity_lower] = node

        # Index by type
        if entity_type not in self._entity_index:
            self._entity_index[entity_type] = set()
        self._entity_index[entity_type].add(entity_lower)

        # Auto-link to related entities
        self._auto_link(entity_lower, entity_type, source_log, step)

        return node

    def add_edge(
        self,
        from_entity: str,
        relation: str,
        to_entity: str,
        weight: float = 1.0,
        step: int = 0,
        source: str = "",
    ) -> KGEdge:
        """Add a relationship edge between two entities."""
        edge = KGEdge(
            from_entity=from_entity.lower(),
            relation=relation,
            to_entity=to_entity.lower(),
            weight=weight,
            step_created=step,
            source=source,
        )
        self.edges.append(edge)
        return edge

    def _auto_link(
        self, entity: str, entity_type: str, source_log: str, step: int
    ) -> None:
        """Auto-link entity to related existing entities."""
        # Link IPs to hostnames that reference them
        if entity_type == "ip":
            for hostname in self._entity_index.get("hostname", set()):
                node = self.nodes[hostname]
                if entity in node.metadata.get("connections", ""):
                    self.add_edge(hostname, "contacted", entity, step=step, source=source_log)

        # Link processes to hosts
        if entity_type == "process":
            for hostname in self._entity_index.get("hostname", set()):
                if source_log:
                    self.add_edge(hostname, "runs", entity, step=step, source=source_log)

        # Link users to auth events
        if entity_type == "user":
            for ip in self._entity_index.get("ip", set()):
                self.add_edge(entity, "authenticated_from", ip, step=step, source=source_log)

    def query_by_type(self, entity_type: str) -> List[KGNode]:
        """Get all nodes of a specific type."""
        entities = self._entity_index.get(entity_type, set())
        return [self.nodes[e] for e in entities if e in self.nodes]

    def query_high_confidence(self, threshold: float = 0.7) -> List[KGNode]:
        """Get all nodes above a confidence threshold."""
        return [n for n in self.nodes.values() if n.confidence >= threshold]

    def get_iocs(self) -> List[KGNode]:
        """Get all identified IOCs."""
        return [n for n in self.nodes.values() if n.is_ioc]

    def flag_as_decoy(self, entity: str) -> bool:
        """Flag an entity as a potential decoy (called by ToM-2 agent)."""
        entity_lower = entity.lower()
        if entity_lower in self.nodes:
            self.nodes[entity_lower].is_decoy = True
            self.nodes[entity_lower].confidence *= 0.5  # Halve confidence
            return True
        return False

    def publish_to_shared_board(self, threshold: float = 0.7) -> Dict[str, Any]:
        """
        Publish high-confidence nodes to the shared investigation board.
        Filters out flagged decoys.
        """
        published = {}
        for key, node in self.nodes.items():
            if node.confidence >= threshold and not node.is_decoy:
                published[key] = {
                    "entity": node.entity,
                    "type": node.entity_type,
                    "confidence": round(node.confidence, 2),
                    "is_ioc": node.is_ioc,
                    "source": node.source_log,
                    "step": node.step_discovered,
                }
        return published

    def merge_from_peer(self, peer_published: Dict[str, Any], peer_id: str) -> int:
        """
        Integrate another agent's published nodes into this graph.
        Returns the number of new nodes added.
        """
        new_count = 0
        for key, data in peer_published.items():
            if key not in self.nodes:
                self.add_evidence(
                    entity=data["entity"],
                    entity_type=data["type"],
                    source_log=f"peer:{peer_id}",
                    confidence=data["confidence"] * 0.9,  # Slight discount for hearsay
                    is_ioc=data.get("is_ioc", False),
                    step=data.get("step", 0),
                )
                new_count += 1
            else:
                # Corroborate existing evidence
                existing = self.nodes[key]
                existing.corroborating_sources += 1
                existing.confidence = min(1.0, existing.confidence + 0.1)
        return new_count

    def get_evidence_chain(self) -> List[Dict[str, Any]]:
        """
        Build an ordered evidence chain for report generation.
        Returns nodes sorted by discovery step with relationship context.
        """
        chain = []
        sorted_nodes = sorted(
            self.nodes.values(),
            key=lambda n: n.step_discovered
        )
        for node in sorted_nodes:
            related_edges = [
                {"relation": e.relation, "target": e.to_entity}
                for e in self.edges
                if e.from_entity == node.entity.lower()
            ]
            chain.append({
                "step": node.step_discovered,
                "entity": node.entity,
                "type": node.entity_type,
                "confidence": round(node.confidence, 2),
                "is_ioc": node.is_ioc,
                "source": node.source_log,
                "relationships": related_edges,
            })
        return chain

    def get_belief_summary(self) -> Dict[str, Any]:
        """
        Export graph state as a belief summary (feeds into ToM).
        """
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "iocs_found": len(self.get_iocs()),
            "high_confidence_nodes": len(self.query_high_confidence()),
            "entity_types": {
                etype: len(entities)
                for etype, entities in self._entity_index.items()
            },
            "decoys_flagged": sum(1 for n in self.nodes.values() if n.is_decoy),
            "avg_confidence": (
                sum(n.confidence for n in self.nodes.values()) /
                max(len(self.nodes), 1)
            ),
        }

    def get_graph_stats_for_eureka(self) -> Dict[str, Any]:
        """
        Export graph statistics for EUREKA trajectory analysis.
        Feeds into LLM reward refinement.
        """
        return {
            "evidence_count": len(self.nodes),
            "edge_count": len(self.edges),
            "ioc_count": len(self.get_iocs()),
            "decoy_count": sum(1 for n in self.nodes.values() if n.is_decoy),
            "avg_confidence": round(
                sum(n.confidence for n in self.nodes.values()) /
                max(len(self.nodes), 1), 3
            ),
            "source_diversity": len(
                set(n.source_log for n in self.nodes.values() if n.source_log)
            ),
            "corroboration_rate": round(
                sum(n.corroborating_sources for n in self.nodes.values()) /
                max(len(self.nodes), 1), 2
            ),
            "entity_type_coverage": list(self._entity_index.keys()),
        }

    def to_visualization_dict(self) -> Dict[str, Any]:
        """
        Export full graph for demo visualization.
        Shows nodes, edges, and confidence-based sizing.
        """
        return {
            "nodes": [
                {
                    "id": key,
                    "label": node.entity,
                    "type": node.entity_type,
                    "confidence": round(node.confidence, 2),
                    "is_ioc": node.is_ioc,
                    "is_decoy": node.is_decoy,
                    "size": max(10, int(node.confidence * 50)),
                }
                for key, node in self.nodes.items()
            ],
            "edges": [
                {
                    "from": edge.from_entity,
                    "to": edge.to_entity,
                    "label": edge.relation,
                    "weight": edge.weight,
                }
                for edge in self.edges
            ],
            "stats": self.get_belief_summary(),
        }

    def compare_with_ground_truth(
        self, true_evidence: Set[str], true_iocs: Set[str]
    ) -> Dict[str, Any]:
        """
        Compare discovered evidence against ground truth.
        Used by Red Team to assess defender's progress.
        """
        discovered_evidence = set(self.nodes.keys())
        found_iocs = {n.entity.lower() for n in self.get_iocs()}

        return {
            "evidence_recall": (
                len(discovered_evidence & {e.lower() for e in true_evidence}) /
                max(len(true_evidence), 1)
            ),
            "ioc_recall": (
                len(found_iocs & {i.lower() for i in true_iocs}) /
                max(len(true_iocs), 1)
            ),
            "missed_evidence": list({e.lower() for e in true_evidence} - discovered_evidence),
            "missed_iocs": list({i.lower() for i in true_iocs} - found_iocs),
        }
