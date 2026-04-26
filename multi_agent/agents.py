# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Multi-Agent SOC Team — L1/L2/L3 Agents
# BSD-3-Clause License

"""
SOC Agent hierarchy with ToM-aware coordination.

L1 Triage Agent (ToM-0):
  - First responder — examines alerts, queries basic logs
  - Reports raw findings to the shared board

L2 Senior Analyst (ToM-1):
  - Models L1's beliefs to avoid redundant queries
  - Performs deep investigation: correlations, threat intel, endpoint inspection
  - Decides when to escalate to L3

L3 IR Lead (ToM-2):
  - Models what L2 thinks L1 discovered
  - Resolves conflicts between L1/L2 findings
  - Makes classification and containment decisions
  - Writes the final incident report
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .knowledge_graph import AgentMemoryGraph
from .tom import AdaptiveToM, BeliefState, ToMLevel
from .communication import Message, SharedInvestigationBoard


class AgentRole(str, Enum):
    """Roles in the SOC team hierarchy."""
    L1_TRIAGE = "l1_triage"
    L2_SENIOR = "l2_senior"
    L3_LEAD = "l3_lead"
    OVERSEER = "overseer"
    RED_TEAM = "red_team"


@dataclass
class AgentContext:
    """Context provided to an agent for decision-making."""
    role: AgentRole
    step: int
    max_steps: int
    observation: Dict[str, Any]
    kg_belief_summary: Dict[str, Any]
    tom_alignment: Dict[str, Any]
    board_summary: Dict[str, Any]
    peer_messages: List[Message]
    red_team_alerts: List[Dict[str, Any]]


class SOCAgent:
    """
    Base class for SOC team agents with ToM-aware message processing.
    """

    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        tom_level: ToMLevel,
    ):
        self.agent_id = agent_id
        self.role = role
        self.tom_level = tom_level
        self.memory = AgentMemoryGraph(agent_id)
        self.tom = AdaptiveToM(agent_id)
        self._action_history: List[str] = []
        self._current_phase: str = "investigate"

    def reset(self, partner_ids: List[str]) -> None:
        """Reset agent state for a new episode."""
        self.memory = AgentMemoryGraph(self.agent_id)
        self.tom = AdaptiveToM(self.agent_id)
        self.tom.initialize_beliefs(partner_ids)
        self._action_history = []
        self._current_phase = "investigate"

    def process_observation(
        self,
        observation: Dict[str, Any],
        step: int,
    ) -> None:
        """
        Process an environment observation and update knowledge graph.
        """
        # Extract evidence from findings
        findings = observation.get("findings", "")
        evidence = observation.get("evidence_collected", [])
        iocs = observation.get("iocs_discovered", [])

        for ev in evidence:
            self.memory.add_evidence(
                entity=ev,
                entity_type="evidence",
                source_log="observation",
                confidence=0.8,
                step=step,
            )

        for ioc in iocs:
            self.memory.add_evidence(
                entity=ioc,
                entity_type="ioc",
                source_log="observation",
                confidence=0.9,
                is_ioc=True,
                step=step,
            )

    def prepare_message(
        self,
        receiver_id: str,
        message_type: str = "info",
        step: int = 0,
    ) -> Message:
        """
        Prepare a message to send to another agent.
        Content is informedby the knowledge graph and ToM alignment.
        """
        # Get high-confidence evidence to share
        published = self.memory.publish_to_shared_board(threshold=0.6)

        # Get ToM alignment hint
        alignment = self.tom.align_reasoning_depth(receiver_id)

        content = {
            "evidence": {k: v["confidence"] for k, v in published.items()},
            "iocs": {
                n.entity: n.confidence
                for n in self.memory.get_iocs()
            },
            "phase": self._current_phase,
            "action_history": self._action_history[-5:],
            "tom_hint": alignment.get("reasoning_hint", ""),
        }

        priority = 0.5
        if message_type == "alert":
            priority = 0.9
        elif message_type == "handoff":
            priority = 0.8

        return Message(
            sender_id=self.agent_id,
            receiver_id=receiver_id,
            content=content,
            priority=priority,
            step=step,
            message_type=message_type,
        )

    def receive_messages(
        self,
        messages: List[Message],
        board: SharedInvestigationBoard,
    ) -> None:
        """
        Process incoming messages and update beliefs/KG.
        """
        for msg in messages:
            # Update ToM beliefs based on sender's message
            self.tom.predict_partner_belief(
                partner_id=msg.sender_id,
                partner_messages=[{"content": msg.content}],
                shared_evidence=board.get_all_published_evidence(),
            )

            # Merge peer evidence into own KG
            if "evidence" in msg.content:
                peer_published = {}
                for entity, confidence in msg.content["evidence"].items():
                    peer_published[entity] = {
                        "entity": entity,
                        "type": "evidence",
                        "confidence": confidence,
                        "is_ioc": False,
                        "source": f"msg:{msg.sender_id}",
                        "step": msg.step,
                    }
                self.memory.merge_from_peer(peer_published, msg.sender_id)

    def get_system_prompt_context(self) -> str:
        """
        Generate ToM-aware context to inject into the LLM system prompt.
        """
        kg_summary = self.memory.get_belief_summary()
        tom_summary = self.tom.get_tom_summary()

        context = (
            f"\n--- Agent: {self.agent_id} (Role: {self.role.value}, ToM Level: {self.tom_level.name}) ---\n"
            f"Knowledge Graph: {kg_summary['total_nodes']} nodes, "
            f"{kg_summary['iocs_found']} IOCs, "
            f"{kg_summary['high_confidence_nodes']} high-confidence items\n"
            f"Current Phase: {self._current_phase}\n"
        )

        # Add ToM alignment for partners
        for partner_id in self.tom.beliefs:
            alignment = self.tom.align_reasoning_depth(partner_id)
            context += f"  → {alignment.get('reasoning_hint', '')}\n"

        return context

    def record_action(self, action: str) -> None:
        """Record an action taken by this agent."""
        self._action_history.append(action)

    def set_phase(self, phase: str) -> None:
        """Update the current investigation phase."""
        self._current_phase = phase


class L1TriageAgent(SOCAgent):
    """
    Level 1 Triage Agent — first responder, ToM-0.

    Responsibilities:
    - Examine alerts and initial logs
    - Quick evidence gathering from all log sources
    - Report raw findings to shared board
    - Escalate to L2 when evidence warrants deeper investigation
    """

    def __init__(self, agent_id: str = "l1_triage"):
        super().__init__(agent_id, AgentRole.L1_TRIAGE, ToMLevel.TOM_0)
        self.preferred_actions = [
            "examine_alert", "query_logs", "check_threat_intel",
        ]

    def should_escalate_to_l2(self) -> bool:
        """Determine if investigation should be handed to L2."""
        kg = self.memory
        # Escalate if: high-confidence IOCs found OR multiple corroborating sources
        high_conf_iocs = [n for n in kg.get_iocs() if n.confidence >= 0.7]
        if len(high_conf_iocs) >= 2:
            return True
        if len(kg.query_high_confidence()) >= 3:
            return True
        return False


class L2SeniorAnalyst(SOCAgent):
    """
    Level 2 Senior Analyst — deep investigator, ToM-1.

    Responsibilities:
    - Models L1's beliefs to avoid redundant queries
    - Performs deep investigation: correlations, threat intel, endpoint inspection
    - Validates L1's findings against threat intelligence
    - Decides when to escalate to L3
    """

    def __init__(self, agent_id: str = "l2_senior"):
        super().__init__(agent_id, AgentRole.L2_SENIOR, ToMLevel.TOM_1)
        self.preferred_actions = [
            "correlate_events", "inspect_endpoint", "check_threat_intel",
            "analyze_malware", "check_user_history",
        ]

    def get_uninvestigated_leads(self, l1_context: Dict[str, Any]) -> List[str]:
        """
        Using ToM-1: determine what L1 has NOT investigated yet.
        Returns list of suggested actions.
        """
        l1_belief = self.tom.predict_partner_belief(
            "l1_triage",
            partner_messages=[],
            shared_evidence={},
        )

        # Find what L1 believes it has found
        l1_evidence = set(l1_belief.believed_evidence.keys())
        our_evidence = set(self.memory.nodes.keys())

        # Uninvestigated = in our KG but not in L1's believed evidence
        gaps = our_evidence - l1_evidence
        return list(gaps)

    def should_escalate_to_l3(self) -> bool:
        """Determine if investigation warrants L3 (IR Lead) involvement."""
        kg = self.memory
        # Escalate for: critical severity indicators OR containment needed
        iocs = kg.get_iocs()
        if len(iocs) >= 3:
            return True
        if kg.get_belief_summary()["avg_confidence"] >= 0.75:
            return True
        return False


class L3IRLead(SOCAgent):
    """
    Level 3 IR Lead — decision maker, ToM-2.

    Responsibilities:
    - Models what L2 thinks L1 discovered (nested beliefs)
    - Resolves conflicts between L1/L2 findings
    - Makes classification decisions (severity, category)
    - Coordinates containment actions
    - Writes the final incident report
    - Can flag entities as decoys based on ToM-2 reasoning
    """

    def __init__(self, agent_id: str = "l3_lead"):
        super().__init__(agent_id, AgentRole.L3_LEAD, ToMLevel.TOM_2)
        self.preferred_actions = [
            "classify_severity", "contain_threat", "escalate",
            "submit_report",
        ]

    def resolve_conflict(
        self,
        l1_belief: BeliefState,
        l2_belief: BeliefState,
    ) -> Dict[str, Any]:
        """
        Using ToM-2: resolve conflicting beliefs between L1 and L2.

        Returns resolution with confidence-weighted decision.
        """
        # Find evidence that L1 and L2 disagree on
        l1_evidence = l1_belief.believed_evidence
        l2_evidence = l2_belief.believed_evidence

        conflicts = {}
        for ev in set(l1_evidence.keys()) | set(l2_evidence.keys()):
            l1_conf = l1_evidence.get(ev, 0.0)
            l2_conf = l2_evidence.get(ev, 0.0)
            if abs(l1_conf - l2_conf) > 0.3:
                # Conflict: L2's assessment gets more weight (deeper analysis)
                resolved_conf = l2_conf * 0.7 + l1_conf * 0.3
                conflicts[ev] = {
                    "l1_confidence": l1_conf,
                    "l2_confidence": l2_conf,
                    "resolved_confidence": resolved_conf,
                    "resolution": "l2_weighted" if l2_conf > l1_conf else "l1_weighted",
                }

        return {
            "conflicts_found": len(conflicts),
            "resolutions": conflicts,
        }

    def assess_decoy_probability(self, entity: str) -> float:
        """
        Using ToM-2: assess whether an entity is likely a red team decoy.

        Considers:
        - Entity was found in only one source (low corroboration)
        - Entity doesn't connect to other known evidence
        - Entity appeared after red team detection alerts
        """
        if entity.lower() not in self.memory.nodes:
            return 0.0

        node = self.memory.nodes[entity.lower()]

        decoy_score = 0.0

        # Single source = suspicious
        if node.corroborating_sources <= 1:
            decoy_score += 0.3

        # No relationships = isolated (suspicious)
        edges = [e for e in self.memory.edges if entity.lower() in (e.from_entity, e.to_entity)]
        if len(edges) == 0:
            decoy_score += 0.3

        # Low confidence = suspicious
        if node.confidence < 0.5:
            decoy_score += 0.2

        # Appeared late in investigation = more likely planted
        if node.step_discovered > 10:
            decoy_score += 0.1

        return min(1.0, decoy_score)

    def generate_report_from_kg(self) -> str:
        """
        Generate a comprehensive incident report from the knowledge graph's
        evidence chain. This is the primary output of the L3 agent.
        """
        chain = self.memory.get_evidence_chain()
        iocs = self.memory.get_iocs()

        report_parts = ["INCIDENT REPORT (Generated by L3 IR Lead)\n"]
        report_parts.append("=" * 50 + "\n\n")

        report_parts.append("EVIDENCE CHAIN:\n")
        for item in chain:
            report_parts.append(
                f"  Step {item['step']}: [{item['type']}] {item['entity']} "
                f"(confidence: {item['confidence']}) from {item['source']}\n"
            )
            for rel in item.get("relationships", []):
                report_parts.append(
                    f"    → {rel['relation']} → {rel['target']}\n"
                )

        report_parts.append(f"\nIOCs IDENTIFIED ({len(iocs)}):\n")
        for ioc in iocs:
            status = "DECOY" if ioc.is_decoy else "CONFIRMED"
            report_parts.append(
                f"  [{status}] {ioc.entity} ({ioc.entity_type}) "
                f"confidence: {ioc.confidence:.2f}\n"
            )

        return "".join(report_parts)
