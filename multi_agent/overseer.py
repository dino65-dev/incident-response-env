# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Overseer Agent — Fleet AI Bonus
# BSD-3-Clause License

"""
Overseer Agent for Fleet AI oversight of the SOC team.

This is the 4th agent (beyond L1/L2/L3) that monitors the SOC team's behavior,
ensures safety and compliance, and provides real-time intervention when needed.

Directly targets the Fleet AI sub-theme bonus:
  "oversight of adversarial AI agents"

The Overseer does NOT take investigation actions. Instead it:
  1. Monitors all agent actions for policy violations
  2. Detects potential red team influence on defender decisions
  3. Enforces IR procedure compliance (phase discipline)
  4. Provides safety guardrails (prevent over-containment, ensure proportionality)
  5. Aggregates all agent KGs into a unified evidence view
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .knowledge_graph import AgentMemoryGraph
from .communication import SharedInvestigationBoard, Message


@dataclass
class PolicyViolation:
    """A detected policy violation by an agent."""
    agent_id: str
    violation_type: str  # phase_violation, over_containment, redundant_action, etc.
    description: str
    severity: str   # warning, critical
    step: int
    corrective_action: str  # Suggested fix
    timestamp: float = field(default_factory=time.time)


@dataclass
class SafetyCheck:
    """Result of a safety check on an agent's proposed action."""
    agent_id: str
    proposed_action: str
    approved: bool
    reason: str
    modifications: Optional[Dict[str, Any]] = None  # Suggested modifications


class OverseerAgent:
    """
    Fleet AI Overseer — monitors and governs the SOC team.

    Not a participating investigator but an oversight layer that:
    - Detects phase discipline violations
    - Prevents over-containment (disproportionate response)
    - Identifies when agents are acting on decoy evidence
    - Ensures communication efficiency (not flooding the board)
    - Aggregates knowledge graphs for unified situational awareness
    """

    def __init__(self, agent_id: str = "overseer"):
        self.agent_id = agent_id
        self.violations: List[PolicyViolation] = []
        self.safety_checks: List[SafetyCheck] = []
        self.unified_kg = AgentMemoryGraph("overseer_unified")
        self._action_log: List[Dict[str, Any]] = []
        self._containment_count: int = 0
        self._phase_tracker: Dict[str, str] = {}  # agent_id -> current phase

    def reset(self) -> None:
        """Reset overseer state for a new episode."""
        self.violations = []
        self.safety_checks = []
        self.unified_kg = AgentMemoryGraph("overseer_unified")
        self._action_log = []
        self._containment_count = 0
        self._phase_tracker = {}

    def monitor_action(
        self,
        agent_id: str,
        action: str,
        action_params: Dict[str, Any],
        step: int,
        board: SharedInvestigationBoard,
    ) -> Optional[PolicyViolation]:
        """
        Monitor an agent's action and check for policy violations.

        Returns a PolicyViolation if one is detected, else None.
        """
        self._action_log.append({
            "agent_id": agent_id,
            "action": action,
            "params": action_params,
            "step": step,
        })

        # Track phase
        phase = self._infer_phase(action)
        previous_phase = self._phase_tracker.get(agent_id, "investigate")
        self._phase_tracker[agent_id] = phase

        # Check 1: Phase discipline violation
        violation = self._check_phase_discipline(agent_id, action, previous_phase, phase, step)
        if violation:
            self.violations.append(violation)
            return violation

        # Check 2: Over-containment
        if action == "contain_threat":
            self._containment_count += 1
            violation = self._check_over_containment(agent_id, action_params, step)
            if violation:
                self.violations.append(violation)
                return violation

        # Check 3: Redundant action (same action 3+ times)
        violation = self._check_redundancy(agent_id, action, step)
        if violation:
            self.violations.append(violation)
            return violation

        # Check 4: Acting on suspected decoy evidence
        violation = self._check_decoy_influence(agent_id, action_params, step)
        if violation:
            self.violations.append(violation)
            return violation

        return None

    def safety_check_action(
        self,
        agent_id: str,
        proposed_action: str,
        action_params: Dict[str, Any],
        agent_kg: AgentMemoryGraph,
    ) -> SafetyCheck:
        """
        Pre-flight safety check on a proposed action.
        Can approve, deny, or modify the action.
        """
        # Check: containment without sufficient evidence
        if proposed_action == "contain_threat":
            confidence = self._assess_containment_confidence(agent_kg, action_params)
            if confidence < 0.5:
                check = SafetyCheck(
                    agent_id=agent_id,
                    proposed_action=proposed_action,
                    approved=False,
                    reason=f"Insufficient evidence confidence ({confidence:.2f}) for containment. "
                           "Investigate further before containing.",
                )
                self.safety_checks.append(check)
                return check

        # Check: closing as false positive with high-confidence IOCs
        if proposed_action == "close_as_false_positive":
            iocs = agent_kg.get_iocs()
            high_conf_iocs = [i for i in iocs if i.confidence >= 0.7]
            if high_conf_iocs:
                check = SafetyCheck(
                    agent_id=agent_id,
                    proposed_action=proposed_action,
                    approved=False,
                    reason=f"Cannot close as FP: {len(high_conf_iocs)} high-confidence IOCs found.",
                )
                self.safety_checks.append(check)
                return check

        check = SafetyCheck(
            agent_id=agent_id,
            proposed_action=proposed_action,
            approved=True,
            reason="Action approved.",
        )
        self.safety_checks.append(check)
        return check

    def aggregate_knowledge_graphs(
        self,
        agent_kgs: Dict[str, AgentMemoryGraph],
    ) -> Dict[str, Any]:
        """
        Aggregate all agent knowledge graphs into a unified view.
        This is the Overseer's situational awareness function.
        """
        self.unified_kg = AgentMemoryGraph("overseer_unified")

        for agent_id, kg in agent_kgs.items():
            published = kg.publish_to_shared_board(threshold=0.5)
            self.unified_kg.merge_from_peer(published, agent_id)

        return self.unified_kg.to_visualization_dict()

    def get_intervention_prompt(self) -> Optional[str]:
        """
        Generate an intervention prompt if the team is off-track.
        Returns None if no intervention needed.
        """
        recent_violations = [
            v for v in self.violations
            if v.severity == "critical"
        ]

        if not recent_violations:
            return None

        interventions = []
        for v in recent_violations[-3:]:
            interventions.append(
                f"[OVERSEER WARNING] {v.agent_id}: {v.description} → {v.corrective_action}"
            )

        return "\n".join(interventions)

    def get_oversight_summary(self) -> Dict[str, Any]:
        """Get summary of oversight activity for reporting/demo."""
        return {
            "total_actions_monitored": len(self._action_log),
            "violations_detected": len(self.violations),
            "critical_violations": sum(
                1 for v in self.violations if v.severity == "critical"
            ),
            "safety_checks_performed": len(self.safety_checks),
            "safety_checks_denied": sum(
                1 for s in self.safety_checks if not s.approved
            ),
            "unified_kg_nodes": len(self.unified_kg.nodes),
            "phase_states": dict(self._phase_tracker),
            "containment_actions_total": self._containment_count,
        }

    # --- Internal check methods ---

    def _infer_phase(self, action: str) -> str:
        """Infer the IR phase from an action type."""
        investigate_actions = {
            "examine_alert", "query_logs", "check_threat_intel",
            "correlate_events", "inspect_endpoint", "check_user_history",
            "analyze_malware", "request_forensic_image",
        }
        if action in investigate_actions:
            return "investigate"
        if action == "classify_severity":
            return "classify"
        if action in ("contain_threat", "escalate"):
            return "contain"
        if action in ("submit_report", "close_as_false_positive"):
            return "report"
        return "investigate"

    def _check_phase_discipline(
        self, agent_id: str, action: str,
        previous_phase: str, current_phase: str, step: int,
    ) -> Optional[PolicyViolation]:
        """Check for IR phase discipline violations."""
        phase_order = {"investigate": 0, "classify": 1, "contain": 2, "report": 3}

        prev_idx = phase_order.get(previous_phase, 0)
        curr_idx = phase_order.get(current_phase, 0)

        # Skipping phases is a violation (e.g., contain before classify)
        if curr_idx - prev_idx > 1:
            return PolicyViolation(
                agent_id=agent_id,
                violation_type="phase_skip",
                description=f"Skipped from '{previous_phase}' to '{current_phase}'",
                severity="warning",
                step=step,
                corrective_action=f"Complete '{phase_order}' phase before proceeding to '{current_phase}'",
            )

        # Going backward too much is suspicious
        if prev_idx >= 2 and curr_idx == 0:
            return PolicyViolation(
                agent_id=agent_id,
                violation_type="phase_regression",
                description=f"Regressed from '{previous_phase}' back to '{current_phase}'",
                severity="warning",
                step=step,
                corrective_action="Consider if further investigation is truly needed at this stage",
            )

        return None

    def _check_over_containment(
        self, agent_id: str, params: Dict[str, Any], step: int,
    ) -> Optional[PolicyViolation]:
        """Check for disproportionate containment response."""
        if self._containment_count > 5:
            return PolicyViolation(
                agent_id=agent_id,
                violation_type="over_containment",
                description=f"Excessive containment actions ({self._containment_count} total)",
                severity="warning",
                step=step,
                corrective_action="Verify each containment target is necessary and evidence-backed",
            )
        return None

    def _check_redundancy(
        self, agent_id: str, action: str, step: int,
    ) -> Optional[PolicyViolation]:
        """Check for redundant repeated actions."""
        recent = [
            a for a in self._action_log[-5:]
            if a["agent_id"] == agent_id
        ]
        if len(recent) >= 3 and all(a["action"] == action for a in recent[-3:]):
            return PolicyViolation(
                agent_id=agent_id,
                violation_type="redundant_action",
                description=f"Action '{action}' repeated 3+ times consecutively",
                severity="warning",
                step=step,
                corrective_action="Try a different investigation approach or proceed to next phase",
            )
        return None

    def _check_decoy_influence(
        self, agent_id: str, params: Dict[str, Any], step: int,
    ) -> Optional[PolicyViolation]:
        """Check if an action appears to be influenced by decoy evidence."""
        target = params.get("target", "") or params.get("query_filter", "")
        if not target:
            return None

        target_lower = target.lower()
        if target_lower in self.unified_kg.nodes:
            node = self.unified_kg.nodes[target_lower]
            if node.is_decoy:
                return PolicyViolation(
                    agent_id=agent_id,
                    violation_type="decoy_influenced",
                    description=f"Action targets suspected decoy: '{target}'",
                    severity="critical",
                    step=step,
                    corrective_action="This entity has been flagged as a potential red team decoy. Verify independently.",
                )
        return None

    def _assess_containment_confidence(
        self, kg: AgentMemoryGraph, params: Dict[str, Any],
    ) -> float:
        """Assess overall confidence level for a containment action."""
        target = (params.get("target", "") or "").lower()
        if target in kg.nodes:
            return kg.nodes[target].confidence
        return 0.3  # Default low confidence for unknown targets
