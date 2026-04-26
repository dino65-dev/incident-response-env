# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Adaptive Theory of Mind (A-ToM)
# BSD-3-Clause License

"""
Adaptive Theory of Mind for LLM-based Multi-Agent Coordination.

Based on arXiv 2603.16264 (March 2026) — the first adaptive ToM agent
for LLMs that estimates its partner's ToM order in real time.

Key insight: agents at different reasoning depths can catastrophically
interfere even when cooperating. A-ToM fixes this with the Hedge online
learning algorithm to dynamically weight {ToM-0, ToM-1, ToM-2} hypotheses.

- L1 (Triage):       ToM-0 — reasons only about direct evidence
- L2 (Senior):       ToM-1 — models L1's beliefs to avoid redundant queries
- L3 (IR Lead):      ToM-2 — models what L2 thinks L1 discovered
"""

import math
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple


class ToMLevel(IntEnum):
    """Theory of Mind reasoning depth levels."""
    TOM_0 = 0  # Direct reasoning about evidence only
    TOM_1 = 1  # Models what one partner believes
    TOM_2 = 2  # Models what a partner thinks another partner believes


@dataclass
class BeliefState:
    """
    What an agent believes about another agent's knowledge.

    At ToM-1: "I believe agent X has found evidence Y with confidence Z"
    At ToM-2: "I believe agent X believes agent Y has found evidence Z"
    """
    about_agent: str               # Agent being modeled
    believed_evidence: Dict[str, float] = field(default_factory=dict)  # evidence -> confidence
    believed_iocs: Dict[str, float] = field(default_factory=dict)      # ioc -> confidence
    believed_phase: str = "investigate"  # investigate, classify, contain, report
    tom_level: ToMLevel = ToMLevel.TOM_0
    accuracy: float = 0.5          # How accurate this belief model is (updated over time)
    # Nested belief (for ToM-2): what does about_agent believe about a third agent?
    nested_belief: Optional["BeliefState"] = None


class AdaptiveToM:
    """
    Adaptive Theory of Mind module using Hedge online learning.

    Maintains probability weights over {ToM-0, ToM-1, ToM-2} hypotheses
    and updates them based on prediction accuracy.

    The Hedge algorithm (Freund & Schapire 1997) provides:
    - No-regret online learning guarantee
    - Multiplicative weight updates for fast adaptation
    - Natural convergence to the best ToM level for each partner
    """

    def __init__(
        self,
        agent_id: str,
        learning_rate: float = 0.3,
        num_levels: int = 3,
    ):
        self.agent_id = agent_id
        self.learning_rate = learning_rate
        self.num_levels = num_levels

        # Hedge weights: uniform initialization
        self.weights = [1.0 / num_levels] * num_levels

        # Belief models for each partner at each ToM level
        self.beliefs: Dict[str, List[BeliefState]] = {}

        # Prediction history for accuracy tracking
        self._prediction_history: List[Dict[str, Any]] = []

    def initialize_beliefs(self, partner_ids: List[str]) -> None:
        """Initialize belief models for all partners."""
        for pid in partner_ids:
            self.beliefs[pid] = [
                BeliefState(about_agent=pid, tom_level=ToMLevel(i))
                for i in range(self.num_levels)
            ]

    def estimate_partner_tom(self, partner_id: str) -> ToMLevel:
        """
        Estimate a partner's ToM order from message history.
        Returns the ToM level with highest weight.
        """
        if partner_id not in self.beliefs:
            return ToMLevel.TOM_0

        max_idx = self.weights.index(max(self.weights))
        return ToMLevel(max_idx)

    def predict_partner_belief(
        self,
        partner_id: str,
        partner_messages: List[Dict[str, Any]],
        shared_evidence: Dict[str, Any],
    ) -> BeliefState:
        """
        Predict what a partner believes given their messages.

        "Given what L1 just told me, what does L1 believe about this incident?"
        """
        if partner_id not in self.beliefs:
            return BeliefState(about_agent=partner_id)

        estimated_tom = self.estimate_partner_tom(partner_id)
        belief = self.beliefs[partner_id][estimated_tom.value]

        # Update belief based on partner's messages
        for msg in partner_messages:
            content = msg.get("content", {})

            # Extract evidence mentions from message
            if "evidence" in content:
                for ev, conf in content["evidence"].items():
                    belief.believed_evidence[ev] = conf

            # Extract IOC mentions
            if "iocs" in content:
                for ioc, conf in content["iocs"].items():
                    belief.believed_iocs[ioc] = conf

            # Infer phase from action types
            if "action" in content:
                action = content["action"]
                if action in ("classify_severity", "classify"):
                    belief.believed_phase = "classify"
                elif action in ("contain_threat", "contain"):
                    belief.believed_phase = "contain"
                elif action in ("submit_report", "report"):
                    belief.believed_phase = "report"

        return belief

    def update_weights(
        self,
        partner_id: str,
        actual_action: str,
        predictions: List[str],
    ) -> None:
        """
        Hedge update: adjust ToM level weights based on prediction accuracy.

        Args:
            partner_id: The partner whose action we predicted
            actual_action: What the partner actually did
            predictions: What each ToM level predicted the partner would do
        """
        losses = []
        for i, pred in enumerate(predictions):
            # Binary loss: 0 if correct, 1 if wrong
            loss = 0.0 if pred == actual_action else 1.0
            losses.append(loss)

        # Multiplicative weight update (Hedge algorithm)
        for i in range(self.num_levels):
            self.weights[i] *= math.exp(-self.learning_rate * losses[i])

        # Normalize weights
        total = sum(self.weights)
        if total > 0:
            self.weights = [w / total for w in self.weights]

        # Track prediction accuracy
        best_level = losses.index(min(losses))
        self._prediction_history.append({
            "partner": partner_id,
            "best_level": best_level,
            "weights": list(self.weights),
        })

    def align_reasoning_depth(
        self, partner_id: str
    ) -> Dict[str, Any]:
        """
        Adjust own reasoning to match partner's estimated ToM level.

        Returns context hints that should be added to the LLM prompt
        to structurally align reasoning depth.
        """
        estimated_tom = self.estimate_partner_tom(partner_id)

        alignment_context = {
            "partner_tom_level": estimated_tom.value,
            "weights": {
                f"tom_{i}": round(w, 3) for i, w in enumerate(self.weights)
            },
        }

        if estimated_tom == ToMLevel.TOM_0:
            alignment_context["reasoning_hint"] = (
                f"Partner {partner_id} reasons at ToM-0 (direct evidence only). "
                "Communicate concrete findings, not meta-reasoning."
            )
        elif estimated_tom == ToMLevel.TOM_1:
            alignment_context["reasoning_hint"] = (
                f"Partner {partner_id} reasons at ToM-1 (models your beliefs). "
                "Share what you've found AND what you haven't checked yet."
            )
        else:
            alignment_context["reasoning_hint"] = (
                f"Partner {partner_id} reasons at ToM-2 (models nested beliefs). "
                "Share your assessment of the full investigation state."
            )

        return alignment_context

    def get_tom_summary(self) -> Dict[str, Any]:
        """Get ToM state summary for visualization/debugging."""
        return {
            "agent_id": self.agent_id,
            "weights": {f"tom_{i}": round(w, 3) for i, w in enumerate(self.weights)},
            "dominant_level": ToMLevel(self.weights.index(max(self.weights))).name,
            "beliefs": {
                pid: {
                    "estimated_tom": self.estimate_partner_tom(pid).name,
                    "evidence_count": len(
                        self.beliefs[pid][0].believed_evidence
                    ) if pid in self.beliefs else 0,
                }
                for pid in self.beliefs
            },
            "prediction_count": len(self._prediction_history),
        }
