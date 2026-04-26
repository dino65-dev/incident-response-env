# Copyright (c) 2026 - OpenEnv Hackathon Submission
# ReSCOM Communication Protocol + Shared Investigation Board
# BSD-3-Clause License

"""
ReSCOM-inspired emergent communication protocol (AAMAS 2025).

Implements a 3-phase reward-shaped curriculum that progressively teaches
agents *when* to communicate rather than *how*, improving coordination
by 16-22% over baselines.

Phase 1 (steps 0-40%):   Reward ANY communication attempt
Phase 2 (steps 40-80%):  Only reward communication that CHANGES receiver's action
Phase 3 (steps 80-100%): Only reward communication that IMPROVES team reward
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class Message:
    """A communication message between agents."""
    sender_id: str
    receiver_id: str
    content: Dict[str, Any]     # Structured content (evidence, beliefs, requests)
    priority: float = 0.5       # 0.0-1.0 — used for filtering
    step: int = 0
    message_type: str = "info"  # info, request, alert, belief_update, handoff
    timestamp: float = field(default_factory=time.time)


class CommunicationReward:
    """
    ReSCOM 3-phase communication reward curriculum.

    Progressively shifts agent focus from "how to communicate"
    to "when to communicate" for emergent protocol development.
    """

    def __init__(self, total_training_steps: int = 1000):
        self.total_steps = total_training_steps
        self.phase_boundaries = (0.4, 0.8)  # Phase 1→2 at 40%, Phase 2→3 at 80%
        self.messages_sent: int = 0
        self.messages_that_changed_action: int = 0
        self.messages_that_improved_reward: int = 0

    def compute_reward(
        self,
        sender_id: str,
        receiver_id: str,
        message: Optional[Message],
        receiver_action_before: Optional[str],
        receiver_action_after: Optional[str],
        team_reward_before: float,
        team_reward_after: float,
        training_step: int,
    ) -> float:
        """
        Compute communication reward based on current curriculum phase.

        Returns:
            Float reward for the communication action
        """
        if message is None:
            return 0.0

        self.messages_sent += 1
        progress = training_step / max(self.total_steps, 1)

        if progress < self.phase_boundaries[0]:
            # Phase 1: Reward any communication attempt
            return 0.02

        elif progress < self.phase_boundaries[1]:
            # Phase 2: Reward communication that changes receiver's action
            action_changed = (
                receiver_action_before is not None and
                receiver_action_after is not None and
                receiver_action_before != receiver_action_after
            )
            if action_changed:
                self.messages_that_changed_action += 1
                return 0.04
            return -0.01  # Penalize useless communication

        else:
            # Phase 3: Reward communication that improves team reward
            team_improved = team_reward_after > team_reward_before
            if team_improved:
                self.messages_that_improved_reward += 1
                return 0.06
            return -0.02  # Penalize communication that doesn't help

    def get_stats(self) -> Dict[str, Any]:
        """Get communication statistics for monitoring."""
        return {
            "total_messages": self.messages_sent,
            "action_changing_messages": self.messages_that_changed_action,
            "reward_improving_messages": self.messages_that_improved_reward,
            "action_change_rate": (
                self.messages_that_changed_action / max(self.messages_sent, 1)
            ),
            "reward_improvement_rate": (
                self.messages_that_improved_reward / max(self.messages_sent, 1)
            ),
        }


class SharedInvestigationBoard:
    """
    Centralized shared state for multi-agent coordination.

    Integrates:
    - Published evidence from each agent's KG (high-confidence only)
    - Message history with priority filtering
    - Belief state snapshots from ToM
    - Red team detection alerts
    """

    def __init__(self):
        self.published_evidence: Dict[str, Dict[str, Any]] = {}  # agent_id -> published KG
        self.messages: List[Message] = []
        self.belief_states: Dict[str, Dict[str, Any]] = {}  # agent_id -> belief summary
        self.red_team_alerts: List[Dict[str, Any]] = []
        self.team_reward_history: List[float] = []
        self.handoff_history: List[Dict[str, Any]] = []

    def publish_evidence(self, agent_id: str, evidence: Dict[str, Any]) -> None:
        """Publish an agent's high-confidence evidence to the board."""
        self.published_evidence[agent_id] = evidence

    def get_all_published_evidence(self) -> Dict[str, Dict[str, Any]]:
        """Get all published evidence from all agents."""
        return self.published_evidence

    def send_message(self, message: Message) -> None:
        """Send a message through the board."""
        self.messages.append(message)

    def get_messages_for(
        self,
        agent_id: str,
        min_priority: float = 0.0,
        since_step: int = 0,
    ) -> List[Message]:
        """Get messages intended for a specific agent."""
        return [
            m for m in self.messages
            if m.receiver_id == agent_id
            and m.priority >= min_priority
            and m.step >= since_step
        ]

    def update_belief_state(self, agent_id: str, belief: Dict[str, Any]) -> None:
        """Update an agent's belief state snapshot (from ToM)."""
        self.belief_states[agent_id] = belief

    def get_belief_state(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get an agent's latest belief state."""
        return self.belief_states.get(agent_id)

    def add_red_team_alert(self, alert: Dict[str, Any]) -> None:
        """Add a red team detection alert."""
        self.red_team_alerts.append(alert)

    def record_team_reward(self, reward: float) -> None:
        """Track team reward for communication curriculum (Phase 3)."""
        self.team_reward_history.append(reward)

    def record_handoff(
        self,
        from_agent: str,
        to_agent: str,
        reason: str,
        step: int,
    ) -> None:
        """Record an investigation handoff between agents."""
        self.handoff_history.append({
            "from": from_agent,
            "to": to_agent,
            "reason": reason,
            "step": step,
            "timestamp": time.time(),
        })

    def get_board_summary(self) -> Dict[str, Any]:
        """Get a summary of the board state for agent context."""
        return {
            "evidence_publishers": list(self.published_evidence.keys()),
            "total_evidence_items": sum(
                len(e) for e in self.published_evidence.values()
            ),
            "total_messages": len(self.messages),
            "active_beliefs": list(self.belief_states.keys()),
            "red_team_alerts": len(self.red_team_alerts),
            "team_reward_trend": (
                self.team_reward_history[-5:]
                if self.team_reward_history else []
            ),
            "handoffs": len(self.handoff_history),
        }

    def reset(self) -> None:
        """Reset the board for a new episode."""
        self.published_evidence.clear()
        self.messages.clear()
        self.belief_states.clear()
        self.red_team_alerts.clear()
        self.team_reward_history.clear()
        self.handoff_history.clear()
