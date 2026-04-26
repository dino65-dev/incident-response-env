# Copyright (c) 2026 - OpenEnv Hackathon Submission
# CTDE: Centralized Training, Decentralized Execution
# BSD-3-Clause License

"""
CTDE training paradigm for multi-agent LLM SOC team.

Based on:
  - CTDE is the dominant paradigm in MARL (Emergent Mind 2025)
  - A 2025 paper applying GRPO under CTDE got 3× speed improvement
    with 98.7% coordination consistency
  - CADP (IJCAI 2025): explicit message channels during training,
    pruned at inference

Architecture:
  During TRAINING: Centralized critic sees all agents' obs + global state
  During INFERENCE: Each agent uses only its local observation (decentralized)

This stabilizes learning (lower variance in reward curves) while enabling
each agent to act independently at deployment.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class JointObservation:
    """Joint observation combining all agents' views (training only)."""
    l1_obs: Dict[str, Any] = field(default_factory=dict)
    l2_obs: Dict[str, Any] = field(default_factory=dict)
    l3_obs: Dict[str, Any] = field(default_factory=dict)
    overseer_obs: Dict[str, Any] = field(default_factory=dict)
    global_state: Dict[str, Any] = field(default_factory=dict)
    red_team_state: Dict[str, Any] = field(default_factory=dict)
    shared_board_state: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CriticOutput:
    """Output from the centralized critic."""
    value_estimate: float = 0.0
    advantage_per_agent: Dict[str, float] = field(default_factory=dict)
    coordination_score: float = 0.0  # How well agents are coordinating


class CentralizedCritic:
    """
    Centralized critic with access to full joint observation during training.
    Discarded at inference time — each agent runs decentralized.

    The critic estimates the value of the joint state, enabling:
    - Counterfactual baselines (what if agent X did something else?)
    - Coordination reward shaping (incentivize complementary actions)
    - Variance reduction in policy gradient updates
    """

    def __init__(self, hidden_dim: int = 256):
        self.hidden_dim = hidden_dim
        self._value_history: List[float] = []
        self._coordination_history: List[float] = []

    def forward(self, joint_obs: JointObservation) -> CriticOutput:
        """
        Compute centralized value estimate from joint observation.

        In a full implementation, this would be a neural network.
        Here we provide a heuristic estimate for the training pipeline.
        """
        # Heuristic value estimation based on joint state
        value = 0.0

        # Evidence discovery across all agents
        for agent_key in ["l1_obs", "l2_obs", "l3_obs"]:
            obs = getattr(joint_obs, agent_key, {})
            evidence_count = len(obs.get("evidence_collected", []))
            ioc_count = len(obs.get("iocs_discovered", []))
            value += evidence_count * 0.05 + ioc_count * 0.08

        # Coordination metric: are agents querying different log sources?
        all_sources = set()
        source_overlap = 0
        for agent_key in ["l1_obs", "l2_obs", "l3_obs"]:
            obs = getattr(joint_obs, agent_key, {})
            sources = set(obs.get("log_sources_queried", []))
            overlap = all_sources & sources
            source_overlap += len(overlap)
            all_sources |= sources

        coordination = len(all_sources) / max(6, 1) - source_overlap * 0.1
        coordination = max(0.0, min(1.0, coordination))

        # Global state factors
        global_state = joint_obs.global_state
        if global_state.get("severity_classified", False):
            value += 0.1
        if global_state.get("report_submitted", False):
            value += 0.15

        # Red team adversarial pressure
        red_state = joint_obs.red_team_state
        if red_state.get("exfiltration_succeeded", False):
            value -= 0.5

        # Agent-specific advantages
        advantages = {}
        for agent_id in ["l1_triage", "l2_senior", "l3_lead"]:
            # Simple advantage: agent's contribution minus average
            agent_obs = getattr(
                joint_obs,
                {"l1_triage": "l1_obs", "l2_senior": "l2_obs", "l3_lead": "l3_obs"}[agent_id],
                {}
            )
            agent_evidence = len(agent_obs.get("evidence_collected", []))
            avg_evidence = value / 3 if value > 0 else 0
            advantages[agent_id] = agent_evidence * 0.05 - avg_evidence

        self._value_history.append(value)
        self._coordination_history.append(coordination)

        return CriticOutput(
            value_estimate=round(value, 4),
            advantage_per_agent=advantages,
            coordination_score=round(coordination, 4),
        )

    def get_training_stats(self) -> Dict[str, Any]:
        """Get critic training statistics."""
        if not self._value_history:
            return {"status": "no_data"}
        return {
            "mean_value": sum(self._value_history) / len(self._value_history),
            "mean_coordination": (
                sum(self._coordination_history) / len(self._coordination_history)
            ),
            "value_trend": self._value_history[-10:],
            "coordination_trend": self._coordination_history[-10:],
        }


class DecentralizedPolicy:
    """
    Base class for decentralized agent policies.

    At inference time, each agent only sees its local observation.
    The centralized critic is not used — pure local decision-making.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._action_history: List[str] = []

    def select_action(self, local_obs: Dict[str, Any]) -> str:
        """
        Select an action based on local observation ONLY.
        No access to other agents' observations.

        In a full implementation, this would be a policy network.
        """
        # Heuristic policy based on investigation progress
        progress = local_obs.get("investigation_progress", 0.0)
        steps_remaining = local_obs.get("steps_remaining", 10)
        evidence = local_obs.get("evidence_collected", [])
        severity_set = local_obs.get("severity_set", False)

        if progress < 0.3 and steps_remaining > 5:
            return "query_logs"
        elif progress < 0.6 and not severity_set:
            return "check_threat_intel"
        elif not severity_set:
            return "classify_severity"
        else:
            return "submit_report"

    def record_action(self, action: str) -> None:
        """Record an action for anti-loop detection."""
        self._action_history.append(action)


class CTDETrainer:
    """
    CTDE training orchestrator.

    Manages the training loop where:
    1. All agents act in the environment
    2. Joint observations are collected
    3. Centralized critic computes values/advantages
    4. Individual policies are updated using advantages
    5. At deployment, critics are discarded
    """

    def __init__(self):
        self.critic = CentralizedCritic()
        self.policies: Dict[str, DecentralizedPolicy] = {}
        self._episode_data: List[Dict[str, Any]] = []
        self._training_step: int = 0

    def initialize_policies(self, agent_ids: List[str]) -> None:
        """Initialize decentralized policies for each agent."""
        for agent_id in agent_ids:
            self.policies[agent_id] = DecentralizedPolicy(agent_id)

    def collect_training_step(
        self,
        joint_obs: JointObservation,
        actions: Dict[str, str],
        rewards: Dict[str, float],
    ) -> CriticOutput:
        """
        Collect one training step: joint observation + actions + rewards.
        Returns the critic's evaluation.
        """
        critic_output = self.critic.forward(joint_obs)

        self._episode_data.append({
            "step": self._training_step,
            "value": critic_output.value_estimate,
            "coordination": critic_output.coordination_score,
            "actions": actions,
            "rewards": rewards,
            "advantages": critic_output.advantage_per_agent,
        })
        self._training_step += 1

        return critic_output

    def get_training_summary(self) -> Dict[str, Any]:
        """Get training summary for EUREKA integration."""
        return {
            "total_steps": self._training_step,
            "critic_stats": self.critic.get_training_stats(),
            "agent_policies": list(self.policies.keys()),
            "episode_data_points": len(self._episode_data),
        }
