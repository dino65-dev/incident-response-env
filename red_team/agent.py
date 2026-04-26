# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Red Team Adversarial Agent
# BSD-3-Clause License

"""
Red Team Agent — adversarial counterpart to the SOC defender team.

Based on:
  - AdvEvo-MARL (NeurIPS 2025): adversarial co-evolution reduces ASR to <20%
  - CAGE Challenge 4: gold-standard attacker/defender MARL benchmark

The Red Team acts simultaneously with the SOC team on the opposite side of each
episode, injecting false evidence, covering tracks, and attempting exfiltration.
Its reward signal is visible per-step to enable adversarial co-training.
"""

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RedTeamActionType(str, Enum):
    """Actions available to the Red Team agent."""
    INJECT_FALSE_LOG = "inject_false_log"           # Plant misleading log entry
    COVER_TRACKS = "cover_tracks"                   # Remove critical evidence
    LATERAL_MOVE_SILENTLY = "lateral_move_silently"  # Below-threshold lateral movement
    DEPLOY_DECOY_IOC = "deploy_decoy_ioc"           # Plant fake IOC
    ACCELERATE_ATTACK = "accelerate_attack"          # Reduce defender time window
    EXFILTRATE_DATA = "exfiltrate_data"              # Terminal: succeed if not contained
    WAIT = "wait"                                     # Do nothing this step


@dataclass
class RedTeamAction:
    """An action taken by the Red Team agent."""
    action_type: RedTeamActionType
    target: Optional[str] = None    # Target log source, evidence key, or IOC
    payload: Optional[str] = None   # Content for injected logs/IOCs
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RedTeamState:
    """Tracks the Red Team's progression through the attack kill chain."""
    steps_taken: int = 0
    tracks_covered: int = 0
    false_logs_injected: int = 0
    decoy_iocs_deployed: int = 0
    lateral_moves_completed: int = 0
    exfiltration_attempted: bool = False
    exfiltration_succeeded: bool = False
    total_reward: float = 0.0
    step_rewards: List[float] = field(default_factory=list)
    # Observable by defenders (partial info)
    detected_actions: List[str] = field(default_factory=list)
    # Hidden from defenders
    hidden_actions: List[str] = field(default_factory=list)


class RedTeamAgent:
    """
    Adversarial agent that co-evolves with the SOC defender team.

    Reward signal is visible per-step:
      - +0.10 per false log that wastes a defender step
      - +0.15 per successful track covering (evidence removed)
      - +0.08 per decoy IOC that misdirects threat intel
      - +0.05 per silent lateral movement
      - +1.0  if exfiltration succeeds (defenders failed to contain)
      - -0.50 if exfiltration is blocked (defenders contained the threat)
      - -0.05 per detected action (stealth penalty)
    """

    def __init__(self, strategy: Optional["AttackStrategy"] = None):
        self.state = RedTeamState()
        self.strategy = strategy
        self._false_log_entries: List[Dict[str, Any]] = []
        self._decoy_iocs: List[str] = []
        self._covered_evidence: List[str] = []

    def reset(self) -> None:
        """Reset red team state for a new episode."""
        self.state = RedTeamState()
        self._false_log_entries = []
        self._decoy_iocs = []
        self._covered_evidence = []

    def step(
        self,
        action: RedTeamAction,
        defender_state: Dict[str, Any],
        scenario_evidence: List[str],
    ) -> Dict[str, Any]:
        """
        Execute a red team action and return result with visible reward.

        Args:
            action: The red team action to execute
            defender_state: Observable defender state (evidence found, steps used, etc.)
            scenario_evidence: List of critical evidence keys in the scenario

        Returns:
            Dict with: reward, result, detected, state_update
        """
        self.state.steps_taken += 1
        reward = 0.0
        result = ""
        detected = False

        if action.action_type == RedTeamActionType.INJECT_FALSE_LOG:
            reward, result, detected = self._inject_false_log(action, defender_state)

        elif action.action_type == RedTeamActionType.COVER_TRACKS:
            reward, result, detected = self._cover_tracks(action, scenario_evidence)

        elif action.action_type == RedTeamActionType.LATERAL_MOVE_SILENTLY:
            reward, result, detected = self._lateral_move(action, defender_state)

        elif action.action_type == RedTeamActionType.DEPLOY_DECOY_IOC:
            reward, result, detected = self._deploy_decoy(action)

        elif action.action_type == RedTeamActionType.ACCELERATE_ATTACK:
            reward, result, detected = self._accelerate(action, defender_state)

        elif action.action_type == RedTeamActionType.EXFILTRATE_DATA:
            reward, result, detected = self._exfiltrate(defender_state)

        elif action.action_type == RedTeamActionType.WAIT:
            reward = 0.0
            result = "Red team is waiting."

        # Stealth penalty for detection
        if detected:
            reward -= 0.05
            self.state.detected_actions.append(action.action_type.value)
        else:
            self.state.hidden_actions.append(action.action_type.value)

        self.state.total_reward += reward
        self.state.step_rewards.append(reward)

        return {
            "reward": round(reward, 4),
            "result": result,
            "detected": detected,
            "red_team_state": {
                "steps_taken": self.state.steps_taken,
                "total_reward": round(self.state.total_reward, 4),
                "exfiltration_attempted": self.state.exfiltration_attempted,
                "exfiltration_succeeded": self.state.exfiltration_succeeded,
                "tracks_covered": self.state.tracks_covered,
                "false_logs_injected": self.state.false_logs_injected,
                "decoy_iocs_deployed": self.state.decoy_iocs_deployed,
            },
        }

    def _inject_false_log(
        self, action: RedTeamAction, defender_state: Dict[str, Any]
    ) -> tuple:
        """Inject a misleading log entry to waste defender steps."""
        target_source = action.target or random.choice(
            ["email", "edr", "auth", "proxy", "firewall", "dns"]
        )
        payload = action.payload or self._generate_false_log(target_source)

        self._false_log_entries.append({
            "source": target_source,
            "content": payload,
            "step_injected": self.state.steps_taken,
        })
        self.state.false_logs_injected += 1

        # Reward if defenders haven't queried this source yet (higher chance of confusion)
        queried_sources = defender_state.get("log_sources_queried", set())
        if target_source not in queried_sources:
            reward = 0.10
        else:
            reward = 0.03  # Less effective if already queried

        # Detection chance: 20% base
        detected = random.random() < 0.20

        return reward, f"Injected false log into {target_source}", detected

    def _cover_tracks(
        self, action: RedTeamAction, scenario_evidence: List[str]
    ) -> tuple:
        """Remove or obscure critical evidence."""
        # Pick a random undiscovered evidence item to hide
        uncovered = [e for e in scenario_evidence if e not in self._covered_evidence]
        if not uncovered:
            return -0.02, "No more evidence to cover.", False

        target = action.target or random.choice(uncovered)
        self._covered_evidence.append(target)
        self.state.tracks_covered += 1

        reward = 0.15  # High reward for successfully hiding evidence
        detected = random.random() < 0.15  # 15% detection chance

        return reward, f"Covered tracks: obscured evidence '{target}'", detected

    def _lateral_move(
        self, action: RedTeamAction, defender_state: Dict[str, Any]
    ) -> tuple:
        """Execute a below-threshold lateral movement."""
        self.state.lateral_moves_completed += 1

        # More lateral moves = closer to exfiltration but higher detection risk
        detection_chance = 0.10 + (self.state.lateral_moves_completed * 0.05)
        detected = random.random() < detection_chance

        reward = 0.05
        return reward, "Silent lateral movement completed.", detected

    def _deploy_decoy(self, action: RedTeamAction) -> tuple:
        """Plant a fake IOC to misdirect threat intel queries."""
        decoy = action.payload or f"decoy_{random.randint(1000, 9999)}.malware.test"
        self._decoy_iocs.append(decoy)
        self.state.decoy_iocs_deployed += 1

        reward = 0.08
        detected = random.random() < 0.10  # Hard to detect

        return reward, f"Deployed decoy IOC: {decoy}", detected

    def _accelerate(
        self, action: RedTeamAction, defender_state: Dict[str, Any]
    ) -> tuple:
        """Reduce the time window available to defenders."""
        steps_remaining = defender_state.get("steps_remaining", 20)
        if steps_remaining > 5:
            reward = 0.05
            result = "Attack accelerated — pressure on defenders increased."
        else:
            reward = 0.02
            result = "Attack already near terminal phase."

        detected = random.random() < 0.25  # Acceleration is noisy
        return reward, result, detected

    def _exfiltrate(self, defender_state: Dict[str, Any]) -> tuple:
        """Terminal action: attempt data exfiltration."""
        self.state.exfiltration_attempted = True

        # Exfiltration succeeds if defenders haven't achieved containment
        containment_score = defender_state.get("containment_score", 0.0)
        severity_set = defender_state.get("severity_set", False)

        if containment_score < 0.5 and not severity_set:
            # Defenders failed — exfiltration succeeds
            self.state.exfiltration_succeeded = True
            reward = 1.0
            result = "EXFILTRATION SUCCESSFUL — defenders failed to contain."
            detected = True  # Always detected post-exfiltration
        elif containment_score < 0.5:
            # Partial success
            self.state.exfiltration_succeeded = True
            reward = 0.50
            result = "PARTIAL EXFILTRATION — some data extracted before containment."
            detected = True
        else:
            # Defenders contained the threat
            self.state.exfiltration_succeeded = False
            reward = -0.50
            result = "EXFILTRATION BLOCKED — defenders contained the threat."
            detected = True

        return reward, result, detected

    def _generate_false_log(self, source: str) -> str:
        """Generate a plausible but false log entry for a given source."""
        templates = {
            "email": "Suspicious email from admin@internal-it-support.com with attachment 'security_update.exe' — flagged by gateway",
            "edr": "Process 'svchost.exe' spawned child 'cmd.exe' with arguments '/c whoami' — possible reconnaissance",
            "auth": "Failed login attempt for user 'admin' from 10.0.0.1 — 3 attempts in 60 seconds",
            "proxy": "Outbound connection to hxxp://cdn-updates.internal.net/package.bin — categorized as 'Software Updates'",
            "firewall": "Allowed outbound TCP 443 to 8.8.8.8 from 192.168.1.100 — DNS over HTTPS detected",
            "dns": "Query for updates.microsoft-cdn.com from 10.0.0.50 — resolved to 203.0.113.99",
        }
        return templates.get(source, f"Anomalous activity detected in {source} logs")

    def get_false_logs(self) -> List[Dict[str, Any]]:
        """Return injected false log entries (for environment integration)."""
        return self._false_log_entries

    def get_decoy_iocs(self) -> List[str]:
        """Return deployed decoy IOCs."""
        return self._decoy_iocs

    def get_covered_evidence(self) -> List[str]:
        """Return evidence items that have been covered/hidden."""
        return self._covered_evidence

    def get_reward_summary(self) -> Dict[str, Any]:
        """Return full reward breakdown (visible to training loop)."""
        return {
            "total_reward": round(self.state.total_reward, 4),
            "step_rewards": [round(r, 4) for r in self.state.step_rewards],
            "steps_taken": self.state.steps_taken,
            "exfiltration_succeeded": self.state.exfiltration_succeeded,
            "attack_success_rate": 1.0 if self.state.exfiltration_succeeded else 0.0,
            "stealth_ratio": (
                len(self.state.hidden_actions) /
                max(len(self.state.hidden_actions) + len(self.state.detected_actions), 1)
            ),
        }
