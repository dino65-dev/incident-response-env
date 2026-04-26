# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Red Team Attack Strategies
# BSD-3-Clause License

"""
Pre-defined attack strategies for the Red Team agent.

Each strategy defines a preference ordering over red team actions
based on the current defender state, enabling diverse adversarial
behavior during co-evolutionary training.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional

from .agent import RedTeamAction, RedTeamActionType, RedTeamState


class AttackStrategy(ABC):
    """Base class for red team attack strategies."""

    @abstractmethod
    def select_action(
        self,
        red_state: RedTeamState,
        defender_state: Dict,
        step: int,
        max_steps: int,
    ) -> RedTeamAction:
        """Select the next red team action based on strategy."""
        ...

    @abstractmethod
    def get_name(self) -> str:
        ...


class StealthStrategy(AttackStrategy):
    """
    Prioritizes remaining undetected while slowly building attack position.

    Action ordering:
    1. Deploy decoys early (misdirect early investigation)
    2. Cover tracks mid-game (hide evidence before defenders find it)
    3. Lateral moves late-game (build position for exfiltration)
    4. Exfiltrate only when defenders seem behind
    """

    def get_name(self) -> str:
        return "stealth"

    def select_action(
        self,
        red_state: RedTeamState,
        defender_state: Dict,
        step: int,
        max_steps: int,
    ) -> RedTeamAction:
        progress = step / max(max_steps, 1)
        containment = defender_state.get("containment_score", 0.0)
        severity_set = defender_state.get("severity_set", False)

        if progress < 0.3:
            # Early: deploy decoys
            if red_state.decoy_iocs_deployed < 2:
                return RedTeamAction(action_type=RedTeamActionType.DEPLOY_DECOY_IOC)
            return RedTeamAction(action_type=RedTeamActionType.WAIT)

        elif progress < 0.6:
            # Mid: cover tracks
            if red_state.tracks_covered < 3:
                return RedTeamAction(action_type=RedTeamActionType.COVER_TRACKS)
            return RedTeamAction(action_type=RedTeamActionType.LATERAL_MOVE_SILENTLY)

        elif progress < 0.85:
            # Late: lateral movement
            if red_state.lateral_moves_completed < 2:
                return RedTeamAction(action_type=RedTeamActionType.LATERAL_MOVE_SILENTLY)
            return RedTeamAction(action_type=RedTeamActionType.COVER_TRACKS)

        else:
            # Endgame: exfiltrate if defenders are behind
            if containment < 0.5 and not severity_set:
                return RedTeamAction(action_type=RedTeamActionType.EXFILTRATE_DATA)
            return RedTeamAction(action_type=RedTeamActionType.COVER_TRACKS)


class AggressiveStrategy(AttackStrategy):
    """
    Maximizes disruption — injects false logs aggressively and
    attempts early exfiltration.

    Action ordering:
    1. Inject false logs constantly (waste defender steps)
    2. Accelerate attack (reduce time window)
    3. Exfiltrate as soon as possible
    """

    def get_name(self) -> str:
        return "aggressive"

    def select_action(
        self,
        red_state: RedTeamState,
        defender_state: Dict,
        step: int,
        max_steps: int,
    ) -> RedTeamAction:
        progress = step / max(max_steps, 1)
        containment = defender_state.get("containment_score", 0.0)

        if progress < 0.4:
            return RedTeamAction(action_type=RedTeamActionType.INJECT_FALSE_LOG)
        elif progress < 0.6:
            if red_state.false_logs_injected < 4:
                return RedTeamAction(action_type=RedTeamActionType.INJECT_FALSE_LOG)
            return RedTeamAction(action_type=RedTeamActionType.ACCELERATE_ATTACK)
        else:
            if containment < 0.3:
                return RedTeamAction(action_type=RedTeamActionType.EXFILTRATE_DATA)
            return RedTeamAction(action_type=RedTeamActionType.INJECT_FALSE_LOG)


class DeceptiveStrategy(AttackStrategy):
    """
    Plants decoy IOCs and false evidence to misdirect investigation.

    Most effective against ToM-0 agents that don't model adversarial intent.

    Action ordering:
    1. Deploy decoy IOCs (misdirect threat intel)
    2. Inject false logs in unqueried sources
    3. Cover tracks on real evidence
    4. Exfiltrate when defenders are chasing decoys
    """

    def get_name(self) -> str:
        return "deceptive"

    def select_action(
        self,
        red_state: RedTeamState,
        defender_state: Dict,
        step: int,
        max_steps: int,
    ) -> RedTeamAction:
        progress = step / max(max_steps, 1)
        containment = defender_state.get("containment_score", 0.0)
        sources_queried = defender_state.get("log_sources_queried", set())

        if progress < 0.3:
            if red_state.decoy_iocs_deployed < 3:
                return RedTeamAction(action_type=RedTeamActionType.DEPLOY_DECOY_IOC)
            return RedTeamAction(action_type=RedTeamActionType.INJECT_FALSE_LOG)

        elif progress < 0.6:
            # Inject into sources defenders haven't checked yet
            unqueried = {"email", "edr", "auth", "proxy", "firewall", "dns"} - set(sources_queried)
            if unqueried:
                target = list(unqueried)[0]
                return RedTeamAction(
                    action_type=RedTeamActionType.INJECT_FALSE_LOG,
                    target=target,
                )
            return RedTeamAction(action_type=RedTeamActionType.COVER_TRACKS)

        elif progress < 0.8:
            return RedTeamAction(action_type=RedTeamActionType.COVER_TRACKS)

        else:
            if containment < 0.4:
                return RedTeamAction(action_type=RedTeamActionType.EXFILTRATE_DATA)
            return RedTeamAction(action_type=RedTeamActionType.DEPLOY_DECOY_IOC)


# Strategy registry
STRATEGIES: Dict[str, type] = {
    "stealth": StealthStrategy,
    "aggressive": AggressiveStrategy,
    "deceptive": DeceptiveStrategy,
}


def get_strategy(name: str) -> AttackStrategy:
    """Get an attack strategy by name."""
    cls = STRATEGIES.get(name)
    if cls is None:
        raise ValueError(f"Unknown strategy: {name}. Available: {list(STRATEGIES.keys())}")
    return cls()


def get_random_strategy() -> AttackStrategy:
    """Get a random attack strategy (for population diversity)."""
    import random
    cls = random.choice(list(STRATEGIES.values()))
    return cls()
