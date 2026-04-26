# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Red Team Adversarial Agent Package
# BSD-3-Clause License

"""
Red Team adversarial agent for co-evolutionary SOC training.

Based on AdvEvo-MARL (NeurIPS 2025) — jointly trains attackers and defenders
to reduce attack success rates while improving defender accuracy.
"""

from .agent import RedTeamAgent, RedTeamAction, RedTeamActionType
from .strategies import AttackStrategy, StealthStrategy, AggressiveStrategy, DeceptiveStrategy

__all__ = [
    "RedTeamAgent",
    "RedTeamAction",
    "RedTeamActionType",
    "AttackStrategy",
    "StealthStrategy",
    "AggressiveStrategy",
    "DeceptiveStrategy",
]
