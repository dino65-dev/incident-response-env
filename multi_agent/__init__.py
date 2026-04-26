# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Multi-Agent SOC Team Package
# BSD-3-Clause License

"""
Multi-Agent SOC Team with Theory of Mind coordination.

Implements:
  - Adaptive Theory of Mind (A-ToM, arXiv 2026) — belief alignment
  - DAMCS Knowledge Graph Memory — hierarchical evidence graph
  - ReSCOM Communication (AAMAS 2025) — emergent communication protocol
  - Overseer Agent (Fleet AI) — team oversight and safety monitoring
"""

from .tom import AdaptiveToM, ToMLevel, BeliefState
from .knowledge_graph import AgentMemoryGraph, KGNode, KGEdge
from .communication import (
    CommunicationReward,
    SharedInvestigationBoard,
    Message,
)
from .agents import SOCAgent, L1TriageAgent, L2SeniorAnalyst, L3IRLead
from .overseer import OverseerAgent

__all__ = [
    "AdaptiveToM",
    "ToMLevel",
    "BeliefState",
    "AgentMemoryGraph",
    "KGNode",
    "KGEdge",
    "CommunicationReward",
    "SharedInvestigationBoard",
    "Message",
    "SOCAgent",
    "L1TriageAgent",
    "L2SeniorAnalyst",
    "L3IRLead",
    "OverseerAgent",
]
