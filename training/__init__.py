# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Training Infrastructure Package
# BSD-3-Clause License

"""
Training infrastructure for multi-agent SOC team.

  - CTDE (Centralized Training, Decentralized Execution)
  - H-MARL (Hierarchical MARL with LLM Skill Discovery)
"""

from .ctde import CentralizedCritic, DecentralizedPolicy, CTDETrainer
from .hmarl import SkillDiscovery, HierarchicalPolicy, SubSkill

__all__ = [
    "CentralizedCritic",
    "DecentralizedPolicy",
    "CTDETrainer",
    "SkillDiscovery",
    "HierarchicalPolicy",
    "SubSkill",
]
