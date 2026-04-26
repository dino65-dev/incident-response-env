# Copyright (c) 2026 - OpenEnv Hackathon Submission
# EUREKA Reward Refinement Package
# BSD-3-Clause License

"""
EUREKA-style LLM Reward Design (NeurIPS 2023, NVIDIA/CMU).

Iterative reward refinement loop:
  generate → evaluate on trajectories → reflect on stats → regenerate

GPT-4 as reward designer outperforms human expert rewards on 83% of tasks
with an average 52% improvement.
"""

from .reward_designer import EurekaRewardDesigner
from .trajectory_analyzer import TrajectoryAnalyzer, TrajectoryStats

__all__ = [
    "EurekaRewardDesigner",
    "TrajectoryAnalyzer",
    "TrajectoryStats",
]
