# Copyright (c) 2026 - OpenEnv Hackathon Submission
# α-Curriculum Scenario Selector
# BSD-3-Clause License

"""
α-Curriculum Scenario Selector — connects the self-evolving engine's
α-Curriculum to the multi-agent task selection pipeline.

Bridges:
  self_evolving/evolution_engine.py (α-Curriculum fitness)
  → inference.py (task selection)

The α-Curriculum reward R_env(p̂) = -|p̂ - α| naturally selects scenarios
at the agent's learning frontier. This module exposes that as a simple
API: given performance history, return the next optimal task_id.
"""

from typing import Any, Dict, List, Optional, Tuple

try:
    from self_evolving.evolution_engine import (
        AgentPerformanceRecord,
        EvolutionEngine,
        FitnessEvaluator,
        ScenarioGenome,
    )
    EVOLUTION_AVAILABLE = True
except ImportError:
    EVOLUTION_AVAILABLE = False


# Map task_ids to approximate difficulty for α-Curriculum
TASK_DIFFICULTY_MAP = {
    "easy":        0.15,
    "medium":      0.35,
    "hard":        0.55,
    "medium_hard": 0.50,
    "hard_plus":   0.70,
    "expert":      0.85,
}

# Reverse: difficulty range → task_id
DIFFICULTY_TO_TASK = [
    (0.0, 0.25, "easy"),
    (0.25, 0.45, "medium"),
    (0.45, 0.55, "medium_hard"),
    (0.55, 0.65, "hard"),
    (0.65, 0.80, "hard_plus"),
    (0.80, 1.0, "expert"),
]


class AlphaCurriculumSelector:
    """
    Selects the next task based on α-Curriculum learning frontier.

    Uses the agent's performance history to estimate the optimal
    difficulty level where P(success) ≈ α ≈ 0.5.

    This means the agent always trains on scenarios that are
    challenging but achievable — maximizing learning rate.
    """

    def __init__(self, alpha: float = 0.5):
        self.alpha = alpha
        self.performance_history: List[Dict[str, Any]] = []
        self.task_scores: Dict[str, List[float]] = {}
        self._fitness = FitnessEvaluator(alpha=alpha) if EVOLUTION_AVAILABLE else None

    def record_performance(
        self,
        task_id: str,
        score: float,
        steps_used: int = 0,
        max_steps: int = 25,
    ) -> None:
        """Record performance on a task for curriculum adaptation."""
        self.performance_history.append({
            "task_id": task_id,
            "score": score,
            "steps_used": steps_used,
            "max_steps": max_steps,
        })

        if task_id not in self.task_scores:
            self.task_scores[task_id] = []
        self.task_scores[task_id].append(score)

    def select_next_task(self, available_tasks: List[str]) -> str:
        """
        Select the next task using α-Curriculum.

        Algorithm:
        1. Estimate success probability for each task
        2. Compute α-Curriculum reward: R = -|p̂ - α|
        3. Select task with highest reward (closest to α)
        """
        if not self.performance_history:
            # Cold start: return medium difficulty
            return "medium" if "medium" in available_tasks else available_tasks[0]

        best_task = available_tasks[0]
        best_reward = -float("inf")

        for task_id in available_tasks:
            scores = self.task_scores.get(task_id, [])
            if scores:
                # Use recent performance
                recent = scores[-5:]
                p_hat = sum(recent) / len(recent)
            else:
                # No data: use difficulty as proxy
                difficulty = TASK_DIFFICULTY_MAP.get(task_id, 0.5)
                p_hat = 1.0 - difficulty

            # α-Curriculum reward
            reward = -abs(p_hat - self.alpha)

            if reward > best_reward:
                best_reward = reward
                best_task = task_id

        return best_task

    def get_curriculum_order(self, available_tasks: List[str]) -> List[str]:
        """
        Return all tasks ordered by α-Curriculum priority.
        Tasks closest to the learning frontier come first.
        """
        task_rewards = []
        for task_id in available_tasks:
            scores = self.task_scores.get(task_id, [])
            if scores:
                recent = scores[-5:]
                p_hat = sum(recent) / len(recent)
            else:
                difficulty = TASK_DIFFICULTY_MAP.get(task_id, 0.5)
                p_hat = 1.0 - difficulty

            reward = -abs(p_hat - self.alpha)
            task_rewards.append((task_id, reward))

        # Sort by reward (highest first = closest to α)
        task_rewards.sort(key=lambda x: x[1], reverse=True)
        return [t for t, _ in task_rewards]

    def get_optimal_difficulty(self) -> float:
        """
        Estimate the agent's current optimal difficulty level.
        Uses the α-Curriculum to find where P(success) ≈ α.
        """
        if not self.performance_history:
            return 0.3  # Default: medium-easy

        # Build difficulty → score mapping
        difficulty_scores: Dict[float, List[float]] = {}
        for record in self.performance_history:
            difficulty = TASK_DIFFICULTY_MAP.get(record["task_id"], 0.5)
            if difficulty not in difficulty_scores:
                difficulty_scores[difficulty] = []
            difficulty_scores[difficulty].append(record["score"])

        # Find difficulty where avg score ≈ α
        best_difficulty = 0.3
        best_gap = float("inf")

        for difficulty, scores in difficulty_scores.items():
            avg = sum(scores) / len(scores)
            gap = abs(avg - self.alpha)
            if gap < best_gap:
                best_gap = gap
                best_difficulty = difficulty

        return best_difficulty

    def get_curriculum_stats(self) -> Dict[str, Any]:
        """Get α-Curriculum statistics for monitoring."""
        stats = {
            "alpha": self.alpha,
            "total_episodes": len(self.performance_history),
            "optimal_difficulty": round(self.get_optimal_difficulty(), 3),
            "task_stats": {},
        }

        for task_id, scores in self.task_scores.items():
            recent = scores[-5:]
            stats["task_stats"][task_id] = {
                "episodes": len(scores),
                "avg_score": round(sum(scores) / len(scores), 3),
                "recent_avg": round(sum(recent) / len(recent), 3),
                "alpha_reward": round(-abs(sum(recent) / len(recent) - self.alpha), 3),
                "difficulty": TASK_DIFFICULTY_MAP.get(task_id, 0.5),
            }

        return stats
