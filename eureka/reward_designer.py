# Copyright (c) 2026 - OpenEnv Hackathon Submission
# EUREKA-Style LLM Reward Designer with Feedback Loop
# BSD-3-Clause License

"""
EUREKA-inspired iterative reward improvement with closed feedback loop.

Based on:
  - EUREKA (NeurIPS 2023): GPT-4 outperforms human expert rewards on 83% of tasks
  - CARD (2025): iterative reward refinement without per-iteration RL training

Feedback loop:
  1. GENERATE: LLM reads env source code + task description → produces N reward candidates
  2. EVALUATE: Run candidates against stored trajectories → rank by score correlation
  3. REFLECT: Summarize trajectory stats + failure modes → natural language feedback
  4. REFINE: LLM receives reflection + best candidate → produces improved version
  5. REPEAT: Loop until convergence or max iterations

Connected to:
  - Knowledge Graph: KG stats feed into trajectory analysis
  - Red Team: Red team reward signal included in evaluation
  - Overseer: Policy violations feed into reflection
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .trajectory_analyzer import TrajectoryAnalyzer, TrajectoryStats


@dataclass
class RewardCandidate:
    """A generated reward function candidate."""
    candidate_id: str
    code: str                       # Python code defining the reward function
    description: str                # Natural language description
    iteration: int = 0             # Which iteration generated this
    score: float = 0.0              # Evaluation score
    correlation: float = 0.0        # Correlation with grader score
    failure_modes: List[str] = field(default_factory=list)


@dataclass
class RefinementIteration:
    """Record of one refinement iteration."""
    iteration: int
    candidates_generated: int
    best_score: float
    best_candidate_id: str
    reflection: str
    improvements: List[str]
    timestamp: float = field(default_factory=time.time)


class EurekaRewardDesigner:
    """
    EUREKA-style iterative reward refinement with closed feedback loop.

    Unlike a one-shot generation, this system:
    1. Evaluates reward candidates against actual trajectories
    2. Identifies failure modes (loops, premature classification, etc.)
    3. Feeds failure analysis back to the LLM for targeted improvement
    4. Tracks improvement across iterations
    5. Produces a history of refinements for demonstration
    """

    def __init__(
        self,
        llm_client: Optional[Any] = None,
        model_name: str = "gpt-4o-mini",
    ):
        self.llm_client = llm_client
        self.model_name = model_name
        self.analyzer = TrajectoryAnalyzer()
        self.candidates: List[RewardCandidate] = []
        self.iterations: List[RefinementIteration] = []
        self.best_reward: Optional[RewardCandidate] = None
        self._env_source: str = ""
        self._task_description: str = ""

    def set_context(self, env_source_code: str, task_description: str) -> None:
        """Set the environment source code and task description for generation."""
        self._env_source = env_source_code
        self._task_description = task_description

    def generate_reward_candidates(
        self,
        n_candidates: int = 4,
        iteration: int = 0,
    ) -> List[RewardCandidate]:
        """
        Step 1: GENERATE — LLM produces N reward function candidates.
        """
        prompt = self._build_generation_prompt(iteration)

        candidates = []
        for i in range(n_candidates):
            candidate_id = f"reward_v{iteration}_{i}"

            if self.llm_client:
                response = self.llm_client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": self._get_system_prompt()},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.7 + (i * 0.1),  # Diverse temperatures
                    max_tokens=2048,
                )
                code = self._extract_code(response.choices[0].message.content)
                description = self._extract_description(response.choices[0].message.content)
            else:
                # Fallback: generate a template reward function
                code = self._generate_template_reward(iteration, i)
                description = f"Template reward candidate {candidate_id}"

            candidate = RewardCandidate(
                candidate_id=candidate_id,
                code=code,
                description=description,
                iteration=iteration,
            )
            candidates.append(candidate)

        self.candidates.extend(candidates)
        return candidates

    def evaluate_candidates(
        self,
        candidates: List[RewardCandidate],
        trajectories: List[Dict[str, Any]],
        grader_scores: List[float],
    ) -> List[RewardCandidate]:
        """
        Step 2: EVALUATE — Run candidates against stored trajectories.

        Scores each candidate by correlation between its reward output
        and the actual grader scores.
        """
        for candidate in candidates:
            try:
                reward_fn = self._compile_reward(candidate.code)
                candidate_rewards = []

                for traj in trajectories:
                    try:
                        reward = reward_fn(traj)
                        candidate_rewards.append(reward)
                    except Exception:
                        candidate_rewards.append(0.0)
                        candidate.failure_modes.append(f"Runtime error on trajectory")

                # Compute correlation with grader scores
                if len(candidate_rewards) == len(grader_scores) and len(grader_scores) > 1:
                    candidate.correlation = self._pearson_correlation(
                        candidate_rewards, grader_scores
                    )
                    candidate.score = candidate.correlation
                else:
                    candidate.score = sum(candidate_rewards) / max(len(candidate_rewards), 1)

            except Exception as e:
                candidate.score = -1.0
                candidate.failure_modes.append(f"Compilation error: {str(e)}")

        # Sort by score
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    def reflect_and_analyze(
        self,
        trajectories: List[Dict[str, Any]],
        kg_stats: Optional[Dict[str, Any]] = None,
        red_team_stats: Optional[Dict[str, Any]] = None,
        overseer_violations: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Step 3: REFLECT — Analyze trajectories and produce feedback.

        Feeds in:
        - Trajectory stats (from TrajectoryAnalyzer)
        - KG stats (from DAMCS knowledge graph)
        - Red team reward signal
        - Overseer policy violations
        """
        # Analyze trajectories
        stats = self.analyzer.analyze_trajectories(trajectories)

        reflection_parts = [
            "=== EUREKA REFLECTION (Iteration {}) ===\n".format(
                len(self.iterations)
            ),
            f"\nTrajectory Analysis ({stats.num_trajectories} episodes):\n",
            f"  Mean score: {stats.mean_score:.3f}\n",
            f"  Score std: {stats.score_std:.3f}\n",
            f"  Mean steps used: {stats.mean_steps:.1f}\n",
            f"  Timeout rate: {stats.timeout_rate:.1%}\n",
        ]

        # Failure modes
        if stats.common_failure_modes:
            reflection_parts.append("\nCommon Failure Modes:\n")
            for mode, count in stats.common_failure_modes.items():
                reflection_parts.append(f"  - {mode}: {count} occurrences\n")

        # Action distribution
        if stats.action_distribution:
            reflection_parts.append("\nAction Distribution (top 5):\n")
            sorted_actions = sorted(
                stats.action_distribution.items(),
                key=lambda x: x[1], reverse=True
            )[:5]
            for action, count in sorted_actions:
                reflection_parts.append(f"  - {action}: {count}\n")

        # KG integration
        if kg_stats:
            reflection_parts.append("\nKnowledge Graph Insights:\n")
            reflection_parts.append(
                f"  Avg evidence nodes: {kg_stats.get('evidence_count', 0)}\n"
            )
            reflection_parts.append(
                f"  Avg corroboration rate: {kg_stats.get('corroboration_rate', 0)}\n"
            )
            reflection_parts.append(
                f"  Source diversity: {kg_stats.get('source_diversity', 0)}\n"
            )

        # Red team feedback
        if red_team_stats:
            reflection_parts.append("\nRed Team Impact:\n")
            reflection_parts.append(
                f"  Attack success rate: {red_team_stats.get('attack_success_rate', 0):.1%}\n"
            )
            reflection_parts.append(
                f"  Stealth ratio: {red_team_stats.get('stealth_ratio', 0):.1%}\n"
            )
            reflection_parts.append(
                f"  Decoys deployed: {red_team_stats.get('decoy_iocs_deployed', 0)}\n"
            )

        # Overseer feedback
        if overseer_violations:
            reflection_parts.append("\nOverseer Policy Violations:\n")
            for v in overseer_violations[-5:]:
                reflection_parts.append(
                    f"  [{v.get('severity', 'warning')}] "
                    f"{v.get('agent_id', '?')}: {v.get('description', '')}\n"
                )

        # Improvement suggestions
        reflection_parts.append("\nSuggested Reward Improvements:\n")
        suggestions = self.analyzer.suggest_improvements(stats)
        for s in suggestions:
            reflection_parts.append(f"  → {s}\n")

        return "".join(reflection_parts)

    def refine_reward(
        self,
        current_best: RewardCandidate,
        reflection: str,
        iteration: int,
    ) -> RewardCandidate:
        """
        Step 4: REFINE — LLM improves reward based on reflection feedback.
        """
        prompt = (
            f"You are refining a reward function for an incident response environment.\n\n"
            f"Current best reward function (score: {current_best.score:.3f}):\n"
            f"```python\n{current_best.code}\n```\n\n"
            f"Reflection from trajectory analysis:\n{reflection}\n\n"
            f"Generate an improved reward function that addresses the identified failure modes. "
            f"Return ONLY the Python function code."
        )

        if self.llm_client:
            response = self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4,
                max_tokens=2048,
            )
            code = self._extract_code(response.choices[0].message.content)
            description = f"Refined from {current_best.candidate_id} based on reflection"
        else:
            code = self._refine_template_reward(current_best, iteration)
            description = f"Template refinement v{iteration}"

        refined = RewardCandidate(
            candidate_id=f"reward_refined_v{iteration}",
            code=code,
            description=description,
            iteration=iteration,
        )
        return refined

    def run_refinement_loop(
        self,
        trajectories: List[Dict[str, Any]],
        grader_scores: List[float],
        n_iterations: int = 5,
        n_candidates_per_iter: int = 4,
        kg_stats: Optional[Dict[str, Any]] = None,
        red_team_stats: Optional[Dict[str, Any]] = None,
        overseer_violations: Optional[List[Dict[str, Any]]] = None,
    ) -> RewardCandidate:
        """
        Full EUREKA refinement loop with closed feedback.

        generate → evaluate → reflect → refine → repeat
        """
        best_overall = None

        for iteration in range(n_iterations):
            # Step 1: Generate candidates
            if iteration == 0:
                candidates = self.generate_reward_candidates(
                    n_candidates=n_candidates_per_iter,
                    iteration=iteration,
                )
            else:
                # Generate fewer + refine the best
                candidates = self.generate_reward_candidates(
                    n_candidates=max(1, n_candidates_per_iter // 2),
                    iteration=iteration,
                )
                # Add refined version of current best
                if best_overall:
                    reflection = self.reflect_and_analyze(
                        trajectories, kg_stats, red_team_stats, overseer_violations,
                    )
                    refined = self.refine_reward(best_overall, reflection, iteration)
                    candidates.append(refined)

            # Step 2: Evaluate
            evaluated = self.evaluate_candidates(
                candidates, trajectories, grader_scores
            )

            # Step 3: Track best
            if evaluated and evaluated[0].score > 0:
                if best_overall is None or evaluated[0].score > best_overall.score:
                    best_overall = evaluated[0]

            # Step 4: Record iteration
            self.iterations.append(RefinementIteration(
                iteration=iteration,
                candidates_generated=len(candidates),
                best_score=best_overall.score if best_overall else 0.0,
                best_candidate_id=best_overall.candidate_id if best_overall else "",
                reflection=self.reflect_and_analyze(
                    trajectories, kg_stats, red_team_stats, overseer_violations
                ),
                improvements=[
                    c.description for c in evaluated[:2]
                ] if evaluated else [],
            ))

        self.best_reward = best_overall
        return best_overall

    def get_refinement_history(self) -> List[Dict[str, Any]]:
        """Get the full history of refinement iterations (for demo)."""
        return [
            {
                "iteration": it.iteration,
                "candidates": it.candidates_generated,
                "best_score": round(it.best_score, 4),
                "best_id": it.best_candidate_id,
                "improvements": it.improvements,
            }
            for it in self.iterations
        ]

    # --- Internal helpers ---

    def _get_system_prompt(self) -> str:
        return (
            "You are an expert reward function designer for reinforcement learning. "
            "You design reward functions for a cybersecurity incident response environment "
            "where AI agents investigate security alerts, classify threats, and execute containment. "
            "Your reward functions should be Python functions that take a trajectory dict "
            "and return a float score. Focus on: investigation thoroughness, correct classification, "
            "containment precision, and efficiency."
        )

    def _build_generation_prompt(self, iteration: int) -> str:
        prompt = (
            f"Design a reward function for this cybersecurity SOC environment.\n\n"
            f"Task: {self._task_description}\n\n"
        )
        if self._env_source:
            # Include abbreviated env source
            prompt += f"Environment code (abbreviated):\n{self._env_source[:3000]}\n\n"

        prompt += (
            "Generate a Python function with signature:\n"
            "  def compute_reward(trajectory: dict) -> float\n\n"
            "The trajectory dict has keys: actions, evidence_found, iocs_found, "
            "severity_set, category_set, containment_executed, report_submitted, "
            "steps_used, max_steps.\n\n"
            "Return ONLY the Python function code."
        )
        return prompt

    def _extract_code(self, response: str) -> str:
        """Extract Python code from LLM response."""
        if "```python" in response:
            start = response.index("```python") + 9
            end = response.index("```", start)
            return response[start:end].strip()
        if "```" in response:
            start = response.index("```") + 3
            end = response.index("```", start)
            return response[start:end].strip()
        return response.strip()

    def _extract_description(self, response: str) -> str:
        """Extract description from LLM response."""
        lines = response.strip().split("\n")
        for line in lines:
            if not line.startswith("```") and not line.startswith("def ") and line.strip():
                return line.strip()[:200]
        return "Generated reward function"

    def _compile_reward(self, code: str) -> Callable:
        """Compile a reward function from code string."""
        namespace = {}
        exec(code, namespace)
        # Find the function in the namespace
        for name, obj in namespace.items():
            if callable(obj) and name.startswith("compute"):
                return obj
        raise ValueError("No compute_reward function found in generated code")

    def _pearson_correlation(self, x: List[float], y: List[float]) -> float:
        """Compute Pearson correlation between two lists."""
        n = len(x)
        if n < 2:
            return 0.0

        mean_x = sum(x) / n
        mean_y = sum(y) / n

        cov = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
        std_x = sum((xi - mean_x) ** 2 for xi in x) ** 0.5
        std_y = sum((yi - mean_y) ** 2 for yi in y) ** 0.5

        if std_x * std_y == 0:
            return 0.0
        return cov / (std_x * std_y)

    def _generate_template_reward(self, iteration: int, variant: int) -> str:
        """Generate a template reward function (fallback without LLM)."""
        weights = {
            0: (0.25, 0.15, 0.15, 0.10, 0.15, 0.10, 0.10),
            1: (0.20, 0.10, 0.20, 0.10, 0.20, 0.10, 0.10),
            2: (0.15, 0.10, 0.10, 0.15, 0.20, 0.15, 0.15),
            3: (0.20, 0.20, 0.10, 0.10, 0.10, 0.15, 0.15),
        }
        w = weights.get(variant % 4, weights[0])

        return f'''def compute_reward(trajectory: dict) -> float:
    """Auto-generated reward function v{iteration}_{variant}."""
    score = 0.0

    # Evidence discovery ({w[0]:.0%})
    evidence = trajectory.get("evidence_found", [])
    score += {w[0]} * min(len(evidence) / 5, 1.0)

    # IOC identification ({w[1]:.0%})
    iocs = trajectory.get("iocs_found", [])
    score += {w[1]} * min(len(iocs) / 3, 1.0)

    # Classification ({w[2]:.0%})
    if trajectory.get("severity_set"):
        score += {w[2]} * 0.6
    if trajectory.get("category_set"):
        score += {w[2]} * 0.4

    # Containment ({w[3]:.0%})
    containment = trajectory.get("containment_executed", [])
    score += {w[3]} * min(len(containment) / 3, 1.0)

    # Report ({w[4]:.0%})
    if trajectory.get("report_submitted"):
        score += {w[4]}

    # Efficiency ({w[5]:.0%})
    steps = trajectory.get("steps_used", 20)
    max_steps = trajectory.get("max_steps", 20)
    ratio = steps / max(max_steps, 1)
    if ratio <= 0.6:
        score += {w[5]}
    elif ratio <= 0.8:
        score += {w[5]} * 0.6

    # Anti-loop ({w[6]:.0%})
    actions = trajectory.get("actions", [])
    unique_ratio = len(set(actions)) / max(len(actions), 1)
    score += {w[6]} * unique_ratio

    return min(1.0, max(0.0, score))
'''

    def _refine_template_reward(
        self, current: RewardCandidate, iteration: int
    ) -> str:
        """Refine a template reward (fallback without LLM)."""
        # Simple heuristic refinement: adjust weights based on common failures
        return self._generate_template_reward(iteration, iteration % 4)
