# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Trajectory Analyzer for EUREKA Feedback Loop
# BSD-3-Clause License

"""
Trajectory analysis for EUREKA reward refinement feedback loop.

Analyzes agent trajectories to:
  - Identify common failure modes (loops, premature classification, etc.)
  - Compute aggregate statistics for LLM reflection
  - Suggest specific reward improvements
  - Feed KG stats into the analysis
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TrajectoryStats:
    """Aggregate statistics from a batch of trajectories."""
    num_trajectories: int = 0
    mean_score: float = 0.0
    score_std: float = 0.0
    mean_steps: float = 0.0
    timeout_rate: float = 0.0
    completion_rate: float = 0.0
    mean_evidence_found: float = 0.0
    mean_iocs_found: float = 0.0
    severity_accuracy: float = 0.0
    category_accuracy: float = 0.0
    containment_rate: float = 0.0
    report_rate: float = 0.0
    action_distribution: Dict[str, int] = field(default_factory=dict)
    common_failure_modes: Dict[str, int] = field(default_factory=dict)
    phase_violations: int = 0
    loop_incidents: int = 0
    # KG integration
    avg_kg_nodes: float = 0.0
    avg_kg_confidence: float = 0.0
    avg_source_diversity: float = 0.0


class TrajectoryAnalyzer:
    """
    Analyzes agent trajectories for the EUREKA feedback loop.

    Produces structured statistics and natural language summaries
    that the LLM can use to improve reward functions.
    """

    def analyze_trajectories(
        self,
        trajectories: List[Dict[str, Any]],
    ) -> TrajectoryStats:
        """
        Compute aggregate statistics from a batch of trajectories.
        """
        if not trajectories:
            return TrajectoryStats()

        n = len(trajectories)
        stats = TrajectoryStats(num_trajectories=n)

        scores = []
        steps_list = []
        evidence_counts = []
        ioc_counts = []
        action_dist: Dict[str, int] = {}
        failure_modes: Dict[str, int] = {}
        timeouts = 0
        completions = 0
        severity_correct = 0
        category_correct = 0
        contained = 0
        reported = 0
        phase_violations = 0
        loops = 0
        kg_nodes_list = []
        kg_conf_list = []
        kg_diversity_list = []

        for traj in trajectories:
            score = traj.get("score", 0.0)
            scores.append(score)

            steps = traj.get("steps_used", 0)
            steps_list.append(steps)

            max_steps = traj.get("max_steps", 20)
            if steps >= max_steps and not traj.get("report_submitted", False):
                timeouts += 1
                failure_modes["timeout"] = failure_modes.get("timeout", 0) + 1

            if traj.get("report_submitted", False):
                completions += 1
                reported += 1

            evidence = traj.get("evidence_found", [])
            evidence_counts.append(len(evidence))

            iocs = traj.get("iocs_found", [])
            ioc_counts.append(len(iocs))

            if traj.get("severity_correct", False):
                severity_correct += 1

            if traj.get("category_correct", False):
                category_correct += 1

            if traj.get("containment_executed", []):
                contained += 1

            # Action distribution
            actions = traj.get("actions", [])
            for action in actions:
                action_dist[action] = action_dist.get(action, 0) + 1

            # Detect loops (same action 3+ times in a row)
            for i in range(len(actions) - 2):
                if actions[i] == actions[i+1] == actions[i+2]:
                    loops += 1
                    failure_modes["action_loop"] = failure_modes.get("action_loop", 0) + 1
                    break

            # Detect premature classification
            if "classify_severity" in actions:
                classify_idx = actions.index("classify_severity")
                investigate_count = sum(
                    1 for a in actions[:classify_idx]
                    if a in ("query_logs", "check_threat_intel", "inspect_endpoint")
                )
                if investigate_count < 2:
                    failure_modes["premature_classification"] = \
                        failure_modes.get("premature_classification", 0) + 1

            # Detect containment before classification
            if "contain_threat" in actions and "classify_severity" in actions:
                contain_idx = actions.index("contain_threat")
                classify_idx = actions.index("classify_severity")
                if contain_idx < classify_idx:
                    phase_violations += 1
                    failure_modes["contain_before_classify"] = \
                        failure_modes.get("contain_before_classify", 0) + 1

            # KG stats integration
            kg_stats = traj.get("kg_stats", {})
            if kg_stats:
                kg_nodes_list.append(kg_stats.get("evidence_count", 0))
                kg_conf_list.append(kg_stats.get("avg_confidence", 0))
                kg_diversity_list.append(kg_stats.get("source_diversity", 0))

        # Compute aggregates
        stats.mean_score = sum(scores) / n
        stats.score_std = (
            sum((s - stats.mean_score) ** 2 for s in scores) / n
        ) ** 0.5
        stats.mean_steps = sum(steps_list) / n
        stats.timeout_rate = timeouts / n
        stats.completion_rate = completions / n
        stats.mean_evidence_found = sum(evidence_counts) / n
        stats.mean_iocs_found = sum(ioc_counts) / n
        stats.severity_accuracy = severity_correct / n
        stats.category_accuracy = category_correct / n
        stats.containment_rate = contained / n
        stats.report_rate = reported / n
        stats.action_distribution = action_dist
        stats.common_failure_modes = failure_modes
        stats.phase_violations = phase_violations
        stats.loop_incidents = loops

        if kg_nodes_list:
            stats.avg_kg_nodes = sum(kg_nodes_list) / len(kg_nodes_list)
            stats.avg_kg_confidence = sum(kg_conf_list) / len(kg_conf_list)
            stats.avg_source_diversity = sum(kg_diversity_list) / len(kg_diversity_list)

        return stats

    def suggest_improvements(self, stats: TrajectoryStats) -> List[str]:
        """
        Generate specific reward improvement suggestions based on analysis.
        These are fed back to the LLM for guided refinement.
        """
        suggestions = []

        # Score-based suggestions
        if stats.mean_score < 0.5:
            suggestions.append(
                "Overall scores are low. Consider increasing rewards for "
                "evidence discovery and correct classification."
            )

        # Failure mode-based suggestions
        if stats.common_failure_modes.get("timeout", 0) > stats.num_trajectories * 0.3:
            suggestions.append(
                "High timeout rate ({:.0%}). Add stronger efficiency incentives "
                "or penalties for slow progress.".format(stats.timeout_rate)
            )

        if stats.common_failure_modes.get("action_loop", 0) > 0:
            suggestions.append(
                "Action loops detected ({} episodes). Strengthen anti-loop "
                "penalty or add diversity bonus.".format(stats.loop_incidents)
            )

        if stats.common_failure_modes.get("premature_classification", 0) > 0:
            count = stats.common_failure_modes["premature_classification"]
            suggestions.append(
                f"Premature classification in {count} episodes. "
                "Add minimum evidence threshold before classification reward."
            )

        if stats.common_failure_modes.get("contain_before_classify", 0) > 0:
            suggestions.append(
                "Phase discipline violations detected. "
                "Increase penalty for containment before classification."
            )

        # Coverage suggestions
        if stats.mean_evidence_found < 3:
            suggestions.append(
                "Low evidence discovery ({:.1f} avg). Increase per-evidence "
                "reward to encourage thorough investigation.".format(
                    stats.mean_evidence_found
                )
            )

        if stats.containment_rate < 0.5:
            suggestions.append(
                "Low containment rate ({:.0%}). Ensure containment reward "
                "is proportional to threat severity.".format(stats.containment_rate)
            )

        if stats.report_rate < 0.7:
            suggestions.append(
                "Low report submission rate ({:.0%}). Add explicit reward "
                "for report submission even with imperfect investigation.".format(
                    stats.report_rate
                )
            )

        # KG-based suggestions
        if stats.avg_source_diversity < 3:
            suggestions.append(
                "Low source diversity in knowledge graphs ({:.1f} avg). "
                "Add reward for querying diverse log sources.".format(
                    stats.avg_source_diversity
                )
            )

        if not suggestions:
            suggestions.append(
                "Performance is solid. Consider fine-tuning weight distribution "
                "or adding bonus for investigation breadth."
            )

        return suggestions

    def trajectory_to_summary(self, trajectory: Dict[str, Any]) -> str:
        """
        Convert a single trajectory to a natural language summary
        for LLM consumption during reflection.
        """
        actions = trajectory.get("actions", [])
        score = trajectory.get("score", 0.0)
        steps = trajectory.get("steps_used", 0)
        evidence = trajectory.get("evidence_found", [])
        iocs = trajectory.get("iocs_found", [])

        return (
            f"Episode: {steps} steps, score={score:.3f}, "
            f"evidence={len(evidence)}, iocs={len(iocs)}, "
            f"actions={' → '.join(actions[:10])}"
            f"{'...' if len(actions) > 10 else ''}"
        )
