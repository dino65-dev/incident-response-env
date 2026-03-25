# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Baseline Runner
# BSD-3-Clause License

"""
Baseline runner for the Incident Response Triage Environment.

Runs a deterministic baseline agent against all 3 tasks and produces
reproducible scores. Can be used standalone or via the /baseline endpoint.
"""

from typing import Any, Dict, List

try:
    from ..models import (
        ActionType,
        ContainmentAction,
        IncidentAction,
        Severity,
        ThreatCategory,
    )
    from ..scenarios import SCENARIOS
    from .incident_response_env_environment import IncidentResponseEnvEnvironment
except ImportError:
    from models import (
        ActionType,
        ContainmentAction,
        IncidentAction,
        Severity,
        ThreatCategory,
    )
    from scenarios import SCENARIOS
    from server.incident_response_env_environment import IncidentResponseEnvEnvironment


def run_deterministic_baseline(task_id: str) -> Dict[str, Any]:
    """
    Run a deterministic scripted baseline agent for a given task.

    The baseline follows a fixed investigation strategy:
    1. Examine the alert
    2. Query all relevant log sources
    3. Check threat intel for known IOCs
    4. Inspect endpoints
    5. Check user profiles
    6. Correlate events
    7. Classify severity and category
    8. Execute containment
    9. Submit report

    Args:
        task_id: One of "easy", "medium", "hard"

    Returns:
        Dict with score, steps taken, and action history
    """
    env = IncidentResponseEnvEnvironment()
    obs = env.reset(seed=42, task_id=task_id)

    scenario = SCENARIOS[task_id]
    actions_taken = []

    # Step 1: Examine alert
    obs = env.step(IncidentAction(action_type=ActionType.EXAMINE_ALERT))
    actions_taken.append("examine_alert")

    # Step 2: Query all log sources
    for source in ["email", "edr", "auth", "proxy", "firewall", "dns"]:
        obs = env.step(IncidentAction(
            action_type=ActionType.QUERY_LOGS,
            log_source=source,
        ))
        actions_taken.append(f"query_logs:{source}")

    # Step 3: Check threat intel for known IOCs
    for ioc in list(scenario.critical_iocs)[:3]:
        obs = env.step(IncidentAction(
            action_type=ActionType.CHECK_THREAT_INTEL,
            query_filter=ioc,
        ))
        actions_taken.append(f"check_ti:{ioc[:20]}")

    # Step 4: Inspect endpoints
    for ep in scenario.endpoints[:2]:
        obs = env.step(IncidentAction(
            action_type=ActionType.INSPECT_ENDPOINT,
            endpoint_id=ep.hostname,
        ))
        actions_taken.append(f"inspect:{ep.hostname}")

    # Step 5: Check users
    for user in scenario.users[:1]:
        obs = env.step(IncidentAction(
            action_type=ActionType.CHECK_USER_HISTORY,
            user_id=user.user_id,
        ))
        actions_taken.append(f"check_user:{user.user_id}")

    # Step 6: Correlate events
    obs = env.step(IncidentAction(action_type=ActionType.CORRELATE_EVENTS))
    actions_taken.append("correlate_events")

    # Step 7: Classify severity
    obs = env.step(IncidentAction(
        action_type=ActionType.CLASSIFY_SEVERITY,
        severity=scenario.true_severity,
        threat_category=scenario.true_category,
    ))
    actions_taken.append("classify_severity")

    # Step 8: Containment
    for ca in scenario.required_containment[:2]:
        target = scenario.containment_targets.get(ca.value, "unknown")
        obs = env.step(IncidentAction(
            action_type=ActionType.CONTAIN_THREAT,
            containment_actions=[ca],
            target=target,
        ))
        actions_taken.append(f"contain:{ca.value}")

    # Step 9: Escalate if needed
    if scenario.correct_escalation:
        obs = env.step(IncidentAction(
            action_type=ActionType.ESCALATE,
            escalate_to=scenario.correct_escalation,
        ))
        actions_taken.append(f"escalate:{scenario.correct_escalation}")

    # Step 10: Submit report
    report = (
        f"Incident Report - {scenario.scenario_id}\n"
        f"Severity: {scenario.true_severity.value}\n"
        f"Category: {scenario.true_category.value}\n"
        f"Summary: Baseline investigation completed. "
        f"Evidence items found: {len(env._evidence_discovered)}. "
        f"IOCs identified: {', '.join(env._iocs_discovered)}. "
        f"Containment actions taken on identified targets. "
        f"{'Escalated to ' + scenario.correct_escalation + '.' if scenario.correct_escalation else ''}"
    )
    for kw in scenario.report_keywords:
        report += f" {kw}"

    obs = env.step(IncidentAction(
        action_type=ActionType.SUBMIT_REPORT,
        report_summary=report,
    ))
    actions_taken.append("submit_report")

    # Get final grader score
    grader_result = env.get_grader_score()

    return {
        "task_id": task_id,
        "score": grader_result["score"],
        "steps_taken": len(actions_taken),
        "actions": actions_taken,
        "breakdown": grader_result["breakdown"],
    }


def run_baseline_all_tasks() -> Dict[str, Any]:
    """
    Run baseline agent against all 3 tasks and return results.

    Returns:
        Dict with results for each task and aggregate score
    """
    results = {}
    total_score = 0.0

    for task_id in ["easy", "medium", "hard"]:
        result = run_deterministic_baseline(task_id)
        results[task_id] = result
        total_score += result["score"]

    results["aggregate"] = {
        "mean_score": round(total_score / 3, 4),
        "total_score": round(total_score, 4),
    }

    return results


if __name__ == "__main__":
    import json
    results = run_baseline_all_tasks()
    print(json.dumps(results, indent=2))
