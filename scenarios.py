# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Backward Compatibility Wrapper
# BSD-3-Clause License

"""Backward compatibility wrapper. Scenarios now live in tasks/ package."""

try:
    from tasks import SCENARIOS, TASK_DEFINITIONS
    from tasks.base import LogEntry, ThreatIntelEntry, EndpointInfo, UserProfile, Scenario
except ImportError:
    from .tasks import SCENARIOS, TASK_DEFINITIONS
    from .tasks.base import LogEntry, ThreatIntelEntry, EndpointInfo, UserProfile, Scenario

# Re-export individual scenarios for backward compat
SCENARIO_EASY_PHISHING = SCENARIOS["easy"]
SCENARIO_MEDIUM_LATERAL = SCENARIOS["medium"]
SCENARIO_HARD_INSIDER = SCENARIOS["hard"]

__all__ = [
    "SCENARIOS",
    "TASK_DEFINITIONS",
    "LogEntry",
    "ThreatIntelEntry",
    "EndpointInfo",
    "UserProfile",
    "Scenario",
    "SCENARIO_EASY_PHISHING",
    "SCENARIO_MEDIUM_LATERAL",
    "SCENARIO_HARD_INSIDER",
]
