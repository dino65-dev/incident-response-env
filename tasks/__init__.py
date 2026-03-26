# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Tasks Package
# BSD-3-Clause License

"""
Task definitions for the Incident Response Triage Environment.

Exports SCENARIOS dict and TASK_DEFINITIONS dict for use by the environment
and server components.
"""

try:
    from .task_easy_phishing import SCENARIO_EASY_PHISHING, TASK_DEFINITION as TD_EASY
    from .task_medium_lateral import SCENARIO_MEDIUM_LATERAL, TASK_DEFINITION as TD_MEDIUM
    from .task_hard_insider import SCENARIO_HARD_INSIDER, TASK_DEFINITION as TD_HARD
    from .task_medium_ransomware import SCENARIO_MEDIUM_RANSOMWARE, TASK_DEFINITION as TD_MEDIUM_HARD
    from .task_hard_supply_chain import SCENARIO_HARD_SUPPLY_CHAIN, TASK_DEFINITION as TD_HARD_PLUS
    from .task_expert_apt_zeroday import SCENARIO_EXPERT_APT_ZERODAY, TASK_DEFINITION as TD_EXPERT
    from .base import LogEntry, ThreatIntelEntry, EndpointInfo, UserProfile, Scenario
except ImportError:
    from tasks.task_easy_phishing import SCENARIO_EASY_PHISHING, TASK_DEFINITION as TD_EASY
    from tasks.task_medium_lateral import SCENARIO_MEDIUM_LATERAL, TASK_DEFINITION as TD_MEDIUM
    from tasks.task_hard_insider import SCENARIO_HARD_INSIDER, TASK_DEFINITION as TD_HARD
    from tasks.task_medium_ransomware import SCENARIO_MEDIUM_RANSOMWARE, TASK_DEFINITION as TD_MEDIUM_HARD
    from tasks.task_hard_supply_chain import SCENARIO_HARD_SUPPLY_CHAIN, TASK_DEFINITION as TD_HARD_PLUS
    from tasks.task_expert_apt_zeroday import SCENARIO_EXPERT_APT_ZERODAY, TASK_DEFINITION as TD_EXPERT
    from tasks.base import LogEntry, ThreatIntelEntry, EndpointInfo, UserProfile, Scenario


SCENARIOS = {
    "easy": SCENARIO_EASY_PHISHING,
    "medium": SCENARIO_MEDIUM_LATERAL,
    "hard": SCENARIO_HARD_INSIDER,
    "medium_hard": SCENARIO_MEDIUM_RANSOMWARE,
    "hard_plus": SCENARIO_HARD_SUPPLY_CHAIN,
    "expert": SCENARIO_EXPERT_APT_ZERODAY,
}

TASK_DEFINITIONS = {
    "easy": TD_EASY,
    "medium": TD_MEDIUM,
    "hard": TD_HARD,
    "medium_hard": TD_MEDIUM_HARD,
    "hard_plus": TD_HARD_PLUS,
    "expert": TD_EXPERT,
}

__all__ = [
    "SCENARIOS",
    "TASK_DEFINITIONS",
    "LogEntry",
    "ThreatIntelEntry",
    "EndpointInfo",
    "UserProfile",
    "Scenario",
]
