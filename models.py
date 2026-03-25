# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment
# BSD-3-Clause License

"""
Data models for the Incident Response Triage Environment.

This environment simulates a Security Operations Center (SOC) where an AI agent
must triage cybersecurity alerts, investigate incidents through structured
forensic actions, and execute appropriate containment/response measures.

The agent interacts through a structured action space that mirrors real SOC
analyst workflows: examine logs, query threat intel, correlate events,
classify severity, and take response actions.
"""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from openenv.core.env_server.types import Action, Observation, State
from pydantic import Field


# =============================================================================
# Enums for Type Safety
# =============================================================================


class Severity(str, Enum):
    """Alert severity levels following standard SOC classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ActionType(str, Enum):
    """Available investigation and response action types."""
    # Investigation actions
    EXAMINE_ALERT = "examine_alert"
    QUERY_LOGS = "query_logs"
    CHECK_THREAT_INTEL = "check_threat_intel"
    CORRELATE_EVENTS = "correlate_events"
    INSPECT_ENDPOINT = "inspect_endpoint"
    CHECK_USER_HISTORY = "check_user_history"

    # Response actions
    CLASSIFY_SEVERITY = "classify_severity"
    CONTAIN_THREAT = "contain_threat"
    ESCALATE = "escalate"
    CLOSE_AS_FALSE_POSITIVE = "close_as_false_positive"
    SUBMIT_REPORT = "submit_report"


class ContainmentAction(str, Enum):
    """Containment response actions available to the agent."""
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    REVOKE_SESSIONS = "revoke_sessions"
    NONE = "none"


class ThreatCategory(str, Enum):
    """Categories of security threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    INSIDER_THREAT = "insider_threat"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FALSE_POSITIVE = "false_positive"


# =============================================================================
# Action Model
# =============================================================================


class IncidentAction(Action):
    """
    Action for the Incident Response environment.

    The agent selects an action_type and provides relevant parameters.
    Investigation actions gather information; response actions resolve the incident.
    """

    action_type: ActionType = Field(
        ..., description="Type of action to perform (investigation or response)"
    )

    # Investigation parameters
    log_source: Optional[str] = Field(
        None,
        description="Log source to query: 'firewall', 'edr', 'proxy', 'auth', 'dns', 'email'"
    )
    query_filter: Optional[str] = Field(
        None,
        description="Filter/keyword for log queries or threat intel lookups"
    )
    endpoint_id: Optional[str] = Field(
        None, description="Endpoint/host identifier to inspect"
    )
    user_id: Optional[str] = Field(
        None, description="User identifier for history check"
    )

    # Response parameters
    severity: Optional[Severity] = Field(
        None, description="Severity classification for the incident"
    )
    threat_category: Optional[ThreatCategory] = Field(
        None, description="Category of the detected threat"
    )
    containment_actions: Optional[List[ContainmentAction]] = Field(
        None, description="List of containment actions to execute"
    )
    target: Optional[str] = Field(
        None, description="Target for containment (IP, hostname, username, file hash)"
    )
    report_summary: Optional[str] = Field(
        None,
        description="Final incident report summary (required for submit_report)"
    )
    escalate_to: Optional[str] = Field(
        None,
        description="Escalation target: 'tier2', 'tier3', 'management', 'legal'"
    )


# =============================================================================
# Observation Model
# =============================================================================


class IncidentObservation(Observation):
    """
    Observation from the Incident Response environment.

    Contains structured information about the current alert state,
    investigation findings, and action results.
    """

    # Alert context
    alert_id: str = Field(default="", description="Unique alert identifier")
    alert_summary: str = Field(default="", description="Human-readable alert summary")
    alert_source: str = Field(default="", description="Source system that generated the alert")
    timestamp: str = Field(default="", description="Alert timestamp in ISO format")

    # Investigation results
    findings: str = Field(
        default="",
        description="Results from the last investigation action"
    )
    evidence_collected: List[str] = Field(
        default_factory=list,
        description="List of evidence items gathered so far"
    )
    iocs_discovered: List[str] = Field(
        default_factory=list,
        description="Indicators of Compromise found during investigation"
    )

    # Environment feedback
    action_result: str = Field(
        default="", description="Result/feedback from the last action taken"
    )
    available_actions: List[str] = Field(
        default_factory=list,
        description="Actions currently available to the agent"
    )
    steps_remaining: int = Field(
        default=0, description="Investigation steps remaining before timeout"
    )
    investigation_progress: float = Field(
        default=0.0,
        description="Fraction of critical evidence discovered (0.0-1.0)"
    )


# =============================================================================
# State Model
# =============================================================================


class IncidentState(State):
    """Extended state for tracking incident investigation progress."""

    current_task: str = Field(default="", description="Current task identifier")
    severity_classified: bool = Field(default=False)
    threat_categorized: bool = Field(default=False)
    containment_executed: bool = Field(default=False)
    report_submitted: bool = Field(default=False)
    evidence_found: List[str] = Field(default_factory=list)
    iocs_found: List[str] = Field(default_factory=list)
    actions_taken: List[str] = Field(default_factory=list)
    reward_accumulated: float = Field(default=0.0)
    investigation_complete: bool = Field(default=False)


__all__ = [
    "Severity",
    "ActionType",
    "ContainmentAction",
    "ThreatCategory",
    "IncidentAction",
    "IncidentObservation",
    "IncidentState",
]
