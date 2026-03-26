# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment - Base Dataclasses
# BSD-3-Clause License

"""
Shared dataclasses for scenario definitions.

These are used by all task files in the tasks/ package and by the
environment grading engine.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from ..models import ContainmentAction, Severity, ThreatCategory
except ImportError:
    from models import ContainmentAction, Severity, ThreatCategory


@dataclass
class LogEntry:
    """A single log entry that can be discovered during investigation."""
    source: str  # firewall, edr, proxy, auth, dns, email
    content: str
    is_critical: bool = False  # Whether this is key evidence
    keywords: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelEntry:
    """Threat intelligence data linked to an IOC."""
    ioc: str
    ioc_type: str  # ip, domain, hash, email
    description: str
    severity: str
    source: str
    keywords: List[str] = field(default_factory=list)


@dataclass
class EndpointInfo:
    """Information about an endpoint in the network."""
    endpoint_id: str
    hostname: str
    os: str
    ip: str
    status: str
    processes: List[str] = field(default_factory=list)
    connections: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    is_compromised: bool = False


@dataclass
class UserProfile:
    """User profile information for investigation."""
    user_id: str
    display_name: str
    department: str
    role: str
    recent_logins: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    notes: str = ""


@dataclass
class Scenario:
    """Complete incident scenario definition."""
    # Identification
    scenario_id: str
    task_id: str  # easy, medium, hard, medium_hard, hard_plus, expert
    difficulty: str

    # Alert metadata
    alert_summary: str
    alert_source: str
    alert_timestamp: str
    initial_observation: str

    # Ground truth
    true_severity: Severity
    true_category: ThreatCategory
    required_containment: List[ContainmentAction]
    containment_targets: Dict[str, str]  # action -> target
    is_false_positive: bool = False
    correct_escalation: Optional[str] = None  # None if no escalation needed

    # Evidence layers
    log_entries: List[LogEntry] = field(default_factory=list)
    threat_intel: List[ThreatIntelEntry] = field(default_factory=list)
    endpoints: List[EndpointInfo] = field(default_factory=list)
    users: List[UserProfile] = field(default_factory=list)
    correlation_findings: List[str] = field(default_factory=list)

    # Critical evidence items the agent should find
    critical_evidence: Set[str] = field(default_factory=set)
    critical_iocs: Set[str] = field(default_factory=set)

    # Episode parameters
    max_steps: int = 20
    report_keywords: List[str] = field(default_factory=list)

    # Multi-target containment (new: for scenarios with multiple targets per action type)
    required_containment_pairs: List[Tuple[str, str]] = field(default_factory=list)
