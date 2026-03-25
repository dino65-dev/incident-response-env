# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment
# BSD-3-Clause License

"""
Incident Response Triage Environment Implementation.

A real-world SOC analyst simulation where AI agents investigate cybersecurity
alerts, gather forensic evidence, correlate findings, classify threats,
and execute incident response actions.

Features:
- 3 tasks with progressive difficulty (easy → medium → hard)
- Rich, multi-dimensional reward shaping over the full trajectory
- Realistic forensic artifacts and investigation mechanics
- Programmatic graders with deterministic scoring

Evaluation criteria:
- Investigation thoroughness (evidence discovery)
- IOC identification
- Correct severity classification
- Appropriate containment actions
- Report quality
- Efficiency (steps used)
"""

import random
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import (
        ActionType,
        ContainmentAction,
        IncidentAction,
        IncidentObservation,
        IncidentState,
        Severity,
        ThreatCategory,
    )
    from ..scenarios import SCENARIOS, Scenario, TASK_DEFINITIONS
except ImportError:
    from models import (
        ActionType,
        ContainmentAction,
        IncidentAction,
        IncidentObservation,
        IncidentState,
        Severity,
        ThreatCategory,
    )
    from scenarios import SCENARIOS, Scenario, TASK_DEFINITIONS


class IncidentResponseEnvEnvironment(Environment):
    """
    A cybersecurity incident response environment for training AI SOC agents.

    The agent receives an alert and must investigate it through structured
    forensic actions (examining logs, querying threat intel, inspecting endpoints,
    correlating events) and then take appropriate response actions (classify
    severity, contain the threat, submit a report).

    Reward is shaped across the full trajectory:
    - Investigation actions that discover critical evidence earn partial reward
    - IOC discovery is rewarded incrementally
    - Correct severity classification earns reward
    - Appropriate containment actions earn reward
    - A quality incident report earns bonus reward
    - Efficiency bonus for completing within expected step range
    - Penalties for destructive actions (containing the wrong target),
      infinite investigation loops, or misclassification

    Example:
        >>> env = IncidentResponseEnvEnvironment()
        >>> obs = env.reset(task_id="easy")
        >>> obs = env.step(IncidentAction(action_type=ActionType.EXAMINE_ALERT))
        >>> obs = env.step(IncidentAction(
        ...     action_type=ActionType.QUERY_LOGS,
        ...     log_source="email", query_filter="phishing"
        ... ))
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = False

    def __init__(self):
        """Initialize the incident response environment."""
        self._state = IncidentState(episode_id=str(uuid4()), step_count=0)
        self._scenario: Optional[Scenario] = None
        self._evidence_discovered: Set[str] = set()
        self._iocs_discovered: Set[str] = set()
        self._actions_history: List[str] = []
        self._containment_executed: List[Tuple[str, str]] = []
        self._severity_set: Optional[Severity] = None
        self._category_set: Optional[ThreatCategory] = None
        self._escalated_to: Optional[str] = None
        self._report_submitted: bool = False
        self._report_text: str = ""
        self._episode_done: bool = False
        self._task_id: str = "easy"
        self._reward_this_step: float = 0.0
        self._total_reward: float = 0.0
        self._closed_as_fp: bool = False

    def reset(self, seed=None, episode_id=None, task_id: str = None, **kwargs) -> IncidentObservation:
        """
        Reset the environment with a specific task.

        Args:
            seed: Optional seed for reproducibility
            episode_id: Optional custom episode ID
            task_id: Task identifier: "easy", "medium", or "hard"

        Returns:
            Initial IncidentObservation with alert context
        """
        # Determine task
        if task_id is None:
            task_id = kwargs.get("task_id", "easy")
        self._task_id = task_id if task_id in SCENARIOS else "easy"

        # Load scenario
        self._scenario = SCENARIOS[self._task_id]

        # Reset all state
        self._state = IncidentState(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            current_task=self._task_id,
        )
        self._evidence_discovered = set()
        self._iocs_discovered = set()
        self._actions_history = []
        self._containment_executed = []
        self._severity_set = None
        self._category_set = None
        self._escalated_to = None
        self._report_submitted = False
        self._report_text = ""
        self._episode_done = False
        self._reward_this_step = 0.0
        self._total_reward = 0.0
        self._closed_as_fp = False

        if seed is not None:
            random.seed(seed)

        return IncidentObservation(
            alert_id=self._scenario.scenario_id,
            alert_summary=self._scenario.alert_summary,
            alert_source=self._scenario.alert_source,
            timestamp=self._scenario.alert_timestamp,
            findings=self._scenario.initial_observation,
            evidence_collected=[],
            iocs_discovered=[],
            action_result="Environment initialized. Begin your investigation.",
            available_actions=[at.value for at in ActionType],
            steps_remaining=self._scenario.max_steps,
            investigation_progress=0.0,
            done=False,
            reward=0.0,
        )

    def step(self, action: IncidentAction) -> IncidentObservation:
        """
        Execute an investigation or response action.

        Args:
            action: IncidentAction specifying the action type and parameters

        Returns:
            IncidentObservation with results and reward
        """
        if self._scenario is None:
            return self._error_obs("Environment not initialized. Call reset() first.")

        if self._episode_done:
            return self._error_obs("Episode is complete. Call reset() to start a new one.")

        self._state.step_count += 1
        self._reward_this_step = 0.0

        # Check step limit
        steps_remaining = self._scenario.max_steps - self._state.step_count
        if steps_remaining <= 0:
            self._episode_done = True
            # Penalty for running out of time without resolving
            if not self._report_submitted and not self._closed_as_fp:
                self._reward_this_step = -0.1
            self._total_reward += self._reward_this_step
            return self._build_observation(
                findings="Investigation time limit reached. Episode terminated.",
                action_result="TIMEOUT: You ran out of investigation steps.",
                steps_remaining=0,
            )

        # Track action
        self._actions_history.append(action.action_type.value)

        # Penalize repeated identical actions (anti-loop)
        recent = self._actions_history[-5:]
        if len(recent) >= 3 and len(set(recent)) == 1:
            self._reward_this_step -= 0.02

        # Route to handler
        handler_map = {
            ActionType.EXAMINE_ALERT: self._handle_examine_alert,
            ActionType.QUERY_LOGS: self._handle_query_logs,
            ActionType.CHECK_THREAT_INTEL: self._handle_check_threat_intel,
            ActionType.CORRELATE_EVENTS: self._handle_correlate_events,
            ActionType.INSPECT_ENDPOINT: self._handle_inspect_endpoint,
            ActionType.CHECK_USER_HISTORY: self._handle_check_user,
            ActionType.CLASSIFY_SEVERITY: self._handle_classify_severity,
            ActionType.CONTAIN_THREAT: self._handle_contain_threat,
            ActionType.ESCALATE: self._handle_escalate,
            ActionType.CLOSE_AS_FALSE_POSITIVE: self._handle_close_fp,
            ActionType.SUBMIT_REPORT: self._handle_submit_report,
        }

        handler = handler_map.get(action.action_type)
        if handler is None:
            return self._error_obs(f"Unknown action type: {action.action_type}")

        obs = handler(action)
        self._total_reward += self._reward_this_step

        return obs

    # =========================================================================
    # Investigation Action Handlers
    # =========================================================================

    def _handle_examine_alert(self, action: IncidentAction) -> IncidentObservation:
        """Provide detailed alert context."""
        s = self._scenario
        findings = (
            f"ALERT DETAILS:\n"
            f"  ID: {s.scenario_id}\n"
            f"  Source: {s.alert_source}\n"
            f"  Time: {s.alert_timestamp}\n"
            f"  Summary: {s.alert_summary}\n\n"
            f"RECOMMENDED NEXT STEPS:\n"
            f"  1. Query relevant log sources (email, edr, auth, proxy, dns, firewall)\n"
            f"  2. Check threat intelligence for any IOCs mentioned\n"
            f"  3. Inspect affected endpoints\n"
            f"  4. Check user activity history\n"
            f"  5. Correlate events across sources"
        )

        # Small reward for starting investigation properly
        self._reward_this_step += 0.01

        return self._build_observation(
            findings=findings,
            action_result="Alert details retrieved successfully.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_query_logs(self, action: IncidentAction) -> IncidentObservation:
        """Query log sources with optional filtering."""
        s = self._scenario
        log_source = (action.log_source or "").lower()
        query_filter = (action.query_filter or "").lower()

        if not log_source:
            return self._build_observation(
                findings="No log source specified.",
                action_result="ERROR: Please specify a log_source: 'firewall', 'edr', 'proxy', 'auth', 'dns', 'email'",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        # Find matching log entries
        matching_logs = []
        for entry in s.log_entries:
            if entry.source.lower() == log_source:
                if not query_filter or any(kw in query_filter or query_filter in kw for kw in entry.keywords):
                    matching_logs.append(entry)

        if not matching_logs:
            # Also check if any logs match partial filter across all sources
            if not log_source or log_source not in ["firewall", "edr", "proxy", "auth", "dns", "email"]:
                return self._build_observation(
                    findings=f"Invalid log source: '{log_source}'",
                    action_result="Available log sources: firewall, edr, proxy, auth, dns, email",
                    steps_remaining=self._scenario.max_steps - self._state.step_count,
                )
            return self._build_observation(
                findings=f"No log entries found in '{log_source}' matching filter '{query_filter}'.",
                action_result=f"Query returned 0 results from {log_source} logs.",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        # Build findings
        findings_parts = [f"LOG QUERY RESULTS ({log_source.upper()}):\n"]
        for entry in matching_logs:
            findings_parts.append(f"  {entry.content}\n")

            # Award evidence discovery
            if entry.is_critical:
                evidence_keys = self._extract_evidence_keys(entry)
                new_evidence = evidence_keys - self._evidence_discovered
                if new_evidence:
                    self._evidence_discovered.update(new_evidence)
                    self._state.evidence_found = list(self._evidence_discovered)
                    # Reward for discovering critical evidence
                    self._reward_this_step += 0.03 * len(new_evidence)

            # Extract IOCs from log content
            new_iocs = self._extract_iocs_from_content(entry.content)
            newly_found = new_iocs - self._iocs_discovered
            if newly_found:
                self._iocs_discovered.update(newly_found)
                self._state.iocs_found = list(self._iocs_discovered)
                self._reward_this_step += 0.02 * len(newly_found)

        findings = "".join(findings_parts)
        return self._build_observation(
            findings=findings,
            action_result=f"Retrieved {len(matching_logs)} log entries from {log_source}.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_check_threat_intel(self, action: IncidentAction) -> IncidentObservation:
        """Check threat intelligence for IOCs."""
        s = self._scenario
        query = (action.query_filter or "").lower()

        if not query:
            return self._build_observation(
                findings="No IOC or query specified for threat intelligence lookup.",
                action_result="ERROR: Please specify a query_filter with an IOC (IP, domain, hash, email) to look up.",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        # Find matching threat intel
        matches = []
        for ti in s.threat_intel:
            if query in ti.ioc.lower() or any(query in kw for kw in ti.keywords):
                matches.append(ti)

        if not matches:
            return self._build_observation(
                findings=f"THREAT INTEL: No results found for query '{query}'.",
                action_result="No threat intelligence data found for this indicator.",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        findings_parts = ["THREAT INTELLIGENCE RESULTS:\n"]
        for ti in matches:
            findings_parts.append(
                f"  IOC: {ti.ioc} (Type: {ti.ioc_type})\n"
                f"  Severity: {ti.severity}\n"
                f"  Description: {ti.description}\n"
                f"  Source: {ti.source}\n\n"
            )
            # Reward for checking threat intel on relevant IOCs
            if ti.ioc in s.critical_iocs:
                if ti.ioc not in self._iocs_discovered:
                    self._iocs_discovered.add(ti.ioc)
                    self._state.iocs_found = list(self._iocs_discovered)
                    self._reward_this_step += 0.03

        findings = "".join(findings_parts)
        return self._build_observation(
            findings=findings,
            action_result=f"Found {len(matches)} threat intelligence matches.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_correlate_events(self, action: IncidentAction) -> IncidentObservation:
        """Correlate events across data sources."""
        s = self._scenario

        if not s.correlation_findings:
            return self._build_observation(
                findings="No cross-source correlations available yet. Gather more evidence first.",
                action_result="Correlation engine found no additional patterns.",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        # Release correlation findings based on evidence discovered
        evidence_ratio = len(self._evidence_discovered) / max(len(s.critical_evidence), 1)
        available_correlations = s.correlation_findings[
            : max(1, int(len(s.correlation_findings) * min(1.0, evidence_ratio + 0.3)))
        ]

        findings_parts = ["EVENT CORRELATION RESULTS:\n"]
        for corr in available_correlations:
            findings_parts.append(f"  {corr}\n\n")

        # Reward for correlating (but diminishing returns)
        correlation_count = self._actions_history.count("correlate_events")
        if correlation_count <= 2:
            self._reward_this_step += 0.02
        else:
            self._reward_this_step -= 0.01  # Diminishing returns

        findings = "".join(findings_parts)
        return self._build_observation(
            findings=findings,
            action_result=f"Correlation analysis complete. {len(available_correlations)} patterns found.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_inspect_endpoint(self, action: IncidentAction) -> IncidentObservation:
        """Inspect an endpoint for signs of compromise."""
        s = self._scenario
        endpoint_id = (action.endpoint_id or "").lower()

        # Find by ID or hostname
        endpoint = None
        for ep in s.endpoints:
            if (endpoint_id in ep.endpoint_id.lower() or
                endpoint_id in ep.hostname.lower() or
                endpoint_id in ep.ip.lower()):
                endpoint = ep
                break

        if endpoint is None:
            available = ", ".join(
                f"{ep.hostname}({ep.ip})" for ep in s.endpoints
            )
            return self._build_observation(
                findings=f"Endpoint '{endpoint_id}' not found.",
                action_result=f"Available endpoints: {available}",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        findings = (
            f"ENDPOINT INSPECTION - {endpoint.hostname}:\n"
            f"  ID: {endpoint.endpoint_id}\n"
            f"  OS: {endpoint.os}\n"
            f"  IP: {endpoint.ip}\n"
            f"  Status: {endpoint.status}\n\n"
            f"  RUNNING PROCESSES:\n"
        )
        for proc in endpoint.processes:
            findings += f"    - {proc}\n"
        findings += "\n  NETWORK CONNECTIONS:\n"
        for conn in endpoint.connections:
            findings += f"    - {conn}\n"
        findings += "\n  RECENTLY MODIFIED FILES:\n"
        for f_mod in endpoint.files_modified:
            findings += f"    - {f_mod}\n"

        # Reward for inspecting compromised endpoints
        if endpoint.is_compromised:
            evidence_key = f"endpoint_compromised_{endpoint.hostname.lower()}"
            if evidence_key not in self._evidence_discovered:
                self._evidence_discovered.add(evidence_key)
                self._state.evidence_found = list(self._evidence_discovered)
                self._reward_this_step += 0.03

        return self._build_observation(
            findings=findings,
            action_result=f"Endpoint {endpoint.hostname} inspected.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_check_user(self, action: IncidentAction) -> IncidentObservation:
        """Check user history and profile."""
        s = self._scenario
        user_id = (action.user_id or "").lower()

        user = None
        for u in s.users:
            if user_id in u.user_id.lower() or user_id in u.display_name.lower():
                user = u
                break

        if user is None:
            available = ", ".join(u.user_id for u in s.users)
            return self._build_observation(
                findings=f"User '{user_id}' not found.",
                action_result=f"Known users in this incident: {available}",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        findings = (
            f"USER PROFILE - {user.display_name} ({user.user_id}):\n"
            f"  Department: {user.department}\n"
            f"  Role: {user.role}\n"
            f"  Risk Score: {user.risk_score:.2f}\n\n"
            f"  RECENT LOGINS:\n"
        )
        for login in user.recent_logins:
            findings += f"    - {login}\n"
        findings += f"\n  NOTES: {user.notes}\n"

        # Reward for user investigation
        self._reward_this_step += 0.02

        return self._build_observation(
            findings=findings,
            action_result=f"User profile retrieved for {user.display_name}.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    # =========================================================================
    # Response Action Handlers
    # =========================================================================

    def _handle_classify_severity(self, action: IncidentAction) -> IncidentObservation:
        """Classify the incident severity."""
        if action.severity is None:
            return self._build_observation(
                findings="No severity level specified.",
                action_result="ERROR: Set 'severity' field to: critical, high, medium, low, or informational",
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        self._severity_set = action.severity
        self._state.severity_classified = True

        if action.threat_category is not None:
            self._category_set = action.threat_category
            self._state.threat_categorized = True

        # Reward for correct classification
        correct_severity = self._severity_set == self._scenario.true_severity
        correct_category = (
            self._category_set == self._scenario.true_category
            if self._category_set else False
        )

        if correct_severity:
            self._reward_this_step += 0.10
            severity_msg = f"Severity classified as {action.severity.value}."
        else:
            # Partial reward for adjacent severity
            severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            true_idx = severity_order.index(self._scenario.true_severity)
            set_idx = severity_order.index(self._severity_set)
            distance = abs(true_idx - set_idx)
            if distance == 1:
                self._reward_this_step += 0.03  # Adjacent
            elif distance >= 2:
                self._reward_this_step -= 0.05  # Significantly wrong
            severity_msg = f"Severity classified as {action.severity.value}."

        if correct_category:
            self._reward_this_step += 0.08
            category_msg = f" Threat category: {action.threat_category.value}."
        elif self._category_set:
            self._reward_this_step -= 0.03
            category_msg = f" Threat category: {action.threat_category.value}."
        else:
            category_msg = " No threat category specified."

        return self._build_observation(
            findings=f"Incident classified.\n{severity_msg}{category_msg}",
            action_result="Classification recorded. Consider containment and response actions.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_contain_threat(self, action: IncidentAction) -> IncidentObservation:
        """Execute containment actions."""
        if not action.containment_actions or not action.target:
            return self._build_observation(
                findings="Containment requires both 'containment_actions' and 'target'.",
                action_result=(
                    "ERROR: Specify containment_actions (list of: isolate_host, block_ip, "
                    "disable_account, quarantine_file, revoke_sessions, none) "
                    "and target (hostname, IP, username, or file hash)."
                ),
                steps_remaining=self._scenario.max_steps - self._state.step_count,
            )

        results = []
        for ca in action.containment_actions:
            self._containment_executed.append((ca.value, action.target))
            self._state.containment_executed = True

            # Check if this containment action matches ground truth
            is_correct = False
            for req_action in self._scenario.required_containment:
                if ca == req_action:
                    expected_target = self._scenario.containment_targets.get(ca.value, "")
                    if action.target.lower() in expected_target.lower() or expected_target.lower() in action.target.lower():
                        is_correct = True
                        break

            if is_correct:
                self._reward_this_step += 0.06
                results.append(f"  [SUCCESS] {ca.value} on {action.target} - Executed successfully")
            elif ca == ContainmentAction.NONE:
                results.append(f"  [INFO] No containment action taken")
            else:
                # Wrong target or unnecessary action
                self._reward_this_step -= 0.04
                results.append(f"  [EXECUTED] {ca.value} on {action.target} - Action completed (verify target correctness)")

        findings = "CONTAINMENT ACTIONS EXECUTED:\n" + "\n".join(results)

        return self._build_observation(
            findings=findings,
            action_result="Containment actions processed.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_escalate(self, action: IncidentAction) -> IncidentObservation:
        """Escalate the incident."""
        escalate_to = action.escalate_to or "tier2"
        self._escalated_to = escalate_to.lower()

        if self._scenario.correct_escalation:
            if self._escalated_to == self._scenario.correct_escalation:
                self._reward_this_step += 0.05
                result = f"Incident escalated to {escalate_to}. Appropriate escalation target."
            else:
                self._reward_this_step += 0.01  # Some credit for escalating at all
                result = f"Incident escalated to {escalate_to}."
        else:
            # Unnecessary escalation
            self._reward_this_step -= 0.02
            result = f"Incident escalated to {escalate_to}. (Consider if escalation was necessary.)"

        return self._build_observation(
            findings=result,
            action_result="Escalation recorded.",
            steps_remaining=self._scenario.max_steps - self._state.step_count,
        )

    def _handle_close_fp(self, action: IncidentAction) -> IncidentObservation:
        """Close incident as false positive."""
        self._closed_as_fp = True
        self._episode_done = True

        if self._scenario.is_false_positive:
            self._reward_this_step += 0.15
            result = "Incident correctly closed as false positive."
        else:
            # Major penalty for closing a real incident as FP
            self._reward_this_step -= 0.20
            result = "Incident closed as false positive. (WARNING: This may not be correct.)"

        self._total_reward += self._reward_this_step

        return self._build_observation(
            findings=result,
            action_result="Incident closed.",
            steps_remaining=0,
            done=True,
        )

    def _handle_submit_report(self, action: IncidentAction) -> IncidentObservation:
        """Submit final incident report and end episode."""
        self._report_submitted = True
        self._state.report_submitted = True
        self._episode_done = True

        report = action.report_summary or ""
        self._report_text = report

        # Grade the report
        report_score = self._grade_report(report)
        self._reward_this_step += report_score

        # Efficiency bonus
        efficiency = self._calculate_efficiency_bonus()
        self._reward_this_step += efficiency

        # Final investigation completeness bonus
        completeness = self._calculate_investigation_completeness()
        self._reward_this_step += completeness * 0.05

        self._total_reward += self._reward_this_step

        return self._build_observation(
            findings=(
                f"INCIDENT REPORT SUBMITTED\n"
                f"  Investigation Completeness: {completeness:.0%}\n"
                f"  Evidence Items: {len(self._evidence_discovered)}/{len(self._scenario.critical_evidence)}\n"
                f"  IOCs Identified: {len(self._iocs_discovered)}/{len(self._scenario.critical_iocs)}\n"
                f"  Severity: {self._severity_set.value if self._severity_set else 'NOT SET'}\n"
                f"  Category: {self._category_set.value if self._category_set else 'NOT SET'}\n"
                f"  Containment Actions: {len(self._containment_executed)}\n"
                f"  Escalated: {self._escalated_to or 'No'}\n"
            ),
            action_result="Report submitted. Episode complete.",
            steps_remaining=0,
            done=True,
        )

    # =========================================================================
    # Grading Functions
    # =========================================================================

    def grade(self) -> float:
        """
        Compute the final grader score for the episode (0.0 - 1.0).

        Scoring breakdown:
        - Investigation thoroughness (evidence): 25%
        - IOC identification: 15%
        - Severity classification: 15%
        - Threat categorization: 10%
        - Containment actions: 20%
        - Report quality: 10%
        - Efficiency: 5%

        Returns:
            Float score between 0.0 and 1.0
        """
        if self._scenario is None:
            return 0.0

        score = 0.0

        # 1. Investigation thoroughness (25%)
        completeness = self._calculate_investigation_completeness()
        score += 0.25 * completeness

        # 2. IOC identification (15%)
        ioc_ratio = len(self._iocs_discovered & self._scenario.critical_iocs) / max(
            len(self._scenario.critical_iocs), 1
        )
        score += 0.15 * ioc_ratio

        # 3. Severity classification (15%)
        if self._severity_set is not None:
            if self._severity_set == self._scenario.true_severity:
                score += 0.15
            else:
                severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                true_idx = severity_order.index(self._scenario.true_severity)
                set_idx = severity_order.index(self._severity_set)
                distance = abs(true_idx - set_idx)
                score += 0.15 * max(0, 1.0 - distance * 0.35)

        # 4. Threat categorization (10%)
        if self._category_set == self._scenario.true_category:
            score += 0.10
        elif self._category_set is not None:
            score += 0.02  # At least attempted

        # 5. Containment actions (20%)
        containment_score = self._grade_containment()
        score += 0.20 * containment_score

        # 6. Report quality (10%)
        if self._report_submitted:
            report_grade = self._grade_report(self._report_text) / 0.10  # Normalize
            score += 0.10 * min(1.0, max(0.0, report_grade))

        # 7. Efficiency (5%)
        if self._state.step_count > 0:
            expected_max = self._scenario.max_steps
            usage_ratio = self._state.step_count / expected_max
            if usage_ratio <= 0.6:
                score += 0.05  # Very efficient
            elif usage_ratio <= 0.8:
                score += 0.03
            elif usage_ratio <= 1.0:
                score += 0.01

        # 8. Penalty for closing real incident as FP
        if self._closed_as_fp and not self._scenario.is_false_positive:
            score = max(0.0, score - 0.30)

        return round(min(1.0, max(0.0, score)), 4)

    def _grade_containment(self) -> float:
        """Grade containment actions. Returns 0.0-1.0."""
        if not self._scenario.required_containment:
            return 1.0 if not self._containment_executed else 0.5

        correct = 0
        total_required = len(self._scenario.required_containment)

        for req_action in self._scenario.required_containment:
            expected_target = self._scenario.containment_targets.get(req_action.value, "")
            for exec_action, exec_target in self._containment_executed:
                if exec_action == req_action.value:
                    if expected_target.lower() in exec_target.lower() or exec_target.lower() in expected_target.lower():
                        correct += 1
                        break

        # Penalty for wrong containment actions
        wrong_actions = len(self._containment_executed) - correct
        penalty = wrong_actions * 0.1

        return max(0.0, (correct / max(total_required, 1)) - penalty)

    def _grade_report(self, report: str) -> float:
        """Grade the incident report quality. Returns reward value."""
        if not report:
            return 0.0

        report_lower = report.lower()
        score = 0.0

        # Check for key terms
        keywords_found = sum(
            1 for kw in self._scenario.report_keywords
            if kw.lower() in report_lower
        )
        keyword_ratio = keywords_found / max(len(self._scenario.report_keywords), 1)
        score += 0.04 * keyword_ratio

        # Check report length (reasonable length expected)
        word_count = len(report.split())
        if word_count >= 50:
            score += 0.03
        elif word_count >= 20:
            score += 0.01

        # Check for IOC mentions in report
        iocs_mentioned = sum(
            1 for ioc in self._scenario.critical_iocs
            if ioc.lower() in report_lower
        )
        if iocs_mentioned > 0:
            score += 0.03 * min(1.0, iocs_mentioned / max(len(self._scenario.critical_iocs), 1))

        return min(0.10, score)

    def _calculate_investigation_completeness(self) -> float:
        """Calculate what fraction of critical evidence was discovered."""
        if not self._scenario.critical_evidence:
            return 1.0

        discovered = self._evidence_discovered & self._scenario.critical_evidence
        return len(discovered) / len(self._scenario.critical_evidence)

    def _calculate_efficiency_bonus(self) -> float:
        """Calculate efficiency bonus based on steps used."""
        if self._state.step_count == 0:
            return 0.0

        expected_max = self._scenario.max_steps
        usage_ratio = self._state.step_count / expected_max

        if usage_ratio <= 0.5:
            return 0.03
        elif usage_ratio <= 0.7:
            return 0.01
        else:
            return 0.0

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _extract_evidence_keys(self, log_entry) -> Set[str]:
        """Extract evidence keys from a log entry based on its keywords."""
        evidence = set()
        keywords = set(kw.lower() for kw in log_entry.keywords)
        s = self._scenario

        # Map log keywords to critical evidence keys
        keyword_to_evidence = {
            # Easy scenario mappings
            "spf": "email_spf_dkim_fail",
            "dkim": "email_spf_dkim_fail",
            "dmarc": "email_spf_dkim_fail",
            "macro": "macro_execution",
            "vba": "macro_execution",
            "powershell": "powershell_spawned_from_excel",
            "excel": "powershell_spawned_from_excel",
            "c2": "c2_connection_185.220.101.42",
            "dropped": "dropped_executable",
            "executable": "dropped_executable",
            # Medium scenario mappings
            "brute_force": "brute_force_from_91.134.205.17",
            "mfa": "vpn_login_without_mfa",
            "bypass": "vpn_login_without_mfa",
            "rdp": "lateral_movement_rdp",
            "lateral": "lateral_movement_rdp",
            "lateral_movement": "lateral_movement_rdp",
            "domain_controller": "domain_controller_access",
            "ntdsutil": "ntdsdit_extraction",
            "ntds": "ntdsdit_extraction",
            "credential": "ntdsdit_extraction",
            "exfiltration": "data_exfiltration_transfer_sh",
            "transfer.sh": "data_exfiltration_transfer_sh",
            "upload": "data_exfiltration_transfer_sh",
            # Hard scenario mappings
            "confidential": "dlp_alert_confidential_upload",
            "dlp": "dlp_alert_confidential_upload",
            "after_hours": "after_hours_access_pattern",
            "anomalous": "anomalous_file_access_scope",
            "bulk_download": "anomalous_file_access_scope",
            "sharepoint": "anomalous_file_access_scope",
            "password": "password_protected_archive",
            "encrypted": "password_protected_archive",
            "archive": "password_protected_archive",
            "7zip": "password_protected_archive",
            "job_search": "job_search_and_recruiter_contact",
            "recruiter": "job_search_and_recruiter_contact",
            "linkedin": "job_search_and_recruiter_contact",
            "glassdoor": "job_search_and_recruiter_contact",
            "resignation": "job_search_and_recruiter_contact",
            "competitor": "job_search_and_recruiter_contact",
            "evasion": "search_queries_monitoring_evasion",
            "monitoring": "search_queries_monitoring_evasion",
            "volume": "data_volume_anomaly",
            "data_transfer": "data_volume_anomaly",
        }

        for kw in keywords:
            if kw in keyword_to_evidence:
                ev_key = keyword_to_evidence[kw]
                if ev_key in s.critical_evidence:
                    evidence.add(ev_key)

        return evidence

    def _extract_iocs_from_content(self, content: str) -> Set[str]:
        """Extract known IOCs from log content."""
        found = set()
        if self._scenario:
            for ioc in self._scenario.critical_iocs:
                if ioc.lower() in content.lower():
                    found.add(ioc)
        return found

    def _build_observation(
        self,
        findings: str,
        action_result: str,
        steps_remaining: int,
        done: bool = None,
    ) -> IncidentObservation:
        """Build a standard observation."""
        if done is None:
            done = self._episode_done

        progress = self._calculate_investigation_completeness()

        return IncidentObservation(
            alert_id=self._scenario.scenario_id if self._scenario else "",
            alert_summary=self._scenario.alert_summary if self._scenario else "",
            alert_source=self._scenario.alert_source if self._scenario else "",
            timestamp=self._scenario.alert_timestamp if self._scenario else "",
            findings=findings,
            evidence_collected=list(self._evidence_discovered),
            iocs_discovered=list(self._iocs_discovered),
            action_result=action_result,
            available_actions=[at.value for at in ActionType],
            steps_remaining=steps_remaining,
            investigation_progress=round(progress, 2),
            done=done,
            reward=round(self._reward_this_step, 4),
            metadata={
                "total_reward": round(self._total_reward, 4),
                "step_count": self._state.step_count,
                "task_id": self._task_id,
            },
        )

    def _error_obs(self, message: str) -> IncidentObservation:
        """Build an error observation."""
        return IncidentObservation(
            alert_id=self._scenario.scenario_id if self._scenario else "",
            alert_summary="",
            alert_source="",
            timestamp="",
            findings="",
            evidence_collected=[],
            iocs_discovered=[],
            action_result=f"ERROR: {message}",
            available_actions=[at.value for at in ActionType],
            steps_remaining=0,
            investigation_progress=0.0,
            done=self._episode_done,
            reward=-0.01,
        )

    @property
    def state(self) -> IncidentState:
        """Get the current environment state."""
        return self._state

    # =========================================================================
    # Task & Grader Endpoints (for hackathon requirements)
    # =========================================================================

    def get_tasks(self) -> List[Dict[str, Any]]:
        """Return the list of available tasks with their descriptions."""
        return [
            {
                "task_id": tid,
                "name": tdef["name"],
                "description": tdef["description"],
                "difficulty": tdef["difficulty"],
                "expected_steps": tdef["expected_steps"],
                "key_skills": tdef["key_skills"],
                "action_schema": IncidentAction.model_json_schema(),
            }
            for tid, tdef in TASK_DEFINITIONS.items()
        ]

    def get_grader_score(self) -> Dict[str, Any]:
        """Return the grader score for the current/last episode."""
        final_score = self.grade()
        return {
            "score": final_score,
            "task_id": self._task_id,
            "breakdown": {
                "investigation_completeness": round(self._calculate_investigation_completeness(), 4),
                "ioc_identification": round(
                    len(self._iocs_discovered & self._scenario.critical_iocs) / max(len(self._scenario.critical_iocs), 1), 4
                ) if self._scenario else 0.0,
                "severity_correct": self._severity_set == self._scenario.true_severity if self._scenario else False,
                "category_correct": self._category_set == self._scenario.true_category if self._scenario else False,
                "containment_score": round(self._grade_containment(), 4),
                "report_submitted": self._report_submitted,
                "steps_used": self._state.step_count,
                "max_steps": self._scenario.max_steps if self._scenario else 0,
            },
        }
