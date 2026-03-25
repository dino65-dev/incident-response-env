# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment
# BSD-3-Clause License

"""Incident Response Triage Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import IncidentAction, IncidentObservation


class IncidentResponseEnv(
    EnvClient[IncidentAction, IncidentObservation, State]
):
    """
    Client for the Incident Response Triage Environment.

    Example:
        >>> with IncidentResponseEnv(base_url="http://localhost:8000") as client:
        ...     result = client.reset()
        ...     print(result.observation.alert_summary)
        ...
        ...     result = client.step(IncidentAction(
        ...         action_type=ActionType.EXAMINE_ALERT
        ...     ))
        ...     print(result.observation.findings)
    """

    def _step_payload(self, action: IncidentAction) -> Dict:
        """Convert action to JSON payload."""
        payload = {"action_type": action.action_type.value}

        if action.log_source is not None:
            payload["log_source"] = action.log_source
        if action.query_filter is not None:
            payload["query_filter"] = action.query_filter
        if action.endpoint_id is not None:
            payload["endpoint_id"] = action.endpoint_id
        if action.user_id is not None:
            payload["user_id"] = action.user_id
        if action.severity is not None:
            payload["severity"] = action.severity.value
        if action.threat_category is not None:
            payload["threat_category"] = action.threat_category.value
        if action.containment_actions is not None:
            payload["containment_actions"] = [ca.value for ca in action.containment_actions]
        if action.target is not None:
            payload["target"] = action.target
        if action.report_summary is not None:
            payload["report_summary"] = action.report_summary
        if action.escalate_to is not None:
            payload["escalate_to"] = action.escalate_to

        return payload

    def _parse_result(self, payload: Dict) -> StepResult[IncidentObservation]:
        """Parse server response into StepResult."""
        obs_data = payload.get("observation", {})
        observation = IncidentObservation(
            alert_id=obs_data.get("alert_id", ""),
            alert_summary=obs_data.get("alert_summary", ""),
            alert_source=obs_data.get("alert_source", ""),
            timestamp=obs_data.get("timestamp", ""),
            findings=obs_data.get("findings", ""),
            evidence_collected=obs_data.get("evidence_collected", []),
            iocs_discovered=obs_data.get("iocs_discovered", []),
            action_result=obs_data.get("action_result", ""),
            available_actions=obs_data.get("available_actions", []),
            steps_remaining=obs_data.get("steps_remaining", 0),
            investigation_progress=obs_data.get("investigation_progress", 0.0),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """Parse server response into State."""
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
