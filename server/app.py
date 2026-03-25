# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment
# BSD-3-Clause License

"""
FastAPI application for the Incident Response Triage Environment.

This module creates an HTTP server that exposes the IncidentResponseEnvEnvironment
over HTTP and WebSocket endpoints, compatible with EnvClient.

Endpoints:
    - POST /reset: Reset the environment
    - POST /step: Execute an action
    - GET /state: Get current environment state
    - GET /schema: Get action/observation schemas
    - GET /tasks: Get list of available tasks
    - GET /grader: Get grader score for current episode
    - POST /baseline: Run baseline inference on all tasks
    - WS /ws: WebSocket endpoint for persistent sessions

Usage:
    # Development (with auto-reload):
    uvicorn server.app:app --reload --host 0.0.0.0 --port 8000

    # Production:
    uvicorn server.app:app --host 0.0.0.0 --port 8000 --workers 4
"""

from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.responses import JSONResponse

try:
    from openenv.core.env_server.http_server import create_app
except ImportError as e:
    raise ImportError(
        "openenv is required. Install with: pip install openenv-core[core]"
    ) from e

try:
    from ..models import IncidentAction, IncidentObservation
    from .incident_response_env_environment import IncidentResponseEnvEnvironment
except ImportError:
    from models import IncidentAction, IncidentObservation
    from server.incident_response_env_environment import IncidentResponseEnvEnvironment


# Create the OpenEnv app
app = create_app(
    IncidentResponseEnvEnvironment,
    IncidentAction,
    IncidentObservation,
    env_name="incident_response_env",
    max_concurrent_envs=1,
)

# Store a reference for additional endpoints
_env_instance = IncidentResponseEnvEnvironment()


# =============================================================================
# Additional Hackathon-Required Endpoints
# =============================================================================


@app.get("/tasks", response_model=List[Dict[str, Any]])
async def get_tasks():
    """
    Returns the list of tasks and the action schema.

    Each task includes:
    - task_id: Unique identifier (easy, medium, hard)
    - name: Human-readable task name
    - description: What the task involves
    - difficulty: Difficulty level
    - expected_steps: Expected step range
    - key_skills: Skills tested
    - action_schema: JSON schema for the Action model
    """
    return JSONResponse(content=_env_instance.get_tasks())


@app.get("/grader")
async def get_grader():
    """
    Returns the grader score after an episode is completed.

    Returns a score between 0.0 and 1.0 with a detailed breakdown
    across investigation completeness, IOC identification, severity
    classification, containment accuracy, and report quality.
    """
    return JSONResponse(content=_env_instance.get_grader_score())


@app.post("/baseline")
async def run_baseline():
    """
    Trigger baseline inference script and returns baseline scores for all 3 tasks.

    This endpoint creates a fresh environment instance and runs a deterministic
    baseline agent (random valid actions) against each task, returning scores.
    """
    from .baseline_runner import run_baseline_all_tasks

    results = run_baseline_all_tasks()
    return JSONResponse(content=results)


def main(host: str = "0.0.0.0", port: int = 8000):
    """
    Entry point for direct execution.

    Args:
        host: Host address to bind to (default: "0.0.0.0")
        port: Port number to listen on (default: 8000)
    """
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
