# Copyright (c) 2026 - OpenEnv Hackathon Submission
# Incident Response Triage Environment
# BSD-3-Clause License

"""
FastAPI application for the Incident Response Triage Environment.

This module creates an HTTP server that exposes the IncidentResponseEnvEnvironment
over HTTP and WebSocket endpoints, compatible with EnvClient.

IMPORTANT: OpenEnv's create_app() generates stateless REST endpoints (each call
creates a new environment instance). For our stateful incident investigation,
we add custom stateful endpoints (/env/reset, /env/step, /env/state) that share
a single environment instance across calls. The baseline inference script uses
these stateful endpoints.

Endpoints (stateful — use these for agent interaction):
    - POST /env/reset: Reset the environment (preserves state for subsequent steps)
    - POST /env/step: Execute an action (uses the environment from the last reset)
    - GET  /env/state: Get current environment state

Endpoints (OpenEnv spec — stateless, for validation):
    - POST /reset: Reset (stateless, OpenEnv spec)
    - POST /step: Execute action (stateless, OpenEnv spec)
    - GET  /state: Get state (stateless, OpenEnv spec)
    - GET  /schema: Get action/observation JSON schemas
    - GET  /health: Health check
    - WS   /ws: WebSocket for persistent sessions

Endpoints (hackathon extras):
    - GET  /tasks: List all tasks with descriptions and action schema
    - GET  /grader: Get grader score for current episode
    - POST /baseline: Run deterministic baseline on all 6 tasks
"""

import os
import sys
import traceback
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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
    # When running from server/ directory, add parent to path
    _parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    from models import IncidentAction, IncidentObservation
    try:
        from server.incident_response_env_environment import IncidentResponseEnvEnvironment
    except ImportError:
        from incident_response_env_environment import IncidentResponseEnvEnvironment


# Create the OpenEnv spec-compliant app (stateless REST + WebSocket)
app = create_app(
    IncidentResponseEnvEnvironment,
    IncidentAction,
    IncidentObservation,
    env_name="incident_response_env",
    max_concurrent_envs=1,
)


# =============================================================================
# Shared Stateful Environment for HTTP interaction
# =============================================================================

# This single instance persists state across /env/reset and /env/step calls
_shared_env = IncidentResponseEnvEnvironment()


class ResetBody(BaseModel):
    seed: int | None = None
    episode_id: str | None = None
    task_id: str | None = "easy"


class StepBody(BaseModel):
    action: Dict[str, Any]


@app.post("/env/reset")
async def stateful_reset(body: ResetBody):
    """
    Reset the shared environment instance (stateful).
    State persists for subsequent /env/step calls.
    """
    try:
        obs = _shared_env.reset(
            seed=body.seed,
            episode_id=body.episode_id,
            task_id=body.task_id,
        )
        obs_dict = obs.model_dump(exclude={"reward", "done", "metadata"})
        return JSONResponse(content={
            "observation": obs_dict,
            "reward": obs.reward,
            "done": obs.done,
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/env/step")
async def stateful_step(body: StepBody):
    """
    Execute an action on the shared environment (stateful).
    Uses the environment state from the last /env/reset call.
    """
    try:
        # Validate and create the action
        action = IncidentAction.model_validate(body.action)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action: {e}"
        )

    try:
        obs = _shared_env.step(action)
        obs_dict = obs.model_dump(exclude={"reward", "done", "metadata"})
        return JSONResponse(content={
            "observation": obs_dict,
            "reward": obs.reward if isinstance(obs.reward, (int, float)) else 0.0,
            "done": obs.done,
        })
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/env/state")
async def stateful_state():
    """Get the current state of the shared environment."""
    state = _shared_env.state
    return JSONResponse(content=state.model_dump())


# =============================================================================
# Hackathon-Required Endpoints
# =============================================================================


@app.get("/tasks", response_model=List[Dict[str, Any]])
async def get_tasks():
    """
    Returns the list of tasks and the action schema.
    """
    return JSONResponse(content=_shared_env.get_tasks())


@app.get("/grader")
async def get_grader():
    """
    Returns the grader score after an episode is completed.
    """
    return JSONResponse(content=_shared_env.get_grader_score())


@app.post("/baseline")
async def run_baseline():
    """
    Trigger baseline and return scores for all 3 tasks.
    """
    from .baseline_runner import run_baseline_all_tasks

    results = run_baseline_all_tasks()
    return JSONResponse(content=results)


@app.post("/env/evolve")
async def evolve_population():
    """Trigger evolution of the scenario population."""
    if not hasattr(_shared_env, '_evolution_engine') or _shared_env._evolution_engine is None:
        raise HTTPException(status_code=400, detail="Evolution engine not initialized. Reset with task_id='evolved' first.")
    new_pop = _shared_env._evolution_engine.evolve()
    return JSONResponse(content={
        "status": "evolved",
        "generation": _shared_env._evolution_engine.state.generation,
        "population_size": len(new_pop),
    })


@app.get("/env/evolution-stats")
async def evolution_stats():
    """Get evolution engine statistics."""
    if not hasattr(_shared_env, '_evolution_engine') or _shared_env._evolution_engine is None:
        return JSONResponse(content={"status": "not_initialized", "message": "Reset with task_id='evolved' to activate"})
    return JSONResponse(content=_shared_env._evolution_engine.get_evolution_stats())


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for direct execution."""
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
