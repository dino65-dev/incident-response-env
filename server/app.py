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
from typing import Any, Dict, List, Optional

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
# Multi-Agent & Adversarial Infrastructure
# =============================================================================
try:
    from red_team.agent import RedTeamAgent, RedTeamAction, RedTeamActionType
    from red_team.strategies import get_random_strategy
    from multi_agent.agents import L1TriageAgent, L2SeniorAnalyst, L3IRLead, AgentRole
    from multi_agent.overseer import OverseerAgent
    from multi_agent.communication import SharedInvestigationBoard, CommunicationReward
    from multi_agent.knowledge_graph import AgentMemoryGraph
    from eureka.reward_designer import EurekaRewardDesigner
    from eureka.trajectory_analyzer import TrajectoryAnalyzer
    from training.ctde import CTDETrainer, JointObservation
    from training.hmarl import SkillDiscovery, HierarchicalPolicy, DEFAULT_SOC_SKILLS
    _MULTI_AGENT_AVAILABLE = True
except ImportError:
    _MULTI_AGENT_AVAILABLE = False

# =============================================================================
# Shared Stateful Environment for HTTP interaction
# =============================================================================

# This single instance persists state across /env/reset and /env/step calls
_shared_env = IncidentResponseEnvEnvironment()

# Multi-agent instances (initialized lazily)
_red_team: Optional["RedTeamAgent"] = None
_soc_agents: Dict[str, Any] = {}
_overseer: Optional["OverseerAgent"] = None
_shared_board: Optional["SharedInvestigationBoard"] = None
_comm_reward: Optional["CommunicationReward"] = None
_eureka: Optional["EurekaRewardDesigner"] = None
_ctde_trainer: Optional["CTDETrainer"] = None
_trajectory_store: List[Dict[str, Any]] = []
_grader_score_store: List[float] = []


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


# =============================================================================
# Multi-Agent, Red Team & Research Endpoints
# =============================================================================


class RedTeamStepBody(BaseModel):
    action_type: str
    target: Optional[str] = None
    payload: Optional[str] = None


@app.post("/env/multi-agent/init")
async def init_multi_agent():
    """Initialize multi-agent infrastructure (L1/L2/L3 + Overseer + Red Team)."""
    global _red_team, _soc_agents, _overseer, _shared_board, _comm_reward, _ctde_trainer
    if not _MULTI_AGENT_AVAILABLE:
        raise HTTPException(status_code=501, detail="Multi-agent modules not available")

    _red_team = RedTeamAgent(strategy=get_random_strategy())
    _soc_agents = {
        "l1_triage": L1TriageAgent(),
        "l2_senior": L2SeniorAnalyst(),
        "l3_lead": L3IRLead(),
    }
    _overseer = OverseerAgent()
    _shared_board = SharedInvestigationBoard()
    _comm_reward = CommunicationReward(total_training_steps=1000)
    _ctde_trainer = CTDETrainer()
    _ctde_trainer.initialize_policies(["l1_triage", "l2_senior", "l3_lead"])

    # Reset all agents
    for agent in _soc_agents.values():
        agent.reset(partner_ids=list(_soc_agents.keys()))
    _overseer.reset()
    _red_team.reset()
    _shared_board.reset()

    return JSONResponse(content={
        "status": "initialized",
        "agents": list(_soc_agents.keys()) + ["overseer", "red_team"],
        "red_team_strategy": _red_team.strategy.get_name() if _red_team.strategy else "random",
    })


@app.post("/env/red-team-step")
async def red_team_step(body: RedTeamStepBody):
    """Execute a red team action and return result with visible reward."""
    if _red_team is None:
        raise HTTPException(status_code=400, detail="Red team not initialized. Call /env/multi-agent/init first.")

    try:
        action_type = RedTeamActionType(body.action_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action: {body.action_type}. Valid: {[a.value for a in RedTeamActionType]}"
        )

    action = RedTeamAction(
        action_type=action_type,
        target=body.target,
        payload=body.payload,
    )

    defender_state = {
        "log_sources_queried": list(_shared_env._log_sources_queried),
        "containment_score": _shared_env._grade_containment() if _shared_env._scenario else 0.0,
        "severity_set": _shared_env._severity_set is not None,
        "steps_remaining": (
            _shared_env._scenario.max_steps - _shared_env._state.step_count
            if _shared_env._scenario else 0
        ),
    }

    scenario_evidence = list(_shared_env._scenario.critical_evidence) if _shared_env._scenario else []

    result = _red_team.step(action, defender_state, scenario_evidence)

    # Add red team alert to shared board if detected
    if result["detected"] and _shared_board:
        _shared_board.add_red_team_alert({
            "action": body.action_type,
            "detected": True,
            "step": _shared_env._state.step_count,
        })

    return JSONResponse(content=result)


@app.get("/env/knowledge-graph")
async def get_knowledge_graph():
    """Get the aggregated knowledge graph from all agents (for visualization)."""
    if not _soc_agents or _overseer is None:
        raise HTTPException(status_code=400, detail="Multi-agent not initialized.")

    agent_kgs = {aid: agent.memory for aid, agent in _soc_agents.items()}
    unified = _overseer.aggregate_knowledge_graphs(agent_kgs)
    return JSONResponse(content=unified)


@app.get("/env/overseer")
async def get_overseer_status():
    """Get Overseer agent oversight summary."""
    if _overseer is None:
        raise HTTPException(status_code=400, detail="Overseer not initialized.")
    return JSONResponse(content=_overseer.get_oversight_summary())


@app.get("/env/red-team-summary")
async def get_red_team_summary():
    """Get Red Team reward summary (visible to training loop)."""
    if _red_team is None:
        raise HTTPException(status_code=400, detail="Red team not initialized.")
    return JSONResponse(content=_red_team.get_reward_summary())


@app.get("/env/shared-board")
async def get_shared_board():
    """Get shared investigation board summary."""
    if _shared_board is None:
        raise HTTPException(status_code=400, detail="Shared board not initialized.")
    return JSONResponse(content=_shared_board.get_board_summary())


@app.post("/eureka/refine")
async def eureka_refine():
    """Run EUREKA reward refinement loop on stored trajectories."""
    global _eureka
    if not _MULTI_AGENT_AVAILABLE:
        raise HTTPException(status_code=501, detail="EUREKA modules not available")

    if not _trajectory_store:
        raise HTTPException(status_code=400, detail="No trajectories stored. Run episodes first.")

    if _eureka is None:
        _eureka = EurekaRewardDesigner()
        _eureka.set_context(
            env_source_code="Incident Response SOC Environment with multi-agent team",
            task_description="Investigate cybersecurity alerts, classify threats, contain them, and report",
        )

    kg_stats = None
    if _soc_agents:
        kg_stats = list(_soc_agents.values())[0].memory.get_graph_stats_for_eureka()

    red_stats = _red_team.get_reward_summary() if _red_team else None
    overseer_v = [
        {"severity": v.severity, "agent_id": v.agent_id, "description": v.description}
        for v in (_overseer.violations if _overseer else [])
    ]

    best = _eureka.run_refinement_loop(
        trajectories=_trajectory_store,
        grader_scores=_grader_score_store,
        n_iterations=3,
        kg_stats=kg_stats,
        red_team_stats=red_stats,
        overseer_violations=overseer_v,
    )

    return JSONResponse(content={
        "best_reward": {
            "id": best.candidate_id if best else None,
            "score": round(best.score, 4) if best else 0,
            "description": best.description if best else "",
        },
        "history": _eureka.get_refinement_history(),
    })


@app.get("/env/training-stats")
async def get_training_stats():
    """Get CTDE training statistics."""
    if _ctde_trainer is None:
        raise HTTPException(status_code=400, detail="CTDE trainer not initialized.")
    return JSONResponse(content=_ctde_trainer.get_training_summary())


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for direct execution."""
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
