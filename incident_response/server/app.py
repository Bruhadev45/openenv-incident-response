"""
FastAPI application for the SRE Incident Response Environment.

Provides a REST API for agents to interact with simulated production incidents.
Can run standalone without openenv-core dependency.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from incident_response.models import (
    IncidentAction,
    IncidentObservation,
    IncidentState,
)
from incident_response.server.environment import IncidentResponseEnvironment

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SRE Incident Response Environment",
    description=(
        "Train AI agents on production incident handling with realistic scenarios. "
        "Features 3 progressive tasks: alert triage, root cause analysis, and cascading failure resolution."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for browser-based clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------


class ResetRequest(BaseModel):
    """Request body for /reset endpoint."""

    seed: Optional[int] = None
    task_id: Optional[str] = None
    episode_id: Optional[str] = None


class TaskInfo(BaseModel):
    """Information about an available task."""

    id: str
    name: str
    description: str
    difficulty: str
    max_steps: int
    objectives: list[str]
    action_schema: dict[str, Any]


# ---------------------------------------------------------------------------
# Task definitions
# ---------------------------------------------------------------------------

TASKS: dict[str, TaskInfo] = {
    "triage": TaskInfo(
        id="triage",
        name="Alert Triage",
        description=(
            "You are the on-call SRE receiving a page about service degradation. "
            "Assess the situation, classify severity, acknowledge the incident, "
            "and provide an initial status update to stakeholders."
        ),
        difficulty="Easy",
        max_steps=15,
        objectives=[
            "Acknowledge the incoming alert",
            "Investigate logs and metrics to understand the issue",
            "Classify the incident severity (P1-P4)",
            "Send an appropriate status update to stakeholders",
        ],
        action_schema=IncidentAction.model_json_schema(),
    ),
    "rca": TaskInfo(
        id="rca",
        name="Root Cause Analysis",
        description=(
            "An ongoing incident requires root cause analysis. Multiple services show degradation. "
            "Use investigation tools systematically to identify the primary failing component, "
            "diagnose the root cause, and apply the correct remediation."
        ),
        difficulty="Medium",
        max_steps=20,
        objectives=[
            "Investigate multiple services to trace the failure path",
            "Identify the root cause service and failure mode",
            "Diagnose the specific issue (e.g., memory leak, bad deploy)",
            "Apply the correct remediation action to the right service",
            "Verify the fix and update stakeholders",
        ],
        action_schema=IncidentAction.model_json_schema(),
    ),
    "cascading": TaskInfo(
        id="cascading",
        name="Cascading Failure Resolution",
        description=(
            "A cascading failure is spreading through the system. Multiple services are down, "
            "alerts are firing rapidly, and the blast radius is expanding. You must quickly "
            "identify the origin, stop the cascade, restore services in the correct order, "
            "and coordinate communication throughout the incident."
        ),
        difficulty="Hard",
        max_steps=30,
        objectives=[
            "Rapidly triage multiple simultaneous alerts",
            "Trace the cascade to identify the origin service",
            "Diagnose the root cause under time pressure",
            "Apply targeted remediation to stop the cascade",
            "Coordinate recovery of dependent services",
            "Manage stakeholder communication throughout",
        ],
        action_schema=IncidentAction.model_json_schema(),
    ),
}




# ---------------------------------------------------------------------------
# Global environment instance
# ---------------------------------------------------------------------------

# Single environment for simple deployments
_env = IncidentResponseEnvironment()


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/")
async def root() -> dict[str, Any]:
    """Root endpoint with environment information."""
    return {
        "name": "SRE Incident Response Environment",
        "version": "0.1.0",
        "description": "Train AI agents on production incident handling",
        "tasks": ["triage", "rca", "cascading"],
        "endpoints": {
            "health": "/health",
            "tasks": "/tasks",
            "reset": "/reset (POST)",
            "step": "/step (POST)",
            "state": "/state",
            "grader": "/grader",
            "docs": "/docs",
        },
        "status": "ready",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/tasks", response_model=list[TaskInfo])
async def list_tasks() -> list[TaskInfo]:
    """List all available tasks with descriptions and action schemas."""
    return list(TASKS.values())


@app.post("/reset", response_model=IncidentObservation)
async def reset(request: Optional[ResetRequest] = None) -> IncidentObservation:
    """Reset the environment and start a new episode."""
    try:
        # Handle empty body - use defaults
        seed = request.seed if request else None
        task_id = request.task_id if request else None
        episode_id = request.episode_id if request else None
        return _env.reset(
            seed=seed,
            task_id=task_id,
            episode_id=episode_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/step", response_model=IncidentObservation)
async def step(action: IncidentAction) -> IncidentObservation:
    """Execute an action and return the next observation."""
    try:
        return _env.step(action)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/state", response_model=IncidentState)
async def get_state() -> IncidentState:
    """Get the current internal state of the environment."""
    try:
        state = _env.state
        # Clamp total_reward to (0.0, 1.0) - strictly between, not inclusive
        state.total_reward = max(0.001, min(0.999, state.total_reward))
        return state
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/grader")
async def get_grader() -> dict[str, float]:
    """Get grader score breakdown for the current episode."""
    try:
        if _env._grader is None or _env._state is None:
            raise RuntimeError("Environment not initialized. Call reset() first.")
        result = _env._grader.compute_final_score(_env._state)
        if isinstance(result, dict):
            return result
        return {"total": float(result)}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/baseline")
async def run_baseline() -> dict[str, Any]:
    """
    Trigger baseline inference using the baseline script.

    Returns baseline scores for each task.
    """
    script_path = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "baseline.py")

    if not os.path.exists(script_path):
        raise HTTPException(
            status_code=500,
            detail="Baseline script not found. Ensure scripts/baseline.py exists.",
        )

    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=600,
            env={**os.environ, "ENV_BASE_URL": "http://localhost:8000"},
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Baseline script failed: {result.stderr}",
            )

        # Parse JSON output from script
        import json

        try:
            scores = json.loads(result.stdout.strip().split("\n")[-1])
            return scores
        except json.JSONDecodeError:
            return {"output": result.stdout, "error": "Could not parse JSON output"}

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Baseline script timed out.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running baseline: {str(e)}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the server using uvicorn."""
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")

    uvicorn.run(
        "incident_response.server.app:app",
        host=host,
        port=port,
        reload=os.environ.get("ENV", "production") != "production",
    )


if __name__ == "__main__":
    main()
