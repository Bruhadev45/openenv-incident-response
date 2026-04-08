#!/usr/bin/env python3
"""
Baseline inference using OpenAI API against the incident response environment.

Runs the GPT model through each task multiple times to establish baseline scores
for the OpenEnv competition.

Usage:
    export OPENAI_API_KEY="sk-..."
    python scripts/baseline.py

Environment variables:
    OPENAI_API_KEY: Required. Your OpenAI API key.
    ENV_BASE_URL: Optional. Environment server URL (default: http://localhost:8000).
    OPENAI_MODEL: Optional. Model to use (default: gpt-4o).
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

# Check for OpenAI API key early
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    print("Error: OPENAI_API_KEY environment variable not set.", file=sys.stderr)
    print("Export your OpenAI API key: export OPENAI_API_KEY='sk-...'", file=sys.stderr)
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Error: requests library not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    from openai import OpenAI
except ImportError:
    print("Error: openai library not installed. Run: pip install openai", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ENV_BASE_URL = os.environ.get("ENV_BASE_URL", "http://localhost:8000")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")

# Tasks and seeds for reproducibility
TASKS = ["triage", "rca", "cascading"]
SEEDS = [42, 123, 456]


def clamp_strict_score(value: float) -> float:
    """Clamp scores into the open interval required by submission validators."""
    return max(0.001, min(0.999, value))

# System prompt for the SRE agent
SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) responding to a production incident.

Your goal is to efficiently diagnose and resolve the incident by taking appropriate actions.

## Available Actions

You MUST respond with a JSON object containing your action. Here are the available action types:

### 1. acknowledge
Acknowledge the incident to become the primary responder.
```json
{"action_type": "acknowledge"}
```

### 2. investigate
Investigate a service using diagnostic tools.
Tools: logs, metrics, traces, deploys, config, dependencies, alerts
```json
{"action_type": "investigate", "tool": "logs", "target": "api-gateway"}
{"action_type": "investigate", "tool": "metrics", "target": "auth-service"}
{"action_type": "investigate", "tool": "traces", "target": "order-service"}
{"action_type": "investigate", "tool": "deploys", "target": "auth-service"}
{"action_type": "investigate", "tool": "dependencies", "target": "order-db"}
```

### 3. diagnose
Identify the root cause after investigation.
```json
{"action_type": "diagnose", "root_cause": "memory_leak", "target": "auth-service", "confidence": 0.85}
```

### 4. classify
Classify the incident severity (P1=critical, P2=high, P3=medium, P4=low).
```json
{"action_type": "classify", "severity": "P1"}
```

### 5. remediate
Apply a fix. Actions: rollback, restart, scale_up, drain_traffic, failover, toggle_flag, clear_cache
```json
{"action_type": "remediate", "remediation": "rollback", "target": "auth-service"}
{"action_type": "remediate", "remediation": "restart", "target": "order-db"}
```

### 6. communicate
Send status updates to stakeholders.
```json
{"action_type": "communicate", "message": "Investigating elevated error rates on auth-service..."}
```

### 7. escalate
Escalate to additional team members.
```json
{"action_type": "escalate", "target": "database-team"}
```

## Strategy

1. Start by acknowledging the incident
2. Review alerts and system status to identify affected services
3. Investigate the most impacted services using logs and metrics
4. Use dependencies tool to understand the service graph
5. Trace the issue to the root cause service
6. Diagnose the specific failure mode
7. Apply the appropriate remediation
8. Communicate status updates throughout

## Response Format

ALWAYS respond with ONLY a valid JSON object. No explanation text, no markdown formatting.
Example: {"action_type": "investigate", "tool": "logs", "target": "api-gateway"}
"""


# ---------------------------------------------------------------------------
# HTTP client for environment
# ---------------------------------------------------------------------------


class EnvClient:
    """Simple HTTP client for the environment server."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def reset(self, task_id: str, seed: int) -> dict[str, Any]:
        """Reset environment and return initial observation."""
        resp = self.session.post(
            f"{self.base_url}/reset",
            json={"task_id": task_id, "seed": seed},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        """Execute action and return observation."""
        resp = self.session.post(
            f"{self.base_url}/step",
            json=action,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def grader(self) -> dict[str, float]:
        """Get grader scores for current episode."""
        resp = self.session.get(f"{self.base_url}/grader", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict[str, str]:
        """Check server health."""
        resp = self.session.get(f"{self.base_url}/health", timeout=10)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Observation formatting
# ---------------------------------------------------------------------------


def format_observation_for_prompt(obs: dict[str, Any]) -> str:
    """Format an observation into a prompt for the LLM."""
    lines = []

    # Task info
    lines.append(f"## Task: {obs.get('task_id', 'unknown')}")
    lines.append(f"Step: {obs.get('step_number', 0)}/{obs.get('max_steps', 20)}")
    lines.append(f"Description: {obs.get('task_description', '')}")
    lines.append("")

    # Feedback from last action
    if obs.get("feedback"):
        lines.append(f"## Feedback from last action")
        lines.append(obs["feedback"])
        lines.append("")

    # Active alerts
    alerts = obs.get("alerts", [])
    if alerts:
        lines.append("## Active Alerts")
        for alert in alerts:
            lines.append(f"- [{alert.get('severity', 'P3')}] {alert.get('service', 'unknown')}: {alert.get('title', '')}")
            lines.append(f"  {alert.get('description', '')}")
        lines.append("")

    # System status summary
    system_status = obs.get("system_status", [])
    if system_status:
        lines.append("## System Status")
        critical = [s for s in system_status if s.get("status") in ["critical", "down"]]
        degraded = [s for s in system_status if s.get("status") == "degraded"]
        healthy = [s for s in system_status if s.get("status") == "healthy"]

        if critical:
            lines.append(f"CRITICAL: {', '.join(s['name'] for s in critical)}")
        if degraded:
            lines.append(f"DEGRADED: {', '.join(s['name'] for s in degraded)}")
        if healthy:
            lines.append(f"Healthy: {len(healthy)} services")
        lines.append("")

    # Investigation result (if any)
    if obs.get("investigation_result"):
        lines.append("## Investigation Result")
        lines.append(obs["investigation_result"])
        lines.append("")

    # Available actions
    available = obs.get("available_actions", [])
    if available:
        lines.append(f"## Available Actions: {', '.join(available)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Action parsing
# ---------------------------------------------------------------------------


def parse_action_from_response(response_text: str) -> dict[str, Any]:
    """Parse a JSON action from the LLM response."""
    text = response_text.strip()

    # Try to extract JSON from markdown code blocks
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if json_match:
        text = json_match.group(1)

    # Try to find a JSON object
    json_match = re.search(r"\{[^{}]*\}", text)
    if json_match:
        text = json_match.group(0)

    try:
        action = json.loads(text)
        if "action_type" in action:
            return action
    except json.JSONDecodeError:
        pass

    # Fallback: try to infer action from text
    text_lower = text.lower()

    if "acknowledge" in text_lower:
        return {"action_type": "acknowledge"}
    elif "investigate" in text_lower:
        # Try to extract tool and target
        tool = "logs"
        target = "api-gateway"
        for t in ["logs", "metrics", "traces", "deploys", "config", "dependencies", "alerts"]:
            if t in text_lower:
                tool = t
                break
        # Look for service names
        services = ["api-gateway", "auth-service", "user-service", "order-service",
                   "auth-db", "user-db", "order-db", "redis", "kafka", "frontend",
                   "order-worker", "warehouse-api"]
        for s in services:
            if s in text_lower:
                target = s
                break
        return {"action_type": "investigate", "tool": tool, "target": target}
    elif "remediate" in text_lower or "rollback" in text_lower or "restart" in text_lower:
        remediation = "restart"
        for r in ["rollback", "restart", "scale_up", "drain_traffic", "failover", "toggle_flag", "clear_cache"]:
            if r in text_lower:
                remediation = r
                break
        return {"action_type": "remediate", "remediation": remediation, "target": "api-gateway"}
    elif "diagnose" in text_lower:
        return {"action_type": "diagnose", "root_cause": "unknown", "confidence": 0.5}
    elif "classify" in text_lower or any(p in text_lower for p in ["p1", "p2", "p3", "p4"]):
        severity = "P2"
        for p in ["P1", "P2", "P3", "P4"]:
            if p.lower() in text_lower:
                severity = p
                break
        return {"action_type": "classify", "severity": severity}
    elif "communicate" in text_lower or "status" in text_lower:
        return {"action_type": "communicate", "message": "Investigating the incident."}
    elif "escalate" in text_lower:
        return {"action_type": "escalate", "target": "on-call"}

    # Default fallback
    return {"action_type": "investigate", "tool": "logs", "target": "api-gateway"}


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------


def run_episode(
    client: EnvClient,
    openai_client: OpenAI,
    task_id: str,
    seed: int,
    verbose: bool = False,
) -> dict[str, float]:
    """Run a single episode and return grader scores."""
    if verbose:
        print(f"  Running {task_id} seed={seed}...", end=" ", flush=True)

    # Reset environment
    obs = client.reset(task_id, seed)

    # Conversation history for the LLM
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    step = 0
    max_steps = obs.get("max_steps", 20)

    while not obs.get("done", False) and step < max_steps:
        # Format observation as user message
        obs_text = format_observation_for_prompt(obs)
        messages.append({"role": "user", "content": obs_text})

        # Call OpenAI API
        try:
            response = openai_client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=messages,
                max_tokens=256,
                temperature=0.1,
            )
            assistant_message = response.choices[0].message.content or ""
        except Exception as e:
            print(f"OpenAI API error: {e}", file=sys.stderr)
            assistant_message = '{"action_type": "investigate", "tool": "logs", "target": "api-gateway"}'

        messages.append({"role": "assistant", "content": assistant_message})

        # Parse action from response
        action = parse_action_from_response(assistant_message)

        # Execute action
        try:
            obs = client.step(action)
        except Exception as e:
            print(f"Environment step error: {e}", file=sys.stderr)
            break

        step += 1

    # Get final scores
    try:
        scores = client.grader()
    except Exception as e:
        print(f"Grader error: {e}", file=sys.stderr)
        scores = {"total": 0.001}

    scores["total"] = clamp_strict_score(float(scores.get("total", 0.001)))

    if verbose:
        print(f"score={scores.get('total', 0.001):.3f}")

    return scores


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Run baseline inference across all tasks and seeds."""
    print("=" * 60)
    print("SRE Incident Response Environment - Baseline Inference")
    print("=" * 60)
    print(f"Environment URL: {ENV_BASE_URL}")
    print(f"Model: {OPENAI_MODEL}")
    print(f"Tasks: {TASKS}")
    print(f"Seeds: {SEEDS}")
    print()

    # Initialize clients
    env_client = EnvClient(ENV_BASE_URL)
    openai_client = OpenAI(api_key=OPENAI_API_KEY)

    # Check environment health
    try:
        health = env_client.health()
        print(f"Environment health: {health.get('status', 'unknown')}")
    except Exception as e:
        print(f"Error: Cannot connect to environment at {ENV_BASE_URL}", file=sys.stderr)
        print(f"  {e}", file=sys.stderr)
        print("Make sure the environment server is running:", file=sys.stderr)
        print("  python -m incident_response.server.app", file=sys.stderr)
        sys.exit(1)

    print()
    print("Running baseline...")
    print("-" * 40)

    # Collect scores per task
    task_scores: dict[str, list[float]] = {task: [] for task in TASKS}

    for task_id in TASKS:
        print(f"\nTask: {task_id}")
        for seed in SEEDS:
            scores = run_episode(env_client, openai_client, task_id, seed, verbose=True)
            task_scores[task_id].append(clamp_strict_score(float(scores.get("total", 0.001))))

    # Calculate averages
    print()
    print("-" * 40)
    print("Results:")
    print()

    results: dict[str, float] = {}
    all_scores = []

    for task_id in TASKS:
        scores = task_scores[task_id]
        avg = sum(scores) / len(scores) if scores else 0.001
        results[task_id] = clamp_strict_score(round(avg, 3))
        all_scores.extend(scores)
        print(f"  {task_id}: {avg:.3f} (scores: {[round(s, 3) for s in scores]})")

    overall_avg = sum(all_scores) / len(all_scores) if all_scores else 0.001
    results["average"] = clamp_strict_score(round(overall_avg, 3))

    print()
    print(f"  Overall average: {overall_avg:.3f}")
    print()

    # Output final JSON (for programmatic consumption)
    print("=" * 60)
    print("Final scores (JSON):")
    print(json.dumps(results))


if __name__ == "__main__":
    main()
