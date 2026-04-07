#!/usr/bin/env python3
"""
Inference Script for SRE Incident Response OpenEnv Environment.

MANDATORY STDOUT FORMAT:
- [START] task=<task_name> env=<benchmark> model=<model_name>
- [STEP] step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
- [END] success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>

Environment Variables:
- API_BASE_URL: The API endpoint for the LLM (default: https://router.huggingface.co/v1)
- MODEL_NAME: The model identifier (default: Qwen/Qwen2.5-72B-Instruct)
- HF_TOKEN: Your Hugging Face API key (required)
- ENV_BASE_URL: Environment server URL (default: http://localhost:8000)
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Configuration from Environment Variables (MANDATORY)
# ---------------------------------------------------------------------------

# Required environment variables per OpenEnv spec
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"
HF_TOKEN = os.getenv("HF_TOKEN")  # No default - required
API_KEY = HF_TOKEN or os.getenv("API_KEY")  # Fallback for compatibility

# Optional: for docker-based environments
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")

# Environment server URL
ENV_BASE_URL = os.getenv("ENV_BASE_URL") or "http://localhost:8000"

# Task configuration
TASKS = ["triage", "rca", "cascading"]
BENCHMARK = "incident_response"
SEEDS = [42, 123, 456]

# Agent configuration
TEMPERATURE = 0.1
MAX_TOKENS = 512

# ---------------------------------------------------------------------------
# Validate Requirements
# ---------------------------------------------------------------------------

if not API_KEY:
    print("Error: HF_TOKEN environment variable not set.", file=sys.stderr)
    print("Export your HuggingFace token: export HF_TOKEN='hf_...'", file=sys.stderr)
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
# Stdout Logging Functions (MANDATORY FORMAT)
# ---------------------------------------------------------------------------


def log_start(task: str, env: str, model: str) -> None:
    """Log episode start in required format."""
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    """Log step result in required format."""
    error_val = error if error else "null"
    done_val = str(done).lower()
    # Sanitize action string (remove newlines, limit length)
    action_clean = action.replace("\n", " ").replace("\r", "")[:100]
    print(
        f"[STEP] step={step} action={action_clean} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: list[float]) -> None:
    """Log episode end in required format."""
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.2f} rewards={rewards_str}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# HTTP Client for Environment
# ---------------------------------------------------------------------------


class EnvClient:
    """HTTP client for the incident response environment server."""

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
# LLM System Prompt
# ---------------------------------------------------------------------------

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
# Observation Formatting
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
        lines.append("## Feedback from last action")
        lines.append(obs["feedback"])
        lines.append("")

    # Active alerts
    alerts = obs.get("alerts", [])
    if alerts:
        lines.append("## Active Alerts")
        for alert in alerts:
            lines.append(
                f"- [{alert.get('severity', 'P3')}] {alert.get('service', 'unknown')}: {alert.get('title', '')}"
            )
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
# Action Parsing
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
        tool = "logs"
        target = "api-gateway"
        for t in ["logs", "metrics", "traces", "deploys", "config", "dependencies", "alerts"]:
            if t in text_lower:
                tool = t
                break
        services = [
            "api-gateway",
            "auth-service",
            "user-service",
            "order-service",
            "auth-db",
            "user-db",
            "order-db",
            "redis",
            "kafka",
            "frontend",
            "order-worker",
            "warehouse-api",
        ]
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
# Episode Runner
# ---------------------------------------------------------------------------


def run_episode(
    env_client: EnvClient,
    openai_client: OpenAI,
    task_id: str,
    seed: int,
) -> float:
    """Run a single episode and return the final score."""

    # Log episode start
    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

    rewards: list[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    try:
        # Reset environment
        obs = env_client.reset(task_id, seed)

        # Conversation history for the LLM
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]

        step = 0
        max_steps = obs.get("max_steps", 20)

        while not obs.get("done", False) and step < max_steps:
            # Format observation as user message
            obs_text = format_observation_for_prompt(obs)
            messages.append({"role": "user", "content": obs_text})

            # Call LLM API
            try:
                response = openai_client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    max_tokens=MAX_TOKENS,
                    temperature=TEMPERATURE,
                )
                assistant_message = response.choices[0].message.content or ""
            except Exception as e:
                print(f"[DEBUG] LLM API error: {e}", file=sys.stderr)
                assistant_message = '{"action_type": "investigate", "tool": "logs", "target": "api-gateway"}'

            messages.append({"role": "assistant", "content": assistant_message})

            # Parse action from response
            action = parse_action_from_response(assistant_message)
            action_str = json.dumps(action)

            # Execute action
            error = None
            try:
                obs = env_client.step(action)
            except Exception as e:
                error = str(e)
                print(f"[DEBUG] Environment step error: {e}", file=sys.stderr)
                break

            step += 1
            steps_taken = step

            # Extract reward and done status
            reward = obs.get("reward", 0.0)
            done = obs.get("done", False)

            rewards.append(reward)

            # Log the step
            log_step(step=step, action=action_str, reward=reward, done=done, error=error)

            if done:
                break

        # Get final scores from grader
        try:
            grader_result = env_client.grader()
            score = grader_result.get("total", 0.0)
        except Exception as e:
            print(f"[DEBUG] Grader error: {e}", file=sys.stderr)
            score = sum(rewards)

        # Clamp score to [0, 1]
        score = max(0.0, min(1.0, score))
        success = score >= 0.1  # Threshold for success

    except Exception as e:
        print(f"[DEBUG] Episode error: {e}", file=sys.stderr)
        score = 0.0
        success = False

    # Log episode end
    log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

    return score


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run baseline inference across all tasks."""

    # Initialize clients
    env_client = EnvClient(ENV_BASE_URL)
    openai_client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    # Check environment health
    try:
        health = env_client.health()
        print(f"[DEBUG] Environment health: {health.get('status', 'unknown')}", file=sys.stderr)
    except Exception as e:
        print(f"[DEBUG] Cannot connect to environment at {ENV_BASE_URL}: {e}", file=sys.stderr)
        print("[DEBUG] Starting server may be required...", file=sys.stderr)
        # Continue anyway - the errors will be logged per episode

    # Run all tasks with all seeds
    all_scores: list[float] = []

    for task_id in TASKS:
        for seed in SEEDS:
            try:
                score = run_episode(env_client, openai_client, task_id, seed)
                all_scores.append(score)
            except Exception as e:
                print(f"[DEBUG] Failed to run {task_id} seed={seed}: {e}", file=sys.stderr)
                # Log a failed episode
                log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)
                log_end(success=False, steps=0, score=0.0, rewards=[])

    # Print summary to stderr (not part of required format)
    if all_scores:
        avg_score = sum(all_scores) / len(all_scores)
        print(f"[DEBUG] Average score across all episodes: {avg_score:.3f}", file=sys.stderr)


if __name__ == "__main__":
    main()
