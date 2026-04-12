#!/usr/bin/env python3
"""
Inference entrypoint for the SRE Incident Response OpenEnv submission.

Required environment variables:
- API_BASE_URL: LLM endpoint, defaults to https://router.huggingface.co/v1
- MODEL_NAME: model identifier, defaults to Qwen/Qwen2.5-7B-Instruct
- HF_TOKEN: API token for the OpenAI-compatible client, no default

Optional environment variables:
- ENV_BASE_URL: environment server URL, defaults to http://localhost:8000
- TASK_ID: task to run, defaults to triage
- TASK_SEED: seed to use, defaults to 42
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

import requests
from openai import OpenAI

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-7B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:8000")
TASK_ID = os.getenv("TASK_ID", "triage")
TASK_SEED = int(os.getenv("TASK_SEED", "42"))

BENCHMARK = "incident_response"
TEMPERATURE = 0.1
MAX_TOKENS = 384
FALLBACK_ACTION = {"action_type": "investigate", "tool": "logs", "target": "api-gateway"}


def sanitize_line_value(value: Any) -> str:
    """Render values as single-line strings for strict stdout formatting."""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def format_reward(value: float) -> str:
    """Format rewards with exactly two decimals."""
    return f"{float(value):.2f}"


def log_start(task: str, env: str, model: str) -> None:
    print(
        f"[START] task={sanitize_line_value(task)} "
        f"env={sanitize_line_value(env)} "
        f"model={sanitize_line_value(model)}",
        flush=True,
    )


def log_step(step: int, action: str, reward: float, done: bool, error: str | None) -> None:
    error_value = sanitize_line_value(error) if error else "null"
    print(
        f"[STEP] step={step} "
        f"action={sanitize_line_value(action)} "
        f"reward={format_reward(reward)} "
        f"done={str(done).lower()} "
        f"error={error_value}",
        flush=True,
    )


def log_end(success: bool, steps: int, rewards: list[float]) -> None:
    rewards_str = ",".join(format_reward(reward) for reward in rewards)
    print(
        f"[END] success={str(success).lower()} "
        f"steps={steps} "
        f"rewards={rewards_str}",
        flush=True,
    )


class EnvClient:
    """HTTP client for the incident response environment."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def reset(self, task_id: str, seed: int) -> dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}/reset",
            json={"task_id": task_id, "seed": seed},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}/step",
            json=action,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def grader(self) -> dict[str, Any]:
        response = self.session.get(f"{self.base_url}/grader", timeout=30)
        response.raise_for_status()
        return response.json()

    def health(self) -> dict[str, Any]:
        response = self.session.get(f"{self.base_url}/health", timeout=10)
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self.session.close()


SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) responding to a production incident.

Your goal is to efficiently diagnose and resolve the incident by taking appropriate actions.

You MUST respond with ONLY a valid JSON object describing exactly one action.

Available action shapes:
{"action_type": "acknowledge"}
{"action_type": "investigate", "tool": "logs", "target": "api-gateway"}
{"action_type": "diagnose", "root_cause": "memory_leak", "target": "auth-service", "confidence": 0.85}
{"action_type": "classify", "severity": "P1"}
{"action_type": "remediate", "remediation": "rollback", "target": "auth-service"}
{"action_type": "communicate", "message": "Investigating elevated error rates on auth-service."}
{"action_type": "escalate", "target": "database-team"}
"""


def format_observation_for_prompt(observation: dict[str, Any]) -> str:
    """Flatten the observation into a compact prompt for the model."""
    lines = [
        f"Task: {observation.get('task_id', 'unknown')}",
        f"Step: {observation.get('step_number', 0)}/{observation.get('max_steps', 20)}",
        f"Description: {observation.get('task_description', '')}",
    ]

    feedback = observation.get("feedback")
    if feedback:
        lines.extend(["", "Feedback:", str(feedback)])

    alerts = observation.get("alerts", [])
    if alerts:
        lines.append("")
        lines.append("Alerts:")
        for alert in alerts:
            lines.append(
                f"- [{alert.get('severity', 'P3')}] {alert.get('service', 'unknown')}: "
                f"{alert.get('title', '')}"
            )
            lines.append(f"  {alert.get('description', '')}")

    system_status = observation.get("system_status", [])
    if system_status:
        critical = [item["name"] for item in system_status if item.get("status") in {"critical", "down"}]
        degraded = [item["name"] for item in system_status if item.get("status") == "degraded"]
        if critical or degraded:
            lines.append("")
            lines.append(
                "System status: "
                f"critical={','.join(critical) or 'none'} "
                f"degraded={','.join(degraded) or 'none'}"
            )

    investigation_result = observation.get("investigation_result")
    if investigation_result:
        lines.extend(["", "Investigation result:", str(investigation_result)])

    available_actions = observation.get("available_actions", [])
    if available_actions:
        lines.extend(["", f"Available actions: {', '.join(available_actions)}"])

    return "\n".join(lines)


def parse_action_from_response(response_text: str) -> dict[str, Any]:
    """Extract an action JSON object from the model output."""
    text = response_text.strip()

    block_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if block_match:
        text = block_match.group(1)

    json_match = re.search(r"\{.*\}", text, re.DOTALL)
    if json_match:
        text = json_match.group(0)

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return FALLBACK_ACTION.copy()

    if isinstance(parsed, dict) and parsed.get("action_type"):
        return parsed
    return FALLBACK_ACTION.copy()


def parse_request_error(error: Exception) -> str:
    """Extract the most useful single-line error string from request failures."""
    if isinstance(error, requests.HTTPError) and error.response is not None:
        body = error.response.text.strip()
        if body:
            return body
    return sanitize_line_value(error)


def build_openai_client() -> OpenAI:
    if not HF_TOKEN:
        raise ValueError("HF_TOKEN environment variable is required")
    return OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)


def run_episode(env_client: EnvClient, openai_client: OpenAI, task_id: str, seed: int) -> None:
    rewards: list[float] = []
    steps_taken = 0
    success = False
    final_observation: dict[str, Any] | None = None

    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

    try:
        observation = env_client.reset(task_id, seed)
        messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]

        while not observation.get("done", False):
            messages.append({"role": "user", "content": format_observation_for_prompt(observation)})

            try:
                completion = openai_client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    max_tokens=MAX_TOKENS,
                    temperature=TEMPERATURE,
                )
                assistant_message = completion.choices[0].message.content or ""
            except Exception as error:  # noqa: BLE001
                print(f"[DEBUG] LLM API error: {error}", file=sys.stderr)
                assistant_message = json.dumps(FALLBACK_ACTION)

            messages.append({"role": "assistant", "content": assistant_message})
            action = parse_action_from_response(assistant_message)
            action_str = json.dumps(action, separators=(",", ":"), ensure_ascii=True)

            try:
                observation = env_client.step(action)
            except Exception as error:  # noqa: BLE001
                print(f"[DEBUG] Environment step error: {error}", file=sys.stderr)
                break

            final_observation = observation
            steps_taken = int(observation.get("step_number", steps_taken + 1))
            reward = float(observation.get("reward", 0.0))
            rewards.append(reward)

            error_value = observation.get("last_action_error")
            log_step(
                step=steps_taken,
                action=action_str,
                reward=reward,
                done=bool(observation.get("done", False)),
                error=str(error_value) if error_value else None,
            )

        if final_observation and final_observation.get("done", False):
            feedback = str(final_observation.get("feedback", ""))
            success = "resolved successfully" in feedback.lower()

            if not success:
                try:
                    grader_result = env_client.grader()
                    success = float(grader_result.get("total", 0.0)) >= 0.5
                except Exception as error:  # noqa: BLE001
                    print(f"[DEBUG] Grader error: {error}", file=sys.stderr)

    except Exception as error:  # noqa: BLE001
        print(f"[DEBUG] Episode error: {parse_request_error(error)}", file=sys.stderr)
    finally:
        log_end(success=success, steps=steps_taken, rewards=rewards)


def main() -> None:
    env_client = EnvClient(ENV_BASE_URL)

    try:
        try:
            health = env_client.health()
            print(f"[DEBUG] Environment health: {health.get('status', 'unknown')}", file=sys.stderr)
        except Exception as error:  # noqa: BLE001
            print(f"[DEBUG] Health check failed: {parse_request_error(error)}", file=sys.stderr)

        openai_client = build_openai_client()
        run_episode(env_client, openai_client, TASK_ID, TASK_SEED)
    finally:
        env_client.close()


if __name__ == "__main__":
    main()
