"""
Main Environment class for the SRE Incident Response OpenEnv environment.

Implements reset(), step(), and state following the OpenEnv pattern without
depending on openenv.core. The environment is wired directly to FastAPI.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from incident_response.models import (
    ActionType,
    Alert,
    IncidentAction,
    IncidentObservation,
    IncidentState,
    ServiceHealth,
    ServiceStatus,
    Severity,
    TimelineEvent,
)
from incident_response.scenarios.service_graph import ServiceGraph


# ---------------------------------------------------------------------------
# Task Configuration
# ---------------------------------------------------------------------------

TASK_CONFIG: dict[str, dict[str, Any]] = {
    "triage": {
        "description": (
            "Triage the incoming alerts. Acknowledge the incident and classify "
            "its severity (P1-P4) based on impact and urgency. Investigate logs, "
            "metrics, and traces to determine the appropriate severity level."
        ),
        "max_steps": 15,
        "available_actions": [
            ActionType.INVESTIGATE,
            ActionType.CLASSIFY,
            ActionType.ACKNOWLEDGE,
            ActionType.COMMUNICATE,
            ActionType.ESCALATE,
        ],
    },
    "rca": {
        "description": (
            "Identify the root cause of the incident. Investigate logs, metrics, "
            "traces, recent deploys, and service dependencies. Submit your diagnosis "
            "with the root cause identifier and confidence level."
        ),
        "max_steps": 25,
        "available_actions": [
            ActionType.INVESTIGATE,
            ActionType.DIAGNOSE,
            ActionType.COMMUNICATE,
            ActionType.ESCALATE,
        ],
    },
    "cascading": {
        "description": (
            "Handle a cascading failure affecting multiple services. Identify the "
            "primary failing service, determine the root cause, and apply the correct "
            "remediation to restore service health."
        ),
        "max_steps": 30,
        "available_actions": [
            ActionType.INVESTIGATE,
            ActionType.DIAGNOSE,
            ActionType.REMEDIATE,
            ActionType.COMMUNICATE,
            ActionType.ESCALATE,
        ],
    },
}


# ---------------------------------------------------------------------------
# Scenario Config Types (used before generators are implemented)
# ---------------------------------------------------------------------------


def _generate_default_scenario(
    rng: random.Random, task_type: str, service_graph: ServiceGraph
) -> dict[str, Any]:
    """
    Generate a default scenario configuration.

    This provides working scenarios before the dedicated generators are implemented.
    """
    services = service_graph.get_service_names()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if task_type == "triage":
        affected_service = rng.choice(["api-gateway", "auth-service", "order-service"])
        severity = rng.choice([Severity.P1, Severity.P2, Severity.P3])
        return {
            "task_type": "triage",
            "incident_id": f"INC-{rng.randint(10000, 99999)}",
            "affected_services": [affected_service],
            "primary_service": affected_service,
            "ground_truth_severity": severity,
            "ground_truth_root_cause": f"{affected_service}-high-error-rate",
            "ground_truth_remediations": ["restart"],
            "alerts": [
                {
                    "alert_id": f"ALT-{rng.randint(1000, 9999)}",
                    "service": affected_service,
                    "severity": severity,
                    "title": f"High error rate on {affected_service}",
                    "description": f"Error rate exceeded threshold on {affected_service}. "
                    f"Current: {rng.uniform(5, 25):.1f}%, Threshold: 1%",
                    "timestamp": timestamp,
                    "labels": {"env": "production", "region": "us-east-1"},
                }
            ],
            "tool_data": _generate_tool_data(rng, affected_service, severity, service_graph),
        }

    elif task_type == "rca":
        # Pick a service and a plausible root cause
        root_causes = [
            ("auth-db", "connection_pool_exhaustion", "Connection pool exhausted"),
            ("redis", "memory_limit_reached", "Memory limit reached, evictions high"),
            ("kafka", "consumer_lag", "Consumer lag exceeding threshold"),
            ("order-db", "slow_queries", "Slow query detected on orders table"),
            ("api-gateway", "bad_deploy", "Recent deploy introduced regression"),
        ]
        root_cause_info = rng.choice(root_causes)
        affected_service = root_cause_info[0]
        root_cause_id = root_cause_info[1]
        root_cause_desc = root_cause_info[2]

        # Get affected services via propagation
        propagation = service_graph.propagate_failure(affected_service, "errors")
        affected_list = list(propagation.keys())

        return {
            "task_type": "rca",
            "incident_id": f"INC-{rng.randint(10000, 99999)}",
            "affected_services": affected_list,
            "primary_service": affected_service,
            "ground_truth_severity": Severity.P2,
            "ground_truth_root_cause": root_cause_id,
            "ground_truth_root_cause_description": root_cause_desc,
            "ground_truth_remediations": ["restart", "scale_up"],
            "alerts": [
                {
                    "alert_id": f"ALT-{rng.randint(1000, 9999)}",
                    "service": svc,
                    "severity": Severity.P2 if svc == affected_service else Severity.P3,
                    "title": f"Elevated error rate on {svc}",
                    "description": f"Error rate spike detected on {svc}",
                    "timestamp": timestamp,
                    "labels": {"env": "production"},
                }
                for svc in affected_list[:4]  # Limit alerts
            ],
            "tool_data": _generate_tool_data(
                rng, affected_service, Severity.P2, service_graph, root_cause_id
            ),
        }

    else:  # cascading
        # Pick a root service that causes cascading failure
        root_service = rng.choice(["auth-db", "redis", "kafka", "order-db"])
        propagation = service_graph.propagate_failure(root_service, "down")
        affected_list = list(propagation.keys())

        remediation_map = {
            "auth-db": "failover",
            "redis": "restart",
            "kafka": "restart",
            "order-db": "failover",
        }

        return {
            "task_type": "cascading",
            "incident_id": f"INC-{rng.randint(10000, 99999)}",
            "affected_services": affected_list,
            "primary_service": root_service,
            "ground_truth_severity": Severity.P1,
            "ground_truth_root_cause": f"{root_service}-failure",
            "ground_truth_remediations": [remediation_map.get(root_service, "restart")],
            "alerts": [
                {
                    "alert_id": f"ALT-{rng.randint(1000, 9999)}",
                    "service": svc,
                    "severity": Severity.P1
                    if propagation.get(svc, {}).get("distance", 0) == 0
                    else Severity.P2,
                    "title": f"Service degraded: {svc}",
                    "description": f"{svc} is experiencing failures. "
                    f"Error rate: {propagation.get(svc, {}).get('error_rate_multiplier', 1) * 0.1:.1f}%",
                    "timestamp": timestamp,
                    "labels": {"env": "production", "cascade": "true"},
                }
                for svc in affected_list[:6]
            ],
            "tool_data": _generate_tool_data(
                rng, root_service, Severity.P1, service_graph, f"{root_service}-failure"
            ),
            "propagation_impact": propagation,
        }


def _generate_tool_data(
    rng: random.Random,
    primary_service: str,
    severity: Severity,
    service_graph: ServiceGraph,
    root_cause: str = "",
) -> dict[str, dict[str, Any]]:
    """Generate mock tool data for investigations."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Services with relevant data
    affected = [primary_service] + service_graph.get_dependents(primary_service)

    tool_data: dict[str, dict[str, Any]] = {}

    # Logs data
    tool_data["logs"] = {
        primary_service: {
            "has_data": True,
            "entries": [
                {
                    "timestamp": timestamp,
                    "level": "ERROR",
                    "message": f"Connection timeout after 30s",
                    "trace_id": f"trace-{rng.randint(1000, 9999)}",
                },
                {
                    "timestamp": timestamp,
                    "level": "ERROR",
                    "message": f"Failed to process request: {root_cause or 'internal error'}",
                    "trace_id": f"trace-{rng.randint(1000, 9999)}",
                },
                {
                    "timestamp": timestamp,
                    "level": "WARN",
                    "message": "Retry attempt 3 of 3 failed",
                    "trace_id": f"trace-{rng.randint(1000, 9999)}",
                },
            ],
        }
    }
    for svc in affected:
        if svc != primary_service:
            tool_data["logs"][svc] = {
                "has_data": True,
                "entries": [
                    {
                        "timestamp": timestamp,
                        "level": "ERROR",
                        "message": f"Upstream dependency {primary_service} unavailable",
                        "trace_id": f"trace-{rng.randint(1000, 9999)}",
                    }
                ],
            }

    # Metrics data
    error_rate = 0.15 if severity == Severity.P1 else 0.08 if severity == Severity.P2 else 0.03
    tool_data["metrics"] = {
        primary_service: {
            "has_data": True,
            "error_rate": error_rate,
            "latency_p99_ms": rng.uniform(500, 2000),
            "request_rate_rps": rng.uniform(100, 500),
            "cpu_percent": rng.uniform(60, 95),
            "memory_percent": rng.uniform(70, 95),
        }
    }
    for svc in affected:
        if svc != primary_service:
            tool_data["metrics"][svc] = {
                "has_data": True,
                "error_rate": error_rate * 0.5,
                "latency_p99_ms": rng.uniform(200, 800),
                "request_rate_rps": rng.uniform(200, 800),
                "cpu_percent": rng.uniform(30, 60),
                "memory_percent": rng.uniform(40, 70),
            }

    # Traces data
    tool_data["traces"] = {
        primary_service: {
            "has_data": True,
            "sample_trace": {
                "trace_id": f"trace-{rng.randint(10000, 99999)}",
                "spans": [
                    {
                        "service": primary_service,
                        "operation": "handleRequest",
                        "duration_ms": rng.uniform(500, 1500),
                        "status": "ERROR",
                        "error": root_cause or "timeout",
                    }
                ],
            },
        }
    }

    # Deploys data
    tool_data["deploys"] = {
        primary_service: {
            "has_data": True,
            "recent_deploys": [
                {
                    "deploy_id": f"deploy-{rng.randint(100, 999)}",
                    "timestamp": timestamp,
                    "version": f"v1.{rng.randint(10, 50)}.{rng.randint(0, 20)}",
                    "author": "deploy-bot",
                    "change_summary": "Performance improvements and bug fixes",
                }
            ],
        }
    }

    # Config data
    tool_data["config"] = {
        primary_service: {
            "has_data": True,
            "current_config": {
                "max_connections": 100,
                "timeout_ms": 30000,
                "retry_count": 3,
                "circuit_breaker_enabled": True,
            },
        }
    }

    # Dependencies data
    tool_data["dependencies"] = {}
    for svc_name in service_graph.get_service_names():
        svc = service_graph.get_service(svc_name)
        if svc:
            tool_data["dependencies"][svc_name] = {
                "has_data": True,
                "dependencies": svc.dependencies,
                "dependents": service_graph.get_dependents(svc_name),
            }

    return tool_data


# ---------------------------------------------------------------------------
# Grader Stubs (used before graders are implemented)
# ---------------------------------------------------------------------------


class BaseGrader:
    """Base grader with default scoring logic."""

    def __init__(self, scenario_config: dict[str, Any]) -> None:
        self.scenario_config = scenario_config

    def score_classification(self, classified: Severity, ground_truth: Severity) -> float:
        """Score severity classification. Returns 1.0 for exact match, partial credit otherwise."""
        if classified == ground_truth:
            return 1.0
        severity_order = [Severity.P4, Severity.P3, Severity.P2, Severity.P1]
        classified_idx = severity_order.index(classified)
        truth_idx = severity_order.index(ground_truth)
        distance = abs(classified_idx - truth_idx)
        return max(0.0, 1.0 - (distance * 0.3))

    def score_diagnosis(
        self,
        diagnosed: str,
        ground_truth: str,
        expected_service: str = "",
        expected_category: Optional[str] = None,
        expected_symptoms: Optional[list[str]] = None,
    ) -> float:
        """Score root cause diagnosis."""
        if diagnosed.lower() == ground_truth.lower():
            return 1.0
        if ground_truth.lower() in diagnosed.lower() or diagnosed.lower() in ground_truth.lower():
            return 0.7
        if expected_service and expected_service.lower() in diagnosed.lower():
            return 0.4
        if expected_category and expected_category.lower() in diagnosed.lower():
            return 0.3
        return 0.0

    def score_remediation(
        self, remediation: str, target: str, expected_remediations: list[str], expected_target: str
    ) -> float:
        """Score remediation action."""
        target_correct = target.lower() == expected_target.lower()
        remediation_correct = remediation.lower() in [r.lower() for r in expected_remediations]

        if target_correct and remediation_correct:
            return 1.0
        elif remediation_correct:
            return 0.5
        elif target_correct:
            return 0.3
        return 0.0

    def score_communication(
        self,
        message: str,
        affected_services: Optional[list[str]] = None,
        severity: Optional[Severity] = None,
    ) -> float:
        """Score communication quality."""
        if not message:
            return 0.0
        score = 0.3
        if len(message) > 50:
            score += 0.2
        if any(word in message.lower() for word in ["investigating", "identified", "working"]):
            score += 0.2
        if any(word in message.lower() for word in ["impact", "affected", "service"]):
            score += 0.15
        if any(word in message.lower() for word in ["eta", "update", "status"]):
            score += 0.15
        return min(1.0, score)

    def compute_final_score(self, state: IncidentState) -> float:
        """Compute final episode score based on task type and accomplishments."""
        raise NotImplementedError("Subclasses must implement compute_final_score")


class TriageGrader(BaseGrader):
    """Grader for triage task."""

    def compute_final_score(self, state: IncidentState) -> float:
        score = 0.0
        # Acknowledgment: 20%
        if state.acknowledged:
            score += 0.2
        # Classification: 60%
        if state.classification_correct:
            score += 0.6
        elif state.severity_classified is not None:
            # Partial credit
            score += 0.3 * self.score_classification(
                state.severity_classified, state.ground_truth_severity or Severity.P3
            )
        # Efficiency bonus: 20%
        if state.step_count > 0:
            efficiency = max(0.0, 1.0 - (state.wasted_steps / state.step_count))
            score += 0.2 * efficiency
        return score


class RCAGrader(BaseGrader):
    """Grader for RCA task."""

    def compute_final_score(self, state: IncidentState) -> float:
        score = 0.0
        # Root cause identification: 70%
        if state.root_cause_correct:
            score += 0.7
        elif state.root_cause_identified:
            # Partial credit
            score += 0.35 * self.score_diagnosis(
                state.root_cause_identified, state.ground_truth_root_cause
            )
        # Investigation efficiency: 20%
        if state.investigation_steps > 0:
            useful_ratio = len(state.useful_investigations) / state.investigation_steps
            score += 0.2 * useful_ratio
        # Communication: 10%
        if state.status_updates:
            score += 0.1
        return score


class CascadingGrader(BaseGrader):
    """Grader for cascading failure task."""

    def compute_final_score(self, state: IncidentState) -> float:
        score = 0.0
        # Root cause: 30%
        if state.root_cause_correct:
            score += 0.3
        elif state.root_cause_identified:
            score += 0.15 * self.score_diagnosis(
                state.root_cause_identified, state.ground_truth_root_cause
            )
        # Remediation: 50%
        if state.remediation_correct:
            score += 0.5
        elif state.remediations_applied:
            # Partial credit for trying
            score += 0.15
        # Services fixed: bonus up to 10%
        if state.ground_truth_affected_services:
            fixed_ratio = len(state.services_fixed) / len(state.ground_truth_affected_services)
            score += 0.1 * fixed_ratio
        # Efficiency: 10%
        if state.step_count > 0:
            efficiency = max(0.0, 1.0 - (state.wasted_steps / state.step_count))
            score += 0.1 * efficiency
        return score


# ---------------------------------------------------------------------------
# Main Environment Class
# ---------------------------------------------------------------------------


class IncidentResponseEnvironment:
    """
    SRE Incident Response Environment.

    Simulates production incidents where agents must:
    - Task 1 (triage): Classify severity and acknowledge alerts
    - Task 2 (rca): Investigate and identify root cause
    - Task 3 (cascading): Handle multi-service cascading failure
    """

    def __init__(self) -> None:
        self._state: Optional[IncidentState] = None
        self._scenario_config: dict[str, Any] = {}
        self._grader: Optional[BaseGrader] = None
        self._rng: random.Random = random.Random()
        self._service_graph: ServiceGraph = ServiceGraph.create_ecommerce()

    @property
    def state(self) -> IncidentState:
        """Return current state."""
        if self._state is None:
            raise RuntimeError("Environment not initialized. Call reset() first.")
        return self._state

    def reset(
        self,
        seed: Optional[int] = None,
        task_id: Optional[str] = None,
        episode_id: Optional[str] = None,
    ) -> IncidentObservation:
        """
        Reset the environment and start a new episode.

        Args:
            seed: Random seed for deterministic scenario generation
            task_id: Task type ("triage", "rca", "cascading"). Defaults to "triage"
            episode_id: Optional episode identifier. Auto-generated if not provided.

        Returns:
            Initial observation with alerts, system status, and task description.
        """
        # Determine task type
        task_type = task_id or "triage"
        if task_type not in TASK_CONFIG:
            raise ValueError(f"Unknown task_id: {task_type}. Must be one of {list(TASK_CONFIG.keys())}")

        # Create deterministic RNG
        if seed is not None:
            self._rng = random.Random(seed)
        else:
            self._rng = random.Random()

        # Generate episode ID
        ep_id = episode_id or f"ep-{uuid.uuid4().hex[:12]}"

        # Generate scenario using appropriate generator
        self._scenario_config = self._generate_scenario(task_type)

        # Initialize fresh state with ground truth
        task_config = TASK_CONFIG[task_type]
        self._state = IncidentState(
            episode_id=ep_id,
            step_count=0,
            task_id=task_type,
            task_type=task_type,
            max_steps=task_config["max_steps"],
            incident_id=self._scenario_config["incident_id"],
            acknowledged=False,
            severity_classified=None,
            root_cause_identified=None,
            remediations_applied=[],
            status_updates=[],
            classification_correct=False,
            root_cause_correct=False,
            remediation_correct=False,
            services_fixed=[],
            investigation_steps=0,
            wasted_steps=0,
            useful_investigations=[],
            timeline=[],
            done=False,
            total_reward=0.0,
            ground_truth_root_cause=self._scenario_config.get("ground_truth_root_cause", ""),
            ground_truth_severity=self._scenario_config.get("ground_truth_severity"),
            ground_truth_affected_services=self._scenario_config.get("affected_services", []),
            ground_truth_remediations=self._scenario_config.get("ground_truth_remediations", []),
            ground_truth_primary_service=self._scenario_config.get("primary_service", ""),
        )

        # Create appropriate grader
        self._grader = self._create_grader(task_type)

        # Add initial timeline event
        self._add_timeline_event(
            event_type="incident_created",
            description=f"Incident {self._state.incident_id} created",
            actor="system",
        )

        # Return initial observation
        return self._build_observation(
            feedback="Incident response started. Review the alerts and take appropriate action.",
            investigation_result="",
            reward=0.0,
            done=False,
        )

    def step(self, action: IncidentAction) -> IncidentObservation:
        """
        Execute an action and return the resulting observation.

        Args:
            action: The action to execute

        Returns:
            Observation with feedback, investigation results, and rewards
        """
        if self._state is None:
            raise RuntimeError("Environment not initialized. Call reset() first.")

        if self._state.done:
            return self._build_observation(
                feedback="Episode already ended. Call reset() to start a new episode.",
                investigation_result="",
                reward=0.0,
                done=True,
            )

        # Process action by type
        feedback: str = ""
        investigation_result: str = ""
        action_reward: float = 0.0

        if action.action_type == ActionType.INVESTIGATE:
            feedback, investigation_result, action_reward = self._handle_investigate(action)
        elif action.action_type == ActionType.CLASSIFY:
            feedback, action_reward = self._handle_classify(action)
        elif action.action_type == ActionType.DIAGNOSE:
            feedback, action_reward = self._handle_diagnose(action)
        elif action.action_type == ActionType.REMEDIATE:
            feedback, action_reward = self._handle_remediate(action)
        elif action.action_type == ActionType.ACKNOWLEDGE:
            feedback, action_reward = self._handle_acknowledge(action)
        elif action.action_type == ActionType.COMMUNICATE:
            feedback, action_reward = self._handle_communicate(action)
        elif action.action_type == ActionType.ESCALATE:
            feedback, action_reward = self._handle_escalate(action)
        else:
            feedback = f"Unknown action type: {action.action_type}"
            action_reward = -0.1

        # Increment step count
        self._state.step_count += 1

        # Check if episode is done
        resolved = self._check_resolution()
        timeout = self._state.step_count >= self._state.max_steps

        # Compute step reward (action reward + time penalty)
        step_reward = action_reward - 0.01  # Small time penalty per step

        # Update total reward
        self._state.total_reward += step_reward

        # If done, compute final score and add to total reward
        if resolved or timeout:
            self._state.done = True
            if self._grader:
                final_result = self._grader.compute_final_score(self._state)
                if isinstance(final_result, dict):
                    final_score = final_result.get("total", 0.0)
                else:
                    final_score = float(final_result)
                self._state.total_reward += final_score

            self._add_timeline_event(
                event_type="incident_resolved" if resolved else "timeout",
                description="Incident resolved successfully"
                if resolved
                else "Episode timed out before resolution",
                actor="system",
            )

            if resolved:
                feedback += " Incident resolved successfully!"
            else:
                feedback += " Episode timed out."

        return self._build_observation(
            feedback=feedback,
            investigation_result=investigation_result,
            reward=step_reward,
            done=self._state.done,
        )

    # ---------------------------------------------------------------------------
    # Action Handlers
    # ---------------------------------------------------------------------------

    def _handle_investigate(self, action: IncidentAction) -> tuple[str, str, float]:
        """Handle investigate action."""
        tool = action.tool or ""
        target = action.target or ""

        if not tool:
            return "Investigation requires a tool (logs, metrics, traces, deploys, config, dependencies, alerts).", "", -0.05

        if not target and tool not in ["alerts", "dependencies"]:
            return f"Investigation with {tool} requires a target service.", "", -0.05

        self._state.investigation_steps += 1

        # Add timeline event
        self._add_timeline_event(
            event_type="investigate",
            description=f"Investigated {tool} for {target or 'all services'}",
            actor="agent",
            metadata={"tool": tool, "target": target},
        )

        # Look up tool data — supports both legacy "tool_data" format and
        # direct "logs_data"/"metrics_data"/etc format from external generators.
        tool_data = self._scenario_config.get("tool_data", {})
        investigation_result = ""
        reward = 0.0

        if tool == "logs":
            investigation_result, reward = self._format_logs(target, tool_data)
        elif tool == "metrics":
            investigation_result, reward = self._format_metrics(target, tool_data)
        elif tool == "traces":
            investigation_result, reward = self._format_traces(target, tool_data)
        elif tool == "deploys":
            investigation_result, reward = self._format_deploys(target, tool_data)
        elif tool == "config":
            investigation_result, reward = self._format_config(target, tool_data)
        elif tool == "dependencies":
            investigation_result = self._format_dependencies(target)
            reward = 0.02  # Dependencies always useful
        elif tool == "alerts":
            investigation_result = self._format_alerts_list()
            reward = 0.01
        else:
            investigation_result = f"Unknown tool: {tool}"
            reward = -0.05

        # Track useful vs wasted investigations
        if reward > 0:
            self._state.useful_investigations.append(f"{tool}:{target}")
        else:
            self._state.wasted_steps += 1

        return f"Investigated {tool} for {target or 'system'}.", investigation_result, reward

    def _handle_classify(self, action: IncidentAction) -> tuple[str, float]:
        """Handle classify action."""
        if action.severity is None:
            return "Classification requires a severity level (P1-P4).", -0.05

        self._state.severity_classified = action.severity

        # Compare to ground truth
        ground_truth = self._state.ground_truth_severity
        if ground_truth and action.severity == ground_truth:
            self._state.classification_correct = True
            reward = 0.3
            feedback = f"Classified incident as {action.severity.value}. Correct!"
        elif ground_truth:
            reward = 0.1 * self._grader.score_classification(action.severity, ground_truth) if self._grader else 0.05
            feedback = f"Classified incident as {action.severity.value}. Ground truth was {ground_truth.value}."
        else:
            reward = 0.05
            feedback = f"Classified incident as {action.severity.value}."

        self._add_timeline_event(
            event_type="classify",
            description=f"Classified severity as {action.severity.value}",
            actor="agent",
            metadata={"severity": action.severity.value, "correct": self._state.classification_correct},
        )

        return feedback, reward

    def _handle_diagnose(self, action: IncidentAction) -> tuple[str, float]:
        """Handle diagnose action."""
        if not action.root_cause:
            return "Diagnosis requires a root_cause identifier.", -0.05

        self._state.root_cause_identified = action.root_cause

        # Compare to ground truth
        ground_truth = self._state.ground_truth_root_cause
        root_cause_obj = self._scenario_config.get("root_cause")
        expected_service = self._scenario_config.get("primary_service", "")
        expected_category = root_cause_obj.category.value if root_cause_obj and hasattr(root_cause_obj.category, "value") else None
        expected_symptoms = root_cause_obj.symptoms if root_cause_obj else None
        diagnosis_score = self._grader.score_diagnosis(
            action.root_cause, ground_truth, expected_service, expected_category, expected_symptoms
        ) if self._grader else 0.0

        if diagnosis_score >= 0.9:
            self._state.root_cause_correct = True
            reward = 0.4
            feedback = f"Diagnosed root cause as '{action.root_cause}'. Correct!"
        elif diagnosis_score > 0:
            reward = 0.2 * diagnosis_score
            feedback = f"Diagnosed root cause as '{action.root_cause}'. Partially correct."
        else:
            reward = 0.0
            feedback = f"Diagnosed root cause as '{action.root_cause}'. Incorrect."

        self._add_timeline_event(
            event_type="diagnose",
            description=f"Diagnosed root cause: {action.root_cause}",
            actor="agent",
            metadata={
                "root_cause": action.root_cause,
                "confidence": action.confidence,
                "correct": self._state.root_cause_correct,
            },
        )

        return feedback, reward

    def _handle_remediate(self, action: IncidentAction) -> tuple[str, float]:
        """Handle remediate action."""
        if not action.remediation:
            return "Remediation requires specifying the remediation action.", -0.05
        if not action.target:
            return "Remediation requires a target service.", -0.05

        self._state.remediations_applied.append(f"{action.remediation}:{action.target}")

        # Score remediation
        expected_remediations = self._state.ground_truth_remediations
        expected_target = self._state.ground_truth_primary_service

        remediation_score = 0.0
        if self._grader:
            remediation_score = self._grader.score_remediation(
                action.remediation, action.target, expected_remediations, expected_target
            )

        if remediation_score >= 0.9:
            self._state.remediation_correct = True
            self._state.services_fixed.append(action.target)
            reward = 0.5
            feedback = f"Applied {action.remediation} to {action.target}. Remediation successful!"
        elif remediation_score > 0:
            reward = 0.2 * remediation_score
            feedback = f"Applied {action.remediation} to {action.target}. Partially effective."
        else:
            reward = -0.1
            feedback = f"Applied {action.remediation} to {action.target}. No effect or wrong target."

        self._add_timeline_event(
            event_type="remediate",
            description=f"Applied {action.remediation} to {action.target}",
            actor="agent",
            metadata={
                "remediation": action.remediation,
                "target": action.target,
                "correct": self._state.remediation_correct,
            },
        )

        return feedback, reward

    def _handle_acknowledge(self, action: IncidentAction) -> tuple[str, float]:
        """Handle acknowledge action."""
        if self._state.acknowledged:
            return "Incident already acknowledged.", 0.0

        self._state.acknowledged = True

        self._add_timeline_event(
            event_type="acknowledge",
            description="Incident acknowledged by responder",
            actor="agent",
        )

        return "Incident acknowledged. Stakeholders have been notified.", 0.1

    def _handle_communicate(self, action: IncidentAction) -> tuple[str, float]:
        """Handle communicate action."""
        if not action.message:
            return "Communication requires a message.", -0.02

        self._state.status_updates.append(action.message)

        # Score communication quality
        affected = self._state.ground_truth_affected_services
        severity = self._state.ground_truth_severity
        comm_score = self._grader.score_communication(action.message, affected, severity) if self._grader else 0.5
        reward = 0.05 * comm_score

        self._add_timeline_event(
            event_type="communicate",
            description=f"Status update: {action.message[:100]}...",
            actor="agent",
            metadata={"full_message": action.message},
        )

        return "Status update posted to incident channel.", reward

    def _handle_escalate(self, action: IncidentAction) -> tuple[str, float]:
        """Handle escalate action."""
        escalation_target = action.target or "on-call engineer"

        self._add_timeline_event(
            event_type="escalate",
            description=f"Escalated to {escalation_target}",
            actor="agent",
            metadata={"escalation_target": escalation_target},
        )

        return f"Escalated incident to {escalation_target}.", 0.05

    # ---------------------------------------------------------------------------
    # Helper Methods
    # ---------------------------------------------------------------------------

    def _generate_scenario(self, task_type: str) -> dict[str, Any]:
        """Generate scenario using appropriate generator or fallback."""
        seed = self._rng.randint(0, 2**31 - 1)
        try:
            if task_type == "triage":
                from incident_response.scenarios.alert_triage import AlertTriageGenerator
                config = AlertTriageGenerator().generate(seed)
            elif task_type == "rca":
                from incident_response.scenarios.root_cause import RCAGenerator
                config = RCAGenerator().generate(seed)
            elif task_type == "cascading":
                from incident_response.scenarios.cascading_failure import CascadingFailureGenerator
                config = CascadingFailureGenerator().generate(seed)
            else:
                return _generate_default_scenario(self._rng, task_type, self._service_graph)

            # Convert ScenarioConfig to dict for environment consumption
            # Also propagate failure to get cascade impact
            graph = config.service_graph or self._service_graph
            propagation = {}
            if graph and config.root_cause:
                propagation = graph.propagate_failure(
                    config.root_cause.service, config.root_cause.category.value
                )

            return {
                "task_id": config.task_id,
                "incident_id": f"INC-{seed:06d}",
                "ground_truth_root_cause": config.root_cause.id,
                "ground_truth_severity": Severity(config.severity) if isinstance(config.severity, str) else config.severity,
                "ground_truth_remediations": config.root_cause.remediations,
                "primary_service": config.root_cause.service,
                "affected_services": config.affected_services,
                "alerts": config.alerts,
                "logs_data": config.logs_data,
                "metrics_data": config.metrics_data,
                "traces_data": config.traces_data,
                "deploys_data": config.deploys_data,
                "service_graph": graph,
                "root_cause": config.root_cause,
                "propagation_impact": propagation,
                "max_steps": config.max_steps,
            }
        except (ImportError, Exception):
            pass

        # Fallback to default generator
        return _generate_default_scenario(self._rng, task_type, self._service_graph)

    def _create_grader(self, task_type: str) -> BaseGrader:
        """Create appropriate grader for task type."""
        # Extract ground truth from scenario config
        gt_root_cause = self._scenario_config.get("ground_truth_root_cause", "")
        gt_severity = self._scenario_config.get("ground_truth_severity", Severity.P3)
        gt_remediations = self._scenario_config.get("ground_truth_remediations", [])
        gt_primary = self._scenario_config.get("primary_service", "")
        affected = self._scenario_config.get("affected_services", [])

        grader_args = (gt_root_cause, gt_severity, gt_remediations, gt_primary, affected)

        try:
            if task_type == "triage":
                from incident_response.graders.triage_grader import TriageGrader as ExtTriageGrader
                return ExtTriageGrader(*grader_args)
            elif task_type == "rca":
                from incident_response.graders.rca_grader import RCAGrader as ExtRCAGrader
                return ExtRCAGrader(*grader_args)
            elif task_type == "cascading":
                from incident_response.graders.cascading_grader import CascadingGrader as ExtCascadingGrader
                return ExtCascadingGrader(*grader_args, expected_remediation_order=gt_remediations)
        except (ImportError, TypeError):
            pass

        # Fallback to built-in graders
        if task_type == "triage":
            return TriageGrader(self._scenario_config)
        elif task_type == "rca":
            return RCAGrader(self._scenario_config)
        else:
            return CascadingGrader(self._scenario_config)

    def _build_observation(
        self, feedback: str, investigation_result: str, reward: float, done: bool
    ) -> IncidentObservation:
        """Construct observation from current state."""
        task_config = TASK_CONFIG.get(self._state.task_type, TASK_CONFIG["triage"])

        # Build alerts from scenario config
        alerts: list[Alert] = []
        for alert_data in self._scenario_config.get("alerts", []):
            alerts.append(
                Alert(
                    alert_id=alert_data["alert_id"],
                    service=alert_data["service"],
                    severity=alert_data["severity"],
                    title=alert_data["title"],
                    description=alert_data["description"],
                    timestamp=alert_data["timestamp"],
                    labels=alert_data.get("labels", {}),
                    acknowledged=self._state.acknowledged,
                )
            )

        # Clamp reward to (0.0, 1.0) - strictly between, not inclusive
        # Validator requires all scores > 0 and < 1
        clamped_reward = max(0.001, min(0.999, reward))

        return IncidentObservation(
            alerts=alerts,
            investigation_result=investigation_result,
            system_status=self._get_system_status(),
            timeline=list(self._state.timeline),
            available_actions=[a.value for a in task_config["available_actions"]],
            feedback=feedback,
            task_id=self._state.task_id,
            task_description=task_config["description"],
            done=done,
            reward=clamped_reward,
            step_number=self._state.step_count,
            max_steps=self._state.max_steps,
        )

    def _get_system_status(self) -> list[ServiceHealth]:
        """Build service health list from scenario."""
        affected_services = set(self._scenario_config.get("affected_services", []))
        primary_service = self._scenario_config.get("primary_service", "")
        propagation = self._scenario_config.get("propagation_impact", {})

        status_list: list[ServiceHealth] = []

        for svc in self._service_graph.get_all_services():
            if svc.name in affected_services:
                # Determine status based on impact
                if svc.name == primary_service:
                    status = ServiceStatus.CRITICAL
                    error_mult = propagation.get(svc.name, {}).get("error_rate_multiplier", 100)
                    latency_mult = propagation.get(svc.name, {}).get("latency_multiplier", 10)
                elif svc.name in propagation:
                    distance = propagation[svc.name].get("distance", 1)
                    status = ServiceStatus.CRITICAL if distance <= 1 else ServiceStatus.DEGRADED
                    error_mult = propagation[svc.name].get("error_rate_multiplier", 10)
                    latency_mult = propagation[svc.name].get("latency_multiplier", 5)
                else:
                    status = ServiceStatus.DEGRADED
                    error_mult = 10
                    latency_mult = 3

                status_list.append(
                    ServiceHealth(
                        name=svc.name,
                        status=status,
                        error_rate=min(0.5, svc.baseline_metrics.error_rate * error_mult),
                        latency_p99_ms=svc.baseline_metrics.latency_p99_ms * latency_mult,
                        request_rate_rps=svc.baseline_metrics.request_rate * 0.7,
                        cpu_percent=min(95.0, 25.0 + self._rng.uniform(20, 50)),
                        memory_percent=min(95.0, 40.0 + self._rng.uniform(20, 40)),
                        last_deploy=None,
                    )
                )
            else:
                status_list.append(
                    ServiceHealth(
                        name=svc.name,
                        status=ServiceStatus.HEALTHY,
                        error_rate=svc.baseline_metrics.error_rate,
                        latency_p99_ms=svc.baseline_metrics.latency_p99_ms,
                        request_rate_rps=svc.baseline_metrics.request_rate,
                        cpu_percent=25.0 + self._rng.uniform(0, 10),
                        memory_percent=40.0 + self._rng.uniform(0, 15),
                        last_deploy=None,
                    )
                )

        return status_list

    def _check_resolution(self) -> bool:
        """Task-specific completion check."""
        task_type = self._state.task_type

        if task_type == "triage":
            return self._state.acknowledged and self._state.classification_correct

        elif task_type == "rca":
            return self._state.root_cause_correct

        elif task_type == "cascading":
            # Need correct remediation on primary service
            return self._state.remediation_correct and self._state.root_cause_correct

        return False

    def _add_timeline_event(
        self, event_type: str, description: str, actor: str, metadata: Optional[dict[str, Any]] = None
    ) -> None:
        """Add an event to the timeline."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._state.timeline.append(
            TimelineEvent(
                timestamp=timestamp,
                event_type=event_type,
                description=description,
                actor=actor,
                metadata=metadata or {},
            )
        )

    # ---------------------------------------------------------------------------
    # Tool Data Formatters
    # ---------------------------------------------------------------------------

    def _format_logs(self, target: str, tool_data: dict[str, Any]) -> tuple[str, float]:
        """Format log investigation results."""
        # Check legacy format (tool_data.logs.{service}) and direct format (logs_data.{service})
        logs_data = tool_data.get("logs", {})
        service_logs = logs_data.get(target, {})
        entries: list[dict[str, Any]] = []

        if isinstance(service_logs, dict) and service_logs.get("has_data"):
            entries = service_logs.get("entries", [])
        elif isinstance(service_logs, list):
            entries = service_logs

        # Also check direct logs_data from external generators
        if not entries:
            direct_logs = self._scenario_config.get("logs_data", {})
            svc_entries = direct_logs.get(target, [])
            if isinstance(svc_entries, list):
                entries = svc_entries

        if not entries:
            return f"No relevant logs found for {target}.", -0.02

        # Format using LogsEngine if available, otherwise simple format
        try:
            from incident_response.simulation.logs_engine import LogsEngine
            formatted = LogsEngine.format_logs(entries, target, limit=20)
            reward = 0.05 if target in self._scenario_config.get("affected_services", []) else 0.01
            return formatted, reward
        except (ImportError, AttributeError, TypeError):
            pass

        lines = [f"=== Logs for {target} ==="]
        for entry in entries[:20]:
            ts = entry.get("timestamp", "")
            level = entry.get("level", "INFO")
            msg = entry.get("message", "")
            lines.append(f"[{ts}] {level}: {msg}")
            if entry.get("trace_id"):
                lines.append(f"  trace_id: {entry['trace_id']}")

        reward = 0.05 if target in self._scenario_config.get("affected_services", []) else 0.01
        return "\n".join(lines), reward

    def _format_metrics(self, target: str, tool_data: dict[str, Any]) -> tuple[str, float]:
        """Format metrics investigation results."""
        metrics_data = tool_data.get("metrics", {})
        service_metrics = metrics_data.get(target, {})

        # Also check direct metrics_data from external generators
        if not service_metrics or (isinstance(service_metrics, dict) and not service_metrics.get("has_data", True)):
            direct_metrics = self._scenario_config.get("metrics_data", {})
            svc_metrics = direct_metrics.get(target, {})
            if svc_metrics:
                service_metrics = svc_metrics

        if not service_metrics:
            return f"No metrics data available for {target}.", -0.02

        lines = [f"=== Metrics for {target} ==="]
        error_rate = service_metrics.get("error_rate", 0)
        lines.append(f"Error Rate: {error_rate * 100 if error_rate < 1 else error_rate:.2f}%")
        lines.append(f"Latency P99: {service_metrics.get('latency_p99_ms', 0):.1f}ms")
        lines.append(f"Request Rate: {service_metrics.get('request_rate_rps', service_metrics.get('request_rate', 0)):.1f} RPS")
        lines.append(f"CPU: {service_metrics.get('cpu_percent', 0):.1f}%")
        lines.append(f"Memory: {service_metrics.get('memory_percent', 0):.1f}%")

        reward = 0.05 if target in self._scenario_config.get("affected_services", []) else 0.01
        return "\n".join(lines), reward

    def _format_traces(self, target: str, tool_data: dict[str, Any]) -> tuple[str, float]:
        """Format trace investigation results."""
        traces_data = tool_data.get("traces", {})
        service_traces = traces_data.get(target, {})

        # Also check direct traces_data from external generators
        if not service_traces:
            direct_traces = self._scenario_config.get("traces_data", {})
            svc_traces = direct_traces.get(target, [])
            if svc_traces:
                service_traces = svc_traces

        if not service_traces:
            return f"No trace data available for {target}.", -0.02

        # Handle list format from external generators
        if isinstance(service_traces, list):
            lines = [f"=== Distributed Traces for {target} ==="]
            for trace in service_traces[:5]:
                lines.append(f"Trace ID: {trace.get('trace_id', 'N/A')}")
                for span in trace.get("spans", []):
                    svc = span.get("service", "unknown")
                    op = span.get("operation", "unknown")
                    dur = span.get("duration_ms", 0)
                    status = span.get("status", "OK")
                    lines.append(f"  [{svc}] {op} — {dur:.1f}ms ({status})")
                    if span.get("error"):
                        lines.append(f"    Error: {span['error']}")
            reward = 0.05 if target in self._scenario_config.get("affected_services", []) else 0.01
            return "\n".join(lines), reward

        # Handle dict format from fallback generator
        if isinstance(service_traces, dict) and not service_traces.get("has_data", True):
            return f"No trace data available for {target}.", -0.02

        sample = service_traces.get("sample_trace", {}) if isinstance(service_traces, dict) else {}
        lines = [f"=== Traces for {target} ==="]
        lines.append(f"Trace ID: {sample.get('trace_id', 'N/A')}")
        for span in sample.get("spans", []):
            lines.append(f"  [{span['service']}] {span['operation']}")
            lines.append(f"    Duration: {span['duration_ms']:.1f}ms")
            lines.append(f"    Status: {span['status']}")
            if span.get("error"):
                lines.append(f"    Error: {span['error']}")

        reward = 0.05 if target in self._scenario_config.get("affected_services", []) else 0.01
        return "\n".join(lines), reward

    def _format_deploys(self, target: str, tool_data: dict[str, Any]) -> tuple[str, float]:
        """Format deploy history."""
        deploys_data = tool_data.get("deploys", {})
        service_deploys = deploys_data.get(target, {})
        deploys: list[dict[str, Any]] = []

        if isinstance(service_deploys, dict) and service_deploys.get("has_data"):
            deploys = service_deploys.get("recent_deploys", [])
        elif isinstance(service_deploys, list):
            deploys = service_deploys

        # Also check direct deploys_data from external generators
        if not deploys:
            direct_deploys = self._scenario_config.get("deploys_data", {})
            svc_deploys = direct_deploys.get(target, [])
            if isinstance(svc_deploys, list):
                deploys = svc_deploys

        if not deploys:
            return f"No recent deploys for {target}.", 0.0

        lines = [f"=== Recent Deploys for {target} ==="]
        for deploy in deploys:
            lines.append(f"Deploy ID: {deploy.get('deploy_id', 'N/A')}")
            lines.append(f"  Timestamp: {deploy.get('timestamp', 'N/A')}")
            lines.append(f"  Version: {deploy.get('version', 'N/A')}")
            lines.append(f"  Author: {deploy.get('author', 'N/A')}")
            lines.append(f"  Changes: {deploy.get('change_summary', deploy.get('changes', 'N/A'))}")
            lines.append("")

        reward = 0.03 if target in self._scenario_config.get("affected_services", []) else 0.01
        return "\n".join(lines), reward

    def _format_config(self, target: str, tool_data: dict[str, Any]) -> tuple[str, float]:
        """Format config data."""
        config_data = tool_data.get("config", {})
        service_config = config_data.get(target, {})

        if not service_config.get("has_data"):
            return f"No config data for {target}.", 0.0

        current = service_config.get("current_config", {})
        lines = [f"=== Configuration for {target} ==="]
        for key, value in current.items():
            lines.append(f"{key}: {value}")

        return "\n".join(lines), 0.02

    def _format_dependencies(self, target: str) -> str:
        """Show service dependency graph."""
        if target:
            deps = self._service_graph.get_dependencies(target)
            dependents = self._service_graph.get_dependents(target)
            lines = [f"=== Dependencies for {target} ==="]
            lines.append(f"Depends on: {', '.join(deps) if deps else 'None'}")
            lines.append(f"Depended by: {', '.join(dependents) if dependents else 'None'}")
        else:
            lines = ["=== Service Dependency Graph ==="]
            for svc in self._service_graph.get_all_services():
                deps = self._service_graph.get_dependencies(svc.name)
                if deps:
                    lines.append(f"{svc.name} -> {', '.join(deps)}")
                else:
                    lines.append(f"{svc.name} (no dependencies)")

        return "\n".join(lines)

    def _format_alerts_list(self) -> str:
        """Format all current alerts."""
        alerts = self._scenario_config.get("alerts", [])
        if not alerts:
            return "No active alerts."

        lines = ["=== Active Alerts ==="]
        for alert in alerts:
            lines.append(f"[{alert['severity'].value}] {alert['alert_id']}: {alert['title']}")
            lines.append(f"  Service: {alert['service']}")
            lines.append(f"  {alert['description']}")
            lines.append(f"  Time: {alert['timestamp']}")
            lines.append("")

        return "\n".join(lines)
