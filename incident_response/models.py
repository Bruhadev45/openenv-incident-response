"""
Pydantic models for the SRE Incident Response environment.

Defines the typed contracts for Action, Observation, and State that form
the core OpenEnv interface. All communication between client and server
uses these models for type-safe serialization.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Incident severity levels following industry-standard P1-P4 scale."""

    P1 = "P1"  # Critical — full outage, all users affected, immediate response
    P2 = "P2"  # High — major feature broken, many users impacted
    P3 = "P3"  # Medium — partial loss, workarounds exist
    P4 = "P4"  # Low — minor issue, cosmetic, minimal impact


class ActionType(str, Enum):
    """Types of actions the agent can take during incident response."""

    INVESTIGATE = "investigate"
    DIAGNOSE = "diagnose"
    REMEDIATE = "remediate"
    ESCALATE = "escalate"
    COMMUNICATE = "communicate"
    CLASSIFY = "classify"
    ACKNOWLEDGE = "acknowledge"


class InvestigateTool(str, Enum):
    """Diagnostic tools available for investigation."""

    LOGS = "logs"
    METRICS = "metrics"
    TRACES = "traces"
    DEPLOYS = "deploys"
    CONFIG = "config"
    DEPENDENCIES = "dependencies"
    ALERTS = "alerts"


class RemediationAction(str, Enum):
    """Available remediation actions an agent can execute."""

    ROLLBACK = "rollback"
    RESTART = "restart"
    SCALE_UP = "scale_up"
    DRAIN_TRAFFIC = "drain_traffic"
    FAILOVER = "failover"
    TOGGLE_FLAG = "toggle_flag"
    CLEAR_CACHE = "clear_cache"


class ServiceStatus(str, Enum):
    """Health status of a service."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    DOWN = "down"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class Alert(BaseModel):
    """A monitoring alert from the observability stack."""

    alert_id: str
    service: str
    severity: Severity
    title: str
    description: str
    timestamp: str
    labels: dict[str, str] = Field(default_factory=dict)
    acknowledged: bool = False


class ServiceHealth(BaseModel):
    """Health snapshot for a single service."""

    name: str
    status: ServiceStatus = ServiceStatus.HEALTHY
    error_rate: float = 0.001
    latency_p99_ms: float = 100.0
    request_rate_rps: float = 1000.0
    cpu_percent: float = 25.0
    memory_percent: float = 40.0
    last_deploy: Optional[str] = None


class TimelineEvent(BaseModel):
    """An event in the incident timeline."""

    timestamp: str
    event_type: str
    description: str
    actor: str  # "agent", "system", "monitor"
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Core OpenEnv models
# ---------------------------------------------------------------------------


class IncidentAction(BaseModel):
    """
    Action that an agent submits to the environment each step.

    The agent must set `action_type` and then fill in the relevant fields
    for that action type. Irrelevant fields are ignored.
    """

    action_type: ActionType = Field(..., description="The type of action to perform")

    # Common
    target: str = Field(default="", description="Target service or resource name")

    # investigate
    tool: Optional[str] = Field(
        default=None,
        description="Diagnostic tool to use (logs, metrics, traces, deploys, config, dependencies, alerts)",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific parameters (e.g. time_range, filter, service)",
    )

    # diagnose
    root_cause: Optional[str] = Field(
        default=None,
        description="Proposed root cause identifier or description",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence in diagnosis (0.0-1.0)",
    )

    # classify
    severity: Optional[Severity] = Field(
        default=None,
        description="Incident severity classification (P1-P4)",
    )

    # remediate
    remediation: Optional[str] = Field(
        default=None,
        description="Remediation action (rollback, restart, scale_up, drain_traffic, failover, toggle_flag, clear_cache)",
    )

    # communicate
    message: Optional[str] = Field(
        default=None,
        description="Status update message to post",
    )


class IncidentObservation(BaseModel):
    """
    Observation returned to the agent after each step.

    Contains everything the agent can see: alerts, investigation results,
    system status, timeline, and feedback on its last action.
    """

    # Alerts
    alerts: list[Alert] = Field(default_factory=list, description="Active alerts")

    # Investigation output
    investigation_result: str = Field(
        default="", description="Text result from the last investigation action"
    )

    # System overview
    system_status: list[ServiceHealth] = Field(
        default_factory=list, description="Health of all services"
    )

    # Timeline
    timeline: list[TimelineEvent] = Field(
        default_factory=list, description="Chronological event log"
    )

    # Guidance
    available_actions: list[str] = Field(
        default_factory=list, description="Valid action types in current state"
    )
    feedback: str = Field(default="", description="Feedback on the last action")

    # Task info
    task_id: str = Field(default="", description="Current task identifier")
    task_description: str = Field(default="", description="What the agent should do")

    # OpenEnv standard fields
    done: bool = Field(default=False, description="Whether the episode is over")
    reward: float = Field(default=0.0, description="Reward for this step")

    # Step metadata
    step_number: int = Field(default=0, description="Current step number")
    max_steps: int = Field(default=20, description="Maximum steps for this task")


class IncidentState(BaseModel):
    """
    Internal state of the environment, returned by state().

    Includes both visible tracking info and hidden ground-truth used by graders.
    """

    # Episode tracking
    episode_id: str = ""
    step_count: int = 0
    task_id: str = ""
    task_type: str = ""  # "triage", "rca", "cascading"
    max_steps: int = 20

    # Incident tracking
    incident_id: str = ""
    acknowledged: bool = False
    severity_classified: Optional[Severity] = None
    root_cause_identified: Optional[str] = None
    remediations_applied: list[str] = Field(default_factory=list)
    status_updates: list[str] = Field(default_factory=list)

    # Scoring flags
    classification_correct: bool = False
    root_cause_correct: bool = False
    remediation_correct: bool = False
    services_fixed: list[str] = Field(default_factory=list)

    # Efficiency tracking
    investigation_steps: int = 0
    wasted_steps: int = 0
    useful_investigations: list[str] = Field(default_factory=list)

    # Timeline
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # Episode status
    done: bool = False
    total_reward: float = 0.0

    # Ground truth (used by graders, not exposed to agent in observations)
    ground_truth_root_cause: str = ""
    ground_truth_severity: Optional[Severity] = None
    ground_truth_affected_services: list[str] = Field(default_factory=list)
    ground_truth_remediations: list[str] = Field(default_factory=list)
    ground_truth_primary_service: str = ""
