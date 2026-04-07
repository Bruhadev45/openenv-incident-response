"""
Base classes and root cause definitions for scenario generation.

Defines the abstract interface for scenario generators and provides
pre-built banks of root causes for different difficulty levels.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .service_graph import ServiceGraph


class RootCauseCategory(str, Enum):
    """Categories of root causes for incidents."""

    DEPLOYMENT = "deployment"
    INFRASTRUCTURE = "infrastructure"
    TRAFFIC = "traffic"
    DEPENDENCY = "dependency"


class Difficulty(str, Enum):
    """Difficulty levels for scenarios."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass
class RootCause:
    """
    Definition of a root cause for an incident.

    Contains the symptoms that manifest, red herrings that may confuse
    investigation, and the correct remediation steps.
    """

    id: str
    service: str
    category: RootCauseCategory
    description: str
    symptoms: list[str] = field(default_factory=list)
    red_herrings: list[str] = field(default_factory=list)
    remediations: list[str] = field(default_factory=list)


@dataclass
class ScenarioConfig:
    """
    Complete configuration for a generated scenario.

    Contains all the data needed to simulate an incident, including
    the ground truth and all observable diagnostic data.
    """

    seed: int
    task_id: str
    difficulty: Difficulty
    root_cause: RootCause
    severity: str  # "P1", "P2", "P3", "P4"
    service_graph: ServiceGraph
    affected_services: list[str]
    max_steps: int

    # Diagnostic data dictionaries
    logs_data: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    metrics_data: dict[str, dict[str, Any]] = field(default_factory=dict)
    traces_data: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    deploys_data: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    # Alert data
    alerts: list[dict[str, Any]] = field(default_factory=list)


class ScenarioGenerator(ABC):
    """
    Abstract base class for scenario generators.

    Subclasses implement generate() to create fully specified scenarios
    with deterministic behavior based on the provided seed.
    """

    @abstractmethod
    def generate(self, seed: int) -> ScenarioConfig:
        """
        Generate a complete scenario configuration.

        Args:
            seed: Random seed for deterministic generation

        Returns:
            Fully populated ScenarioConfig
        """
        pass

    @abstractmethod
    def get_task_description(self) -> str:
        """
        Get a human-readable description of the task type.

        Returns:
            Description string explaining what the agent should do
        """
        pass


# ---------------------------------------------------------------------------
# Root Cause Banks
# ---------------------------------------------------------------------------

TRIAGE_ROOT_CAUSES: list[RootCause] = [
    RootCause(
        id="bad_deploy_api",
        service="api-gateway",
        category=RootCauseCategory.DEPLOYMENT,
        description="Bad deployment to api-gateway introduced a null pointer exception in request parsing",
        symptoms=[
            "High 5xx error rate on api-gateway",
            "NullPointerException in api-gateway logs",
            "Recent deployment to api-gateway (10 minutes ago)",
            "Error rate spike correlates with deploy timestamp",
        ],
        red_herrings=[],
        remediations=["rollback"],
    ),
    RootCause(
        id="db_connection_pool_exhausted",
        service="user-db",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="Database connection pool exhausted due to connection leak in user-service",
        symptoms=[
            "Connection timeout errors in user-service logs",
            "user-db showing max_connections reached",
            "user-service latency p99 spiking to 30s",
            "Gradually increasing active connections over past hour",
        ],
        red_herrings=[],
        remediations=["restart"],
    ),
    RootCause(
        id="redis_oom",
        service="redis",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="Redis out of memory due to unbounded cache growth",
        symptoms=[
            "Redis OOM errors in logs",
            "Memory usage at 100%",
            "Cache eviction failures",
            "auth-service latency increase due to cache misses",
        ],
        red_herrings=[],
        remediations=["clear_cache", "restart"],
    ),
    RootCause(
        id="cert_expiry",
        service="auth-service",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="TLS certificate expired for auth-service internal communication",
        symptoms=[
            "SSL handshake failures in auth-service logs",
            "Certificate expired error messages",
            "All auth requests failing with 503",
            "No recent deployments",
        ],
        red_herrings=[],
        remediations=["restart"],  # Triggers cert renewal
    ),
    RootCause(
        id="config_drift",
        service="order-service",
        category=RootCauseCategory.DEPLOYMENT,
        description="Configuration drift caused order-service to connect to wrong database endpoint",
        symptoms=[
            "Database connection errors in order-service",
            "Config shows unexpected database host",
            "Recent config change in deployment manifest",
            "order-db healthy but receiving no traffic",
        ],
        red_herrings=[],
        remediations=["rollback"],
    ),
    RootCause(
        id="disk_pressure",
        service="auth-db",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="Disk space exhausted on auth-db causing write failures",
        symptoms=[
            "Disk usage at 99% on auth-db",
            "Write failures in auth-db logs",
            "Transaction log cannot grow",
            "New user registrations failing",
        ],
        red_herrings=[],
        remediations=["scale_up"],
    ),
]

RCA_ROOT_CAUSES: list[RootCause] = [
    RootCause(
        id="auth_service_bad_deploy",
        service="auth-service",
        category=RootCauseCategory.DEPLOYMENT,
        description="Bad deployment introduced infinite loop in token validation",
        symptoms=[
            "CPU at 100% on auth-service pods",
            "Request timeout errors across frontend and api-gateway",
            "Recent deployment to auth-service",
            "Thread dump shows spinning in TokenValidator.validate()",
        ],
        red_herrings=[
            "Redis showing slightly elevated latency (caused by auth-service hammering)",
            "api-gateway error rate elevated (downstream effect)",
        ],
        remediations=["rollback"],
    ),
    RootCause(
        id="kafka_partition_imbalance",
        service="kafka",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="Kafka partition leader imbalance causing order processing delays",
        symptoms=[
            "Consumer lag increasing on order-events topic",
            "Uneven partition distribution in Kafka metrics",
            "order-worker processing latency spiking",
            "One broker handling 80% of traffic",
        ],
        red_herrings=[
            "warehouse-api showing timeouts (backpressure from worker)",
            "order-db CPU elevated (unrelated batch job)",
        ],
        remediations=["restart"],  # Triggers rebalance
    ),
    RootCause(
        id="memory_leak_user_service",
        service="user-service",
        category=RootCauseCategory.DEPLOYMENT,
        description="Memory leak in user-service caused by unclosed database cursors",
        symptoms=[
            "Gradual memory increase in user-service over 6 hours",
            "user-service pods restarting due to OOMKilled",
            "Heap dump shows DbCursor objects not finalized",
            "Deploy 6 hours ago introduced new query pattern",
        ],
        red_herrings=[
            "user-db showing connection churn (symptom not cause)",
            "GC pause times elevated (symptom of memory pressure)",
        ],
        remediations=["rollback", "restart"],
    ),
    RootCause(
        id="dns_resolution_failure",
        service="order-service",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="DNS resolution intermittently failing for order-db hostname",
        symptoms=[
            "UnknownHostException for order-db in order-service logs",
            "Intermittent 5xx errors on order endpoints",
            "DNS TTL recently changed",
            "order-db is healthy and reachable by IP",
        ],
        red_herrings=[
            "kafka consumer lag increasing (downstream effect)",
            "order-worker errors (caused by order-service failures)",
        ],
        remediations=["restart"],  # Forces DNS cache refresh
    ),
    RootCause(
        id="order_db_slow_queries",
        service="order-db",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="Missing index causing full table scans on orders table",
        symptoms=[
            "Slow query log showing 10s+ queries on orders table",
            "order-db CPU at 95%",
            "Query plan shows sequential scan",
            "order-service latency p99 at 15 seconds",
        ],
        red_herrings=[
            "kafka showing consumer lag (backpressure)",
            "frontend showing elevated error rate (timeout cascade)",
        ],
        remediations=["scale_up"],  # Short term; index needed long term
    ),
    RootCause(
        id="rate_limit_misconfiguration",
        service="api-gateway",
        category=RootCauseCategory.DEPLOYMENT,
        description="Rate limiter misconfigured to 10 req/s instead of 10000 req/s",
        symptoms=[
            "429 Too Many Requests errors across all endpoints",
            "Rate limit config shows incorrect value",
            "Recent config deployment to api-gateway",
            "Actual traffic well below historical averages",
        ],
        red_herrings=[
            "auth-service showing reduced traffic (caused by rate limiting)",
            "order-service latency improved (less traffic)",
        ],
        remediations=["rollback"],
    ),
]

CASCADING_ROOT_CAUSES: list[RootCause] = [
    RootCause(
        id="order_db_disk_full",
        service="order-db",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="order-db disk filled up causing cascading failures through order processing pipeline",
        symptoms=[
            "order-db: Disk 100% full, all writes failing",
            "order-service: SQLException on all write operations",
            "kafka: Messages rejected, producer buffer full",
            "order-worker: Stalled, no new messages to process",
            "api-gateway: Elevated 5xx on /orders/* endpoints",
            "frontend: Order submission failing for all users",
        ],
        red_herrings=[
            "redis memory slightly elevated (unrelated cache growth)",
            "auth-service had a deploy yesterday (unrelated, working fine)",
            "user-db showing minor slow queries (normal operation)",
        ],
        remediations=["scale_up", "drain_traffic"],
    ),
    RootCause(
        id="redis_cluster_split",
        service="redis",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="Redis cluster split brain causing auth failures and session inconsistencies",
        symptoms=[
            "redis: Cluster state FAIL, nodes disagree on leader",
            "auth-service: Session validation failures, inconsistent reads",
            "api-gateway: 50% of requests failing auth",
            "frontend: Users randomly logged out",
            "user-service: Profile updates not persisting",
        ],
        red_herrings=[
            "order-db had minor checkpoint delay (normal operation)",
            "kafka broker metrics show leader elections (normal)",
            "warehouse-api latency slightly elevated (external factor)",
        ],
        remediations=["failover", "restart"],
    ),
    RootCause(
        id="auth_db_failover_loop",
        service="auth-db",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="auth-db stuck in failover loop causing complete authentication outage",
        symptoms=[
            "auth-db: Primary/replica switching every 30 seconds",
            "auth-service: Connection reset errors, cannot establish stable connection",
            "api-gateway: All authenticated endpoints returning 503",
            "frontend: Login page showing service unavailable",
            "redis: Auth tokens being invalidated repeatedly",
        ],
        red_herrings=[
            "user-service memory usage increased (cached data for failed auths)",
            "order-service queue depth elevated (orders can't complete)",
            "kafka consumer lag (downstream effect of no new orders)",
        ],
        remediations=["drain_traffic", "failover"],
    ),
    RootCause(
        id="network_partition",
        service="api-gateway",
        category=RootCauseCategory.INFRASTRUCTURE,
        description="Network partition isolated api-gateway from backend services",
        symptoms=[
            "api-gateway: Connection refused to all backend services",
            "auth-service: No incoming traffic despite frontend requests",
            "user-service: Health checks failing from load balancer",
            "order-service: Zero requests per second",
            "frontend: All API calls timing out after 30s",
        ],
        red_herrings=[
            "All database services showing healthy metrics",
            "kafka operating normally with no new messages",
            "redis cluster healthy but idle",
        ],
        remediations=["restart", "failover"],
    ),
]
