"""
Alert triage scenario generator.

Generates easy difficulty scenarios where agents must classify severity
and acknowledge alerts for a single service incident.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from .base import (
    Difficulty,
    RootCause,
    ScenarioConfig,
    ScenarioGenerator,
    TRIAGE_ROOT_CAUSES,
)
from .service_graph import ServiceGraph


class AlertTriageGenerator(ScenarioGenerator):
    """
    Generates easy triage scenarios for single-service incidents.

    The agent sees alerts for a SINGLE service and must:
    1. Classify the severity correctly
    2. Acknowledge the alert

    No red herrings are included to keep the task straightforward.
    """

    def __init__(self) -> None:
        self._base_time = datetime(2024, 1, 15, 10, 30, 0)

    def get_task_description(self) -> str:
        return (
            "ALERT TRIAGE: Review the active alerts for the affected service. "
            "Classify the incident severity (P1-P4) and acknowledge the alerts. "
            "Use the classify action to set severity and acknowledge action to confirm."
        )

    def generate(self, seed: int) -> ScenarioConfig:
        """Generate a triage scenario with deterministic randomness."""
        rng = random.Random(seed)

        # Select root cause
        root_cause = rng.choice(TRIAGE_ROOT_CAUSES)

        # Create service graph
        service_graph = ServiceGraph.create_ecommerce()

        # Determine severity based on service criticality
        severity = self._determine_severity(root_cause, rng)

        # Generate alerts (2-4 clear alerts for the single service)
        num_alerts = rng.randint(2, 4)
        alerts = self._generate_alerts(root_cause, severity, num_alerts, rng)

        # Generate matching logs
        logs_data = self._generate_logs(root_cause, rng)

        # Generate matching metrics
        metrics_data = self._generate_metrics(root_cause, service_graph, rng)

        # Generate deploy data if relevant
        deploys_data = self._generate_deploys(root_cause, rng)

        task_id = f"triage-{seed:04d}"

        return ScenarioConfig(
            seed=seed,
            task_id=task_id,
            difficulty=Difficulty.EASY,
            root_cause=root_cause,
            severity=severity,
            service_graph=service_graph,
            affected_services=[root_cause.service],
            max_steps=10,
            logs_data=logs_data,
            metrics_data=metrics_data,
            traces_data={},
            deploys_data=deploys_data,
            alerts=alerts,
        )

    def _determine_severity(self, root_cause: RootCause, rng: random.Random) -> str:
        """Determine incident severity based on root cause characteristics."""
        critical_services = {"api-gateway", "auth-service", "auth-db", "redis"}
        high_services = {"order-service", "order-db", "user-service"}

        if root_cause.service in critical_services:
            # Critical services are usually P1 or P2
            return rng.choice(["P1", "P1", "P2"])
        elif root_cause.service in high_services:
            return rng.choice(["P2", "P2", "P3"])
        else:
            return rng.choice(["P3", "P3", "P4"])

    def _generate_alerts(
        self, root_cause: RootCause, severity: str, num_alerts: int, rng: random.Random
    ) -> list[dict[str, Any]]:
        """Generate clear alerts for the affected service."""
        alerts: list[dict[str, Any]] = []

        # Define alert templates based on root cause
        alert_templates = self._get_alert_templates(root_cause)

        # Shuffle and select
        rng.shuffle(alert_templates)
        selected_templates = alert_templates[:num_alerts]

        for i, template in enumerate(selected_templates):
            alert_time = self._base_time - timedelta(minutes=rng.randint(1, 15))
            alerts.append(
                {
                    "alert_id": f"alert-{root_cause.service}-{i:03d}",
                    "service": root_cause.service,
                    "severity": severity,
                    "title": template["title"],
                    "description": template["description"],
                    "timestamp": alert_time.isoformat() + "Z",
                    "labels": {
                        "service": root_cause.service,
                        "env": "production",
                        "region": "us-east-1",
                    },
                    "acknowledged": False,
                }
            )

        return alerts

    def _get_alert_templates(self, root_cause: RootCause) -> list[dict[str, str]]:
        """Get alert templates based on root cause type."""
        templates: dict[str, list[dict[str, str]]] = {
            "bad_deploy_api": [
                {
                    "title": "High Error Rate - api-gateway",
                    "description": "5xx error rate exceeded 5% threshold (current: 23.4%)",
                },
                {
                    "title": "Request Success Rate Critical",
                    "description": "Success rate dropped below 80% on api-gateway",
                },
                {
                    "title": "Unhandled Exception Spike",
                    "description": "NullPointerException count exceeded 100/min on api-gateway",
                },
                {
                    "title": "API Gateway Health Check Failing",
                    "description": "Health endpoint returning 500 errors",
                },
            ],
            "db_connection_pool_exhausted": [
                {
                    "title": "Connection Pool Exhausted - user-db",
                    "description": "Active connections: 100/100, waiting queue: 47",
                },
                {
                    "title": "Database Query Timeout",
                    "description": "Query timeout rate exceeded 10% on user-db",
                },
                {
                    "title": "High Latency - user-service",
                    "description": "P99 latency: 28,450ms (threshold: 1000ms)",
                },
                {
                    "title": "Service Degraded - user-service",
                    "description": "Error rate elevated, response times critical",
                },
            ],
            "redis_oom": [
                {
                    "title": "Redis Memory Critical",
                    "description": "Memory usage at 99.8%, OOM imminent",
                },
                {
                    "title": "Cache Eviction Failures",
                    "description": "Redis unable to evict keys, all writes failing",
                },
                {
                    "title": "auth-service Cache Miss Rate High",
                    "description": "Cache miss rate: 94% (baseline: 5%)",
                },
                {
                    "title": "Redis Command Failures",
                    "description": "SET commands failing with OOM error",
                },
            ],
            "cert_expiry": [
                {
                    "title": "TLS Handshake Failures - auth-service",
                    "description": "SSL handshake failure rate: 100%",
                },
                {
                    "title": "Certificate Expired",
                    "description": "auth-service certificate expired 2 hours ago",
                },
                {
                    "title": "Service Unavailable - auth-service",
                    "description": "All requests returning 503",
                },
                {
                    "title": "Downstream Auth Failures",
                    "description": "api-gateway cannot connect to auth-service",
                },
            ],
            "config_drift": [
                {
                    "title": "Database Connection Errors - order-service",
                    "description": "Connection refused to database endpoint",
                },
                {
                    "title": "Order Service Health Critical",
                    "description": "Health check failing - database unreachable",
                },
                {
                    "title": "Configuration Mismatch Detected",
                    "description": "order-service database host does not match expected value",
                },
                {
                    "title": "Zero Traffic to order-db",
                    "description": "order-db receiving no queries despite order-service activity",
                },
            ],
            "disk_pressure": [
                {
                    "title": "Disk Space Critical - auth-db",
                    "description": "Disk usage: 99.2%, only 800MB remaining",
                },
                {
                    "title": "Write Failures - auth-db",
                    "description": "Transaction log writes failing, disk full",
                },
                {
                    "title": "auth-db Degraded",
                    "description": "Read-only mode activated due to disk pressure",
                },
                {
                    "title": "User Registration Failures",
                    "description": "New user creation failing with database error",
                },
            ],
        }

        return templates.get(
            root_cause.id,
            [
                {
                    "title": f"Service Alert - {root_cause.service}",
                    "description": root_cause.symptoms[0]
                    if root_cause.symptoms
                    else "Service experiencing issues",
                }
            ],
        )

    def _generate_logs(
        self, root_cause: RootCause, rng: random.Random
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate realistic log entries for the affected service."""
        logs: dict[str, list[dict[str, Any]]] = {}
        service = root_cause.service

        log_entries: list[dict[str, Any]] = []

        # Generate 15-25 log entries over the past 30 minutes
        num_entries = rng.randint(15, 25)

        for i in range(num_entries):
            log_time = self._base_time - timedelta(
                minutes=rng.randint(0, 30), seconds=rng.randint(0, 59)
            )

            # Mix of normal and error logs, weighted toward errors
            if rng.random() < 0.7:  # 70% error logs
                entry = self._generate_error_log(root_cause, log_time, rng)
            else:
                entry = self._generate_normal_log(service, log_time, rng)

            log_entries.append(entry)

        # Sort by timestamp
        log_entries.sort(key=lambda x: x["timestamp"])
        logs[service] = log_entries

        return logs

    def _generate_error_log(
        self, root_cause: RootCause, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate an error log entry based on root cause."""
        error_messages: dict[str, list[str]] = {
            "bad_deploy_api": [
                "java.lang.NullPointerException: Cannot invoke method on null object",
                "ERROR RequestHandler: Failed to parse request body",
                "FATAL Unhandled exception in request pipeline",
                "ERROR Response status: 500, path: /api/v1/resource",
            ],
            "db_connection_pool_exhausted": [
                "ERROR ConnectionPool: Cannot acquire connection, pool exhausted",
                "WARN ConnectionPool: Waiting for available connection (queue: 47)",
                "ERROR Query timeout after 30000ms",
                "ERROR HikariPool: Connection is not available, request timed out",
            ],
            "redis_oom": [
                "ERROR Redis: OOM command not allowed when used memory > 'maxmemory'",
                "WARN Cache: Failed to set key, Redis memory limit reached",
                "ERROR RedisClient: Command SET failed with OOM error",
                "ERROR Cache eviction failed, no keys to evict",
            ],
            "cert_expiry": [
                "ERROR SSL: Certificate has expired",
                "ERROR TLS handshake failed: certificate verify failed",
                "FATAL Cannot establish secure connection: CERT_HAS_EXPIRED",
                "ERROR mTLS: Peer certificate validation failed",
            ],
            "config_drift": [
                "ERROR Database: Connection refused to db-prod-wrong.internal:5432",
                "ERROR Config mismatch: Expected host db-prod.internal, got db-prod-wrong.internal",
                "FATAL Cannot initialize database pool: connection refused",
                "ERROR HealthCheck: Database connectivity check failed",
            ],
            "disk_pressure": [
                "ERROR PostgreSQL: could not extend file, No space left on device",
                "FATAL Transaction log: cannot write, disk full",
                "ERROR Checkpoint failed: disk space exhausted",
                "WARN Tablespace: approaching maximum capacity",
            ],
        }

        messages = error_messages.get(
            root_cause.id, [f"ERROR Service error on {root_cause.service}"]
        )

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["ERROR", "ERROR", "ERROR", "FATAL", "WARN"]),
            "service": root_cause.service,
            "message": rng.choice(messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
        }

    def _generate_normal_log(
        self, service: str, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate a normal operational log entry."""
        normal_messages = [
            "INFO Request completed successfully",
            "DEBUG Processing request",
            "INFO Health check passed",
            "DEBUG Cache hit for key",
            "INFO Connection established",
        ]

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["INFO", "DEBUG"]),
            "service": service,
            "message": rng.choice(normal_messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
        }

    def _generate_metrics(
        self, root_cause: RootCause, service_graph: ServiceGraph, rng: random.Random
    ) -> dict[str, dict[str, Any]]:
        """Generate metrics showing clear anomalies for affected service."""
        metrics: dict[str, dict[str, Any]] = {}

        # Get baseline for the affected service
        affected_service = service_graph.get_service(root_cause.service)

        if affected_service:
            baseline = affected_service.baseline_metrics

            # Generate anomalous metrics for affected service
            metrics[root_cause.service] = self._generate_anomalous_metrics(
                root_cause, baseline, rng
            )

        # Generate normal metrics for a few other services
        other_services = [
            s
            for s in service_graph.get_service_names()
            if s != root_cause.service
        ]
        rng.shuffle(other_services)

        for svc_name in other_services[:3]:
            svc = service_graph.get_service(svc_name)
            if svc:
                metrics[svc_name] = self._generate_normal_metrics(
                    svc.baseline_metrics, rng
                )

        return metrics

    def _generate_anomalous_metrics(
        self, root_cause: RootCause, baseline: Any, rng: random.Random
    ) -> dict[str, Any]:
        """Generate metrics showing clear problems."""
        metrics: dict[str, Any] = {
            "error_rate": baseline.error_rate,
            "latency_p99_ms": baseline.latency_p99_ms,
            "request_rate": baseline.request_rate,
            "cpu_percent": rng.uniform(20, 40),
            "memory_percent": rng.uniform(30, 50),
        }

        # Adjust based on root cause
        if root_cause.id == "bad_deploy_api":
            metrics["error_rate"] = rng.uniform(0.15, 0.30)
            metrics["latency_p99_ms"] = baseline.latency_p99_ms * rng.uniform(2, 4)

        elif root_cause.id == "db_connection_pool_exhausted":
            metrics["error_rate"] = rng.uniform(0.20, 0.40)
            metrics["latency_p99_ms"] = rng.uniform(25000, 35000)
            metrics["active_connections"] = 100
            metrics["connection_pool_size"] = 100

        elif root_cause.id == "redis_oom":
            metrics["memory_percent"] = rng.uniform(98, 100)
            metrics["error_rate"] = rng.uniform(0.30, 0.50)
            metrics["cache_hit_rate"] = rng.uniform(0.02, 0.08)

        elif root_cause.id == "cert_expiry":
            metrics["error_rate"] = 1.0  # All requests failing
            metrics["ssl_handshake_failures"] = rng.randint(500, 1000)

        elif root_cause.id == "config_drift":
            metrics["error_rate"] = rng.uniform(0.80, 1.0)
            metrics["db_connection_errors"] = rng.randint(100, 200)

        elif root_cause.id == "disk_pressure":
            metrics["disk_usage_percent"] = rng.uniform(98, 100)
            metrics["write_errors"] = rng.randint(50, 150)
            metrics["error_rate"] = rng.uniform(0.10, 0.25)

        return metrics

    def _generate_normal_metrics(
        self, baseline: Any, rng: random.Random
    ) -> dict[str, Any]:
        """Generate normal baseline metrics with slight variance."""
        return {
            "error_rate": baseline.error_rate * rng.uniform(0.8, 1.2),
            "latency_p99_ms": baseline.latency_p99_ms * rng.uniform(0.9, 1.1),
            "request_rate": baseline.request_rate * rng.uniform(0.95, 1.05),
            "cpu_percent": rng.uniform(15, 35),
            "memory_percent": rng.uniform(30, 50),
        }

    def _generate_deploys(
        self, root_cause: RootCause, rng: random.Random
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate deployment history if relevant to root cause."""
        deploys: dict[str, list[dict[str, Any]]] = {}

        if root_cause.category.value == "deployment":
            # Recent problematic deploy
            deploy_time = self._base_time - timedelta(minutes=rng.randint(5, 20))
            deploys[root_cause.service] = [
                {
                    "deploy_id": f"deploy-{rng.randint(10000, 99999)}",
                    "service": root_cause.service,
                    "version": f"v2.{rng.randint(10, 50)}.{rng.randint(0, 9)}",
                    "timestamp": deploy_time.isoformat() + "Z",
                    "deployed_by": rng.choice(
                        ["jenkins-ci", "github-actions", "argocd"]
                    ),
                    "status": "completed",
                    "commit_sha": f"{rng.randint(0, 0xFFFFFFFF):08x}",
                    "change_description": "Feature update and bug fixes",
                },
                {
                    "deploy_id": f"deploy-{rng.randint(10000, 99999)}",
                    "service": root_cause.service,
                    "version": f"v2.{rng.randint(5, 9)}.{rng.randint(0, 9)}",
                    "timestamp": (self._base_time - timedelta(days=2)).isoformat() + "Z",
                    "deployed_by": "jenkins-ci",
                    "status": "completed",
                    "commit_sha": f"{rng.randint(0, 0xFFFFFFFF):08x}",
                    "change_description": "Dependency updates",
                },
            ]

        return deploys
