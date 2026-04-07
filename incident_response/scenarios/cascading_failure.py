"""
Cascading failure scenario generator.

Generates hard difficulty scenarios where agents must handle multiple
services failing in cascade, prioritize remediation, and restore services
in the correct order.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from .base import (
    Difficulty,
    RootCause,
    RootCauseCategory,
    ScenarioConfig,
    ScenarioGenerator,
    CASCADING_ROOT_CAUSES,
)
from .service_graph import ServiceGraph


class CascadingFailureGenerator(ScenarioGenerator):
    """
    Generates hard difficulty cascading failure scenarios.

    The agent must:
    1. Investigate widespread failures across 4-6+ services
    2. Filter out red herrings and noise
    3. Identify the root cause amidst cascading symptoms
    4. Prioritize and remediate services in the correct order
    5. Verify recovery of dependent services

    Includes extensive red herrings and diagnostic data.
    """

    def __init__(self) -> None:
        self._base_time = datetime(2024, 1, 15, 3, 15, 0)  # 3 AM - typical incident time

    def get_task_description(self) -> str:
        return (
            "CASCADING FAILURE: A critical incident is causing widespread service failures. "
            "Multiple services are affected with cascading symptoms. "
            "Investigate thoroughly using all available tools (logs, metrics, traces, deploys, dependencies). "
            "Identify the root cause, filter out misleading signals, and apply remediations "
            "in the correct priority order to restore services. "
            "Monitor recovery and verify dependent services are restored."
        )

    def generate(self, seed: int) -> ScenarioConfig:
        """Generate a cascading failure scenario with deterministic randomness."""
        rng = random.Random(seed)

        # Select root cause
        root_cause = rng.choice(CASCADING_ROOT_CAUSES)

        # Create service graph
        service_graph = ServiceGraph.create_ecommerce()

        # Use service graph to propagate failure
        failure_type = self._get_failure_type(root_cause)
        cascade_impact = service_graph.propagate_failure(root_cause.service, failure_type)

        # Determine all affected services (4-6 minimum)
        affected_services = self._determine_affected_services(
            root_cause, cascade_impact, service_graph, rng
        )

        # Severity is always P1 for cascading failures
        severity = "P1"

        # Generate comprehensive alerts for all affected services
        alerts = self._generate_alerts(
            root_cause, affected_services, cascade_impact, severity, rng
        )

        # Add multiple red herring alerts (2-3)
        red_herring_alerts = self._generate_red_herring_alerts(
            affected_services, service_graph, rng
        )
        alerts.extend(red_herring_alerts)

        # Shuffle to mix real and red herrings
        rng.shuffle(alerts)

        # Generate extensive diagnostic data
        logs_data = self._generate_logs(root_cause, affected_services, cascade_impact, rng)
        metrics_data = self._generate_metrics(
            root_cause, affected_services, cascade_impact, service_graph, rng
        )
        traces_data = self._generate_traces(
            root_cause, affected_services, cascade_impact, rng
        )
        deploys_data = self._generate_deploys(root_cause, service_graph, rng)

        task_id = f"cascade-{seed:04d}"

        return ScenarioConfig(
            seed=seed,
            task_id=task_id,
            difficulty=Difficulty.HARD,
            root_cause=root_cause,
            severity=severity,
            service_graph=service_graph,
            affected_services=affected_services,
            max_steps=30,
            logs_data=logs_data,
            metrics_data=metrics_data,
            traces_data=traces_data,
            deploys_data=deploys_data,
            alerts=alerts,
        )

    def _get_failure_type(self, root_cause: RootCause) -> str:
        """Map root cause to failure type for propagation."""
        failure_type_mapping = {
            "order_db_disk_full": "errors",
            "redis_cluster_split": "errors",
            "auth_db_failover_loop": "down",
            "network_partition": "down",
        }
        return failure_type_mapping.get(root_cause.id, "errors")

    def _determine_affected_services(
        self,
        root_cause: RootCause,
        cascade_impact: dict[str, dict[str, float]],
        service_graph: ServiceGraph,
        rng: random.Random,
    ) -> list[str]:
        """Determine all affected services ensuring minimum of 4-6."""
        affected = list(cascade_impact.keys())

        # Ensure we have at least 4 services
        if len(affected) < 4:
            all_services = service_graph.get_service_names()
            remaining = [s for s in all_services if s not in affected]
            rng.shuffle(remaining)

            # Add additional services as "slightly affected"
            while len(affected) < 4 and remaining:
                affected.append(remaining.pop())

        # Sort by distance from root cause (closest first)
        affected.sort(key=lambda s: cascade_impact.get(s, {}).get("distance", 999))

        return affected

    def _generate_alerts(
        self,
        root_cause: RootCause,
        affected_services: list[str],
        cascade_impact: dict[str, dict[str, float]],
        severity: str,
        rng: random.Random,
    ) -> list[dict[str, Any]]:
        """Generate alerts for all affected services."""
        alerts: list[dict[str, Any]] = []

        # Get alert templates
        alert_configs = self._get_alert_configs(root_cause)

        for i, svc in enumerate(affected_services):
            impact = cascade_impact.get(svc, {})
            distance = impact.get("distance", 0)

            # Severity degrades with distance
            if distance == 0:
                svc_severity = "P1"
            elif distance == 1:
                svc_severity = rng.choice(["P1", "P2"])
            else:
                svc_severity = rng.choice(["P2", "P3"])

            # Generate 1-2 alerts per affected service
            num_alerts = 2 if distance == 0 else 1

            for j in range(num_alerts):
                alert_time = self._base_time - timedelta(
                    minutes=rng.randint(1, 20) + (distance * 2)
                )

                title, description = self._get_alert_content(
                    svc, root_cause, alert_configs, distance, rng
                )

                alerts.append(
                    {
                        "alert_id": f"alert-{svc}-{i:03d}-{j}",
                        "service": svc,
                        "severity": svc_severity,
                        "title": title,
                        "description": description,
                        "timestamp": alert_time.isoformat() + "Z",
                        "labels": {
                            "service": svc,
                            "env": "production",
                            "region": "us-east-1",
                            "incident": f"INC-{rng.randint(10000, 99999)}",
                            "team": self._get_team_for_service(svc),
                        },
                        "acknowledged": False,
                    }
                )

        return alerts

    def _get_team_for_service(self, service: str) -> str:
        """Get the owning team for a service."""
        team_mapping = {
            "frontend": "web-team",
            "api-gateway": "platform-team",
            "auth-service": "auth-team",
            "auth-db": "auth-team",
            "redis": "platform-team",
            "user-service": "user-team",
            "user-db": "user-team",
            "order-service": "order-team",
            "order-db": "order-team",
            "kafka": "platform-team",
            "order-worker": "order-team",
            "warehouse-api": "fulfillment-team",
        }
        return team_mapping.get(service, "platform-team")

    def _get_alert_configs(self, root_cause: RootCause) -> dict[str, list[dict[str, str]]]:
        """Get alert configurations for cascading failure scenarios."""
        configs: dict[str, dict[str, list[dict[str, str]]]] = {
            "order_db_disk_full": {
                "order-db": [
                    {"title": "CRITICAL: Disk Full - order-db", "description": "Disk usage 100%, all writes failing"},
                    {"title": "Transaction Log Full - order-db", "description": "WAL cannot grow, database in recovery mode"},
                ],
                "order-service": [
                    {"title": "Database Write Failures - order-service", "description": "All INSERT/UPDATE operations failing"},
                ],
                "kafka": [
                    {"title": "Producer Failures - kafka", "description": "Messages rejected, producer buffer full"},
                ],
                "order-worker": [
                    {"title": "Processing Stalled - order-worker", "description": "No new messages, consumer idle"},
                ],
                "api-gateway": [
                    {"title": "Order Endpoints Down - api-gateway", "description": "/orders/* returning 503"},
                ],
                "frontend": [
                    {"title": "Checkout Failures - frontend", "description": "Order submission failing for all users"},
                ],
            },
            "redis_cluster_split": {
                "redis": [
                    {"title": "CRITICAL: Cluster Split Brain - redis", "description": "Cluster state FAIL, nodes disagree"},
                    {"title": "Data Inconsistency - redis", "description": "Read/write inconsistencies detected"},
                ],
                "auth-service": [
                    {"title": "Session Validation Failures - auth-service", "description": "50% of session lookups failing"},
                ],
                "api-gateway": [
                    {"title": "Auth Failures Spiking - api-gateway", "description": "50% of requests failing auth"},
                ],
                "frontend": [
                    {"title": "User Session Issues - frontend", "description": "Users randomly being logged out"},
                ],
                "user-service": [
                    {"title": "Cache Inconsistency - user-service", "description": "Profile updates not persisting"},
                ],
            },
            "auth_db_failover_loop": {
                "auth-db": [
                    {"title": "CRITICAL: Failover Loop - auth-db", "description": "Primary/replica switching every 30s"},
                    {"title": "Replication Lag Critical - auth-db", "description": "Replication cannot stabilize"},
                ],
                "auth-service": [
                    {"title": "Connection Reset Errors - auth-service", "description": "Stable connection cannot be established"},
                ],
                "api-gateway": [
                    {"title": "Auth Endpoints Down - api-gateway", "description": "All authenticated endpoints 503"},
                ],
                "frontend": [
                    {"title": "Login Unavailable - frontend", "description": "Service unavailable error on login"},
                ],
                "redis": [
                    {"title": "Token Churn - redis", "description": "Auth tokens being invalidated repeatedly"},
                ],
            },
            "network_partition": {
                "api-gateway": [
                    {"title": "CRITICAL: Backend Unreachable - api-gateway", "description": "Connection refused to all backends"},
                    {"title": "Network Partition Detected - api-gateway", "description": "Cannot reach internal services"},
                ],
                "auth-service": [
                    {"title": "No Incoming Traffic - auth-service", "description": "Zero requests despite frontend activity"},
                ],
                "user-service": [
                    {"title": "Health Checks Failing - user-service", "description": "Load balancer health checks timing out"},
                ],
                "order-service": [
                    {"title": "Zero Traffic - order-service", "description": "No requests in last 5 minutes"},
                ],
                "frontend": [
                    {"title": "API Timeouts - frontend", "description": "All API calls timing out after 30s"},
                ],
            },
        }
        return configs.get(root_cause.id, {})

    def _get_alert_content(
        self,
        service: str,
        root_cause: RootCause,
        alert_configs: dict[str, list[dict[str, str]]],
        distance: int,
        rng: random.Random,
    ) -> tuple[str, str]:
        """Get alert title and description for a service."""
        if service in alert_configs:
            configs = alert_configs[service]
            config = rng.choice(configs)
            return config["title"], config["description"]

        # Generic cascade-aware fallback
        if distance == 0:
            templates = [
                (f"CRITICAL: Service Down - {service}", f"Complete failure on {service}"),
                (f"Service Health Critical - {service}", f"All health checks failing on {service}"),
            ]
        elif distance == 1:
            templates = [
                (f"Dependency Failure Impact - {service}", f"Errors due to upstream dependency"),
                (f"High Error Rate - {service}", f"Error rate at {rng.randint(20, 50)}%"),
            ]
        else:
            templates = [
                (f"Elevated Errors - {service}", f"Cascading impact from upstream failures"),
                (f"Degraded Performance - {service}", f"Latency elevated due to upstream issues"),
            ]

        return rng.choice(templates)

    def _generate_red_herring_alerts(
        self,
        affected_services: list[str],
        service_graph: ServiceGraph,
        rng: random.Random,
    ) -> list[dict[str, Any]]:
        """Generate misleading alerts from unrelated services."""
        red_herrings: list[dict[str, Any]] = []

        all_services = service_graph.get_service_names()
        unaffected = [s for s in all_services if s not in affected_services]

        if not unaffected:
            return red_herrings

        # Generate 2-3 red herring alerts
        num_red_herrings = rng.randint(2, 3)
        selected = rng.sample(unaffected, min(num_red_herrings, len(unaffected)))

        red_herring_templates = [
            ("GC Pressure Warning", "Full GC taking 150ms, monitoring"),
            ("Connection Pool Utilization", "Pool at 70% capacity"),
            ("Memory Usage Trend", "Memory slowly increasing, may need attention"),
            ("Disk I/O Latency", "Disk latency spike to 20ms, recovered"),
            ("Thread Pool Warning", "Thread pool at 80% utilization"),
            ("CPU Spike Detected", "Brief CPU spike to 70%, normal now"),
            ("Log Rotation Delayed", "Log rotation took 5 minutes longer than usual"),
        ]

        for i, svc in enumerate(selected):
            alert_time = self._base_time - timedelta(minutes=rng.randint(10, 60))
            template = rng.choice(red_herring_templates)

            red_herrings.append(
                {
                    "alert_id": f"alert-{svc}-rh-{i:03d}",
                    "service": svc,
                    "severity": rng.choice(["P3", "P4"]),
                    "title": f"{template[0]} - {svc}",
                    "description": template[1],
                    "timestamp": alert_time.isoformat() + "Z",
                    "labels": {
                        "service": svc,
                        "env": "production",
                        "region": "us-east-1",
                    },
                    "acknowledged": False,
                }
            )

        return red_herrings

    def _generate_logs(
        self,
        root_cause: RootCause,
        affected_services: list[str],
        cascade_impact: dict[str, dict[str, float]],
        rng: random.Random,
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate extensive logs for all affected services."""
        logs: dict[str, list[dict[str, Any]]] = {}

        for svc in affected_services:
            entries: list[dict[str, Any]] = []
            distance = cascade_impact.get(svc, {}).get("distance", 0)

            # More logs for services closer to root cause
            num_entries = rng.randint(30, 60) if distance < 2 else rng.randint(15, 30)

            for _ in range(num_entries):
                log_time = self._base_time - timedelta(
                    minutes=rng.randint(0, 60), seconds=rng.randint(0, 59)
                )

                if svc == root_cause.service:
                    if rng.random() < 0.7:
                        entry = self._generate_root_cause_log(root_cause, log_time, rng)
                    else:
                        entry = self._generate_normal_log(svc, log_time, rng)
                elif distance == 1:
                    if rng.random() < 0.5:
                        entry = self._generate_direct_impact_log(svc, root_cause, log_time, rng)
                    else:
                        entry = self._generate_normal_log(svc, log_time, rng)
                else:
                    if rng.random() < 0.3:
                        entry = self._generate_cascade_impact_log(svc, log_time, rng)
                    else:
                        entry = self._generate_normal_log(svc, log_time, rng)

                entries.append(entry)

            entries.sort(key=lambda x: x["timestamp"])
            logs[svc] = entries

        return logs

    def _generate_root_cause_log(
        self, root_cause: RootCause, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate log entry showing root cause symptoms."""
        log_messages: dict[str, list[str]] = {
            "order_db_disk_full": [
                "FATAL PostgreSQL: could not extend file 'base/16384/2619': No space left on device",
                "ERROR WAL writer: cannot write to WAL, disk full",
                "FATAL pg_xlog: transaction log cannot grow",
                "ERROR Checkpoint failed: could not write to file, no space left",
                "CRITICAL Tablespace 'pg_default' is full, refusing writes",
            ],
            "redis_cluster_split": [
                "ERROR CLUSTER: Cluster state changed to FAIL",
                "FATAL CLUSTER: Node disagrees about slots ownership",
                "ERROR CLUSTERDOWN: Hash slot not served",
                "WARN CLUSTER: Manual failover requested but multiple masters",
                "ERROR CLUSTER: Unable to achieve quorum for failover",
            ],
            "auth_db_failover_loop": [
                "ERROR pg_hba: Rejecting connection, not primary",
                "FATAL standby: Timeline switch detected, entering recovery",
                "ERROR primary: Lost connection to standby, initiating failover",
                "WARN patroni: Failover initiated, previous primary demoted",
                "ERROR patroni: Multiple nodes claiming primary role",
            ],
            "network_partition": [
                "ERROR TCP: Connection refused to 10.0.1.0/24 network",
                "FATAL gRPC: Deadline exceeded calling backend services",
                "ERROR DNS: Resolution failed for internal hostnames",
                "WARN LoadBalancer: All backend targets unhealthy",
                "ERROR Network: Route to 10.0.1.0/24 unreachable",
            ],
        }

        messages = log_messages.get(root_cause.id, ["FATAL Critical system error"])

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["ERROR", "FATAL", "CRITICAL"]),
            "service": root_cause.service,
            "message": rng.choice(messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
            "host": f"{root_cause.service}-{rng.choice(['01', '02', '03'])}.prod.internal",
        }

    def _generate_direct_impact_log(
        self, service: str, root_cause: RootCause, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate log for service directly impacted by root cause."""
        direct_impact_messages = [
            f"ERROR Connection to {root_cause.service} failed: Connection refused",
            f"FATAL Cannot reach {root_cause.service}, circuit breaker OPEN",
            f"ERROR Timeout waiting for response from {root_cause.service}",
            "ERROR All retry attempts exhausted",
            "FATAL Dependency unavailable, failing request",
            "ERROR Health check failed: upstream dependency unhealthy",
        ]

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["ERROR", "FATAL"]),
            "service": service,
            "message": rng.choice(direct_impact_messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
            "host": f"{service}-{rng.choice(['01', '02', '03'])}.prod.internal",
        }

    def _generate_cascade_impact_log(
        self, service: str, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate log for cascading impact on distant services."""
        cascade_messages = [
            "WARN Elevated error rate detected",
            "ERROR Request failed, upstream service unavailable",
            "WARN Degraded mode: some features unavailable",
            "ERROR 503 from upstream, returning cached response",
            "WARN Circuit breaker preventing cascade",
            "ERROR Response timeout, failing gracefully",
        ]

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["ERROR", "WARN"]),
            "service": service,
            "message": rng.choice(cascade_messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
            "host": f"{service}-{rng.choice(['01', '02', '03'])}.prod.internal",
        }

    def _generate_normal_log(
        self, service: str, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate normal operational log."""
        normal_messages = [
            "INFO Request handled successfully",
            "DEBUG Processing incoming request",
            "INFO Health check passed",
            "DEBUG Metrics exported",
            "INFO Connection pool healthy",
            "DEBUG Cache operation completed",
        ]

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["INFO", "DEBUG"]),
            "service": service,
            "message": rng.choice(normal_messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
            "host": f"{service}-{rng.choice(['01', '02', '03'])}.prod.internal",
        }

    def _generate_metrics(
        self,
        root_cause: RootCause,
        affected_services: list[str],
        cascade_impact: dict[str, dict[str, float]],
        service_graph: ServiceGraph,
        rng: random.Random,
    ) -> dict[str, dict[str, Any]]:
        """Generate comprehensive metrics for all services."""
        metrics: dict[str, dict[str, Any]] = {}

        for svc_name in service_graph.get_service_names():
            svc = service_graph.get_service(svc_name)
            if not svc:
                continue

            baseline = svc.baseline_metrics
            impact = cascade_impact.get(svc_name, {})

            if svc_name == root_cause.service:
                metrics[svc_name] = self._generate_root_cause_metrics(
                    root_cause, baseline, rng
                )
            elif svc_name in affected_services:
                multipliers = {
                    "error_rate": impact.get("error_rate_multiplier", 1.0),
                    "latency": impact.get("latency_multiplier", 1.0),
                }
                metrics[svc_name] = self._generate_cascade_metrics(
                    baseline, multipliers, rng
                )
            else:
                metrics[svc_name] = self._generate_normal_metrics(baseline, rng)

        return metrics

    def _generate_root_cause_metrics(
        self, root_cause: RootCause, baseline: Any, rng: random.Random
    ) -> dict[str, Any]:
        """Generate metrics showing critical failure."""
        metrics: dict[str, Any] = {
            "error_rate": baseline.error_rate,
            "latency_p99_ms": baseline.latency_p99_ms,
            "request_rate": baseline.request_rate,
            "cpu_percent": rng.uniform(20, 40),
            "memory_percent": rng.uniform(30, 50),
            "status": "CRITICAL",
        }

        if root_cause.id == "order_db_disk_full":
            metrics["disk_usage_percent"] = 100.0
            metrics["disk_free_bytes"] = 0
            metrics["write_errors_per_sec"] = rng.randint(100, 500)
            metrics["iops_write"] = 0
            metrics["wal_size_mb"] = rng.randint(10000, 15000)
            metrics["error_rate"] = rng.uniform(0.80, 1.0)

        elif root_cause.id == "redis_cluster_split":
            metrics["cluster_state"] = "FAIL"
            metrics["cluster_known_nodes"] = 6
            metrics["cluster_slots_ok"] = rng.randint(8000, 12000)
            metrics["cluster_slots_fail"] = 16384 - metrics["cluster_slots_ok"]
            metrics["error_rate"] = rng.uniform(0.40, 0.60)
            metrics["keyspace_misses"] = rng.randint(10000, 50000)

        elif root_cause.id == "auth_db_failover_loop":
            metrics["replication_lag_seconds"] = rng.uniform(30, 120)
            metrics["failovers_last_hour"] = rng.randint(10, 30)
            metrics["connection_resets"] = rng.randint(500, 1000)
            metrics["primary_role_changes"] = rng.randint(5, 15)
            metrics["error_rate"] = rng.uniform(0.70, 0.95)

        elif root_cause.id == "network_partition":
            metrics["connection_refused_count"] = rng.randint(1000, 5000)
            metrics["tcp_retransmits"] = rng.randint(10000, 50000)
            metrics["healthy_backends"] = 0
            metrics["unhealthy_backends"] = rng.randint(3, 8)
            metrics["error_rate"] = 1.0
            metrics["request_rate"] = 0

        return metrics

    def _generate_cascade_metrics(
        self, baseline: Any, multipliers: dict[str, float], rng: random.Random
    ) -> dict[str, Any]:
        """Generate metrics for cascading impact."""
        error_mult = multipliers.get("error_rate", 1.0)
        latency_mult = multipliers.get("latency", 1.0)

        return {
            "error_rate": min(1.0, baseline.error_rate * error_mult * rng.uniform(0.8, 1.2)),
            "latency_p99_ms": baseline.latency_p99_ms * latency_mult * rng.uniform(0.9, 1.1),
            "request_rate": baseline.request_rate * rng.uniform(0.3, 0.7),
            "cpu_percent": rng.uniform(50, 80),
            "memory_percent": rng.uniform(50, 70),
            "circuit_breaker_state": rng.choice(["OPEN", "HALF_OPEN"]),
            "retry_rate": rng.uniform(0.2, 0.5),
            "status": "DEGRADED",
        }

    def _generate_normal_metrics(
        self, baseline: Any, rng: random.Random
    ) -> dict[str, Any]:
        """Generate normal baseline metrics."""
        return {
            "error_rate": baseline.error_rate * rng.uniform(0.8, 1.2),
            "latency_p99_ms": baseline.latency_p99_ms * rng.uniform(0.9, 1.1),
            "request_rate": baseline.request_rate * rng.uniform(0.95, 1.05),
            "cpu_percent": rng.uniform(15, 35),
            "memory_percent": rng.uniform(30, 50),
            "status": "HEALTHY",
        }

    def _generate_traces(
        self,
        root_cause: RootCause,
        affected_services: list[str],
        cascade_impact: dict[str, dict[str, float]],
        rng: random.Random,
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate detailed distributed traces."""
        traces: dict[str, list[dict[str, Any]]] = {}

        # Generate multiple traces showing the cascade
        for i in range(5):
            trace_id = f"trace-cascade-{rng.randint(100000, 999999)}"
            base_time = self._base_time - timedelta(minutes=rng.randint(1, 30))

            # Build a trace through the service chain
            span_offset = 0

            for svc in affected_services:
                if svc not in traces:
                    traces[svc] = []

                distance = cascade_impact.get(svc, {}).get("distance", 0)
                span_time = base_time + timedelta(milliseconds=span_offset)

                # Duration increases dramatically at the root cause
                if svc == root_cause.service:
                    duration = rng.randint(25000, 60000)  # Very slow
                else:
                    base_duration = rng.randint(50, 200)
                    latency_mult = cascade_impact.get(svc, {}).get("latency_multiplier", 1.0)
                    duration = int(base_duration * latency_mult)

                is_error = (
                    svc == root_cause.service or
                    (svc in affected_services and rng.random() < 0.7)
                )

                traces[svc].append(
                    {
                        "trace_id": trace_id,
                        "span_id": f"span-{rng.randint(10000, 99999)}",
                        "parent_span_id": f"span-{rng.randint(10000, 99999)}" if distance > 0 else None,
                        "service": svc,
                        "operation": self._get_operation_name(svc, root_cause),
                        "start_time": span_time.isoformat() + "Z",
                        "duration_ms": duration,
                        "status": "ERROR" if is_error else "OK",
                        "tags": {
                            "http.method": "POST" if "order" in svc or "auth" in svc else "GET",
                            "http.status_code": 500 if is_error else 200,
                            "error": is_error,
                            "error.message": self._get_error_message(svc, root_cause) if is_error else None,
                        },
                        "logs": self._generate_span_logs(svc, root_cause, is_error, rng) if is_error else [],
                    }
                )

                span_offset += duration + rng.randint(5, 20)

        return traces

    def _get_operation_name(self, service: str, root_cause: RootCause) -> str:
        """Get the operation name for a span."""
        operation_mapping = {
            "frontend": "frontend.render",
            "api-gateway": "gateway.route",
            "auth-service": "auth.validate_token",
            "auth-db": "db.query",
            "redis": "redis.get",
            "user-service": "user.get_profile",
            "user-db": "db.query",
            "order-service": "order.create",
            "order-db": "db.insert",
            "kafka": "kafka.produce",
            "order-worker": "worker.process",
            "warehouse-api": "warehouse.check_inventory",
        }
        return operation_mapping.get(service, f"{service}.handle")

    def _get_error_message(self, service: str, root_cause: RootCause) -> str:
        """Get error message for a failed span."""
        if service == root_cause.service:
            error_messages = {
                "order_db_disk_full": "SQLSTATE[53100]: Disk full",
                "redis_cluster_split": "CLUSTERDOWN The cluster is down",
                "auth_db_failover_loop": "Connection reset during failover",
                "network_partition": "Connection refused",
            }
            return error_messages.get(root_cause.id, "Internal error")

        return f"Upstream service {root_cause.service} unavailable"

    def _generate_span_logs(
        self, service: str, root_cause: RootCause, is_error: bool, rng: random.Random
    ) -> list[dict[str, str]]:
        """Generate logs attached to a span."""
        if not is_error:
            return []

        logs = []

        if service == root_cause.service:
            logs.append({
                "timestamp": "0ms",
                "event": "error",
                "message": f"Root cause: {root_cause.description}",
            })
        else:
            logs.append({
                "timestamp": "0ms",
                "event": "error",
                "message": f"Dependency {root_cause.service} failure",
            })
            logs.append({
                "timestamp": f"{rng.randint(100, 500)}ms",
                "event": "retry",
                "message": "Retry attempt failed",
            })

        return logs

    def _generate_deploys(
        self,
        root_cause: RootCause,
        service_graph: ServiceGraph,
        rng: random.Random,
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate deployment history with potential red herrings."""
        deploys: dict[str, list[dict[str, Any]]] = {}

        # Add recent deploys to several services (red herrings)
        all_services = service_graph.get_service_names()
        rng.shuffle(all_services)

        for svc in all_services[:4]:
            # Vary deploy times to create confusion
            if svc == root_cause.service and root_cause.category == RootCauseCategory.DEPLOYMENT:
                deploy_time = self._base_time - timedelta(minutes=rng.randint(15, 45))
            else:
                # Red herring deploys from yesterday
                deploy_time = self._base_time - timedelta(hours=rng.randint(6, 48))

            deploys[svc] = [
                {
                    "deploy_id": f"deploy-{rng.randint(10000, 99999)}",
                    "service": svc,
                    "version": f"v{rng.randint(1, 3)}.{rng.randint(10, 50)}.{rng.randint(0, 20)}",
                    "timestamp": deploy_time.isoformat() + "Z",
                    "deployed_by": rng.choice(["jenkins-ci", "github-actions", "argocd", "manual"]),
                    "status": "completed",
                    "commit_sha": f"{rng.randint(0, 0xFFFFFFFF):08x}",
                    "change_description": rng.choice([
                        "Dependency updates",
                        "Performance optimization",
                        "Bug fix",
                        "Feature flag update",
                        "Config change",
                    ]),
                    "rollback_available": True,
                    "previous_version": f"v{rng.randint(1, 3)}.{rng.randint(5, 15)}.{rng.randint(0, 10)}",
                },
            ]

        return deploys
