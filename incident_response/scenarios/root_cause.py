"""
Root cause analysis scenario generator.

Generates medium difficulty scenarios where agents must investigate
multiple services showing symptoms and diagnose the true root cause.
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
    RCA_ROOT_CAUSES,
)
from .service_graph import ServiceGraph


class RCAGenerator(ScenarioGenerator):
    """
    Generates medium difficulty root cause analysis scenarios.

    The agent sees symptoms across multiple services and must:
    1. Investigate using logs, metrics, and traces
    2. Filter out red herring alerts from unrelated services
    3. Identify the true root cause
    4. Apply the correct remediation

    Includes 1-2 red herring alerts to increase difficulty.
    """

    def __init__(self) -> None:
        self._base_time = datetime(2024, 1, 15, 14, 45, 0)

    def get_task_description(self) -> str:
        return (
            "ROOT CAUSE ANALYSIS: Multiple services are showing symptoms. "
            "Investigate using available diagnostic tools (logs, metrics, traces, deploys). "
            "Identify the true root cause, filtering out misleading signals. "
            "Once confident, use the diagnose action to report the root cause, "
            "then apply the appropriate remediation."
        )

    def generate(self, seed: int) -> ScenarioConfig:
        """Generate an RCA scenario with deterministic randomness."""
        rng = random.Random(seed)

        # Select root cause
        root_cause = rng.choice(RCA_ROOT_CAUSES)

        # Create service graph
        service_graph = ServiceGraph.create_ecommerce()

        # Determine affected services (root cause + dependents)
        affected_services = self._determine_affected_services(
            root_cause, service_graph
        )

        # Determine severity
        severity = self._determine_severity(root_cause, affected_services, rng)

        # Generate alerts for affected services
        alerts = self._generate_alerts(root_cause, affected_services, severity, rng)

        # Add red herring alerts (1-2)
        red_herring_alerts = self._generate_red_herring_alerts(
            affected_services, service_graph, rng
        )
        alerts.extend(red_herring_alerts)

        # Shuffle alerts to mix real and red herrings
        rng.shuffle(alerts)

        # Generate comprehensive diagnostic data
        logs_data = self._generate_logs(root_cause, affected_services, rng)
        metrics_data = self._generate_metrics(
            root_cause, affected_services, service_graph, rng
        )
        traces_data = self._generate_traces(root_cause, affected_services, rng)
        deploys_data = self._generate_deploys(root_cause, service_graph, rng)

        task_id = f"rca-{seed:04d}"

        return ScenarioConfig(
            seed=seed,
            task_id=task_id,
            difficulty=Difficulty.MEDIUM,
            root_cause=root_cause,
            severity=severity,
            service_graph=service_graph,
            affected_services=affected_services,
            max_steps=20,
            logs_data=logs_data,
            metrics_data=metrics_data,
            traces_data=traces_data,
            deploys_data=deploys_data,
            alerts=alerts,
        )

    def _determine_affected_services(
        self, root_cause: RootCause, service_graph: ServiceGraph
    ) -> list[str]:
        """Determine all services affected by the root cause."""
        affected = [root_cause.service]

        # Get services that depend on the root cause service
        dependents = service_graph.get_dependents(root_cause.service)
        affected.extend(dependents)

        # For some root causes, add transitive dependents
        if root_cause.id in ["auth_service_bad_deploy", "kafka_partition_imbalance"]:
            for dep in dependents:
                transitive = service_graph.get_dependents(dep)
                for t in transitive:
                    if t not in affected:
                        affected.append(t)

        return affected

    def _determine_severity(
        self,
        root_cause: RootCause,
        affected_services: list[str],
        rng: random.Random,
    ) -> str:
        """Determine incident severity based on impact scope."""
        critical_services = {"api-gateway", "auth-service", "auth-db", "redis"}

        # Check if critical services are affected
        critical_affected = any(svc in critical_services for svc in affected_services)

        if critical_affected and len(affected_services) >= 3:
            return "P1"
        elif critical_affected or len(affected_services) >= 2:
            return rng.choice(["P1", "P2"])
        else:
            return "P2"

    def _generate_alerts(
        self,
        root_cause: RootCause,
        affected_services: list[str],
        severity: str,
        rng: random.Random,
    ) -> list[dict[str, Any]]:
        """Generate alerts for all affected services."""
        alerts: list[dict[str, Any]] = []

        # Alert templates by root cause
        alert_configs = self._get_alert_configs(root_cause)

        for i, svc in enumerate(affected_services):
            alert_time = self._base_time - timedelta(minutes=rng.randint(2, 20))

            # Primary service gets more severe alert
            svc_severity = severity if svc == root_cause.service else self._downgrade_severity(severity)

            # Get service-specific alert content
            title, description = self._get_alert_content(svc, root_cause, alert_configs, rng)

            alerts.append(
                {
                    "alert_id": f"alert-{svc}-{i:03d}",
                    "service": svc,
                    "severity": svc_severity,
                    "title": title,
                    "description": description,
                    "timestamp": alert_time.isoformat() + "Z",
                    "labels": {
                        "service": svc,
                        "env": "production",
                        "region": "us-east-1",
                        "team": self._get_team_for_service(svc),
                    },
                    "acknowledged": False,
                }
            )

        return alerts

    def _downgrade_severity(self, severity: str) -> str:
        """Downgrade severity for downstream affected services."""
        mapping = {"P1": "P2", "P2": "P3", "P3": "P4", "P4": "P4"}
        return mapping.get(severity, severity)

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

    def _get_alert_configs(self, root_cause: RootCause) -> dict[str, dict[str, str]]:
        """Get alert configurations for root cause scenarios."""
        configs: dict[str, dict[str, dict[str, str]]] = {
            "auth_service_bad_deploy": {
                "auth-service": {
                    "title": "CPU Critical - auth-service",
                    "description": "CPU usage at 100% across all pods",
                },
                "api-gateway": {
                    "title": "High Latency - api-gateway",
                    "description": "P99 latency exceeded 10s on auth-dependent routes",
                },
                "frontend": {
                    "title": "Error Rate Elevated - frontend",
                    "description": "5xx error rate increased to 15%",
                },
            },
            "kafka_partition_imbalance": {
                "kafka": {
                    "title": "Partition Imbalance - kafka",
                    "description": "Broker-1 handling 80% of partition leaders",
                },
                "order-worker": {
                    "title": "Processing Lag - order-worker",
                    "description": "Consumer lag exceeding 10,000 messages",
                },
                "order-service": {
                    "title": "Queue Backpressure - order-service",
                    "description": "Producer send latency spiking",
                },
            },
            "memory_leak_user_service": {
                "user-service": {
                    "title": "Memory Critical - user-service",
                    "description": "Memory usage at 95%, pods restarting",
                },
                "user-db": {
                    "title": "Connection Churn - user-db",
                    "description": "High rate of connection open/close cycles",
                },
                "api-gateway": {
                    "title": "Elevated Errors - api-gateway",
                    "description": "User endpoints returning 503 intermittently",
                },
            },
            "dns_resolution_failure": {
                "order-service": {
                    "title": "DNS Resolution Errors - order-service",
                    "description": "UnknownHostException rate: 30%",
                },
                "order-db": {
                    "title": "Low Traffic Alert - order-db",
                    "description": "Query rate dropped 70% from baseline",
                },
                "kafka": {
                    "title": "Consumer Lag Increasing - kafka",
                    "description": "order-events consumer lag growing",
                },
            },
            "order_db_slow_queries": {
                "order-db": {
                    "title": "Slow Query Alert - order-db",
                    "description": "Queries exceeding 10s detected in slow log",
                },
                "order-service": {
                    "title": "High Latency - order-service",
                    "description": "P99 latency at 15,000ms",
                },
                "api-gateway": {
                    "title": "Timeout Rate Elevated - api-gateway",
                    "description": "Order endpoints timing out at 8%",
                },
            },
            "rate_limit_misconfiguration": {
                "api-gateway": {
                    "title": "Rate Limit Threshold - api-gateway",
                    "description": "Rate limit rejecting 95% of requests",
                },
                "auth-service": {
                    "title": "Traffic Drop - auth-service",
                    "description": "Request rate dropped to 5% of normal",
                },
                "order-service": {
                    "title": "No Traffic - order-service",
                    "description": "Zero requests in last 5 minutes",
                },
            },
        }
        return configs.get(root_cause.id, {})

    def _get_alert_content(
        self,
        service: str,
        root_cause: RootCause,
        alert_configs: dict[str, dict[str, str]],
        rng: random.Random,
    ) -> tuple[str, str]:
        """Get alert title and description for a service."""
        if service in alert_configs:
            config = alert_configs[service]
            return config["title"], config["description"]

        # Generic fallback
        generic_alerts = [
            (f"Service Degraded - {service}", f"Error rate elevated on {service}"),
            (f"High Latency - {service}", f"P99 latency exceeding threshold on {service}"),
            (f"Health Check Warning - {service}", f"Intermittent health check failures on {service}"),
        ]
        return rng.choice(generic_alerts)

    def _generate_red_herring_alerts(
        self,
        affected_services: list[str],
        service_graph: ServiceGraph,
        rng: random.Random,
    ) -> list[dict[str, Any]]:
        """Generate misleading alerts from unrelated services."""
        red_herrings: list[dict[str, Any]] = []

        # Find services NOT affected
        all_services = service_graph.get_service_names()
        unaffected = [s for s in all_services if s not in affected_services]

        if not unaffected:
            return red_herrings

        # Generate 1-2 red herring alerts
        num_red_herrings = rng.randint(1, 2)
        selected = rng.sample(unaffected, min(num_red_herrings, len(unaffected)))

        red_herring_templates = [
            ("Minor GC Pause Detected", "GC pause exceeded 100ms threshold"),
            ("Connection Pool Warning", "Connection pool at 60% capacity"),
            ("Memory Usage Elevated", "Memory at 75% - monitoring"),
            ("Latency Spike Detected", "Brief latency spike to 500ms, recovered"),
            ("Log Volume Increased", "Log output 20% above baseline"),
        ]

        for i, svc in enumerate(selected):
            alert_time = self._base_time - timedelta(minutes=rng.randint(5, 30))
            template = rng.choice(red_herring_templates)

            red_herrings.append(
                {
                    "alert_id": f"alert-{svc}-rh-{i:03d}",
                    "service": svc,
                    "severity": "P4",  # Low severity for red herrings
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
        rng: random.Random,
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate logs for all affected services."""
        logs: dict[str, list[dict[str, Any]]] = {}

        for svc in affected_services:
            entries: list[dict[str, Any]] = []
            num_entries = rng.randint(20, 40)

            for _ in range(num_entries):
                log_time = self._base_time - timedelta(
                    minutes=rng.randint(0, 45), seconds=rng.randint(0, 59)
                )

                if svc == root_cause.service:
                    # Root cause service has more diagnostic logs
                    if rng.random() < 0.6:
                        entry = self._generate_root_cause_log(root_cause, log_time, rng)
                    else:
                        entry = self._generate_normal_log(svc, log_time, rng)
                else:
                    # Affected services show downstream symptoms
                    if rng.random() < 0.4:
                        entry = self._generate_downstream_error_log(svc, root_cause, log_time, rng)
                    else:
                        entry = self._generate_normal_log(svc, log_time, rng)

                entries.append(entry)

            entries.sort(key=lambda x: x["timestamp"])
            logs[svc] = entries

        return logs

    def _generate_root_cause_log(
        self, root_cause: RootCause, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate a log entry showing root cause symptoms."""
        log_messages: dict[str, list[str]] = {
            "auth_service_bad_deploy": [
                "ERROR TokenValidator: Infinite loop detected in validate()",
                "ERROR CPU throttling detected, processing stalled",
                "FATAL Thread pool exhausted, all workers busy",
                "ERROR RequestHandler: Timeout waiting for token validation",
            ],
            "kafka_partition_imbalance": [
                "WARN PartitionManager: Leader skew detected, broker-1 overloaded",
                "ERROR Consumer lag exceeding threshold: 15,234 messages",
                "WARN Rebalance triggered but partition assignment unchanged",
                "ERROR Producer: Batch send timeout, broker-1 under pressure",
            ],
            "memory_leak_user_service": [
                "WARN HeapMonitor: Memory usage at 94%, approaching limit",
                "ERROR OOMKilled: Container exceeded memory limit",
                "DEBUG DbCursor: 3,847 unclosed cursors detected",
                "WARN GC: Full GC taking 2.3s, heap nearly full",
            ],
            "dns_resolution_failure": [
                "ERROR DNS: UnknownHostException for order-db.internal",
                "WARN DNS cache miss, TTL expired for order-db.internal",
                "ERROR Connection failed: Name resolution failed",
                "DEBUG DNS: Intermittent resolution failure, retry 3/5",
            ],
            "order_db_slow_queries": [
                "WARN SlowQueryLog: SELECT on orders took 12,453ms",
                "ERROR QueryOptimizer: Full table scan detected on orders",
                "DEBUG QueryPlan: Seq Scan on orders (rows=2,847,392)",
                "ERROR Connection timeout waiting for query result",
            ],
            "rate_limit_misconfiguration": [
                "WARN RateLimiter: Config loaded, limit=10 req/s",
                "ERROR RateLimiter: Request rejected, limit exceeded",
                "INFO RateLimiter: 94% of requests rate limited",
                "DEBUG RateLimiter: Bucket capacity: 10, current: 10",
            ],
        }

        messages = log_messages.get(root_cause.id, ["ERROR Service error detected"])

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["ERROR", "ERROR", "WARN", "FATAL"]),
            "service": root_cause.service,
            "message": rng.choice(messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
        }

    def _generate_downstream_error_log(
        self, service: str, root_cause: RootCause, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate error logs for downstream affected services."""
        downstream_messages = [
            f"ERROR Upstream service {root_cause.service} not responding",
            f"ERROR Timeout calling {root_cause.service}: 30000ms exceeded",
            "ERROR Circuit breaker OPEN, failing fast",
            "WARN Retry attempt 3/3 failed",
            "ERROR Request failed with 503 Service Unavailable",
            "WARN Degraded mode activated due to dependency failure",
        ]

        return {
            "timestamp": log_time.isoformat() + "Z",
            "level": rng.choice(["ERROR", "WARN"]),
            "service": service,
            "message": rng.choice(downstream_messages),
            "trace_id": f"trace-{rng.randint(100000, 999999)}",
            "span_id": f"span-{rng.randint(1000, 9999)}",
        }

    def _generate_normal_log(
        self, service: str, log_time: datetime, rng: random.Random
    ) -> dict[str, Any]:
        """Generate a normal operational log entry."""
        normal_messages = [
            "INFO Request processed successfully",
            "DEBUG Processing request payload",
            "INFO Health check passed",
            "DEBUG Cache operation completed",
            "INFO Connection pool healthy",
            "DEBUG Metrics exported",
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
        self,
        root_cause: RootCause,
        affected_services: list[str],
        service_graph: ServiceGraph,
        rng: random.Random,
    ) -> dict[str, dict[str, Any]]:
        """Generate metrics for all services."""
        metrics: dict[str, dict[str, Any]] = {}

        for svc_name in service_graph.get_service_names():
            svc = service_graph.get_service(svc_name)
            if not svc:
                continue

            baseline = svc.baseline_metrics

            if svc_name == root_cause.service:
                # Root cause service shows clear anomalies
                metrics[svc_name] = self._generate_root_cause_metrics(
                    root_cause, baseline, rng
                )
            elif svc_name in affected_services:
                # Downstream services show partial impact
                metrics[svc_name] = self._generate_affected_metrics(baseline, rng)
            else:
                # Unaffected services show normal metrics
                metrics[svc_name] = self._generate_normal_metrics(baseline, rng)

        return metrics

    def _generate_root_cause_metrics(
        self, root_cause: RootCause, baseline: Any, rng: random.Random
    ) -> dict[str, Any]:
        """Generate metrics showing root cause problems."""
        metrics: dict[str, Any] = {
            "error_rate": baseline.error_rate,
            "latency_p99_ms": baseline.latency_p99_ms,
            "request_rate": baseline.request_rate,
            "cpu_percent": rng.uniform(20, 40),
            "memory_percent": rng.uniform(30, 50),
        }

        if root_cause.id == "auth_service_bad_deploy":
            metrics["cpu_percent"] = rng.uniform(98, 100)
            metrics["error_rate"] = rng.uniform(0.30, 0.50)
            metrics["latency_p99_ms"] = rng.uniform(25000, 35000)
            metrics["thread_pool_active"] = 200
            metrics["thread_pool_max"] = 200

        elif root_cause.id == "kafka_partition_imbalance":
            metrics["partition_leader_count"] = {
                "broker-0": 2,
                "broker-1": 14,
                "broker-2": 2,
            }
            metrics["consumer_lag"] = rng.randint(10000, 20000)
            metrics["produce_latency_ms"] = rng.uniform(500, 1500)

        elif root_cause.id == "memory_leak_user_service":
            metrics["memory_percent"] = rng.uniform(92, 98)
            metrics["gc_pause_ms"] = rng.uniform(1500, 3000)
            metrics["heap_used_mb"] = rng.randint(3800, 4000)
            metrics["heap_max_mb"] = 4096
            metrics["restarts_last_hour"] = rng.randint(3, 7)

        elif root_cause.id == "dns_resolution_failure":
            metrics["dns_failures"] = rng.randint(100, 300)
            metrics["dns_latency_ms"] = rng.uniform(500, 2000)
            metrics["error_rate"] = rng.uniform(0.25, 0.40)

        elif root_cause.id == "order_db_slow_queries":
            metrics["cpu_percent"] = rng.uniform(90, 98)
            metrics["query_latency_p99_ms"] = rng.uniform(10000, 15000)
            metrics["slow_queries_per_min"] = rng.randint(50, 100)
            metrics["sequential_scans"] = rng.randint(200, 500)

        elif root_cause.id == "rate_limit_misconfiguration":
            metrics["rate_limit_rejects"] = rng.randint(800, 1000)
            metrics["rate_limit_config"] = 10
            metrics["actual_traffic_rps"] = baseline.request_rate
            metrics["error_rate"] = rng.uniform(0.90, 0.98)

        return metrics

    def _generate_affected_metrics(
        self, baseline: Any, rng: random.Random
    ) -> dict[str, Any]:
        """Generate metrics for downstream affected services."""
        return {
            "error_rate": baseline.error_rate * rng.uniform(10, 50),
            "latency_p99_ms": baseline.latency_p99_ms * rng.uniform(3, 8),
            "request_rate": baseline.request_rate * rng.uniform(0.6, 0.9),
            "cpu_percent": rng.uniform(40, 70),
            "memory_percent": rng.uniform(40, 60),
            "circuit_breaker_state": rng.choice(["OPEN", "HALF_OPEN", "CLOSED"]),
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
        }

    def _generate_traces(
        self,
        root_cause: RootCause,
        affected_services: list[str],
        rng: random.Random,
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate distributed traces showing the error path."""
        traces: dict[str, list[dict[str, Any]]] = {}

        # Generate a few example traces
        for i in range(3):
            trace_id = f"trace-{rng.randint(100000, 999999)}"
            trace_time = self._base_time - timedelta(minutes=rng.randint(1, 15))

            for svc in affected_services:
                if svc not in traces:
                    traces[svc] = []

                span_time = trace_time + timedelta(milliseconds=rng.randint(0, 500))
                duration = rng.randint(100, 5000) if svc != root_cause.service else rng.randint(5000, 30000)

                traces[svc].append(
                    {
                        "trace_id": trace_id,
                        "span_id": f"span-{rng.randint(1000, 9999)}",
                        "parent_span_id": f"span-{rng.randint(1000, 9999)}" if svc != "frontend" else None,
                        "service": svc,
                        "operation": f"{svc}.handle_request",
                        "start_time": span_time.isoformat() + "Z",
                        "duration_ms": duration,
                        "status": "ERROR" if svc in affected_services and rng.random() < 0.6 else "OK",
                        "tags": {
                            "http.method": "POST" if "order" in svc else "GET",
                            "http.status_code": 500 if svc == root_cause.service else 200,
                        },
                    }
                )

        return traces

    def _generate_deploys(
        self,
        root_cause: RootCause,
        service_graph: ServiceGraph,
        rng: random.Random,
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate deployment history."""
        deploys: dict[str, list[dict[str, Any]]] = {}

        # Root cause service deployment if it's deployment-related
        if root_cause.category == RootCauseCategory.DEPLOYMENT:
            deploy_time = self._base_time - timedelta(minutes=rng.randint(15, 60))
            deploys[root_cause.service] = [
                {
                    "deploy_id": f"deploy-{rng.randint(10000, 99999)}",
                    "service": root_cause.service,
                    "version": f"v2.{rng.randint(10, 50)}.{rng.randint(0, 9)}",
                    "timestamp": deploy_time.isoformat() + "Z",
                    "deployed_by": rng.choice(["jenkins-ci", "github-actions", "argocd"]),
                    "status": "completed",
                    "commit_sha": f"{rng.randint(0, 0xFFFFFFFF):08x}",
                    "change_description": "Feature update",
                },
            ]

        # Add some recent deploys to other services (potential red herrings)
        other_services = [
            s for s in service_graph.get_service_names() if s != root_cause.service
        ]
        rng.shuffle(other_services)

        for svc in other_services[:2]:
            deploy_time = self._base_time - timedelta(hours=rng.randint(12, 48))
            deploys[svc] = [
                {
                    "deploy_id": f"deploy-{rng.randint(10000, 99999)}",
                    "service": svc,
                    "version": f"v1.{rng.randint(20, 40)}.{rng.randint(0, 9)}",
                    "timestamp": deploy_time.isoformat() + "Z",
                    "deployed_by": "jenkins-ci",
                    "status": "completed",
                    "commit_sha": f"{rng.randint(0, 0xFFFFFFFF):08x}",
                    "change_description": "Dependency updates",
                },
            ]

        return deploys
