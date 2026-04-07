"""
Logs simulation engine for generating realistic application log output.

Formats pre-generated log data into human-readable text that LLM agents
can interpret during incident investigation.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Optional


class LogsEngine:
    """Formats log data into realistic application log output."""

    # Common log message templates by category
    _NORMAL_MESSAGES = {
        "request": [
            "Handling request {method} {path} from {ip}",
            "Request processed successfully in {duration}ms",
            "Incoming request id={req_id} method={method} path={path}",
            "Response sent status={status} duration={duration}ms",
        ],
        "health": [
            "Health check passed: all dependencies healthy",
            "Liveness probe OK",
            "Readiness probe OK",
            "Service health: cpu={cpu}% memory={mem}% connections={conn}",
        ],
        "connection": [
            "Connection pool stats: active={active} idle={idle} waiting={waiting}",
            "Established connection to {target}",
            "Connection keepalive ping successful",
            "Pool rebalanced: {count} connections",
        ],
        "startup": [
            "Service started on port {port}",
            "Configuration loaded from {source}",
            "Registered {count} routes",
            "Worker thread pool initialized with {threads} threads",
        ],
        "cache": [
            "Cache hit for key {key}",
            "Cache stats: hits={hits} misses={misses} ratio={ratio}%",
            "Cache TTL refresh for {count} entries",
        ],
    }

    _ERROR_TEMPLATES = {
        "deployment": [
            "FATAL: Service failed to start: {error}",
            "Configuration validation failed: missing required field '{field}'",
            "Incompatible schema version: expected {expected}, got {actual}",
            "Failed to bind to port {port}: address already in use",
            "Startup probe failed after {attempts} attempts",
            "Cannot connect to required dependency {dep}: {error}",
            "OOM killed during initialization: memory limit exceeded",
            "Feature flag '{flag}' evaluation failed: invalid configuration",
            "Rolling update failed: new pods not reaching ready state",
            "Deployment rollback triggered: health checks failing",
        ],
        "infrastructure": [
            "Connection refused to {target}:{port}",
            "Connection timeout after {timeout}ms to {target}",
            "DNS resolution failed for {hostname}",
            "SSL handshake failed: certificate expired",
            "Network unreachable: {target}",
            "Socket error: {error}",
            "Max connections reached for pool {pool}",
            "Disk I/O error: {error}",
            "Out of memory: cannot allocate {size} bytes",
            "CPU throttling detected: {percent}% throttled",
        ],
        "traffic": [
            "Rate limit exceeded for client {client_id}",
            "Request queue full: dropping request {req_id}",
            "Connection backlog exceeded: {count} pending",
            "Load shedding activated: rejecting {percent}% of requests",
            "Circuit breaker OPEN: too many failures",
            "Timeout processing request: exceeded {timeout}ms",
            "Request body too large: {size} bytes exceeds limit",
            "Too many concurrent requests from {ip}",
            "Backpressure applied: slowing intake",
            "Queue depth critical: {depth} messages pending",
        ],
        "dependency": [
            "Dependency {service} health check failed",
            "Upstream service {service} returned {status}",
            "Retry attempt {attempt}/{max} for {service}",
            "Circuit breaker OPEN for {service}",
            "Fallback activated for {service}",
            "Dependency {service} latency spike: {latency}ms",
            "Connection pool exhausted for {service}",
            "Database query timeout: {query}",
            "Cache connection lost: {cache}",
            "Message broker unreachable: {broker}",
        ],
    }

    _WARNING_TEMPLATES = {
        "deployment": [
            "Deprecation warning: {feature} will be removed in {version}",
            "Configuration override detected: {key}={value}",
            "Using fallback configuration for {setting}",
            "Startup slower than expected: {duration}ms",
        ],
        "infrastructure": [
            "High memory usage: {percent}%",
            "Disk space low: {available} remaining",
            "Connection pool nearing capacity: {used}/{max}",
            "Network latency elevated: {latency}ms to {target}",
            "GC pause exceeded threshold: {duration}ms",
        ],
        "traffic": [
            "Request rate approaching limit: {rate}/{limit} rps",
            "Response time degraded: p99={latency}ms",
            "Retry rate elevated: {rate}%",
            "Error rate above threshold: {rate}%",
        ],
        "dependency": [
            "Dependency {service} responding slowly: {latency}ms",
            "Retry attempt {attempt}/{max} for {service}",
            "Falling back to cached data for {service}",
            "Secondary replica selected for {service}",
        ],
    }

    @staticmethod
    def format_logs(logs: list[dict], service: str, limit: int = 20) -> str:
        """Format log entries into a human-readable log dump.

        Args:
            logs: List of log dicts with timestamp, level, message, service keys
            limit: Maximum number of log entries to include

        Returns:
            Formatted log output string
        """
        if not logs:
            return f"=== Logs for {service} (no entries found) ===\n"

        # Filter logs for the specified service and apply limit
        service_logs = [log for log in logs if log.get("service") == service]
        if not service_logs:
            # If no logs match the service, show all logs (cross-service view)
            service_logs = logs

        # Sort by timestamp descending (most recent first), then take limit
        service_logs = sorted(
            service_logs,
            key=lambda x: x.get("timestamp", ""),
            reverse=True,
        )[:limit]

        # Reverse to show chronological order
        service_logs = list(reversed(service_logs))

        lines = [f"=== Logs for {service} (last {len(service_logs)} entries) ==="]

        for log in service_logs:
            timestamp = log.get("timestamp", "unknown")
            level = log.get("level", "INFO")
            message = log.get("message", "")
            log_service = log.get("service", service)

            # Align level field for readability
            level_padded = f"[{level}]".ljust(7)
            lines.append(f"{timestamp} {level_padded} {log_service}: {message}")

        return "\n".join(lines)

    @staticmethod
    def generate_normal_logs(
        service: str,
        count: int = 10,
        rng: Optional[random.Random] = None,
    ) -> list[dict]:
        """Generate normal-looking log entries for a healthy service.

        Args:
            service: Service name for the logs
            count: Number of log entries to generate
            rng: Random number generator for deterministic output

        Returns:
            List of log entry dicts
        """
        if rng is None:
            rng = random.Random()

        logs = []
        base_time = datetime.now() - timedelta(minutes=15)

        for i in range(count):
            # Progress time forward
            time_offset = timedelta(seconds=rng.randint(30, 120) * (i + 1) // 2)
            timestamp = base_time + time_offset

            # Mostly INFO, occasional DEBUG
            level = rng.choices(["INFO", "DEBUG"], weights=[0.85, 0.15])[0]

            # Pick a message category and template
            category = rng.choice(list(LogsEngine._NORMAL_MESSAGES.keys()))
            template = rng.choice(LogsEngine._NORMAL_MESSAGES[category])

            # Fill in template variables
            message = LogsEngine._fill_template(template, service, rng)

            logs.append(
                {
                    "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
                    "level": level,
                    "message": message,
                    "service": service,
                }
            )

        return logs

    @staticmethod
    def generate_error_logs(
        service: str,
        root_cause_category: str,
        symptoms: list[str],
        count: int = 15,
        rng: Optional[random.Random] = None,
    ) -> list[dict]:
        """Generate error logs matching a specific incident.

        Args:
            service: Service name for the logs
            root_cause_category: One of deployment, infrastructure, traffic, dependency
            symptoms: List of symptom descriptions to weave into logs
            count: Number of log entries to generate
            rng: Random number generator for deterministic output

        Returns:
            List of log entry dicts
        """
        if rng is None:
            rng = random.Random()

        logs = []
        base_time = datetime.now() - timedelta(minutes=15)

        # Determine when the incident starts (around minute 8-10 of 15)
        incident_start_idx = count // 3

        for i in range(count):
            time_offset = timedelta(seconds=rng.randint(45, 90) * (i + 1))
            timestamp = base_time + time_offset

            is_incident_phase = i >= incident_start_idx

            if is_incident_phase:
                # Generate error/warning logs during incident
                level = rng.choices(
                    ["ERROR", "WARN", "INFO"],
                    weights=[0.5, 0.3, 0.2],
                )[0]

                if level == "ERROR":
                    templates = LogsEngine._ERROR_TEMPLATES.get(
                        root_cause_category,
                        LogsEngine._ERROR_TEMPLATES["infrastructure"],
                    )
                    template = rng.choice(templates)
                    message = LogsEngine._fill_template(template, service, rng)

                    # Occasionally use a symptom directly
                    if symptoms and rng.random() < 0.3:
                        message = rng.choice(symptoms)

                elif level == "WARN":
                    templates = LogsEngine._WARNING_TEMPLATES.get(
                        root_cause_category,
                        LogsEngine._WARNING_TEMPLATES["infrastructure"],
                    )
                    template = rng.choice(templates)
                    message = LogsEngine._fill_template(template, service, rng)
                else:
                    # INFO during incident - often about retries or degradation
                    message = rng.choice(
                        [
                            f"Attempting recovery for {service}",
                            "Initiating graceful degradation mode",
                            f"Alerting on-call team for {service}",
                            "Health check probe initiated",
                            f"Metrics export delayed: {rng.randint(5, 30)}s backlog",
                        ]
                    )
            else:
                # Normal operation before incident
                level = rng.choices(["INFO", "DEBUG"], weights=[0.9, 0.1])[0]
                category = rng.choice(list(LogsEngine._NORMAL_MESSAGES.keys()))
                template = rng.choice(LogsEngine._NORMAL_MESSAGES[category])
                message = LogsEngine._fill_template(template, service, rng)

            logs.append(
                {
                    "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
                    "level": level,
                    "message": message,
                    "service": service,
                }
            )

        return logs

    @staticmethod
    def _fill_template(template: str, service: str, rng: random.Random) -> str:
        """Fill in placeholder variables in a log message template."""
        replacements = {
            "{method}": rng.choice(["GET", "POST", "PUT", "DELETE"]),
            "{path}": rng.choice(
                ["/api/v1/users", "/api/v1/orders", "/health", "/metrics", "/api/v1/auth"]
            ),
            "{ip}": f"10.0.{rng.randint(1, 255)}.{rng.randint(1, 255)}",
            "{duration}": str(rng.randint(5, 250)),
            "{req_id}": f"req-{rng.randint(10000, 99999)}",
            "{status}": rng.choice(["200", "201", "204", "500", "502", "503"]),
            "{cpu}": str(rng.randint(15, 45)),
            "{mem}": str(rng.randint(30, 60)),
            "{conn}": str(rng.randint(50, 200)),
            "{active}": str(rng.randint(20, 80)),
            "{idle}": str(rng.randint(10, 40)),
            "{waiting}": str(rng.randint(0, 10)),
            "{target}": rng.choice(
                ["postgres-primary", "redis-cluster", "kafka-broker", "auth-service"]
            ),
            "{count}": str(rng.randint(5, 50)),
            "{port}": rng.choice(["8080", "5432", "6379", "9092", "443"]),
            "{source}": rng.choice(["configmap", "env", "secrets", "file"]),
            "{threads}": str(rng.randint(4, 32)),
            "{key}": f"cache::{service}::{rng.randint(1000, 9999)}",
            "{hits}": str(rng.randint(5000, 50000)),
            "{misses}": str(rng.randint(100, 2000)),
            "{ratio}": str(rng.randint(85, 99)),
            "{error}": rng.choice(
                [
                    "connection reset by peer",
                    "no route to host",
                    "connection timed out",
                    "broken pipe",
                ]
            ),
            "{field}": rng.choice(["database_url", "api_key", "secret_token", "host"]),
            "{expected}": f"v{rng.randint(1, 3)}.{rng.randint(0, 9)}",
            "{actual}": f"v{rng.randint(1, 3)}.{rng.randint(0, 9)}",
            "{attempts}": str(rng.randint(3, 10)),
            "{dep}": rng.choice(["postgres", "redis", "kafka", "auth-service"]),
            "{timeout}": str(rng.randint(5000, 30000)),
            "{hostname}": f"{service}.internal.svc.cluster.local",
            "{pool}": f"{service}-pool",
            "{size}": str(rng.randint(1024, 1024 * 1024)),
            "{percent}": str(rng.randint(60, 95)),
            "{client_id}": f"client-{rng.randint(1000, 9999)}",
            "{limit}": str(rng.randint(100, 1000)),
            "{rate}": str(rng.randint(10, 100)),
            "{depth}": str(rng.randint(1000, 10000)),
            "{service}": rng.choice(
                ["auth-service", "user-service", "order-service", "payment-service"]
            ),
            "{attempt}": str(rng.randint(1, 3)),
            "{max}": "3",
            "{latency}": str(rng.randint(500, 5000)),
            "{query}": "SELECT * FROM users WHERE ...",
            "{cache}": "redis-primary",
            "{broker}": "kafka-cluster",
            "{feature}": rng.choice(["legacy_auth", "v1_api", "sync_mode"]),
            "{version}": f"v{rng.randint(2, 4)}.0",
            "{value}": rng.choice(["true", "false", "override"]),
            "{setting}": rng.choice(["timeout", "retry_count", "batch_size"]),
            "{available}": f"{rng.randint(1, 10)}GB",
            "{used}": str(rng.randint(80, 95)),
            "{flag}": rng.choice(["new_checkout", "beta_features", "dark_mode"]),
        }

        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, value)

        return result
