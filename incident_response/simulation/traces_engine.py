"""
Traces simulation engine for generating distributed trace data.

Formats pre-generated trace data into human-readable span trees that
LLM agents can interpret during incident investigation.
"""

from __future__ import annotations

import random
import string
from typing import Optional


class TracesEngine:
    """Formats distributed trace data into readable span trees."""

    # Common operation names by service type
    _OPERATIONS = {
        "frontend": [
            "GET /login",
            "GET /dashboard",
            "POST /api/submit",
            "GET /profile",
            "GET /orders",
            "POST /checkout",
        ],
        "api-gateway": [
            "route /login",
            "route /api/users",
            "route /api/orders",
            "route /health",
            "authenticate_request",
            "rate_limit_check",
        ],
        "auth-service": [
            "authenticate",
            "validate_token",
            "refresh_token",
            "check_permissions",
            "generate_jwt",
        ],
        "user-service": [
            "get_profile",
            "update_profile",
            "list_users",
            "create_user",
            "validate_user",
        ],
        "order-service": [
            "create_order",
            "get_order",
            "list_orders",
            "update_status",
            "cancel_order",
        ],
        "payment-service": [
            "process_payment",
            "refund",
            "validate_card",
            "check_balance",
        ],
        "notification-service": [
            "send_email",
            "send_sms",
            "push_notification",
            "queue_notification",
        ],
        "postgres": [
            "SELECT users",
            "INSERT orders",
            "UPDATE status",
            "SELECT orders",
            "DELETE session",
        ],
        "redis": [
            "GET session:*",
            "SET cache:*",
            "EXPIRE key",
            "HGET user:*",
            "INCR counter",
        ],
        "kafka": [
            "produce events",
            "consume events",
            "commit offset",
        ],
    }

    # Error messages by service type
    _ERRORS = {
        "database": [
            "Connection timeout to database",
            "Connection refused",
            "Too many connections",
            "Query timeout exceeded",
            "Deadlock detected",
            "Connection reset by peer",
        ],
        "cache": [
            "Connection timeout to redis",
            "Cache miss cascade",
            "Memory limit exceeded",
            "Connection pool exhausted",
        ],
        "service": [
            "Service unavailable",
            "Circuit breaker OPEN",
            "Request timeout",
            "Rate limit exceeded",
            "Internal server error",
            "Dependency failure",
        ],
        "network": [
            "Network unreachable",
            "DNS resolution failed",
            "SSL handshake failed",
            "Connection refused",
        ],
    }

    @staticmethod
    def format_traces(traces: list[dict], service: str) -> str:
        """Format trace data into a human-readable trace view.

        Args:
            traces: List of trace dicts with trace_id, spans (list of span dicts)
            service: Service name for filtering/highlighting

        Returns:
            Formatted trace tree string
        """
        if not traces:
            return f"=== Distributed Traces involving {service} (no traces found) ===\n"

        lines = [f"=== Distributed Traces involving {service} ===", ""]

        for trace in traces:
            trace_id = trace.get("trace_id", "unknown")
            spans = trace.get("spans", [])

            if not spans:
                continue

            # Calculate total duration and overall status
            total_duration = sum(
                s.get("duration_ms", 0)
                for s in spans
                if s.get("duration_ms") is not None
            )
            has_error = any(s.get("status") == "ERROR" for s in spans)
            trace_status = "ERROR" if has_error else "OK"

            # Format duration
            if total_duration >= 1000:
                duration_str = f"{total_duration}ms"
            else:
                duration_str = f"{total_duration}ms"

            lines.append(f"Trace {trace_id} (total: {duration_str}) [{trace_status}]")

            # Build and render the span tree
            tree_lines = TracesEngine._render_span_tree(spans, service)
            lines.extend(tree_lines)
            lines.append("")  # Blank line between traces

        return "\n".join(lines)

    @staticmethod
    def _render_span_tree(spans: list[dict], highlight_service: str) -> list[str]:
        """Render spans as an indented tree structure."""
        lines = []

        for i, span in enumerate(spans):
            service = span.get("service", "unknown")
            operation = span.get("operation", "unknown")
            duration_ms = span.get("duration_ms")
            status = span.get("status", "OK")
            error = span.get("error")
            depth = span.get("depth", 0)

            # Check if this is the last span at depth 0 (for proper tree endings)
            is_last_top_level = (
                depth == 0
                and all(s.get("depth", 0) > 0 for s in spans[i + 1 :])
            )

            # Build prefix based on depth
            if depth == 0:
                if is_last_top_level or i == len(spans) - 1:
                    prefix = "\u2514\u2500\u2500 "  # └──
                else:
                    prefix = "\u251c\u2500\u2500 "  # ├──
            else:
                # Build indent with proper continuation lines
                indent_parts = []
                for d in range(depth):
                    # Check if there are more spans at this depth level after current
                    has_more_at_level = any(
                        s.get("depth", 0) == d for s in spans[i + 1 :]
                    )
                    if has_more_at_level:
                        indent_parts.append("\u2502   ")  # │   (continuing line)
                    else:
                        indent_parts.append("    ")  # spaces (no more at this level)

                indent = "".join(indent_parts)

                # Check if last at this depth
                is_last_at_depth = not any(
                    s.get("depth", 0) == depth for s in spans[i + 1 :]
                )

                if is_last_at_depth:
                    prefix = indent + "\u2514\u2500\u2500 "  # └──
                else:
                    prefix = indent + "\u251c\u2500\u2500 "  # ├──

            # Format duration
            if duration_ms is None:
                duration_str = "TIMEOUT"
            else:
                duration_str = f"{duration_ms}ms"

            # Format status with error message
            if status == "ERROR" and error:
                status_str = f"[ERROR: {error}]"
            elif status == "ERROR":
                status_str = "[ERROR]"
            else:
                status_str = "[OK]"

            line = f"{prefix}{service}: {operation} ({duration_str}) {status_str}"
            lines.append(line)

        return lines

    @staticmethod
    def _is_last_at_depth(spans: list[dict], index: int, depth: int) -> bool:
        """Check if span at index is the last one at its depth level."""
        for span in spans[index + 1 :]:
            span_depth = span.get("depth", 0)
            if span_depth == depth:
                return False
            if span_depth < depth:
                return True
        return True

    @staticmethod
    def generate_error_traces(
        affected_service: str,
        root_cause_service: str,
        dependency_chain: list[str],
        count: int = 3,
        rng: Optional[random.Random] = None,
    ) -> list[dict]:
        """Generate traces showing errors propagating through the dependency chain.

        Args:
            affected_service: Service where errors are visible
            root_cause_service: Service that is the actual root cause
            dependency_chain: List of services from entry point to root cause
            count: Number of traces to generate
            rng: Random number generator for deterministic output

        Returns:
            List of trace dicts
        """
        if rng is None:
            rng = random.Random()

        traces = []

        for _ in range(count):
            trace_id = "".join(rng.choices(string.ascii_lowercase + string.digits, k=6))
            spans = []

            # Build spans following the dependency chain
            for i, service in enumerate(dependency_chain):
                is_root_cause = service == root_cause_service
                is_affected = service == affected_service

                # Get operation for this service
                service_type = TracesEngine._get_service_type(service)
                operations = TracesEngine._OPERATIONS.get(
                    service, TracesEngine._OPERATIONS.get(service_type, ["process"])
                )
                operation = rng.choice(operations)

                # Determine timing and status
                if is_root_cause:
                    # Root cause has timeout or error
                    duration_ms = (
                        None if rng.random() < 0.3 else rng.randint(5000, 30000)
                    )
                    status = "ERROR"
                    error = TracesEngine._get_error_message(service, rng)
                elif i > dependency_chain.index(root_cause_service):
                    # Spans after root cause won't execute (or will fail fast)
                    continue
                elif is_affected or dependency_chain.index(
                    service
                ) > dependency_chain.index(root_cause_service):
                    # Services affected by the root cause
                    duration_ms = rng.randint(100, 500)
                    status = "ERROR"
                    error = "Dependency failure"
                else:
                    # Services before the root cause in the chain
                    duration_ms = rng.randint(5, 50)
                    status = "OK"
                    error = None

                spans.append(
                    {
                        "service": service,
                        "operation": operation,
                        "duration_ms": duration_ms,
                        "status": status,
                        "error": error,
                        "depth": i,
                    }
                )

            # Possibly add a successful sibling span (to show contrast)
            if len(dependency_chain) > 1 and rng.random() < 0.5:
                sibling_services = ["redis", "cache", "config-service"]
                sibling = rng.choice(sibling_services)
                spans.insert(
                    1,
                    {
                        "service": sibling,
                        "operation": rng.choice(["GET key", "check config", "cache hit"]),
                        "duration_ms": rng.randint(1, 10),
                        "status": "OK",
                        "error": None,
                        "depth": 1,
                    },
                )

            traces.append(
                {
                    "trace_id": trace_id,
                    "spans": spans,
                }
            )

        return traces

    @staticmethod
    def generate_normal_traces(
        services: list[str],
        count: int = 2,
        rng: Optional[random.Random] = None,
    ) -> list[dict]:
        """Generate normal-looking traces for healthy services.

        Args:
            services: List of services to include in traces
            count: Number of traces to generate
            rng: Random number generator for deterministic output

        Returns:
            List of trace dicts
        """
        if rng is None:
            rng = random.Random()

        traces = []

        for _ in range(count):
            trace_id = "".join(rng.choices(string.ascii_lowercase + string.digits, k=6))
            spans = []

            # Use a subset of services for this trace
            trace_services = rng.sample(services, min(len(services), rng.randint(2, 4)))

            for i, service in enumerate(trace_services):
                service_type = TracesEngine._get_service_type(service)
                operations = TracesEngine._OPERATIONS.get(
                    service, TracesEngine._OPERATIONS.get(service_type, ["process"])
                )
                operation = rng.choice(operations)

                # Normal latencies
                if "db" in service or "postgres" in service:
                    duration_ms = rng.randint(5, 50)
                elif "redis" in service or "cache" in service:
                    duration_ms = rng.randint(1, 10)
                elif "gateway" in service:
                    duration_ms = rng.randint(5, 20)
                else:
                    duration_ms = rng.randint(10, 150)

                spans.append(
                    {
                        "service": service,
                        "operation": operation,
                        "duration_ms": duration_ms,
                        "status": "OK",
                        "error": None,
                        "depth": i,
                    }
                )

            traces.append(
                {
                    "trace_id": trace_id,
                    "spans": spans,
                }
            )

        return traces

    @staticmethod
    def _get_service_type(service: str) -> str:
        """Infer service type from service name."""
        service_lower = service.lower()

        if any(db in service_lower for db in ["postgres", "mysql", "db", "database"]):
            return "postgres"
        if any(cache in service_lower for cache in ["redis", "cache", "memcached"]):
            return "redis"
        if "kafka" in service_lower or "queue" in service_lower:
            return "kafka"
        if "gateway" in service_lower or "ingress" in service_lower:
            return "api-gateway"
        if "frontend" in service_lower or "web" in service_lower:
            return "frontend"
        if "auth" in service_lower:
            return "auth-service"
        if "user" in service_lower:
            return "user-service"
        if "order" in service_lower:
            return "order-service"
        if "payment" in service_lower:
            return "payment-service"
        if "notification" in service_lower or "notify" in service_lower:
            return "notification-service"

        return "api-gateway"  # Default

    @staticmethod
    def _get_error_message(service: str, rng: random.Random) -> str:
        """Get an appropriate error message for a service."""
        service_lower = service.lower()

        if any(db in service_lower for db in ["postgres", "mysql", "db", "database"]):
            return rng.choice(TracesEngine._ERRORS["database"])
        if any(cache in service_lower for cache in ["redis", "cache", "memcached"]):
            return rng.choice(TracesEngine._ERRORS["cache"])

        return rng.choice(TracesEngine._ERRORS["service"])
