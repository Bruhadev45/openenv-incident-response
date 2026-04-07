"""
Metrics simulation engine for generating realistic time-series data.

Formats pre-generated metric data into human-readable dashboard views that
LLM agents can interpret during incident investigation.
"""

from __future__ import annotations

import random
from typing import Optional


class MetricsEngine:
    """Formats metrics data into readable time-series summaries."""

    # Metric thresholds for visual indicators
    _THRESHOLDS = {
        "error_rate": {"warning": 1.0, "critical": 5.0},  # percentage
        "latency_p99": {"warning": 200, "critical": 1000},  # ms
        "request_rate": {"warning_low": 0.5, "critical_low": 0.2},  # ratio of baseline
        "cpu_percent": {"warning": 70, "critical": 90},  # percentage
        "memory_percent": {"warning": 75, "critical": 90},  # percentage
        "connection_count": {"warning": 80, "critical": 95},  # percentage of max
        "queue_depth": {"warning": 100, "critical": 500},  # count
        "gc_pause_ms": {"warning": 100, "critical": 500},  # ms
    }

    # Baseline values by service type
    _BASELINES = {
        "api": {
            "error_rate": 0.1,
            "latency_p99": 50,
            "request_rate": 1000,
            "cpu_percent": 25,
            "memory_percent": 40,
        },
        "database": {
            "error_rate": 0.01,
            "latency_p99": 20,
            "request_rate": 5000,
            "cpu_percent": 35,
            "memory_percent": 60,
        },
        "cache": {
            "error_rate": 0.001,
            "latency_p99": 5,
            "request_rate": 10000,
            "cpu_percent": 15,
            "memory_percent": 70,
        },
        "worker": {
            "error_rate": 0.1,
            "latency_p99": 500,
            "request_rate": 100,
            "cpu_percent": 45,
            "memory_percent": 50,
        },
        "gateway": {
            "error_rate": 0.05,
            "latency_p99": 30,
            "request_rate": 2000,
            "cpu_percent": 20,
            "memory_percent": 35,
        },
    }

    @staticmethod
    def format_metrics(metrics: dict[str, list[float]], service: str) -> str:
        """Format metric time-series into a human-readable dashboard view.

        Args:
            metrics: Dict mapping metric_name -> list of values (1 min intervals)
            service: Service name for the header

        Returns:
            Formatted dashboard view string
        """
        if not metrics:
            return f"=== Metrics for {service} (no data available) ===\n"

        # Determine time range from longest metric series
        max_points = max(len(v) for v in metrics.values()) if metrics else 0
        if max_points == 0:
            return f"=== Metrics for {service} (no data points) ===\n"

        lines = [f"=== Metrics for {service} (last {max_points} minutes) ===", ""]

        # Format each metric as a row
        for metric_name, values in metrics.items():
            if not values:
                continue

            # Format values based on metric type
            formatted_values = MetricsEngine._format_metric_values(metric_name, values)

            # Generate indicator line
            indicators = MetricsEngine._generate_indicators(metric_name, values)

            # Pad metric name for alignment
            name_padded = f"{metric_name}:".ljust(18)

            lines.append(f"{name_padded} {formatted_values}")
            lines.append(f"{''.ljust(18)} {indicators}")

        # Add legend
        lines.extend(["", "Legend: ---- normal  ~~~~ warning  ^^^^^ critical"])

        return "\n".join(lines)

    @staticmethod
    def _format_metric_values(metric_name: str, values: list[float]) -> str:
        """Format metric values with appropriate units."""
        formatted = []

        for v in values:
            if "rate" in metric_name and "request" not in metric_name:
                # Percentage values (error_rate, etc.)
                formatted.append(f"{v:.1f}%")
            elif "latency" in metric_name or "ms" in metric_name:
                # Millisecond values
                if v >= 1000:
                    formatted.append(f"{int(v)}ms")
                else:
                    formatted.append(f"{int(v)}ms")
            elif "percent" in metric_name:
                # Percentage values
                formatted.append(f"{int(v)}%")
            elif "request_rate" in metric_name:
                # Request rate (rps)
                formatted.append(str(int(v)))
            else:
                # Generic numeric
                if v >= 1000:
                    formatted.append(f"{v/1000:.1f}k")
                elif v == int(v):
                    formatted.append(str(int(v)))
                else:
                    formatted.append(f"{v:.1f}")

        return " ".join(formatted)

    @staticmethod
    def _generate_indicators(metric_name: str, values: list[float]) -> str:
        """Generate visual indicators for each value."""
        indicators = []

        # Get thresholds for this metric type
        thresholds = None
        for key in MetricsEngine._THRESHOLDS:
            if key in metric_name:
                thresholds = MetricsEngine._THRESHOLDS[key]
                break

        if thresholds is None:
            # Default: all normal
            return " ".join(["----"] * len(values))

        # Check for "low" thresholds (like request_rate drop)
        is_low_threshold = "warning_low" in thresholds

        for v in values:
            if is_low_threshold:
                # For metrics where LOW is bad (request_rate)
                # These thresholds are ratios, so we need baseline context
                # For simplicity, use absolute thresholds
                if "request_rate" in metric_name:
                    if v < 200:
                        indicators.append("^^^^^")
                    elif v < 500:
                        indicators.append("~~~~~")
                    else:
                        indicators.append("-----")
                else:
                    indicators.append("-----")
            else:
                # For metrics where HIGH is bad
                warning = thresholds.get("warning", float("inf"))
                critical = thresholds.get("critical", float("inf"))

                if v >= critical:
                    indicators.append("^^^^^")
                elif v >= warning:
                    indicators.append("~~~~~")
                else:
                    indicators.append("-----")

        # Match width of formatted values approximately
        return " ".join(indicators)

    @staticmethod
    def generate_normal_metrics(
        service_type: str,
        duration_min: int = 15,
        rng: Optional[random.Random] = None,
    ) -> dict[str, list[float]]:
        """Generate normal metric time-series for a healthy service.

        Args:
            service_type: Type of service (api, database, cache, worker, gateway)
            duration_min: Number of minutes of data to generate
            rng: Random number generator for deterministic output

        Returns:
            Dict mapping metric_name -> list of values
        """
        if rng is None:
            rng = random.Random()

        baselines = MetricsEngine._BASELINES.get(
            service_type, MetricsEngine._BASELINES["api"]
        )

        metrics: dict[str, list[float]] = {
            "error_rate": [],
            "latency_p99": [],
            "request_rate": [],
            "cpu_percent": [],
            "memory_percent": [],
        }

        for _ in range(duration_min):
            # Add small random variance to baselines (normal operation)
            variance_factor = rng.uniform(0.9, 1.1)

            metrics["error_rate"].append(
                max(0, baselines["error_rate"] * rng.uniform(0.5, 1.5))
            )
            metrics["latency_p99"].append(
                baselines["latency_p99"] * variance_factor
            )
            metrics["request_rate"].append(
                baselines["request_rate"] * rng.uniform(0.95, 1.05)
            )
            metrics["cpu_percent"].append(
                baselines["cpu_percent"] * rng.uniform(0.9, 1.15)
            )
            metrics["memory_percent"].append(
                baselines["memory_percent"] * rng.uniform(0.98, 1.02)
            )

        return metrics

    @staticmethod
    def generate_anomalous_metrics(
        service_type: str,
        anomaly_type: str,
        duration_min: int = 15,
        onset_min: int = 10,
        rng: Optional[random.Random] = None,
    ) -> dict[str, list[float]]:
        """Generate metrics with an anomaly starting at onset_min.

        Args:
            service_type: Type of service (api, database, cache, worker, gateway)
            anomaly_type: Type of anomaly (latency_spike, error_spike,
                          resource_exhaustion, traffic_surge, service_down)
            duration_min: Total minutes of data to generate
            onset_min: Minute when the anomaly begins
            rng: Random number generator for deterministic output

        Returns:
            Dict mapping metric_name -> list of values
        """
        if rng is None:
            rng = random.Random()

        baselines = MetricsEngine._BASELINES.get(
            service_type, MetricsEngine._BASELINES["api"]
        )

        metrics: dict[str, list[float]] = {
            "error_rate": [],
            "latency_p99": [],
            "request_rate": [],
            "cpu_percent": [],
            "memory_percent": [],
        }

        for minute in range(duration_min):
            is_anomaly_phase = minute >= onset_min
            anomaly_progress = (
                (minute - onset_min) / max(1, duration_min - onset_min)
                if is_anomaly_phase
                else 0
            )

            if is_anomaly_phase:
                # Apply anomaly patterns
                anomaly_values = MetricsEngine._apply_anomaly(
                    baselines, anomaly_type, anomaly_progress, rng
                )
                metrics["error_rate"].append(anomaly_values["error_rate"])
                metrics["latency_p99"].append(anomaly_values["latency_p99"])
                metrics["request_rate"].append(anomaly_values["request_rate"])
                metrics["cpu_percent"].append(anomaly_values["cpu_percent"])
                metrics["memory_percent"].append(anomaly_values["memory_percent"])
            else:
                # Normal values before anomaly
                variance = rng.uniform(0.95, 1.05)
                metrics["error_rate"].append(
                    baselines["error_rate"] * rng.uniform(0.8, 1.2)
                )
                metrics["latency_p99"].append(baselines["latency_p99"] * variance)
                metrics["request_rate"].append(baselines["request_rate"] * variance)
                metrics["cpu_percent"].append(
                    baselines["cpu_percent"] * rng.uniform(0.9, 1.1)
                )
                metrics["memory_percent"].append(
                    baselines["memory_percent"] * rng.uniform(0.98, 1.02)
                )

        return metrics

    @staticmethod
    def _apply_anomaly(
        baselines: dict[str, float],
        anomaly_type: str,
        progress: float,
        rng: random.Random,
    ) -> dict[str, float]:
        """Apply anomaly patterns to baseline values.

        Args:
            baselines: Baseline metric values
            anomaly_type: Type of anomaly
            progress: How far into the anomaly (0.0 to 1.0)
            rng: Random number generator

        Returns:
            Anomalous metric values
        """
        # Start with baseline + small variance
        values = {
            "error_rate": baselines["error_rate"],
            "latency_p99": baselines["latency_p99"],
            "request_rate": baselines["request_rate"],
            "cpu_percent": baselines["cpu_percent"],
            "memory_percent": baselines["memory_percent"],
        }

        # Escalation factor increases with progress
        escalation = 1 + (progress * 10)  # 1x to 11x
        noise = rng.uniform(0.9, 1.1)

        if anomaly_type == "latency_spike":
            # Latency increases dramatically, errors follow
            values["latency_p99"] = baselines["latency_p99"] * escalation * 20 * noise
            values["error_rate"] = min(
                100, baselines["error_rate"] + (progress * 30) * noise
            )
            values["cpu_percent"] = min(
                99, baselines["cpu_percent"] * (1 + progress * 0.5)
            )

        elif anomaly_type == "error_spike":
            # Errors spike, latency increases moderately
            values["error_rate"] = min(100, progress * 50 * noise + baselines["error_rate"])
            values["latency_p99"] = baselines["latency_p99"] * (1 + progress * 5) * noise
            values["request_rate"] = baselines["request_rate"] * (1 - progress * 0.3)

        elif anomaly_type == "resource_exhaustion":
            # CPU/memory climb, then errors spike
            values["cpu_percent"] = min(99, baselines["cpu_percent"] + progress * 60)
            values["memory_percent"] = min(
                99, baselines["memory_percent"] + progress * 45
            )
            values["latency_p99"] = baselines["latency_p99"] * (1 + progress * 10) * noise
            values["error_rate"] = baselines["error_rate"] + (progress ** 2) * 40

        elif anomaly_type == "traffic_surge":
            # Request rate spikes, then resources and errors follow
            values["request_rate"] = baselines["request_rate"] * (1 + progress * 5) * noise
            values["cpu_percent"] = min(
                99, baselines["cpu_percent"] * (1 + progress * 2)
            )
            values["memory_percent"] = min(
                99, baselines["memory_percent"] * (1 + progress * 1.5)
            )
            values["latency_p99"] = baselines["latency_p99"] * (1 + progress * 8)
            values["error_rate"] = baselines["error_rate"] + (progress ** 2) * 25

        elif anomaly_type == "service_down":
            # Abrupt failure: requests drop, errors spike to 100%
            values["request_rate"] = baselines["request_rate"] * max(0.05, 1 - progress)
            values["error_rate"] = min(100, 50 + progress * 50)
            values["latency_p99"] = (
                baselines["latency_p99"] * 100 if progress > 0.5 else 30000
            )  # timeout

        return values
