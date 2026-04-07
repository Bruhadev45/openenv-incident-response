"""
Service graph modeling for e-commerce topology.

Defines the relationships between services, their baseline metrics,
and provides utilities for simulating cascading failures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ServiceType(str, Enum):
    """Types of services in the topology."""

    FRONTEND = "frontend"
    API = "api"
    WORKER = "worker"
    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"
    EXTERNAL = "external"


@dataclass
class BaselineMetrics:
    """Baseline performance metrics for a service."""

    error_rate: float = 0.001
    latency_p99_ms: float = 100.0
    request_rate: float = 1000.0


@dataclass
class ServiceNode:
    """A node in the service graph representing a single service."""

    name: str
    service_type: ServiceType
    dependencies: list[str] = field(default_factory=list)
    baseline_metrics: BaselineMetrics = field(default_factory=BaselineMetrics)

    def __hash__(self) -> int:
        return hash(self.name)


class ServiceGraph:
    """
    Models a service topology with dependency relationships.

    Provides utilities for:
    - Finding upstream/downstream services
    - Simulating cascading failure propagation
    - Generating health status based on failures
    """

    def __init__(self) -> None:
        self._services: dict[str, ServiceNode] = {}

    def add_service(self, service: ServiceNode) -> None:
        """Add a service to the graph."""
        self._services[service.name] = service

    def get_service(self, name: str) -> Optional[ServiceNode]:
        """Get a service by name."""
        return self._services.get(name)

    def get_all_services(self) -> list[ServiceNode]:
        """Get all services in the graph."""
        return list(self._services.values())

    def get_service_names(self) -> list[str]:
        """Get all service names."""
        return list(self._services.keys())

    def get_dependencies(self, service_name: str) -> list[str]:
        """Get direct dependencies of a service (services it calls)."""
        service = self._services.get(service_name)
        if service is None:
            return []
        return list(service.dependencies)

    def get_dependents(self, service_name: str) -> list[str]:
        """
        Find services that depend on the given service (upstream services).

        Returns a list of service names that call this service.
        """
        dependents: list[str] = []
        for svc in self._services.values():
            if service_name in svc.dependencies:
                dependents.append(svc.name)
        return dependents

    def get_all_dependents_recursive(self, service_name: str) -> dict[str, int]:
        """
        Find all services that transitively depend on the given service.

        Returns dict mapping service name to graph distance from failed service.
        """
        result: dict[str, int] = {}
        queue: list[tuple[str, int]] = [(service_name, 0)]
        visited: set[str] = set()

        while queue:
            current, distance = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current != service_name:
                result[current] = distance

            for dependent in self.get_dependents(current):
                if dependent not in visited:
                    queue.append((dependent, distance + 1))

        return result

    def propagate_failure(
        self, failed_service: str, failure_type: str
    ) -> dict[str, dict[str, float]]:
        """
        Simulate cascading impact when a service fails.

        Args:
            failed_service: Name of the service that failed
            failure_type: Type of failure (e.g., "latency", "errors", "down")

        Returns:
            Dict mapping service name to impact metrics:
            {
                "service-name": {
                    "error_rate_multiplier": float,
                    "latency_multiplier": float,
                    "distance": int
                }
            }
        """
        impact: dict[str, dict[str, float]] = {}

        # Get all services that depend on the failed service
        dependents = self.get_all_dependents_recursive(failed_service)

        # Define base impact based on failure type
        if failure_type == "down":
            base_error_multiplier = 500.0  # 50% of requests fail
            base_latency_multiplier = 10.0  # Timeouts cause high latency
        elif failure_type == "latency":
            base_error_multiplier = 10.0  # Some timeouts
            base_latency_multiplier = 20.0  # Latency cascades
        elif failure_type == "errors":
            base_error_multiplier = 100.0  # Error rate spikes
            base_latency_multiplier = 2.0  # Slight latency from retries
        else:
            base_error_multiplier = 50.0
            base_latency_multiplier = 5.0

        # Impact on the failed service itself
        failed_svc = self._services.get(failed_service)
        if failed_svc:
            impact[failed_service] = {
                "error_rate_multiplier": base_error_multiplier,
                "latency_multiplier": base_latency_multiplier,
                "distance": 0,
            }

        # Propagate impact to dependent services with decay
        for svc_name, distance in dependents.items():
            # Impact diminishes with distance
            decay_factor = 0.5**distance
            impact[svc_name] = {
                "error_rate_multiplier": max(1.0, base_error_multiplier * decay_factor),
                "latency_multiplier": max(1.0, base_latency_multiplier * decay_factor),
                "distance": distance,
            }

        return impact

    @classmethod
    def create_ecommerce(cls) -> "ServiceGraph":
        """
        Create the standard 12-service e-commerce topology.

        Topology:
        frontend -> api-gateway -> [auth-service, user-service, order-service]
                                        |              |              |
                                     auth-db        user-db       order-db
                                        |                            |
                                      redis                       kafka -> order-worker -> warehouse-api
        """
        graph = cls()

        # Define latency baselines by service type
        type_latency: dict[ServiceType, float] = {
            ServiceType.FRONTEND: 200.0,
            ServiceType.API: 150.0,
            ServiceType.WORKER: 500.0,
            ServiceType.DATABASE: 50.0,
            ServiceType.CACHE: 5.0,
            ServiceType.QUEUE: 20.0,
            ServiceType.EXTERNAL: 300.0,
        }

        # Frontend tier
        graph.add_service(
            ServiceNode(
                name="frontend",
                service_type=ServiceType.FRONTEND,
                dependencies=["api-gateway"],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.001,
                    latency_p99_ms=type_latency[ServiceType.FRONTEND],
                    request_rate=2000.0,
                ),
            )
        )

        # API Gateway tier
        graph.add_service(
            ServiceNode(
                name="api-gateway",
                service_type=ServiceType.API,
                dependencies=["auth-service", "user-service", "order-service"],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.001,
                    latency_p99_ms=type_latency[ServiceType.API],
                    request_rate=5000.0,
                ),
            )
        )

        # Auth service and its dependencies
        graph.add_service(
            ServiceNode(
                name="auth-service",
                service_type=ServiceType.API,
                dependencies=["auth-db", "redis"],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.001,
                    latency_p99_ms=100.0,
                    request_rate=3000.0,
                ),
            )
        )

        graph.add_service(
            ServiceNode(
                name="auth-db",
                service_type=ServiceType.DATABASE,
                dependencies=[],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.0001,
                    latency_p99_ms=type_latency[ServiceType.DATABASE],
                    request_rate=3000.0,
                ),
            )
        )

        graph.add_service(
            ServiceNode(
                name="redis",
                service_type=ServiceType.CACHE,
                dependencies=[],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.0001,
                    latency_p99_ms=type_latency[ServiceType.CACHE],
                    request_rate=10000.0,
                ),
            )
        )

        # User service and its dependencies
        graph.add_service(
            ServiceNode(
                name="user-service",
                service_type=ServiceType.API,
                dependencies=["user-db"],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.001,
                    latency_p99_ms=80.0,
                    request_rate=2000.0,
                ),
            )
        )

        graph.add_service(
            ServiceNode(
                name="user-db",
                service_type=ServiceType.DATABASE,
                dependencies=[],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.0001,
                    latency_p99_ms=type_latency[ServiceType.DATABASE],
                    request_rate=2000.0,
                ),
            )
        )

        # Order service and its dependencies
        graph.add_service(
            ServiceNode(
                name="order-service",
                service_type=ServiceType.API,
                dependencies=["order-db", "kafka"],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.001,
                    latency_p99_ms=120.0,
                    request_rate=1500.0,
                ),
            )
        )

        graph.add_service(
            ServiceNode(
                name="order-db",
                service_type=ServiceType.DATABASE,
                dependencies=[],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.0001,
                    latency_p99_ms=type_latency[ServiceType.DATABASE],
                    request_rate=1500.0,
                ),
            )
        )

        graph.add_service(
            ServiceNode(
                name="kafka",
                service_type=ServiceType.QUEUE,
                dependencies=[],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.0001,
                    latency_p99_ms=type_latency[ServiceType.QUEUE],
                    request_rate=5000.0,
                ),
            )
        )

        # Order worker and warehouse
        graph.add_service(
            ServiceNode(
                name="order-worker",
                service_type=ServiceType.WORKER,
                dependencies=["kafka", "warehouse-api"],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.002,
                    latency_p99_ms=type_latency[ServiceType.WORKER],
                    request_rate=500.0,
                ),
            )
        )

        graph.add_service(
            ServiceNode(
                name="warehouse-api",
                service_type=ServiceType.EXTERNAL,
                dependencies=[],
                baseline_metrics=BaselineMetrics(
                    error_rate=0.005,
                    latency_p99_ms=type_latency[ServiceType.EXTERNAL],
                    request_rate=500.0,
                ),
            )
        )

        return graph
