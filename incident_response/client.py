"""
Synchronous HTTP client for the SRE Incident Response Environment.

Provides a simple interface to interact with the environment server
without requiring openenv-core as a dependency.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

from incident_response.models import IncidentAction, IncidentObservation, IncidentState


class IncidentEnvClient:
    """
    Synchronous client for the Incident Response Environment.

    Example usage:
        with IncidentEnvClient("http://localhost:8000") as client:
            obs = client.reset(task_id="triage", seed=42)
            while not obs.done:
                action = IncidentAction(action_type="investigate", tool="logs", target="api-gateway")
                obs = client.step(action)
            state = client.state()
            print(f"Final reward: {state.total_reward}")
    """

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 30.0):
        """
        Initialize the client.

        Args:
            base_url: Base URL of the environment server.
            timeout: Request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def reset(
        self,
        seed: Optional[int] = None,
        task_id: Optional[str] = None,
        episode_id: Optional[str] = None,
    ) -> IncidentObservation:
        """
        Reset the environment and start a new episode.

        Args:
            seed: Random seed for deterministic scenario generation.
            task_id: Task identifier (triage, rca, cascading).
            episode_id: Optional episode identifier for tracking.

        Returns:
            Initial observation for the new episode.
        """
        payload: dict[str, Any] = {}
        if seed is not None:
            payload["seed"] = seed
        if task_id is not None:
            payload["task_id"] = task_id
        if episode_id is not None:
            payload["episode_id"] = episode_id

        resp = self.session.post(
            f"{self.base_url}/reset",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return IncidentObservation(**resp.json())

    def step(self, action: IncidentAction) -> IncidentObservation:
        """
        Execute an action in the environment.

        Args:
            action: The action to execute.

        Returns:
            Observation after executing the action.
        """
        resp = self.session.post(
            f"{self.base_url}/step",
            json=action.model_dump(exclude_none=True),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return IncidentObservation(**resp.json())

    def state(self) -> IncidentState:
        """
        Get the current internal state of the environment.

        Returns:
            Current environment state including ground truth and scores.
        """
        resp = self.session.get(
            f"{self.base_url}/state",
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return IncidentState(**resp.json())

    def health(self) -> dict[str, Any]:
        """
        Check server health status.

        Returns:
            Health status dictionary.
        """
        resp = self.session.get(
            f"{self.base_url}/health",
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def tasks(self) -> list[dict[str, Any]]:
        """
        Get list of available tasks.

        Returns:
            List of task descriptors with id, description, and action schema.
        """
        resp = self.session.get(
            f"{self.base_url}/tasks",
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def grader(self) -> dict[str, float]:
        """
        Get grader score breakdown for the current episode.

        Returns:
            Score breakdown with classification, investigation, diagnosis, etc.
        """
        resp = self.session.get(
            f"{self.base_url}/grader",
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def baseline(self) -> dict[str, float]:
        """
        Trigger baseline inference and get scores.

        Returns:
            Baseline scores for each task.
        """
        resp = self.session.post(
            f"{self.base_url}/baseline",
            timeout=300.0,  # Longer timeout for baseline runs
        )
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self) -> "IncidentEnvClient":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()


class AsyncIncidentEnvClient:
    """
    Asynchronous client for the Incident Response Environment.

    Requires httpx to be installed (pip install httpx).

    Example usage:
        async with AsyncIncidentEnvClient("http://localhost:8000") as client:
            obs = await client.reset(task_id="triage", seed=42)
            while not obs.done:
                action = IncidentAction(action_type="investigate", tool="logs", target="api-gateway")
                obs = await client.step(action)
    """

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 30.0):
        """
        Initialize the async client.

        Args:
            base_url: Base URL of the environment server.
            timeout: Request timeout in seconds.
        """
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for async client. Install with: pip install httpx"
            )

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._httpx = httpx
        self.client: Optional[Any] = None

    async def _get_client(self) -> Any:
        """Get or create the httpx client."""
        if self.client is None:
            self.client = self._httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
        return self.client

    async def reset(
        self,
        seed: Optional[int] = None,
        task_id: Optional[str] = None,
        episode_id: Optional[str] = None,
    ) -> IncidentObservation:
        """Reset the environment and start a new episode."""
        client = await self._get_client()
        payload: dict[str, Any] = {}
        if seed is not None:
            payload["seed"] = seed
        if task_id is not None:
            payload["task_id"] = task_id
        if episode_id is not None:
            payload["episode_id"] = episode_id

        resp = await client.post("/reset", json=payload)
        resp.raise_for_status()
        return IncidentObservation(**resp.json())

    async def step(self, action: IncidentAction) -> IncidentObservation:
        """Execute an action in the environment."""
        client = await self._get_client()
        resp = await client.post("/step", json=action.model_dump(exclude_none=True))
        resp.raise_for_status()
        return IncidentObservation(**resp.json())

    async def state(self) -> IncidentState:
        """Get the current internal state of the environment."""
        client = await self._get_client()
        resp = await client.get("/state")
        resp.raise_for_status()
        return IncidentState(**resp.json())

    async def health(self) -> dict[str, Any]:
        """Check server health status."""
        client = await self._get_client()
        resp = await client.get("/health")
        resp.raise_for_status()
        return resp.json()

    async def tasks(self) -> list[dict[str, Any]]:
        """Get list of available tasks."""
        client = await self._get_client()
        resp = await client.get("/tasks")
        resp.raise_for_status()
        return resp.json()

    async def grader(self) -> dict[str, float]:
        """Get grader score breakdown for the current episode."""
        client = await self._get_client()
        resp = await client.get("/grader")
        resp.raise_for_status()
        return resp.json()

    async def close(self) -> None:
        """Close the HTTP client."""
        if self.client is not None:
            await self.client.aclose()
            self.client = None

    async def __aenter__(self) -> "AsyncIncidentEnvClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.close()
