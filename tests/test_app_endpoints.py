from __future__ import annotations

from fastapi.testclient import TestClient

from incident_response.server.app import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_tasks_endpoint_lists_all_tasks() -> None:
    response = client.get("/tasks")

    assert response.status_code == 200
    task_ids = [task["id"] for task in response.json()]
    assert task_ids == ["triage", "rca", "cascading"]


def test_reset_and_step_flow() -> None:
    reset_response = client.post("/reset", json={"task_id": "triage", "seed": 42})
    reset_payload = reset_response.json()

    assert reset_response.status_code == 200
    assert reset_payload["done"] is False
    assert reset_payload["step_number"] == 0

    step_response = client.post("/step", json={"action_type": "acknowledge"})
    step_payload = step_response.json()

    assert step_response.status_code == 200
    assert step_payload["step_number"] == 1
    assert step_payload["feedback"]
