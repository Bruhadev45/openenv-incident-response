#!/usr/bin/env python3
"""
Pre-submission validator for the OpenEnv competition.

Validates that the environment meets all competition requirements before submission.

Usage:
    python scripts/validate.py [--url http://localhost:8000]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any, Optional

try:
    import requests
except ImportError:
    print("Error: requests library not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_URL = "http://localhost:8000"
TIMEOUT = 30
TASKS = ["triage", "rca", "cascading"]


# ---------------------------------------------------------------------------
# Validation checks
# ---------------------------------------------------------------------------


class ValidationResult:
    """Result of a validation check."""

    def __init__(self, name: str, passed: bool, message: str, details: Optional[str] = None):
        self.name = name
        self.passed = passed
        self.message = message
        self.details = details

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        result = f"[{status}] {self.name}: {self.message}"
        if self.details:
            result += f"\n       {self.details}"
        return result


class Validator:
    """Runs validation checks against the environment."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.results: list[ValidationResult] = []

    def run_all_checks(self) -> bool:
        """Run all validation checks and return True if all pass."""
        print("=" * 60)
        print("OpenEnv Pre-Submission Validator")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print()

        # Run each check
        self.check_openenv_yaml()
        self.check_dockerfile()
        self.check_health_endpoint()
        self.check_tasks_endpoint()
        self.check_reset_endpoint()
        self.check_step_endpoint()
        self.check_grader_endpoint()
        self.check_state_endpoint()
        self.check_all_tasks()
        self.check_determinism()

        # Print results
        print()
        print("-" * 60)
        print("RESULTS:")
        print("-" * 60)

        passed = 0
        failed = 0

        for result in self.results:
            print(result)
            if result.passed:
                passed += 1
            else:
                failed += 1

        print()
        print("-" * 60)
        total = passed + failed
        print(f"Total: {passed}/{total} checks passed")

        if failed == 0:
            print("\nALL CHECKS PASSED - Ready for submission!")
            return True
        else:
            print(f"\n{failed} CHECK(S) FAILED - Please fix before submission.")
            return False

    def _add_result(self, name: str, passed: bool, message: str, details: Optional[str] = None) -> None:
        """Add a validation result."""
        self.results.append(ValidationResult(name, passed, message, details))

    def check_openenv_yaml(self) -> None:
        """Check 1: openenv.yaml exists and has required fields."""
        name = "openenv.yaml"

        # Find the file relative to the script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        yaml_path = os.path.join(project_root, "openenv.yaml")

        if not os.path.exists(yaml_path):
            self._add_result(name, False, "File not found", f"Expected at: {yaml_path}")
            return

        try:
            # Parse YAML (simple parser for our needs)
            with open(yaml_path, "r") as f:
                content = f.read()

            required_fields = ["spec_version", "name", "type", "runtime", "app", "port"]
            missing = []

            for field in required_fields:
                if f"{field}:" not in content:
                    missing.append(field)

            if missing:
                self._add_result(name, False, f"Missing required fields: {missing}")
            else:
                self._add_result(name, True, "File exists with required fields")

        except Exception as e:
            self._add_result(name, False, f"Error reading file: {e}")

    def check_dockerfile(self) -> None:
        """Check 2: Dockerfile exists."""
        name = "Dockerfile"

        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)

        # Check multiple possible locations
        locations = [
            os.path.join(project_root, "Dockerfile"),
            os.path.join(project_root, "incident_response", "server", "Dockerfile"),
        ]

        for path in locations:
            if os.path.exists(path):
                self._add_result(name, True, f"Found at: {path}")
                return

        self._add_result(name, False, "Not found", f"Checked: {locations}")

    def check_health_endpoint(self) -> None:
        """Check 3: Server starts and /health returns 200."""
        name = "/health endpoint"

        try:
            resp = self.session.get(f"{self.base_url}/health", timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "healthy":
                    self._add_result(name, True, "Returns healthy status")
                else:
                    self._add_result(name, False, f"Unexpected response: {data}")
            else:
                self._add_result(name, False, f"HTTP {resp.status_code}")
        except requests.exceptions.ConnectionError:
            self._add_result(name, False, "Cannot connect to server", f"Is server running at {self.base_url}?")
        except Exception as e:
            self._add_result(name, False, f"Error: {e}")

    def check_tasks_endpoint(self) -> None:
        """Check 4: /tasks returns 3+ tasks."""
        name = "/tasks endpoint"

        try:
            resp = self.session.get(f"{self.base_url}/tasks", timeout=TIMEOUT)
            if resp.status_code != 200:
                self._add_result(name, False, f"HTTP {resp.status_code}")
                return

            tasks = resp.json()
            if not isinstance(tasks, list):
                self._add_result(name, False, f"Expected list, got {type(tasks)}")
                return

            if len(tasks) < 3:
                self._add_result(name, False, f"Expected 3+ tasks, got {len(tasks)}")
                return

            # Verify task structure
            required_keys = ["id", "name", "description"]
            for task in tasks:
                missing = [k for k in required_keys if k not in task]
                if missing:
                    self._add_result(name, False, f"Task missing keys: {missing}")
                    return

            task_ids = [t["id"] for t in tasks]
            self._add_result(name, True, f"Returns {len(tasks)} tasks: {task_ids}")

        except Exception as e:
            self._add_result(name, False, f"Error: {e}")

    def check_reset_endpoint(self) -> None:
        """Check 5: /reset returns valid IncidentObservation."""
        name = "/reset endpoint"

        try:
            resp = self.session.post(
                f"{self.base_url}/reset",
                json={"task_id": "triage", "seed": 42},
                timeout=TIMEOUT,
            )

            if resp.status_code != 200:
                self._add_result(name, False, f"HTTP {resp.status_code}", resp.text[:200])
                return

            obs = resp.json()

            # Check required fields
            required = ["alerts", "system_status", "done", "reward", "step_number", "max_steps"]
            missing = [k for k in required if k not in obs]

            if missing:
                self._add_result(name, False, f"Missing fields: {missing}")
                return

            if obs.get("done", True):
                self._add_result(name, False, "Episode should not be done at start")
                return

            if obs.get("step_number", -1) != 0:
                self._add_result(name, False, f"step_number should be 0, got {obs.get('step_number')}")
                return

            self._add_result(name, True, "Returns valid observation")

        except Exception as e:
            self._add_result(name, False, f"Error: {e}")

    def check_step_endpoint(self) -> None:
        """Check 6: /step with valid action returns valid IncidentObservation."""
        name = "/step endpoint"

        try:
            # First reset
            self.session.post(
                f"{self.base_url}/reset",
                json={"task_id": "triage", "seed": 42},
                timeout=TIMEOUT,
            )

            # Then step
            action = {"action_type": "acknowledge"}
            resp = self.session.post(
                f"{self.base_url}/step",
                json=action,
                timeout=TIMEOUT,
            )

            if resp.status_code != 200:
                self._add_result(name, False, f"HTTP {resp.status_code}", resp.text[:200])
                return

            obs = resp.json()

            # Check step incremented
            if obs.get("step_number", 0) != 1:
                self._add_result(name, False, f"step_number should be 1, got {obs.get('step_number')}")
                return

            # Check feedback exists
            if not obs.get("feedback"):
                self._add_result(name, False, "No feedback in observation")
                return

            self._add_result(name, True, "Returns valid observation after action")

        except Exception as e:
            self._add_result(name, False, f"Error: {e}")

    def check_grader_endpoint(self) -> None:
        """Check 7: /grader returns score in [0.0, 1.0]."""
        name = "/grader endpoint"

        try:
            # Reset first
            self.session.post(
                f"{self.base_url}/reset",
                json={"task_id": "triage", "seed": 42},
                timeout=TIMEOUT,
            )

            # Get grader scores
            resp = self.session.get(f"{self.base_url}/grader", timeout=TIMEOUT)

            if resp.status_code != 200:
                self._add_result(name, False, f"HTTP {resp.status_code}", resp.text[:200])
                return

            scores = resp.json()

            if "total" not in scores:
                self._add_result(name, False, "Missing 'total' in scores")
                return

            total = scores["total"]
            if not isinstance(total, (int, float)):
                self._add_result(name, False, f"'total' should be numeric, got {type(total)}")
                return

            if not 0.0 <= total <= 1.0:
                self._add_result(name, False, f"'total' should be in [0,1], got {total}")
                return

            self._add_result(name, True, f"Returns valid scores (total={total:.3f})")

        except Exception as e:
            self._add_result(name, False, f"Error: {e}")

    def check_state_endpoint(self) -> None:
        """Check 8: /state returns valid IncidentState."""
        name = "/state endpoint"

        try:
            # Reset first
            self.session.post(
                f"{self.base_url}/reset",
                json={"task_id": "triage", "seed": 42},
                timeout=TIMEOUT,
            )

            # Get state
            resp = self.session.get(f"{self.base_url}/state", timeout=TIMEOUT)

            if resp.status_code != 200:
                self._add_result(name, False, f"HTTP {resp.status_code}", resp.text[:200])
                return

            state = resp.json()

            # Check required fields
            required = ["episode_id", "task_id", "step_count", "done"]
            missing = [k for k in required if k not in state]

            if missing:
                self._add_result(name, False, f"Missing fields: {missing}")
                return

            self._add_result(name, True, "Returns valid state")

        except Exception as e:
            self._add_result(name, False, f"Error: {e}")

    def check_all_tasks(self) -> None:
        """Check 9: All 3 tasks can be reset and stepped through."""
        name = "All tasks playable"

        failed_tasks = []

        for task_id in TASKS:
            try:
                # Reset
                resp = self.session.post(
                    f"{self.base_url}/reset",
                    json={"task_id": task_id, "seed": 42},
                    timeout=TIMEOUT,
                )
                if resp.status_code != 200:
                    failed_tasks.append(f"{task_id}:reset")
                    continue

                obs = resp.json()
                if obs.get("done"):
                    failed_tasks.append(f"{task_id}:done_at_start")
                    continue

                # Step a few times
                for _ in range(3):
                    if obs.get("done"):
                        break

                    action = {"action_type": "investigate", "tool": "logs", "target": "api-gateway"}
                    resp = self.session.post(
                        f"{self.base_url}/step",
                        json=action,
                        timeout=TIMEOUT,
                    )
                    if resp.status_code != 200:
                        failed_tasks.append(f"{task_id}:step")
                        break
                    obs = resp.json()

            except Exception as e:
                failed_tasks.append(f"{task_id}:{e}")

        if failed_tasks:
            self._add_result(name, False, f"Failed: {failed_tasks}")
        else:
            self._add_result(name, True, f"All {len(TASKS)} tasks can be played")

    def check_determinism(self) -> None:
        """Check 10: Grader scores are deterministic (same seed = same score)."""
        name = "Deterministic scoring"

        try:
            scores = []

            # Run same task/seed twice
            for _ in range(2):
                # Reset
                self.session.post(
                    f"{self.base_url}/reset",
                    json={"task_id": "triage", "seed": 12345},
                    timeout=TIMEOUT,
                )

                # Take same actions
                actions = [
                    {"action_type": "acknowledge"},
                    {"action_type": "investigate", "tool": "logs", "target": "api-gateway"},
                    {"action_type": "classify", "severity": "P2"},
                ]

                for action in actions:
                    self.session.post(
                        f"{self.base_url}/step",
                        json=action,
                        timeout=TIMEOUT,
                    )

                # Get score
                resp = self.session.get(f"{self.base_url}/grader", timeout=TIMEOUT)
                score = resp.json().get("total", -1)
                scores.append(score)

            # Check scores match
            if len(scores) == 2 and scores[0] == scores[1]:
                self._add_result(name, True, f"Same seed produces same score: {scores[0]:.3f}")
            else:
                self._add_result(name, False, f"Scores differ: {scores}")

        except Exception as e:
            self._add_result(name, False, f"Error: {e}")


# ---------------------------------------------------------------------------
# Server launcher
# ---------------------------------------------------------------------------


def start_server_if_needed(base_url: str) -> Optional[subprocess.Popen]:
    """Try to connect to server, start it if needed."""
    try:
        resp = requests.get(f"{base_url}/health", timeout=5)
        if resp.status_code == 200:
            print(f"Server already running at {base_url}")
            return None
    except requests.exceptions.ConnectionError:
        pass

    print(f"Starting server...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    proc = subprocess.Popen(
        [sys.executable, "-m", "incident_response.server.app"],
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to start
    for _ in range(30):
        time.sleep(0.5)
        try:
            resp = requests.get(f"{base_url}/health", timeout=2)
            if resp.status_code == 200:
                print(f"Server started at {base_url}")
                return proc
        except requests.exceptions.ConnectionError:
            continue

    print("Warning: Could not start server automatically")
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the validator."""
    parser = argparse.ArgumentParser(
        description="Pre-submission validator for OpenEnv competition"
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Environment server URL (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Don't try to start server automatically",
    )

    args = parser.parse_args()

    # Try to start server if needed
    server_proc = None
    if not args.no_start:
        server_proc = start_server_if_needed(args.url)

    try:
        # Run validation
        validator = Validator(args.url)
        success = validator.run_all_checks()

        sys.exit(0 if success else 1)

    finally:
        # Cleanup server if we started it
        if server_proc:
            print("\nStopping server...")
            server_proc.terminate()
            server_proc.wait(timeout=5)


if __name__ == "__main__":
    main()
