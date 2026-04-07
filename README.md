---
title: SRE Incident Response Environment
emoji: 🚨
colorFrom: red
colorTo: orange
sdk: docker
app_port: 8000
tags:
  - openenv
  - sre
  - incident-response
---

# SRE Incident Response Environment for OpenEnv

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![OpenEnv](https://img.shields.io/badge/OpenEnv-compatible-green.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

A realistic incident response training environment for AI agents. Master the art of production incident handling through three progressive challenges: alert triage, root cause analysis, and cascading failure resolution.

## Why This Environment?

Modern production systems fail in complex, interconnected ways. Training AI agents to handle these incidents requires:

- **Realistic scenarios** modeled after actual production outages
- **Rich observability** with logs, metrics, traces, and dependency maps
- **Progressive difficulty** from simple triage to multi-service cascade resolution
- **Quantitative scoring** across classification, investigation, diagnosis, remediation, and communication

This environment provides all of these, built on a 12-service e-commerce topology that mirrors real-world distributed systems.

## Architecture

```
                                    +-------------------+
                                    |     Frontend      |
                                    +--------+----------+
                                             |
                                    +--------v----------+
                                    |    API Gateway    |
                                    +---+-----+-----+---+
                                        |     |     |
              +-------------------------+     |     +-------------------------+
              |                               |                               |
     +--------v--------+           +----------v---------+           +---------v-------+
     |  Auth Service   |           |   User Service     |           |  Order Service  |
     +---+--------+----+           +----------+---------+           +---+--------+----+
         |        |                           |                         |        |
    +----v--+ +---v---+                  +----v----+                +---v---+ +--v---+
    |Auth DB| | Redis |                  | User DB |                |Order DB| |Kafka|
    +-------+ +-------+                  +---------+                +--------+ +--+--+
                                                                                  |
                                                                          +-------v------+
                                                                          | Order Worker |
                                                                          +-------+------+
                                                                                  |
                                                                          +-------v-------+
                                                                          | Warehouse API |
                                                                          +---------------+
```

## Tasks

### Task 1: Alert Triage (Easy)

**Objective:** Respond to an incoming page and establish initial incident response.

| Attribute | Value |
|-----------|-------|
| Difficulty | Easy |
| Max Steps | 15 |
| Primary Skills | Alert acknowledgment, severity classification, initial communication |

**Goals:**
1. Acknowledge the incoming alert
2. Investigate logs and metrics to understand the scope
3. Classify incident severity (P1-P4)
4. Post initial status update to stakeholders

### Task 2: Root Cause Analysis (Medium)

**Objective:** Trace a production incident to its root cause and apply the correct fix.

| Attribute | Value |
|-----------|-------|
| Difficulty | Medium |
| Max Steps | 20 |
| Primary Skills | Systematic investigation, dependency analysis, targeted remediation |

**Goals:**
1. Investigate multiple services to trace the failure path
2. Identify the root cause service and failure mode
3. Diagnose the specific issue (memory leak, bad deploy, etc.)
4. Apply the correct remediation action
5. Verify fix and communicate resolution

### Task 3: Cascading Failure Resolution (Hard)

**Objective:** Stop a spreading outage, restore services, and manage crisis communication.

| Attribute | Value |
|-----------|-------|
| Difficulty | Hard |
| Max Steps | 30 |
| Primary Skills | Rapid triage, cascade analysis, coordinated recovery |

**Goals:**
1. Rapidly triage multiple simultaneous alerts
2. Trace the cascade to its origin
3. Diagnose root cause under time pressure
4. Apply targeted remediation to stop the spread
5. Coordinate recovery of dependent services
6. Maintain stakeholder communication throughout

## Action Space

| Action | Required Fields | Optional Fields | Description |
|--------|-----------------|-----------------|-------------|
| `acknowledge` | - | - | Acknowledge incident, become primary responder |
| `investigate` | `tool`, `target` | `parameters` | Query observability tools |
| `diagnose` | `root_cause` | `target`, `confidence` | Record root cause hypothesis |
| `classify` | `severity` | - | Set incident severity (P1-P4) |
| `remediate` | `remediation`, `target` | - | Apply fix to a service |
| `communicate` | `message` | - | Post status update |
| `escalate` | - | `target` | Page additional responders |

### Investigation Tools

| Tool | Description | Example Output |
|------|-------------|----------------|
| `logs` | Application logs for a service | Timestamped log entries with ERROR/WARN/INFO levels |
| `metrics` | Service metrics snapshot | Error rate, latency p99, CPU, memory, request rate |
| `traces` | Distributed traces | Dependency calls, latencies, error propagation |
| `deploys` | Recent deployments | Deploy history with status and changes |
| `config` | Configuration state | Config drift detection |
| `dependencies` | Service dependency map | Upstream and downstream service relationships |
| `alerts` | Active alerts for a service | Alert titles, descriptions, and severity |

### Remediation Actions

| Remediation | Description |
|-------------|-------------|
| `rollback` | Revert to previous deployment |
| `restart` | Restart service instances |
| `scale_up` | Add more instances |
| `drain_traffic` | Remove service from load balancer |
| `failover` | Switch to backup/replica |
| `toggle_flag` | Enable/disable feature flag |
| `clear_cache` | Invalidate cache entries |

## Observation Space

Each step returns an `IncidentObservation` with:

| Field | Type | Description |
|-------|------|-------------|
| `alerts` | `list[Alert]` | Active alerts with severity, title, description |
| `investigation_result` | `str` | Output from last investigation action |
| `system_status` | `list[ServiceHealth]` | Health status of all services |
| `timeline` | `list[TimelineEvent]` | Chronological incident timeline |
| `available_actions` | `list[str]` | Valid action types in current state |
| `feedback` | `str` | Feedback on last action |
| `task_id` | `str` | Current task identifier |
| `task_description` | `str` | What the agent should accomplish |
| `done` | `bool` | Whether episode is finished |
| `reward` | `float` | Reward for this step |
| `step_number` | `int` | Current step count |
| `max_steps` | `int` | Maximum allowed steps |

## Reward Function

Scores are computed across five dimensions, weighted and summed:

| Component | Weight | Scoring |
|-----------|--------|---------|
| Classification | 20% | Exact match: 0.2, one-off: 0.1 |
| Investigation | 20% | Optimal (2-3 steps, no waste): 0.2, penalized for excess |
| Diagnosis | 30% | Exact root cause: 0.3, service match: 0.2, category: 0.15 |
| Remediation | 20% | Correct action + target: 0.2, action only: 0.1, wrong: -0.1 |
| Communication | 10% | Based on service mentions, urgency, and clarity |

**Penalties:**
- Time penalty: -0.01 per step
- Wasted actions: -0.05 per irrelevant investigation/remediation

Final score is clamped to [0.0, 1.0].

## Installation

### Option 1: pip install

```bash
# Clone the repository
git clone https://github.com/your-org/openenv-incident-response
cd openenv-incident-response

# Install with dependencies
pip install -e .

# Install baseline dependencies (optional)
pip install -e ".[baseline]"
```

### Option 2: Docker

```bash
# Build the image
docker build -f incident_response/server/Dockerfile -t incident-response .

# Run the container
docker run -p 8000:8000 incident-response
```

### Option 3: HuggingFace Spaces

Deploy directly to HuggingFace Spaces using the provided Dockerfile. The environment is configured for single-session use, ideal for evaluation.

## Usage

### Starting the Server

```bash
# Using the entry point
server

# Or directly with Python
python -m incident_response.server.app

# Or with uvicorn
uvicorn incident_response.server.app:app --host 0.0.0.0 --port 8000
```

### Python Client Example

```python
from incident_response.client import IncidentEnvClient
from incident_response.models import IncidentAction, ActionType, Severity

# Connect to the environment
with IncidentEnvClient("http://localhost:8000") as client:
    # Start a new episode
    obs = client.reset(task_id="rca", seed=42)
    print(f"Task: {obs.task_id}")
    print(f"Alerts: {len(obs.alerts)}")

    # Acknowledge the incident
    action = IncidentAction(action_type=ActionType.ACKNOWLEDGE)
    obs = client.step(action)
    print(f"Feedback: {obs.feedback}")

    # Investigate the primary alert
    alert_service = obs.alerts[0].service
    action = IncidentAction(
        action_type=ActionType.INVESTIGATE,
        tool="logs",
        target=alert_service
    )
    obs = client.step(action)
    print(obs.investigation_result)

    # Check metrics
    action = IncidentAction(
        action_type=ActionType.INVESTIGATE,
        tool="metrics",
        target=alert_service
    )
    obs = client.step(action)

    # Classify severity
    action = IncidentAction(
        action_type=ActionType.CLASSIFY,
        severity=Severity.P2
    )
    obs = client.step(action)

    # ... continue investigation and remediation ...

    # Get final scores
    scores = client.grader()
    print(f"Total score: {scores['total']:.3f}")
```

### Running Inference (OpenEnv Submission)

The `inference.py` script follows the mandatory OpenEnv submission format with `[START]`, `[STEP]`, and `[END]` logging.

```bash
# Set required environment variables
export HF_TOKEN="hf_..."  # Your HuggingFace token
export API_BASE_URL="https://router.huggingface.co/v1"  # LLM API endpoint
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"  # Model to use

# Optional: Set environment server URL if not running locally
export ENV_BASE_URL="http://localhost:8000"

# Run inference
python inference.py
```

**Output Format:**
```
[START] task=triage env=incident_response model=Qwen/Qwen2.5-72B-Instruct
[STEP] step=1 action={"action_type":"acknowledge"} reward=0.10 done=false error=null
[STEP] step=2 action={"action_type":"investigate","tool":"logs","target":"api-gateway"} reward=0.05 done=false error=null
...
[END] success=true steps=5 score=0.65 rewards=0.10,0.05,0.05,0.30,0.00
```

### Running the Legacy Baseline

```bash
# Set your OpenAI API key
export OPENAI_API_KEY="sk-..."

# Run baseline inference
python scripts/baseline.py
```

### Validating Before Submission

```bash
# Run the validator
python scripts/validate.py

# Or with a custom URL
python scripts/validate.py --url http://your-server:8000
```

## Baseline Scores

Baseline performance using GPT-4o with 3 seeds per task:

| Task | Average Score | Min | Max |
|------|---------------|-----|-----|
| Triage | 0.65 | 0.58 | 0.72 |
| RCA | 0.45 | 0.38 | 0.52 |
| Cascading | 0.28 | 0.20 | 0.35 |
| **Overall** | **0.46** | - | - |

*Note: Scores vary by model, prompting strategy, and random seed.*

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/tasks` | List available tasks |
| POST | `/reset` | Start new episode |
| POST | `/step` | Execute action |
| GET | `/state` | Get internal state |
| GET | `/grader` | Get score breakdown |
| POST | `/baseline` | Run baseline inference |

### POST /reset

```json
{
  "task_id": "triage",
  "seed": 42,
  "episode_id": "optional-id"
}
```

### POST /step

```json
{
  "action_type": "investigate",
  "tool": "logs",
  "target": "api-gateway",
  "parameters": {}
}
```

## Project Structure

```
openenv-incident-response/
├── incident_response/
│   ├── __init__.py
│   ├── client.py              # HTTP client for the environment
│   ├── models.py              # Pydantic models (Action, Observation, State)
│   ├── graders/
│   │   ├── __init__.py
│   │   └── base.py            # Scoring logic
│   ├── scenarios/
│   │   ├── __init__.py
│   │   └── service_graph.py   # 12-service e-commerce topology
│   ├── server/
│   │   ├── __init__.py
│   │   ├── app.py             # FastAPI application
│   │   └── Dockerfile         # Container build
│   └── simulation/
│       ├── __init__.py
│       └── logs_engine.py     # Realistic log generation
├── scripts/
│   ├── baseline.py            # GPT-4 baseline agent
│   └── validate.py            # Pre-submission validator
├── tests/
│   └── __init__.py
├── openenv.yaml               # OpenEnv specification
├── pyproject.toml             # Package configuration
└── README.md                  # This file
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=incident_response --cov-report=html

# Lint code
ruff check incident_response/ scripts/
```

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built for the [OpenEnv](https://openenv.org) benchmark competition. Inspired by real-world incident response practices at major tech companies.

---

**Ready to train your agent?** Start the server, connect a client, and see how well your AI can handle production incidents!
