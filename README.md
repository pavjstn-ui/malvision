# MalVision

MalVision is a behavioral ransomware detection system built around host-based telemetry collection and centralized scoring. It monitors filesystem, process, and network activity, detects high-signal behaviors such as honeytoken access and entropy spikes, and exposes a FastAPI engine for scoring, alerting, and operator visibility.

## What It Does

- Monitors filesystem activity for honeytoken access, ransom note drops, extension changes, rename bursts, and high-entropy write patterns
- Monitors process activity for shadow copy deletion, suspicious command execution, backup tampering, and encryption-loop behavior
- Monitors network activity for SMB lateral movement, rapid connection bursts, and suspicious destination ports
- Aggregates events in a FastAPI scoring engine that maintains host threat state and emits alerts
- Supports alert fan-out through webhook, SMTP, and Splunk HEC integrations
- Runs the engine stack in Docker with `docker compose` for repeatable local deployment

## Architecture

```text
 +-------------------+      +-------------------+      +-------------------+
 | Filesystem Agent  |      | Process Agent     |      | Network Agent     |
 | watcher.py        |      | process_monitor.py|      | net_monitor.py    |
 +---------+---------+      +---------+---------+      +---------+---------+
           \                         |                          /
            \                        |                         /
             \                       |                        /
              +----------------------+-----------------------+
                                     |
                                     v
                        +-----------------------------+
                        | FastAPI Scoring Engine      |
                        | /events /status /alerts     |
                        | BehavioralScorer            |
                        +-------------+---------------+
                                      |
                 +--------------------+--------------------+
                 |                    |                    |
                 v                    v                    v
       +----------------+   +--------------------+   +----------------+
       | Alert Channels |   | Event Queue Replay |   | Operator Views |
       | Webhook/SMTP   |   | event_queue.jsonl  |   | Dashboard/API  |
       | Splunk HEC     |   | offline recovery   |   | status checks  |
       +----------------+   +--------------------+   +----------------+
                                      |
                                      v
                        +-----------------------------+
                        | Docker Compose Deployment   |
                        | engine + nginx              |
                        +-----------------------------+
```

## Tech Stack

- Python 3.11
- FastAPI
- Uvicorn
- Pydantic
- Requests
- psutil
- watchdog
- Docker
- Docker Compose
- Nginx

## Quick Start

MalVision uses Docker Compose for the scoring engine and reverse proxy. The detection agents run on monitored hosts and send telemetry to the engine API.

### 1. Start the stack

```bash
docker compose up --build -d
```

This starts:

- `malvision-engine` on port `8000`
- `malvision-nginx` on ports `80` and `443`

### 2. Verify the API

```bash
curl http://127.0.0.1:8000/health
```

Expected response:

```json
{
  "status": "ok",
  "service": "malvision-engine"
}
```

### 3. Point agents to the engine

Set the engine URL on monitored hosts before running the agents:

```bash
export MALVISION_ENGINE_URL=http://127.0.0.1:8000/events
```

Then run the host agents as needed:

```bash
python agent/watcher.py
python agent/process_monitor.py
python agent/net_monitor.py
```

### 4. Stop the stack

```bash
docker compose down
```

## API Endpoints

### `GET /health`

Liveness check for the detection engine.

Example response:

```json
{
  "status": "ok",
  "service": "malvision-engine"
}
```

### `POST /events`

Ingests a single agent event for behavioral scoring.

Example request:

```bash
curl -X POST "http://127.0.0.1:8000/events" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "ws-01",
    "timestamp": "2026-03-08T12:00:00Z",
    "event_type": "entropy_spike",
    "severity": "HIGH",
    "payload": {
      "file_path": "/srv/share/finance.xlsx",
      "entropy": 7.95
    }
  }'
```

Example response:

```json
{
  "status": "ok",
  "result": {
    "action": "score_updated",
    "host": "ws-01",
    "score": 72,
    "level": "high",
    "reason": "entropy_spike"
  }
}
```

### `GET /status`

Returns the current threat state for all tracked hosts.

### `GET /status/{host}`

Returns the current threat state for a single host.

### `GET /alerts`

Returns recent alert records from the in-memory alert log. Supports `limit` as an optional query parameter.

### `POST /reset/{host}`

Clears threat state for a host after analyst review.

### `POST /replay`

Replays locally queued events from `event_queue.jsonl` after engine downtime.

## Deployment Notes

- Docker Compose currently deploys the engine and Nginx reverse proxy
- Agent processes are designed to run on monitored hosts rather than inside the Compose stack
- Alert integrations are configured through environment variables such as `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `MALVISION_WEBHOOK_URL`, `SMTP_HOST`, and `ALERT_EMAIL_TO`

## Project Status

Active development.
