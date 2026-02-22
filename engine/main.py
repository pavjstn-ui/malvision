"""
MalVision - main.py
FastAPI detection engine. Receives AgentEvents from watcher.py and
process_monitor.py, runs them through the behavioral scorer, fires alerts.

Endpoints:
  POST /events          — ingest agent event
  GET  /status          — all host threat scores
  GET  /status/{host}   — single host status
  GET  /alerts          — recent alerts log
  POST /reset/{host}    — reset host after review
  GET  /health          — liveness check
"""

import os
import json
import logging
import threading
import collections
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from scorer import BehavioralScorer

# ─── Config ───────────────────────────────────────────────────────────────────

SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
WEBHOOK_URL      = os.getenv("MALVISION_WEBHOOK_URL", "")
SMTP_HOST        = os.getenv("SMTP_HOST", "")
SMTP_PORT        = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER        = os.getenv("SMTP_USER", "")
SMTP_PASS        = os.getenv("SMTP_PASS", "")
ALERT_EMAIL_TO   = os.getenv("ALERT_EMAIL_TO", "")

MAX_ALERTS_LOG   = 500   # Keep last N alerts in memory

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("malvision.engine")

# ─── Alert Log ────────────────────────────────────────────────────────────────

alerts_log: collections.deque = collections.deque(maxlen=MAX_ALERTS_LOG)
alerts_lock = threading.Lock()

def record_alert(host, level, reason, score, summary):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host":      host,
        "level":     level,
        "reason":    reason,
        "score":     score,
        "summary":   summary,
    }
    with alerts_lock:
        alerts_log.appendleft(entry)

    log.warning(f"[{level}] {host} | {reason} | events={summary}")

    # Fire all alert channels concurrently
    threading.Thread(target=_dispatch_alerts, args=(entry,), daemon=True).start()

def _dispatch_alerts(entry: dict):
    if SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN:
        _send_splunk(entry)
    if WEBHOOK_URL:
        _send_webhook(entry)
    if SMTP_HOST and ALERT_EMAIL_TO:
        _send_email(entry)

# ─── Alert Channels ───────────────────────────────────────────────────────────

def _send_splunk(entry: dict):
    try:
        payload = {
            "time":       entry["timestamp"],
            "sourcetype": "malvision:alert",
            "source":     "malvision-engine",
            "host":       entry["host"],
            "event":      entry,
        }
        resp = requests.post(
            SPLUNK_HEC_URL,
            headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
            json=payload,
            timeout=5,
        )
        if resp.status_code != 200:
            log.warning(f"Splunk HEC returned {resp.status_code}: {resp.text}")
        else:
            log.info("Alert sent to Splunk")
    except Exception as e:
        log.error(f"Splunk send failed: {e}")


def _send_webhook(entry: dict):
    try:
        resp = requests.post(WEBHOOK_URL, json=entry, timeout=5)
        if resp.status_code not in (200, 201, 204):
            log.warning(f"Webhook returned {resp.status_code}")
        else:
            log.info("Alert sent to webhook")
    except Exception as e:
        log.error(f"Webhook send failed: {e}")


def _send_email(entry: dict):
    try:
        subject = f"[MalVision {entry['level']}] {entry['host']} — {entry['reason']}"
        body = (
            f"MalVision Ransomware Alert\n"
            f"{'='*50}\n"
            f"Host:    {entry['host']}\n"
            f"Level:   {entry['level']}\n"
            f"Time:    {entry['timestamp']}\n"
            f"Score:   {entry['score']}\n"
            f"Reason:  {entry['reason']}\n"
            f"Events:  {json.dumps(entry['summary'], indent=2)}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL_TO

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        log.info(f"Alert email sent to {ALERT_EMAIL_TO}")
    except Exception as e:
        log.error(f"Email send failed: {e}")

# ─── Scorer ───────────────────────────────────────────────────────────────────

scorer = BehavioralScorer(alert_callback=record_alert)

# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="MalVision Detection Engine",
    description="Behavioral ransomware detection for Czech/Slovak SMBs",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Request Models ───────────────────────────────────────────────────────────

class AgentEvent(BaseModel):
    host: str
    timestamp: str
    event_type: str
    severity: str
    payload: dict

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "malvision-engine"}


@app.post("/events")
def ingest_event(event: AgentEvent):
    """Receive event from agent, score it, fire alerts if needed."""
    result = scorer.ingest(event.model_dump())
    log.info(f"Event ingested: {event.event_type} from {event.host} → {result['action']}")
    return {"status": "ok", "result": result}


@app.get("/status")
def all_status():
    """Threat scores for all known hosts."""
    return {"hosts": scorer.all_hosts_status()}


@app.get("/status/{host}")
def host_status(host: str):
    """Threat score for a specific host."""
    status = scorer.host_status(host)
    if not status:
        raise HTTPException(status_code=404, detail=f"Host '{host}' not seen yet")
    return status


@app.get("/alerts")
def get_alerts(limit: int = 50):
    """Recent alerts log."""
    with alerts_lock:
        return {"alerts": list(alerts_log)[:limit]}


@app.post("/reset/{host}")
def reset_host(host: str):
    """Reset alert state for a host after human review."""
    scorer.reset_host(host)
    log.info(f"Host {host} reset by operator")
    return {"status": "ok", "host": host, "message": "Alert state cleared"}


@app.post("/replay")
def replay_queue():
    """
    Replay events from event_queue.jsonl (queued when engine was offline).
    Run this after engine starts to catch up on missed events.
    """
    queue_file = "event_queue.jsonl"
    if not __import__("os").path.exists(queue_file):
        return {"status": "ok", "replayed": 0, "message": "No queue file found"}

    replayed = 0
    errors = 0
    with open(queue_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event_dict = json.loads(line)
                scorer.ingest(event_dict)
                replayed += 1
            except Exception as e:
                log.error(f"Replay error: {e}")
                errors += 1

    # Archive the queue
    __import__("os").rename(queue_file, f"{queue_file}.replayed")
    log.info(f"Replayed {replayed} queued events ({errors} errors)")
    return {"status": "ok", "replayed": replayed, "errors": errors}
