"""
MalVision - scorer.py
Behavioral scoring engine. Receives AgentEvents, maintains per-host
threat scores, fires alerts when thresholds are crossed.

Scoring philosophy:
- Honeytokens and VSS deletion skip scoring entirely → instant CRITICAL
- Everything else accumulates a score per host over a rolling window
- Score >= ALERT_THRESHOLD → CRITICAL alert
- Score >= WARN_THRESHOLD → WARNING alert
"""

import time
import threading
import collections
from dataclasses import dataclass, field
from typing import Optional

# ─── Thresholds ───────────────────────────────────────────────────────────────

ALERT_THRESHOLD = 2.0    # CRITICAL alert
WARN_THRESHOLD  = 1.0    # WARNING alert
SCORE_WINDOW    = 300    # Rolling 5-minute window (seconds)

# ─── Rule Weights ─────────────────────────────────────────────────────────────
# Weight 1.0 = instant CRITICAL (bypass scoring)
# Weight 0.x = accumulates toward threshold

RULES: dict[str, float] = {
    # Instant CRITICAL — no accumulation needed
    "honeytoken_hit":         1.0,
    "vss_deletion":           1.0,
    "ransom_note":            1.0,

    # High weight — one or two hits should alert
    "entropy_spike":          0.6,
    "rapid_rename":           0.5,
    "rapid_file_opens":       0.4,

    # Medium weight — meaningful in combination
    "ext_change":             0.3,
    "suspicious_spawn":       0.35,
    "backup_process_killed":  0.4,

    # Lower weight — worth tracking, not alarming alone
    "net_lateral":            0.3,
}

INSTANT_CRITICAL = {k for k, v in RULES.items() if v >= 1.0}

# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class ScoredEvent:
    event_type: str
    severity: str
    weight: float
    timestamp: float
    payload: dict


@dataclass
class HostState:
    host: str
    events: collections.deque = field(default_factory=collections.deque)
    alerted: bool = False
    warned: bool = False
    last_score: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_event(self, event: ScoredEvent):
        with self.lock:
            self.events.append(event)
            self._prune()

    def _prune(self):
        cutoff = time.monotonic() - SCORE_WINDOW
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def current_score(self) -> float:
        cutoff = time.monotonic() - SCORE_WINDOW
        with self.lock:
            score = sum(
                e.weight for e in self.events
                if e.timestamp >= cutoff and e.weight < 1.0
            )
            self.last_score = round(score, 3)
            return self.last_score

    def event_summary(self) -> dict[str, int]:
        cutoff = time.monotonic() - SCORE_WINDOW
        with self.lock:
            counts: dict[str, int] = collections.Counter(
                e.event_type for e in self.events
                if e.timestamp >= cutoff
            )
            return dict(counts)

# ─── Scorer ───────────────────────────────────────────────────────────────────

class BehavioralScorer:

    def __init__(self, alert_callback=None):
        """
        alert_callback: callable(host, level, reason, score, event_summary)
        Called when a host crosses WARN or ALERT threshold.
        """
        self.hosts: dict[str, HostState] = {}
        self.lock = threading.Lock()
        self.alert_callback = alert_callback or self._default_callback

    def _get_host(self, host: str) -> HostState:
        with self.lock:
            if host not in self.hosts:
                self.hosts[host] = HostState(host=host)
            return self.hosts[host]

    def _default_callback(self, host, level, reason, score, summary):
        print(f"[{level}] {host} | score={score} | {reason} | {summary}")

    def ingest(self, event: dict) -> dict:
        """
        Process a raw AgentEvent dict.
        Returns a result dict with: action, level, score, reason.
        """
        host       = event.get("host", "unknown")
        event_type = event.get("event_type", "unknown")
        severity   = event.get("severity", "LOW")
        payload    = event.get("payload", {})
        weight     = RULES.get(event_type, 0.1)

        # ── Instant CRITICAL bypass ───────────────────────────────────────────
        if event_type in INSTANT_CRITICAL:
            self.alert_callback(
                host=host,
                level="CRITICAL",
                reason=f"Instant trigger: {event_type}",
                score=1.0,
                summary={event_type: 1},
            )
            return {
                "action":     "CRITICAL",
                "level":      "CRITICAL",
                "score":      1.0,
                "reason":     f"Instant trigger: {event_type}",
                "event_type": event_type,
            }

        # ── Accumulate score ──────────────────────────────────────────────────
        host_state = self._get_host(host)
        scored = ScoredEvent(
            event_type=event_type,
            severity=severity,
            weight=weight,
            timestamp=time.monotonic(),
            payload=payload,
        )
        host_state.add_event(scored)
        score   = host_state.current_score()
        summary = host_state.event_summary()

        # ── Threshold checks ──────────────────────────────────────────────────
        if score >= ALERT_THRESHOLD and not host_state.alerted:
            host_state.alerted = True
            host_state.warned  = True
            self.alert_callback(
                host=host,
                level="CRITICAL",
                reason=f"Score {score:.2f} exceeded alert threshold {ALERT_THRESHOLD}",
                score=score,
                summary=summary,
            )
            return {"action": "CRITICAL", "level": "CRITICAL", "score": score,
                    "reason": f"Threshold crossed: {score:.2f}", "event_type": event_type}

        if score >= WARN_THRESHOLD and not host_state.warned:
            host_state.warned = True
            self.alert_callback(
                host=host,
                level="WARNING",
                reason=f"Score {score:.2f} exceeded warning threshold {WARN_THRESHOLD}",
                score=score,
                summary=summary,
            )
            return {"action": "WARNING", "level": "WARNING", "score": score,
                    "reason": f"Warning threshold crossed: {score:.2f}", "event_type": event_type}

        return {"action": "LOG", "level": "INFO", "score": score,
                "reason": "Accumulating", "event_type": event_type}

    def host_status(self, host: str) -> Optional[dict]:
        with self.lock:
            if host not in self.hosts:
                return None
        state = self.hosts[host]
        return {
            "host":         host,
            "score":        state.current_score(),
            "alerted":      state.alerted,
            "warned":       state.warned,
            "event_summary": state.event_summary(),
            "alert_threshold": ALERT_THRESHOLD,
            "warn_threshold":  WARN_THRESHOLD,
        }

    def all_hosts_status(self) -> list[dict]:
        with self.lock:
            hosts = list(self.hosts.keys())
        return [self.host_status(h) for h in hosts]

    def reset_host(self, host: str):
        """Reset alert state for a host (after human review)."""
        with self.lock:
            if host in self.hosts:
                del self.hosts[host]
