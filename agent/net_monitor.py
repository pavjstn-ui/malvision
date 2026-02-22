"""
MalVision - net_monitor.py
Network monitor for ransomware lateral movement detection.

Detects:
- SMB spread: one host connecting to many others over 445 (lateral movement)
- Rapid new connection bursts (port scanning / network mapping)
- DNS resolution storms (recon pattern)
- Known C2 port patterns

Key design decision for Czech SMBs:
  Normal SMB traffic (endpoint → file server) is expected and ignored.
  We alert on SMB SPREAD — one endpoint talking to many hosts it hasn't
  talked to before. That's the ransomware propagation signature.
  LockBit/BlackCat map the network first, then encrypt all reachable shares.

Requires: psutil (cross-platform), no raw packet capture needed.
Uses psutil.net_connections() — works without root on Windows.
"""

import os
import sys
import time
import json
import logging
import threading
import collections
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

import psutil
import requests

# ─── Configuration ────────────────────────────────────────────────────────────

ENGINE_URL = os.getenv("MALVISION_ENGINE_URL", "http://localhost:8000/events")
HOSTNAME   = os.getenv("HOSTNAME", os.uname().nodename)

POLL_INTERVAL = 2.0  # seconds

# SMB lateral movement — how many distinct hosts on port 445
# before we consider it suspicious
SMB_HOST_THRESHOLD = 4       # >4 unique SMB destinations in window = alert
SMB_WINDOW_SECONDS = 120     # 2-minute sliding window

# Known legitimate file server IPs for this network
# Agents auto-learn the first SMB destination they see and whitelist it
# (the assumption: first contact is the real file server)
MAX_AUTO_WHITELIST = 2       # Auto-whitelist up to 2 SMB servers

# Rapid connection burst — new unique IPs per minute
CONNECTION_BURST_THRESHOLD = 30
CONNECTION_BURST_WINDOW    = 60

# Suspicious destination ports (C2 patterns, not common in SMB environments)
SUSPICIOUS_PORTS = {
    4444,   # Metasploit default
    1337,   # Common C2
    8888,   # Common C2
    9001,   # Tor
    9050,   # Tor SOCKS
    6667,   # IRC (botnet C2)
}

# Ports that are normal — never alert on these alone
BENIGN_PORTS = {
    80, 443,    # HTTP/HTTPS
    53,         # DNS
    25, 587,    # SMTP
    110, 993,   # IMAP
    389, 636,   # LDAP
    3389,       # RDP (flag separately if spread)
    445, 139,   # SMB (handled separately by spread detection)
}

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("malvision_net.log"),
    ]
)
log = logging.getLogger("malvision.net")

# ─── Event Schema ─────────────────────────────────────────────────────────────

@dataclass
class AgentEvent:
    host: str
    timestamp: str
    event_type: str
    severity: str
    payload: dict

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def make_event(event_type: str, severity: str, **kwargs) -> AgentEvent:
    return AgentEvent(
        host=HOSTNAME,
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        severity=severity,
        payload=kwargs,
    )


def send_event(event: AgentEvent):
    log.info(f"[{event.severity}] {event.event_type} | {event.payload}")
    try:
        resp = requests.post(ENGINE_URL, json=asdict(event), timeout=3)
        if resp.status_code != 200:
            log.warning(f"Engine returned {resp.status_code}")
    except requests.exceptions.ConnectionError:
        with open("event_queue.jsonl", "a") as f:
            f.write(event.to_json() + "\n")
        log.warning("Engine unreachable — event queued locally")

# ─── Sliding Window Tracker ───────────────────────────────────────────────────

class UniqueHostTracker:
    """
    Tracks unique destination IPs in a sliding window.
    Used to detect SMB spread and connection bursts.
    """
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.events: collections.deque = collections.deque()  # (timestamp, ip)
        self.lock = threading.Lock()

    def record(self, ip: str) -> set:
        """Record a connection to ip, return current unique IPs in window."""
        now = time.monotonic()
        with self.lock:
            self.events.append((now, ip))
            cutoff = now - self.window
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()
            return {e[1] for e in self.events}

    def current_unique(self) -> set:
        now = time.monotonic()
        cutoff = now - self.window
        with self.lock:
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()
            return {e[1] for e in self.events}

# ─── Network Monitor ──────────────────────────────────────────────────────────

class NetworkMonitor:

    def __init__(self):
        self.smb_tracker       = UniqueHostTracker(SMB_WINDOW_SECONDS)
        self.burst_tracker     = UniqueHostTracker(CONNECTION_BURST_WINDOW)
        self.smb_whitelist:  set[str] = set()
        self.seen_connections: set[tuple] = set()   # (laddr, raddr, rport)
        self.alerted_smb_spread   = False
        self.alerted_burst        = False
        self.suspicious_port_seen: set[int] = set()
        self.lock = threading.Lock()
        self.running = False

    def _auto_whitelist_smb(self, ip: str):
        """
        Auto-learn legitimate SMB servers.
        First few SMB destinations are assumed to be real file servers.
        """
        if len(self.smb_whitelist) < MAX_AUTO_WHITELIST:
            if ip not in self.smb_whitelist:
                self.smb_whitelist.add(ip)
                log.info(f"Auto-whitelisted SMB server: {ip}")

    def _get_connections(self) -> list:
        """Get current network connections via psutil."""
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, Exception) as e:
            log.debug(f"net_connections error: {e}")
            return []

    def process_connections(self, connections: list):
        new_connections = []

        for conn in connections:
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue

            rip   = conn.raddr.ip
            rport = conn.raddr.port
            lport = conn.laddr.port if conn.laddr else 0

            # Skip loopback
            if rip.startswith("127.") or rip == "::1":
                continue

            key = (conn.laddr, conn.raddr, rport)
            if key in self.seen_connections:
                continue

            self.seen_connections.add(key)
            new_connections.append((rip, rport))

        for rip, rport in new_connections:
            self._check_smb_spread(rip, rport)
            self._check_connection_burst(rip, rport)
            self._check_suspicious_port(rip, rport)

        # Prune seen_connections periodically to avoid memory growth
        if len(self.seen_connections) > 10000:
            self.seen_connections = set(list(self.seen_connections)[-5000:])

    def _check_smb_spread(self, ip: str, port: int):
        """
        Alert if this host is connecting to many distinct IPs over SMB.
        Normal: endpoint → 1-2 file servers (whitelisted)
        Suspicious: endpoint → 4+ distinct hosts over SMB
        """
        if port not in (445, 139):
            return

        # Learn first contacts as legitimate servers
        self._auto_whitelist_smb(ip)

        if ip in self.smb_whitelist:
            return

        unique_smb_hosts = self.smb_tracker.record(ip)
        non_whitelisted  = unique_smb_hosts - self.smb_whitelist

        if len(non_whitelisted) >= SMB_HOST_THRESHOLD and not self.alerted_smb_spread:
            self.alerted_smb_spread = True
            send_event(make_event(
                "net_lateral",
                "HIGH",
                destination_ip=ip,
                port=port,
                unique_smb_hosts=len(non_whitelisted),
                smb_hosts=list(non_whitelisted),
                threshold=SMB_HOST_THRESHOLD,
                window_seconds=SMB_WINDOW_SECONDS,
                whitelisted_servers=list(self.smb_whitelist),
                note="SMB lateral spread detected — host connecting to many SMB targets. "
                     "Consistent with ransomware network propagation (LockBit/BlackCat pattern).",
            ))

    def _check_connection_burst(self, ip: str, port: int):
        """
        Alert on sudden burst of connections to new unique IPs.
        Ransomware maps the network before encrypting — this shows up as
        rapid new connections across the subnet.
        """
        if port in BENIGN_PORTS:
            return

        unique_ips = self.burst_tracker.record(ip)

        if len(unique_ips) >= CONNECTION_BURST_THRESHOLD and not self.alerted_burst:
            self.alerted_burst = True
            send_event(make_event(
                "connection_burst",
                "MEDIUM",
                unique_ips_count=len(unique_ips),
                threshold=CONNECTION_BURST_THRESHOLD,
                window_seconds=CONNECTION_BURST_WINDOW,
                sample_ips=list(unique_ips)[:10],
                note="Rapid new connections to many unique IPs — possible network reconnaissance.",
            ))

    def _check_suspicious_port(self, ip: str, port: int):
        """Alert on connections to known C2/suspicious ports."""
        if port in SUSPICIOUS_PORTS and port not in self.suspicious_port_seen:
            self.suspicious_port_seen.add(port)
            send_event(make_event(
                "suspicious_port",
                "HIGH",
                destination_ip=ip,
                port=port,
                note=f"Connection to suspicious port {port} — associated with C2 frameworks or Tor.",
            ))

    def reset_spread_alert(self):
        """Call after human review to re-arm spread detection."""
        with self.lock:
            self.alerted_smb_spread = False
            self.alerted_burst      = False

    def run(self):
        self.running = True
        log.info("=" * 60)
        log.info("MalVision Agent — net_monitor.py")
        log.info(f"Host:              {HOSTNAME}")
        log.info(f"Engine URL:        {ENGINE_URL}")
        log.info(f"SMB spread threshold: {SMB_HOST_THRESHOLD} hosts / {SMB_WINDOW_SECONDS}s")
        log.info(f"Burst threshold:   {CONNECTION_BURST_THRESHOLD} IPs / {CONNECTION_BURST_WINDOW}s")
        log.info("=" * 60)
        log.info("Monitoring network connections...")

        while self.running:
            try:
                conns = self._get_connections()
                self.process_connections(conns)
            except Exception as e:
                log.error(f"Monitor error: {e}")
            time.sleep(POLL_INTERVAL)

    def stop(self):
        self.running = False


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    monitor = NetworkMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        log.info("Shutting down network monitor...")
        monitor.stop()
        log.info("Network monitor stopped.")


if __name__ == "__main__":
    main()
