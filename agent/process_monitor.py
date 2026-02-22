"""
MalVision - process_monitor.py
Process behavior monitor for ransomware detection.

Detects:
- VSS / shadow copy deletion commands (instant CRITICAL)
- Suspicious child process spawns (cmd, powershell, wmic patterns)
- Rapid file open/close rates per process (encryption loop signature)
- Backup/recovery tool termination
- Suspicious process trees

Runs alongside watcher.py — both emit AgentEvent to engine.
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
HOSTNAME = os.getenv("HOSTNAME", os.uname().nodename)

# Poll interval in seconds
POLL_INTERVAL = 1.0

# Rapid file open rate — opens/sec per process before alert
FILE_OPEN_RATE_THRESHOLD = 50

# Window for file open rate tracking (seconds)
FILE_OPEN_WINDOW = 10

# VSS / shadow copy deletion patterns
# On Windows: vssadmin delete shadows, wmic shadowcopy delete, bcdedit /set recoveryenabled No
VSS_PATTERNS = [
    "vssadmin",           # catches vssadmin.exe delete shadows /all etc.
    "shadowcopy delete",
    "delete shadows",
    "bcdedit",            # catches bcdedit /set recoveryenabled no
    "diskshadow",
    "resize shadowstorage",
    "wmic shadowcopy",
]

# Backup/recovery processes ransomware commonly kills
BACKUP_PROCESS_NAMES = {
    "veeam", "veeambackup", "backup", "acronis", "shadowprotect",
    "backupexec", "arcserve", "commvault", "symantec", "norton",
    "malwarebytes", "mbam", "sophos", "eset", "kaspersky",
    "sqlwriter", "mssqlserver",
}

# Suspicious process spawns — ransomware commonly uses these
SUSPICIOUS_SPAWN_PATTERNS = [
    "powershell -enc",           # base64 encoded payload
    "powershell -e ",
    "powershell -nop",           # no profile — evasion
    "powershell -w hidden",      # hidden window
    "cmd /c del",                # file deletion
    "cmd /c rd /s",              # recursive directory delete
    "icacls * /grant",           # permission manipulation
    "net stop",                  # stopping services
    "sc stop",                   # stopping services
    "taskkill /f",               # force kill processes
    "wmic process call create",  # remote process creation
    "certutil -decode",          # decoding payloads
    "certutil -urlcache",        # downloading payloads
    "bitsadmin /transfer",       # file download
    "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",  # persistence
]

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("malvision_process.log"),
    ]
)
log = logging.getLogger("malvision.process")

# ─── Event Schema (mirrors watcher.py) ────────────────────────────────────────

@dataclass
class AgentEvent:
    host: str
    timestamp: str
    event_type: str
    severity: str
    payload: dict

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def make_event(event_type: str, severity: str, **payload_kwargs) -> AgentEvent:
    return AgentEvent(
        host=HOSTNAME,
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        severity=severity,
        payload=payload_kwargs,
    )

# ─── Event Sender (mirrors watcher.py) ────────────────────────────────────────

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

# ─── VSS Detection ────────────────────────────────────────────────────────────

def check_vss_pattern(cmdline: str) -> Optional[str]:
    """Return matching VSS pattern if found in command line, else None."""
    cmdline_lower = cmdline.lower()
    for pattern in VSS_PATTERNS:
        if pattern.lower() in cmdline_lower:
            return pattern
    return None


def check_suspicious_spawn(cmdline: str) -> Optional[str]:
    """Return matching suspicious pattern if found, else None."""
    cmdline_lower = cmdline.lower()
    for pattern in SUSPICIOUS_SPAWN_PATTERNS:
        if pattern.lower() in cmdline_lower:
            return pattern
    return None

# ─── File Open Rate Tracker ───────────────────────────────────────────────────

class ProcessFileRateTracker:
    """
    Tracks file open rate per process using a sliding window.
    Ransomware encryption loops open/read/write/close files rapidly.
    """

    def __init__(self):
        self.lock = threading.Lock()
        # pid → deque of timestamps
        self.open_events: dict[int, collections.deque] = collections.defaultdict(
            lambda: collections.deque()
        )
        self.alerted_pids: set[int] = set()

    def record_opens(self, pid: int, count: int) -> int:
        """Record `count` file opens for pid, return current rate."""
        now = time.monotonic()
        cutoff = now - FILE_OPEN_WINDOW
        with self.lock:
            dq = self.open_events[pid]
            for _ in range(count):
                dq.append(now)
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def already_alerted(self, pid: int) -> bool:
        return pid in self.alerted_pids

    def mark_alerted(self, pid: int):
        self.alerted_pids.add(pid)

    def cleanup_dead(self, live_pids: set[int]):
        with self.lock:
            dead = set(self.open_events.keys()) - live_pids
            for pid in dead:
                del self.open_events[pid]
            self.alerted_pids -= dead

# ─── Process Monitor ──────────────────────────────────────────────────────────

class ProcessMonitor:

    def __init__(self):
        self.file_rate_tracker = ProcessFileRateTracker()
        self.seen_pids: set[int] = set()
        self.killed_backups: set[str] = set()
        self.running = False

    def get_cmdline(self, proc: psutil.Process) -> str:
        try:
            return " ".join(proc.cmdline())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return ""

    def get_open_file_count(self, proc: psutil.Process) -> int:
        try:
            return len(proc.open_files())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return 0

    def check_process(self, proc: psutil.Process):
        try:
            pid = proc.pid
            name = proc.name().lower()
            cmdline = self.get_cmdline(proc)

            if not cmdline:
                return

            # ── VSS deletion ─────────────────────────────────────────────────
            vss_match = check_vss_pattern(cmdline)
            if vss_match:
                send_event(make_event(
                    "vss_deletion",
                    "CRITICAL",
                    pid=pid,
                    process_name=proc.name(),
                    cmdline=cmdline,
                    matched_pattern=vss_match,
                    note="Shadow copy / backup deletion — classic ransomware pre-encryption step",
                ))

            # ── Suspicious spawn ──────────────────────────────────────────────
            spawn_match = check_suspicious_spawn(cmdline)
            if spawn_match:
                try:
                    parent = proc.parent()
                    parent_name = parent.name() if parent else "unknown"
                    parent_cmdline = self.get_cmdline(parent) if parent else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = "unknown"
                    parent_cmdline = ""

                send_event(make_event(
                    "suspicious_spawn",
                    "HIGH",
                    pid=pid,
                    process_name=proc.name(),
                    cmdline=cmdline,
                    matched_pattern=spawn_match,
                    parent_name=parent_name,
                    parent_cmdline=parent_cmdline,
                ))

            # ── Backup process termination ────────────────────────────────────
            # Detect if a backup tool has disappeared since last poll
            # (handled in scan_all via diff of live pids)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def check_file_open_rates(self, proc: psutil.Process):
        """Check if process is opening files at ransomware encryption loop rates."""
        try:
            pid = proc.pid
            if self.file_rate_tracker.already_alerted(pid):
                return

            open_count = self.get_open_file_count(proc)
            if open_count == 0:
                return

            rate = self.file_rate_tracker.record_opens(pid, open_count)
            per_second = rate / FILE_OPEN_WINDOW

            if per_second >= FILE_OPEN_RATE_THRESHOLD:
                self.file_rate_tracker.mark_alerted(pid)
                send_event(make_event(
                    "rapid_file_opens",
                    "HIGH",
                    pid=pid,
                    process_name=proc.name(),
                    cmdline=self.get_cmdline(proc),
                    files_per_second=round(per_second, 1),
                    threshold=FILE_OPEN_RATE_THRESHOLD,
                    note="Rapid file open rate — consistent with encryption loop",
                ))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def check_backup_process_deaths(self, current_processes: dict[int, str]):
        """Alert if a known backup/AV process has disappeared."""
        current_names = set(current_processes.values())

        for name in list(self.killed_backups):
            if name not in current_names:
                # Already alerted, still gone — that's expected
                pass

        # Find newly killed backup processes
        current_backup_names = {n for n in current_names if any(b in n for b in BACKUP_PROCESS_NAMES)}
        prev_backup_names = getattr(self, '_prev_backup_names', current_backup_names)

        newly_killed = prev_backup_names - current_backup_names
        for name in newly_killed:
            if name not in self.killed_backups:
                self.killed_backups.add(name)
                send_event(make_event(
                    "backup_process_killed",
                    "HIGH",
                    process_name=name,
                    note="Backup/AV process disappeared — ransomware commonly terminates these before encrypting",
                ))

        self._prev_backup_names = current_backup_names

    def scan_all(self):
        """Full process scan — runs every POLL_INTERVAL seconds."""
        current_processes = {}
        new_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = proc.pid
                name = proc.name().lower()
                current_processes[pid] = name
                new_pids.add(pid)

                # Only check new processes for VSS/spawn patterns
                # (avoids re-alerting on long-running processes)
                if pid not in self.seen_pids:
                    self.check_process(proc)

                # File open rate checked every poll for all processes
                self.check_file_open_rates(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.check_backup_process_deaths(current_processes)
        self.file_rate_tracker.cleanup_dead(new_pids)
        self.seen_pids = new_pids

    def run(self):
        self.running = True
        log.info("=" * 60)
        log.info("MalVision Agent — process_monitor.py")
        log.info(f"Host:        {HOSTNAME}")
        log.info(f"Engine URL:  {ENGINE_URL}")
        log.info(f"Poll interval: {POLL_INTERVAL}s")
        log.info(f"File open threshold: {FILE_OPEN_RATE_THRESHOLD}/s")
        log.info("=" * 60)
        log.info("Monitoring processes...")

        while self.running:
            try:
                self.scan_all()
            except Exception as e:
                log.error(f"Scan error: {e}")
            time.sleep(POLL_INTERVAL)

    def stop(self):
        self.running = False

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    monitor = ProcessMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        log.info("Shutting down process monitor...")
        monitor.stop()
        log.info("Process monitor stopped.")


if __name__ == "__main__":
    main()
