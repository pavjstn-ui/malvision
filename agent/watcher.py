"""
MalVision - watcher.py
File system monitor for ransomware behavioral detection.

Detects:
- Honeytoken file access (instant CRITICAL, fires before encryption)
- File entropy spikes (Shannon > 7.2 on writes)
- Mass extension changes
- Rapid file rename patterns

Emits AgentEvent JSON to detection engine endpoint.
"""

import os
import sys
import math
import time
import json
import logging
import hashlib
import threading
import collections
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─── Configuration ────────────────────────────────────────────────────────────

ENGINE_URL = os.getenv("MALVISION_ENGINE_URL", "http://localhost:8000/events")
HOSTNAME = os.getenv("HOSTNAME", os.uname().nodename)

# Shannon entropy threshold — above this on a written file is suspicious
ENTROPY_THRESHOLD = 7.2

# How many files/min before entropy spike alert fires
ENTROPY_RATE_THRESHOLD = 20

# Mass extension change threshold
EXT_CHANGE_THRESHOLD = 10

# Rapid rename threshold (files per 30 seconds)
RENAME_RATE_THRESHOLD = 50

# Honeytoken file paths — any access is instant CRITICAL
# On Windows deployment these will be:
#   C:\Users\Public\config.ini
#   C:\Users\Admin\.ssh\id_rsa
#   D:\backups\accounts_payable.xlsx
HONEYTOKEN_PATHS = set([
    p.lower() for p in [
        r"C:\Users\Public\config.ini",
        r"C:\Users\Admin\.ssh\id_rsa",
        r"D:\backups\accounts_payable.xlsx",
        # Dev/test paths (Mac/Linux) — add your local test honeytokens here
        os.path.expanduser("~/malvision-test/config.ini"),
        os.path.expanduser("~/malvision-test/id_rsa"),
        os.path.expanduser("~/malvision-test/accounts_payable.xlsx"),
    ]
])

# Known ransomware note filenames
RANSOM_NOTE_NAMES = {
    "readme.txt", "read_me.txt", "how_to_decrypt.txt",
    "recovery_instructions.txt", "!!!restore!!!.txt",
    "decrypt_instructions.html", "lockbit_readme.txt",
    "files_encrypted.txt", "your_files_are_encrypted.txt",
}

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("malvision_agent.log"),
    ]
)
log = logging.getLogger("malvision.watcher")

# ─── Event Schema ─────────────────────────────────────────────────────────────

@dataclass
class AgentEvent:
    host: str
    timestamp: str
    event_type: str   # honeytoken_hit | entropy_spike | ext_change | rapid_rename | ransom_note
    severity: str     # CRITICAL | HIGH | MEDIUM | LOW
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

# ─── Entropy Calculation ───────────────────────────────────────────────────────

def shannon_entropy(filepath: str, sample_bytes: int = 65536) -> Optional[float]:
    """
    Calculate Shannon entropy of a file (or first sample_bytes of it).
    Returns 0.0-8.0. Encrypted/compressed data typically > 7.2.
    Returns None if file can't be read.
    """
    try:
        counts = collections.Counter()
        with open(filepath, "rb") as f:
            data = f.read(sample_bytes)
        if not data:
            return None
        counts = collections.Counter(data)
        total = len(data)
        entropy = -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values()
            if c > 0
        )
        return round(entropy, 4)
    except (PermissionError, FileNotFoundError, OSError):
        return None

# ─── Rate Tracker ─────────────────────────────────────────────────────────────

class RateTracker:
    """Sliding window event rate tracker."""

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self.events = collections.deque()
        self.lock = threading.Lock()

    def record(self) -> int:
        """Record an event, return current count in window."""
        now = time.monotonic()
        with self.lock:
            self.events.append(now)
            cutoff = now - self.window
            while self.events and self.events[0] < cutoff:
                self.events.popleft()
            return len(self.events)

    def count(self) -> int:
        now = time.monotonic()
        with self.lock:
            cutoff = now - self.window
            while self.events and self.events[0] < cutoff:
                self.events.popleft()
            return len(self.events)

# ─── Event Sender ─────────────────────────────────────────────────────────────

def send_event(event: AgentEvent):
    """Ship event to detection engine. Log locally on failure."""
    log.info(f"[{event.severity}] {event.event_type} | {event.payload}")
    try:
        resp = requests.post(
            ENGINE_URL,
            json=asdict(event),
            timeout=3,
        )
        if resp.status_code != 200:
            log.warning(f"Engine returned {resp.status_code}: {resp.text}")
    except requests.exceptions.ConnectionError:
        # Engine not up yet — write to local queue file for replay
        with open("event_queue.jsonl", "a") as f:
            f.write(event.to_json() + "\n")
        log.warning(f"Engine unreachable — event queued locally")

# ─── File System Handler ──────────────────────────────────────────────────────

class RansomwareHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self.entropy_rate = RateTracker(window_seconds=60)
        self.rename_rate = RateTracker(window_seconds=30)
        self.ext_changes: dict[str, set] = collections.defaultdict(set)  # path → set of extensions seen
        self.ext_change_count = 0
        self.lock = threading.Lock()

    def _is_honeytoken(self, path: str) -> bool:
        return path.lower() in HONEYTOKEN_PATHS

    def _is_ransom_note(self, path: str) -> bool:
        return Path(path).name.lower() in RANSOM_NOTE_NAMES

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path

        # ── Honeytoken check ──────────────────────────────────────────────────
        if self._is_honeytoken(path):
            send_event(make_event(
                "honeytoken_hit",
                "CRITICAL",
                file_path=path,
                access_type="write",
                note="Honeytoken modified — ransomware recon or encryption in progress",
            ))
            return  # Don't need further analysis — alert already fired

        # ── Ransom note check ─────────────────────────────────────────────────
        if self._is_ransom_note(path):
            send_event(make_event(
                "ransom_note",
                "CRITICAL",
                file_path=path,
                filename=Path(path).name,
                note="Known ransomware note filename detected",
            ))

        # ── Entropy check ─────────────────────────────────────────────────────
        entropy = shannon_entropy(path)
        if entropy is not None and entropy > ENTROPY_THRESHOLD:
            rate = self.entropy_rate.record()
            severity = "CRITICAL" if rate >= ENTROPY_RATE_THRESHOLD else "HIGH"
            send_event(make_event(
                "entropy_spike",
                severity,
                file_path=path,
                entropy=entropy,
                threshold=ENTROPY_THRESHOLD,
                files_per_minute=rate,
                rate_threshold=ENTROPY_RATE_THRESHOLD,
            ))

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path

        if self._is_honeytoken(path):
            send_event(make_event(
                "honeytoken_hit",
                "CRITICAL",
                file_path=path,
                access_type="create",
                note="File created at honeytoken path",
            ))

        if self._is_ransom_note(path):
            send_event(make_event(
                "ransom_note",
                "CRITICAL",
                file_path=path,
                filename=Path(path).name,
            ))

    def on_moved(self, event):
        if event.is_directory:
            return

        src = event.src_path
        dst = event.dest_path

        # ── Honeytoken rename/move ────────────────────────────────────────────
        if self._is_honeytoken(src) or self._is_honeytoken(dst):
            send_event(make_event(
                "honeytoken_hit",
                "CRITICAL",
                file_path=src,
                dest_path=dst,
                access_type="rename",
                note="Honeytoken file renamed — likely encryption attempt",
            ))
            return

        # ── Extension change tracking ─────────────────────────────────────────
        src_ext = Path(src).suffix.lower()
        dst_ext = Path(dst).suffix.lower()

        if src_ext != dst_ext and dst_ext:
            with self.lock:
                self.ext_change_count += 1
                count = self.ext_change_count

            if count >= EXT_CHANGE_THRESHOLD:
                send_event(make_event(
                    "ext_change",
                    "HIGH",
                    src_path=src,
                    dst_path=dst,
                    src_ext=src_ext,
                    dst_ext=dst_ext,
                    total_ext_changes=count,
                    threshold=EXT_CHANGE_THRESHOLD,
                ))

        # ── Rapid rename tracking ─────────────────────────────────────────────
        rate = self.rename_rate.record()
        if rate >= RENAME_RATE_THRESHOLD:
            send_event(make_event(
                "rapid_rename",
                "HIGH",
                src_path=src,
                dst_path=dst,
                renames_per_30s=rate,
                threshold=RENAME_RATE_THRESHOLD,
            ))

    def on_deleted(self, event):
        if self._is_honeytoken(event.src_path):
            send_event(make_event(
                "honeytoken_hit",
                "CRITICAL",
                file_path=event.src_path,
                access_type="delete",
                note="Honeytoken deleted",
            ))

# ─── Honeytoken Setup ─────────────────────────────────────────────────────────

def plant_test_honeytokens():
    """
    Create test honeytoken files for local development.
    On Windows deployment, these are pre-placed manually.
    """
    test_dir = os.path.expanduser("~/malvision-test")
    os.makedirs(test_dir, exist_ok=True)

    files = {
        "config.ini": "[database]\nhost=10.0.0.5\nuser=admin\npassword=Tr0ub4dor&3\ndb=accounts_prod\n",
        "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA[FAKE KEY - DO NOT USE]\n-----END RSA PRIVATE KEY-----\n",
        "accounts_payable.xlsx": "PLACEHOLDER - replace with actual .xlsx decoy\n",
    }

    for filename, content in files.items():
        path = os.path.join(test_dir, filename)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)
            log.info(f"Honeytoken planted: {path}")

    log.info(f"Test honeytokens ready in {test_dir}")
    log.info("Add this directory to your watch path to test honeytoken detection")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    watch_path = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~")

    log.info("=" * 60)
    log.info("MalVision Agent — watcher.py")
    log.info(f"Host:        {HOSTNAME}")
    log.info(f"Watch path:  {watch_path}")
    log.info(f"Engine URL:  {ENGINE_URL}")
    log.info(f"Honeytokens: {len(HONEYTOKEN_PATHS)} paths registered")
    log.info("=" * 60)

    # Plant test honeytokens for dev
    if "--plant-honeytokens" in sys.argv:
        plant_test_honeytokens()

    handler = RansomwareHandler()
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()

    log.info(f"Watching {watch_path} recursively...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down watcher...")
        observer.stop()

    observer.join()
    log.info("Watcher stopped.")


if __name__ == "__main__":
    main()
