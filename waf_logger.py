"""
SentinelShield - Logging Module
Writes every inspected request to a structured CSV log file so it can later
be parsed by analyze_logs.py, matching how a real SOC would pull SIEM data.
"""

import csv
import os
from datetime import datetime, timezone

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "waf_access.log.csv")

FIELDS = ["timestamp", "ip", "method", "path", "query", "category",
          "rule_id", "action", "severity", "mitre", "detail"]


def init_log():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=FIELDS).writeheader()


def log_event(ip, method, path, query, category, rule_id, action, severity, mitre, detail=""):
    init_log()
    row = dict(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ip=ip, method=method, path=path, query=query,
        category=category, rule_id=rule_id, action=action,
        severity=severity, mitre=mitre, detail=detail,
    )
    with open(LOG_FILE, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDS).writerow(row)


def clear_log():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    init_log()
