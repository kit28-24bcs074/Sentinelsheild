"""
SentinelShield - Traffic Monitoring / Rate Limiter
Tracks request timestamps per source IP using a sliding time window.
If an IP exceeds REQUEST_THRESHOLD within WINDOW_SECONDS, it is flagged as abusive.
"""

import time
from collections import defaultdict, deque

WINDOW_SECONDS = 10      # sliding time window
REQUEST_THRESHOLD = 8    # max requests allowed per window before flagging

# ip -> deque of request timestamps
_history = defaultdict(deque)
# ip -> flagged-until timestamp (temporary block)
_flagged = {}

BLOCK_DURATION = 30  # seconds an abusive IP stays flagged


def check(ip: str):
    """Register a request from `ip` and return (is_abusive: bool, count_in_window: int)."""
    now = time.time()

    # Already flagged?
    if ip in _flagged:
        if now < _flagged[ip]:
            return True, len(_history[ip])
        else:
            del _flagged[ip]

    dq = _history[ip]
    dq.append(now)

    # Drop timestamps outside the window
    while dq and dq[0] < now - WINDOW_SECONDS:
        dq.popleft()

    if len(dq) > REQUEST_THRESHOLD:
        _flagged[ip] = now + BLOCK_DURATION
        return True, len(dq)

    return False, len(dq)


def reset():
    """Clear all tracked state (used between simulation runs)."""
    _history.clear()
    _flagged.clear()
