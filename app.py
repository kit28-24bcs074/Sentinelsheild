"""
SentinelShield - Advanced Intrusion Detection & Web Protection System
Main application: a small demo web app fronted by an inline WAF middleware.

Flow implemented (matches the practical spec):
    request arrives -> inspect (rules.py) -> rate-limit check (rate_limiter.py)
    -> decision (allow / block) -> log (waf_logger.py) -> dashboard visibility

Run:
    python app.py
Then in another terminal, generate traffic:
    python simulate_traffic.py
Then view the dashboard:
    http://127.0.0.1:5000/dashboard
"""

from flask import Flask, request, jsonify, render_template
import csv
import os
from urllib.parse import unquote_plus

import rules
import rate_limiter
import waf_logger

app = Flask(__name__)
waf_logger.init_log()


@app.before_request
def waf_inspect():
    if request.path.startswith("/dashboard") or request.path.startswith("/static"):
        return  # don't inspect internal/dashboard traffic

    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    path = request.path
    query_raw = request.query_string.decode("utf-8", errors="ignore")
    body_raw = ""
    if request.method in ("POST", "PUT", "PATCH"):
        body_raw = request.get_data(as_text=True) or ""

    # Decode URL-encoding (twice, to also catch double-encoded evasion
    # attempts such as %252e%252e) before running signatures against the text.
    query = unquote_plus(unquote_plus(query_raw))
    body = unquote_plus(unquote_plus(body_raw))

    combined_text = " ".join([path, query, body])

    # 1. Rule-based signature inspection
    matched_rule = rules.inspect(combined_text)

    # 2. Behavior / rate-limit inspection
    is_abusive, count = rate_limiter.check(ip)

    if matched_rule:
        waf_logger.log_event(
            ip=ip, method=request.method, path=path, query=query,
            category=matched_rule["category"], rule_id=matched_rule["id"],
            action="BLOCKED", severity=matched_rule["severity"],
            mitre=matched_rule["mitre"], detail=matched_rule["description"],
        )
        return jsonify({
            "status": "blocked",
            "reason": matched_rule["description"],
            "rule_id": matched_rule["id"],
            "category": matched_rule["category"],
        }), 403

    if is_abusive:
        waf_logger.log_event(
            ip=ip, method=request.method, path=path, query=query,
            category="RATE_LIMIT", rule_id="RATE-01", action="BLOCKED",
            severity="MEDIUM", mitre="T1110 - Brute Force",
            detail=f"{count} requests within {rate_limiter.WINDOW_SECONDS}s window",
        )
        return jsonify({
            "status": "blocked",
            "reason": "Rate limit exceeded - possible brute force / flooding",
            "rule_id": "RATE-01",
            "category": "RATE_LIMIT",
        }), 429

    # 3. Allowed traffic is still logged (as ALLOWED) for full visibility
    waf_logger.log_event(
        ip=ip, method=request.method, path=path, query=query,
        category="NONE", rule_id="-", action="ALLOWED",
        severity="-", mitre="-", detail="No signature matched",
    )


# ---------------- Demo "protected" application routes ----------------

@app.route("/")
def home():
    return jsonify({"message": "Welcome to the SentinelShield demo application."})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"query_received": q, "results": []})


@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.values.get("username", "")
    return jsonify({"message": f"Login attempt for user '{username}' processed."})


@app.route("/profile")
def profile():
    filename = request.args.get("file", "profile.txt")
    return jsonify({"message": f"Would load file: {filename}"})


@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "")
    return jsonify({"message": f"Would execute: {cmd}"})


# ---------------- Dashboard ----------------

@app.route("/dashboard")
def dashboard():
    rows = []
    if os.path.exists(waf_logger.LOG_FILE):
        with open(waf_logger.LOG_FILE, newline="") as f:
            rows = list(csv.DictReader(f))

    total = len(rows)
    blocked = [r for r in rows if r["action"] == "BLOCKED"]
    allowed_count = total - len(blocked)

    cat_counts = {}
    ip_counts = {}
    for r in blocked:
        cat_counts[r["category"]] = cat_counts.get(r["category"], 0) + 1
        ip_counts[r["ip"]] = ip_counts.get(r["ip"], 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:5]

    return render_template(
        "dashboard.html",
        total=total,
        allowed_count=allowed_count,
        blocked_count=len(blocked),
        cat_counts=cat_counts,
        top_ips=top_ips,
        recent=list(reversed(rows))[:25],
    )


if __name__ == "__main__":
    app.run(debug=False, port=5000)
