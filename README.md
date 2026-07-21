# SentinelShield - Advanced Intrusion Detection & Web Protection System

A small but fully working Web Application Firewall (WAF) / Intrusion Detection
System built in Flask, created for the SentinelShield practical work
documentation assignment.

## What's included

| File | Purpose |
|---|---|
| `app.py` | Main Flask app: demo routes + inline WAF inspection middleware + `/dashboard` |
| `rules.py` | 16 regex-based attack signatures (SQLi, XSS, LFI, traversal, command injection), each mapped to a MITRE ATT&CK technique |
| `rate_limiter.py` | Sliding-window rate limiter (brute-force / flooding detection) |
| `waf_logger.py` | Writes every request to a structured CSV log (`logs/waf_access.log.csv`) |
| `templates/dashboard.html` | Live dashboard: totals, blocked-by-category chart, top flagged IPs, recent events |
| `simulate_traffic.py` | Sends realistic normal + malicious + brute-force traffic for testing |
| `analyze_logs.py` | Parses the log file, prints a summary, and generates `analysis_chart.png` |
| `architecture.svg` / `architecture.png` | System architecture diagram |
| `logs/waf_access.log.csv` | Sample log data from an actual run (already generated for you) |
| `SentinelShield_Practical_Report.docx` | Completed practical journal + final report, populated with real results |

## How to run it yourself

```bash
# 1. Install dependencies
pip install flask requests matplotlib --break-system-packages

# 2. Start the WAF app (terminal 1)
python app.py
# Running on http://127.0.0.1:5000

# 3. Generate traffic (terminal 2)
python simulate_traffic.py

# 4. View the dashboard
# open http://127.0.0.1:5000/dashboard in a browser

# 5. Analyze the logs and regenerate the chart
python analyze_logs.py
```

## Detection flow

```
HTTP request -> WAF inspection (rules.py + rate_limiter.py) -> Decision
   -> Allowed  -> passed to the demo app route
   -> Blocked  -> 403 (signature match) or 429 (rate-limit exceeded)
-> Logged (logs/waf_access.log.csv) -> visible on /dashboard
```

## Extending it for your submission

- Add more attack signatures in `rules.py` (NoSQLi, SSRF, etc.) - the pattern is
  self-documenting, just append a new `dict(...)` entry to `RULES`.
- Change `WINDOW_SECONDS` / `REQUEST_THRESHOLD` in `rate_limiter.py` to tune
  brute-force sensitivity.
- Re-run `simulate_traffic.py` with your own payloads to generate fresh log
  data, then re-run `analyze_logs.py` before updating your report numbers.
- The practical journal and final report in the `.docx` file were written
  directly from a real run of this system - if you change the rules or
  traffic, re-generate the log, chart, and dashboard screenshot before
  updating the report so your numbers stay accurate to what you actually ran.

## Notes on the encoding-evasion lesson (see report Section 3.5)

The first version of the WAF inspected the *raw* query string, which meant
URL-encoded payloads (e.g. `%2e%2e%2fetc%2fpasswd`, `%3Cscript%3E`) slipped
through undetected. The fix was decoding the query string and body with
`urllib.parse.unquote_plus` (twice, to also catch double-encoding) before
running signature checks. This is a real, well-known WAF evasion technique
and is worth mentioning explicitly if you're asked about it in an interview
or viva.
