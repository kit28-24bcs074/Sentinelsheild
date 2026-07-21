"""
SentinelShield - Rule Engine
Defines regex-based attack signatures used to inspect incoming HTTP requests.

Each rule has:
    id          - short rule identifier (e.g. SQLI-01)
    category    - attack class (SQLI, XSS, LFI, TRAVERSAL, CMDI)
    pattern     - compiled regex applied against URL path, query string, and body
    description - human readable explanation
    mitre       - approximate MITRE ATT&CK technique mapping (for student reference)
    severity    - LOW / MEDIUM / HIGH
"""

import re

RULES = [
    # ---------------- SQL Injection ----------------
    dict(id="SQLI-01", category="SQLI", severity="HIGH",
         pattern=re.compile(r"(\bunion\b\s+\bselect\b)", re.I),
         description="UNION-based SQL injection attempt",
         mitre="T1190 - Exploit Public-Facing Application"),
    dict(id="SQLI-02", category="SQLI", severity="HIGH",
         pattern=re.compile(r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)", re.I),
         description="Boolean-based tautology (e.g. OR 1=1)",
         mitre="T1190 - Exploit Public-Facing Application"),
    dict(id="SQLI-03", category="SQLI", severity="MEDIUM",
         pattern=re.compile(r"(--|#|/\*)\s*$|;\s*--"),
         description="SQL comment sequence used to truncate queries",
         mitre="T1190 - Exploit Public-Facing Application"),
    dict(id="SQLI-04", category="SQLI", severity="HIGH",
         pattern=re.compile(r";\s*drop\s+table", re.I),
         description="Destructive DROP TABLE statement",
         mitre="T1190 - Exploit Public-Facing Application"),
    dict(id="SQLI-05", category="SQLI", severity="MEDIUM",
         pattern=re.compile(r"\bsleep\s*\(\s*\d+\s*\)", re.I),
         description="Time-based blind SQL injection (SLEEP)",
         mitre="T1190 - Exploit Public-Facing Application"),

    # ---------------- Cross-Site Scripting ----------------
    dict(id="XSS-01", category="XSS", severity="HIGH",
         pattern=re.compile(r"<script[^>]*>", re.I),
         description="Inline <script> tag injection",
         mitre="T1059.007 - Command and Scripting Interpreter: JavaScript"),
    dict(id="XSS-02", category="XSS", severity="MEDIUM",
         pattern=re.compile(r"on(error|load|mouseover|focus)\s*=", re.I),
         description="Event-handler based XSS payload",
         mitre="T1059.007 - Command and Scripting Interpreter: JavaScript"),
    dict(id="XSS-03", category="XSS", severity="MEDIUM",
         pattern=re.compile(r"javascript\s*:", re.I),
         description="javascript: URI scheme injection",
         mitre="T1059.007 - Command and Scripting Interpreter: JavaScript"),
    dict(id="XSS-04", category="XSS", severity="LOW",
         pattern=re.compile(r"<img[^>]+src\s*=\s*[\"']?x[\"']?", re.I),
         description="Broken-image XSS trigger pattern",
         mitre="T1059.007 - Command and Scripting Interpreter: JavaScript"),

    # ---------------- Local File Inclusion / Directory Traversal ----------------
    dict(id="TRAV-01", category="TRAVERSAL", severity="HIGH",
         pattern=re.compile(r"(\.\./|\.\.\\)"),
         description="Directory traversal sequence (../)",
         mitre="T1083 - File and Directory Discovery"),
    dict(id="TRAV-02", category="TRAVERSAL", severity="HIGH",
         pattern=re.compile(r"%2e%2e(%2f|%5c)", re.I),
         description="URL-encoded directory traversal sequence",
         mitre="T1083 - File and Directory Discovery"),
    dict(id="LFI-01", category="LFI", severity="HIGH",
         pattern=re.compile(r"etc/passwd", re.I),
         description="Attempt to read /etc/passwd",
         mitre="T1005 - Data from Local System"),
    dict(id="LFI-02", category="LFI", severity="MEDIUM",
         pattern=re.compile(r"boot\.ini", re.I),
         description="Attempt to read Windows boot.ini",
         mitre="T1005 - Data from Local System"),

    # ---------------- Command Injection ----------------
    dict(id="CMDI-01", category="CMDI", severity="HIGH",
         pattern=re.compile(r";\s*(cat|ls|whoami|id|uname|nc|wget|curl)\b", re.I),
         description="Chained shell command after semicolon",
         mitre="T1059 - Command and Scripting Interpreter"),
    dict(id="CMDI-02", category="CMDI", severity="HIGH",
         pattern=re.compile(r"\|\s*(nc|bash|sh|powershell)\b", re.I),
         description="Piped command execution",
         mitre="T1059 - Command and Scripting Interpreter"),
    dict(id="CMDI-03", category="CMDI", severity="MEDIUM",
         pattern=re.compile(r"`[^`]+`"),
         description="Backtick command substitution",
         mitre="T1059 - Command and Scripting Interpreter"),
]


def inspect(text: str):
    """Run all rules against a piece of text (path, query string, or body).
    Returns the first matching rule dict, or None if no match."""
    if not text:
        return None
    for rule in RULES:
        if rule["pattern"].search(text):
            return rule
    return None
