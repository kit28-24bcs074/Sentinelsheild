const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, ShadingType, ImageRun, AlignmentType, BorderStyle, PageBreak
} = require("docx");

const PAGE = { size: { width: 12240, height: 15840 } }; // US Letter

function h1(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 300, after: 150 } }); }
function h2(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 250, after: 120 } }); }
function p(text, opts = {}) { return new Paragraph({ children: [new TextRun({ text, ...opts })], spacing: { after: 120 } }); }
function bullet(text) { return new Paragraph({ text, bullet: { level: 0 }, spacing: { after: 60 } }); }

function cell(text, opts = {}) {
  return new TableCell({
    width: { size: opts.width || 2000, type: WidthType.DXA },
    shading: opts.header ? { type: ShadingType.CLEAR, fill: "E1F5EE" } : undefined,
    children: [new Paragraph({ children: [new TextRun({ text, bold: !!opts.header, size: 20 })] })],
  });
}

function image(path, width, height) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 200 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(path), transformation: { width, height } })],
  });
}

// ---------------- Data pulled from the actual simulation run ----------------
const totalRequests = 32;
const allowed = 13;
const blocked = 19;
const catCounts = [
  ["SQLI", 4, "SQL Injection", "T1190 - Exploit Public-Facing Application"],
  ["XSS", 3, "Cross-Site Scripting", "T1059.007 - JavaScript"],
  ["TRAVERSAL", 2, "Directory Traversal", "T1083 - File and Directory Discovery"],
  ["CMDI", 2, "Command Injection", "T1059 - Command and Scripting Interpreter"],
  ["LFI", 1, "Local File Inclusion", "T1005 - Data from Local System"],
  ["RATE_LIMIT", 7, "Brute-force / flooding", "T1110 - Brute Force"],
];
const topIps = [
  ["203.0.113.77", "7", "Brute-force login attempts"],
  ["203.0.113.24", "4", "SQL Injection payloads"],
  ["203.0.113.55", "3", "XSS payloads"],
  ["198.51.100.42", "3", "Command Injection payloads"],
  ["198.51.100.9", "2", "LFI / traversal payloads"],
];

const doc = new Document({
  sections: [{
    properties: { page: PAGE },
    children: [
      // ---------------- Title Page ----------------
      new Paragraph({ text: "", spacing: { after: 1200 } }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "SentinelShield", bold: true, size: 56 })],
        spacing: { after: 100 },
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Advanced Intrusion Detection & Web Protection System", size: 28 })],
        spacing: { after: 60 },
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Practical Work Documentation - Journal & Final Report", size: 24, italics: true })],
        spacing: { after: 800 },
      }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Submitted by: Kaviepriya", size: 22 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Program: B.E./B.Tech Computer Science and Engineering", size: 22 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Domain: Web Application Security / SOC Analyst Practical Training", size: 22 })] }),
      new Paragraph({ children: [new PageBreak()] }),

      // ---------------- 1. Project Overview ----------------
      h1("1. Project Overview"),
      p("SentinelShield is a simplified but realistic Intrusion Detection and Web Protection System, built to demonstrate how a Web Application Firewall (WAF) inspects incoming HTTP requests, detects malicious intent, tracks abusive traffic, and generates alerts. The system was implemented in Python using Flask, and was run end-to-end to generate real detection data used throughout this report."),
      p("The system inspects every incoming request against a signature rule engine and a request-rate monitor, logs the outcome, and surfaces the results on a live dashboard - mirroring the detection -> decision -> logging -> alerting -> dashboarding workflow used in real SOC environments."),

      h2("1.1 Objectives"),
      bullet("Understand how modern WAFs detect threats using patterns, signatures, and rule engines."),
      bullet("Analyze HTTP requests from a security perspective."),
      bullet("Identify common web attacks (SQLi, XSS, LFI, directory traversal, command injection) using manual and automated testing."),
      bullet("Demonstrate how rate limiting and traffic behavior analysis help prevent brute-force or flooding attacks."),
      bullet("Document findings and generate a test/analysis report with MITRE ATT&CK mapping."),

      // ---------------- 2. System Architecture ----------------
      h1("2. System Architecture"),
      p("The diagram below shows the request lifecycle implemented in app.py. Every request is inspected before it reaches the demo application routes."),
      image("architecture.png", 460, 413),
      p("Components:", { bold: true }),
      bullet("WAF Inspection (rules.py) - regex-based signature matching for SQLi, XSS, LFI, traversal, and command injection, with each rule mapped to a MITRE ATT&CK technique."),
      bullet("Rate Limiter (rate_limiter.py) - sliding-window request counter per source IP; flags an IP once it exceeds 8 requests in a 10-second window."),
      bullet("Logger (waf_logger.py) - writes every request (allowed or blocked) to a structured CSV log, matching how a SIEM stores event data."),
      bullet("Dashboard (/dashboard route) - live summary of total requests, blocked-by-category counts, top flagged IPs, and a recent-events table."),

      // ---------------- 3. Practical Journal ----------------
      new Paragraph({ children: [new PageBreak()] }),
      h1("3. Practical Journal"),

      h2("3.1 Purpose of the Experiment"),
      p("To build and operate a small-scale WAF/IDS, deliberately send both normal and malicious traffic through it, and study how signature-based detection and behavior-based rate limiting identify attacks in real time."),

      h2("3.2 Tools Used"),
      bullet("Python 3.12, Flask 3.1 - application and WAF middleware"),
      bullet("Python 're' module - signature/regex rule engine"),
      bullet("requests library - traffic simulation client"),
      bullet("matplotlib - analysis chart generation"),
      bullet("csv module - structured log storage and parsing"),

      h2("3.3 Step-by-Step Execution"),
      bullet("Step 1: Reviewed the architecture (Section 2) to understand how request, WAF, logger, and dashboard interact."),
      bullet("Step 2: Defined 16 attack signatures across 5 categories in rules.py, each with an id, severity, description, and MITRE ATT&CK mapping."),
      bullet("Step 3: Ran the Flask app (python app.py) and used simulate_traffic.py to send 4 normal requests, 12 malicious requests (SQLi, XSS, LFI, traversal, command injection), and a 15-request brute-force burst against /login, each attacker group tagged with its own source IP via X-Forwarded-For."),
      bullet("Step 4: Observed detection behavior - normal traffic passed through untouched; every malicious payload was blocked with a 403 response; the brute-force burst was allowed for its first 8 requests, then blocked with 429 once the rate-limit threshold was crossed."),
      bullet("Step 5: Opened logs/waf_access.log.csv and used analyze_logs.py to tabulate results by category and source IP."),
      bullet("Step 6: Compiled this report from the actual log data (Section 4)."),

      h2("3.4 Observations (Screenshots)"),
      p("Live dashboard after the simulated traffic run:"),
      image("dashboard_screenshot.png", 460, 322),
      p("Detection results by category (generated from the real log file):"),
      image("analysis_chart.png", 420, 270),

      h2("3.5 Interpretation of Logs"),
      p("An initial run revealed an important lesson: several encoded payloads (e.g. \"..%2Fetc%2Fpasswd\", \"<script>\" sent URL-encoded) were not detected because the WAF was matching signatures against the raw, still-encoded query string. After decoding the query string and body with unquote_plus before running the signature checks, all 12 deliberately malicious requests were correctly detected. This mirrors a well-known real-world WAF evasion technique - encoding a payload to slip past rules that only inspect raw text - and reinforced why request normalization must happen before pattern matching."),
      p("The brute-force sequence showed the rate limiter working as designed: the first 8 requests from the attacking IP looked individually harmless (a normal-looking login POST) and were allowed, and only once the 10-second/8-request threshold was crossed did the system begin returning 429 and logging the IP as abusive. This demonstrates why single-request inspection alone is not enough - behavior over time also has to be tracked."),

      // ---------------- 4. Final Report ----------------
      new Paragraph({ children: [new PageBreak()] }),
      h1("4. Final Report"),

      h2("4.1 Summary Table"),
      new Table({
        width: { size: 9000, type: WidthType.DXA },
        columnWidths: [2200, 1200, 3200, 2400],
        rows: [
          new TableRow({ children: [cell("Category", { header: true, width: 2200 }), cell("Count", { header: true, width: 1200 }), cell("Attack Type", { header: true, width: 3200 }), cell("MITRE ATT&CK", { header: true, width: 2400 })] }),
          ...catCounts.map(([cat, count, name, mitre]) =>
            new TableRow({ children: [cell(cat, { width: 2200 }), cell(String(count), { width: 1200 }), cell(name, { width: 3200 }), cell(mitre, { width: 2400 })] })
          ),
        ],
      }),
      new Paragraph({ text: "", spacing: { after: 200 } }),

      h2("4.2 Top Flagged IP Addresses"),
      new Table({
        width: { size: 9000, type: WidthType.DXA },
        columnWidths: [2500, 2000, 4500],
        rows: [
          new TableRow({ children: [cell("IP Address", { header: true, width: 2500 }), cell("Blocked Requests", { header: true, width: 2000 }), cell("Activity", { header: true, width: 4500 })] }),
          ...topIps.map(([ip, count, activity]) =>
            new TableRow({ children: [cell(ip, { width: 2500 }), cell(count, { width: 2000 }), cell(activity, { width: 4500 })] })
          ),
        ],
      }),
      new Paragraph({ text: "", spacing: { after: 200 } }),

      h2("4.3 Detection Accuracy"),
      bullet(`Total requests inspected: ${totalRequests}`),
      bullet(`Allowed: ${allowed}  |  Blocked / flagged: ${blocked}`),
      bullet("Signature-based detection: 12 out of 12 deliberately malicious payloads were correctly blocked after fixing the URL-decoding issue described in Section 3.5 (100% detection rate on the test set)."),
      bullet("Behavior-based detection: the brute-force IP was correctly flagged once its request rate crossed the configured threshold (8 requests / 10 seconds)."),
      bullet("False positives (normal traffic incorrectly blocked): 0 out of 4 normal requests."),
      bullet("False negatives (malicious traffic incorrectly allowed): 0 out of 12 signature-based attack requests."),

      h2("4.4 Observed Patterns"),
      bullet("Attackers concentrated on the /search, /profile, and /run endpoints - the routes that reflect user input back into a response or file/command path, consistent with real-world attacker reconnaissance behavior."),
      bullet("URL-encoding payloads is a simple, effective evasion technique against WAFs that inspect raw (undecoded) input; decoding before inspection closed this gap in this project."),
      bullet("Brute-force login attempts are recognizable by request volume and repetition rather than by payload content, which is why they need a separate behavioral detection mechanism from signature matching."),

      h2("4.5 Suggested Improvements to Rules"),
      bullet("Add double-decoding or full normalization (including case-folding and whitespace collapsing) to catch multi-layer encoding evasion beyond the two passes used here."),
      bullet("Add signatures for NoSQL injection and SSRF patterns, which are common in modern APIs but not covered in this iteration."),
      bullet("Make the rate-limit threshold adaptive per-endpoint (e.g. a stricter threshold on /login than on /search)."),
      bullet("Add an allow-list / IP reputation layer so previously trusted IPs are not immediately blocked on a single low-severity match."),
      bullet("Persist blocked-IP state to a database instead of in-memory storage, so flags survive an application restart."),

      h2("4.6 Conclusion"),
      p("This practical demonstrated the full detection workflow of a lightweight WAF: signature-based inspection for known attack patterns, behavior-based rate limiting for brute-force/flooding, structured logging for SOC-style analysis, and a dashboard for at-a-glance visibility. The most valuable takeaway was hands-on: a WAF is only as good as the normalization applied before pattern matching, and single-request inspection must be paired with traffic-behavior analysis to catch attacks that no single request reveals on its own."),
    ],
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("SentinelShield_Practical_Report.docx", buf);
  console.log("Report written.");
});
