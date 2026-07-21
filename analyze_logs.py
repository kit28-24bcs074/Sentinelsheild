"""
SentinelShield - Log Analyzer
Reads logs/waf_access.log.csv and produces:
  1. A printed summary (counts by category, top IPs, false positive check)
  2. A bar chart image (analysis_chart.png) for use in the practical report
"""

import csv
import os
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "waf_access.log.csv")
CHART_OUT = os.path.join(os.path.dirname(__file__), "analysis_chart.png")

# Requests we deliberately sent as "normal" traffic, used to check for false positives
NORMAL_IPS = {"10.0.0.15"}
# Requests we deliberately sent with an injection payload, used to check for false negatives
# (the brute-force IP 203.0.113.77 is excluded here: its early requests are legitimate-looking
# by design and are only expected to be caught once the rate-limit threshold is crossed)
ATTACK_IPS = {"203.0.113.24", "203.0.113.55", "198.51.100.9", "198.51.100.42"}
BRUTE_FORCE_IP = "203.0.113.77"


def main():
    with open(LOG_FILE, newline="") as f:
        rows = list(csv.DictReader(f))

    total = len(rows)
    blocked = [r for r in rows if r["action"] == "BLOCKED"]
    allowed = [r for r in rows if r["action"] == "ALLOWED"]

    cat_counts = Counter(r["category"] for r in blocked)
    ip_counts = Counter(r["ip"] for r in blocked)

    # False positives: normal-traffic IPs that got blocked
    false_positives = [r for r in blocked if r["ip"] in NORMAL_IPS]
    # False negatives: attack IPs whose requests were allowed through
    false_negatives = [r for r in allowed if r["ip"] in ATTACK_IPS]

    print("=" * 60)
    print("SENTINELSHIELD - LOG ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total requests inspected : {total}")
    print(f"Allowed                  : {len(allowed)}")
    print(f"Blocked / Flagged        : {len(blocked)}")
    print()
    print("Blocked requests by category:")
    for cat, count in cat_counts.most_common():
        print(f"   {cat:12s} : {count}")
    print()
    print("Top flagged IP addresses:")
    for ip, count in ip_counts.most_common(5):
        print(f"   {ip:16s} : {count} blocked requests")
    print()
    print(f"False positives (normal traffic blocked) : {len(false_positives)}")
    for r in false_positives:
        print(f"   -> {r['timestamp']} {r['ip']} {r['path']} rule={r['rule_id']}")
    print(f"False negatives (attack traffic allowed) : {len(false_negatives)}")
    for r in false_negatives:
        print(f"   -> {r['timestamp']} {r['ip']} {r['path']}?{r['query']}")

    brute_rows = [r for r in rows if r["ip"] == BRUTE_FORCE_IP]
    brute_allowed = [r for r in brute_rows if r["action"] == "ALLOWED"]
    brute_blocked = [r for r in brute_rows if r["action"] == "BLOCKED"]
    print()
    print(f"Brute-force IP {BRUTE_FORCE_IP}: {len(brute_allowed)} requests allowed "
          f"before the rate-limit threshold was crossed, {len(brute_blocked)} blocked after.")
    print("(This ramp-up window is expected behavior, not a detection failure.)")
    print("=" * 60)

    # ---- Chart: blocked requests by category ----
    if cat_counts:
        cats = list(cat_counts.keys())
        counts = [cat_counts[c] for c in cats]
        colors = ["#e63946" if c != "RATE_LIMIT" else "#f4a261" for c in cats]

        plt.figure(figsize=(7, 4.5))
        bars = plt.bar(cats, counts, color=colors)
        plt.title("Blocked / Flagged Requests by Detection Category")
        plt.ylabel("Number of Requests")
        plt.xlabel("Category")
        for b, c in zip(bars, counts):
            plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.1, str(c),
                     ha="center", va="bottom", fontsize=10)
        plt.tight_layout()
        plt.savefig(CHART_OUT, dpi=150)
        print(f"\nChart saved to: {CHART_OUT}")

    return dict(total=total, allowed=len(allowed), blocked=len(blocked),
                cat_counts=dict(cat_counts), ip_counts=dict(ip_counts),
                false_positives=false_positives, false_negatives=false_negatives)


if __name__ == "__main__":
    main()
