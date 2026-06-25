#!/usr/bin/env python3
"""
SecureAudit — Python Security Code Review Tool
================================================
CLI entry point.  Scans Python source files for security vulnerabilities
and produces a rich HTML report with remediation guidance.

Usage:
    python audit.py <target_file_or_dir> [--output report.html]
    python audit.py samples/vulnerable_app.py
"""

import argparse
import os
import sys
import time
from pathlib import Path

# Ensure local modules resolve correctly regardless of working directory
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
os.chdir(_HERE)  # make relative paths work too

from core.analyzer import SecurityAnalyzer, AnalysisResult
from reports.html_reporter import generate_html_report
from rules.vulnerability_rules import SEVERITY_COLORS, SEVERITY_ORDER


# ─── ANSI colour helpers ─────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GREY   = "\033[90m"
WHITE  = "\033[97m"

SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      BLUE,
    "INFO":     GREY,
}


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text


def print_banner():
    banner = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗
║          🛡️  SecureAudit — Python Security Analyzer          ║
║          Static Code Review · CWE/OWASP Mapped · v1.0        ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def print_summary(results: list[AnalysisResult]):
    from collections import defaultdict
    all_findings = [f for r in results for f in r.findings]
    sev_counts = defaultdict(int)
    for f in all_findings:
        sev_counts[f.severity] += 1

    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
    risk_score = min(100, sum(weights.get(f.severity, 0) for f in all_findings))

    if risk_score == 0:   grade = "A"
    elif risk_score <= 10: grade = "B"
    elif risk_score <= 30: grade = "C"
    elif risk_score <= 60: grade = "D"
    else:                  grade = "F"

    grade_color = {
        "A": GREEN, "B": GREEN, "C": YELLOW, "D": ORANGE, "F": RED
    }.get(grade, WHITE)

    total_lines = sum(r.total_lines for r in results)
    total_files = len(results)

    print(f"\n{BOLD}{'─'*62}{RESET}")
    print(f"  {BOLD}Files scanned:{RESET}  {total_files}")
    print(f"  {BOLD}Lines scanned:{RESET}  {total_lines:,}")
    print(f"  {BOLD}Total findings:{RESET} {len(all_findings)}")
    print()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = sev_counts.get(sev, 0)
        if c:
            col = SEV_COLORS.get(sev, WHITE)
            bar = "█" * c
            print(f"  {col}{BOLD}{sev:<10}{RESET}  {col}{bar}{RESET} {c}")
    print()
    print(f"  {BOLD}Risk Score:{RESET}   {grade_color}{risk_score}/100{RESET}")
    print(f"  {BOLD}Grade:{RESET}        {grade_color}{BOLD}{grade}{RESET}")
    print(f"{BOLD}{'─'*62}{RESET}\n")


def print_findings(results: list[AnalysisResult]):
    all_findings = [f for r in results for f in r.findings]
    if not all_findings:
        print(colorize("  ✅  No vulnerabilities detected!", GREEN))
        return

    print(f"{BOLD}{'─'*62}{RESET}")
    print(f"  {BOLD}FINDINGS{RESET}")
    print(f"{BOLD}{'─'*62}{RESET}")

    for f in all_findings:
        col = SEV_COLORS.get(f.severity, WHITE)
        print(f"\n  {col}{BOLD}[{f.severity}]{RESET}  {BOLD}{f.rule_name}{RESET}  "
              f"{GREY}({f.rule_id} · {f.cwe_id}){RESET}")
        print(f"  {GREY}File: {f.file_path}:{f.line_number}{RESET}")
        print(f"  {GREY}Code: {f.line_content.strip()[:80]}{RESET}")
        print(f"  {CYAN}Category: {f.category}  ·  OWASP: {f.owasp_category}{RESET}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="audit.py",
        description="SecureAudit — Python Static Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="Python file or directory to audit",
    )
    parser.add_argument(
        "--output", "-o",
        default="reports/security_report.html",
        help="Output HTML report path (default: reports/security_report.html)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip HTML report generation",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Only show findings at or above this severity",
    )

    args = parser.parse_args()
    target = args.target

    if not os.path.exists(target):
        print(colorize(f"  ❌  Target not found: {target}", RED))
        sys.exit(1)

    analyzer = SecurityAnalyzer()
    t0 = time.time()

    if os.path.isfile(target):
        print(f"  {CYAN}Scanning:{RESET}  {target}")
        results = [analyzer.analyze_file(target)]
    else:
        print(f"  {CYAN}Scanning directory:{RESET}  {target}")
        results = analyzer.analyze_directory(target)

    elapsed = (time.time() - t0) * 1000
    print(f"  {GREEN}Scan complete{RESET} in {elapsed:.1f}ms\n")

    # Apply severity filter
    if args.severity:
        threshold = SEVERITY_ORDER[args.severity]
        for r in results:
            r.findings = [f for f in r.findings
                          if SEVERITY_ORDER.get(f.severity, 99) <= threshold]

    print_summary(results)
    print_findings(results)

    if not args.no_report:
        report_path = args.output
        generate_html_report(results, report_path)
        print(f"\n  {GREEN}✅  HTML report saved:{RESET}  {os.path.abspath(report_path)}\n")

    total_critical = sum(r.critical_count for r in results)
    sys.exit(1 if total_critical > 0 else 0)


if __name__ == "__main__":
    main()