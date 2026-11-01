import json
from pathlib import Path

REPORT_FILE = Path("report.json")


def load_findings():
    if not REPORT_FILE.exists():
        raise FileNotFoundError(
            "report.json not found. Run the Bandit scan first."
        )

    with REPORT_FILE.open("r", encoding="utf-8") as file:
        report = json.load(file)

    findings = report.get("results", [])

    summary = {
        "total": len(findings),
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.get("issue_severity", "").lower()

        if severity in summary:
            summary[severity] += 1

    return findings, summary


if __name__ == "__main__":
    findings, summary = load_findings()

    print("\n========== VulnLens AI ==========")
    print("Security Scan Summary")
    print("=================================")

    print(f"Total findings: {summary['total']}")
    print(f"High severity:  {summary['high']}")
    print(f"Medium severity:{summary['medium']}")
    print(f"Low severity:   {summary['low']}")

    print("\nDetailed Findings")
    print("---------------------------------")

    for finding in findings:
        print(f"\nIssue: {finding.get('test_name')}")
        print(f"Severity: {finding.get('issue_severity')}")
        print(f"File: {finding.get('filename')}")
        print(f"Line: {finding.get('line_number')}")
        print(f"Description: {finding.get('issue_text')}")
