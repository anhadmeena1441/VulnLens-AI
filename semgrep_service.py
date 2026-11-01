import os
import json
import logging
import subprocess
import tempfile
import shutil
import sys
from pathlib import Path

venv_bin = str(Path(sys.prefix) / "bin")

search_path = os.pathsep.join(
    p for p in os.environ.get("PATH", "").split(os.pathsep)
    if p and str(Path(p).resolve()) != str(Path(venv_bin).resolve())
)

SEMGREP_PATH = shutil.which("semgrep", path=search_path)
SEMGREP = str(Path(SEMGREP_PATH).resolve()) if SEMGREP_PATH else "semgrep"

logger = logging.getLogger("vulnlens.semgrep")


def scan_with_semgrep(project_dir: str) -> list:
    project = Path(project_dir).resolve()

    if not project.is_dir():
        raise ValueError("Project directory does not exist.")

    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".json", encoding="utf-8"
    ) as report:
        command = [
            SEMGREP,
            "scan",
            "--config", "auto",
            "--json",
            "--no-git-ignore",
            str(project),
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
                env={
                    **os.environ,
                    "PATH": f"{Path(SEMGREP).parent}:{os.environ.get('PATH', '')}",
                },
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Semgrep scan timed out.")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("Semgrep output: %s", result.stderr[-2000:])
            raise RuntimeError("Semgrep returned invalid JSON.")

    if result.returncode not in (0, 1):
        logger.error("Semgrep failed: %s", result.stderr[-2000:])
        raise RuntimeError("Semgrep scan failed.")

    findings = []

    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = extra.get("severity", "WARNING").upper()

        findings.append({
            "test_id": item.get("check_id", "Unknown"),
            "test_name": item.get("check_id", "Semgrep finding"),
            "issue_text": extra.get("message", "Security finding"),
            "issue_severity": {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW",
            }.get(severity, "MEDIUM"),
            "issue_confidence": metadata.get("confidence", "Unknown"),
            "filename": item.get("path", "Unknown"),
            "line_number": item.get("start", {}).get("line"),
            "code": extra.get("lines", ""),
            "scanner": "Semgrep",
            "cwe": metadata.get("cwe", []),
            "remediation": extra.get("fix"),
        })

    return findings
