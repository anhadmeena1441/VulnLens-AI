	
import json
import logging
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ai_service import explain_finding
from semgrep_service import scan_with_semgrep

BASE_DIR = Path(__file__).resolve().parent
REPORT_FILE = BASE_DIR / "report.json"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnlens")

app = FastAPI(
    title="VulnLens AI",
    description="AI-powered security analysis for Python projects",
    version="0.2.0",
)

app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def load_report():
    if not REPORT_FILE.exists():
        return {"results": [], "errors": []}

    try:
        with REPORT_FILE.open("r", encoding="utf-8") as file:
            report = json.load(file)

        return {
            "results": report.get("results", []),
            "errors": report.get("errors", []),
        }

    except (json.JSONDecodeError, OSError):
        return {
            "results": [],
            "errors": ["Unable to read the security report."],
        }


def get_summary(findings):
    summary = {
        "total": len(findings),
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.get("issue_severity", "").upper()

        if severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1

    return summary


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    report = load_report()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "findings": report["results"],
            "summary": get_summary(report["results"]),
            "errors": report["errors"],
        },
    )


@app.get("/api/findings")
async def api_findings():
    report = load_report()

    return {
        "summary": get_summary(report["results"]),
        "findings": report["results"],
        "errors": report["errors"],
    }

@app.post("/api/scan")
async def scan_project(request: Request):
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        body = {}

    raw_path = body.get("project_path", "")

    if not isinstance(raw_path, str) or not raw_path.strip():
        raise HTTPException(
            status_code=400,
            detail="Enter a project directory to scan.",
        )

    project_dir = Path(raw_path).expanduser().resolve()
    home_dir = Path.home().resolve()

    if project_dir == home_dir or not project_dir.is_relative_to(home_dir):
        raise HTTPException(
            status_code=403,
            detail="Choose a project directory inside your home directory.",
        )

    if project_dir == BASE_DIR or BASE_DIR in project_dir.parents:
        raise HTTPException(
            status_code=400,
            detail="Choose a Python project outside the VulnLens AI application directory.",
        )

    if not project_dir.is_dir():
        raise HTTPException(
            status_code=400,
            detail="The selected project directory does not exist.",
        )

    if not any(project_dir.rglob("*.py")):
        raise HTTPException(
            status_code=400,
            detail="No Python files were found in the selected directory.",
        )

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(project_dir),
        "-f",
        "json",
        "-o",
        str(REPORT_FILE),
    ]

    try:
        result = await run_in_threadpool(
            subprocess.run,
            command,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="The security scan timed out.",
        )
    except OSError:
        logger.exception("Unable to start Bandit")
        raise HTTPException(
            status_code=500,
            detail="Unable to start the security scanner.",
        )

    if result.returncode not in (0, 1):
        logger.error("Bandit failed: %s", result.stderr[-2000:])
        raise HTTPException(
            status_code=500,
            detail="The security scan failed. Check the server terminal.",
        )


    report = load_report()

    if report["errors"]:
        raise HTTPException(
            status_code=500,
            detail="The scan report could not be read.",
        )
    
    # Label Bandit findings
    bandit_findings = report["results"]
    
    for finding in bandit_findings:
        finding["scanner"] = "Bandit"
    
    # Run Semgrep
    try:
        semgrep_findings = await run_in_threadpool(
            scan_with_semgrep,
            str(project_dir),
        )
    except Exception:
        logger.exception("Semgrep scan failed")
        raise HTTPException(
            status_code=502,
            detail="Semgrep scanning failed. Check the server logs.",
        )
    
    # Combine both scanner results
    combined_findings = bandit_findings + semgrep_findings
    
    # Save combined findings for dashboard and Gemini
    combined_report = {
        "results": combined_findings,
        "errors": [],
    }
    
    REPORT_FILE.write_text(
        json.dumps(combined_report, indent=2),
        encoding="utf-8",
    )
    
    return {
        "message": "Bandit and Semgrep scans completed.",
        "project_path": str(project_dir),
        "summary": get_summary(combined_findings),
        "findings": combined_findings,
    }


@app.post("/api/findings/{finding_id}/explain")
async def explain_finding_endpoint(finding_id: int):
    report = load_report()
    findings = report["results"]

    if finding_id < 0 or finding_id >= len(findings):
        raise HTTPException(
            status_code=404,
	            detail="Finding not found.",
        )

    finding = findings[finding_id]

    try:
        explanation = await run_in_threadpool(
            explain_finding,
            finding,
        )

        return {
            "finding_id": finding_id,
            "rule": finding.get("test_id", "Unknown"),
            "explanation": explanation,
        }

    except Exception:
        logger.exception("AI explanation request failed")

        raise HTTPException(
            status_code=502,
            detail="Unable to generate an AI explanation. Check the server logs.",
        )
