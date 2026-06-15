"""
SecureCodeSentinel — FastAPI backend
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
from collections import Counter, defaultdict

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import init_db, get_db
from models import (
    DBReport, DBVulnerability,
    CodeAnalysisRequest, GitHubPRRequest, FixRequest,
    ReportOut, ReportSummaryOut, DashboardStats, VulnerabilityOut,
)
from analyzer import CodeAnalyzer
from github_integration import GitHubIntegration

app = FastAPI(title="SecureCodeSentinel API", version="1.0.0", docs_url="/docs")

# ── CORS ───────────────────────────────────────────────────────────────────────
origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = CodeAnalyzer()
github = GitHubIntegration()


@app.on_event("startup")
def startup():
    init_db()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _save_report(
    db: Session,
    analysis: dict,
    code: str,
    source: str = "paste",
    filename: Optional[str] = None,
    pr_url: Optional[str] = None,
    repo_name: Optional[str] = None,
) -> DBReport:
    report = DBReport(
        id=str(uuid.uuid4()),
        source=source,
        filename=filename,
        language=analysis.get("language"),
        risk_score=float(analysis.get("risk_score", 0)),
        summary=analysis.get("summary"),
        code_snippet=code[:3000],
        pr_url=pr_url,
        repo_name=repo_name,
    )
    db.add(report)
    db.flush()

    for v in analysis.get("vulnerabilities", []):
        vuln = DBVulnerability(
            id=str(uuid.uuid4()),
            report_id=report.id,
            vuln_type=v.get("type", "Unknown"),
            owasp_category=v.get("owasp_category"),
            cwe_id=v.get("cwe_id"),
            cwe_name=v.get("cwe_name"),
            severity=v.get("severity", "LOW"),
            line_start=v.get("line_start"),
            line_end=v.get("line_end"),
            description=v.get("description"),
            vulnerable_code=v.get("vulnerable_code"),
            fix_description=v.get("fix_description"),
            fixed_code=v.get("fixed_code"),
        )
        db.add(vuln)

    db.commit()
    db.refresh(report)
    return report


def _report_to_summary(report: DBReport) -> ReportSummaryOut:
    vulns = report.vulnerabilities
    severity_counts = Counter(v.severity for v in vulns)
    return ReportSummaryOut(
        id=report.id,
        created_at=report.created_at,
        source=report.source,
        filename=report.filename,
        language=report.language,
        risk_score=report.risk_score,
        summary=report.summary,
        pr_url=report.pr_url,
        repo_name=report.repo_name,
        vulnerability_count=len(vulns),
        critical_count=severity_counts.get("CRITICAL", 0),
        high_count=severity_counts.get("HIGH", 0),
        medium_count=severity_counts.get("MEDIUM", 0),
        low_count=severity_counts.get("LOW", 0),
    )


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "provider": analyzer.provider,
        "model": analyzer.model,
    }


# ── Analysis endpoints ─────────────────────────────────────────────────────────

@app.post("/analyze", response_model=ReportOut)
def analyze_code(req: CodeAnalysisRequest, db: Session = Depends(get_db)):
    """Analyse a code snippet pasted directly."""
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Code must not be empty.")

    analysis = analyzer.analyze(req.code, language=req.language, filename=req.filename)
    report = _save_report(db, analysis, req.code, source="paste", filename=req.filename)
    return report


@app.post("/analyze/file", response_model=ReportOut)
async def analyze_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Analyse an uploaded source file."""
    content = await file.read()
    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text.")

    if len(code) > 500_000:
        raise HTTPException(status_code=400, detail="File too large (max 500 KB).")

    analysis = analyzer.analyze(code, filename=file.filename)
    report = _save_report(db, analysis, code, source="file", filename=file.filename)
    return report


@app.post("/analyze/github-pr", response_model=List[ReportOut])
def analyze_github_pr(req: GitHubPRRequest, db: Session = Depends(get_db)):
    """Analyse all changed source files in a GitHub Pull Request."""
    try:
        token = req.github_token or os.getenv("GITHUB_TOKEN")
        meta = github.get_pr_metadata(req.pr_url, token=token)
        files = github.get_pr_files(req.pr_url, token=token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")

    if not files:
        raise HTTPException(status_code=404, detail="No supported source files found in this PR.")

    reports = []
    all_analyses = []
    for f in files:
        # Use patch if raw content unavailable
        code = f.get("patch", "")
        if f.get("raw_url"):
            try:
                code = github.get_file_content(f["raw_url"], token=token)
            except Exception:
                pass  # fall back to patch

        if not code.strip():
            continue

        analysis = analyzer.analyze(code, filename=f["filename"])
        analysis["filename"] = f["filename"]
        all_analyses.append(analysis)
        report = _save_report(
            db, analysis, code,
            source="github_pr",
            filename=f["filename"],
            pr_url=req.pr_url,
            repo_name=meta.get("repo_name"),
        )
        reports.append(report)

    # Optionally post review back to GitHub
    if req.post_review and token and reports:
        review_body = github.format_review_body(all_analyses)
        try:
            github.post_review_comment(req.pr_url, review_body, token=token)
        except Exception:
            pass  # non-fatal

    return reports


# ── Fix endpoint ───────────────────────────────────────────────────────────────

@app.post("/fix")
def get_fix(req: FixRequest, db: Session = Depends(get_db)):
    """Return a detailed remediation guide for a specific vulnerability."""
    report = db.query(DBReport).filter(DBReport.id == req.report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    vuln = db.query(DBVulnerability).filter(
        DBVulnerability.id == req.vulnerability_id,
        DBVulnerability.report_id == req.report_id,
    ).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")

    vuln_dict = {
        "type": vuln.vuln_type,
        "cwe_id": vuln.cwe_id,
        "severity": vuln.severity,
        "description": vuln.description,
        "fixed_code": vuln.fixed_code,
    }
    fix = analyzer.suggest_fix(vuln.vulnerable_code or report.code_snippet or "", vuln_dict)
    return fix


# ── Reports endpoints ──────────────────────────────────────────────────────────

@app.get("/reports", response_model=List[ReportSummaryOut])
def list_reports(
    limit: int = 50,
    offset: int = 0,
    source: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(DBReport)
    if source:
        q = q.filter(DBReport.source == source)
    reports = q.order_by(DBReport.created_at.desc()).offset(offset).limit(limit).all()
    return [_report_to_summary(r) for r in reports]


@app.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(DBReport).filter(DBReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@app.delete("/reports/{report_id}")
def delete_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(DBReport).filter(DBReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    db.delete(report)
    db.commit()
    return {"deleted": report_id}


# ── Dashboard ──────────────────────────────────────────────────────────────────

@app.get("/dashboard", response_model=DashboardStats)
def get_dashboard(db: Session = Depends(get_db)):
    reports = db.query(DBReport).order_by(DBReport.created_at.desc()).all()
    all_vulns = db.query(DBVulnerability).all()

    avg_score = sum(r.risk_score for r in reports) / len(reports) if reports else 0

    by_severity = Counter(v.severity for v in all_vulns)
    by_owasp = Counter(v.owasp_category for v in all_vulns if v.owasp_category)

    # Risk trend: group by day (last 30 days)
    cutoff = datetime.utcnow() - timedelta(days=30)
    trend_data: dict = defaultdict(list)
    for r in reports:
        if r.created_at >= cutoff:
            day = r.created_at.strftime("%Y-%m-%d")
            trend_data[day].append(r.risk_score)
    risk_trend = [
        {"date": day, "avg_score": round(sum(scores) / len(scores), 1)}
        for day, scores in sorted(trend_data.items())
    ]

    return DashboardStats(
        total_reports=len(reports),
        avg_risk_score=round(avg_score, 1),
        total_vulnerabilities=len(all_vulns),
        by_severity=dict(by_severity),
        by_owasp=dict(by_owasp),
        recent_reports=[_report_to_summary(r) for r in reports[:10]],
        risk_trend=risk_trend,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
