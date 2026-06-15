"""
Integration tests for the FastAPI endpoints.
The analyzer is mocked to avoid real Claude API calls.
DB uses an in-memory SQLite instance provided by conftest.py.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import (
    SAMPLE_SQL_INJECTION,
    SAMPLE_CLEAN_CODE,
    MOCK_ANALYSIS_RESULT,
    MOCK_CLEAN_RESULT,
)


def _patch_analyzer(result):
    """Context manager that patches CodeAnalyzer.analyze() with `result`."""
    return patch("main.analyzer.analyze", return_value=result)


def _patch_analyzer_clean():
    return _patch_analyzer(MOCK_CLEAN_RESULT)


def _patch_analyzer_vuln():
    return _patch_analyzer(MOCK_ANALYSIS_RESULT)


# ── /health ────────────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


# ── /analyze ──────────────────────────────────────────────────────────────────

class TestAnalyzeEndpoint:
    def test_analyze_returns_report(self, client):
        with _patch_analyzer_vuln():
            r = client.post("/analyze", json={"code": SAMPLE_SQL_INJECTION})
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] == 85
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["cwe_id"] == "CWE-89"
        assert "id" in data

    def test_analyze_clean_code(self, client):
        with _patch_analyzer_clean():
            r = client.post("/analyze", json={"code": SAMPLE_CLEAN_CODE})
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] == 0
        assert data["vulnerabilities"] == []

    def test_analyze_with_language_and_filename(self, client):
        with _patch_analyzer_vuln():
            r = client.post("/analyze", json={
                "code": SAMPLE_SQL_INJECTION,
                "language": "Python",
                "filename": "auth.py",
            })
        assert r.status_code == 200
        assert r.json()["filename"] == "auth.py"

    def test_empty_code_returns_400(self, client):
        r = client.post("/analyze", json={"code": "   "})
        assert r.status_code == 400

    def test_report_persisted_to_db(self, client):
        with _patch_analyzer_vuln():
            r = client.post("/analyze", json={"code": SAMPLE_SQL_INJECTION})
        report_id = r.json()["id"]

        # Fetch it back
        r2 = client.get(f"/reports/{report_id}")
        assert r2.status_code == 200
        assert r2.json()["id"] == report_id


# ── /analyze/file ─────────────────────────────────────────────────────────────

class TestAnalyzeFileEndpoint:
    def test_upload_text_file(self, client):
        with _patch_analyzer_vuln():
            r = client.post(
                "/analyze/file",
                files={"file": ("vuln.py", SAMPLE_SQL_INJECTION.encode(), "text/plain")},
            )
        assert r.status_code == 200
        assert r.json()["filename"] == "vuln.py"

    def test_upload_empty_file_still_analysed(self, client):
        with _patch_analyzer_clean():
            r = client.post(
                "/analyze/file",
                files={"file": ("clean.py", SAMPLE_CLEAN_CODE.encode(), "text/plain")},
            )
        assert r.status_code == 200


# ── /reports ──────────────────────────────────────────────────────────────────

class TestReportsEndpoint:
    def test_list_empty(self, client):
        r = client.get("/reports")
        assert r.status_code == 200
        assert r.json() == []

    def test_list_after_analysis(self, client):
        with _patch_analyzer_vuln():
            client.post("/analyze", json={"code": SAMPLE_SQL_INJECTION})
        r = client.get("/reports")
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_get_report_not_found(self, client):
        r = client.get("/reports/nonexistent-id")
        assert r.status_code == 404

    def test_delete_report(self, client):
        with _patch_analyzer_vuln():
            report_id = client.post("/analyze", json={"code": SAMPLE_SQL_INJECTION}).json()["id"]

        r = client.delete(f"/reports/{report_id}")
        assert r.status_code == 200

        r2 = client.get(f"/reports/{report_id}")
        assert r2.status_code == 404

    def test_list_source_filter(self, client):
        with _patch_analyzer_vuln():
            client.post("/analyze", json={"code": SAMPLE_SQL_INJECTION})
        r = client.get("/reports", params={"source": "paste"})
        assert all(x["source"] == "paste" for x in r.json())

        r2 = client.get("/reports", params={"source": "github_pr"})
        assert r2.json() == []


# ── /dashboard ────────────────────────────────────────────────────────────────

class TestDashboardEndpoint:
    def test_empty_dashboard(self, client):
        r = client.get("/dashboard")
        assert r.status_code == 200
        data = r.json()
        assert data["total_reports"] == 0
        assert data["total_vulnerabilities"] == 0
        assert data["avg_risk_score"] == 0

    def test_dashboard_counts_after_analysis(self, client):
        with _patch_analyzer_vuln():
            client.post("/analyze", json={"code": SAMPLE_SQL_INJECTION})
        r = client.get("/dashboard")
        assert r.status_code == 200
        data = r.json()
        assert data["total_reports"] == 1
        assert data["total_vulnerabilities"] == 1
        assert data["by_severity"].get("CRITICAL", 0) == 1

    def test_dashboard_recent_reports_capped_at_10(self, client):
        with _patch_analyzer_clean():
            for _ in range(15):
                client.post("/analyze", json={"code": SAMPLE_CLEAN_CODE})
        r = client.get("/dashboard")
        assert len(r.json()["recent_reports"]) <= 10


# ── /fix ──────────────────────────────────────────────────────────────────────

class TestFixEndpoint:
    def test_get_fix_returns_remediation(self, client):
        with _patch_analyzer_vuln():
            report = client.post("/analyze", json={"code": SAMPLE_SQL_INJECTION}).json()

        report_id = report["id"]
        vuln_id = report["vulnerabilities"][0]["id"]

        fix_data = {
            "explanation": "Concatenating user input into SQL is dangerous.",
            "fixed_code": "cursor.execute('SELECT * FROM users WHERE username = ?', (username,))",
            "best_practices": ["Use parameterised queries"],
            "references": ["https://owasp.org"],
        }
        with patch("main.analyzer.suggest_fix", return_value=fix_data):
            r = client.post("/fix", json={"report_id": report_id, "vulnerability_id": vuln_id})

        assert r.status_code == 200
        assert "explanation" in r.json()

    def test_fix_invalid_report_returns_404(self, client):
        r = client.post("/fix", json={"report_id": "bad-id", "vulnerability_id": "bad-id"})
        assert r.status_code == 404
