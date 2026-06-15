"""
Unit tests for Pydantic models and DB ORM models.
"""

import pytest
from datetime import datetime
from models import (
    DBReport, DBVulnerability,
    CodeAnalysisRequest, GitHubPRRequest, FixRequest,
    VulnerabilityOut, ReportSummaryOut,
)


class TestCodeAnalysisRequest:
    def test_valid_request(self):
        req = CodeAnalysisRequest(code="print('hello')")
        assert req.code == "print('hello')"
        assert req.language is None

    def test_with_optional_fields(self):
        req = CodeAnalysisRequest(code="x = 1", language="Python", filename="main.py")
        assert req.language == "Python"
        assert req.filename == "main.py"

    def test_empty_code_is_allowed_at_pydantic_level(self):
        # Validation of empty string happens at API layer, not pydantic layer
        req = CodeAnalysisRequest(code="")
        assert req.code == ""


class TestGitHubPRRequest:
    def test_valid_pr_url(self):
        req = GitHubPRRequest(pr_url="https://github.com/org/repo/pull/1")
        assert req.post_review is False

    def test_post_review_default_false(self):
        req = GitHubPRRequest(pr_url="https://github.com/org/repo/pull/1")
        assert req.post_review is False


class TestVulnerabilityOut:
    def test_from_orm(self, db):
        report = DBReport(id="r1", source="paste")
        db.add(report)
        db.flush()

        vuln = DBVulnerability(
            id="v1",
            report_id="r1",
            vuln_type="SQL Injection",
            owasp_category="A03:2021 – Injection",
            cwe_id="CWE-89",
            cwe_name="SQL Command Injection",
            severity="CRITICAL",
            line_start=5,
            line_end=7,
            description="Direct SQL concat",
            vulnerable_code="query = 'SELECT' + user_input",
            fix_description="Use parameterised queries",
            fixed_code="cursor.execute('SELECT ?', (user_input,))",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)

        out = VulnerabilityOut.model_validate(vuln)
        assert out.id == "v1"
        assert out.cwe_id == "CWE-89"
        assert out.severity == "CRITICAL"
        assert out.line_start == 5


class TestDBReport:
    def test_report_vulnerability_relationship(self, db):
        report = DBReport(id="r2", source="file", filename="test.py")
        db.add(report)
        db.flush()

        for i in range(3):
            db.add(DBVulnerability(
                id=f"v{i}",
                report_id="r2",
                vuln_type=f"Vuln{i}",
                severity=["CRITICAL", "HIGH", "MEDIUM"][i],
            ))

        db.commit()
        db.refresh(report)
        assert len(report.vulnerabilities) == 3

    def test_cascade_delete(self, db):
        report = DBReport(id="r3", source="paste")
        db.add(report)
        db.flush()
        db.add(DBVulnerability(id="v99", report_id="r3", vuln_type="X", severity="LOW"))
        db.commit()

        db.delete(report)
        db.commit()

        remaining = db.query(DBVulnerability).filter_by(id="v99").first()
        assert remaining is None, "Cascade delete should remove child vulnerabilities"
