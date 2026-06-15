"""
Unit tests for the GitHubIntegration module.
All HTTP calls are mocked with pytest-monkeypatch / unittest.mock.
"""

import pytest
from unittest.mock import MagicMock, patch
from github_integration import GitHubIntegration


class TestParsePrUrl:
    def test_valid_url(self):
        owner, repo, num = GitHubIntegration.parse_pr_url(
            "https://github.com/acme/my-app/pull/42"
        )
        assert owner == "acme"
        assert repo == "my-app"
        assert num == 42

    def test_url_with_trailing_slash(self):
        owner, repo, num = GitHubIntegration.parse_pr_url(
            "https://github.com/org/repo/pull/1/"
        )
        assert num == 1

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            GitHubIntegration.parse_pr_url("https://gitlab.com/org/repo/merge_requests/1")

    def test_non_pr_github_url_raises(self):
        with pytest.raises(ValueError):
            GitHubIntegration.parse_pr_url("https://github.com/org/repo/issues/5")


class TestGetPrFiles:
    PR_URL = "https://github.com/acme/app/pull/7"

    def _make_response(self, files):
        resp = MagicMock()
        resp.json.return_value = files
        resp.raise_for_status = MagicMock()
        return resp

    @patch("github_integration.httpx.Client")
    def test_returns_supported_files(self, mock_client_cls):
        files = [
            {"filename": "app/auth.py", "status": "modified", "additions": 10,
             "deletions": 2, "patch": "@@ -1 +1 @@\n+import hashlib", "raw_url": ""},
            {"filename": "README.md", "status": "modified", "additions": 1,
             "deletions": 0, "patch": "", "raw_url": ""},  # not in SUPPORTED_EXTS
        ]
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.get.return_value = self._make_response(files)
        mock_client_cls.return_value = ctx

        gh = GitHubIntegration(token="tok")
        result = gh.get_pr_files(self.PR_URL)

        assert len(result) == 1
        assert result[0]["filename"] == "app/auth.py"

    @patch("github_integration.httpx.Client")
    def test_skips_unsupported_extensions(self, mock_client_cls):
        files = [
            {"filename": "image.png", "status": "added", "additions": 1,
             "deletions": 0, "patch": "", "raw_url": ""},
        ]
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.get.return_value = self._make_response(files)
        mock_client_cls.return_value = ctx

        gh = GitHubIntegration(token="tok")
        result = gh.get_pr_files(self.PR_URL)
        assert result == []

    def test_invalid_pr_url_raises(self):
        gh = GitHubIntegration(token="tok")
        with pytest.raises(ValueError):
            gh.get_pr_files("not-a-url")


class TestFormatReviewBody:
    def test_format_with_vulns(self):
        reports = [
            {
                "filename": "auth.py",
                "risk_score": 90,
                "vulnerabilities": [
                    {"type": "SQL Injection", "severity": "CRITICAL",
                     "cwe_id": "CWE-89", "description": "Direct SQL concat",
                     "line_start": 5},
                ],
            }
        ]
        body = GitHubIntegration.format_review_body(reports)
        assert "SecureCodeSentinel" in body
        assert "auth.py" in body
        assert "CRITICAL" in body
        assert "CWE-89" in body

    def test_format_empty_reports(self):
        body = GitHubIntegration.format_review_body([])
        assert "0" in body  # total vulnerabilities = 0

    def test_format_sorts_by_severity(self):
        reports = [
            {
                "filename": "main.py",
                "risk_score": 50,
                "vulnerabilities": [
                    {"type": "Info Leak", "severity": "LOW", "cwe_id": "CWE-200",
                     "description": "...", "line_start": 10},
                    {"type": "RCE", "severity": "CRITICAL", "cwe_id": "CWE-78",
                     "description": "...", "line_start": 1},
                ],
            }
        ]
        body = GitHubIntegration.format_review_body(reports)
        # CRITICAL should appear before LOW in the output
        assert body.index("CRITICAL") < body.index("LOW")
