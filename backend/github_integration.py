"""
GitHub integration — fetch PR diffs and post review comments.
"""

import os
import re
from typing import Optional
import httpx


class GitHubIntegration:
    BASE = "https://api.github.com"
    SUPPORTED_EXTS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".kt", ".swift",
        ".sh", ".bash", ".yaml", ".yml", ".json", ".xml", ".tf",
        ".sql", ".env.example",
    }

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN", "")

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    @staticmethod
    def parse_pr_url(url: str) -> tuple[str, str, int]:
        """Return (owner, repo, pr_number) from a GitHub PR URL."""
        m = re.search(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)", url)
        if not m:
            raise ValueError(f"Cannot parse GitHub PR URL: {url}")
        return m.group(1), m.group(2), int(m.group(3))

    def get_pr_files(self, pr_url: str, token: Optional[str] = None) -> list[dict]:
        """
        Fetch the list of changed files in a PR.
        Returns list of {filename, patch, status, additions, deletions, raw_url}.
        """
        if token:
            self.token = token
        owner, repo, pr_num = self.parse_pr_url(pr_url)
        url = f"{self.BASE}/repos/{owner}/{repo}/pulls/{pr_num}/files"

        with httpx.Client(timeout=30) as client:
            resp = client.get(url, headers=self._headers())
            resp.raise_for_status()
            files = resp.json()

        result = []
        for f in files:
            ext = "." + f["filename"].rsplit(".", 1)[-1] if "." in f["filename"] else ""
            if ext.lower() not in self.SUPPORTED_EXTS:
                continue
            entry = {
                "filename": f["filename"],
                "status": f.get("status"),
                "additions": f.get("additions", 0),
                "deletions": f.get("deletions", 0),
                "patch": f.get("patch", ""),
                "raw_url": f.get("raw_url", ""),
            }
            result.append(entry)
        return result

    def get_file_content(self, raw_url: str, token: Optional[str] = None) -> str:
        """Download raw file content from GitHub."""
        if token:
            self.token = token
        with httpx.Client(timeout=30) as client:
            resp = client.get(raw_url, headers=self._headers())
            resp.raise_for_status()
            return resp.text

    def get_pr_metadata(self, pr_url: str, token: Optional[str] = None) -> dict:
        """Return basic PR metadata (title, author, base branch, etc.)."""
        if token:
            self.token = token
        owner, repo, pr_num = self.parse_pr_url(pr_url)
        url = f"{self.BASE}/repos/{owner}/{repo}/pulls/{pr_num}"
        with httpx.Client(timeout=30) as client:
            resp = client.get(url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
        return {
            "title": data.get("title"),
            "author": data.get("user", {}).get("login"),
            "base_branch": data.get("base", {}).get("ref"),
            "head_branch": data.get("head", {}).get("ref"),
            "repo_name": f"{owner}/{repo}",
            "html_url": data.get("html_url"),
        }

    def post_review_comment(
        self,
        pr_url: str,
        body: str,
        token: Optional[str] = None,
    ) -> dict:
        """Post a PR review comment summarising findings."""
        if token:
            self.token = token
        owner, repo, pr_num = self.parse_pr_url(pr_url)
        url = f"{self.BASE}/repos/{owner}/{repo}/pulls/{pr_num}/reviews"
        payload = {"body": body, "event": "COMMENT"}
        with httpx.Client(timeout=30) as client:
            resp = client.post(url, json=payload, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def format_review_body(reports: list[dict]) -> str:
        """Format analysis results into a GitHub PR review comment (Markdown)."""
        lines = ["## SecureCodeSentinel Security Review\n"]
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in reports)
        avg_score = (
            sum(r.get("risk_score", 0) for r in reports) / len(reports) if reports else 0
        )
        lines.append(f"**Files analysed:** {len(reports)}  ")
        lines.append(f"**Total vulnerabilities:** {total_vulns}  ")
        lines.append(f"**Average risk score:** {avg_score:.0f}/100\n")

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

        for report in reports:
            lines.append(f"### `{report.get('filename', 'unknown')}`")
            lines.append(f"Risk score: **{report.get('risk_score', 0)}/100**\n")
            vulns = sorted(
                report.get("vulnerabilities", []),
                key=lambda v: severity_order.get(v.get("severity", "LOW"), 3),
            )
            for v in vulns:
                sev = v.get("severity", "LOW")
                lines.append(
                    f"- {emoji.get(sev, '')} **{sev}** — {v.get('type')} "
                    f"({v.get('cwe_id', '')}) @ line {v.get('line_start', '?')}"
                )
                lines.append(f"  > {v.get('description', '')}")
            lines.append("")

        lines.append(
            "\n_Generated by [SecureCodeSentinel](https://github.com/your-org/secure-code-sentinel)_"
        )
        return "\n".join(lines)
