"""
Demo tests — showcase the tool against deliberately vulnerable code snippets.
These tests run against the real Claude API (requires ANTHROPIC_API_KEY).
Skip them in CI or when the key is unavailable.

Run with:
    pytest tests/test_demo.py -v -s --demo

They are marked with @pytest.mark.demo so they are excluded from the default
test run and only execute when --demo is passed.
"""

import os
import pytest

demo = pytest.mark.skipif(
    os.getenv("ANTHROPIC_API_KEY", "").startswith("test"),
    reason="Skipped: real ANTHROPIC_API_KEY required for demo tests",
)


# ── Vulnerable code fixtures ───────────────────────────────────────────────────

SQL_INJECTION_PY = """
import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()
"""

HARDCODED_AWS_CREDS = """
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def upload_to_s3(file_path, bucket):
    s3 = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    s3.upload_file(file_path, bucket, file_path)
"""

COMMAND_INJECTION_JS = """
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, (error, stdout) => {
        res.send(stdout);
    });
});
"""

XSS_PHP = """
<?php
$name = $_GET['name'];
echo "<h1>Welcome, " . $name . "!</h1>";

$search = $_POST['search'];
$results = db_query("SELECT * FROM products WHERE name LIKE '%" . $search . "%'");
?>
"""

PATH_TRAVERSAL_JAVA = """
import java.io.*;
import javax.servlet.http.*;

public class FileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        File file = new File("/var/www/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        // stream file to response...
    }
}
"""

CLEAN_PYTHON = """
import secrets
import hashlib
import hmac
from typing import Optional

def generate_secure_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 260_000)
    return key.hex(), salt

def verify_password(password: str, stored_hash: str, salt: bytes) -> bool:
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, stored_hash)
"""


# ── Demo test class ────────────────────────────────────────────────────────────

class TestDemoVulnerableCode:
    """
    End-to-end demonstration tests against real Claude API.
    Each test asserts that the analyser correctly identifies the expected
    vulnerability class in obviously vulnerable code.
    """

    @demo
    def test_detects_sql_injection(self):
        from analyzer import CodeAnalyzer
        a = CodeAnalyzer()
        result = a.analyze(SQL_INJECTION_PY, language="Python", filename="auth.py")

        print(f"\n[SQL Injection Demo] Risk score: {result['risk_score']}")
        vuln_types = [v["type"].lower() for v in result["vulnerabilities"]]
        cwe_ids = [v.get("cwe_id", "") for v in result["vulnerabilities"]]

        assert result["risk_score"] > 50, "SQL injection code should score > 50"
        assert any("sql" in t for t in vuln_types) or "CWE-89" in cwe_ids, \
            f"Expected SQL injection detection, got: {vuln_types}"

    @demo
    def test_detects_hardcoded_credentials(self):
        from analyzer import CodeAnalyzer
        a = CodeAnalyzer()
        result = a.analyze(HARDCODED_AWS_CREDS, language="Python", filename="s3_upload.py")

        print(f"\n[Hardcoded Creds Demo] Risk score: {result['risk_score']}")
        vuln_types = [v["type"].lower() for v in result["vulnerabilities"]]
        cwe_ids = [v.get("cwe_id", "") for v in result["vulnerabilities"]]

        assert result["risk_score"] > 40
        assert any(
            "secret" in t or "credential" in t or "hardcod" in t or "key" in t
            for t in vuln_types
        ) or any(c in ("CWE-798", "CWE-259", "CWE-321") for c in cwe_ids), \
            f"Expected credential detection, got: {vuln_types}"

    @demo
    def test_detects_command_injection_js(self):
        from analyzer import CodeAnalyzer
        a = CodeAnalyzer()
        result = a.analyze(COMMAND_INJECTION_JS, language="JavaScript", filename="server.js")

        print(f"\n[Command Injection Demo] Risk score: {result['risk_score']}")
        vuln_types = [v["type"].lower() for v in result["vulnerabilities"]]
        cwe_ids = [v.get("cwe_id", "") for v in result["vulnerabilities"]]

        assert result["risk_score"] > 50
        assert any("command" in t or "injection" in t or "exec" in t for t in vuln_types) \
            or "CWE-78" in cwe_ids, \
            f"Expected command injection detection, got: {vuln_types}"

    @demo
    def test_detects_xss_and_sqli_php(self):
        from analyzer import CodeAnalyzer
        a = CodeAnalyzer()
        result = a.analyze(XSS_PHP, language="PHP", filename="search.php")

        print(f"\n[XSS+SQLi PHP Demo] Risk score: {result['risk_score']}")
        assert result["risk_score"] > 60, "PHP with XSS+SQLi should score > 60"
        assert len(result["vulnerabilities"]) >= 1

    @demo
    def test_detects_path_traversal_java(self):
        from analyzer import CodeAnalyzer
        a = CodeAnalyzer()
        result = a.analyze(PATH_TRAVERSAL_JAVA, language="Java", filename="FileServlet.java")

        print(f"\n[Path Traversal Demo] Risk score: {result['risk_score']}")
        vuln_types = [v["type"].lower() for v in result["vulnerabilities"]]
        cwe_ids = [v.get("cwe_id", "") for v in result["vulnerabilities"]]

        assert result["risk_score"] > 30
        assert any("path" in t or "traversal" in t or "directory" in t for t in vuln_types) \
            or "CWE-22" in cwe_ids, \
            f"Expected path traversal detection, got: {vuln_types}"

    @demo
    def test_clean_code_scores_low(self):
        from analyzer import CodeAnalyzer
        a = CodeAnalyzer()
        result = a.analyze(CLEAN_PYTHON, language="Python", filename="crypto_utils.py")

        print(f"\n[Clean Code Demo] Risk score: {result['risk_score']}")
        assert result["risk_score"] < 30, \
            f"Clean code should score < 30, got {result['risk_score']}"

    @demo
    def test_fix_suggestion_is_actionable(self):
        """Ensure fix suggestions are syntactically non-empty and relevant."""
        from analyzer import CodeAnalyzer
        a = CodeAnalyzer()
        analysis = a.analyze(SQL_INJECTION_PY)
        assert len(analysis["vulnerabilities"]) > 0

        vuln = analysis["vulnerabilities"][0]
        fix = a.suggest_fix(vuln.get("vulnerable_code", SQL_INJECTION_PY), vuln)

        print(f"\n[Fix Demo] Explanation: {fix.get('explanation', '')[:120]}…")
        assert fix.get("explanation"), "Fix must include an explanation"
        assert fix.get("fixed_code"), "Fix must include fixed_code"
        # The fix should not reproduce the exact same vulnerable pattern
        assert "' +" not in fix.get("fixed_code", ""), \
            "Fixed code should not contain raw string concatenation for SQL"
