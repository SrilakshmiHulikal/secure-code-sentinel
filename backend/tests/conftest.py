"""
Shared pytest fixtures for SecureCodeSentinel tests.
"""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Use an in-memory SQLite DB for tests
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from database import get_db
from models import Base
import main as app_module

# StaticPool ensures ALL connections reuse the same underlying SQLite connection,
# which is required so that create_all() and subsequent sessions share the same
# in-memory database.
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture(scope="function")
def client(db):
    """FastAPI test client with overridden DB session and engine."""
    # Create all tables in the in-memory test engine
    Base.metadata.create_all(bind=TEST_ENGINE)

    def override_get_db():
        try:
            yield db
        finally:
            pass

    # Also patch init_db so the startup event doesn't touch the prod DB
    import database as db_module
    original_engine = db_module.engine
    db_module.engine = TEST_ENGINE

    app_module.app.dependency_overrides[get_db] = override_get_db
    with TestClient(app_module.app) as c:
        yield c
    app_module.app.dependency_overrides.clear()
    db_module.engine = original_engine


# ── Sample vulnerable code snippets used across tests ─────────────────────────

SAMPLE_SQL_INJECTION = """
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return db.execute(query)
"""

SAMPLE_HARDCODED_SECRET = """
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def connect():
    return boto3.client('s3', aws_secret_access_key=AWS_SECRET_KEY)
"""

SAMPLE_COMMAND_INJECTION = """
import subprocess

def ping(host):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout
"""

SAMPLE_XSS = """
def render_greeting(name):
    return f"<h1>Hello, {name}!</h1>"

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return render_greeting(name)
"""

SAMPLE_CLEAN_CODE = """
import secrets
import hashlib

def generate_token():
    return secrets.token_urlsafe(32)

def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
"""

MOCK_ANALYSIS_RESULT = {
    "language": "Python",
    "risk_score": 85,
    "summary": "Critical SQL injection and hardcoded secrets detected.",
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "owasp_category": "A03:2021 – Injection",
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "severity": "CRITICAL",
            "line_start": 2,
            "line_end": 3,
            "description": "User input is directly concatenated into SQL query.",
            "vulnerable_code": "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"",
            "fix_description": "Use parameterised queries or an ORM.",
            "fixed_code": "query = 'SELECT * FROM users WHERE username = ?'\ndb.execute(query, (username,))",
        }
    ],
}

MOCK_CLEAN_RESULT = {
    "language": "Python",
    "risk_score": 0,
    "summary": "No vulnerabilities detected.",
    "vulnerabilities": [],
}
