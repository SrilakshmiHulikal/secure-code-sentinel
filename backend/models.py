from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid

Base = declarative_base()


# ── SQLAlchemy ORM models ──────────────────────────────────────────────────────

class DBReport(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String, default="paste")          # paste | file | github_pr
    filename = Column(String, nullable=True)
    language = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    summary = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)        # first 2000 chars for display
    pr_url = Column(String, nullable=True)
    repo_name = Column(String, nullable=True)
    vulnerabilities = relationship("DBVulnerability", back_populates="report", cascade="all, delete-orphan")


class DBVulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = Column(String, ForeignKey("reports.id"), nullable=False)
    vuln_type = Column(String, nullable=False)
    owasp_category = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    cwe_name = Column(String, nullable=True)
    severity = Column(String, nullable=False)         # CRITICAL | HIGH | MEDIUM | LOW
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    description = Column(Text, nullable=True)
    vulnerable_code = Column(Text, nullable=True)
    fix_description = Column(Text, nullable=True)
    fixed_code = Column(Text, nullable=True)
    report = relationship("DBReport", back_populates="vulnerabilities")


# ── Pydantic request / response schemas ───────────────────────────────────────

class CodeAnalysisRequest(BaseModel):
    code: str
    language: Optional[str] = None
    filename: Optional[str] = None


class GitHubPRRequest(BaseModel):
    pr_url: str
    github_token: Optional[str] = None   # falls back to env var
    post_review: bool = False


class VulnerabilityOut(BaseModel):
    id: str
    vuln_type: str
    owasp_category: Optional[str]
    cwe_id: Optional[str]
    cwe_name: Optional[str]
    severity: str
    line_start: Optional[int]
    line_end: Optional[int]
    description: Optional[str]
    vulnerable_code: Optional[str]
    fix_description: Optional[str]
    fixed_code: Optional[str]

    class Config:
        from_attributes = True


class ReportOut(BaseModel):
    id: str
    created_at: datetime
    source: str
    filename: Optional[str]
    language: Optional[str]
    risk_score: float
    summary: Optional[str]
    code_snippet: Optional[str]
    pr_url: Optional[str]
    repo_name: Optional[str]
    vulnerabilities: List[VulnerabilityOut] = []

    class Config:
        from_attributes = True


class ReportSummaryOut(BaseModel):
    id: str
    created_at: datetime
    source: str
    filename: Optional[str]
    language: Optional[str]
    risk_score: float
    summary: Optional[str]
    pr_url: Optional[str]
    repo_name: Optional[str]
    vulnerability_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_reports: int
    avg_risk_score: float
    total_vulnerabilities: int
    by_severity: dict
    by_owasp: dict
    recent_reports: List[ReportSummaryOut]
    risk_trend: List[dict]   # [{date, avg_score}]


class FixRequest(BaseModel):
    report_id: str
    vulnerability_id: str
