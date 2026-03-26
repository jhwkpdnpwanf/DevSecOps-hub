from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class UserRole(str, enum.Enum):
    ADMIN = "Admin"
    SECURITY_ANALYST = "SecurityAnalyst"
    DEVELOPER = "Developer"
    VIEWER = "Viewer"


class ToolType(str, enum.Enum):
    SAST = "Semgrep"
    DAST = "ZAP"
    SCA = "pip-audit"


class Severity(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Priority(str, enum.Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class VulnStatus(str, enum.Enum):
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    VERIFIED = "VERIFIED"
    CLOSED = "CLOSED"


class Criticality(str, enum.Enum):
    CORE = "CORE"
    IMPORTANT = "IMPORTANT"
    STANDARD = "STANDARD"


class Exposure(str, enum.Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=True)
    password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.DEVELOPER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    assignments = relationship("VulnerabilityAssignment", back_populates="assignee")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    repository_url = Column(String(500), nullable=True)
    api_token = Column(String(255), unique=True, nullable=False, index=True)
    s3_prefix = Column(String(255), nullable=True)
    business_criticality = Column(Enum(Criticality), default=Criticality.STANDARD, nullable=False)
    exposure = Column(Enum(Exposure), default=Exposure.INTERNAL, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    tool_type = Column(Enum(ToolType), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    branch = Column(String(255), nullable=True)
    commit_sha = Column(String(255), nullable=True)
    pipeline_run_id = Column(String(255), nullable=True)
    s3_report_path = Column(String(500), nullable=True)
    raw_report_path = Column(String(500), nullable=True)

    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("scan_id", "vulnerability_key", name="uq_scan_vulnerability_key"),
    )

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    vulnerability_key = Column(String(500), nullable=False)
    title = Column(String(500), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    priority = Column(Enum(Priority), default=Priority.P3, nullable=False)
    status = Column(Enum(VulnStatus), default=VulnStatus.DETECTED, nullable=False)
    category = Column(String(100), nullable=True)
    cve_id = Column(String(100), nullable=True)
    cwe_id = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    location = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    due_date = Column(DateTime, nullable=True)
    extra_context = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="vulnerabilities")
    analysis = relationship("AIAnalysis", back_populates="vulnerability", uselist=False, cascade="all, delete-orphan")
    assignments = relationship("VulnerabilityAssignment", back_populates="vulnerability", cascade="all, delete-orphan")
    status_history = relationship("VulnerabilityStatusHistory", back_populates="vulnerability", cascade="all, delete-orphan")


class VulnerabilityAssignment(Base):
    __tablename__ = "vulnerability_assignments"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    due_date = Column(DateTime, nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="assignments")
    assignee = relationship("User", back_populates="assignments")


class VulnerabilityStatusHistory(Base):
    __tablename__ = "vulnerability_status_history"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    from_status = Column(String(50), nullable=True)
    to_status = Column(String(50), nullable=False)
    changed_by = Column(String(100), nullable=False)
    comment = Column(Text, nullable=True)
    changed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="status_history")


class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, unique=True)
    model_name = Column(String(100), nullable=False)
    summary = Column(Text, nullable=False)
    remediation_code = Column(Text, nullable=True)
    confidence_score = Column(Integer, nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="analysis")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(100), index=True, nullable=False)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(100), nullable=False)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
