from sqlalchemy import Column, Integer, String, Enum, ForeignKey, DateTime, JSON, Text, Boolean
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class UserRole(str, enum.Enum):
    ADMIN = "Admin"
    REVIEWER = "Reviewer"
    DEVELOPER = "Developer"
    AUDITOR = "Auditor"

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

class VulnStatus(str, enum.Enum):
    OPEN = "Open"
    IN_PROGRESS = "In-Progress"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False-Positive"
    RISK_ACCEPTED = "Risk-Accepted"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    github_id = Column(String(100), unique=True, index=True)
    username = Column(String(100), nullable=False)
    email = Column(String(255))
    role = Column(Enum(UserRole), default=UserRole.DEVELOPER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    repository_url = Column(String(500))
    s3_prefix = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="project")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    tool_type = Column(Enum(ToolType), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow)
    s3_report_path = Column(String(500))
    
    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    title = Column(String(500), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    status = Column(Enum(VulnStatus), default=VulnStatus.OPEN)
    category = Column(String(100))
    cve_id = Column(String(50), nullable=True)
    extra_context = Column(JSON)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")
    analysis = relationship("AIAnalysis", back_populates="vulnerability", uselist=False)

class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    summary = Column(Text)
    remediation_code = Column(Text)
    confidence_score = Column(Integer)
    
    vulnerability = relationship("Vulnerability", back_populates="analysis")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)
    action = Column(String(100))
    target_type = Column(String(50))
    target_id = Column(Integer)
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)