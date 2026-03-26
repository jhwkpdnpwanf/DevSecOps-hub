from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy.orm import Session

from app.database.models import (
    AuditLog,
    Priority,
    Project,
    Scan,
    Severity,
    ToolType,
    Vulnerability,
    VulnerabilityStatusHistory,
)


SEVERITY_PRIORITY_MAP = {
    Severity.CRITICAL: (Priority.P0, 1),
    Severity.HIGH: (Priority.P1, 3),
    Severity.MEDIUM: (Priority.P2, 7),
    Severity.LOW: (Priority.P3, 30),
    Severity.INFO: (Priority.P3, 30),
}


def _coerce_tool_type(tool_type: str | ToolType) -> ToolType:
    if isinstance(tool_type, ToolType):
        return tool_type

    normalized = str(tool_type).strip().lower()
    mapping = {
        "semgrep": ToolType.SAST,
        "sast": ToolType.SAST,
        "zap": ToolType.DAST,
        "dast": ToolType.DAST,
        "pip-audit": ToolType.SCA,
        "pip_audit": ToolType.SCA,
        "sca": ToolType.SCA,
    }
    if normalized not in mapping:
        raise ValueError(f"지원하지 않는 tool_type 입니다: {tool_type}")
    return mapping[normalized]


def _apply_policy(vulnerability: Vulnerability, project: Project | None) -> None:
    priority, sla_days = SEVERITY_PRIORITY_MAP.get(vulnerability.severity, (Priority.P3, 30))

    if project and project.business_criticality.value == "CORE" and priority != Priority.P0:
        priority = Priority.P1 if priority in {Priority.P2, Priority.P3} else priority
        sla_days = min(sla_days, 3)

    if project and project.exposure.value == "PUBLIC" and priority in {Priority.P2, Priority.P3}:
        priority = Priority.P1
        sla_days = min(sla_days, 3)

    vulnerability.priority = priority
    vulnerability.due_date = datetime.utcnow() + timedelta(days=sla_days)


def save_scan_results(db: Session, project_id: int, tool_type: str | ToolType, vulnerabilities: Iterable[Vulnerability]):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise ValueError(f"project_id={project_id} 프로젝트가 존재하지 않습니다.")

    new_scan = Scan(project_id=project_id, tool_type=_coerce_tool_type(tool_type))
    db.add(new_scan)
    db.flush()

    count = 0
    for vulnerability in vulnerabilities:
        vulnerability.scan_id = new_scan.id
        _apply_policy(vulnerability, project)
        db.add(vulnerability)
        db.flush()

        db.add(
            VulnerabilityStatusHistory(
                vulnerability_id=vulnerability.id,
                from_status=None,
                to_status=vulnerability.status.value,
                changed_by="system:ingestion",
                comment="초기 탐지 결과 등록",
            )
        )
        count += 1

    db.add(
        AuditLog(
            user_id="system:ingestion",
            action="CREATE_SCAN",
            target_type="scan",
            target_id=str(new_scan.id),
            details={"tool_type": new_scan.tool_type.value, "vulnerability_count": count},
        )
    )

    db.commit()
    return new_scan.id