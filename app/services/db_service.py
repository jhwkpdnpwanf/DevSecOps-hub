from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy.orm import Session

from app.database.models import Project, Scan, ToolType, Vulnerability, VulnerabilityStatusHistory
from app.services.audit_service import write_audit_log
from app.services.policy_service import PolicyEngine


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


def _apply_policy(vulnerability: Vulnerability, project: Project) -> None:
    priority, sla_days = PolicyEngine.evaluate_priority(
        vulnerability.severity,
        project.business_criticality.value,
        project.exposure.value,
    )
    vulnerability.priority = priority
    vulnerability.due_date = datetime.utcnow() + timedelta(days=sla_days)


def save_scan_results(
    db: Session,
    project_id: int,
    tool_type: str | ToolType,
    vulnerabilities: Iterable[Vulnerability],
    *,
    initiated_by: str = "system:ingestion",
    branch: str | None = None,
    commit_sha: str | None = None,
    pipeline_run_id: str | None = None,
    s3_report_path: str | None = None,
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise ValueError(f"project_id={project_id} 프로젝트가 존재하지 않습니다.")

    new_scan = Scan(
        project_id=project_id,
        tool_type=_coerce_tool_type(tool_type),
        initiated_by=initiated_by,
        branch=branch,
        commit_sha=commit_sha,
        pipeline_run_id=pipeline_run_id,
        s3_report_path=s3_report_path,
    )
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
                changed_by=initiated_by,
                comment="초기 탐지 결과 등록",
            )
        )
        count += 1

    write_audit_log(
        db,
        actor=initiated_by,
        action="CREATE_SCAN",
        target_type="scan",
        target_id=str(new_scan.id),
        details={
            "tool_type": new_scan.tool_type.value,
            "vulnerability_count": count,
            "deduplicated_count": 0,
            "project_id": project_id,
        },
    )

    db.commit()
    return new_scan.id