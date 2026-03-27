from datetime import datetime
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.database.models import (
    AIAnalysis,
    Policy,
    Priority,
    Project,
    Scan,
    ToolType,
    User,
    UserRole,
    Vulnerability,
    VulnerabilityAssignment,
    VulnerabilityStatusHistory,
    VulnStatus,
)
from app.database.session import get_db, init_db
from app.parsers.pip_audit import PipAuditParser
from app.parsers.semgrep import SemgrepParser
from app.parsers.zap import ZAPParser
from app.services.ai_service import AISecurityService
from app.services.audit_service import write_audit_log
from app.services.db_service import save_scan_results
from app.services.policy_service import PolicyEngine
from app.services.aws_storage_service import AWSStorageService

init_db()
app = FastAPI(title="DevSecOps-hub API")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "devsecops-hub-secret"))
templates = Jinja2Templates(directory="app/templates")
ai_service = AISecurityService()
md = MarkdownIt("commonmark", {"html": False, "linkify": True})
aws_storage = AWSStorageService()


class IngestRequest(BaseModel):
    project_name: str
    tool_type: ToolType
    report: dict
    initiated_by: str = "ci-pipeline"
    branch: str | None = None
    commit_sha: str | None = None
    pipeline_run_id: str | None = None
    s3_report_path: str | None = None


class StatusUpdateRequest(BaseModel):
    status: VulnStatus
    changed_by: str = "system"
    comment: str | None = None


class AssignmentRequest(BaseModel):
    username: str
    changed_by: str = "security-analyst"
    due_date: datetime | None = None


class PolicyCreateRequest(BaseModel):
    name: str
    rule_expression: str
    priority_result: Priority
    sla_days: int


class MockLoginRequest(BaseModel):
    email: str



class S3ImportRequest(BaseModel):
    project_name: str
    s3_key: str
    tool_type: ToolType | None = None
    initiated_by: str = "aws-import"


def _map_role_by_email(email: str) -> UserRole:
    lowered = email.lower()
    if lowered.startswith("admin") or "@admin." in lowered:
        return UserRole.ADMIN
    if lowered.startswith("sec") or lowered.startswith("security"):
        return UserRole.SECURITY_ANALYST
    if lowered.startswith("view"):
        return UserRole.VIEWER
    return UserRole.DEVELOPER


def _get_session_user(request: Request, db: Session) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        request.session.clear()
        raise HTTPException(status_code=401, detail="세션이 유효하지 않습니다.")
    return user


def _authorize_project(user: User, project: Project) -> bool:
    if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return True
    if not project.owner_team:
        return True
    return project.owner_team.lower() in user.email.lower()


def _can_operate(user: User) -> bool:
    return user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER}


def _ensure_project_with_token(db: Session, project_name: str):
    project = db.query(Project).filter(Project.name == project_name).first()
    if not project:
        project = Project(name=project_name, api_token=f"token-{project_name}")
        db.add(project)
        db.commit()
        db.refresh(project)
    return project


def _validate_project_token(project: Project, provided_token: str | None):
    if provided_token and provided_token != project.api_token:
        raise HTTPException(status_code=401, detail="프로젝트 API Token이 유효하지 않습니다.")


@app.get("/auth/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={})


@app.post("/auth/mock-login")
def mock_login(payload: MockLoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        role = _map_role_by_email(payload.email)
        username = payload.email.split("@")[0]
        user = User(username=username, email=payload.email, password="oauth-user", role=role)
        db.add(user)
        db.commit()
        db.refresh(user)

    request.session["user_id"] = user.id
    return {"message": "로그인 완료", "user": user.username, "role": user.role.value}


@app.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "로그아웃 완료"}


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    project_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
):
    try:
        current_user = _get_session_user(request, db)
    except HTTPException:
        return RedirectResponse(url="/auth/login", status_code=302)

    projects = db.query(Project).order_by(Project.name.asc()).all()
    selected_project = None
    is_authorized = False
    permission_error = None
    vulns = []
    stats = {"total": 0, "severity": {}}
    tool_stats = {}

    if project_id:
        selected_project = db.query(Project).filter(Project.id == project_id).first()
        if not selected_project:
            permission_error = "선택한 프로젝트를 찾을 수 없습니다."
        elif not _authorize_project(current_user, selected_project):
            permission_error = "현재 계정으로는 해당 프로젝트 접근 권한이 없습니다."
        else:
            is_authorized = True
            vulns = (
                db.query(Vulnerability)
                .join(Vulnerability.scan)
                .filter(Scan.project_id == selected_project.id)
                .order_by(Vulnerability.created_at.desc())
                .limit(100)
                .all()
            )
            severity_stats = (
                db.query(Vulnerability.severity, func.count(Vulnerability.id))
                .join(Vulnerability.scan)
                .filter(Scan.project_id == selected_project.id)
                .group_by(Vulnerability.severity)
                .all()
            )
            stats = {
                "total": sum(c for _, c in severity_stats),
                "severity": {s.value: c for s, c in severity_stats},
            }

            tool_query = (
                db.query(func.count(Vulnerability.id), Scan.tool_type)
                .select_from(Vulnerability)
                .join(Vulnerability.scan)
                .filter(Scan.project_id == selected_project.id)
                .group_by(Scan.tool_type)
                .all()
            )
            tool_stats = {tool.value: count for count, tool in tool_query}

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "current_user": current_user,
            "projects": projects,
            "selected_project": selected_project,
            "is_authorized": is_authorized,
            "permission_error": permission_error,
            "vulns": vulns,
            "stats": stats,
            "tool_stats": tool_stats,
        },
    )


@app.get("/api/projects")
def list_projects(request: Request, db: Session = Depends(get_db)):
    _get_session_user(request, db)
    return [{"id": p.id, "name": p.name, "owner_team": p.owner_team} for p in db.query(Project).order_by(Project.name.asc()).all()]


@app.post("/api/ingest")
def ingest_scan_result(
    payload: IngestRequest,
    db: Session = Depends(get_db),
    x_project_token: str | None = Header(default=None),
):
    project = _ensure_project_with_token(db, payload.project_name)
    _validate_project_token(project, x_project_token)

    parser_map = {
        ToolType.SAST: SemgrepParser(),
        ToolType.SCA: PipAuditParser(),
        ToolType.DAST: ZAPParser(),
    }

    parser = parser_map.get(payload.tool_type)
    if parser is None:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 파서: {payload.tool_type.value}")

    vulnerabilities = parser.parse(payload.report, scan_id=0)
    scan_id = save_scan_results(
        db,
        project.id,
        payload.tool_type,
        vulnerabilities,
        initiated_by=payload.initiated_by,
        branch=payload.branch,
        commit_sha=payload.commit_sha,
        pipeline_run_id=payload.pipeline_run_id,
        s3_report_path=payload.s3_report_path,
    )

    return {
        "project": project.name,
        "scan_id": scan_id,
        "tool_type": payload.tool_type.value,
        "vulnerability_count": len(vulnerabilities),
    }


@app.get("/vulnerability/{vuln_id}", response_class=HTMLResponse)
def vulnerability_detail(
    vuln_id: int,
    request: Request,
    project_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
):
    current_user = _get_session_user(request, db)
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if not _authorize_project(current_user, vuln.scan.project):
        raise HTTPException(status_code=403, detail="프로젝트 접근 권한이 없습니다.")

    existing_analysis = db.query(AIAnalysis).filter(AIAnalysis.vulnerability_id == vuln_id).first()
    analysis_html = md.render(existing_analysis.summary) if existing_analysis else ""

    return templates.TemplateResponse(
        request=request,
        name="detail.html",
        context={
            "vuln": vuln,
            "existing_analysis": existing_analysis,
            "existing_analysis_html": analysis_html,
            "current_user": current_user,
            "can_operate": _can_operate(current_user),
            "back_project_id": project_id or vuln.scan.project_id,
        },
    )


@app.get("/api/vulnerabilities/{vuln_id}/policy-preview")
def preview_policy(vuln_id: int, request: Request, db: Session = Depends(get_db)):
    _get_session_user(request, db)
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    project = vuln.scan.project
    priority, sla_days = PolicyEngine.evaluate_priority(vuln.severity, project.business_criticality.value, project.exposure.value)
    return {
        "vulnerability_id": vuln.id,
        "calculated_priority": priority.value,
        "sla_days": sla_days,
        "project_criticality": project.business_criticality.value,
        "project_exposure": project.exposure.value,
    }


@app.patch("/api/vulnerabilities/{vuln_id}/status")
def update_vulnerability_status(vuln_id: int, payload: StatusUpdateRequest, request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if not _can_operate(current_user):
        raise HTTPException(status_code=403, detail="운영 액션 권한이 없습니다.")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    previous = vuln.status
    if not PolicyEngine.validate_status_transition(previous, payload.status):
        if current_user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
            raise HTTPException(status_code=400, detail=f"허용되지 않은 상태 전이: {previous.value} -> {payload.status.value}")

    vuln.status = payload.status

    db.add(VulnerabilityStatusHistory(vulnerability_id=vuln.id, from_status=previous.value if previous else None, to_status=payload.status.value, changed_by=payload.changed_by, comment=payload.comment))

    write_audit_log(db, actor=payload.changed_by, action="UPDATE_STATUS", target_type="vulnerability", target_id=str(vuln.id), details={"from": previous.value if previous else None, "to": payload.status.value})

    db.commit()
    return {"id": vuln.id, "from": previous.value, "to": vuln.status.value}


@app.post("/api/vulnerabilities/{vuln_id}/assign")
def assign_vulnerability(vuln_id: int, payload: AssignmentRequest, request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if not _can_operate(current_user):
        raise HTTPException(status_code=403, detail="운영 액션 권한이 없습니다.")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    assignee = db.query(User).filter(User.username == payload.username).first()
    if not assignee:
        assignee = User(username=payload.username, email=f"{payload.username}@example.local", password="temporary-password", role=UserRole.DEVELOPER)
        db.add(assignee)
        db.flush()

    assignment = VulnerabilityAssignment(vulnerability_id=vuln.id, assignee_id=assignee.id, due_date=payload.due_date or vuln.due_date)
    db.add(assignment)

    previous = vuln.status
    if vuln.status in {VulnStatus.DETECTED, VulnStatus.TRIAGED}:
        vuln.status = VulnStatus.IN_PROGRESS
        db.add(VulnerabilityStatusHistory(vulnerability_id=vuln.id, from_status=previous.value, to_status=VulnStatus.IN_PROGRESS.value, changed_by=payload.changed_by, comment=f"{assignee.username} 할당으로 자동 진행 상태 전환"))

    write_audit_log(db, actor=payload.changed_by, action="ASSIGN_VULNERABILITY", target_type="vulnerability", target_id=str(vuln.id), details={"assignee": assignee.username, "notification": "in-app assignment created"})

    db.commit()
    return {"vulnerability_id": vuln.id, "assignee": assignee.username, "new_status": vuln.status.value}


@app.post("/api/vulnerabilities/{vuln_id}/analyze")
async def analyze_vuln(vuln_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if not _can_operate(current_user):
        raise HTTPException(status_code=403, detail="운영 액션 권한이 없습니다.")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    existing_analysis = db.query(AIAnalysis).filter(AIAnalysis.vulnerability_id == vuln_id).first()
    if existing_analysis:
        return {"analysis": existing_analysis.summary, "analysis_html": md.render(existing_analysis.summary), "cached": True}

    analysis_report = ai_service.analyze_vulnerability(title=vuln.title, description=vuln.description, category=vuln.category)

    db.add(AIAnalysis(vulnerability_id=vuln.id, model_name=ai_service.model, summary=analysis_report, confidence_score=100))
    write_audit_log(db, actor=current_user.username, action="GENERATE_AI_ANALYSIS", target_type="vulnerability", target_id=str(vuln.id))

    db.commit()
    return {"analysis": analysis_report, "analysis_html": md.render(analysis_report), "cached": False}


@app.get("/api/aws/reports")
def list_aws_reports(
    request: Request,
    project_name: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    _get_session_user(request, db)
    if not aws_storage.is_configured():
        raise HTTPException(status_code=400, detail="AWS_S3_REPORT_BUCKET 설정이 필요합니다.")

    try:
        reports = aws_storage.list_reports(project_name)
        return {
            "bucket": aws_storage.bucket,
            "project": project_name,
            "reports": [r.__dict__ for r in reports],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/aws/import-report")
def import_aws_report(payload: S3ImportRequest, request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if not _can_operate(current_user):
        raise HTTPException(status_code=403, detail="운영 액션 권한이 없습니다.")

    if not aws_storage.is_configured():
        raise HTTPException(status_code=400, detail="AWS_S3_REPORT_BUCKET 설정이 필요합니다.")

    project = _ensure_project_with_token(db, payload.project_name)
    report = aws_storage.read_report_json(payload.s3_key)

    tool_type = payload.tool_type or aws_storage._guess_tool_type_from_key(payload.s3_key)
    parser_map = {
        ToolType.SAST: SemgrepParser(),
        ToolType.SCA: PipAuditParser(),
        ToolType.DAST: ZAPParser(),
    }
    parser = parser_map.get(tool_type)
    if not parser:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 파서: {tool_type.value}")

    vulnerabilities = parser.parse(report, scan_id=0)
    scan_id = save_scan_results(
        db,
        project.id,
        tool_type,
        vulnerabilities,
        initiated_by=payload.initiated_by or current_user.username,
        s3_report_path=f"s3://{aws_storage.bucket}/{payload.s3_key}",
    )

    write_audit_log(
        db,
        actor=current_user.username,
        action="IMPORT_S3_REPORT",
        target_type="scan",
        target_id=str(scan_id),
        details={"s3_key": payload.s3_key, "tool_type": tool_type.value},
    )
    db.commit()

    return {
        "project": project.name,
        "scan_id": scan_id,
        "tool_type": tool_type.value,
        "s3_key": payload.s3_key,
        "vulnerability_count": len(vulnerabilities),
    }


@app.post("/api/ingest-from-s3")
def ingest_from_s3_for_ci(
    payload: S3ImportRequest,
    db: Session = Depends(get_db),
    x_project_token: str | None = Header(default=None),
):
    if not aws_storage.is_configured():
        raise HTTPException(status_code=400, detail="AWS_S3_REPORT_BUCKET 설정이 필요합니다.")

    project = _ensure_project_with_token(db, payload.project_name)
    _validate_project_token(project, x_project_token)

    report = aws_storage.read_report_json(payload.s3_key)
    tool_type = payload.tool_type or aws_storage._guess_tool_type_from_key(payload.s3_key)

    parser_map = {
        ToolType.SAST: SemgrepParser(),
        ToolType.SCA: PipAuditParser(),
        ToolType.DAST: ZAPParser(),
    }
    parser = parser_map.get(tool_type)
    if not parser:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 파서: {tool_type.value}")

    vulnerabilities = parser.parse(report, scan_id=0)
    scan_id = save_scan_results(
        db,
        project.id,
        tool_type,
        vulnerabilities,
        initiated_by=payload.initiated_by,
        s3_report_path=f"s3://{aws_storage.bucket}/{payload.s3_key}",
    )

    return {
        "project": project.name,
        "scan_id": scan_id,
        "tool_type": tool_type.value,
        "s3_key": payload.s3_key,
        "vulnerability_count": len(vulnerabilities),
    }


@app.get("/api/aws/presigned-url")
def get_presigned_url(request: Request, key: str, db: Session = Depends(get_db)):
    _get_session_user(request, db)
    if not aws_storage.is_configured():
        raise HTTPException(status_code=400, detail="AWS_S3_REPORT_BUCKET 설정이 필요합니다.")
    url = aws_storage.get_presigned_download_url(key)
    return {"key": key, "url": url, "expires_in": 600}


@app.post("/api/policies")
def create_policy(payload: PolicyCreateRequest, request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if current_user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        raise HTTPException(status_code=403, detail="정책 생성 권한이 없습니다.")

    existing = db.query(Policy).filter(Policy.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="동일한 이름의 Policy가 이미 존재합니다.")

    policy = Policy(name=payload.name, rule_expression=payload.rule_expression, priority_result=payload.priority_result, sla_days=payload.sla_days, is_active=True)
    db.add(policy)

    write_audit_log(db, actor=current_user.username, action="CREATE_POLICY", target_type="policy", target_id=payload.name, details={"sla_days": payload.sla_days, "priority": payload.priority_result.value})

    db.commit()
    return {"name": policy.name, "priority": policy.priority_result.value, "sla_days": policy.sla_days}


@app.get("/api/policies")
def list_policies(request: Request, db: Session = Depends(get_db)):
    _get_session_user(request, db)
    return [{"id": p.id, "name": p.name, "rule_expression": p.rule_expression, "priority_result": p.priority_result.value, "sla_days": p.sla_days, "is_active": p.is_active} for p in db.query(Policy).order_by(Policy.created_at.desc()).all()]