from datetime import datetime
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from authlib.integrations.starlette_client import OAuth, OAuthError
from markdown_it import MarkdownIt
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy import desc, func
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.database.models import (
    AIAnalysis,
    Integration,
    IntegrationType,
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
from app.services.integration_service import notify_integrations
from app.services.data_service import DASTScanService

init_db()
app = FastAPI(title="DevSecOps-hub API")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "devsecops-hub-secret"))
templates = Jinja2Templates(directory="app/templates")
ai_service = AISecurityService()
md = MarkdownIt("commonmark", {"html": False, "linkify": True})
dast_service = DASTScanService()
oauth = OAuth()


def _resolve_s3_read_enabled() -> bool:
    raw = os.getenv("AWS_S3_READ_ENABLED", "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    return False


AWS_S3_READ_ENABLED = _resolve_s3_read_enabled()
aws_storage: AWSStorageService | None = None
aws_storage_init_error: str | None = None
if AWS_S3_READ_ENABLED:
    try:
        aws_storage = AWSStorageService()
    except ValueError as e:
        aws_storage_init_error = str(e)

GITHUB_OAUTH_CLIENT_ID = os.getenv("GITHUB_OAUTH_CLIENT_ID")
GITHUB_OAUTH_CLIENT_SECRET = os.getenv("GITHUB_OAUTH_CLIENT_SECRET")
GITHUB_OAUTH_ENABLED = bool(GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET)

if GITHUB_OAUTH_ENABLED:
    oauth.register(
        name="github",
        client_id=GITHUB_OAUTH_CLIENT_ID,
        client_secret=GITHUB_OAUTH_CLIENT_SECRET,
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email"},
    )

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

class IngestRequest(BaseModel):
    project_name: str
    tool_type: str | ToolType
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


class IntegrationRequest(BaseModel):
    integration_type: IntegrationType
    config_name: str
    enabled: bool = True
    webhook_url: str


class S3ImportRequest(BaseModel):
    project_name: str
    s3_key: str
    tool_type: str | ToolType | None = None
    initiated_by: str = "aws-import"

class DASTRunRequest(BaseModel):
    project_name: str
    target_url: str
    initiated_by: str = "dast-runner"
    branch: str | None = None
    commit_sha: str | None = None
    pipeline_run_id: str | None = None

def _map_role_by_email(email: str) -> UserRole:
    lowered = email.lower()
    if lowered.startswith("admin") or "@admin." in lowered:
        return UserRole.ADMIN
    if lowered.startswith("sec") or lowered.startswith("security"):
        return UserRole.SECURITY_ANALYST
    if lowered.startswith("view"):
        return UserRole.VIEWER
    return UserRole.DEVELOPER


def _parse_csv_env_set(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _map_role_by_identity(username: str, email: str | None) -> UserRole:
    username_l = username.lower()
    email_l = (email or "").lower()

    admins = _parse_csv_env_set("AUTH_ADMIN_USERS")
    security_analysts = _parse_csv_env_set("AUTH_SECURITY_USERS")
    viewers = _parse_csv_env_set("AUTH_VIEWER_USERS")

    if username_l in admins or email_l in admins:
        return UserRole.ADMIN
    if username_l in security_analysts or email_l in security_analysts:
        return UserRole.SECURITY_ANALYST
    if username_l in viewers or email_l in viewers:
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


def _request_meta(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    source_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    return {
        "source_ip": source_ip,
        "path": str(request.url.path),
        "user_agent": request.headers.get("user-agent", "-"),
    }

def _sync_projects_from_s3(db: Session):
    if not aws_storage or not aws_storage.is_configured():
        return

    try:
        discovered = aws_storage.discover_project_names()
    except Exception:
        return

    if not discovered:
        return

    existing = {name for (name,) in db.query(Project.name).all()}
    created = False
    for name in discovered:
        if name not in existing:
            db.add(Project(name=name, api_token=f"token-{name}"))
            created = True

    if created:
        db.commit()



def _authorize_project(user: User, project: Project) -> bool:
    if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return True
    if not project.owner_team:
        return True
    return project.owner_team.lower() in user.email.lower()


def _can_operate(user: User) -> bool:
    return user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER}


def _ensure_project_with_token(db: Session, project_name: str):
    configured_project_name = os.getenv("DEVSECOPS_PROJECT_NAME")
    configured_project_token = os.getenv("DEVSECOPS_PROJECT_TOKEN")
    bootstrap_token = (
        configured_project_token
        if configured_project_name and configured_project_token and configured_project_name == project_name
        else None
    )

    project = db.query(Project).filter(Project.name == project_name).first()
    if not project:
        project = Project(name=project_name, api_token=bootstrap_token or f"token-{project_name}")
        db.add(project)
        db.commit()
        db.refresh(project)
    elif bootstrap_token and project.api_token != bootstrap_token:
        project.api_token = bootstrap_token
        db.commit()
        db.refresh(project)
    return project

def _validate_project_token(project: Project, provided_token: str | None):
    if not provided_token:
        raise HTTPException(status_code=401, detail="프로젝트 API Token이 필요합니다.")
    if provided_token != project.api_token:
        raise HTTPException(status_code=401, detail="프로젝트 API Token이 유효하지 않습니다.")
    

def _resolve_tool_type(tool_type_raw: str | ToolType | None, s3_key: str) -> ToolType:
    if isinstance(tool_type_raw, ToolType):
        return tool_type_raw

    if isinstance(tool_type_raw, str) and tool_type_raw.strip():
        normalized = tool_type_raw.strip().lower()
        alias_map = {
            "sast": ToolType.SAST,
            "semgrep": ToolType.SAST,
            "dast": ToolType.DAST,
            "zap": ToolType.DAST,
            "sca": ToolType.SCA,
            "pip-audit": ToolType.SCA,
            "pipaudit": ToolType.SCA,
        }
        resolved = alias_map.get(normalized)
        if not resolved:
            supported = ", ".join(sorted(alias_map.keys()))
            raise HTTPException(status_code=400, detail=f"지원하지 않는 tool_type: {tool_type_raw}. 지원값: {supported}")
        return resolved

    return AWSStorageService._guess_tool_type_from_key(s3_key)


def _require_aws_storage() -> AWSStorageService:
    if not AWS_S3_READ_ENABLED:
        raise HTTPException(status_code=400, detail="AWS S3 조회 기능이 비활성화되어 있습니다. (AWS_S3_READ_ENABLED=false)")
    if aws_storage_init_error:
        raise HTTPException(status_code=400, detail=f"AWS 인증 설정 오류: {aws_storage_init_error}")
    if not aws_storage:
        raise HTTPException(status_code=400, detail="AWS 스토리지 서비스가 초기화되지 않았습니다.")
    if not aws_storage.is_configured():
        raise HTTPException(status_code=400, detail="AWS_S3_REPORT_BUCKET 설정이 필요합니다.")
    return aws_storage


@app.get("/auth/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"github_oauth_enabled": GITHUB_OAUTH_ENABLED},
    )


@app.post("/auth/mock-login")
def mock_login(payload: MockLoginRequest, request: Request, db: Session = Depends(get_db)):
    if GITHUB_OAUTH_ENABLED:
        raise HTTPException(status_code=403, detail="GitHub OAuth가 활성화되어 Mock 로그인은 비활성화되었습니다.")
    
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        role = _map_role_by_email(payload.email)
        username = payload.email.split("@")[0]
        user = User(username=username, email=payload.email, password="oauth-user", role=role)
        db.add(user)
        db.commit()
        db.refresh(user)

    request.session["user_id"] = user.id
    write_audit_log(
        db,
        actor=user.username,
        action="LOGIN",
        target_type="user",
        target_id=str(user.id),
        details={"email": user.email, **_request_meta(request)},
    )
    db.commit()
    return {"message": "로그인 완료", "user": user.username, "role": user.role.value}


@app.get("/auth/github/login")
async def github_login(request: Request):
    if not GITHUB_OAUTH_ENABLED:
        raise HTTPException(status_code=400, detail="GitHub OAuth 설정이 비어 있습니다.")

    redirect_uri = os.getenv("GITHUB_OAUTH_REDIRECT_URI") or str(request.url_for("github_callback"))
    return await oauth.github.authorize_redirect(request, redirect_uri)


async def _fetch_github_email(token: dict) -> str | None:
    user_resp = await oauth.github.get("user", token=token)
    user_data = user_resp.json()
    email = user_data.get("email")
    if email:
        return email

    emails_resp = await oauth.github.get("user/emails", token=token)
    if emails_resp.status_code >= 400:
        return None

    for item in emails_resp.json():
        if item.get("primary") and item.get("verified") and item.get("email"):
            return item.get("email")
    return None


@app.get("/auth/github/callback")
async def github_callback(request: Request, db: Session = Depends(get_db)):
    if not GITHUB_OAUTH_ENABLED:
        return RedirectResponse(url="/auth/login", status_code=302)

    try:
        token = await oauth.github.authorize_access_token(request)
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=f"GitHub OAuth 인증 실패: {exc.error}") from exc

    user_resp = await oauth.github.get("user", token=token)
    user_data = user_resp.json()
    github_username = (user_data.get("login") or "").strip()
    if not github_username:
        raise HTTPException(status_code=400, detail="GitHub 사용자 정보를 가져오지 못했습니다.")

    email = await _fetch_github_email(token) or f"{github_username}@users.noreply.github.com"
    role = _map_role_by_identity(github_username, email)

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = db.query(User).filter(User.username == github_username).first()

    if not user:
        user = User(username=github_username, email=email, password="oauth-user", role=role)
        db.add(user)
    else:
        user.username = github_username
        user.email = email
        user.role = role

    db.commit()
    db.refresh(user)
    request.session["user_id"] = user.id

    write_audit_log(
        db,
        actor=user.username,
        action="LOGIN",
        target_type="user",
        target_id=str(user.id),
        details={"provider": "github", "email": user.email, **_request_meta(request)},
    )
    db.commit()
    return RedirectResponse(url="/", status_code=302)


@app.post("/auth/logout")

def logout(request: Request, db: Session = Depends(get_db)):
    actor = request.session.get("user_id", "anonymous")
    write_audit_log(
        db,
        actor=str(actor),
        action="LOGOUT",
        target_type="user",
        target_id=str(actor),
        details=_request_meta(request),
    )
    db.commit()
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
    
    write_audit_log(
        db,
        actor=current_user.username,
        action="READ_DASHBOARD",
        target_type="dashboard",
        target_id=str(project_id or "all"),
        details=_request_meta(request),
    )
    db.commit()

    _sync_projects_from_s3(db)

    projects = db.query(Project).order_by(Project.name.asc()).all()
    selected_project = None
    is_authorized = False
    permission_error = None
    vulns = []
    stats = {"total": 0, "severity": {}}
    tool_stats = {}

    latest_scans = {}
    
    if project_id:
        selected_project = db.query(Project).filter(Project.id == project_id).first()
        if not selected_project:
            permission_error = "선택한 프로젝트를 찾을 수 없습니다."
        elif not _authorize_project(current_user, selected_project):
            permission_error = "현재 계정으로는 해당 프로젝트 접근 권한이 없습니다."
        else:
            is_authorized = True

            latest_scan_ids = (
                db.query(func.max(Scan.id))
                .filter(Scan.project_id == selected_project.id)
                .group_by(Scan.tool_type)
                .all()
            )
            if latest_scan_ids:
                ids = [i[0] for i in latest_scan_ids]
                latest_scans_objs = db.query(Scan).filter(Scan.id.in_(ids)).all()
                latest_scans = {s.tool_type.value: s for s in latest_scans_objs}
            else:
                latest_scans = {}

            vulns = (
                db.query(Vulnerability)
                .join(Vulnerability.scan)
                .filter(Scan.project_id == selected_project.id)
                .order_by(desc(Scan.scan_date), desc(Vulnerability.created_at), desc(Vulnerability.id))
                .all()
            )
            for vuln in vulns:
                vuln.risk_score = PolicyEngine.evaluate_risk_score(
                    severity=vuln.severity,
                    priority=vuln.priority,
                    project_criticality=selected_project.business_criticality.value,
                    exposure=selected_project.exposure.value,
                    status=vuln.status,
                )
            severity_counts = {}
            for v in vulns:
                severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1

            stats = {
                "total": len(vulns),
                "severity": severity_counts,
            }

            tool_counts = {}
            for v in vulns:
                tool = v.scan.tool_type.value
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
            tool_stats = tool_counts

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "current_user": current_user,
            "projects": projects,
            "selected_project": selected_project,
            "is_authorized": is_authorized,
            "aws_s3_read_enabled": AWS_S3_READ_ENABLED,
            "permission_error": permission_error,
            "vulns": vulns,
            "stats": stats,
            "tool_stats": tool_stats,
            "latest_scans": latest_scans,
        },
    )


@app.get("/api/projects")
def list_projects(request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    _sync_projects_from_s3(db)
    projects = db.query(Project).order_by(Project.name.asc()).all()
    write_audit_log(
        db,
        actor=current_user.username,
        action="READ_PROJECTS",
        target_type="project",
        target_id="list",
        details={**_request_meta(request), "count": len(projects)},
    )
    db.commit()
    return [{"id": p.id, "name": p.name, "owner_team": p.owner_team} for p in projects]


@app.post("/api/ingest")
def ingest_scan_result(
    payload: IngestRequest,
    db: Session = Depends(get_db),
    x_project_token: str | None = Header(default=None),
):
    project = _ensure_project_with_token(db, payload.project_name)
    _validate_project_token(project, x_project_token)

    tool_type = _resolve_tool_type(payload.tool_type, payload.s3_report_path or "")

    parser_map = {
        ToolType.SAST: SemgrepParser(),
        ToolType.SCA: PipAuditParser(),
        ToolType.DAST: ZAPParser(),
    }

    parser = parser_map.get(tool_type)
    if parser is None:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 파서: {tool_type.value}")

    vulnerabilities = parser.parse(payload.report, scan_id=0)

    scan_id = save_scan_results(
        db,
        project.id,
        tool_type,
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
        "tool_type": tool_type.value,
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

    notify_integrations(
        db,
        "vulnerability_status_updated",
        {
            "actor": payload.changed_by,
            "vulnerability_id": vuln.id,
            "from_status": previous.value if previous else None,
            "to_status": payload.status.value,
        },
    )

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
    notify_integrations(
        db,
        "vulnerability_assigned",
        {
            "actor": payload.changed_by,
            "vulnerability_id": vuln.id,
            "assignee": assignee.username,
            "new_status": vuln.status.value,
        },
    )
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
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=10),
    db: Session = Depends(get_db),
):
    
    current_user = _get_session_user(request, db)
    storage = _require_aws_storage()

    try:
        reports = storage.list_reports(project_name)
        reports.sort(key=lambda x: x.last_modified, reverse=True)
        try:
            write_audit_log(
                db,
                actor=current_user.username,
                action="READ_S3_REPORT_LIST",
                target_type="s3_bucket",
                target_id=storage.bucket or "-",
                details={**_request_meta(request), "project": project_name, "count": len(reports)},
            )
            db.commit()
        except Exception:
            db.rollback()

        total = len(reports)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated = reports[start_idx:end_idx]
        total_pages = (total + page_size - 1) // page_size if total else 1

        return {
            "bucket": storage.bucket,
            "project": project_name,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "reports": [r.__dict__ for r in paginated],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/api/aws/import-report")
def import_aws_report(payload: S3ImportRequest, request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if not _can_operate(current_user):
        raise HTTPException(status_code=403, detail="운영 액션 권한이 없습니다.")

    storage = _require_aws_storage()

    project = _ensure_project_with_token(db, payload.project_name)
    report = storage.read_report_json(payload.s3_key)
    
    tool_type = _resolve_tool_type(payload.tool_type, payload.s3_key)
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
        s3_report_path=f"s3://{storage.bucket}/{payload.s3_key}",
    )

    write_audit_log(
        db,
        actor=current_user.username,
        action="IMPORT_S3_REPORT",
        target_type="scan",
        target_id=str(scan_id),
        details={"s3_key": payload.s3_key, "tool_type": tool_type.value},
    )
    notify_integrations(
        db,
        "s3_report_imported",
        {
            "actor": current_user.username,
            "project": project.name,
            "scan_id": scan_id,
            "s3_key": payload.s3_key,
            "tool_type": tool_type.value,
        },
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
    storage = _require_aws_storage()

    try:
        project = _ensure_project_with_token(db, payload.project_name)
        _validate_project_token(project, x_project_token)

        report = storage.read_report_json(payload.s3_key)
        tool_type = _resolve_tool_type(payload.tool_type, payload.s3_key)
        
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
            s3_report_path=f"s3://{storage.bucket}/{payload.s3_key}",
        )
    except HTTPException:
        raise
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"DB 무결성 오류: {e.orig}") from e
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"S3 ingest 실패: {e}") from e

    return {
        "project": project.name,
        "scan_id": scan_id,
        "tool_type": tool_type.value,
        "s3_key": payload.s3_key,
        "vulnerability_count": len(vulnerabilities),
    }

@app.post("/api/dast/run")
@app.post("/api/dast/run-for-ci")
@app.post("/dast/run")
@app.post("/dast/run-for-ci")
def run_dast_scan(
    payload: DASTRunRequest,
    request: Request,
    db: Session = Depends(get_db),
    x_project_token: str | None = Header(default=None),
):
    current_user: User | None = None
    if x_project_token:
        project = _ensure_project_with_token(db, payload.project_name)
        _validate_project_token(project, x_project_token)
        actor = payload.initiated_by
    else:
        current_user = _get_session_user(request, db)
        if not _can_operate(current_user):
            raise HTTPException(status_code=403, detail="운영 액션 권한이 없습니다.")
        project = _ensure_project_with_token(db, payload.project_name)
        actor = current_user.username

    try:
        run_result = dast_service.run_baseline_scan(payload.target_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    vulnerabilities = ZAPParser().parse(run_result.report, scan_id=0)
    scan_id = save_scan_results(
        db,
        project.id,
        ToolType.DAST,
        vulnerabilities,
        initiated_by=payload.initiated_by if x_project_token else (payload.initiated_by or actor),
        branch=payload.branch,
        commit_sha=payload.commit_sha,
        pipeline_run_id=payload.pipeline_run_id,
    )

    write_audit_log(
        db,
        actor=actor,
        action="RUN_DAST_SCAN",
        target_type="scan",
        target_id=str(scan_id),
        details={
            "project": project.name,
            "target_url": payload.target_url,
            "exit_code": run_result.exit_code,
            "tool_type": ToolType.DAST.value,
        },
    )
    db.commit()

    return {
        "project": project.name,
        "scan_id": scan_id,
        "tool_type": ToolType.DAST.value,
        "target_url": payload.target_url,
        "exit_code": run_result.exit_code,
        "vulnerability_count": len(vulnerabilities),
    }


@app.get("/api/aws/presigned-url")
def get_presigned_url(request: Request, key: str, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    _get_session_user(request, db)
    storage = _require_aws_storage()
    url = storage.get_presigned_download_url(key)

    write_audit_log(
        db,
        actor=current_user.username,
        action="GENERATE_PRESIGNED_URL",
        target_type="s3_object",
        target_id=key,
        details=_request_meta(request),
    )
    db.commit()
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
    notify_integrations(
        db,
        "policy_created",
        {
            "actor": current_user.username,
            "policy_name": payload.name,
            "priority": payload.priority_result.value,
            "sla_days": payload.sla_days,
        },
    )
    db.commit()
    return {"name": policy.name, "priority": policy.priority_result.value, "sla_days": policy.sla_days}


@app.get("/api/policies")
def list_policies(request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    policies = db.query(Policy).order_by(Policy.created_at.desc()).all()
    write_audit_log(
        db,
        actor=current_user.username,
        action="READ_POLICIES",
        target_type="policy",
        target_id="list",
        details={**_request_meta(request), "count": len(policies)},
    )
    db.commit()
    return [{"id": p.id, "name": p.name, "rule_expression": p.rule_expression, "priority_result": p.priority_result.value, "sla_days": p.sla_days, "is_active": p.is_active} for p in policies]


@app.get("/api/integrations")
def list_integrations(request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if current_user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        raise HTTPException(status_code=403, detail="연동 조회 권한이 없습니다.")

    integrations = db.query(Integration).order_by(Integration.created_at.desc()).all()
    return [
        {
            "id": i.id,
            "integration_type": i.integration_type.value,
            "config_name": i.config_name,
            "enabled": i.enabled,
            "masked_config": {"webhook_url": "***"} if (i.masked_config or {}).get("webhook_url") else {},
        }
        for i in integrations
    ]


@app.post("/api/integrations")
def create_or_update_integration(payload: IntegrationRequest, request: Request, db: Session = Depends(get_db)):
    current_user = _get_session_user(request, db)
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="연동 설정은 Admin만 가능합니다.")

    integration = (
        db.query(Integration)
        .filter(Integration.integration_type == payload.integration_type, Integration.config_name == payload.config_name)
        .first()
    )
    if integration:
        integration.enabled = payload.enabled
        integration.masked_config = {"webhook_url": payload.webhook_url}
        action = "UPDATE_INTEGRATION"
    else:
        integration = Integration(
            integration_type=payload.integration_type,
            config_name=payload.config_name,
            enabled=payload.enabled,
            masked_config={"webhook_url": payload.webhook_url},
        )
        db.add(integration)
        action = "CREATE_INTEGRATION"

    write_audit_log(
        db,
        actor=current_user.username,
        action=action,
        target_type="integration",
        target_id=f"{payload.integration_type.value}:{payload.config_name}",
        details={**_request_meta(request), "enabled": payload.enabled},
    )
    db.commit()
    return {"message": "integration saved", "type": payload.integration_type.value, "config_name": payload.config_name, "enabled": payload.enabled}