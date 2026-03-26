from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.models import (
    AIAnalysis,
    Priority,
    Project,
    Severity,
    ToolType,
    Vulnerability,
    VulnerabilityStatusHistory,
    VulnStatus,
)
from app.database.session import get_db, init_db
from app.parsers.pip_audit import PipAuditParser
from app.parsers.semgrep import SemgrepParser
from app.services.ai_service import AISecurityService
from app.services.db_service import save_scan_results

init_db()
app = FastAPI(title="DevSecOps-hub API")
templates = Jinja2Templates(directory="app/templates")
ai_service = AISecurityService()


class IngestRequest(BaseModel):
    project_name: str
    tool_type: ToolType
    report: dict


class StatusUpdateRequest(BaseModel):
    status: VulnStatus
    changed_by: str = "system"
    comment: str | None = None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    vulns = db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).limit(100).all()
    stats_query = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )

    severity_stats = {severity.value: count for severity, count in stats_query}
    stats = {
        "total": sum(severity_stats.values()),
        "severity": severity_stats,
    }

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"vulns": vulns, "stats": stats},
    )


@app.post("/api/ingest")
def ingest_scan_result(payload: IngestRequest, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.name == payload.project_name).first()
    if not project:
        project = Project(name=payload.project_name, api_token=f"token-{payload.project_name}")
        db.add(project)
        db.commit()
        db.refresh(project)

    parser_map = {
        ToolType.SAST: SemgrepParser(),
        ToolType.SCA: PipAuditParser(),
    }

    parser = parser_map.get(payload.tool_type)
    if parser is None:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 파서: {payload.tool_type.value}")

    vulnerabilities = parser.parse(payload.report, scan_id=0)
    scan_id = save_scan_results(db, project.id, payload.tool_type, vulnerabilities)

    return {
        "project": project.name,
        "scan_id": scan_id,
        "tool_type": payload.tool_type.value,
        "vulnerability_count": len(vulnerabilities),
    }


@app.get("/vulnerability/{vuln_id}", response_class=HTMLResponse)
def vulnerability_detail(vuln_id: int, request: Request, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    existing_analysis = db.query(AIAnalysis).filter(AIAnalysis.vulnerability_id == vuln_id).first()

    return templates.TemplateResponse(
        request=request,
        name="detail.html",
        context={"vuln": vuln, "existing_analysis": existing_analysis},
    )


@app.patch("/api/vulnerabilities/{vuln_id}/status")
def update_vulnerability_status(vuln_id: int, payload: StatusUpdateRequest, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    previous = vuln.status
    vuln.status = payload.status

    if payload.status == VulnStatus.TRIAGED and vuln.priority == Priority.P3 and vuln.severity in {Severity.HIGH, Severity.CRITICAL}:
        vuln.priority = Priority.P1

    db.add(
        VulnerabilityStatusHistory(
            vulnerability_id=vuln.id,
            from_status=previous.value if previous else None,
            to_status=payload.status.value,
            changed_by=payload.changed_by,
            comment=payload.comment,
        )
    )

    db.commit()
    return {"id": vuln.id, "from": previous.value, "to": vuln.status.value}


@app.post("/api/vulnerabilities/{vuln_id}/analyze")
async def analyze_vuln(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    existing_analysis = db.query(AIAnalysis).filter(AIAnalysis.vulnerability_id == vuln_id).first()
    if existing_analysis:
        return {"analysis": existing_analysis.summary}

    analysis_report = ai_service.analyze_vulnerability(
        title=vuln.title,
        description=vuln.description,
        category=vuln.category,
    )

    new_analysis = AIAnalysis(
        vulnerability_id=vuln.id,
        model_name=ai_service.model,
        summary=analysis_report,
        confidence_score=100,
    )
    db.add(new_analysis)
    db.commit()

    return {"analysis": analysis_report}