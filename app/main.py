from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database.session import get_db, init_db
from app.database.models import Vulnerability
from app.services.ai_service import AISecurityService

init_db()
app = FastAPI(title="DevSecOps-hub API")
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    vulns = db.query(Vulnerability).all()
    from sqlalchemy import func
    stats_query = db.query(
        Vulnerability.severity, 
        func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity).all()
    stats = {s.value: c for s, c in stats_query}

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"vulns": vulns, "stats": stats}
    )

@app.get("/vulnerability/{vuln_id}", response_class=HTMLResponse)
def vulnerability_detail(vuln_id: int, request: Request, db: Session = Depends(get_db)):
    """취약점 상세 정보를 보여주는 별도 페이지 라우트"""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return templates.TemplateResponse(
        request=request,
        name="detail.html",
        context={"vuln": vuln}
    )


ai_service = AISecurityService()

@app.post("/vulnerability/{vuln_id}/analyze")
async def analyze_vuln(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    analysis_report = ai_service.analyze_vulnerability(
        title=vuln.title,
        description=vuln.description,
        category=vuln.category
    )
    
    return {"analysis": analysis_report}