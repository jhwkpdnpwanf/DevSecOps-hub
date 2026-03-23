import os
import json
import sys
from sqlalchemy.orm import Session

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database.session import SessionLocal, init_db
from app.parsers.semgrep import SemgrepParser
from app.parsers.pip_audit import PipAuditParser
from app.services.db_service import save_scan_results
from app.database.models import Project

def run_full_pipeline():
    init_db(force_drop=True)
    
    db = SessionLocal()

    try:
        project = db.query(Project).filter(Project.name == "Test-Project").first()
        if not project:
            project = Project(name="Test-Project", repository_url="https://github.com/test/repo")
            db.add(project)
            db.commit()
            print(f"[+] 테스트 프로젝트 생성 완료: {project.name}")

        test_dir = os.path.dirname(__file__)
        
        sca_report_path = os.path.join(test_dir, "pip_audit_report.json")
        if os.path.exists(sca_report_path):
            with open(sca_report_path, "r", encoding="utf-8") as f:
                sca_data = json.load(f)
                sca_vulns = PipAuditParser().parse(sca_data, scan_id=0)
                save_scan_results(db, project.id, "pip-audit", sca_vulns)
                print(f"[+] pip-audit 결과 {len(sca_vulns)}건 저장 완료.")

        sast_report_path = os.path.join(test_dir, "semgrep_report.json")
        if os.path.exists(sast_report_path):
            with open(sast_report_path, "r", encoding="utf-8") as f:
                sast_data = json.load(f)
                sast_vulns = SemgrepParser().parse(sast_data, scan_id=0)
                save_scan_results(db, project.id, "Semgrep", sast_vulns)
                print(f"[+] Semgrep 결과 {len(sast_vulns)}건 저장 완료.")

        print("\n[+] 모든 파이프라인 검증이 완료되었습니다.")

    except Exception as e:
        print(f"[!] 테스트 중 예외 발생: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    run_full_pipeline()