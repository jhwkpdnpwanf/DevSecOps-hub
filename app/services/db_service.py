from sqlalchemy.orm import Session
from app.database.models import Scan, Vulnerability

def save_scan_results(db: Session, project_id: int, tool_type: str, vulnerabilities: list):
    new_scan = Scan(
        project_id=project_id,
        tool_type=tool_type,
    )
    db.add(new_scan)
    db.flush()

    for v in vulnerabilities:
        v.scan_id = new_scan.id
        db.add(v)

    try:
        db.commit()
        print(f"[+] {tool_type} 결과 {len(vulnerabilities)}건 저장 완료!")
        return new_scan.id
    except Exception as e:
        db.rollback()
        print(f"[!] DB 저장 중 오류 발생: {e}")
        return None