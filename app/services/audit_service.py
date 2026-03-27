from sqlalchemy.orm import Session

from app.database.models import AuditLog


def write_audit_log(
    db: Session,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    details: dict | None = None,
):
    db.add(
        AuditLog(
            user_id=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
    )