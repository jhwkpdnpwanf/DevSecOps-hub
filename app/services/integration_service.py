import json
from urllib import error, request

from sqlalchemy.orm import Session

from app.database.models import Integration


def notify_integrations(db: Session, event_type: str, payload: dict) -> dict:
    integrations = db.query(Integration).filter(Integration.enabled.is_(True)).all()
    delivered = 0
    failed = 0

    for integration in integrations:
        config = integration.masked_config or {}
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            failed += 1
            continue

        body = {
            "integration_type": integration.integration_type.value,
            "config_name": integration.config_name,
            "event_type": event_type,
            "payload": payload,
        }
        data = json.dumps(body).encode("utf-8")
        req = request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=4):
                delivered += 1
        except (error.URLError, TimeoutError):
            failed += 1

    return {"delivered": delivered, "failed": failed, "total": len(integrations)}