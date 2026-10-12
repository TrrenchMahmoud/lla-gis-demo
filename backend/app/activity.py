from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy.orm import Session

from .models import ActivityLog


def client_ip(request: Request | None) -> str | None:
    """The dashboard sits behind nginx, so request.client.host is usually the proxy itself -
    prefer the client address nginx forwards along, when present."""
    if request is None:
        return None
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None

# Who's "online now" is tracked in memory rather than the database - it only needs to answer
# "have we heard from this person in the last few minutes", never needs to survive a restart,
# and would otherwise mean a database write on every heartbeat from every open tab.
_last_seen: dict[str, datetime] = {}


def touch(email: str | None) -> None:
    if email:
        _last_seen[email] = datetime.now(timezone.utc)


def last_seen_snapshot() -> dict[str, datetime]:
    return dict(_last_seen)


def log_activity(db: Session, actor_email: str | None, action: str, detail: str | None = None,
                  ip_address: str | None = None) -> None:
    """Best-effort audit trail. Never let a logging failure break the request it's logging."""
    touch(actor_email)
    try:
        db.add(ActivityLog(actor_email=actor_email, action=action, detail=detail, ip_address=ip_address))
        db.commit()
    except Exception:
        db.rollback()
