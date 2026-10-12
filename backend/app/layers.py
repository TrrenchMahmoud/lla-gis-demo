import re

from fastapi import APIRouter, Depends
from sqlalchemy import Boolean, Column, String
from sqlalchemy.orm import Session

from .activity import log_activity
from .auth import get_current_user, require_role
from .database import Base, get_db
from .models import Role, User


class LayerAccess(Base):
    """viewers=True means viewers may see that layer. No row = admins only."""
    __tablename__ = "app_layer_access"
    layer_id = Column(String, primary_key=True)
    viewers = Column(Boolean, nullable=False, default=False)


def layer_allowed(db: Session, user: User, uri: str) -> bool:
    if user.role in (Role.admin, Role.super_admin):
        return True
    m = re.match(r"^/(?:tiles|features)/([^/?]+)", uri)
    if not m or m.group(1) == "index.json":
        return True
    name = m.group(1)
    layer = name[:-5] if name.endswith(".json") else name
    row = db.get(LayerAccess, layer)
    return bool(row and row.viewers)


router = APIRouter(prefix="/layers", tags=["layers"])


@router.get("/access")
def access(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    rows = db.query(LayerAccess).filter(LayerAccess.viewers.is_(True)).all()
    return {"viewers": [r.layer_id for r in rows]}


@router.put("/access/{layer_id}")
def set_access(layer_id: str, viewers: bool, db: Session = Depends(get_db),
               admin: User = Depends(require_role(Role.super_admin))):
    """Turning a layer off for viewers dashboard-wide is the same kind of switch as the
    Feature Settings panel, so it's super-admin-only too."""
    row = db.get(LayerAccess, layer_id)
    if row:
        row.viewers = viewers
    else:
        db.add(LayerAccess(layer_id=layer_id, viewers=viewers))
    db.commit()
    log_activity(db, admin.email, "layer.access", f"{layer_id} viewers={viewers}")
    return {"layer": layer_id, "viewers": viewers}
