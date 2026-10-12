"""Sync endpoints for the field-staff mobile app: pull parcel data for offline caching, and
push queued field actions (site visits) captured while offline. See the "Sync Architecture"
section of the mobile-app architecture doc for the design this implements.

Known limitation (MVP): /sync/pull's `since` parameter is accepted but not yet enforced,
because the existing parcel layers (uploaded shapefiles) have no reliable "last changed"
column to filter on. Today it always returns the full bbox - fine at current data volumes,
but worth revisiting (e.g. adding an updated_at column to layers) before regions grow large
enough that re-downloading the whole bbox each time becomes slow on a weak connection."""
import base64
import math
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import get_current_user, require_role
from .config import settings
from .database import get_db
from .models import FieldSubmission, SubmissionStatus, User
from .schemas import ConflictPairOut, ConflictResolve, FieldSubmissionOut, FieldSubmissionPush
from .stats import (STAFF_ROLES, area_expr, geom_col, guard, id_col_of,
                     label_expr, split_layer, table_columns)

router = APIRouter(prefix="/sync", tags=["sync"])

UPLOADS_DIR = Path(settings.field_uploads_dir)
CONFLICT_RADIUS_M = 50.0          # two submissions this close together are treated as "the same spot"
CONFLICT_WINDOW = timedelta(days=30)


@router.get("/pull")
def pull(bbox: str, layer: str = Depends(guard), since: datetime | None = None,
         db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Everything in this layer that falls inside `bbox` (lon/lat, "xmin,ymin,xmax,ymax" in
    WGS84), as a GeoJSON FeatureCollection - what the field app downloads before staff head
    somewhere with no signal. Capped at 5000 features per call."""
    try:
        xmin, ymin, xmax, ymax = (float(v) for v in bbox.split(","))
    except ValueError:
        raise HTTPException(400, "bbox must be 'xmin,ymin,xmax,ymax' (lon/lat, WGS84)")
    schema, table = split_layer(layer)
    gc = geom_col(db, schema, table)
    idc = id_col_of(db, schema, table)
    lbl = label_expr(db, schema, table, idc, user.role in STAFF_ROLES)
    ae = area_expr(db, schema, table)
    cols = table_columns(db, schema, table)
    county_expr = '"county"' if "county" in cols else "NULL"
    sql = text(
        f'SELECT "{idc}" AS id, {lbl} AS label, {ae} AS area_acres, {county_expr} AS county, '
        f'ST_AsGeoJSON(ST_Transform("{gc}", 4326)) AS geom '
        f'FROM "{schema}"."{table}" '
        f'WHERE ST_Intersects(ST_Transform("{gc}", 4326), ST_MakeEnvelope(:xmin, :ymin, :xmax, :ymax, 4326)) '
        f'LIMIT 5000'
    )
    rows = db.execute(sql, {"xmin": xmin, "ymin": ymin, "xmax": xmax, "ymax": ymax}).all()
    import json
    features = [{
        "type": "Feature",
        "geometry": json.loads(r[4]),
        "properties": {"id": r[0], "label": r[1], "area_acres": float(r[2]), "county": r[3]},
    } for r in rows]
    return {
        "type": "FeatureCollection",
        "features": features,
        "layer": layer,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "note": "since is not yet enforced - this is always the full bbox" if since else None,
    }


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _find_conflict(db: Session, incoming: FieldSubmission) -> FieldSubmission | None:
    """A different staff member's submission, close in space and time to this one, on the
    same layer - a sign two people surveyed the same spot independently while both offline.
    Deliberately conservative: only flags when there's a real candidate, not just "any other
    submission exists" - the point is to catch genuine double-coverage, not create noise."""
    if incoming.lat is None or incoming.lon is None:
        return None
    since = incoming.client_ts - CONFLICT_WINDOW
    until = incoming.client_ts + CONFLICT_WINDOW
    candidates = db.query(FieldSubmission).filter(
        FieldSubmission.id != incoming.id,
        FieldSubmission.submitted_by != incoming.submitted_by,
        FieldSubmission.layer == incoming.layer,
        FieldSubmission.lat.isnot(None),
        FieldSubmission.lon.isnot(None),
        FieldSubmission.client_ts >= since,
        FieldSubmission.client_ts <= until,
    ).all()
    for c in candidates:
        if _haversine_m(incoming.lat, incoming.lon, c.lat, c.lon) <= CONFLICT_RADIUS_M:
            return c
    return None


@router.post("/push", response_model=list[FieldSubmissionOut])
def push(payload: FieldSubmissionPush, db: Session = Depends(get_db),
         user: User = Depends(require_role(*STAFF_ROLES))):
    """Apply a batch of queued field actions. Each is looked up by its client-generated
    `client_id` first, so replaying the same batch after a dropped connection is always safe -
    an already-applied submission is just returned again, never duplicated."""
    if len(payload.submissions) > 200:
        raise HTTPException(400, "Too many submissions in one batch (max 200)")
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    out: list[FieldSubmission] = []
    for item in payload.submissions:
        existing = db.query(FieldSubmission).filter(FieldSubmission.client_id == item.client_id).first()
        if existing:
            out.append(existing)
            continue
        photo_path = None
        if item.photo_base64:
            try:
                raw = base64.b64decode(item.photo_base64, validate=True)
            except Exception:
                raise HTTPException(400, f"Invalid photo_base64 for client_id {item.client_id}")
            if len(raw) > 8 * 1024 * 1024:
                raise HTTPException(400, f"Photo too large for client_id {item.client_id} (max 8MB)")
            fname = f"{uuid.uuid4()}.jpg"
            (UPLOADS_DIR / fname).write_bytes(raw)
            photo_path = fname
        row = FieldSubmission(
            client_id=item.client_id, submitted_by=user.email, layer=item.layer,
            parcel_label=item.parcel_label, lat=item.lat, lon=item.lon, note=item.note,
            photo_path=photo_path, client_ts=item.client_ts,
        )
        db.add(row)
        db.flush()  # assigns row.id before the conflict check / commit
        conflict = _find_conflict(db, row)
        if conflict:
            row.status = SubmissionStatus.conflict
            row.conflict_with = conflict.id
        db.commit()
        db.refresh(row)
        out.append(row)
    return out


@router.get("/conflicts", response_model=list[ConflictPairOut])
def list_conflicts(db: Session = Depends(get_db), _: User = Depends(require_role(*STAFF_ROLES))):
    flagged = db.query(FieldSubmission).filter(
        FieldSubmission.status == SubmissionStatus.conflict
    ).order_by(FieldSubmission.created_at.desc()).all()
    out = []
    for sub in flagged:
        other = (db.query(FieldSubmission).filter(FieldSubmission.id == sub.conflict_with).first()
                 if sub.conflict_with else None)
        out.append({"submission": sub, "conflicts_with": other})
    return out


@router.post("/conflicts/{submission_id}/resolve", response_model=FieldSubmissionOut)
def resolve_conflict(submission_id: uuid.UUID, payload: ConflictResolve, db: Session = Depends(get_db),
                      user: User = Depends(require_role(*STAFF_ROLES))):
    if payload.action not in ("keep", "discard"):
        raise HTTPException(400, "action must be 'keep' or 'discard'")
    row = db.query(FieldSubmission).filter(FieldSubmission.id == submission_id).first()
    if not row:
        raise HTTPException(404, "Submission not found")
    if row.status != SubmissionStatus.conflict:
        raise HTTPException(400, "This submission isn't flagged as a conflict")
    row.status = SubmissionStatus.resolved if payload.action == "keep" else SubmissionStatus.resolved
    row.resolved_by = user.email
    row.resolved_at = datetime.now(timezone.utc)
    row.resolution_note = (payload.note or "") + (" [discarded]" if payload.action == "discard" else " [kept]")
    if payload.action == "discard":
        row.lat = row.lon = None
        row.note = (row.note or "") + "\n[discarded by admin - see resolution_note]"
    db.commit()
    db.refresh(row)
    return row
