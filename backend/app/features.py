from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from .database import get_db
from .models import FeatureFlag

# key -> human label shown in the super admin's "Feature Settings" panel.
# Anything not in this dict is not a real, toggleable feature.
FEATURE_LABELS: dict[str, str] = {
    "self_registration": "Public self-signup (Create account)",
    "location_search": "Location search box",
    "measure_tool": "Measure distance tool",
    "occupancy_check": "Check location / occupancy tool",
    "compare_counties": "Compare counties tool",
    "export_csv": "Export CSV",
    "report_print": "Print report",
    "analytics": "Analytics dashboard",
    "overlap_report": "Overlap / duplicate detection report",
    "data_upload": "Admin data upload (CSV / shapefile)",
    "public_view": "Public read-only map (no login)",
    "require_2fa_admins": "Require two-factor login for admins",
    "map_export": "Cartographic map export (image)",
    "bookmarks": "Saved map views / bookmarks",
    "my_location": "\"My location\" GPS button",
    "parcel_certificate": "Single-parcel PDF certificate",
}


def all_flags(db: Session) -> dict[str, bool]:
    """Every known feature key, enabled unless a row explicitly turns it off."""
    rows = {r.key: r.enabled for r in db.query(FeatureFlag).all()}
    return {key: rows.get(key, True) for key in FEATURE_LABELS}


def is_enabled(db: Session, key: str) -> bool:
    row = db.get(FeatureFlag, key)
    return row.enabled if row else True


def require_feature(key: str):
    """A feature a super admin has turned off is refused server-side too, not just hidden
    in the UI, so a tab that was already open before the toggle can't keep using it."""
    def dependency(db: Session = Depends(get_db)) -> None:
        if not is_enabled(db, key):
            raise HTTPException(403, "This feature has been turned off by an administrator")
    return dependency
