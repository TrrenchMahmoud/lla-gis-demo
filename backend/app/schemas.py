import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr

from .models import Role, SubmissionStatus


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: Role = Role.viewer
    county_scope: str | None = None


class UserRegister(BaseModel):
    """Public self-signup: no role field, so a new account can only ever land as viewer."""
    email: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    role: Role
    is_approved: bool
    county_scope: str | None = None
    totp_enabled: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginResult(BaseModel):
    """Either a normal login (access_token set) or a request for the second 2FA step
    (mfa_token set instead, to be posted back to /login/2fa along with the code)."""
    access_token: str | None = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str | None = None


class Verify2FA(BaseModel):
    mfa_token: str
    code: str


class TotpCode(BaseModel):
    code: str


class ForgotPassword(BaseModel):
    email: EmailStr


class ResetPassword(BaseModel):
    token: str
    password: str


class ActivityEvent(BaseModel):
    """A UI-driven event the frontend reports for the analytics view, e.g. a tool used or a
    layer opened. `action` is restricted server-side to a known-safe set of prefixes."""
    action: str
    detail: str | None = None


class OccupancyCheck(BaseModel):
    """points are [lng, lat] pairs. A single point checks "is this spot inside a parcel";
    3+ points are treated as the boundary of an area and checked for overlap with any parcel."""
    points: list[list[float]]


class FieldSubmissionIn(BaseModel):
    """One queued field action from the staff app. client_id is generated on-device the
    moment the action happens (offline or not) so a retried push never creates a duplicate."""
    client_id: str
    layer: str | None = None
    parcel_label: str | None = None
    lat: float | None = None
    lon: float | None = None
    note: str | None = None
    photo_base64: str | None = None   # optional JPEG/PNG, base64-encoded, no data: prefix
    client_ts: datetime


class FieldSubmissionPush(BaseModel):
    submissions: list[FieldSubmissionIn]


class FieldSubmissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    client_id: str
    submitted_by: str
    layer: str | None
    parcel_label: str | None
    lat: float | None
    lon: float | None
    note: str | None
    photo_path: str | None
    client_ts: datetime
    created_at: datetime
    status: SubmissionStatus
    conflict_with: uuid.UUID | None
    resolved_by: str | None
    resolved_at: datetime | None
    resolution_note: str | None


class ConflictResolve(BaseModel):
    action: str   # "keep" (this submission stands) or "discard" (drop it)
    note: str | None = None


class ConflictPairOut(BaseModel):
    """A flagged submission alongside the earlier one it conflicts with, so a reviewer can see
    both sides at once instead of looking up conflict_with separately."""
    submission: FieldSubmissionOut
    conflicts_with: FieldSubmissionOut | None
