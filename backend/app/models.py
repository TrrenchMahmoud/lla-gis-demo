import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Enum, Boolean, Float, Text
from sqlalchemy.dialects.postgresql import UUID

from .database import Base


class Role(str, enum.Enum):
    viewer = "viewer"
    admin = "admin"
    super_admin = "super_admin"


class User(Base):
    __tablename__ = "app_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(Role, name="app_role"), nullable=False, default=Role.viewer)
    is_approved = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Set only on an `admin` account to restrict them to one county's data. Never set on a
    # super_admin - a super admin always sees and controls everything, by design.
    county_scope = Column(String, nullable=True)
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, nullable=False, default=False)


class ActivityLog(Base):
    __tablename__ = "app_activity_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    actor_email = Column(String, nullable=True, index=True)  # null for unauthenticated actions (e.g. a failed login)
    action = Column(String, nullable=False)       # short machine-readable verb, e.g. "user.approve", "layer.view"
    detail = Column(String, nullable=True)        # human-readable one-liner, e.g. the affected email or layer name
    ip_address = Column(String, nullable=True)


class SubmissionStatus(str, enum.Enum):
    applied = "applied"      # accepted, no conflict found
    conflict = "conflict"    # flagged - waiting on an admin to review
    resolved = "resolved"    # an admin has reviewed a conflicted submission


class FieldSubmission(Base):
    """A site visit captured by a field-staff app while offline (photo + GPS pin + notes),
    queued on-device and pushed here once the device reconnects. `client_id` is a UUID the
    device generates when the action is first recorded, so re-sending the same queued item
    after a dropped connection never creates a duplicate row."""
    __tablename__ = "app_field_submissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String, unique=True, nullable=False, index=True)
    submitted_by = Column(String, nullable=False)   # the staff user's email
    layer = Column(String, nullable=True)            # e.g. "public.plsd", if the visit relates to one
    parcel_label = Column(String, nullable=True)      # free-text parcel reference given on-device
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    note = Column(Text, nullable=True)
    photo_path = Column(String, nullable=True)        # relative path under the uploads dir, if a photo was attached
    client_ts = Column(DateTime(timezone=True), nullable=False)   # when it happened on the device, offline or not
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # when the server received it
    status = Column(Enum(SubmissionStatus, name="app_submission_status"), nullable=False, default=SubmissionStatus.applied)
    conflict_with = Column(UUID(as_uuid=True), nullable=True)   # id of the earlier submission this one clashes with
    resolved_by = Column(String, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_note = Column(Text, nullable=True)


class FeatureFlag(Base):
    """A switch a super admin can flip to turn a dashboard feature off for everyone.
    No row for a key means that feature is enabled (the default)."""
    __tablename__ = "app_feature_flags"

    key = Column(String, primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)
