import os
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text
from sqlalchemy.orm import Session

from .activity import client_ip, last_seen_snapshot, log_activity, touch
from .auth import (authenticate_user, create_access_token, create_mfa_token, create_password_reset_token,
                   create_verify_email_token, get_current_user, hash_password, read_mfa_token,
                   read_password_reset_token, read_verify_email_token, require_role)
from .config import settings
from .database import Base, SessionLocal, engine, get_db
from .features import FEATURE_LABELS, all_flags, is_enabled, require_feature
from .layers import layer_allowed, router as layers_router
from .mailer import send_password_reset_email, send_verification_email
from .models import ActivityLog, FeatureFlag, Role, User
from .schemas import (ActivityEvent, ForgotPassword, LoginResult, ResetPassword, Token, TotpCode, UserCreate,
                      UserOut, UserRegister, Verify2FA)
from .stats import LAYER_RE, _COLS_CACHE, _GEOM_COL_CACHE, known_layers, router as stats_router
from .sync import router as sync_router
from .twofactor import new_secret, provisioning_qr_png_b64, verify_code

# Roles that count as "staff" for anything gated to admin+ (viewing users, activity, reports).
# Only super_admin, on top of that, may create/approve/delete another super_admin account or
# touch the feature switches - see the checks inline below.
STAFF_ROLES = (Role.admin, Role.super_admin)


def init_db():
    for attempt in range(1, 11):
        try:
            Base.metadata.create_all(bind=engine)  # only creates app tables

            # ALTER TYPE ... ADD VALUE cannot run inside the same multi-statement transaction
            # as other DDL on some Postgres versions ("cannot run inside a transaction block").
            # It gets its own autocommit connection so a failure here - old Postgres, a
            # permissions quirk, whatever - can NEVER take the column migrations below down
            # with it. (An earlier version of this function had them in one transaction, which
            # silently failed every migration below it and broke every login - fixed here.)
            try:
                with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                    conn.execute(text("ALTER TYPE app_role ADD VALUE IF NOT EXISTS 'super_admin'"))
            except Exception as e:
                print(f"Note: could not add 'super_admin' to the app_role enum ({type(e).__name__}: {e}). "
                      f"If it already exists this is harmless.", flush=True)

            with engine.begin() as conn:
                # create_all() won't add columns to a table that already exists, so migrate by hand.
                # Existing accounts default to approved=true so nobody already using the app gets locked out.
                conn.execute(text(
                    "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS is_approved boolean NOT NULL DEFAULT true"
                ))
                conn.execute(text(
                    "ALTER TABLE app_activity_log ADD COLUMN IF NOT EXISTS ip_address varchar"
                ))
                conn.execute(text(
                    "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS county_scope varchar"
                ))
                conn.execute(text(
                    "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS totp_secret varchar"
                ))
                conn.execute(text(
                    "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS totp_enabled boolean NOT NULL DEFAULT false"
                ))
            break
        except Exception as e:
            print(f"Database not reachable ({type(e).__name__}: {e}), try {attempt}/10", flush=True)
            time.sleep(3)
    else:
        print("GIVING UP: check DATABASE_URL, pg_hba.conf and the Windows firewall, "
              "then run: docker compose restart backend", flush=True)
        return
    if settings.bootstrap_admin_email and settings.bootstrap_admin_password:
        with SessionLocal() as db:
            if not db.query(User).first():
                db.add(User(email=settings.bootstrap_admin_email,
                            hashed_password=hash_password(settings.bootstrap_admin_password),
                            role=Role.super_admin, is_approved=True))
                db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="GIS Dashboard API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list,
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(stats_router)
app.include_router(layers_router)
app.include_router(sync_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/db")
def health_db(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"database": "ok"}
    except Exception as e:
        raise HTTPException(503, f"database unreachable: {type(e).__name__}")


@app.get("/verify", status_code=204)
def verify(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> None:
    """nginx auth_request: needs a valid login, and admin-only layers stay closed to viewers."""
    if not layer_allowed(db, user, request.headers.get("x-original-uri", "")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No access to this layer")


@app.post("/login", response_model=LoginResult)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form.username, form.password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if not user.is_approved:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                             "Please confirm your account via the link we emailed you before logging in")
    if user.totp_enabled:
        # Password checked out, but a second step (the authenticator code) is still needed -
        # no real access token is issued until /login/2fa confirms the code.
        log_activity(db, user.email, "login.mfa_pending", None, client_ip(request))
        return LoginResult(mfa_required=True, mfa_token=create_mfa_token(user.email))
    log_activity(db, user.email, "login", None, client_ip(request))
    return LoginResult(access_token=create_access_token({"sub": user.email, "role": user.role.value}))


@app.post("/login/2fa", response_model=Token)
def login_2fa(payload: Verify2FA, request: Request, db: Session = Depends(get_db)):
    email = read_mfa_token(payload.mfa_token)
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.totp_enabled or not verify_code(user.totp_secret, payload.code):
        raise HTTPException(401, "Invalid or expired authentication code")
    log_activity(db, user.email, "login", "via 2FA", client_ip(request))
    return Token(access_token=create_access_token({"sub": user.email, "role": user.role.value}))


@app.post("/register", status_code=201)
def register(payload: UserRegister, request: Request, db: Session = Depends(get_db)):
    """Public self-signup. Lands as viewer, pending - confirming the emailed link activates it."""
    if not is_enabled(db, "self_registration"):
        raise HTTPException(403, "Public sign-up is currently turned off. Contact an administrator for access.")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(email=payload.email, hashed_password=hash_password(payload.password),
                role=Role.viewer, is_approved=False)
    db.add(user)
    db.commit()
    link = f"{settings.app_base_url.rstrip('/')}/api/verify-email?token={create_verify_email_token(user.email)}"
    send_verification_email(user.email, link)
    log_activity(db, user.email, "register", "self-signup, pending confirmation", client_ip(request))
    return {"detail": "Account created. Check your email for a confirmation link to activate it."}


@app.get("/verify-email", response_class=HTMLResponse)
def verify_email(token: str, request: Request, db: Session = Depends(get_db)):
    """The link from the confirmation email lands here, opened directly in a browser."""
    email = read_verify_email_token(token)
    user = db.query(User).filter(User.email == email).first()
    page = lambda title, body: (
        "<html><body style='font-family:system-ui,sans-serif;text-align:center;padding:60px;color:#1f2430'>"
        f"<h2>{title}</h2><p>{body}</p>"
        f"<p><a href='{settings.app_base_url}' style='color:#3b82f6'>Go to the dashboard</a></p>"
        "</body></html>"
    )
    if not user:
        return HTMLResponse(page("Account not found", "This confirmation link doesn't match an account."), 404)
    if not user.is_approved:
        user.is_approved = True
        db.commit()
        log_activity(db, user.email, "email.confirm", None, client_ip(request))
    return HTMLResponse(page("Email confirmed", "Your account is active - you can log in now."))


@app.post("/forgot-password", status_code=200)
def forgot_password(payload: ForgotPassword, request: Request, db: Session = Depends(get_db)):
    """Always answers the same way whether or not the email exists, so this can't be used to
    probe which addresses have accounts."""
    user = db.query(User).filter(User.email == payload.email).first()
    if user:
        link = (f"{settings.app_base_url.rstrip('/')}/"
                f"?reset={create_password_reset_token(user.email)}")
        send_password_reset_email(user.email, link)
        log_activity(db, user.email, "password.forgot_requested", None, client_ip(request))
    return {"detail": "If an account exists for that email, a reset link has been sent."}


@app.post("/reset-password", status_code=200)
def reset_password(payload: ResetPassword, request: Request, db: Session = Depends(get_db)):
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    email = read_password_reset_token(payload.token)
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(404, "Account not found")
    user.hashed_password = hash_password(payload.password)
    db.commit()
    log_activity(db, user.email, "password.reset", None, client_ip(request))
    return {"detail": "Password updated. You can log in with your new password now."}


@app.get("/me")
def me(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    out = UserOut.model_validate(user).model_dump()
    out["must_setup_2fa"] = (user.role in STAFF_ROLES and not user.totp_enabled
                              and is_enabled(db, "require_2fa_admins"))
    return out


@app.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_role(*STAFF_ROLES))):
    return db.query(User).all()


@app.post("/users", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_role(*STAFF_ROLES))):
    if payload.role == Role.super_admin and admin.role != Role.super_admin:
        raise HTTPException(403, "Only a super admin can create another super admin account")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already registered")
    # county_scope only ever applies to a plain admin - a super admin always sees everything.
    scope = payload.county_scope.strip() if payload.county_scope and payload.role == Role.admin else None
    user = User(email=payload.email, hashed_password=hash_password(payload.password),
                role=payload.role, is_approved=True, county_scope=scope or None)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_activity(db, admin.email, "user.create", f"{user.email} ({user.role.value})", client_ip(request))
    return user


@app.put("/users/{user_id}/approve", response_model=UserOut)
def approve_user(user_id: uuid.UUID, request: Request, role: Role | None = None, county_scope: str | None = None,
                  db: Session = Depends(get_db), admin: User = Depends(require_role(*STAFF_ROLES))):
    """Manual fallback for when email delivery isn't set up yet, or an admin wants to skip it.
    Also doubles as "edit this user's role/county" from the Users panel."""
    if role == Role.super_admin and admin.role != Role.super_admin:
        raise HTTPException(403, "Only a super admin can promote someone to super admin")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.role == Role.super_admin and admin.role != Role.super_admin:
        raise HTTPException(403, "Only a super admin can change another super admin's account")
    user.is_approved = True
    if role is not None:
        user.role = role
    if county_scope is not None:
        user.county_scope = county_scope.strip() or None if user.role == Role.admin else None
    db.commit()
    db.refresh(user)
    log_activity(db, admin.email, "user.approve", user.email, client_ip(request))
    return user


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: uuid.UUID, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_role(*STAFF_ROLES))):
    if user_id == admin.id:
        raise HTTPException(400, "You cannot delete your own account")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.role == Role.super_admin and admin.role != Role.super_admin:
        raise HTTPException(403, "Only a super admin can remove a super admin account")
    deleted_email = user.email
    db.delete(user)
    db.commit()
    log_activity(db, admin.email, "user.delete", deleted_email, client_ip(request))


@app.post("/2fa/setup")
def setup_2fa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generates a fresh secret and a QR code for an authenticator app. Not active yet -
    /2fa/enable with a correct code from that app is what actually turns it on, so a
    half-finished setup can't accidentally lock the account out."""
    secret = new_secret()
    user.totp_secret = secret
    db.commit()
    return {"secret": secret, "qr_png_base64": provisioning_qr_png_b64(user.email, secret)}


@app.post("/2fa/enable", status_code=204)
def enable_2fa(payload: TotpCode, request: Request, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)) -> None:
    if not user.totp_secret or not verify_code(user.totp_secret, payload.code):
        raise HTTPException(400, "Incorrect code - check your authenticator app and try again")
    user.totp_enabled = True
    db.commit()
    log_activity(db, user.email, "user.2fa_enable", None, client_ip(request))


@app.post("/2fa/disable", status_code=204)
def disable_2fa(payload: TotpCode, request: Request, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> None:
    if not user.totp_enabled or not verify_code(user.totp_secret, payload.code):
        raise HTTPException(400, "Incorrect code")
    user.totp_enabled = False
    user.totp_secret = None
    db.commit()
    log_activity(db, user.email, "user.2fa_disable", None, client_ip(request))


@app.put("/users/{user_id}/2fa-reset", status_code=204)
def reset_2fa(user_id: uuid.UUID, request: Request, db: Session = Depends(get_db),
              admin: User = Depends(require_role(Role.super_admin))) -> None:
    """Locked out because a phone with the authenticator app was lost? A super admin can force
    -clear 2FA so the account falls back to password-only login, then set it up again fresh."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.totp_enabled = False
    user.totp_secret = None
    db.commit()
    log_activity(db, admin.email, "user.2fa_reset", user.email, client_ip(request))


# Free-text-ish but restricted to a known-safe set of prefixes, so a compromised or careless
# client can't spam arbitrary strings into the audit trail.
_ALLOWED_EVENT_PREFIXES = (
    "layer.", "tool.", "search.", "export.", "report.", "session.",
)


@app.post("/activity/log", status_code=204)
def report_activity(payload: ActivityEvent, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)) -> None:
    """The frontend calls this for UI-driven events worth tracking for analytics - a layer opened,
    a tool used, a search made, an export taken, a logout - so "what are people doing" isn't limited
    to the handful of endpoints that already log themselves."""
    action = payload.action.strip()[:64]
    if not action.startswith(_ALLOWED_EVENT_PREFIXES):
        raise HTTPException(400, "Unrecognized activity type")
    detail = (payload.detail or "").strip()[:200] or None
    log_activity(db, user.email, action, detail, client_ip(request))


@app.post("/activity/heartbeat", status_code=204)
def heartbeat(user: User = Depends(get_current_user)) -> None:
    """Cheap, frequent "I'm still here" ping for the online-now count - kept in memory only,
    never written to the database, so an open tab left running for hours costs nothing to store."""
    touch(user.email)


@app.get("/activity")
def list_activity(limit: int = 100, db: Session = Depends(get_db),
                   _: User = Depends(require_role(*STAFF_ROLES)), __: None = Depends(require_feature("analytics"))):
    limit = max(1, min(limit, 500))
    rows = db.query(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(limit).all()
    return [{"id": str(r.id), "created_at": r.created_at.isoformat() if r.created_at else None,
             "actor_email": r.actor_email, "action": r.action, "detail": r.detail,
             "ip_address": r.ip_address} for r in rows]


@app.get("/activity/analytics")
def activity_analytics(days: int = 30, db: Session = Depends(get_db),
                        _: User = Depends(require_role(*STAFF_ROLES)),
                        __: None = Depends(require_feature("analytics"))):
    """Who's visiting, for how long, and what they're using - built from the activity log plus
    the in-memory "last seen" heartbeat. Session gaps of more than 20 minutes count as a new visit."""
    days = max(1, min(days, 180))
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (db.query(ActivityLog)
            .filter(ActivityLog.created_at >= since)
            .order_by(ActivityLog.actor_email, ActivityLog.created_at)
            .all())

    SESSION_GAP = timedelta(minutes=20)
    sessions_by_user: dict[str, list[dict]] = defaultdict(list)
    resource_counts: dict[str, int] = defaultdict(int)
    daily_counts: dict[str, int] = defaultdict(int)
    last_ip: dict[str, str] = {}

    for r in rows:
        email = r.actor_email or "(anonymous)"
        resource_counts[r.action] += 1
        daily_counts[r.created_at.date().isoformat()] += 1
        if r.ip_address:
            last_ip[email] = r.ip_address
        sess = sessions_by_user[email]
        if sess and (r.created_at - sess[-1]["end"]) <= SESSION_GAP:
            sess[-1]["end"] = r.created_at
            sess[-1]["events"] += 1
            sess[-1]["actions"].add(r.action)
        else:
            sess.append({"start": r.created_at, "end": r.created_at, "events": 1, "actions": {r.action}})

    now = datetime.now(timezone.utc)
    last_seen = last_seen_snapshot()
    online_cutoff = now - timedelta(minutes=5)
    online_now = sorted(email for email, ts in last_seen.items() if ts >= online_cutoff)

    per_user = []
    for email, sessions in sessions_by_user.items():
        total_seconds = sum((s["end"] - s["start"]).total_seconds() for s in sessions)
        # a session that's still just one event (e.g. a single login with nothing after it)
        # gets a nominal minute credited, rather than reading as "0 minutes spent"
        total_seconds += sum(60 for s in sessions if s["events"] == 1)
        top_actions = defaultdict(int)
        for s in sessions:
            for a in s["actions"]:
                top_actions[a] += 1
        top_resource = max(top_actions, key=top_actions.get) if top_actions else None
        per_user.append({
            "email": email,
            "sessions": len(sessions),
            "total_minutes": round(total_seconds / 60, 1),
            "last_seen": max(s["end"] for s in sessions).isoformat(),
            "top_resource": top_resource,
            "online_now": email in online_now,
            "ip_address": last_ip.get(email),
        })
    per_user.sort(key=lambda u: u["last_seen"], reverse=True)

    all_sessions = []
    for email, sessions in sessions_by_user.items():
        for s in sessions:
            dur_min = max(1, round((s["end"] - s["start"]).total_seconds() / 60, 1))
            all_sessions.append({"email": email, "start": s["start"].isoformat(), "end": s["end"].isoformat(),
                                  "duration_minutes": dur_min, "events": s["events"]})
    all_sessions.sort(key=lambda s: s["start"], reverse=True)

    return {
        "range_days": days,
        "online_now": online_now,
        "total_events": len(rows),
        "unique_users": len(sessions_by_user),
        "resource_counts": sorted(({"action": k, "count": v} for k, v in resource_counts.items()),
                                   key=lambda x: -x["count"]),
        "daily_counts": sorted(({"date": k, "count": v} for k, v in daily_counts.items()),
                                key=lambda x: x["date"]),
        "per_user": per_user,
        "recent_sessions": all_sessions[:100],
    }


@app.get("/features/public")
def public_features(db: Session = Depends(get_db)):
    """No login required: just enough for the login screen to know whether to show
    "Create account" and the public summary link before anyone has a token yet."""
    return {"self_registration": is_enabled(db, "self_registration"), "public_view": is_enabled(db, "public_view")}


@app.get("/features")
def get_features(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Every user needs this - a viewer's UI must hide a tool a super admin turned off too."""
    return {"features": all_flags(db), "labels": FEATURE_LABELS}


@app.put("/features/{key}")
def set_feature(key: str, enabled: bool, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_role(Role.super_admin))):
    """Only a super admin may flip a feature switch - this is the one control an ordinary
    admin does not get, by the person's own design: admins and super admins can both print
    reports, but turning a feature off dashboard-wide is super-admin-only."""
    if key not in FEATURE_LABELS:
        raise HTTPException(404, "Unknown feature")
    row = db.get(FeatureFlag, key)
    if row:
        row.enabled = enabled
    else:
        db.add(FeatureFlag(key=key, enabled=enabled))
    db.commit()
    log_activity(db, admin.email, "feature.toggle", f"{key}={enabled}", client_ip(request))
    return {"key": key, "enabled": enabled}


def _pg_conn_string() -> str:
    """Build an ogr2ogr-style 'PG:...' connection string from DATABASE_URL, so the upload
    endpoint talks to the same database the app itself uses."""
    u = urlparse(settings.database_url.replace("+psycopg2", ""))
    return (f"host={u.hostname or 'localhost'} port={u.port or 5432} "
            f"dbname={(u.path or '/').lstrip('/')} user={u.username or ''} password={u.password or ''}")


@app.post("/admin/upload-shapefile")
async def upload_shapefile(layer_name: str, request: Request, file: UploadFile = File(...), mode: str = "replace",
                           db: Session = Depends(get_db), admin: User = Depends(require_role(Role.super_admin)),
                           _: None = Depends(require_feature("data_upload"))):
    """Upload a zipped shapefile (.shp/.shx/.dbf/.prj at minimum) to create a brand new layer
    or replace/append to an existing one - the same ogr2ogr conversion normally run by hand
    from a terminal, done here through the browser instead. Requires ogr2ogr in the backend
    image (see the Dockerfile note) and is super-admin only, since it can overwrite live data."""
    if not LAYER_RE.match(layer_name):
        raise HTTPException(400, "Layer name must look like schema.table, e.g. public.new_layer")
    schema, table = layer_name.split(".", 1)
    if schema != "public":
        raise HTTPException(400, "Only the public schema is supported")
    if mode not in ("replace", "append"):
        raise HTTPException(400, "mode must be 'replace' or 'append'")
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip containing the .shp/.shx/.dbf/.prj files")
    if not shutil.which("ogr2ogr"):
        raise HTTPException(500, "ogr2ogr is not installed in the backend image - see the Dockerfile note "
                                  "(apt-get install gdal-bin) and rebuild")

    with tempfile.TemporaryDirectory() as tmp:
        zpath = Path(tmp) / "upload.zip"
        with open(zpath, "wb") as f:
            shutil.copyfileobj(file.file, f)
        extract_dir = Path(tmp) / "extract"
        extract_dir.mkdir()
        try:
            with zipfile.ZipFile(zpath) as zf:
                for member in zf.namelist():
                    dest = (extract_dir / member).resolve()
                    if not str(dest).startswith(str(extract_dir.resolve()) + os.sep):
                        raise HTTPException(400, "Invalid path in zip file")
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            raise HTTPException(400, "That doesn't look like a valid .zip file")
        shp_files = list(extract_dir.rglob("*.shp"))
        if not shp_files:
            raise HTTPException(400, "No .shp file found inside the zip")

        cmd = ["ogr2ogr", "-f", "PostgreSQL", f"PG:{_pg_conn_string()}", str(shp_files[0]),
               "-nln", table, "-t_srs", "EPSG:4326",
               "-overwrite" if mode == "replace" else "-append",
               "-lco", "GEOMETRY_NAME=wkb_geometry", "-lco", "FID=ogc_fid"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "Import timed out - the file may be too large")
        if result.returncode != 0:
            raise HTTPException(400, f"Import failed: {(result.stderr or '')[-800:]}")

    _GEOM_COL_CACHE.pop(layer_name, None)
    _COLS_CACHE.pop(layer_name, None)
    count = db.execute(text(f'SELECT COUNT(*) FROM "public"."{table}"')).scalar()
    log_activity(db, admin.email, "layer.import", f"{layer_name} ({mode}, {count} features)", client_ip(request))
    return {"layer": layer_name, "mode": mode, "feature_count": int(count)}


@app.get("/admin/import-history")
def import_history(db: Session = Depends(get_db), _: User = Depends(require_role(*STAFF_ROLES))):
    """The audit trail for data changes: every upload that has touched a layer, newest first."""
    rows = (db.query(ActivityLog).filter(ActivityLog.action == "layer.import")
            .order_by(ActivityLog.created_at.desc()).limit(200).all())
    return [{"created_at": r.created_at.isoformat() if r.created_at else None,
             "actor_email": r.actor_email, "detail": r.detail} for r in rows]


# ---- Public, no-login read-only view -------------------------------------------------------
# Deliberately does NOT proxy the live vector tiles (those carry every raw column, including
# names, straight from the database) - it only ever returns pre-aggregated counts/areas, the
# same anonymized shape a plain viewer sees. Off by default; a super admin turns it on in
# Feature Settings once they're comfortable with what it shows.

def _public_guard(db: Session) -> None:
    if not is_enabled(db, "public_view"):
        raise HTTPException(404, "Not found")


@app.get("/public/summary")
def public_summary(db: Session = Depends(get_db)):
    _public_guard(db)
    from .stats import area_expr, county_condition
    total_parcels, total_acres, by_layer = 0, 0.0, []
    for schema, table in known_layers(db):
        cond, params = county_condition(db, schema, table, None)
        sql = text(f'SELECT COUNT(*), COALESCE(SUM({area_expr(db, schema, table)}), 0) FROM "{schema}"."{table}"')
        r = db.execute(sql, params).one()
        total_parcels += int(r[0])
        total_acres += float(r[1])
        by_layer.append({"layer": f"{schema}.{table}", "parcels": int(r[0]), "acres": round(float(r[1]), 1)})
    return {"parcels": total_parcels, "acres": round(total_acres, 1), "by_layer": by_layer}


@app.get("/public/check-occupancy")
def public_check_occupancy(lng: float, lat: float, db: Session = Depends(get_db)):
    """Same idea as the staff /stats/check-occupancy, but for anyone with no login: does this
    point fall inside any mapped parcel, in any layer? Checked across every layer at once since
    a member of the public has no reason to know which internal layer a parcel lives in.
    Deliberately returns only area/county/which layer - never a name, id, or boundary - matching
    the same no-identifying-details rule the rest of this public view follows."""
    _public_guard(db)
    if not (-180 <= lng <= 180 and -90 <= lat <= 90):
        raise HTTPException(400, "Coordinate out of range - expected lng/lat in WGS84")
    from .stats import area_expr, geom_col, id_col_of, table_columns
    matches = []
    for schema, table in known_layers(db):
        try:
            gc = geom_col(db, schema, table)
            idc = id_col_of(db, schema, table)
            ae = area_expr(db, schema, table)
            cols = table_columns(db, schema, table)
            county_expr = '"county"' if "county" in cols else "NULL"
        except Exception:
            continue
        sql = text(
            f'SELECT {ae} AS area_acres, {county_expr} AS county FROM "{schema}"."{table}" '
            f'WHERE ST_Contains(ST_Transform("{gc}", 4326), ST_SetSRID(ST_MakePoint(:lng, :lat), 4326)) '
            f'LIMIT 5'
        )
        try:
            rows = db.execute(sql, {"lng": lng, "lat": lat}).all()
        except Exception:
            continue
        for r in rows:
            matches.append({"layer": f"{schema}.{table}", "area_acres": round(float(r[0]), 2), "county": r[1]})
    return {"inside_mapped_parcel": len(matches) > 0, "matches": matches}
