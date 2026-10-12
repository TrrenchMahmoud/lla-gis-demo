from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User, Role

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    return jwt.encode({**data, "exp": exp}, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_verify_email_token(email: str) -> str:
    """Long-lived (48h) token embedded in the confirmation link sent by email."""
    exp = datetime.now(timezone.utc) + timedelta(hours=48)
    return jwt.encode({"sub": email, "stage": "verify-email", "exp": exp},
                       settings.jwt_secret, algorithm=settings.jwt_algorithm)


def read_verify_email_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(400, "This confirmation link is invalid or has expired")
    if payload.get("stage") != "verify-email":
        raise HTTPException(400, "This confirmation link is invalid")
    return payload["sub"]


def create_password_reset_token(email: str) -> str:
    """Short-lived (1h) token embedded in the password-reset link sent by email."""
    exp = datetime.now(timezone.utc) + timedelta(hours=1)
    return jwt.encode({"sub": email, "stage": "reset-password", "exp": exp},
                       settings.jwt_secret, algorithm=settings.jwt_algorithm)


def read_password_reset_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(400, "This password reset link is invalid or has expired")
    if payload.get("stage") != "reset-password":
        raise HTTPException(400, "This password reset link is invalid")
    return payload["sub"]


def create_mfa_token(email: str) -> str:
    """Short-lived (10 min) token proving the password step already succeeded, handed back to
    the frontend so it can submit the TOTP code separately without resending the password."""
    exp = datetime.now(timezone.utc) + timedelta(minutes=10)
    return jwt.encode({"sub": email, "stage": "mfa", "exp": exp},
                       settings.jwt_secret, algorithm=settings.jwt_algorithm)


def read_mfa_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(400, "That login attempt expired - please log in again")
    if payload.get("stage") != "mfa":
        raise HTTPException(400, "That login attempt is invalid - please log in again")
    return payload["sub"]


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.query(User).filter(User.email == email).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return None
    return user


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    err = HTTPException(status.HTTP_401_UNAUTHORIZED, "Could not validate credentials",
                        headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        email = payload.get("sub")
    except JWTError:
        raise err
    if payload.get("stage"):
        raise err  # a special-purpose token (e.g. email confirmation) never grants API access
    user = db.query(User).filter(User.email == email).first() if email else None
    if user is None:
        raise err
    return user


def require_role(*roles: Role):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Not allowed")
        return user
    return dependency
