import re
import time
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

import config
import models

ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
router = APIRouter(prefix="/auth", tags=["auth"])

_failures: dict[str, list[float]] = {}   # simple in-memory login rate limit
MAX_FAILS, WINDOW = 5, 300


def get_db():
    db = models.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def audit(db: Session, username: str, action: str, detail: str = ""):
    db.add(models.AuditLog(username=username, action=action, detail=detail[:500]))
    db.commit()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode()[:72], hashed.encode())


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def _pv(user) -> str:
    """Fingerprint of the current password. Tokens carry it, so a password reset logs the user out everywhere."""
    return user.hashed_password[-12:]


def create_access_token(username: str, pv: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "pv": pv, "exp": exp}, config.SECRET_KEY, algorithm=ALGORITHM)


def bootstrap_admin(db: Session):
    """Create the first admin from ADMIN_USERNAME / ADMIN_PASSWORD env vars (if set and missing)."""
    if not (config.ADMIN_USERNAME and config.ADMIN_PASSWORD):
        return
    if not db.query(models.User).filter_by(username=config.ADMIN_USERNAME).first():
        db.add(models.User(username=config.ADMIN_USERNAME,
                           hashed_password=get_password_hash(config.ADMIN_PASSWORD), role="admin"))
        db.commit()


def _check_password(v: str) -> str:
    if not 8 <= len(v) <= 72:
        raise ValueError("Password must be 8-72 characters")
    return v


class RegisterIn(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def _u(cls, v):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", v):
            raise ValueError("Username must be 3-32 characters: letters, numbers, _ . -")
        return v

    @field_validator("password")
    @classmethod
    def _p(cls, v):
        return _check_password(v)


class PasswordIn(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def _p(cls, v):
        return _check_password(v)


class RoleIn(BaseModel):
    role: str


class ActiveIn(BaseModel):
    active: bool


class DeptIn(BaseModel):
    department: str = ""


@router.post("/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(models.User).filter_by(username=data.username).first():
        raise HTTPException(400, "Username already registered")
    # SECURITY: role is NEVER taken from the client. New accounts are always "standard".
    db.add(models.User(username=data.username, hashed_password=get_password_hash(data.password), role="standard"))
    db.commit()
    audit(db, data.username, "register")
    return {"message": f"Account '{data.username}' created."}


@router.post("/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    key = form.username.lower()
    now = time.time()
    recent = [t for t in _failures.get(key, []) if now - t < WINDOW]
    _failures[key] = recent
    if len(recent) >= MAX_FAILS:
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
    user = db.query(models.User).filter_by(username=form.username).first()
    if not user or not user.is_active or not verify_password(form.password, user.hashed_password):
        _failures[key].append(now)
        audit(db, form.username, "login_failed")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password")
    _failures.pop(key, None)
    audit(db, user.username, "login")
    return {"access_token": create_access_token(user.username, _pv(user)), "token_type": "bearer"}


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    err = HTTPException(401, "Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise err
    username = payload.get("sub")
    user = db.query(models.User).filter_by(username=username).first() if username else None
    if not user or not user.is_active or payload.get("pv") != _pv(user):
        raise err
    return user  # role and department are read from the DB each request, so changes apply instantly


def require_admin(user: models.User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


@router.get("/me")
def me(user: models.User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role, "department": user.department,
            "departments": config.DEPARTMENTS}


# ---------------- admin: user management ----------------
def _get_user(db: Session, username: str):
    user = db.query(models.User).filter_by(username=username).first()
    if not user:
        raise HTTPException(404, "User not found")
    return user


@router.get("/users")
def list_users(admin=Depends(require_admin), db: Session = Depends(get_db)):
    return [{"username": u.username, "role": u.role, "active": bool(u.is_active), "department": u.department}
            for u in db.query(models.User).order_by(models.User.id)]


@router.put("/users/{username}/role")
def set_role(username: str, body: RoleIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    if body.role not in config.ROLES:
        raise HTTPException(400, "Role must be 'standard' or 'admin'")
    if username == admin.username:
        raise HTTPException(400, "You cannot change your own role")
    user = _get_user(db, username)
    user.role = body.role
    db.commit()
    audit(db, admin.username, "role_change", f"{username} -> {body.role}")
    return {"message": f"{username} is now '{body.role}'"}


@router.put("/users/{username}/active")
def set_active(username: str, body: ActiveIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    if username == admin.username:
        raise HTTPException(400, "You cannot disable your own account")
    user = _get_user(db, username)
    user.is_active = body.active      # a disabled user's existing login stops working immediately
    db.commit()
    audit(db, admin.username, "user_enabled" if body.active else "user_disabled", username)
    return {"message": f"{username} is now {'active' if body.active else 'disabled'}"}


@router.put("/users/{username}/department")
def set_department(username: str, body: DeptIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    dep = body.department.strip()
    if dep and dep not in config.DEPARTMENTS:
        raise HTTPException(400, f"Unknown department. Choose from: {', '.join(config.DEPARTMENTS)}")
    user = _get_user(db, username)
    user.department = dep or None
    db.commit()
    audit(db, admin.username, "department_change", f"{username} -> {dep or 'none'}")
    return {"message": f"{username} department: {dep or 'none'}"}


@router.put("/users/{username}/password")
def reset_password(username: str, body: PasswordIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    user = _get_user(db, username)
    user.hashed_password = get_password_hash(body.password)   # old tokens stop working (see _pv)
    db.commit()
    _failures.pop(username.lower(), None)
    audit(db, admin.username, "password_reset", username)
    return {"message": f"Password reset for {username}"}


@router.delete("/users/{username}")
def delete_user(username: str, admin=Depends(require_admin), db: Session = Depends(get_db)):
    if username == admin.username:
        raise HTTPException(400, "You cannot delete your own account")
    user = _get_user(db, username)
    db.delete(user)
    db.commit()
    audit(db, admin.username, "user_deleted", username)
    return {"message": f"Deleted user {username}"}
