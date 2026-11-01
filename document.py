import csv
import io
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

import auth
import config
import models
import rag
from encryption import encrypt_bytes

router = APIRouter(prefix="/documents", tags=["documents"])


class ChatQuery(BaseModel):
    query: str = Field(min_length=1, max_length=1000)
    doc_id: Optional[int] = None      # None = search every document you may read


class AccessIn(BaseModel):
    access_level: str                 # "standard" | "admin" | "dept:<Department>"


@router.post("/upload", status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    access_level: str = Form("standard"),
    confirm_sensitive: bool = Form(False),
    user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(auth.get_db),
):
    if not config.valid_access(access_level):
        raise HTTPException(400, "Invalid access level")
    if access_level == "admin" and user.role != "admin":
        raise HTTPException(403, "Only admins can upload confidential (admin-only) documents")
    if access_level.startswith("dept:") and user.role != "admin" and access_level != f"dept:{user.department}":
        raise HTTPException(403, "You can only upload to your own department")

    original = os.path.basename(file.filename or "upload")      # never trust client paths
    ext = os.path.splitext(original)[1].lower()
    if ext not in config.ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported file type. Allowed: {', '.join(sorted(config.ALLOWED_EXTENSIONS))}")
    data = await file.read()
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (10 MB max)")
    try:
        text = rag.extract_text(original, data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        raise HTTPException(400, "Could not read this file. Is it corrupted?")

    # Sensitive-data guard: protect first, ask questions later
    findings = rag.scan_sensitive(text)
    auto_protected = False
    if findings and access_level == "standard":
        if user.role != "admin":
            access_level, auto_protected = "admin", True      # locked to admins until reviewed
        elif not confirm_sensitive:
            return JSONResponse(status_code=409, content={
                "detail": "This file looks sensitive (" + ", ".join(findings) + ").", "sensitive": findings})

    stored = f"{uuid.uuid4().hex}.enc"                           # random on-disk name
    (config.UPLOAD_DIR / stored).write_bytes(encrypt_bytes(data))
    doc = models.Document(filename=original, stored_name=stored, owner=user.username, access_level=access_level)
    db.add(doc)
    db.commit()
    db.refresh(doc)
    doc.chunk_count = rag.index_document(doc.id, original, access_level, text)
    db.commit()
    note = (" sensitive: " + ", ".join(findings)) if findings else ""
    auth.audit(db, user.username, "auto_protect" if auto_protected else "upload", f"{original} [{access_level}]{note}")
    return {"id": doc.id, "filename": original, "access_level": access_level, "chunks_indexed": doc.chunk_count,
            "findings": findings, "auto_protected": auto_protected}


@router.get("/")
def list_documents(user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    q = db.query(models.Document)
    if user.role != "admin":
        conds = [models.Document.access_level == "standard"]
        if user.department:
            conds.append(models.Document.access_level == f"dept:{user.department}")
        q = q.filter(or_(*conds))
    return [{"id": d.id, "filename": d.filename, "access_level": d.access_level, "owner": d.owner,
             "chunks": d.chunk_count, "uploaded_at": d.uploaded_at.isoformat() if d.uploaded_at else None}
            for d in q.order_by(models.Document.id.desc())]


@router.get("/status")
def system_status(admin=Depends(auth.require_admin), db: Session = Depends(auth.get_db)):
    docs = db.query(models.Document).all()
    return {"ai_mode": config.LLM_PROVIDER.capitalize(),
            "model": config.LLM_MODEL,
            "documents": len(docs), "confidential": sum(1 for x in docs if x.access_level != "standard"),
            "users": db.query(models.User).count(),
            "blocked_attempts": db.query(models.AuditLog).filter_by(action="access_denied").count()}


@router.put("/{doc_id}/access")
def change_access(doc_id: int, body: AccessIn, admin=Depends(auth.require_admin), db: Session = Depends(auth.get_db)):
    if not config.valid_access(body.access_level):
        raise HTTPException(400, "Invalid access level")
    doc = db.get(models.Document, doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    doc.access_level = body.access_level
    db.commit()
    rag.set_access(doc.id, body.access_level)       # searchable text follows the same rule
    auth.audit(db, admin.username, "access_change", f"{doc.filename} -> {body.access_level}")
    return {"message": f"{doc.filename} is now '{body.access_level}'"}


@router.delete("/{doc_id}")
def delete_document(doc_id: int, admin=Depends(auth.require_admin), db: Session = Depends(auth.get_db)):
    doc = db.get(models.Document, doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    rag.delete_document(doc.id)
    path = config.UPLOAD_DIR / doc.stored_name
    if path.exists():
        path.unlink()
    name = doc.filename
    db.delete(doc)
    db.commit()
    auth.audit(db, admin.username, "delete", name)
    return {"message": f"Deleted {name}"}


@router.post("/chat")
def chat(req: ChatQuery, user: models.User = Depends(auth.get_current_user), db: Session = Depends(auth.get_db)):
    result = rag.answer_question(req.query, user.role, req.doc_id, user.department)
    if result.pop("blocked", False):
        auth.audit(db, user.username, "access_denied", req.query)
    scope = f" [file #{req.doc_id}]" if req.doc_id is not None else ""
    auth.audit(db, user.username, "chat", f"{req.query}{scope} -> {len(result['sources'])} source(s)")
    return {**result, "user": user.username}


@router.get("/audit")
def audit_log(limit: int = 50, action: Optional[str] = None, admin=Depends(auth.require_admin),
              db: Session = Depends(auth.get_db)):
    q = db.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action == action)
    rows = q.order_by(models.AuditLog.id.desc()).limit(min(limit, 200)).all()
    return [{"time": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "",
             "user": r.username, "action": r.action, "detail": r.detail} for r in rows]


def _csv_safe(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s   # stop spreadsheet formula injection


@router.get("/audit/export")
def export_audit(admin=Depends(auth.require_admin), db: Session = Depends(auth.get_db)):
    rows = db.query(models.AuditLog).order_by(models.AuditLog.id).limit(50000).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time_utc", "user", "action", "detail"])
    for r in rows:
        w.writerow([_csv_safe(r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else ""),
                    _csv_safe(r.username), _csv_safe(r.action), _csv_safe(r.detail)])
    auth.audit(db, admin.username, "audit_export", f"{len(rows)} rows")
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="vaultmind_audit.csv"'})
