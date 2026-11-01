from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse

import auth
import document
import models


@asynccontextmanager
async def lifespan(app: FastAPI):
    models.init_db()
    with models.SessionLocal() as db:
        auth.bootstrap_admin(db)
    yield


app = FastAPI(title="VaultMind - Secure AI Document Search", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(document.router)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/portal")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/portal", include_in_schema=False)
def portal():
    return FileResponse(Path(__file__).parent / "index.html", headers={"Cache-Control": "no-store"})
