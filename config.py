"""Central settings. Secrets come from environment variables or a local .env file, never from code."""
import os
import secrets
from pathlib import Path
from cryptography.fernet import Fernet


def _load_env(path=".env"):
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v[:1] in ("'", '"') and v.count(v[0]) >= 2:
            v = v[1:v.index(v[0], 1)]                 # quoted value: take what is inside the quotes
        else:
            v = v.split(" #", 1)[0].strip()           # unquoted: drop a trailing " # comment"
        os.environ.setdefault(k.strip(), v)


_load_env()

DATA_DIR = Path(os.environ.get("VAULT_DATA_DIR", "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "vaultmind.db"
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _persisted(env_name: str, filename: str, make) -> str:
    """Use the env var if set, otherwise generate once and keep it in a private file."""
    value = os.environ.get(env_name)
    if value:
        return value
    f = DATA_DIR / filename
    if not f.exists():
        f.write_text(make(), encoding="utf-8")
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    return f.read_text(encoding="utf-8").strip()


SECRET_KEY = _persisted("JWT_SECRET", ".jwt_secret", lambda: secrets.token_urlsafe(48))
VAULT_KEY = _persisted("VAULT_KEY", ".vault_key", lambda: Fernet.generate_key().decode())

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")   # verify with find_models.py
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")      # verify with find_models.py
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", os.environ.get("GEMINI_TIMEOUT", "45")))  # seconds to wait for the AI

# Which AI writes the answers: "groq", "gemini" or "offline". Empty LLM_PROVIDER = pick from the keys that are set.
_p = os.environ.get("LLM_PROVIDER", "").strip().lower()
if _p not in ("groq", "gemini", "offline"):
    _p = "groq" if GROQ_API_KEY else "gemini" if GOOGLE_API_KEY else "offline"
if (_p == "groq" and not GROQ_API_KEY) or (_p == "gemini" and not GOOGLE_API_KEY):
    _p = "offline"                                   # chosen provider has no key
LLM_PROVIDER = _p
LLM_MODEL = {"groq": GROQ_MODEL, "gemini": GEMINI_MODEL}.get(_p, "-")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

ACCESS_TOKEN_EXPIRE_MINUTES = 30
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".txt", ".md", ".csv", ".pdf", ".docx"}
ROLES = ("standard", "admin")
DEPARTMENTS = [d.strip() for d in os.environ.get("DEPARTMENTS", "HR,Finance,Engineering").split(",") if d.strip()]


def valid_access(level: str) -> bool:
    """Document access: 'standard' (everyone), 'admin' (admins only) or 'dept:<Name>' (that department + admins)."""
    return level in ROLES or (level.startswith("dept:") and level[5:] in DEPARTMENTS)
