from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
import config

engine = create_engine(f"sqlite:///{config.DB_PATH.resolve().as_posix()}",
                       connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="standard", nullable=False)
    department = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    stored_name = Column(String, unique=True, nullable=False)
    owner = Column(String, nullable=False)
    access_level = Column(String, default="standard", nullable=False)  # "standard" | "admin"
    chunk_count = Column(Integer, default=0)
    uploaded_at = Column(DateTime, default=_now)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=_now, index=True)
    username = Column(String, index=True)
    action = Column(String)   # login, upload, delete, chat, role_change ...
    detail = Column(Text)


def init_db():
    Base.metadata.create_all(bind=engine)
    # light migration so databases created by older builds gain new columns
    from sqlalchemy import text
    with engine.begin() as conn:
        have = {r[1] for r in conn.execute(text("PRAGMA table_info(users)"))}
        if "department" not in have:
            conn.execute(text("ALTER TABLE users ADD COLUMN department VARCHAR"))
