from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def ensure_schema() -> None:
    """Migración mínima (sin Alembic): añade columnas nuevas a tablas existentes sin perder datos. Idempotente."""
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    if "connections" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("connections")}
    if "api_type" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE connections ADD COLUMN api_type VARCHAR(10) NOT NULL DEFAULT 'xml'"))
    if "audit_reports" in insp.get_table_names() and "seq" not in {c["name"] for c in insp.get_columns("audit_reports")}:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE audit_reports ADD COLUMN seq INTEGER"))
            counters: dict = {}  # numeración por conexión, en orden de creación
            for rid, cid in conn.execute(text("SELECT id, connection_id FROM audit_reports ORDER BY connection_id, id")).all():
                counters[cid] = counters.get(cid, 0) + 1
                conn.execute(text("UPDATE audit_reports SET seq = :s WHERE id = :i"), {"s": counters[cid], "i": rid})


def get_db():
    """Dependency for getting database sessions"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
