from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.types import JSON
from sqlalchemy.sql import func
from app.database import Base


class AuditReport(Base):
    __tablename__ = "audit_reports"

    id = Column(Integer, primary_key=True, index=True)
    connection_id = Column(
        Integer,
        ForeignKey("connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Número de auditoría dentro de su conexión (1, 2, 3…). `id` es global a todas las conexiones.
    seq = Column(Integer, nullable=True)
    status = Column(String(20), default="running", nullable=False)  # running | completed | failed
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    summary = Column(JSON, nullable=True)   # {score, critical, warning, info, total_issues}
    report = Column(JSON, nullable=True)    # reporte completo (sections + issues)
    error = Column(Text, nullable=True)
