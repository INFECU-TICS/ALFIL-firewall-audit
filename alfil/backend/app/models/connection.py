from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base


class ConnectionConfig(Base):
    """Model for storing Sophos Firewall connection configurations"""
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, default=4444)
    username = Column(String(100), nullable=False)
    password_encrypted = Column(Text, nullable=False)
    verify_ssl = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<ConnectionConfig(name='{self.name}', host='{self.host}')>"
