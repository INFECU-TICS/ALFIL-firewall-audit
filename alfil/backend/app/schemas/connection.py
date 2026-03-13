from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class ConnectionConfigBase(BaseModel):
    """Base schema for connection configuration"""
    name: str = Field(..., min_length=1, max_length=100, description="Name of the connection")
    host: str = Field(..., min_length=1, max_length=255, description="IP or FQDN of the Sophos Firewall")
    port: int = Field(default=4444, ge=1, le=65535, description="API port (default: 4444)")
    username: str = Field(..., min_length=1, max_length=100, description="API username")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificate")
    is_active: bool = Field(default=True)


class ConnectionConfigCreate(ConnectionConfigBase):
    """Schema for creating a new connection"""
    password: str = Field(..., min_length=1, description="API password (will be encrypted)")


class ConnectionConfigUpdate(BaseModel):
    """Schema for updating an existing connection"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    host: Optional[str] = Field(None, min_length=1, max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)
    username: Optional[str] = Field(None, min_length=1, max_length=100)
    password: Optional[str] = Field(None, min_length=1)
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None


class ConnectionConfigResponse(ConnectionConfigBase):
    """Schema for connection response (excludes password)"""
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ConnectionTestRequest(BaseModel):
    """Schema for testing a connection"""
    host: str
    port: int = 4444
    username: str
    password: str
    verify_ssl: bool = True


class ConnectionTestResponse(BaseModel):
    """Schema for connection test response"""
    success: bool
    message: str
    details: Optional[dict] = None
