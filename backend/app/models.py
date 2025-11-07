"""
Database models for the Prompt Firewall application.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, JSON, Boolean
from sqlalchemy.sql import func
from app.database import Base
import enum


class RiskType(str, enum.Enum):
    """Types of security risks."""
    PII = "PII"
    PHI = "PHI"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    OTHER = "OTHER"


class Severity(str, enum.Enum):
    """Severity levels for risks."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Decision(str, enum.Enum):
    """Firewall decision actions."""
    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"
    ALLOW = "allow"


class RequestLog(Base):
    """Log of all requests processed by the firewall."""
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String, unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    original_prompt = Column(Text, nullable=False)
    modified_prompt = Column(Text, nullable=True)
    
    original_response = Column(Text, nullable=True)
    modified_response = Column(Text, nullable=True)
    
    decision = Column(Enum(Decision), nullable=False)
    
    risks = Column(JSON, nullable=False)
    
    request_metadata = Column(JSON, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class PolicyRule(Base):
    """Policy rules for the firewall."""
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    
    risk_type = Column(Enum(RiskType), nullable=False)
    pattern = Column(String, nullable=False)
    pattern_type = Column(String, nullable=False)
    
    severity = Column(Enum(Severity), nullable=False)
    action = Column(Enum(Decision), nullable=False)
    
    enabled = Column(Boolean, default=True, nullable=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class AdminUser(Base):
    """Admin users for the admin console."""
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class AuditLog(Base):
    """Audit trail for admin actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_user_id = Column(Integer, nullable=False)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(Integer, nullable=True)
    
    details = Column(JSON, nullable=True)
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

