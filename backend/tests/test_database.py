"""
Tests for database setup and models.
Following TDD methodology - these tests should pass after database setup.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, get_db
from app.models import RequestLog, PolicyRule, AdminUser, AuditLog, RiskType, Severity, Decision
from datetime import datetime


@pytest.fixture
def db_session():
    """Create a test database session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_database_connection():
    """Test that database connection can be established."""
    from app.database import engine
    assert engine is not None


def test_request_log_model(db_session):
    """Test RequestLog model creation and retrieval."""
    log = RequestLog(
        request_id="test-123",
        original_prompt="Test prompt",
        modified_prompt="Test prompt",
        decision=Decision.ALLOW,
        risks=[]
    )
    db_session.add(log)
    db_session.commit()
    
    retrieved = db_session.query(RequestLog).filter_by(request_id="test-123").first()
    assert retrieved is not None
    assert retrieved.original_prompt == "Test prompt"
    assert retrieved.decision == Decision.ALLOW


def test_policy_rule_model(db_session):
    """Test PolicyRule model creation and retrieval."""
    rule = PolicyRule(
        name="test-rule",
        description="Test rule",
        risk_type=RiskType.PII,
        pattern=".*@.*",
        pattern_type="regex",
        severity=Severity.HIGH,
        action=Decision.BLOCK,
        enabled=True
    )
    db_session.add(rule)
    db_session.commit()
    
    retrieved = db_session.query(PolicyRule).filter_by(name="test-rule").first()
    assert retrieved is not None
    assert retrieved.risk_type == RiskType.PII
    assert retrieved.enabled is True


def test_admin_user_model(db_session):
    """Test AdminUser model creation and retrieval."""
    user = AdminUser(
        username="testuser",
        email="test@example.com",
        hashed_password="hashed_password_here",
        is_active=True,
        is_superuser=False
    )
    db_session.add(user)
    db_session.commit()
    
    retrieved = db_session.query(AdminUser).filter_by(username="testuser").first()
    assert retrieved is not None
    assert retrieved.email == "test@example.com"
    assert retrieved.is_active is True


def test_audit_log_model(db_session):
    """Test AuditLog model creation and retrieval."""
    audit = AuditLog(
        admin_user_id=1,
        action="CREATE",
        resource_type="policy_rule",
        resource_id=1,
        details={"key": "value"}
    )
    db_session.add(audit)
    db_session.commit()
    
    retrieved = db_session.query(AuditLog).filter_by(admin_user_id=1).first()
    assert retrieved is not None
    assert retrieved.action == "CREATE"
    assert retrieved.details == {"key": "value"}


def test_get_db_generator():
    """Test that get_db returns a generator."""
    db_gen = get_db()
    assert hasattr(db_gen, "__iter__")
    assert hasattr(db_gen, "__next__")

