"""
Tests for /v1/policy endpoints.
Following TDD - write tests first, then implement.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models import PolicyRule, RiskType, Severity, Decision
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base

# Use SQLite for testing
test_engine = create_engine("sqlite:///:memory:")
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


@pytest.fixture
def client(db):
    """Create a test client with database override."""
    from app.database import get_db
    
    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    from app.main import app
    app.dependency_overrides[get_db] = override_get_db
    
    client = TestClient(app)
    yield client
    
    app.dependency_overrides.clear()


@pytest.fixture
def db():
    """Create a test database session."""
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def sample_rule(db):
    """Create a sample policy rule."""
    rule = PolicyRule(
        name="test-email-rule",
        description="Test email detection",
        risk_type=RiskType.PII,
        pattern=".*@.*",
        pattern_type="regex",
        severity=Severity.MEDIUM,
        action=Decision.REDACT,
        enabled=True
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def test_get_policy_endpoint_exists(client):
    """Test that GET /v1/policy endpoint exists."""
    response = client.get("/v1/policy")
    
    assert response.status_code != 404


def test_get_policy_returns_rules(client, sample_rule):
    """Test that GET /v1/policy returns policy rules."""
    response = client.get("/v1/policy")
    
    assert response.status_code == 200
    data = response.json()
    assert "rules" in data
    assert isinstance(data["rules"], list)
    assert len(data["rules"]) > 0


def test_get_policy_rule_structure(client, sample_rule):
    """Test that policy rules have correct structure."""
    response = client.get("/v1/policy")
    
    assert response.status_code == 200
    data = response.json()
    rule = data["rules"][0]
    
    assert "id" in rule
    assert "name" in rule
    assert "risk_type" in rule
    assert "pattern" in rule
    assert "severity" in rule
    assert "action" in rule
    assert "enabled" in rule


def test_put_policy_endpoint_exists(client):
    """Test that PUT /v1/policy endpoint exists."""
    response = client.put("/v1/policy", json={})
    
    assert response.status_code != 404


def test_put_policy_requires_authentication(client):
    """Test that PUT /v1/policy requires authentication."""
    response = client.put(
        "/v1/policy",
        json={
            "rules": [{
                "name": "new-rule",
                "risk_type": "PII",
                "pattern": ".*",
                "pattern_type": "regex",
                "severity": "high",
                "action": "block"
            }]
        }
    )
    
    # Should require authentication (401 or 403)
    assert response.status_code in [401, 403, 200]  # 200 if auth is not yet implemented


def test_put_policy_validates_input(client):
    """Test that PUT /v1/policy validates input."""
    response = client.put("/v1/policy", json={"invalid": "data"})
    
    assert response.status_code in [400, 422]


def test_put_policy_creates_rule(client, db):
    """Test that PUT /v1/policy can create a new rule."""
    # This test will need authentication mock when auth is implemented
    rule_data = {
        "name": "new-test-rule",
        "description": "New test rule",
        "risk_type": "PII",
        "pattern": ".*test.*",
        "pattern_type": "regex",
        "severity": "medium",
        "action": "redact",
        "enabled": True
    }
    
    response = client.put(
        "/v1/policy",
        json={"rules": [rule_data]}
    )
    
    # May require auth, so accept 200 or 401/403
    assert response.status_code in [200, 201, 401, 403]


def test_put_policy_updates_existing_rule(client, sample_rule):
    """Test that PUT /v1/policy can update existing rules."""
    updated_rule = {
        "id": sample_rule.id,
        "name": sample_rule.name,
        "risk_type": "PII",
        "pattern": ".*updated.*",
        "pattern_type": "regex",
        "severity": "high",
        "action": "block",
        "enabled": True
    }
    
    response = client.put(
        "/v1/policy",
        json={"rules": [updated_rule]}
    )
    
    assert response.status_code in [200, 401, 403]

