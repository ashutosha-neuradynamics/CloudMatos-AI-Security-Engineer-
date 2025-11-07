"""
Tests for FastAPI application setup.
Following TDD - write tests first, then implement.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


def test_health_check_endpoint(client):
    """Test that health check endpoint exists and works."""
    response = client.get("/v1/health")
    
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "healthy"


def test_cors_headers(client):
    """Test that CORS headers are configured."""
    response = client.get(
        "/v1/health",
        headers={"Origin": "http://localhost:3000"}
    )
    
    assert response.status_code == 200
    # Check for CORS headers (case-insensitive)
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    assert "access-control-allow-origin" in headers_lower


def test_api_documentation_accessible(client):
    """Test that OpenAPI/Swagger documentation is accessible."""
    response = client.get("/docs")
    
    assert response.status_code == 200


def test_openapi_schema_accessible(client):
    """Test that OpenAPI schema is accessible."""
    response = client.get("/openapi.json")
    
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert "info" in data
    assert "paths" in data


def test_error_handling(client):
    """Test that error handling works."""
    response = client.get("/v1/nonexistent")
    
    assert response.status_code == 404


def test_json_response_format(client):
    """Test that responses are in JSON format."""
    response = client.get("/v1/health")
    
    assert response.headers["content-type"] == "application/json"

