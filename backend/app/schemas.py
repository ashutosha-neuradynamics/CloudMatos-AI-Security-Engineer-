"""
Pydantic schemas for request/response validation.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any


class QueryRequest(BaseModel):
    """Request schema for /v1/query endpoint."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "prompt": "What is the capital of France?",
                "response": "The capital of France is Paris."
            }
        }
    )
    
    prompt: Optional[str] = Field(None, description="User's prompt")
    response: Optional[str] = Field(None, description="Model's response")


class RiskSchema(BaseModel):
    """Schema for risk information."""
    type: str = Field(..., description="Type of risk (PII, PHI, PROMPT_INJECTION, etc.)")
    severity: str = Field(..., description="Severity level (high, medium, low)")
    match: str = Field(..., description="The matched text")
    position: Dict[str, int] = Field(..., description="Start and end positions")
    explanation: str = Field(..., description="Explanation of the risk")


class QueryResponse(BaseModel):
    """Response schema for /v1/query endpoint."""
    decision: str = Field(..., description="Firewall decision (block, redact, warn, allow)")
    promptModified: Optional[str] = Field(None, description="Modified prompt (if redacted/blocked)")
    responseModified: Optional[str] = Field(None, description="Modified response (if redacted/blocked)")
    risks: List[RiskSchema] = Field(..., description="List of detected risks")
    explanation: str = Field(..., description="Human-readable explanation")
    metadata: Dict[str, Any] = Field(..., description="Request metadata (requestId, timestamp)")


class PolicyRuleSchema(BaseModel):
    """Schema for policy rule."""
    id: Optional[int] = None
    name: str
    description: Optional[str] = None
    risk_type: str
    pattern: str
    pattern_type: str
    severity: str
    action: str
    enabled: bool = True


class PolicyResponse(BaseModel):
    """Response schema for policy endpoints."""
    rules: List[PolicyRuleSchema]


class LogFilterSchema(BaseModel):
    """Schema for log filtering."""
    type: Optional[str] = None
    severity: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    limit: int = Field(50, ge=1, le=1000)
    offset: int = Field(0, ge=0)

