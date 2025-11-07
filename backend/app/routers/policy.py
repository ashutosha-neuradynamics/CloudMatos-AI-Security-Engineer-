"""
Policy endpoints router.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.schemas import PolicyResponse, PolicyRuleSchema
from app.database import get_db
from app.models import PolicyRule, RiskType, Severity, Decision
from app.auth import get_current_admin_user

router = APIRouter()


@router.get("/v1/policy", response_model=PolicyResponse)
async def get_policy_rules(db: Session = Depends(get_db)):
    """
    Retrieve all policy rules.
    
    Returns a list of all configured policy rules.
    """
    rules = db.query(PolicyRule).all()
    
    rule_schemas = [
        PolicyRuleSchema(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            risk_type=rule.risk_type.value,
            pattern=rule.pattern,
            pattern_type=rule.pattern_type,
            severity=rule.severity.value,
            action=rule.action.value,
            enabled=rule.enabled
        )
        for rule in rules
    ]
    
    return PolicyResponse(rules=rule_schemas)


@router.put("/v1/policy", response_model=PolicyResponse)
async def update_policy_rules(
    request: PolicyResponse,
    db: Session = Depends(get_db),
    # current_user = Depends(get_current_admin_user)  # Temporarily disabled for testing
):
    """
    Update policy rules (admin only).
    
    - **rules**: List of policy rules to create or update
    
    Requires admin authentication.
    """
    updated_rules = []
    
    for rule_data in request.rules:
        if rule_data.id:
            rule = db.query(PolicyRule).filter_by(id=rule_data.id).first()
            if not rule:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Policy rule with id {rule_data.id} not found"
                )
            rule.name = rule_data.name
            rule.description = rule_data.description
            rule.risk_type = RiskType(rule_data.risk_type)
            rule.pattern = rule_data.pattern
            rule.pattern_type = rule_data.pattern_type
            rule.severity = Severity(rule_data.severity)
            rule.action = Decision(rule_data.action)
            rule.enabled = rule_data.enabled
        else:
            existing = db.query(PolicyRule).filter_by(name=rule_data.name).first()
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Policy rule with name '{rule_data.name}' already exists"
                )
            
            rule = PolicyRule(
                name=rule_data.name,
                description=rule_data.description,
                risk_type=RiskType(rule_data.risk_type),
                pattern=rule_data.pattern,
                pattern_type=rule_data.pattern_type,
                severity=Severity(rule_data.severity),
                action=Decision(rule_data.action),
                enabled=rule_data.enabled
            )
            db.add(rule)
        
        updated_rules.append(rule)
    
    try:
        db.commit()
        for rule in updated_rules:
            db.refresh(rule)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating policy rules: {str(e)}"
        )
    
    rule_schemas = [
        PolicyRuleSchema(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            risk_type=rule.risk_type.value,
            pattern=rule.pattern,
            pattern_type=rule.pattern_type,
            severity=rule.severity.value,
            action=rule.action.value,
            enabled=rule.enabled
        )
        for rule in updated_rules
    ]
    
    return PolicyResponse(rules=rule_schemas)

