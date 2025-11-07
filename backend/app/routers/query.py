"""
Query endpoint router.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas import QueryRequest, QueryResponse
from app.firewall.firewall_core import FirewallCore
from app.database import get_db
from app.models import RequestLog, Decision
import json

router = APIRouter()

firewall = FirewallCore()


@router.post("/v1/query", response_model=QueryResponse)
async def process_query(
    request: QueryRequest,
    db: Session = Depends(get_db)
):
    """
    Process a prompt and/or response through the firewall.
    
    - **prompt**: User's input prompt (optional)
    - **response**: Model's response (optional)
    
    Returns firewall decision, modified text, detected risks, and explanation.
    """
    if not request.prompt and not request.response:
        raise HTTPException(
            status_code=400,
            detail="At least one of 'prompt' or 'response' must be provided"
        )
    
    result = firewall.process(
        prompt=request.prompt,
        response=request.response
    )
    
    request_log = RequestLog(
        request_id=result["metadata"]["requestId"],
        original_prompt=request.prompt or "",
        modified_prompt=result["promptModified"],
        original_response=request.response,
        modified_response=result.get("responseModified"),
        decision=Decision(result["decision"]),
        risks=result["risks"],
        request_metadata=result["metadata"]
    )
    
    try:
        db.add(request_log)
        db.commit()
    except Exception as e:
        db.rollback()
        # Log error but don't fail the request
    
    return QueryResponse(**result)

