"""
Firewall Core

Main integration point for the Prompt Firewall.
Combines PII detection, injection detection, and policy engine.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from app.firewall.pii_detector import PIIDetector
from app.firewall.injection_detector import InjectionDetector
from app.firewall.policy_engine import PolicyEngine, Decision
from app.models import PolicyRule


class FirewallCore:
    """Main firewall core that processes prompts and responses."""
    
    def __init__(self):
        """Initialize firewall core with detectors and policy engine."""
        self.pii_detector = PIIDetector()
        self.injection_detector = InjectionDetector()
        self.policy_engine = PolicyEngine()
    
    def process(
        self,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        policy_rules: Optional[List[PolicyRule]] = None
    ) -> Dict[str, Any]:
        """
        Process prompt and/or response through the firewall.
        
        Args:
            prompt: The user's prompt (optional)
            response: The model's response (optional)
            policy_rules: Optional custom policy rules
            
        Returns:
            Dictionary with decision, modified text, risks, and metadata
        """
        request_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        prompt_risks = []
        response_risks = []
        
        if prompt:
            prompt_pii_risks = self.pii_detector.detect(prompt)
            prompt_injection_risks = self.injection_detector.detect(prompt)
            prompt_risks = prompt_pii_risks + prompt_injection_risks
        
        if response:
            response_pii_risks = self.pii_detector.detect(response)
            response_injection_risks = self.injection_detector.detect(response)
            response_risks = response_pii_risks + response_injection_risks
        
        all_risks = prompt_risks + response_risks
        
        decision = self.policy_engine.determine_action(
            prompt_risks,
            response_risks,
            policy_rules
        )
        
        prompt_modified = prompt
        response_modified = response
        
        if decision == Decision.REDACT:
            if prompt and prompt_risks:
                prompt_modified = self.policy_engine.redact_text(prompt, prompt_risks)
            if response and response_risks:
                response_modified = self.policy_engine.redact_text(response, response_risks)
        elif decision == Decision.BLOCK:
            if prompt:
                prompt_modified = "[BLOCKED]"
            if response:
                response_modified = "[BLOCKED]"
        
        risks_list = [
            {
                "type": risk.risk_type,
                "severity": risk.severity,
                "match": risk.match,
                "position": {"start": risk.start, "end": risk.end},
                "explanation": risk.explanation
            }
            for risk in all_risks
        ]
        
        explanation = self.policy_engine.generate_explanation(all_risks)
        
        result = {
            "decision": decision.value,
            "promptModified": prompt_modified,
            "responseModified": response_modified if response else None,
            "risks": risks_list,
            "explanation": explanation,
            "metadata": {
                "timestamp": timestamp,
                "requestId": request_id
            }
        }
        
        return result

