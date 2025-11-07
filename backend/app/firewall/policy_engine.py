"""
Policy Engine

Applies policy rules to detected risks and determines actions (block, redact, warn, allow).
"""

from enum import Enum
from typing import List, Optional
from app.firewall.pii_detector import RiskMatch as PIIRiskMatch
from app.firewall.injection_detector import RiskMatch as InjectionRiskMatch
from app.models import PolicyRule, RiskType, Severity, Decision


class Decision(str, Enum):
    """Firewall decision actions."""
    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"
    ALLOW = "allow"


class PolicyEngine:
    """Applies policy rules to determine firewall actions."""
    
    def __init__(self):
        """Initialize policy engine."""
        pass
    
    def determine_action(
        self,
        prompt_risks: List[PIIRiskMatch | InjectionRiskMatch],
        response_risks: List[PIIRiskMatch | InjectionRiskMatch],
        policy_rules: Optional[List[PolicyRule]] = None
    ) -> Decision:
        """
        Determine the action to take based on detected risks.
        
        Args:
            prompt_risks: Risks detected in the prompt
            response_risks: Risks detected in the response
            policy_rules: Optional custom policy rules to apply
            
        Returns:
            Decision enum value
        """
        all_risks = prompt_risks + response_risks
        
        if not all_risks:
            return Decision.ALLOW
        
        if policy_rules:
            return self.apply_policy_rules(all_risks, policy_rules)
        
        highest_severity = self._get_highest_severity(all_risks)
        
        has_injection = any(r.risk_type == "PROMPT_INJECTION" for r in all_risks)
        has_high_pii = any(
            r.risk_type in ["PII", "PHI"] and r.severity == "high"
            for r in all_risks
        )
        
        if has_injection or highest_severity == "high":
            return Decision.BLOCK
        
        if has_high_pii or highest_severity == "medium":
            return Decision.REDACT
        
        if highest_severity == "low":
            return Decision.WARN
        
        return Decision.ALLOW
    
    def apply_policy_rules(
        self,
        risks: List[PIIRiskMatch | InjectionRiskMatch],
        policy_rules: List[PolicyRule]
    ) -> Decision:
        """
        Apply custom policy rules to risks.
        
        Args:
            risks: List of detected risks
            policy_rules: Policy rules to apply
            
        Returns:
            Decision enum value
        """
        if not risks or not policy_rules:
            return self.determine_action(risks, [])
        
        enabled_rules = [r for r in policy_rules if r.enabled]
        if not enabled_rules:
            return self.determine_action(risks, [])
        
        decisions = []
        
        for risk in risks:
            matching_rules = []
            
            for rule in enabled_rules:
                if self._risk_matches_rule(risk, rule):
                    matching_rules.append(rule)
            
            if matching_rules:
                highest_priority_rule = max(
                    matching_rules,
                    key=lambda r: self._severity_priority(r.severity)
                )
                decisions.append(highest_priority_rule.action)
        
        if not decisions:
            return self.determine_action(risks, [])
        
        return self._get_strictest_decision(decisions)
    
    def _risk_matches_rule(
        self,
        risk: PIIRiskMatch | InjectionRiskMatch,
        rule: PolicyRule
    ) -> bool:
        """Check if a risk matches a policy rule."""
        risk_type_map = {
            "PII": RiskType.PII,
            "PHI": RiskType.PHI,
            "PROMPT_INJECTION": RiskType.PROMPT_INJECTION,
        }
        
        rule_risk_type = risk_type_map.get(risk.risk_type)
        if rule_risk_type != rule.risk_type:
            return False
        
        if rule.pattern_type == "regex":
            import re
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE)
                return bool(pattern.search(risk.match))
            except re.error:
                return False
        elif rule.pattern_type == "keyword":
            return rule.pattern.lower() in risk.match.lower()
        
        return False
    
    def _severity_priority(self, severity: Severity) -> int:
        """Get priority value for severity (higher = more severe)."""
        priorities = {
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }
        return priorities.get(severity, 0)
    
    def _get_highest_severity(
        self,
        risks: List[PIIRiskMatch | InjectionRiskMatch]
    ) -> str:
        """Get the highest severity level from risks."""
        if not risks:
            return "low"
        
        severities = [r.severity for r in risks]
        severity_priority = {"high": 3, "medium": 2, "low": 1}
        
        return max(severities, key=lambda s: severity_priority.get(s, 0))
    
    def _get_strictest_decision(self, decisions: List[Decision]) -> Decision:
        """Get the strictest decision from a list."""
        priority = {
            Decision.BLOCK: 4,
            Decision.REDACT: 3,
            Decision.WARN: 2,
            Decision.ALLOW: 1,
        }
        
        return max(decisions, key=lambda d: priority.get(d, 0))
    
    def redact_text(
        self,
        text: str,
        risks: List[PIIRiskMatch | InjectionRiskMatch]
    ) -> str:
        """
        Redact sensitive information from text.
        
        Args:
            text: The text to redact
            risks: List of risks to redact
            
        Returns:
            Redacted text
        """
        if not risks:
            return text
        
        redacted = text
        offset = 0
        
        sorted_risks = sorted(risks, key=lambda r: r.start)
        
        for risk in sorted_risks:
            start = risk.start + offset
            end = risk.end + offset
            
            if start < 0 or end > len(redacted):
                continue
            
            replacement = f"[{risk.pattern_name.upper()}_REDACTED]"
            redacted = redacted[:start] + replacement + redacted[end:]
            offset += len(replacement) - (end - start)
        
        return redacted
    
    def generate_explanation(
        self,
        risks: List[PIIRiskMatch | InjectionRiskMatch]
    ) -> str:
        """
        Generate human-readable explanation for security decisions.
        
        Args:
            risks: List of detected risks
            
        Returns:
            Explanation string
        """
        if not risks:
            return "No security risks detected. Request allowed."
        
        explanations = []
        
        risk_types = {}
        for risk in risks:
            if risk.risk_type not in risk_types:
                risk_types[risk.risk_type] = []
            risk_types[risk.risk_type].append(risk)
        
        for risk_type, type_risks in risk_types.items():
            count = len(type_risks)
            if risk_type == "PROMPT_INJECTION":
                explanations.append(
                    f"Detected {count} prompt injection attempt(s): "
                    f"{', '.join(r.explanation for r in type_risks[:3])}"
                )
            elif risk_type in ["PII", "PHI"]:
                pii_types = set(r.pattern_name for r in type_risks)
                explanations.append(
                    f"Detected {count} {risk_type} item(s): "
                    f"{', '.join(pii_types)}"
                )
        
        return "; ".join(explanations)

