"""
PII/PHI Detection Module

Detects personally identifiable information and protected health information
in text using pattern matching.
"""

import re
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum


class RiskType(str, Enum):
    """Types of security risks."""
    PII = "PII"
    PHI = "PHI"


class Severity(str, Enum):
    """Severity levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RiskMatch:
    """Represents a detected risk match."""
    risk_type: str
    pattern_name: str
    match: str
    start: int
    end: int
    severity: str
    explanation: str


class PIIDetector:
    """Detects PII/PHI in text using pattern matching."""
    
    def __init__(self):
        """Initialize PII detector with pattern definitions."""
        self.patterns = [
            {
                "name": "email",
                "risk_type": RiskType.PII,
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "severity": Severity.MEDIUM,
                "explanation": "Email address detected"
            },
            {
                "name": "ssn",
                "risk_type": RiskType.PII,
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "severity": Severity.HIGH,
                "explanation": "Social Security Number detected"
            },
            {
                "name": "phone",
                "risk_type": RiskType.PII,
                "pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b|\(\d{3}\)\s?\d{3}[-.]?\d{4}",
                "severity": Severity.MEDIUM,
                "explanation": "Phone number detected"
            },
            {
                "name": "credit_card",
                "risk_type": RiskType.PII,
                "pattern": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
                "severity": Severity.HIGH,
                "explanation": "Credit card number detected"
            },
            {
                "name": "medical_record_number",
                "risk_type": RiskType.PHI,
                "pattern": r"\bMR[N]?[-]?\d{6,}\b",
                "severity": Severity.HIGH,
                "explanation": "Medical record number detected"
            }
        ]
    
    def detect(self, text: str) -> List[RiskMatch]:
        """
        Detect PII/PHI in the given text.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of RiskMatch objects representing detected risks
        """
        matches = []
        
        for pattern_def in self.patterns:
            regex = re.compile(pattern_def["pattern"], re.IGNORECASE)
            
            for match in regex.finditer(text):
                risk_match = RiskMatch(
                    risk_type=pattern_def["risk_type"].value,
                    pattern_name=pattern_def["name"],
                    match=match.group(),
                    start=match.start(),
                    end=match.end(),
                    severity=pattern_def["severity"].value,
                    explanation=pattern_def["explanation"]
                )
                matches.append(risk_match)
        
        return matches

