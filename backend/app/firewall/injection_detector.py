"""
Prompt Injection Detection Module

Detects prompt injection and jailbreak attempts using pattern matching
and heuristics.
"""

import re
from dataclasses import dataclass
from typing import List
from enum import Enum


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


class InjectionDetector:
    """Detects prompt injection and jailbreak attempts."""
    
    def __init__(self):
        """Initialize injection detector with pattern definitions."""
        self.patterns = [
            {
                "name": "ignore_previous_instructions",
                "risk_type": "PROMPT_INJECTION",
                "pattern": r"(?i)(ignore|forget|disregard|override).*(previous|prior|earlier|above|before).*(instruction|directive|command|rule|guideline|prompt)",
                "severity": Severity.HIGH,
                "explanation": "Attempt to ignore previous instructions detected"
            },
            {
                "name": "role_playing_jailbreak",
                "risk_type": "PROMPT_INJECTION",
                "pattern": r"(?i)(you are now|pretend to be|act as|roleplay as|you become|you're now).*(different|new|unrestricted|unlimited|free|no restrictions|no limits|no rules|helpful assistant)",
                "severity": Severity.HIGH,
                "explanation": "Role-playing jailbreak attempt detected"
            },
            {
                "name": "system_prompt_extraction",
                "risk_type": "PROMPT_INJECTION",
                "pattern": r"(?i)(show|reveal|display|tell|give|provide|share|output|print).*(system|original|initial|starting|base).*(prompt|instruction|directive|command|guideline)",
                "severity": Severity.HIGH,
                "explanation": "System prompt extraction attempt detected"
            },
            {
                "name": "instruction_override",
                "risk_type": "PROMPT_INJECTION",
                "pattern": r"(?i)(new|updated|different|override|replace).*(instruction|directive|command|rule|guideline|prompt)",
                "severity": Severity.HIGH,
                "explanation": "Instruction override attempt detected"
            },
            {
                "name": "bypass_attempt",
                "risk_type": "PROMPT_INJECTION",
                "pattern": r"(?i)(bypass|circumvent|avoid|skip|ignore).*(safety|security|restriction|limit|guideline|rule|filter)",
                "severity": Severity.HIGH,
                "explanation": "Safety bypass attempt detected"
            },
            {
                "name": "encoding_obfuscation",
                "risk_type": "PROMPT_INJECTION",
                "pattern": r"(?i)(decode|decrypt|unscramble|interpret).*(this|the following|below).*([0-9a-f]{16,}|[A-Z0-9+/=]{20,})",
                "severity": Severity.MEDIUM,
                "explanation": "Possible encoding/obfuscation attempt detected"
            }
        ]
    
    def detect(self, text: str) -> List[RiskMatch]:
        """
        Detect prompt injection attempts in the given text.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of RiskMatch objects representing detected risks
        """
        matches = []
        
        for pattern_def in self.patterns:
            regex = re.compile(pattern_def["pattern"], re.IGNORECASE | re.DOTALL)
            
            for match in regex.finditer(text):
                risk_match = RiskMatch(
                    risk_type=pattern_def["risk_type"],
                    pattern_name=pattern_def["name"],
                    match=match.group(),
                    start=match.start(),
                    end=match.end(),
                    severity=pattern_def["severity"].value,
                    explanation=pattern_def["explanation"]
                )
                matches.append(risk_match)
        
        return matches

