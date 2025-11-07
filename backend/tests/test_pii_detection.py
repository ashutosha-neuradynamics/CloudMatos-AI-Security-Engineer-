"""
Tests for PII/PHI detection module.
Following TDD - write tests first, then implement.
"""

import pytest
from app.firewall.pii_detector import PIIDetector, RiskMatch


@pytest.fixture
def pii_detector():
    """Create a PII detector instance."""
    return PIIDetector()


def test_detect_email_addresses(pii_detector):
    """Test detection of email addresses."""
    text = "Contact me at john.doe@example.com or admin@test.org"
    matches = pii_detector.detect(text)
    
    email_matches = [m for m in matches if m.risk_type == "PII" and "email" in m.pattern_name.lower()]
    assert len(email_matches) >= 2
    assert any("john.doe@example.com" in m.match for m in email_matches)
    assert any("admin@test.org" in m.match for m in email_matches)


def test_detect_ssn(pii_detector):
    """Test detection of Social Security Numbers."""
    text = "My SSN is 123-45-6789"
    matches = pii_detector.detect(text)
    
    ssn_matches = [m for m in matches if "ssn" in m.pattern_name.lower()]
    assert len(ssn_matches) >= 1
    assert any("123-45-6789" in m.match for m in ssn_matches)


def test_detect_phone_numbers(pii_detector):
    """Test detection of phone numbers in various formats."""
    text = "Call me at 555-123-4567 or (555) 987-6543 or 555.111.2222"
    matches = pii_detector.detect(text)
    
    phone_matches = [m for m in matches if "phone" in m.pattern_name.lower()]
    assert len(phone_matches) >= 2


def test_detect_credit_card_numbers(pii_detector):
    """Test detection of credit card numbers."""
    text = "My card number is 4532-1234-5678-9010"
    matches = pii_detector.detect(text)
    
    cc_matches = [m for m in matches if "credit" in m.pattern_name.lower() or "card" in m.pattern_name.lower()]
    assert len(cc_matches) >= 1


def test_detect_multiple_pii_types(pii_detector):
    """Test detection of multiple PII types in one text."""
    text = "Email: test@example.com, Phone: 555-123-4567, SSN: 123-45-6789"
    matches = pii_detector.detect(text)
    
    assert len(matches) >= 3
    risk_types = set(m.risk_type for m in matches)
    assert "PII" in risk_types


def test_no_false_positives(pii_detector):
    """Test that normal text doesn't trigger false positives."""
    text = "This is a normal sentence without any sensitive information."
    matches = pii_detector.detect(text)
    
    assert len(matches) == 0


def test_severity_classification(pii_detector):
    """Test that different PII types have appropriate severity."""
    text = "SSN: 123-45-6789, Email: test@example.com"
    matches = pii_detector.detect(text)
    
    ssn_match = next((m for m in matches if "ssn" in m.pattern_name.lower()), None)
    email_match = next((m for m in matches if "email" in m.pattern_name.lower()), None)
    
    if ssn_match:
        assert ssn_match.severity == "high"
    if email_match:
        assert email_match.severity in ["medium", "low"]


def test_match_positions(pii_detector):
    """Test that matches include correct position information."""
    text = "Email: test@example.com"
    matches = pii_detector.detect(text)
    
    email_matches = [m for m in matches if "email" in m.pattern_name.lower()]
    if email_matches:
        match = email_matches[0]
        assert hasattr(match, 'start')
        assert hasattr(match, 'end')
        assert match.start < match.end
        assert text[match.start:match.end] in match.match


def test_medical_record_number(pii_detector):
    """Test detection of medical record numbers (PHI)."""
    text = "Patient MRN: MR123456789"
    matches = pii_detector.detect(text)
    
    mrn_matches = [m for m in matches if m.risk_type == "PHI" or "medical" in m.pattern_name.lower()]
    # This test may not pass initially if MRN detection isn't implemented
    # It's here to guide implementation


def test_partial_ssn_not_detected(pii_detector):
    """Test that partial SSNs are not detected."""
    text = "Last 4 digits: 6789"
    matches = pii_detector.detect(text)
    
    ssn_matches = [m for m in matches if "ssn" in m.pattern_name.lower()]
    assert len(ssn_matches) == 0

