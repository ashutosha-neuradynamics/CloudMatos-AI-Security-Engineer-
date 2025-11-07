"""
Database initialization script.
Creates initial admin user and default policy rules.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SessionLocal, engine, Base
from app.models import AdminUser, PolicyRule, RiskType, Severity, Decision
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def init_db():
    """Initialize database with tables, admin user, and default rules."""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Create default admin user if it doesn't exist
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
        admin_password = os.getenv("ADMIN_PASSWORD", "change-me-in-production")
        
        existing_admin = db.query(AdminUser).filter_by(username=admin_username).first()
        if not existing_admin:
            hashed_password = pwd_context.hash(admin_password)
            admin_user = AdminUser(
                username=admin_username,
                email=admin_email,
                hashed_password=hashed_password,
                is_active=True,
                is_superuser=True
            )
            db.add(admin_user)
            print(f"Created admin user: {admin_username}")
        else:
            print(f"Admin user {admin_username} already exists")
        
        # Create default policy rules
        default_rules = [
            {
                "name": "email-detection",
                "description": "Detect email addresses",
                "risk_type": RiskType.PII,
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "pattern_type": "regex",
                "severity": Severity.MEDIUM,
                "action": Decision.REDACT,
                "enabled": True
            },
            {
                "name": "ssn-detection",
                "description": "Detect Social Security Numbers",
                "risk_type": RiskType.PII,
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "pattern_type": "regex",
                "severity": Severity.HIGH,
                "action": Decision.REDACT,
                "enabled": True
            },
            {
                "name": "phone-detection",
                "description": "Detect phone numbers",
                "risk_type": RiskType.PII,
                "pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
                "pattern_type": "regex",
                "severity": Severity.MEDIUM,
                "action": Decision.REDACT,
                "enabled": True
            },
            {
                "name": "jailbreak-pattern-1",
                "description": "Detect common jailbreak pattern",
                "risk_type": RiskType.PROMPT_INJECTION,
                "pattern": r"(?i)(ignore|forget|disregard).*(previous|prior|earlier|above).*(instruction|directive|command)",
                "pattern_type": "regex",
                "severity": Severity.HIGH,
                "action": Decision.BLOCK,
                "enabled": True
            },
            {
                "name": "jailbreak-pattern-2",
                "description": "Detect role-playing jailbreak",
                "risk_type": RiskType.PROMPT_INJECTION,
                "pattern": r"(?i)(you are now|pretend to be|act as|roleplay as)",
                "pattern_type": "regex",
                "severity": Severity.HIGH,
                "action": Decision.BLOCK,
                "enabled": True
            }
        ]
        
        for rule_data in default_rules:
            existing_rule = db.query(PolicyRule).filter_by(name=rule_data["name"]).first()
            if not existing_rule:
                rule = PolicyRule(**rule_data)
                db.add(rule)
                print(f"Created policy rule: {rule_data['name']}")
            else:
                print(f"Policy rule {rule_data['name']} already exists")
        
        db.commit()
        print("Database initialization complete!")
        
    except Exception as e:
        db.rollback()
        print(f"Error initializing database: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    init_db()

