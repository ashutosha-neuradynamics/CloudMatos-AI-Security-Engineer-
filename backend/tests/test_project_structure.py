"""
Test to verify project structure is set up correctly.
This is the first test following TDD methodology.
"""

import os
import sys
from pathlib import Path


def test_project_structure_exists():
    """Verify all required directories exist."""
    base_path = Path(__file__).parent.parent.parent
    
    required_dirs = [
        "backend",
        "backend/app",
        "backend/tests",
        "frontend",
        "sdk",
        "infrastructure",
        "docs",
    ]
    
    for dir_path in required_dirs:
        full_path = base_path / dir_path
        assert full_path.exists(), f"Directory {dir_path} does not exist"
        assert full_path.is_dir(), f"{dir_path} is not a directory"


def test_requirements_file_exists():
    """Verify requirements.txt exists."""
    base_path = Path(__file__).parent.parent
    requirements_path = base_path / "requirements.txt"
    assert requirements_path.exists(), "requirements.txt does not exist"


def test_gitignore_exists():
    """Verify .gitignore exists."""
    base_path = Path(__file__).parent.parent.parent
    gitignore_path = base_path / ".gitignore"
    assert gitignore_path.exists(), ".gitignore does not exist"


def test_readme_exists():
    """Verify README.md exists."""
    base_path = Path(__file__).parent.parent.parent
    readme_path = base_path / "README.md"
    assert readme_path.exists(), "README.md does not exist"

