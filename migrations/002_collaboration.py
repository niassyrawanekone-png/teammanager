"""Run the shared additive collaboration schema initializer and migrations.

Run from the backend directory after taking a verified database backup:
    python migrations/002_collaboration.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


if __name__ == "__main__":
    database.initialize_database()
    print("Collaboration migrations applied (or already present).")
