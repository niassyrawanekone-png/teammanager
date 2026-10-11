"""Apply the additive, repeatable 0001 workspace migration.

Run from the backend directory with the backend virtual environment:
    python migrations/001_workspaces.py
Back up the SQLite database before running this command.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


if __name__ == "__main__":
    database.initialize_database()
    print("Migration 0001_workspaces applied (or already present).")
