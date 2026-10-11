"""Run the shared additive, repeatable workspace initializer.

Run from the backend directory with the backend virtual environment:
    python migrations/001_workspaces.py
Back up the configured SQLite or PostgreSQL database before running this command.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


if __name__ == "__main__":
    database.initialize_database()
    print("Migration 0001_workspaces applied (or already present).")
