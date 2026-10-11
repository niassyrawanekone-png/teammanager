"""Run the shared initializer, including the single-super-admin constraint.

Back up the existing database before running this migration. It fails closed
if the existing data contains more than one super-admin account.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


if __name__ == "__main__":
    database.initialize_database()
    print("Migration 0003_single_super_admin applied (or already present).")
