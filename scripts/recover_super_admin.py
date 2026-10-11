"""Rotate the existing owner's password from an authorized server shell.

Never pass the new password as a command-line argument. This utility only
updates a database containing exactly one canonical super-admin account.
"""
import sys
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import database
import security


def recover_super_admin_password(db, password: str):
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Le nouveau mot de passe doit contenir entre 12 et 128 caractères.")
    admins = db.query(database.UtilisateurDB).filter(
        database.UtilisateurDB.role == "SUPER_ADMIN",
    ).all()
    if len(admins) != 1:
        raise RuntimeError("Récupération annulée : la base ne contient pas exactement un super administrateur.")
    owner = admins[0]
    owner.hashed_password = security.hash_password(password)
    owner.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    owner.session_version += 1
    db.commit()


def main():
    password = getpass("Nouveau mot de passe propriétaire : ")
    confirmation = getpass("Confirmez le nouveau mot de passe : ")
    if password != confirmation:
        raise SystemExit("Les mots de passe ne correspondent pas.")
    with database.SessionLocal() as db:
        recover_super_admin_password(db, password)
    print("Mot de passe propriétaire mis à jour. Les sessions précédentes sont révoquées.")


if __name__ == "__main__":
    main()
