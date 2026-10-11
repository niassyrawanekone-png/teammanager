import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

import database


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except (ValueError, TypeError):
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret or len(secret) < 32:
        raise RuntimeError("JWT_SECRET_KEY doit être configurée avec au moins 32 caractères.")
    now = datetime.now(timezone.utc)
    payload = data.copy()
    payload.update({"iat": now, "exp": now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))})
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    secret = os.getenv("JWT_SECRET_KEY")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session invalide ou expirée.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not secret or len(secret) < 32:
        raise HTTPException(status_code=503, detail="Le service d'authentification n'est pas configuré.")
    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        user_id = payload.get("uid")
        if isinstance(user_id, int):
            user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == user_id).first()
        else:
            # Keep pre-migration 24-hour sessions valid when the JWT secret is preserved.
            email = payload.get("sub")
            user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email).first() if isinstance(email, str) else None
    except JWTError:
        raise credentials_exception
    if user is None:
        raise credentials_exception
    if payload.get("ver", 0) != user.session_version:
        raise credentials_exception
    return user


def get_membership(db: Session, user: database.UtilisateurDB):
    return db.query(database.WorkspaceMembershipDB).filter(
        database.WorkspaceMembershipDB.user_id == user.id
    ).first()


def require_workspace_membership(db: Session, user: database.UtilisateurDB):
    membership = get_membership(db, user)
    if membership is None:
        raise HTTPException(status_code=403, detail="Aucun espace de travail n'est associé à ce compte.")
    return membership


def is_super_admin(user: database.UtilisateurDB) -> bool:
    return (user.role or "").strip().upper().replace(" ", "_") == "SUPER_ADMIN"
