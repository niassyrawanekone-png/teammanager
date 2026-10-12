import os
import secrets
import hashlib
import hmac
import logging
import smtplib
import json
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from typing import List, Optional
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

import database
import security
import storage
from database import get_db


class UtilisateurCreate(BaseModel):
    nom: str = Field(min_length=1, max_length=160)
    email: EmailStr
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    role: Optional[str] = None
    prenom: Optional[str] = Field(default=None, max_length=100)


class UtilisateurOut(BaseModel):
    id: int
    prenom: Optional[str] = None
    nom: Optional[str] = None
    email: EmailStr
    role: str
    workspace_id: Optional[int] = None
    workspace_name: Optional[str] = None
    can_manage_tasks: bool = False
    model_config = ConfigDict(from_attributes=True)


class NomUpdate(BaseModel):
    nom: str = Field(min_length=1, max_length=160)


class PasswordUpdate(BaseModel):
    ancien_mot_de_passe: str
    nouveau_mot_de_passe: str = Field(min_length=8, max_length=128)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=32, max_length=256)
    nouveau_mot_de_passe: str = Field(min_length=8, max_length=128)
    confirmation: str = Field(min_length=8, max_length=128)


class InvitationAccept(BaseModel):
    token: str = Field(min_length=32, max_length=256)
    nouveau_mot_de_passe: str = Field(min_length=8, max_length=128)
    confirmation: str = Field(min_length=8, max_length=128)


class RoleUpdate(BaseModel):
    role: str
    can_manage_tasks: bool = False


class AdminWorkspaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    owner_user_id: int


class AdminWorkspaceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=160)
    new_owner_user_id: Optional[int] = None


class AdminMemberRoleUpdate(BaseModel):
    role: str
    can_manage_tasks: bool = False


class ProjetCreate(BaseModel):
    titre: str = Field(min_length=1, max_length=200)
    description: Optional[str] = ""
    objectifs: Optional[str] = None
    resultats_attendus: Optional[str] = None
    statut: Optional[str] = "En cours"
    responsable: Optional[str] = None


class ProjetOut(BaseModel):
    id: int
    titre: str
    description: Optional[str] = ""
    objectifs: Optional[str] = ""
    resultats_attendus: Optional[str] = ""
    statut: str
    responsable: str
    workspace_id: Optional[int] = None
    workspace_name: Optional[str] = None
    owner_id: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)


class AdminProjectCreate(ProjetCreate):
    workspace_id: int


class MessageCreate(BaseModel):
    contenu: str = Field(min_length=1, max_length=10000)
    project_id: Optional[int] = None


class MessageOut(BaseModel):
    id: int
    contenu: str
    created_at: datetime
    auteur_nom: str
    auteur_id: Optional[int] = None
    auteur_role: Optional[str] = None
    workspace_id: Optional[int] = None
    project_id: Optional[int] = None
    attachments: List[dict] = Field(default_factory=list)


class MessageAttachmentOut(BaseModel):
    id: int
    original_name: str
    content_type: str
    size_bytes: int
    url: Optional[str] = None


class MessageReadRequest(BaseModel):
    message_ids: List[int] = Field(default_factory=list, max_length=200)


class TaskCreate(BaseModel):
    project_id: int
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    assigned_to: Optional[int] = None
    due_date: Optional[date] = None
    priority: str = "NORMAL"


class TaskUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=10000)
    assigned_to: Optional[int] = None
    due_date: Optional[date] = None
    priority: Optional[str] = None
    status: Optional[str] = None


class TaskStatusUpdate(BaseModel):
    status: str


class AssistantMessage(BaseModel):
    role: str
    content: str = Field(min_length=1, max_length=12000)


class AssistantRequest(BaseModel):
    messages: List[AssistantMessage] = Field(min_length=1, max_length=20)
    project_id: Optional[int] = None


class TaskOut(BaseModel):
    id: int
    workspace_id: int
    project_id: int
    title: str
    description: str
    assigned_to: Optional[int] = None
    assignee_name: Optional[str] = None
    due_date: Optional[date] = None
    priority: str
    status: str
    created_at: datetime


class NotificationOut(BaseModel):
    id: int
    event_type: str
    title: str
    body: str
    related_id: Optional[int]
    is_read: bool
    created_at: datetime


def _is_super(user):
    return security.is_super_admin(user)


def _require_super_admin(user):
    if not _is_super(user):
        raise HTTPException(status_code=403, detail="Cette action est réservée au super administrateur.")
    return user


def _membership(db, user, roles=None):
    membership = security.require_workspace_membership(db, user)
    if roles and membership.role not in roles:
        raise HTTPException(status_code=403, detail="Cette action n'est pas autorisée pour votre rôle.")
    return membership


def _workspace_id(db, user):
    if _is_super(user):
        return None
    return _membership(db, user).workspace_id


def _can_manage_tasks(membership):
    return membership.role == "CHEF_DE_PROJET" or (
        membership.role == "SOUS_CHEF_DE_PROJET" and membership.can_manage_tasks
    )


def _user_out(db, user):
    result = UtilisateurOut.model_validate(user)
    membership = security.get_membership(db, user)
    return result.model_copy(update={"can_manage_tasks": bool(membership and membership.can_manage_tasks)})


def _notify(db, user_id, workspace_id, event_type, title, body="", related_id=None):
    db.add(database.NotificationDB(
        user_id=user_id, workspace_id=workspace_id, event_type=event_type,
        title=title, body=body, related_id=related_id, is_read=False,
        created_at=_utc_now_naive(),
    ))


def _validate_task_fields(data):
    priority = (getattr(data, "priority", None) or "NORMAL").upper()
    if priority not in {"LOW", "NORMAL", "HIGH", "URGENT"}:
        raise HTTPException(status_code=422, detail="La priorité doit être LOW, NORMAL, HIGH ou URGENT.")
    task_status = getattr(data, "status", None)
    if task_status is not None and task_status not in {"TODO", "IN_PROGRESS", "DONE"}:
        raise HTTPException(status_code=422, detail="L'état doit être TODO, IN_PROGRESS ou DONE.")
    return priority


app = FastAPI(title="TeamManager API", version="2.0.0")
allowed_origins = [origin.strip() for origin in os.getenv(
    "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
def _initialize_database():
    database.initialize_database()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/assistant/chat")
def assistant_chat(data: AssistantRequest, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user)
    api_key = os.getenv("AI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=503, detail="Assistant IA indisponible : le fournisseur IA n'est pas configuré.")
    daily_limit = min(max(int(os.getenv("AI_DAILY_REQUEST_LIMIT", "20")), 1), 50)
    since = datetime.utcnow() - timedelta(days=1)
    used = db.query(database.AIUsageDB).filter(
        database.AIUsageDB.user_id == current_user.id,
        database.AIUsageDB.created_at >= since,
    ).count()
    if used >= daily_limit:
        raise HTTPException(status_code=429, detail="Limite quotidienne d'utilisation de l'assistant atteinte.")
    context = ""
    if data.project_id is not None:
        project = db.query(database.ProjetDB).filter(
            database.ProjetDB.id == data.project_id,
            database.ProjetDB.workspace_id == membership.workspace_id,
        ).first()
        if not project or (membership.project_id is not None and membership.project_id != project.id):
            raise HTTPException(status_code=404, detail="Projet introuvable dans votre espace.")
        context = (
            "\nContexte du projet autorisé :\n"
            f"Titre : {project.titre}\nDescription : {project.description or ''}\n"
            f"Objectifs : {project.objectifs or ''}\nRésultats attendus : {project.resultats_attendus or ''}"
        )
    messages = []
    for message in data.messages:
        if message.role not in {"user", "assistant"}:
            raise HTTPException(status_code=422, detail="Rôle de message IA invalide.")
        messages.append({"role": message.role, "content": message.content})
    if messages[-1]["role"] != "user":
        raise HTTPException(status_code=422, detail="Le dernier message doit être une demande utilisateur.")
    endpoint = os.getenv("AI_CHAT_COMPLETIONS_URL", "https://api.openai.com/v1/chat/completions").strip()
    model = os.getenv("AI_MODEL", "gpt-4o-mini").strip()
    payload = {
        "model": model,
        "messages": [{
            "role": "system",
            "content": "Tu es l'assistant de projet Team Manager. Réponds en français de façon structurée. "
                       "Propose des plans et tâches concrets. Ne prétends pas que tes suggestions sont déjà enregistrées. "
                       "Ne demande ni ne révèle des données d'autres équipes." + context,
        }, *messages],
        "max_tokens": 1200,
        "temperature": 0.4,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            result = json.loads(response.read().decode("utf-8"))
        answer = result["choices"][0]["message"]["content"].strip()
        if not answer:
            raise ValueError("empty completion")
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, IndexError, json.JSONDecodeError):
        logging.warning("AI provider request failed for user_id=%s", current_user.id)
        raise HTTPException(status_code=502, detail="L'assistant IA n'a pas pu traiter la demande.")
    db.add(database.AIUsageDB(user_id=current_user.id, created_at=datetime.utcnow()))
    db.commit()
    return {"answer": answer, "remaining_today": max(daily_limit - used - 1, 0)}


def _reset_response():
    return {"message": "Si un compte correspond à cette adresse et que l'envoi est disponible, vous recevrez des instructions."}


def _fingerprint(value, secret):
    return hmac.new(secret.encode(), (value or "").encode(), hashlib.sha256).hexdigest()


def _utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _send_configured_email(email, subject, content):
    required = ("SMTP_HOST", "SMTP_FROM", "APP_BASE_URL")
    if not all(os.getenv(name) for name in required):
        return False
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = email
    message.set_content(content)
    try:
        host = os.environ["SMTP_HOST"]
        port = int(os.getenv("SMTP_PORT", "587"))
        username = os.getenv("SMTP_USERNAME")
        password = os.getenv("SMTP_PASSWORD")
        use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
                if username:
                    smtp.login(username, password or "")
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.starttls()
                if username:
                    smtp.login(username, password or "")
                smtp.send_message(message)
        return True
    except Exception:
        logging.getLogger(__name__).warning("Transactional email delivery failed.")
        return False


def _email_reset_token(email, token):
    link = f"{os.getenv('APP_BASE_URL', '').rstrip('/')}/reinitialiser-mot-de-passe?token={quote(token)}"
    content = (
        "Une demande de réinitialisation a été reçue pour votre compte Team Manager. "
        "Ce lien expire dans 30 minutes et ne peut être utilisé qu'une fois :\n\n" + link +
        "\n\nSi vous n'êtes pas à l'origine de cette demande, ignorez ce message."
    )
    return _send_configured_email(email, "Réinitialisation de votre mot de passe Team Manager", content)


def _email_account_invitation(email, name, token):
    link = f"{os.getenv('APP_BASE_URL', '').rstrip('/')}/activer-compte?token={quote(token)}"
    content = (
        f"Bonjour {name},\n\nVous avez été ajouté à une équipe Team Manager. "
        "Définissez votre mot de passe avec ce lien valable 48 heures :\n\n" + link +
        "\n\nSi vous ne vous attendiez pas à cette invitation, ignorez ce message."
    )
    return _send_configured_email(email, "Invitation à rejoindre une équipe Team Manager", content)


@app.post("/register", response_model=UtilisateurOut, status_code=status.HTTP_201_CREATED)
def inscrire(user: UtilisateurCreate, db: Session = Depends(get_db)):
    email_clean = user.email.lower().strip()
    if not user.password:
        raise HTTPException(status_code=422, detail="Un mot de passe est obligatoire pour l'inscription.")
    super_email = os.getenv("SUPER_ADMIN_EMAIL", "").lower().strip()
    if super_email and email_clean == super_email:
        raise HTTPException(status_code=409, detail="Cette adresse ne peut pas être utilisée pour une inscription publique.")
    if db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first():
        raise HTTPException(status_code=400, detail="Cet e-mail est déjà utilisé.")

    nouveau_user = database.UtilisateurDB(
        prenom=(user.prenom or "").strip() or None,
        nom=user.nom.strip(), email=email_clean,
        hashed_password=security.hash_password(user.password), role="CHEF_DE_PROJET",
    )
    db.add(nouveau_user)
    db.flush()
    workspace = database.WorkspaceDB(name=f"Espace de {nouveau_user.nom}", owner_user_id=nouveau_user.id)
    db.add(workspace)
    db.flush()
    db.add(database.WorkspaceMembershipDB(
        user_id=nouveau_user.id, workspace_id=workspace.id,
        role="CHEF_DE_PROJET", can_manage_tasks=True,
    ))
    db.commit()
    db.refresh(nouveau_user)
    return nouveau_user


@app.post("/login")
def connecter(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email_clean = form_data.username.lower().strip()
    super_email = os.getenv("SUPER_ADMIN_EMAIL", "").lower().strip()
    super_password = os.getenv("SUPER_ADMIN_PASSWORD")
    user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first()

    # Le secret historique n'est plus codé dans le dépôt. Le déploiement fournit le
    # même mot de passe dans l'environnement; son hash est synchronisé à la connexion.
    super_admin_exists = db.query(database.UtilisateurDB.id).filter(
        func.upper(func.replace(func.trim(database.UtilisateurDB.role), " ", "_")) == "SUPER_ADMIN"
    ).first() is not None
    may_bootstrap = (
        not super_admin_exists and bool(super_email) and bool(super_password)
        and email_clean == super_email
        and secrets.compare_digest(form_data.password, super_password)
        and (user is None or not user.password_bootstrapped)
    )
    if may_bootstrap:
        if user is None:
            user = database.UtilisateurDB(
                nom=os.getenv("SUPER_ADMIN_NAME", "Super administrateur"),
                email=super_email, hashed_password=security.hash_password(form_data.password),
                role="SUPER_ADMIN", password_bootstrapped=True,
            )
            db.add(user)
            db.flush()
        else:
            user.role = "SUPER_ADMIN"
            user.hashed_password = security.hash_password(form_data.password)
            user.password_bootstrapped = True
        db.commit()
        db.refresh(user)
    elif not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou mot de passe incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif _is_super(user) and not user.password_bootstrapped:
        user.password_bootstrapped = True
        db.commit()

    try:
        token = security.create_access_token({"uid": user.id, "sub": user.email, "ver": user.session_version})
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me", response_model=UtilisateurOut)
def obtenir_profil(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    return _user_out(db, current_user)


@app.put("/me", response_model=UtilisateurOut)
@app.put("/me/nom", response_model=UtilisateurOut)
def modifier_mon_nom(data: NomUpdate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    current_user.nom = data.nom.strip()
    db.commit()
    db.refresh(current_user)
    return _user_out(db, current_user)


@app.put("/me/mot-de-passe")
def modifier_mon_mot_de_passe(data: PasswordUpdate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    if not security.verify_password(data.ancien_mot_de_passe, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="L'ancien mot de passe est incorrect.")
    current_user.hashed_password = security.hash_password(data.nouveau_mot_de_passe)
    current_user.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    current_user.session_version += 1
    db.commit()
    access_token = security.create_access_token({
        "uid": current_user.id, "sub": current_user.email, "ver": current_user.session_version,
    })
    return {"message": "Mot de passe mis à jour avec succès.", "access_token": access_token, "token_type": "bearer"}


@app.post("/password/forgot")
def demander_reinitialisation(data: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    now = _utc_now_naive()
    secret = os.getenv("RESET_RATE_LIMIT_SECRET") or os.getenv("JWT_SECRET_KEY")
    if not secret:
        return _reset_response()
    email_clean = data.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    email_key = _fingerprint(email_clean, secret)
    ip_key = _fingerprint(ip, secret)
    db.add(database.PasswordResetAttemptDB(
        email_fingerprint=email_key, ip_fingerprint=ip_key, attempted_at=now,
    ))
    db.flush()
    cutoff = now - timedelta(hours=1)
    db.query(database.PasswordResetAttemptDB).filter(
        database.PasswordResetAttemptDB.attempted_at < now - timedelta(days=30),
    ).delete(synchronize_session=False)
    email_count = db.query(database.PasswordResetAttemptDB).filter(
        database.PasswordResetAttemptDB.email_fingerprint == email_key,
        database.PasswordResetAttemptDB.attempted_at >= cutoff,
    ).count()
    ip_count = db.query(database.PasswordResetAttemptDB).filter(
        database.PasswordResetAttemptDB.ip_fingerprint == ip_key,
        database.PasswordResetAttemptDB.attempted_at >= cutoff,
    ).count()
    if email_count > 5 or ip_count > 30:
        db.commit()
        return _reset_response()
    user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first()
    mail_configured = all(os.getenv(name) for name in ("SMTP_HOST", "SMTP_FROM", "APP_BASE_URL"))
    if user and mail_configured:
        token = secrets.token_urlsafe(48)
        now = _utc_now_naive()
        db.query(database.PasswordResetTokenDB).filter(
            database.PasswordResetTokenDB.user_id == user.id,
            database.PasswordResetTokenDB.used_at.is_(None),
        ).update({"used_at": now}, synchronize_session=False)
        reset = database.PasswordResetTokenDB(
            user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
            expires_at=now + timedelta(minutes=30), created_at=now,
        )
        db.add(reset)
        db.commit()
        if not _email_reset_token(user.email, token):
            reset.used_at = _utc_now_naive()
            db.commit()
    else:
        db.commit()
    return _reset_response()


@app.post("/password/reset")
def confirmer_reinitialisation(data: PasswordResetConfirm, db: Session = Depends(get_db)):
    if not secrets.compare_digest(data.nouveau_mot_de_passe, data.confirmation):
        raise HTTPException(status_code=422, detail="Les deux mots de passe ne correspondent pas.")
    token_hash = hashlib.sha256(data.token.encode()).hexdigest()
    now = _utc_now_naive()
    reset = db.query(database.PasswordResetTokenDB).filter(
        database.PasswordResetTokenDB.token_hash == token_hash,
        database.PasswordResetTokenDB.used_at.is_(None),
        database.PasswordResetTokenDB.expires_at > now,
    ).first()
    if reset is None:
        raise HTTPException(status_code=400, detail="Ce lien est invalide ou a expiré.")
    claim = db.query(database.PasswordResetTokenDB).filter(
        database.PasswordResetTokenDB.id == reset.id,
        database.PasswordResetTokenDB.used_at.is_(None),
        database.PasswordResetTokenDB.expires_at > now,
    ).update({"used_at": now}, synchronize_session=False)
    if claim != 1:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ce lien est invalide ou a expiré.")
    user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == reset.user_id).first()
    if user is None:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ce lien est invalide ou a expiré.")
    user.hashed_password = security.hash_password(data.nouveau_mot_de_passe)
    user.password_changed_at = now
    user.session_version += 1
    db.query(database.PasswordResetTokenDB).filter(
        database.PasswordResetTokenDB.user_id == user.id,
        database.PasswordResetTokenDB.used_at.is_(None),
    ).update({"used_at": now}, synchronize_session=False)
    db.commit()
    return {"message": "Le mot de passe a été réinitialisé. Vous pouvez vous connecter."}


@app.post("/invitations/accept")
def accepter_invitation(data: InvitationAccept, db: Session = Depends(get_db)):
    if not secrets.compare_digest(data.nouveau_mot_de_passe, data.confirmation):
        raise HTTPException(status_code=422, detail="Les deux mots de passe ne correspondent pas.")
    token_hash = hashlib.sha256(data.token.encode()).hexdigest()
    now = _utc_now_naive()
    invitation = db.query(database.AccountInvitationTokenDB).filter(
        database.AccountInvitationTokenDB.token_hash == token_hash,
        database.AccountInvitationTokenDB.used_at.is_(None),
        database.AccountInvitationTokenDB.expires_at > now,
    ).first()
    if invitation is None:
        raise HTTPException(status_code=400, detail="Cette invitation est invalide ou expirée.")
    claim = db.query(database.AccountInvitationTokenDB).filter(
        database.AccountInvitationTokenDB.id == invitation.id,
        database.AccountInvitationTokenDB.used_at.is_(None),
        database.AccountInvitationTokenDB.expires_at > now,
    ).update({"used_at": now}, synchronize_session=False)
    if claim != 1:
        db.rollback()
        raise HTTPException(status_code=400, detail="Cette invitation est invalide ou expirée.")
    user = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == invitation.user_id).first()
    if user is None:
        db.rollback()
        raise HTTPException(status_code=400, detail="Cette invitation est invalide ou expirée.")
    user.hashed_password = security.hash_password(data.nouveau_mot_de_passe)
    user.password_changed_at = now
    user.session_version += 1
    db.query(database.AccountInvitationTokenDB).filter(
        database.AccountInvitationTokenDB.user_id == user.id,
        database.AccountInvitationTokenDB.used_at.is_(None),
    ).update({"used_at": now}, synchronize_session=False)
    db.commit()
    return {"message": "Compte activé. Vous pouvez maintenant vous connecter."}


@app.get("/utilisateurs/", response_model=List[UtilisateurOut])
def lister_utilisateurs(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    if _is_super(current_user):
        users = db.query(database.UtilisateurDB).order_by(database.UtilisateurDB.id).all()
    else:
        membership = _membership(db, current_user)
        users = db.query(database.UtilisateurDB).join(database.WorkspaceMembershipDB).filter(
            database.WorkspaceMembershipDB.workspace_id == membership.workspace_id
        ).order_by(database.UtilisateurDB.id).all()
    return [_user_out(db, user) for user in users]


@app.get("/admin/overview")
def administrer_statistiques(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    return {
        "users": db.query(database.UtilisateurDB).count(),
        "workspaces": db.query(database.WorkspaceDB).count(),
        "projects": db.query(database.ProjetDB).count(),
        "tasks": db.query(database.TaskDB).count(),
        "messages": db.query(database.MessagePartageDB).count(),
    }


@app.get("/admin/users", response_model=List[UtilisateurOut])
def administrer_liste_utilisateurs(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    users = db.query(database.UtilisateurDB).order_by(database.UtilisateurDB.id).all()
    return [_user_out(db, user) for user in users]


@app.get("/admin/workspaces")
def administrer_liste_espaces(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    workspaces = db.query(database.WorkspaceDB).order_by(database.WorkspaceDB.id).all()
    return [{
        "id": workspace.id,
        "name": workspace.name,
        "owner_user_id": workspace.owner_user_id,
        "members_count": db.query(database.WorkspaceMembershipDB).filter_by(workspace_id=workspace.id).count(),
        "projects_count": db.query(database.ProjetDB).filter_by(workspace_id=workspace.id).count(),
    } for workspace in workspaces]


@app.post("/admin/workspaces", status_code=status.HTTP_201_CREATED)
def administrer_creer_espace(data: AdminWorkspaceCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    if not data.name.strip():
        raise HTTPException(status_code=422, detail="Le nom de l'espace est obligatoire.")
    owner = db.query(database.UtilisateurDB).filter_by(id=data.owner_user_id).first()
    if not owner or _is_super(owner):
        raise HTTPException(status_code=404, detail="Compte propriétaire introuvable.")
    if security.get_membership(db, owner):
        raise HTTPException(status_code=409, detail="Ce compte appartient déjà à un espace.")
    if db.query(database.WorkspaceDB.id).filter_by(owner_user_id=owner.id).first():
        raise HTTPException(status_code=409, detail="Ce compte possède déjà un espace.")
    workspace = database.WorkspaceDB(
        name=data.name.strip(), owner_user_id=owner.id, created_at=_utc_now_naive(),
    )
    owner.role = "CHEF_DE_PROJET"
    db.add(workspace)
    db.flush()
    db.add(database.WorkspaceMembershipDB(
        user_id=owner.id, workspace_id=workspace.id,
        role="CHEF_DE_PROJET", can_manage_tasks=True,
    ))
    db.commit()
    db.refresh(workspace)
    return {"id": workspace.id, "name": workspace.name, "owner_user_id": workspace.owner_user_id}


@app.patch("/admin/workspaces/{workspace_id}")
def administrer_modifier_espace(workspace_id: int, data: AdminWorkspaceUpdate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    workspace = db.query(database.WorkspaceDB).filter_by(id=workspace_id).first()
    if not workspace:
        raise HTTPException(status_code=404, detail="Espace introuvable.")
    if data.name is not None:
        if not data.name.strip():
            raise HTTPException(status_code=422, detail="Le nom de l'espace est obligatoire.")
        workspace.name = data.name.strip()
    if data.new_owner_user_id is not None and data.new_owner_user_id != workspace.owner_user_id:
        new_owner = db.query(database.UtilisateurDB).filter_by(id=data.new_owner_user_id).first()
        new_membership = security.get_membership(db, new_owner) if new_owner else None
        if not new_owner or _is_super(new_owner) or not new_membership or new_membership.workspace_id != workspace.id:
            raise HTTPException(status_code=422, detail="Le nouveau propriétaire doit être membre de cet espace.")
        other_owned_space = db.query(database.WorkspaceDB.id).filter(
            database.WorkspaceDB.owner_user_id == new_owner.id,
            database.WorkspaceDB.id != workspace.id,
        ).first()
        if other_owned_space:
            raise HTTPException(status_code=409, detail="Ce compte possède déjà un autre espace.")
        previous_owner = db.query(database.UtilisateurDB).filter_by(id=workspace.owner_user_id).first()
        previous_membership = security.get_membership(db, previous_owner) if previous_owner else None
        if previous_membership and previous_membership.workspace_id == workspace.id and not _is_super(previous_owner):
            previous_membership.role = "MEMBRE"
            previous_membership.can_manage_tasks = False
            previous_owner.role = "MEMBRE"
        new_membership.role = "CHEF_DE_PROJET"
        new_membership.can_manage_tasks = True
        new_owner.role = "CHEF_DE_PROJET"
        workspace.owner_user_id = new_owner.id
    db.commit()
    db.refresh(workspace)
    return {"id": workspace.id, "name": workspace.name, "owner_user_id": workspace.owner_user_id}


@app.patch("/admin/users/{user_id}/role", response_model=UtilisateurOut)
def administrer_role_membre(user_id: int, data: AdminMemberRoleUpdate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    role = data.role.strip().upper().replace(" ", "_").replace("-", "_")
    if role not in {"MEMBRE", "SOUS_CHEF", "SOUS_CHEF_DE_PROJET"}:
        raise HTTPException(status_code=422, detail="Utilisez le transfert de propriété pour modifier le chef d'un espace.")
    target = db.query(database.UtilisateurDB).filter_by(id=user_id).first()
    membership = security.get_membership(db, target) if target else None
    if not target or _is_super(target) or not membership:
        raise HTTPException(status_code=404, detail="Compte membre introuvable.")
    if target.id == db.query(database.WorkspaceDB.owner_user_id).filter_by(id=membership.workspace_id).scalar():
        raise HTTPException(status_code=409, detail="Transférez d'abord la propriété de cet espace.")
    role = "SOUS_CHEF_DE_PROJET" if role in {"SOUS_CHEF", "SOUS_CHEF_DE_PROJET"} else "MEMBRE"
    target.role = role
    membership.role = role
    membership.can_manage_tasks = bool(data.can_manage_tasks and role == "SOUS_CHEF_DE_PROJET")
    db.commit()
    db.refresh(target)
    return _user_out(db, target)


@app.post("/admin/projects", response_model=ProjetOut, status_code=status.HTTP_201_CREATED)
def administrer_creer_projet(data: AdminProjectCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    workspace = db.query(database.WorkspaceDB).filter_by(id=data.workspace_id).first()
    if not workspace:
        raise HTTPException(status_code=404, detail="Espace introuvable.")
    owner = db.query(database.UtilisateurDB).filter_by(id=workspace.owner_user_id).first()
    project = database.ProjetDB(
        titre=data.titre.strip(), description=data.description or "",
        objectifs=data.objectifs or "", resultats_attendus=data.resultats_attendus or "",
        statut=data.statut or "En cours", responsable=owner.nom if owner else "Non assigné",
        workspace_id=workspace.id, owner_id=workspace.owner_user_id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@app.get("/admin/projects", response_model=List[ProjetOut])
def administrer_liste_projets(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    return db.query(database.ProjetDB).order_by(database.ProjetDB.id).all()


@app.put("/admin/projects/{project_id}", response_model=ProjetOut)
def administrer_modifier_projet(project_id: int, data: ProjetCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    _require_super_admin(current_user)
    project = db.query(database.ProjetDB).filter_by(id=project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Projet introuvable.")
    project.titre = data.titre.strip()
    if data.description is not None:
        project.description = data.description
    if data.objectifs is not None:
        project.objectifs = data.objectifs
    if data.resultats_attendus is not None:
        project.resultats_attendus = data.resultats_attendus
    if data.statut:
        project.statut = data.statut
    db.commit()
    db.refresh(project)
    return project


@app.post("/utilisateurs/", response_model=UtilisateurOut, status_code=status.HTTP_201_CREATED)
def ajouter_utilisateur(user: UtilisateurCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user, {"CHEF_DE_PROJET"})
    email_clean = user.email.lower().strip()
    prenom = (user.prenom or "").strip()
    nom = user.nom.strip()
    if not prenom:
        raise HTTPException(status_code=422, detail="Le prénom est obligatoire pour inviter un membre.")
    if not all(os.getenv(name) for name in ("SMTP_HOST", "SMTP_FROM", "APP_BASE_URL")):
        raise HTTPException(status_code=503, detail="Les invitations par e-mail ne sont pas configurées.")
    if db.query(database.UtilisateurDB).filter(database.UtilisateurDB.email == email_clean).first():
        raise HTTPException(status_code=409, detail="Cet e-mail est déjà associé à un compte.")
    requested_role = (user.role or "MEMBRE").strip().upper().replace(" ", "_").replace("-", "_")
    if requested_role in {"SOUS_CHEF", "SOUS_CHEF_DE_PROJET"}:
        assigned_role = "SOUS_CHEF_DE_PROJET"
    elif requested_role in {"MEMBRE", ""}:
        assigned_role = "MEMBRE"
    else:
        raise HTTPException(status_code=422, detail="Un chef peut ajouter un membre ou un sous-chef uniquement.")
    nouveau_user = database.UtilisateurDB(
        prenom=prenom, nom=nom, email=email_clean,
        hashed_password=security.hash_password(secrets.token_urlsafe(48)), role=assigned_role,
    )
    db.add(nouveau_user)
    db.flush()
    db.add(database.WorkspaceMembershipDB(
        user_id=nouveau_user.id, workspace_id=membership.workspace_id,
        role=assigned_role, can_manage_tasks=False,
    ))
    raw_token = secrets.token_urlsafe(48)
    now = _utc_now_naive()
    invitation = database.AccountInvitationTokenDB(
        user_id=nouveau_user.id, workspace_id=membership.workspace_id,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        expires_at=now + timedelta(hours=48), created_at=now,
    )
    db.add(invitation)
    db.commit()
    if not _email_account_invitation(email_clean, prenom, raw_token):
        db.delete(invitation)
        db.delete(nouveau_user)
        db.commit()
        raise HTTPException(status_code=502, detail="L'invitation n'a pas pu être envoyée; aucun compte n'a été créé.")
    db.refresh(nouveau_user)
    return nouveau_user


@app.put("/utilisateurs/{user_id}", response_model=UtilisateurOut)
def modifier_role(user_id: int, data: RoleUpdate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user, {"CHEF_DE_PROJET"})
    role = data.role.strip().upper().replace(" ", "_").replace("-", "_")
    aliases = {"MEMBRE": "MEMBRE", "SOUS_CHEF_DE_PROJET": "SOUS_CHEF_DE_PROJET", "SOUS_CHEF": "SOUS_CHEF_DE_PROJET"}
    if role not in aliases:
        raise HTTPException(status_code=422, detail="Seuls les rôles membre et sous-chef peuvent être attribués ici.")
    target = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == user_id).first()
    target_membership = security.get_membership(db, target) if target else None
    if not target or not target_membership or target_membership.workspace_id != membership.workspace_id:
        raise HTTPException(status_code=404, detail="Membre de cette équipe introuvable.")
    is_workspace_owner = db.query(database.WorkspaceDB.id).filter_by(owner_user_id=target.id).first() is not None
    if target.id == current_user.id or _is_super(target) or is_workspace_owner or target.role == "CHEF_DE_PROJET":
        raise HTTPException(status_code=403, detail="Ce compte ne peut pas être modifié depuis cette équipe.")
    target.role = aliases[role]
    target_membership.role = aliases[role]
    target_membership.can_manage_tasks = data.can_manage_tasks if aliases[role] == "SOUS_CHEF_DE_PROJET" else False
    _notify(db, target.id, membership.workspace_id, "ROLE_CHANGED", "Votre rôle a été mis à jour", f"Votre rôle est maintenant {aliases[role]}.", target.id)
    db.commit()
    db.refresh(target)
    return target


@app.delete("/utilisateurs/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def supprimer_utilisateur(user_id: int, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user, {"CHEF_DE_PROJET"})
    target = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == user_id).first()
    target_membership = security.get_membership(db, target) if target else None
    if not target or not target_membership or target_membership.workspace_id != membership.workspace_id:
        raise HTTPException(status_code=404, detail="Membre de cette équipe introuvable.")
    is_workspace_owner = db.query(database.WorkspaceDB.id).filter_by(owner_user_id=target.id).first() is not None
    if target.id == current_user.id or _is_super(target) or is_workspace_owner or target.role == "CHEF_DE_PROJET":
        raise HTTPException(status_code=403, detail="Ce compte ne peut pas être supprimé depuis cette équipe.")
    db.delete(target)
    db.commit()
    return None


@app.get("/projets/", response_model=List[ProjetOut])
def lister_projets(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    if _is_super(current_user):
        return db.query(database.ProjetDB).order_by(database.ProjetDB.id).all()
    membership = _membership(db, current_user)
    query = db.query(database.ProjetDB).filter(database.ProjetDB.workspace_id == membership.workspace_id)
    if membership.project_id is not None:
        query = query.filter(database.ProjetDB.id == membership.project_id)
    return query.order_by(database.ProjetDB.id).all()


@app.post("/projets/", response_model=ProjetOut, status_code=status.HTTP_201_CREATED)
def ajouter_projet(projet: ProjetCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user, {"CHEF_DE_PROJET"})
    nouveau = database.ProjetDB(
        titre=projet.titre.strip(), description=projet.description or "",
        objectifs=projet.objectifs or "", resultats_attendus=projet.resultats_attendus or "",
        statut=projet.statut or "En cours", responsable=current_user.nom or current_user.email,
        workspace_id=membership.workspace_id, owner_id=current_user.id,
    )
    db.add(nouveau)
    db.commit()
    db.refresh(nouveau)
    return nouveau


@app.put("/projets/{projet_id}", response_model=ProjetOut)
def modifier_projet(projet_id: int, projet: ProjetCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user, {"CHEF_DE_PROJET"})
    p = db.query(database.ProjetDB).filter(
        database.ProjetDB.id == projet_id, database.ProjetDB.workspace_id == membership.workspace_id,
    ).first()
    if not p:
        raise HTTPException(status_code=404, detail="Projet de cet espace introuvable.")
    p.titre = projet.titre.strip()
    if projet.description is not None:
        p.description = projet.description
    if projet.objectifs is not None:
        p.objectifs = projet.objectifs
    if projet.resultats_attendus is not None:
        p.resultats_attendus = projet.resultats_attendus
    p.statut = projet.statut or p.statut
    db.commit()
    db.refresh(p)
    return p


@app.delete("/projets/{projet_id}", status_code=status.HTTP_204_NO_CONTENT)
def supprimer_projet(projet_id: int, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user, {"CHEF_DE_PROJET"})
    projet = db.query(database.ProjetDB).filter(
        database.ProjetDB.id == projet_id, database.ProjetDB.workspace_id == membership.workspace_id,
    ).first()
    if not projet:
        raise HTTPException(status_code=404, detail="Projet de cet espace introuvable.")
    db.delete(projet)
    db.commit()
    return None


@app.get("/tasks/", response_model=List[TaskOut])
def lister_taches(project_id: Optional[int] = None, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    if _is_super(current_user):
        query = db.query(database.TaskDB)
    else:
        membership = _membership(db, current_user)
        query = db.query(database.TaskDB).filter(database.TaskDB.workspace_id == membership.workspace_id)
        if membership.project_id is not None:
            query = query.filter(database.TaskDB.project_id == membership.project_id)
    if project_id is not None:
        query = query.filter(database.TaskDB.project_id == project_id)
    return query.order_by(database.TaskDB.due_date.is_(None), database.TaskDB.due_date, database.TaskDB.id).all()


@app.post("/tasks/", response_model=TaskOut, status_code=status.HTTP_201_CREATED)
def creer_tache(data: TaskCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user)
    if not _can_manage_tasks(membership):
        raise HTTPException(status_code=403, detail="Votre rôle ne peut pas gérer les tâches.")
    project = db.query(database.ProjetDB).filter(database.ProjetDB.id == data.project_id).first()
    if not project or project.workspace_id != membership.workspace_id:
        raise HTTPException(status_code=404, detail="Projet de cet espace introuvable.")
    if membership.project_id is not None and membership.project_id != project.id:
        raise HTTPException(status_code=403, detail="Cette tâche ne concerne pas votre projet.")
    if data.assigned_to is not None:
        assignee_membership = security.get_membership(db, db.get(database.UtilisateurDB, data.assigned_to))
        if not assignee_membership or assignee_membership.workspace_id != membership.workspace_id:
            raise HTTPException(status_code=422, detail="La personne assignée n'appartient pas à cette équipe.")
        if assignee_membership.project_id is not None and assignee_membership.project_id != project.id:
            raise HTTPException(status_code=422, detail="La personne assignée n'appartient pas à ce projet.")
    priority = _validate_task_fields(data)
    now = _utc_now_naive()
    task = database.TaskDB(
        workspace_id=membership.workspace_id, project_id=project.id,
        title=data.title.strip(), description=data.description, assigned_to=data.assigned_to,
        created_by=current_user.id, due_date=data.due_date, priority=priority,
        status="TODO", created_at=now, updated_at=now,
    )
    db.add(task)
    db.flush()
    if data.assigned_to and data.assigned_to != current_user.id:
        _notify(db, data.assigned_to, membership.workspace_id, "TASK_ASSIGNED", "Une tâche vous a été attribuée", task.title, task.id)
    if data.due_date and data.due_date <= date.today() + timedelta(days=1) and data.assigned_to:
        _notify(db, data.assigned_to, membership.workspace_id, "TASK_DUE_SOON", "Échéance proche", task.title, task.id)
    db.commit()
    db.refresh(task)
    return task


@app.put("/tasks/{task_id}", response_model=TaskOut)
def modifier_tache(task_id: int, data: TaskUpdate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user)
    if not _can_manage_tasks(membership):
        raise HTTPException(status_code=403, detail="Votre rôle ne peut pas modifier les détails des tâches.")
    query = db.query(database.TaskDB).filter(database.TaskDB.id == task_id)
    if not _is_super(current_user):
        query = query.filter(database.TaskDB.workspace_id == membership.workspace_id)
        if membership.project_id is not None:
            query = query.filter(database.TaskDB.project_id == membership.project_id)
    task = query.first()
    if not task:
        raise HTTPException(status_code=404, detail="Tâche introuvable dans votre espace.")
    values = data.model_dump(exclude_unset=True)
    priority = values.get("priority", task.priority)
    if priority is not None and priority.upper() not in {"LOW", "NORMAL", "HIGH", "URGENT"}:
        raise HTTPException(status_code=422, detail="Priorité invalide.")
    new_status = values.get("status", task.status)
    if new_status not in {"TODO", "IN_PROGRESS", "DONE"}:
        raise HTTPException(status_code=422, detail="État de tâche invalide.")
    if "assigned_to" in values and values["assigned_to"] is not None:
        assignee = db.get(database.UtilisateurDB, values["assigned_to"])
        assignee_membership = security.get_membership(db, assignee) if assignee else None
        if not assignee_membership or assignee_membership.workspace_id != task.workspace_id:
            raise HTTPException(status_code=422, detail="La personne assignée n'appartient pas à cette équipe.")
        if assignee_membership.project_id is not None and assignee_membership.project_id != task.project_id:
            raise HTTPException(status_code=422, detail="La personne assignée n'appartient pas à ce projet.")
    previous_assignee = task.assigned_to
    for key in ("title", "description", "assigned_to", "due_date", "priority", "status"):
        if key in values:
            value = values[key]
            setattr(task, key, value.strip() if key == "title" and value else value)
    task.updated_at = _utc_now_naive()
    if task.assigned_to and task.assigned_to != previous_assignee and task.assigned_to != current_user.id:
        _notify(db, task.assigned_to, task.workspace_id, "TASK_ASSIGNED", "Une tâche vous a été attribuée", task.title, task.id)
    db.commit()
    db.refresh(task)
    return task


@app.patch("/tasks/{task_id}/status", response_model=TaskOut)
def changer_etat_tache(task_id: int, data: TaskStatusUpdate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    if data.status not in {"TODO", "IN_PROGRESS", "DONE"}:
        raise HTTPException(status_code=422, detail="État de tâche invalide.")
    membership = _membership(db, current_user)
    query = db.query(database.TaskDB).filter(database.TaskDB.id == task_id)
    if not _is_super(current_user):
        query = query.filter(database.TaskDB.workspace_id == membership.workspace_id)
        if membership.project_id is not None:
            query = query.filter(database.TaskDB.project_id == membership.project_id)
    task = query.first()
    if not task:
        raise HTTPException(status_code=404, detail="Tâche introuvable dans votre espace.")
    if not _can_manage_tasks(membership) and task.assigned_to != current_user.id:
        raise HTTPException(status_code=403, detail="Vous pouvez modifier uniquement l'état de vos tâches assignées.")
    task.status = data.status
    task.updated_at = _utc_now_naive()
    if task.created_by and task.created_by != current_user.id and _can_manage_tasks(membership):
        _notify(db, task.created_by, task.workspace_id, "TASK_UPDATED", "Une tâche a été mise à jour", task.title, task.id)
    db.commit()
    db.refresh(task)
    return task


@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def supprimer_tache(task_id: int, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user)
    if not _can_manage_tasks(membership):
        raise HTTPException(status_code=403, detail="Votre rôle ne peut pas supprimer les tâches.")
    query = db.query(database.TaskDB).filter(database.TaskDB.id == task_id)
    if not _is_super(current_user):
        query = query.filter(database.TaskDB.workspace_id == membership.workspace_id)
        if membership.project_id is not None:
            query = query.filter(database.TaskDB.project_id == membership.project_id)
    task = query.first()
    if not task:
        raise HTTPException(status_code=404, detail="Tâche introuvable dans votre espace.")
    db.delete(task)
    db.commit()
    return None


def _materialize_due_notifications(db, user, workspace_id):
    today = date.today()
    tasks = db.query(database.TaskDB).filter(
        database.TaskDB.workspace_id == workspace_id,
        database.TaskDB.assigned_to == user.id,
        database.TaskDB.status != "DONE",
        database.TaskDB.due_date >= today,
        database.TaskDB.due_date <= today + timedelta(days=1),
    ).all()
    for task in tasks:
        exists = db.query(database.NotificationDB.id).filter(
            database.NotificationDB.user_id == user.id,
            database.NotificationDB.event_type == "TASK_DUE_SOON",
            database.NotificationDB.related_id == task.id,
        ).first()
        if not exists:
            _notify(db, user.id, workspace_id, "TASK_DUE_SOON", "Échéance proche", task.title, task.id)
    if tasks:
        db.commit()


@app.get("/notifications/", response_model=List[NotificationOut])
def lister_notifications(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = security.get_membership(db, current_user)
    if membership:
        _materialize_due_notifications(db, current_user, membership.workspace_id)
    return db.query(database.NotificationDB).filter(
        database.NotificationDB.user_id == current_user.id,
    ).order_by(database.NotificationDB.created_at.desc()).limit(100).all()


@app.get("/notifications/unread-count")
def compter_notifications_non_lues(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = security.get_membership(db, current_user)
    if membership:
        _materialize_due_notifications(db, current_user, membership.workspace_id)
    count = db.query(database.NotificationDB).filter(
        database.NotificationDB.user_id == current_user.id,
        database.NotificationDB.is_read.is_(False),
    ).count()
    return {"count": count}


@app.post("/notifications/{notification_id}/read")
def marquer_notification_lue(notification_id: int, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    notification = db.query(database.NotificationDB).filter(
        database.NotificationDB.id == notification_id,
        database.NotificationDB.user_id == current_user.id,
    ).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification introuvable.")
    notification.is_read = True
    db.commit()
    return {"message": "Notification marquée comme lue."}


@app.post("/notifications/read-all")
def marquer_toutes_notifications_lues(db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    db.query(database.NotificationDB).filter(
        database.NotificationDB.user_id == current_user.id,
        database.NotificationDB.is_read.is_(False),
    ).update({"is_read": True}, synchronize_session=False)
    db.commit()
    return {"message": "Notifications marquées comme lues."}


@app.get("/partage/", response_model=List[MessageOut])
def lister_messages_partage(
    conversation: str = "all", project_id: Optional[int] = None,
    db: Session = Depends(get_db), current_user=Depends(security.get_current_user),
):
    query = db.query(database.MessagePartageDB)
    if not _is_super(current_user):
        membership = _membership(db, current_user)
        query = query.filter(database.MessagePartageDB.workspace_id == membership.workspace_id)
        if membership.project_id is not None and project_id != membership.project_id:
            if conversation == "project":
                raise HTTPException(status_code=403, detail="Cette conversation ne concerne pas votre projet.")
        if membership.project_id is not None:
            query = query.filter(
                (database.MessagePartageDB.project_id.is_(None)) |
                (database.MessagePartageDB.project_id == membership.project_id)
            )
    if conversation == "team":
        query = query.filter(database.MessagePartageDB.project_id.is_(None))
    elif conversation == "project":
        project = db.query(database.ProjetDB).filter(database.ProjetDB.id == project_id).first()
        if not project or (not _is_super(current_user) and project.workspace_id != membership.workspace_id):
            raise HTTPException(status_code=404, detail="Projet introuvable.")
        query = query.filter(database.MessagePartageDB.project_id == project.id)
    messages = query.order_by(database.MessagePartageDB.created_at.asc()).limit(200).all()
    return [_message_payload(db, message) for message in messages]


def _message_payload(db, msg):
    author = db.query(database.UtilisateurDB).filter(database.UtilisateurDB.id == msg.user_id).first()
    attachments = []
    for attachment in db.query(database.MessageAttachmentDB).filter_by(message_id=msg.id).all():
        if attachment.content_data is not None:
            url = f"/partage/attachments/{attachment.id}"
        else:
            try:
                url = storage.create_private_object_url(attachment.object_key)
            except Exception:
                url = None
        attachments.append({
            "id": attachment.id, "original_name": attachment.original_name,
            "content_type": attachment.content_type, "size_bytes": attachment.size_bytes,
            "url": url,
        })
    return {
        "id": msg.id, "contenu": msg.contenu, "created_at": msg.created_at,
        "auteur_nom": " ".join(filter(None, (author.prenom, author.nom))) if author else "Inconnu",
        "auteur_id": msg.user_id, "auteur_role": author.role if author else None,
        "workspace_id": msg.workspace_id, "project_id": msg.project_id, "attachments": attachments,
    }


@app.post("/partage/", response_model=MessageOut, status_code=status.HTTP_201_CREATED)
def publier_message_partage(msg: MessageCreate, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    workspace_id = _workspace_id(db, current_user)
    if workspace_id is None:
        raise HTTPException(status_code=403, detail="Le super administrateur consulte les discussions sans y participer.")
    if msg.project_id is not None:
        project = db.query(database.ProjetDB).filter(
            database.ProjetDB.id == msg.project_id, database.ProjetDB.workspace_id == workspace_id,
        ).first()
        membership = _membership(db, current_user)
        if not project or (membership.project_id is not None and membership.project_id != project.id):
            raise HTTPException(status_code=404, detail="Projet introuvable.")
    nouveau = database.MessagePartageDB(
        contenu=msg.contenu, user_id=current_user.id, workspace_id=workspace_id,
        project_id=msg.project_id, created_at=_utc_now_naive(),
    )
    db.add(nouveau)
    db.flush()
    recipient_ids = db.query(database.WorkspaceMembershipDB.user_id).filter(
        database.WorkspaceMembershipDB.workspace_id == workspace_id,
        database.WorkspaceMembershipDB.user_id != current_user.id,
    ).all()
    for (recipient_id,) in recipient_ids:
        recipient_membership = security.get_membership(db, db.get(database.UtilisateurDB, recipient_id))
        if msg.project_id and recipient_membership.project_id not in (None, msg.project_id):
            continue
        _notify(db, recipient_id, workspace_id, "NEW_MESSAGE", "Nouveau message", msg.contenu[:180], nouveau.id)
    db.commit()
    db.refresh(nouveau)
    return _message_payload(db, nouveau)


@app.get("/partage/unread-count")
def compter_messages_non_lus(conversation: str = "all", project_id: Optional[int] = None, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    query = db.query(database.MessagePartageDB).filter(database.MessagePartageDB.user_id != current_user.id)
    if not _is_super(current_user):
        membership = _membership(db, current_user)
        query = query.filter(database.MessagePartageDB.workspace_id == membership.workspace_id)
        if membership.project_id is not None:
            query = query.filter(
                (database.MessagePartageDB.project_id.is_(None)) |
                (database.MessagePartageDB.project_id == membership.project_id)
            )
    if conversation == "team":
        query = query.filter(database.MessagePartageDB.project_id.is_(None))
    elif conversation == "project":
        query = query.filter(database.MessagePartageDB.project_id == project_id)
    query = query.filter(~db.query(database.MessageReadDB.message_id).filter(
        database.MessageReadDB.message_id == database.MessagePartageDB.id,
        database.MessageReadDB.user_id == current_user.id,
    ).exists())
    return {"count": query.count()}


@app.post("/partage/read")
def marquer_messages_lus(data: MessageReadRequest, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    if not data.message_ids:
        return {"marked": 0}
    query = db.query(database.MessagePartageDB).filter(
        database.MessagePartageDB.id.in_(set(data.message_ids)),
        database.MessagePartageDB.user_id != current_user.id,
    )
    if not _is_super(current_user):
        membership = _membership(db, current_user)
        query = query.filter(database.MessagePartageDB.workspace_id == membership.workspace_id)
        if membership.project_id is not None:
            query = query.filter(
                (database.MessagePartageDB.project_id.is_(None)) |
                (database.MessagePartageDB.project_id == membership.project_id)
            )
    now = _utc_now_naive()
    marked = 0
    for message in query.all():
        exists = db.query(database.MessageReadDB.message_id).filter_by(
            message_id=message.id, user_id=current_user.id,
        ).first()
        if not exists:
            db.add(database.MessageReadDB(message_id=message.id, user_id=current_user.id, read_at=now))
            marked += 1
    db.commit()
    return {"marked": marked}


MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_AUDIO_BYTES = 20 * 1024 * 1024


def _detect_image(data: bytes):
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", ".gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp", ".webp"
    return None, None


def _detect_audio(data: bytes):
    if data.startswith(b"\x1aE\xdf\xa3"):
        return "audio/webm", ".webm"
    if data.startswith(b"OggS"):
        return "audio/ogg", ".ogg"
    return None, None


def _attachment_message_for_user(db, attachment_id, current_user):
    attachment = db.query(database.MessageAttachmentDB).filter_by(id=attachment_id).first()
    if not attachment:
        raise HTTPException(status_code=404, detail="Pièce jointe introuvable.")
    message = db.query(database.MessagePartageDB).filter_by(id=attachment.message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message introuvable.")
    if not _is_super(current_user):
        membership = _membership(db, current_user)
        if message.workspace_id != membership.workspace_id or (
            membership.project_id is not None
            and message.project_id not in (None, membership.project_id)
        ):
            raise HTTPException(status_code=404, detail="Pièce jointe introuvable.")
    return attachment


@app.get("/partage/attachments/{attachment_id}")
def lire_piece_jointe_partage(
    attachment_id: int, db: Session = Depends(get_db),
    current_user=Depends(security.get_current_user),
):
    attachment = _attachment_message_for_user(db, attachment_id, current_user)
    if attachment.content_data is not None:
        return Response(
            content=attachment.content_data,
            media_type=attachment.content_type,
            headers={"Cache-Control": "private, no-store"},
        )
    try:
        url = storage.create_private_object_url(attachment.object_key)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Le stockage privé de cette pièce jointe est indisponible.") from exc
    return {"url": url}


@app.post("/partage/{message_id}/photos", response_model=MessageAttachmentOut, status_code=status.HTTP_201_CREATED)
async def ajouter_photo_message(message_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user)
    message = db.query(database.MessagePartageDB).filter(
        database.MessagePartageDB.id == message_id,
        database.MessagePartageDB.workspace_id == membership.workspace_id,
    ).first()
    if not message or message.user_id != current_user.id or (membership.project_id is not None and message.project_id not in (None, membership.project_id)):
        raise HTTPException(status_code=404, detail="Message introuvable dans votre espace.")
    data = await file.read(MAX_IMAGE_BYTES + 1)
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="L'image doit faire 5 Mo maximum.")
    content_type, extension = _detect_image(data)
    if not content_type:
        raise HTTPException(status_code=415, detail="Formats acceptés : JPEG, PNG, GIF ou WebP.")
    key = f"postgresql://{membership.workspace_id}/{message.id}/{secrets.token_hex(16)}{extension}"
    original_name = os.path.basename(file.filename or f"photo{extension}")[:180]
    attachment = database.MessageAttachmentDB(
        message_id=message.id, object_key=key, original_name=original_name,
        content_type=content_type, size_bytes=len(data), created_at=_utc_now_naive(),
        content_data=data,
    )
    db.add(attachment)
    try:
        db.commit()
        db.refresh(attachment)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Impossible d'enregistrer l'image dans la base de données.")
    url = f"/partage/attachments/{attachment.id}"
    return {"id": attachment.id, "original_name": attachment.original_name,
            "content_type": attachment.content_type, "size_bytes": attachment.size_bytes, "url": url}


@app.post("/partage/{message_id}/audio", response_model=MessageAttachmentOut, status_code=status.HTTP_201_CREATED)
async def ajouter_audio_message(message_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    membership = _membership(db, current_user)
    message = db.query(database.MessagePartageDB).filter(
        database.MessagePartageDB.id == message_id,
        database.MessagePartageDB.workspace_id == membership.workspace_id,
    ).first()
    if not message or message.user_id != current_user.id or (membership.project_id is not None and message.project_id not in (None, membership.project_id)):
        raise HTTPException(status_code=404, detail="Message introuvable dans votre espace.")
    data = await file.read(MAX_AUDIO_BYTES + 1)
    if not data or len(data) > MAX_AUDIO_BYTES:
        raise HTTPException(status_code=413, detail="Le message vocal doit faire 20 Mo maximum.")
    content_type, extension = _detect_audio(data)
    declared_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if not content_type or declared_type != content_type:
        raise HTTPException(status_code=415, detail="Formats acceptés : audio WebM ou Ogg valide.")
    key = f"postgresql://{membership.workspace_id}/{message.id}/{secrets.token_hex(16)}{extension}"
    attachment = database.MessageAttachmentDB(
        message_id=message.id, object_key=key, original_name=f"message-vocal{extension}",
        content_type=content_type, size_bytes=len(data), created_at=_utc_now_naive(),
        content_data=data,
    )
    db.add(attachment)
    try:
        db.commit()
        db.refresh(attachment)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Impossible d'enregistrer le message vocal dans la base de données.")
    url = f"/partage/attachments/{attachment.id}"
    return {"id": attachment.id, "original_name": attachment.original_name,
            "content_type": attachment.content_type, "size_bytes": attachment.size_bytes, "url": url}


@app.delete("/partage/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def supprimer_message_partage(message_id: int, db: Session = Depends(get_db), current_user=Depends(security.get_current_user)):
    message = db.query(database.MessagePartageDB).filter(database.MessagePartageDB.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message introuvable.")
    if not _is_super(current_user) and message.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Vous ne pouvez supprimer que vos propres messages.")
    if not _is_super(current_user):
        membership = _membership(db, current_user)
        if message.workspace_id != membership.workspace_id:
            raise HTTPException(status_code=404, detail="Message introuvable.")
    attachments = db.query(database.MessageAttachmentDB).filter_by(message_id=message.id).all()
    for attachment in attachments:
        if attachment.content_data is None:
            try:
                storage.delete_private_image(attachment.object_key)
            except Exception as exc:
                raise HTTPException(status_code=503, detail="Impossible de supprimer le fichier privé.") from exc
        db.delete(attachment)
    db.delete(message)
    db.commit()
    return None
