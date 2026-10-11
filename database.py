import os
import unicodedata

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker


SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")
_connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=_connect_args)

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class UtilisateurDB(Base):
    __tablename__ = "utilisateurs"

    id = Column(Integer, primary_key=True, index=True)
    prenom = Column(String, nullable=True)
    nom = Column(String, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="MEMBRE", nullable=False)
    password_changed_at = Column(DateTime, nullable=True)
    password_bootstrapped = Column(Boolean, nullable=False, default=False)
    session_version = Column(Integer, nullable=False, default=0)
    memberships = relationship("WorkspaceMembershipDB", back_populates="user", cascade="all, delete-orphan")

    @property
    def workspace_id(self):
        return self.memberships[0].workspace_id if self.memberships else None

    @property
    def workspace_name(self):
        return self.memberships[0].workspace.name if self.memberships else None


class ProjetDB(Base):
    __tablename__ = "projets"

    id = Column(Integer, primary_key=True, index=True)
    titre = Column(String, index=True)
    description = Column(Text, default="")
    objectifs = Column(Text, default="")
    resultats_attendus = Column(Text, default="")
    statut = Column(String, default="En cours")
    responsable = Column(String, default="Non assigné")
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True, index=True)
    owner_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="RESTRICT"), nullable=True, index=True)
    workspace = relationship("WorkspaceDB", back_populates="projects")
    owner = relationship("UtilisateurDB", foreign_keys=[owner_id])

    @property
    def workspace_name(self):
        return self.workspace.name if self.workspace else None


class WorkspaceDB(Base):
    __tablename__ = "workspaces"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    owner_user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="RESTRICT"), nullable=False, unique=True)
    created_at = Column(DateTime)
    owner = relationship("UtilisateurDB", foreign_keys=[owner_user_id])
    projects = relationship("ProjetDB", back_populates="workspace", cascade="all, delete-orphan")
    memberships = relationship("WorkspaceMembershipDB", back_populates="workspace", cascade="all, delete-orphan")


class WorkspaceMembershipDB(Base):
    __tablename__ = "workspace_memberships"

    user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="CASCADE"), primary_key=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(Integer, ForeignKey("projets.id", ondelete="SET NULL"), nullable=True, index=True)
    role = Column(String, nullable=False, default="MEMBRE")
    can_manage_tasks = Column(Boolean, nullable=False, default=False)
    user = relationship("UtilisateurDB", back_populates="memberships")
    workspace = relationship("WorkspaceDB", back_populates="memberships")
    project = relationship("ProjetDB")


class MessagePartageDB(Base):
    __tablename__ = "messages_partage"

    id = Column(Integer, primary_key=True, index=True)
    contenu = Column(Text, nullable=False)
    created_at = Column(DateTime)
    user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="SET NULL"), nullable=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id = Column(Integer, ForeignKey("projets.id", ondelete="CASCADE"), nullable=True, index=True)
    user = relationship("UtilisateurDB")


class MessageReadDB(Base):
    __tablename__ = "message_reads"

    message_id = Column(Integer, ForeignKey("messages_partage.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="CASCADE"), primary_key=True)
    read_at = Column(DateTime, nullable=False)


class MessageAttachmentDB(Base):
    __tablename__ = "message_attachments"

    id = Column(Integer, primary_key=True)
    message_id = Column(Integer, ForeignKey("messages_partage.id", ondelete="CASCADE"), nullable=False, index=True)
    object_key = Column(String, nullable=False, unique=True)
    original_name = Column(String, nullable=False)
    content_type = Column(String, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)


class TaskDB(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(Integer, ForeignKey("projets.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    assigned_to = Column(Integer, ForeignKey("utilisateurs.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by = Column(Integer, ForeignKey("utilisateurs.id", ondelete="SET NULL"), nullable=True)
    due_date = Column(Date, nullable=True, index=True)
    priority = Column(String, nullable=False, default="NORMAL")
    status = Column(String, nullable=False, default="TODO", index=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    assignee = relationship("UtilisateurDB", foreign_keys=[assigned_to])

    @property
    def assignee_name(self):
        if self.assignee is None:
            return None
        return " ".join(filter(None, (self.assignee.prenom, self.assignee.nom))) or self.assignee.email


class NotificationDB(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True, index=True)
    event_type = Column(String, nullable=False)
    title = Column(String, nullable=False)
    body = Column(Text, nullable=False, default="")
    related_id = Column(Integer, nullable=True)
    is_read = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False)


class AIUsageDB(Base):
    __tablename__ = "ai_usage"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, index=True)


class PasswordResetTokenDB(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False)


class PasswordResetAttemptDB(Base):
    __tablename__ = "password_reset_attempts"

    id = Column(Integer, primary_key=True)
    email_fingerprint = Column(String, nullable=False, index=True)
    ip_fingerprint = Column(String, nullable=False, index=True)
    attempted_at = Column(DateTime, nullable=False, index=True)


class AccountInvitationTokenDB(Base):
    __tablename__ = "account_invitation_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("utilisateurs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _canonical_role(role, email, super_admin_email):
    normalized = "".join(
        char for char in unicodedata.normalize("NFKD", (role or ""))
        if not unicodedata.combining(char)
    ).strip().upper().replace("_", " ").replace("-", " ")
    if super_admin_email and (email or "").lower() == super_admin_email.lower():
        return "SUPER_ADMIN"
    if normalized in {"SUPER ADMIN", "SUPERADMIN"}:
        return "SUPER_ADMIN"
    if "SOUS" in normalized or "SUB" in normalized:
        return "SOUS_CHEF_DE_PROJET"
    if "CHEF" in normalized:
        return "CHEF_DE_PROJET"
    # Les anciens administrateurs intermédiaires ne gardent aucun privilège global.
    return "MEMBRE"


def initialize_database(target_engine=engine):
    """Create new tables and safely backfill legacy ownership without dropping rows."""
    Base.metadata.create_all(bind=target_engine)
    if target_engine.dialect.name != "sqlite":
        raise RuntimeError("La migration initiale des espaces est prévue pour SQLite; utilisez Alembic pour un autre moteur.")

    super_email = os.getenv("SUPER_ADMIN_EMAIL", "").strip().lower()
    with target_engine.begin() as connection:
        column_map = {
            "projets": {
                "workspace_id": "INTEGER REFERENCES workspaces(id) ON DELETE CASCADE",
                "owner_id": "INTEGER REFERENCES utilisateurs(id) ON DELETE RESTRICT",
                "objectifs": "TEXT NOT NULL DEFAULT ''",
                "resultats_attendus": "TEXT NOT NULL DEFAULT ''",
            },
            "messages_partage": {
                "workspace_id": "INTEGER REFERENCES workspaces(id) ON DELETE CASCADE",
                "project_id": "INTEGER REFERENCES projets(id) ON DELETE CASCADE",
            },
            "utilisateurs": {
                "prenom": "VARCHAR",
                "password_changed_at": "DATETIME",
                "password_bootstrapped": "BOOLEAN NOT NULL DEFAULT 0",
                "session_version": "INTEGER NOT NULL DEFAULT 0",
            },
        }
        inspector = inspect(connection)
        for table, columns in column_map.items():
            existing = {item["name"] for item in inspector.get_columns(table)}
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}'))

        connection.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (revision VARCHAR PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL)"))

        users = connection.execute(text("SELECT id, nom, email, role FROM utilisateurs")).mappings().all()
        chefs = []
        for user in users:
            role = _canonical_role(user["role"], user["email"], super_email)
            connection.execute(text("UPDATE utilisateurs SET role=:role WHERE id=:id"), {"role": role, "id": user["id"]})
            if role == "CHEF_DE_PROJET":
                chefs.append(user)
                existing = connection.execute(
                    text("SELECT id FROM workspaces WHERE owner_user_id=:owner"), {"owner": user["id"]}
                ).first()
                if not existing:
                    result = connection.execute(
                        text("INSERT INTO workspaces (name, owner_user_id) VALUES (:name, :owner)"),
                        {"name": f"Espace de {user['nom'] or user['email']}", "owner": user["id"]},
                    )
                    workspace_id = result.lastrowid
                else:
                    workspace_id = existing[0]
                connection.execute(
                    text("INSERT OR IGNORE INTO workspace_memberships (user_id, workspace_id, role, can_manage_tasks) VALUES (:user, :workspace, 'CHEF_DE_PROJET', 1)"),
                    {"user": user["id"], "workspace": workspace_id},
                )

        # Enforce the singleton owner invariant in SQLite as well as in the
        # login bootstrap path, including concurrent bootstrap attempts.
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_utilisateurs_one_super_admin "
            "ON utilisateurs ((1)) "
            "WHERE upper(replace(trim(role), ' ', '_')) = 'SUPER_ADMIN'"
        ))

        workspaces = connection.execute(text("SELECT id, owner_user_id FROM workspaces")).all()
        # If the former creator account is the only historical project owner, retain
        # old members and records in a clearly named legacy workspace without making
        # the super administrator a member or granting ordinary users global access.
        super_user = next((u for u in users if _canonical_role(u["role"], u["email"], super_email) == "SUPER_ADMIN"), None)
        non_super_users = [u for u in users if _canonical_role(u["role"], u["email"], super_email) != "SUPER_ADMIN"]
        legacy_project_count = connection.execute(text("SELECT COUNT(*) FROM projets")).scalar_one()
        if not workspaces and super_user and (non_super_users or legacy_project_count):
            result = connection.execute(
                text("INSERT INTO workspaces (name, owner_user_id) VALUES ('Espace historique', :owner)"),
                {"owner": super_user["id"]},
            )
            workspaces = [(result.lastrowid, super_user["id"])]
        workspace_by_owner = {owner: workspace_id for workspace_id, owner in workspaces}
        # Only infer old project ownership when its responsible matches a chef, or when
        # exactly one project workspace exists. Ambiguous records stay unassigned.
        chef_by_label = {}
        for chef in chefs:
            for label in (chef["email"], chef["nom"]):
                if label:
                    chef_by_label[label.strip().casefold()] = chef
        for project in connection.execute(text("SELECT id, responsable, workspace_id FROM projets")).mappings():
            responsable = (project["responsable"] or "").strip().casefold()
            owner = chef_by_label.get(responsable)
            if not owner and len(workspaces) == 1:
                owner = next((user for user in users if user["id"] == workspaces[0][1]), None)
            if owner:
                connection.execute(
                    text("UPDATE projets SET workspace_id=:workspace, owner_id=:owner WHERE id=:id AND workspace_id IS NULL"),
                    {"workspace": workspace_by_owner[owner["id"]], "owner": owner["id"], "id": project["id"]},
                )

        if len(workspaces) > 1 and super_user:
            assigned_ids = {
                row[0] for row in connection.execute(text("SELECT user_id FROM workspace_memberships")).all()
            }
            orphan_users = [u for u in non_super_users if u["id"] not in assigned_ids]
            if orphan_users:
                historical = connection.execute(
                    text("SELECT id FROM workspaces WHERE owner_user_id=:owner"),
                    {"owner": super_user["id"]},
                ).first()
                if historical:
                    historical_workspace_id = historical[0]
                else:
                    result = connection.execute(
                        text("INSERT INTO workspaces (name, owner_user_id) VALUES ('Espace historique à attribuer', :owner)"),
                        {"owner": super_user["id"]},
                    )
                    historical_workspace_id = result.lastrowid
                for user in orphan_users:
                    role = _canonical_role(user["role"], user["email"], super_email)
                    connection.execute(
                        text("INSERT OR IGNORE INTO workspace_memberships (user_id, workspace_id, role, can_manage_tasks) VALUES (:user, :workspace, :role, 0)"),
                        {"user": user["id"], "workspace": historical_workspace_id, "role": role},
                    )
                    connection.execute(
                        text("UPDATE messages_partage SET workspace_id=:workspace WHERE user_id=:user AND workspace_id IS NULL"),
                        {"workspace": historical_workspace_id, "user": user["id"]},
                    )

        # Existing members can be assigned without guessing only when there is one
        # unambiguous legacy workspace. Otherwise leave them unattached for admin review.
        if len(workspaces) == 1:
            workspace_id = workspaces[0][0]
            for user in users:
                role = _canonical_role(user["role"], user["email"], super_email)
                if role != "SUPER_ADMIN":
                    connection.execute(
                        text("INSERT OR IGNORE INTO workspace_memberships (user_id, workspace_id, role, can_manage_tasks) VALUES (:user, :workspace, :role, 0)"),
                        {"user": user["id"], "workspace": workspace_id, "role": role},
                    )
            connection.execute(
                text("UPDATE messages_partage SET workspace_id=:workspace WHERE workspace_id IS NULL"),
                {"workspace": workspace_id},
            )

        connection.execute(text("INSERT OR IGNORE INTO schema_migrations (revision) VALUES ('0001_workspaces')"))
        connection.execute(text("INSERT OR IGNORE INTO schema_migrations (revision) VALUES ('0002_collaboration')"))
        connection.execute(text("INSERT OR IGNORE INTO schema_migrations (revision) VALUES ('0003_single_super_admin')"))


if __name__ == "__main__":
    initialize_database()
