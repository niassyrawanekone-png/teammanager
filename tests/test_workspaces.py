import os
import sys
import unittest
import asyncio
import json
import wave
from io import BytesIO
from types import SimpleNamespace

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "site-packages"))
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable
from fastapi import HTTPException
from starlette.datastructures import Headers, UploadFile
from starlette.requests import Request
from unittest.mock import MagicMock, patch
from scripts.recover_super_admin import recover_super_admin_password

import database
import main


class DatabaseDialectTests(unittest.TestCase):
    def test_production_frontend_is_allowed_even_when_render_cors_is_customized(self):
        origins = main._allowed_cors_origins("https://custom.example")
        self.assertIn("https://custom.example", origins)
        self.assertIn("https://teammanager-frontend-rawaneproject.vercel.app", origins)
        self.assertEqual(len(origins), len(set(origins)))

    def test_render_postgres_urls_select_psycopg_three(self):
        for value in (
            "postgres://db-user:placeholder@db.example/team_manager",
            "postgresql://db-user:placeholder@db.example/team_manager",
        ):
            normalized = database._normalize_database_url(value)
            self.assertEqual(normalized.drivername, "postgresql+psycopg")
            self.assertEqual(normalized.host, "db.example")
            self.assertEqual(normalized.database, "team_manager")
            self.assertEqual(normalized.password, "placeholder")

    def test_psycopg_engine_can_be_constructed_without_connecting(self):
        engine = create_engine(database._normalize_database_url("postgresql://db.example/team_manager"))
        try:
            self.assertEqual(engine.dialect.name, "postgresql")
            self.assertEqual(engine.dialect.driver, "psycopg")
        finally:
            engine.dispose()

    def test_sqlite_fallback_and_psycopg_specific_urls_are_preserved(self):
        fallback = database._normalize_database_url("sqlite:///./database.db")
        configured = database._normalize_database_url("postgresql+psycopg://db.example/team_manager")
        self.assertEqual(fallback.drivername, "sqlite")
        self.assertEqual(fallback.database, "./database.db")
        self.assertEqual(configured.drivername, "postgresql+psycopg")

    def test_all_model_tables_compile_for_postgresql(self):
        expected = {
            "utilisateurs", "projets", "workspaces", "workspace_memberships",
            "messages_partage", "message_reads", "message_attachments", "tasks",
            "notifications", "ai_usage", "password_reset_tokens",
            "password_reset_attempts", "account_invitation_tokens", "schema_migrations",
        }
        self.assertEqual(set(database.Base.metadata.tables), expected)
        statements = [
            str(CreateTable(table).compile(dialect=postgresql.dialect()))
            for table in database.Base.metadata.sorted_tables
        ]
        self.assertTrue(all("DATETIME" not in statement for statement in statements))

    def test_idempotent_insert_and_super_admin_index_compile_for_both_dialects(self):
        for dialect in (sqlite.dialect(), postgresql.dialect()):
            connection = SimpleNamespace(dialect=dialect)
            membership = database._insert_ignore_statement(
                connection,
                "workspace_memberships",
                {"user_id": 7, "workspace_id": 3, "role": "MEMBRE", "can_manage_tasks": False},
                ("user_id",),
            )
            sql = str(membership.compile(dialect=dialect))
            self.assertIn("ON CONFLICT", sql)
            self.assertIn("DO NOTHING", sql)
            index_sql = database._super_admin_index_ddl(dialect)
            self.assertIn("CREATE UNIQUE INDEX IF NOT EXISTS", index_sql)
            self.assertIn("WHERE", index_sql)
            self.assertIn("upper", index_sql.lower())
            self.assertIn("SUPER_ADMIN", index_sql)

    def test_postgresql_generated_ids_use_returning(self):
        class Result:
            def scalar_one(self):
                return 41

        class Connection:
            dialect = postgresql.dialect()

            def execute(self, statement):
                self.sql = str(statement.compile(dialect=self.dialect))
                return Result()

        connection = Connection()
        value = database._insert_id(
            connection, "workspaces", {"name": "Test workspace", "owner_user_id": 41}
        )
        self.assertEqual(value, 41)
        self.assertIn("RETURNING workspaces.id", connection.sql)

    def test_postgresql_legacy_alter_types_are_compatible(self):
        columns = database._legacy_column_definitions("postgresql")
        self.assertEqual(columns["utilisateurs"]["password_changed_at"], "TIMESTAMP")
        self.assertIn("BOOLEAN NOT NULL DEFAULT FALSE", columns["utilisateurs"]["password_bootstrapped"])
        self.assertNotIn("DATETIME", str(columns))

    def test_empty_sqlite_initialization_creates_all_tables_and_is_repeatable(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            database.initialize_database(engine)
            database.initialize_database(engine)
            with engine.connect() as connection:
                inspector = __import__("sqlalchemy").inspect(connection)
                self.assertEqual(set(database.Base.metadata.tables), set(inspector.get_table_names()))
                revisions = connection.execute(text("SELECT COUNT(*) FROM schema_migrations")).scalar_one()
                self.assertEqual(revisions, 4)
                indexes = connection.execute(text(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )).scalars().all()
                self.assertIn("uq_utilisateurs_one_super_admin", indexes)
        finally:
            engine.dispose()

    def test_attachment_column_is_added_to_existing_schema_idempotently(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with engine.begin() as connection:
                connection.execute(text("CREATE TABLE message_attachments (id INTEGER PRIMARY KEY)"))
            database.initialize_database(engine)
            database.initialize_database(engine)
            columns = {column["name"] for column in __import__("sqlalchemy").inspect(engine).get_columns("message_attachments")}
            self.assertIn("content_data", columns)
        finally:
            engine.dispose()

    def test_duplicate_super_admins_fail_before_schema_or_role_changes(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            with engine.begin() as connection:
                connection.execute(text(
                    "CREATE TABLE utilisateurs (id INTEGER PRIMARY KEY, nom VARCHAR, "
                    "email VARCHAR NOT NULL, hashed_password VARCHAR NOT NULL, role VARCHAR NOT NULL)"
                ))
                connection.execute(text(
                    "INSERT INTO utilisateurs (id, nom, email, hashed_password, role) VALUES "
                    "(1, 'A', 'a@example.test', 'hash-a', 'SUPER_ADMIN'), "
                    "(2, 'B', 'b@example.test', 'hash-b', 'Super Admin')"
                ))
            with self.assertRaisesRegex(RuntimeError, "plusieurs comptes super-administrateur"):
                database.initialize_database(engine)
            with engine.connect() as connection:
                roles = connection.execute(text("SELECT role FROM utilisateurs ORDER BY id")).scalars().all()
                self.assertEqual(roles, ["SUPER_ADMIN", "Super Admin"])
                self.assertNotIn("schema_migrations", __import__("sqlalchemy").inspect(connection).get_table_names())
        finally:
            engine.dispose()


class TransactionalEmailTests(unittest.TestCase):
    def setUp(self):
        self.original_env = {
            key: os.environ.get(key)
            for key in (
                "SMTP_FROM", "APP_BASE_URL", "SMTP_HOST", "MAILJET_API_KEY",
                "MAILJET_API_SECRET",
            )
        }
        for key in self.original_env:
            os.environ.pop(key, None)

    def tearDown(self):
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_mailjet_api_configuration_enables_transactional_email(self):
        os.environ["SMTP_FROM"] = "Team Manager <verified@example.com>"
        os.environ["APP_BASE_URL"] = "https://team.example.com"
        os.environ["MAILJET_API_KEY"] = "public-test-key"
        os.environ["MAILJET_API_SECRET"] = "private-test-secret"
        self.assertTrue(main._email_transport_configured())

    def test_mailjet_api_sends_transactional_plain_text_message(self):
        os.environ["SMTP_FROM"] = "Team Manager <verified@example.com>"
        os.environ["APP_BASE_URL"] = "https://team.example.com"
        os.environ["MAILJET_API_KEY"] = "public-test-key"
        os.environ["MAILJET_API_SECRET"] = "private-test-secret"
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"Messages":[{"Status":"success"}]}'

        with patch.object(main.urllib.request, "urlopen", return_value=response) as send:
            result = main._send_configured_email(
                "recipient@example.com", "Invitation", "Use this link."
            )

        self.assertTrue(result)
        request = send.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.mailjet.com/v3.1/send")
        self.assertEqual(request.get_method(), "POST")
        payload = json.loads(request.data)
        message = payload["Messages"][0]
        self.assertEqual(message["From"], {
            "Email": "verified@example.com", "Name": "Team Manager",
        })
        self.assertEqual(message["To"], [{"Email": "recipient@example.com"}])
        self.assertEqual(message["Subject"], "Invitation")
        self.assertEqual(message["TextPart"], "Use this link.")
        self.assertTrue(request.get_header("Authorization").startswith("Basic "))

    def test_mailjet_api_rejection_is_reported_as_failed_delivery(self):
        os.environ["SMTP_FROM"] = "Team Manager <verified@example.com>"
        os.environ["APP_BASE_URL"] = "https://team.example.com"
        os.environ["MAILJET_API_KEY"] = "public-test-key"
        os.environ["MAILJET_API_SECRET"] = "private-test-secret"
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"Messages":[{"Status":"error"}]}'
        with patch.object(main.urllib.request, "urlopen", return_value=response):
            self.assertFalse(main._send_configured_email(
                "recipient@example.com", "Invitation", "Use this link."
            ))


class WorkspaceMigrationTests(unittest.TestCase):
    def setUp(self):
        os.environ["SUPER_ADMIN_EMAIL"] = "owner@gmail.com"
        self.engine = create_engine("sqlite:///:memory:")
        with self.engine.begin() as conn:
            conn.execute(text("CREATE TABLE utilisateurs (id INTEGER PRIMARY KEY, nom VARCHAR, email VARCHAR UNIQUE NOT NULL, hashed_password VARCHAR NOT NULL, role VARCHAR)"))
            conn.execute(text("CREATE TABLE projets (id INTEGER PRIMARY KEY, titre VARCHAR, description VARCHAR, statut VARCHAR, responsable VARCHAR)"))
            conn.execute(text("CREATE TABLE messages_partage (id INTEGER PRIMARY KEY, contenu TEXT NOT NULL, created_at DATETIME, user_id INTEGER)"))
            conn.execute(text("INSERT INTO utilisateurs VALUES (1,'Lead','lead@gmail.com','hash','Chef de Projet')"))
            conn.execute(text("INSERT INTO utilisateurs VALUES (2,'Member','member@gmail.com','hash','Membre')"))
            conn.execute(text("INSERT INTO projets VALUES (7,'Legacy','Line one'||char(10)||'Line two','En cours','Lead')"))
            conn.execute(text("INSERT INTO messages_partage VALUES (9,'Legacy message',CURRENT_TIMESTAMP,2)"))
        database.initialize_database(self.engine)
        self.db = Session(self.engine)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_migration_is_repeatable_and_preserves_legacy_records(self):
        database.initialize_database(self.engine)
        self.assertEqual(self.db.query(database.UtilisateurDB).count(), 2)
        self.assertEqual(self.db.query(database.ProjetDB).count(), 1)
        self.assertEqual(self.db.query(database.MessagePartageDB).count(), 1)
        project = self.db.get(database.ProjetDB, 7)
        self.assertIn("\n", project.description)
        self.assertEqual(project.owner_id, 1)
        self.assertEqual(self.db.query(database.WorkspaceMembershipDB).count(), 2)

    def test_registration_creates_a_distinct_empty_project_lead_workspace(self):
        user = main.inscrire(main.UtilisateurCreate(
            nom="Second Lead", email="second@gmail.com", password="strong-password",
            role="SUPER_ADMIN",
        ), self.db)
        membership = self.db.query(database.WorkspaceMembershipDB).filter_by(user_id=user.id).one()
        self.assertEqual(user.role, "CHEF_DE_PROJET")
        self.assertNotEqual(membership.workspace_id, self.db.get(database.ProjetDB, 7).workspace_id)
        self.assertEqual(self.db.query(database.ProjetDB).filter_by(workspace_id=membership.workspace_id).count(), 0)

    def test_bootstrap_environment_cannot_promote_a_second_super_admin(self):
        os.environ["JWT_SECRET_KEY"] = "t" * 48
        os.environ["SUPER_ADMIN_EMAIL"] = "ordinary@gmail.com"
        os.environ["SUPER_ADMIN_PASSWORD"] = "bootstrap-password"
        owner = database.UtilisateurDB(
            nom="Owner", email="owner@gmail.com", role="SUPER_ADMIN",
            hashed_password=main.security.hash_password("owner-password"),
        )
        ordinary = database.UtilisateurDB(
            nom="Ordinary", email="ordinary@gmail.com", role="MEMBRE",
            hashed_password=main.security.hash_password("ordinary-password"),
        )
        self.db.add_all([owner, ordinary])
        self.db.commit()
        with self.assertRaises(HTTPException) as denied:
            main.connecter(type("Credentials", (), {
                "username": "ordinary@gmail.com", "password": "bootstrap-password",
            })(), self.db)
        self.assertEqual(denied.exception.status_code, 401)
        self.db.refresh(ordinary)
        self.assertEqual(ordinary.role, "MEMBRE")
        self.assertEqual(self.db.query(database.UtilisateurDB).filter_by(role="SUPER_ADMIN").count(), 1)

    def test_owner_recovery_changes_only_existing_owner_and_revokes_sessions(self):
        owner = database.UtilisateurDB(
            nom="Owner", email="owner@gmail.com", role="SUPER_ADMIN",
            hashed_password=main.security.hash_password("old-owner-password"), session_version=3,
        )
        self.db.add(owner)
        self.db.commit()
        recover_super_admin_password(self.db, "new-owner-password-123")
        self.db.refresh(owner)
        self.assertTrue(main.security.verify_password("new-owner-password-123", owner.hashed_password))
        self.assertEqual(owner.session_version, 4)
        self.assertEqual(self.db.query(database.UtilisateurDB).count(), 3)

    def test_legacy_role_migration_does_not_grant_super_from_substring(self):
        self.assertEqual(database._canonical_role("Supervisor", "person@example.test", ""), "MEMBRE")
        self.assertEqual(database._canonical_role("Super Admin", "owner@example.test", ""), "SUPER_ADMIN")

    def test_database_enforces_one_super_admin(self):
        self.db.add(database.UtilisateurDB(
            nom="First", email="first-owner@example.test", role="SUPER_ADMIN", hashed_password="hash",
        ))
        self.db.commit()
        self.db.add(database.UtilisateurDB(
            nom="Second", email="second-owner@example.test", role="SUPER_ADMIN", hashed_password="hash",
        ))
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_project_listing_is_scoped_and_super_admin_is_global_read_only(self):
        user_b = main.inscrire(main.UtilisateurCreate(
            nom="Second Lead", email="second@gmail.com", password="strong-password",
        ), self.db)
        project_b = main.ajouter_projet(main.ProjetCreate(
            titre="B", description="Paragraph one\nParagraph two",
        ), self.db, user_b)
        legacy_lead = self.db.get(database.UtilisateurDB, 1)
        projects_a = main.lister_projets(self.db, legacy_lead)
        projects_b = main.lister_projets(self.db, user_b)
        self.assertEqual([p.id for p in projects_a], [7])
        self.assertEqual([p.id for p in projects_b], [project_b.id])
        super_user = database.UtilisateurDB(
            nom="Global", email="owner@gmail.com", role="SUPER_ADMIN", hashed_password="hash",
        )
        self.db.add(super_user)
        self.db.commit()
        self.assertEqual(len(main.lister_projets(self.db, super_user)), 2)
        self.assertIn("\n", project_b.description)

    def test_global_admin_routes_reject_non_super_users(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        with self.assertRaises(HTTPException) as denied_stats:
            main.administrer_statistiques(self.db, lead)
        self.assertEqual(denied_stats.exception.status_code, 403)
        with self.assertRaises(HTTPException) as denied_workspace:
            main.administrer_creer_espace(
                main.AdminWorkspaceCreate(name="Denied", owner_user_id=2), self.db, lead,
            )
        self.assertEqual(denied_workspace.exception.status_code, 403)
        self.assertEqual(self.db.query(database.WorkspaceDB).count(), 1)

    def test_super_admin_account_deletion_requires_and_cleans_owned_workspace(self):
        super_admin = database.UtilisateurDB(
            nom="Global", email="super-owner@gmail.com", role="SUPER_ADMIN",
            hashed_password="hash",
        )
        self.db.add(super_admin)
        self.db.commit()
        owner = self.db.get(database.UtilisateurDB, 1)
        member = self.db.get(database.UtilisateurDB, 2)
        workspace = self.db.query(database.WorkspaceDB).filter_by(owner_user_id=owner.id).one()
        project = self.db.query(database.ProjetDB).filter_by(workspace_id=workspace.id).one()
        message = self.db.query(database.MessagePartageDB).filter_by(workspace_id=workspace.id).one()
        workspace_id, project_id, message_id = workspace.id, project.id, message.id
        attachment = database.MessageAttachmentDB(
            message_id=message.id, object_key="test/audio.wav", original_name="audio.wav",
            content_type="audio/wav", size_bytes=46, created_at=main._utc_now_naive(),
            content_data=b"RIFF",
        )
        task = database.TaskDB(
            workspace_id=workspace.id, project_id=project.id, title="Task",
            description="", priority="NORMAL", status="TODO",
            created_at=main._utc_now_naive(), updated_at=main._utc_now_naive(),
        )
        self.db.add_all([attachment, task])
        self.db.commit()
        owner_id, member_id = owner.id, member.id
        attachment_id, task_id = attachment.id, task.id

        with self.assertRaises(HTTPException) as missing_confirmation:
            main.administrer_supprimer_utilisateur(
                owner.id, main.AdminUserDelete(), self.db, super_admin,
            )
        self.assertEqual(missing_confirmation.exception.status_code, 409)
        with self.assertRaises(HTTPException) as other_members:
            main.administrer_supprimer_utilisateur(
                owner.id, main.AdminUserDelete(delete_workspace=True), self.db, super_admin,
            )
        self.assertEqual(other_members.exception.status_code, 409)
        with self.assertRaises(HTTPException) as protected_admin:
            main.administrer_supprimer_utilisateur(
                super_admin.id, main.AdminUserDelete(delete_workspace=True), self.db, super_admin,
            )
        self.assertEqual(protected_admin.exception.status_code, 409)

        self.db.delete(main.security.get_membership(self.db, member))
        self.db.commit()
        main.administrer_supprimer_utilisateur(
            owner.id, main.AdminUserDelete(delete_workspace=True), self.db, super_admin,
        )

        self.db.expire_all()
        self.assertIsNone(self.db.get(database.UtilisateurDB, owner_id))
        self.assertIsNone(self.db.get(database.WorkspaceDB, workspace_id))
        self.assertIsNone(self.db.get(database.ProjetDB, project_id))
        self.assertIsNone(self.db.get(database.MessagePartageDB, message_id))
        self.assertIsNone(self.db.get(database.MessageAttachmentDB, attachment_id))
        self.assertIsNone(self.db.get(database.TaskDB, task_id))
        self.assertIsNotNone(self.db.get(database.UtilisateurDB, member_id))

    def test_super_admin_can_transfer_workspace_owner_without_crossing_workspaces(self):
        owner = database.UtilisateurDB(
            nom="Global", email="owner@gmail.com", role="SUPER_ADMIN", hashed_password="hash",
        )
        self.db.add(owner)
        self.db.commit()
        workspace = self.db.query(database.WorkspaceDB).filter_by(owner_user_id=1).one()
        member = self.db.get(database.UtilisateurDB, 2)

        changed = main.administrer_modifier_espace(
            workspace.id, main.AdminWorkspaceUpdate(name="Renamed", new_owner_user_id=member.id),
            self.db, owner,
        )
        self.assertEqual(changed["name"], "Renamed")
        self.assertEqual(changed["owner_user_id"], member.id)
        self.assertEqual(member.role, "CHEF_DE_PROJET")
        self.assertEqual(self.db.get(database.UtilisateurDB, 1).role, "MEMBRE")

        outsider = main.inscrire(main.UtilisateurCreate(
            nom="Outside", email="outside@gmail.com", password="strong-password",
        ), self.db)
        with self.assertRaises(HTTPException) as denied_transfer:
            main.administrer_modifier_espace(
                workspace.id, main.AdminWorkspaceUpdate(new_owner_user_id=outsider.id),
                self.db, owner,
            )
        self.assertEqual(denied_transfer.exception.status_code, 422)

    def test_global_project_creation_is_scoped_to_explicit_existing_workspace(self):
        owner = database.UtilisateurDB(
            nom="Global", email="owner@gmail.com", role="SUPER_ADMIN", hashed_password="hash",
        )
        self.db.add(owner)
        self.db.commit()
        workspace_b_owner = main.inscrire(main.UtilisateurCreate(
            nom="Second Lead", email="second@gmail.com", password="strong-password",
        ), self.db)
        workspace_b = self.db.query(database.WorkspaceMembershipDB).filter_by(user_id=workspace_b_owner.id).one()

        with self.assertRaises(HTTPException) as denied:
            main.administrer_creer_projet(
                main.AdminProjectCreate(workspace_id=workspace_b.workspace_id, titre="Denied"),
                self.db, workspace_b_owner,
            )
        self.assertEqual(denied.exception.status_code, 403)
        project = main.administrer_creer_projet(
            main.AdminProjectCreate(workspace_id=workspace_b.workspace_id, titre="Global project"),
            self.db, owner,
        )
        projects_a = main.lister_projets(self.db, self.db.get(database.UtilisateurDB, 1))
        self.assertNotIn(project.id, [item.id for item in projects_a])

    def test_lead_cannot_promote_member_to_privileged_or_mutate_other_workspace(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        member = self.db.get(database.UtilisateurDB, 2)
        with self.assertRaises(HTTPException) as denied_role:
            main.modifier_role(member.id, main.RoleUpdate(role="SUPER_ADMIN"), self.db, lead)
        self.assertEqual(denied_role.exception.status_code, 422)
        outsider = main.inscrire(main.UtilisateurCreate(
            nom="Outside", email="outside@gmail.com", password="strong-password",
        ), self.db)
        with self.assertRaises(HTTPException) as denied_project:
            main.modifier_projet(7, main.ProjetCreate(titre="Tampered"), self.db, outsider)
        self.assertEqual(denied_project.exception.status_code, 404)

    def test_workspace_owner_is_protected_even_if_role_data_is_inconsistent(self):
        owner = self.db.get(database.UtilisateurDB, 1)
        owner.role = "MEMBRE"
        owner_membership = main.security.get_membership(self.db, owner)
        owner_membership.role = "MEMBRE"
        acting_lead = self.db.get(database.UtilisateurDB, 2)
        acting_lead.role = "CHEF_DE_PROJET"
        acting_membership = main.security.get_membership(self.db, acting_lead)
        acting_membership.role = "CHEF_DE_PROJET"
        self.db.commit()

        with self.assertRaises(HTTPException) as denied_role:
            main.modifier_role(owner.id, main.RoleUpdate(role="MEMBRE"), self.db, acting_lead)
        self.assertEqual(denied_role.exception.status_code, 403)
        with self.assertRaises(HTTPException) as denied_delete:
            main.supprimer_utilisateur(owner.id, self.db, acting_lead)
        self.assertEqual(denied_delete.exception.status_code, 403)
        self.assertIsNotNone(self.db.get(database.UtilisateurDB, owner.id))

    def test_message_deletion_permissions_follow_workspace_roles(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        member = self.db.get(database.UtilisateurDB, 2)
        workspace_id = main.security.get_membership(self.db, lead).workspace_id
        member_message = database.MessagePartageDB(
            contenu="Member message", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=workspace_id,
        )
        lead_message = database.MessagePartageDB(
            contenu="Lead message", created_at=main._utc_now_naive(), user_id=lead.id,
            workspace_id=workspace_id,
        )
        self.db.add_all([member_message, lead_message])
        self.db.commit()

        with self.assertRaises(HTTPException) as denied:
            main.supprimer_message_partage(lead_message.id, self.db, member)
        self.assertEqual(denied.exception.status_code, 403)
        self.assertIsNotNone(self.db.get(database.MessagePartageDB, lead_message.id))

        self.assertIsNone(main.supprimer_message_partage(member_message.id, self.db, member))
        self.assertIsNone(self.db.get(database.MessagePartageDB, member_message.id))

        team_message = database.MessagePartageDB(
            contenu="Team message", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=workspace_id,
        )
        self.db.add(team_message)
        self.db.commit()
        self.assertIsNone(main.supprimer_message_partage(team_message.id, self.db, lead))
        self.assertIsNone(self.db.get(database.MessagePartageDB, team_message.id))

        super_admin = database.UtilisateurDB(
            nom="Global", email="super-owner@gmail.com", role="SUPER_ADMIN",
            hashed_password="hash",
        )
        self.db.add(super_admin)
        self.db.commit()
        self.assertIsNone(main.supprimer_message_partage(lead_message.id, self.db, super_admin))
        self.assertIsNone(self.db.get(database.MessagePartageDB, lead_message.id))

    def test_voice_attachment_is_private_validated_and_workspace_scoped(self):
        member = self.db.get(database.UtilisateurDB, 2)
        membership = main.security.get_membership(self.db, member)
        message = database.MessagePartageDB(
            contenu="Message vocal", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=membership.workspace_id,
        )
        self.db.add(message)
        self.db.commit()
        upload = UploadFile(
            file=BytesIO(b"\x1aE\xdf\xa3" + b"\x00" * 20), filename="recording.webm",
            headers=Headers({"content-type": "audio/webm;codecs=opus"}),
        )
        result = asyncio.run(main.ajouter_audio_message(message.id, upload, self.db, member))
        self.assertEqual(result["content_type"], "audio/webm")
        self.assertEqual(result["url"], f"/partage/attachments/{result['id']}")
        self.assertEqual(self.db.query(database.MessageAttachmentDB).filter_by(message_id=message.id).count(), 1)
        attachment = self.db.get(database.MessageAttachmentDB, result["id"])
        self.assertEqual(attachment.content_data, b"\x1aE\xdf\xa3" + b"\x00" * 20)
        playback = main.lire_piece_jointe_partage(attachment.id, self.db, member)
        self.assertEqual(playback.body, attachment.content_data)
        self.assertEqual(playback.media_type, "audio/webm")

        outsider = main.inscrire(main.UtilisateurCreate(
            nom="Outside", email="audio-outsider@gmail.com", password="strong-password",
        ), self.db)
        foreign_upload = UploadFile(
            file=BytesIO(b"\x1aE\xdf\xa3" + b"\x00" * 20), filename="recording.webm",
            headers=Headers({"content-type": "audio/webm"}),
        )
        with self.assertRaises(HTTPException) as denied:
            asyncio.run(main.ajouter_audio_message(message.id, foreign_upload, self.db, outsider))
        self.assertEqual(denied.exception.status_code, 404)

    def test_voice_attachment_rejects_mime_spoofing(self):
        member = self.db.get(database.UtilisateurDB, 2)
        membership = main.security.get_membership(self.db, member)
        message = database.MessagePartageDB(
            contenu="Message vocal", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=membership.workspace_id,
        )
        self.db.add(message)
        self.db.commit()
        upload = UploadFile(
            file=BytesIO(b"this is not an audio container"), filename="recording.webm",
            headers=Headers({"content-type": "audio/webm"}),
        )
        with self.assertRaises(HTTPException) as denied:
            asyncio.run(main.ajouter_audio_message(message.id, upload, self.db, member))
        self.assertEqual(denied.exception.status_code, 415)

    def test_wav_voice_attachment_is_saved_and_served(self):
        member = self.db.get(database.UtilisateurDB, 2)
        membership = main.security.get_membership(self.db, member)
        message = database.MessagePartageDB(
            contenu="Message vocal WAV", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=membership.workspace_id,
        )
        self.db.add(message)
        self.db.commit()
        audio = BytesIO()
        with wave.open(audio, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(b"\x00\x00" * 160)
        audio_bytes = audio.getvalue()
        upload = UploadFile(
            file=BytesIO(audio_bytes), filename="recording.wav",
            headers=Headers({"content-type": "audio/wav"}),
        )

        result = asyncio.run(main.ajouter_audio_message(message.id, upload, self.db, member))

        self.assertEqual(result["content_type"], "audio/wav")
        self.assertTrue(result["original_name"].endswith(".wav"))
        attachment = self.db.get(database.MessageAttachmentDB, result["id"])
        self.assertEqual(attachment.content_data, audio_bytes)
        playback = main.lire_piece_jointe_partage(attachment.id, self.db, member)
        self.assertEqual(playback.body, audio_bytes)
        self.assertEqual(playback.media_type, "audio/wav")

    def test_wav_voice_attachment_is_saved_and_served(self):
        member = self.db.get(database.UtilisateurDB, 2)
        membership = main.security.get_membership(self.db, member)
        message = database.MessagePartageDB(
            contenu="Message vocal WAV", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=membership.workspace_id,
        )
        self.db.add(message)
        self.db.commit()
        audio = BytesIO()
        with wave.open(audio, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(b"\x00\x00" * 160)
        audio_bytes = audio.getvalue()
        upload = UploadFile(
            file=BytesIO(audio_bytes), filename="recording.wav",
            headers=Headers({"content-type": "audio/wav"}),
        )

        result = asyncio.run(main.ajouter_audio_message(message.id, upload, self.db, member))

        self.assertEqual(result["content_type"], "audio/wav")
        self.assertTrue(result["original_name"].endswith(".wav"))
        attachment = self.db.get(database.MessageAttachmentDB, result["id"])
        self.assertEqual(attachment.content_data, audio_bytes)
        playback = main.lire_piece_jointe_partage(attachment.id, self.db, member)
        self.assertEqual(playback.body, audio_bytes)
        self.assertEqual(playback.media_type, "audio/wav")

    def test_photo_attachment_bytes_are_persisted_and_playable(self):
        member = self.db.get(database.UtilisateurDB, 2)
        membership = main.security.get_membership(self.db, member)
        message = database.MessagePartageDB(
            contenu="Photo", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=membership.workspace_id,
        )
        self.db.add(message)
        self.db.commit()
        image_bytes = b"\x89PNG\r\n\x1a\n"
        upload = UploadFile(
            file=BytesIO(image_bytes), filename="image.png",
            headers=Headers({"content-type": "image/png"}),
        )
        result = asyncio.run(main.ajouter_photo_message(message.id, upload, self.db, member))
        attachment = self.db.get(database.MessageAttachmentDB, result["id"])
        self.assertEqual(attachment.content_data, image_bytes)
        self.assertEqual(result["url"], f"/partage/attachments/{attachment.id}")
        self.assertEqual(main.lire_piece_jointe_partage(attachment.id, self.db, member).body, image_bytes)

    def test_voice_attachment_persists_without_s3_configuration(self):
        member = self.db.get(database.UtilisateurDB, 2)
        membership = main.security.get_membership(self.db, member)
        message = database.MessagePartageDB(
            contenu="Message vocal", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=membership.workspace_id,
        )
        self.db.add(message)
        self.db.commit()
        upload = UploadFile(
            file=BytesIO(b"\x1aE\xdf\xa3" + b"\x00" * 20), filename="recording.webm",
            headers=Headers({"content-type": "audio/webm"}),
        )
        result = asyncio.run(main.ajouter_audio_message(message.id, upload, self.db, member))
        self.assertEqual(result["content_type"], "audio/webm")
        self.assertEqual(self.db.query(database.MessageAttachmentDB).filter_by(message_id=message.id).count(), 1)

    def test_attachment_playback_is_workspace_scoped(self):
        member = self.db.get(database.UtilisateurDB, 2)
        membership = main.security.get_membership(self.db, member)
        message = database.MessagePartageDB(
            contenu="Photo", created_at=main._utc_now_naive(), user_id=member.id,
            workspace_id=membership.workspace_id,
        )
        self.db.add(message)
        self.db.flush()
        attachment = database.MessageAttachmentDB(
            message_id=message.id, object_key="postgresql://test", original_name="photo.png",
            content_type="image/png", size_bytes=8, content_data=b"\x89PNG\r\n\x1a\n",
            created_at=main._utc_now_naive(),
        )
        self.db.add(attachment)
        self.db.commit()
        outsider = main.inscrire(main.UtilisateurCreate(
            nom="Outside", email="attachment-outsider@gmail.com", password="test-password-123",
        ), self.db)
        with self.assertRaises(HTTPException) as denied:
            main.lire_piece_jointe_partage(attachment.id, self.db, outsider)
        self.assertEqual(denied.exception.status_code, 404)


    def test_password_reset_is_hashed_single_use_and_revokes_old_sessions(self):
        os.environ["JWT_SECRET_KEY"] = "t" * 48
        os.environ["SMTP_HOST"] = "smtp.example.com"
        os.environ["SMTP_FROM"] = "team@example.com"
        os.environ["APP_BASE_URL"] = "https://team.example.com"
        user = main.inscrire(main.UtilisateurCreate(
            nom="Reset User", email="resetuser@gmail.com", password="original-password",
        ), self.db)
        old_token = main.security.create_access_token({"uid": user.id, "sub": user.email, "ver": user.session_version})
        request = Request({
            "type": "http", "method": "POST", "scheme": "http", "path": "/password/forgot",
            "query_string": b"", "headers": [], "server": ("localhost", 80),
            "client": ("127.0.0.1", 1234),
        })
        with patch.object(main, "_email_reset_token", return_value=True) as send:
            response = main.demander_reinitialisation(
                main.PasswordResetRequest(email=user.email), request, self.db,
            )
        self.assertIn("Si un compte correspond", response["message"])
        reset_token = send.call_args.args[1]
        main.confirmer_reinitialisation(main.PasswordResetConfirm(
            token=reset_token, nouveau_mot_de_passe="new-password-123",
            confirmation="new-password-123",
        ), self.db)
        refreshed = self.db.get(database.UtilisateurDB, user.id)
        self.assertTrue(main.security.verify_password("new-password-123", refreshed.hashed_password))
        self.assertEqual(refreshed.session_version, 1)
        with self.assertRaises(HTTPException):
            main.security.get_current_user(old_token, self.db)
        with self.assertRaises(HTTPException):
            main.confirmer_reinitialisation(main.PasswordResetConfirm(
                token=reset_token, nouveau_mot_de_passe="another-password-123",
                confirmation="another-password-123",
            ), self.db)

    def test_member_invitation_requires_email_and_activates_once(self):
        os.environ["SMTP_HOST"] = "smtp.example.com"
        os.environ["SMTP_FROM"] = "team@example.com"
        os.environ["APP_BASE_URL"] = "https://team.example.com"
        lead = self.db.get(database.UtilisateurDB, 1)
        with patch.object(main, "_email_account_invitation", return_value=True) as send:
            member = main.ajouter_utilisateur(main.UtilisateurCreate(
                prenom="New", nom="Member", email="invited@gmail.com",
                password="attacker-known-password", role="SOUS_CHEF_DE_PROJET",
            ), self.db, lead)
        invitation_token = send.call_args.args[2]
        self.assertEqual(member.role, "SOUS_CHEF_DE_PROJET")
        self.assertFalse(main.security.verify_password("attacker-known-password", member.hashed_password))
        main.accepter_invitation(main.InvitationAccept(
            token=invitation_token, nouveau_mot_de_passe="chosen-password-123",
            confirmation="chosen-password-123",
        ), self.db)
        self.assertTrue(main.security.verify_password("chosen-password-123", member.hashed_password))
        with self.assertRaises(HTTPException):
            main.accepter_invitation(main.InvitationAccept(
                token=invitation_token, nouveau_mot_de_passe="another-password-123",
                confirmation="another-password-123",
            ), self.db)

    def test_member_creation_stops_when_invitation_email_is_not_configured(self):
        for key in ("SMTP_HOST", "SMTP_FROM", "APP_BASE_URL"):
            os.environ.pop(key, None)
        lead = self.db.get(database.UtilisateurDB, 1)
        with self.assertRaises(HTTPException) as failure:
            main.ajouter_utilisateur(main.UtilisateurCreate(
                prenom="New", nom="Member", email="noinvite@gmail.com",
            ), self.db, lead)
        self.assertEqual(failure.exception.status_code, 503)
        self.assertIsNone(self.db.query(database.UtilisateurDB).filter_by(email="noinvite@gmail.com").first())
    def test_tasks_persist_and_assignee_can_update_only_status(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        member = self.db.get(database.UtilisateurDB, 2)
        task = main.creer_tache(main.TaskCreate(
            project_id=7, title="Write plan", description="Keep\nline breaks", assigned_to=member.id,
            priority="HIGH",
        ), self.db, lead)
        self.assertEqual(task.description, "Keep\nline breaks")
        self.assertEqual(main.lister_taches(7, self.db, member)[0].id, task.id)
        changed = main.changer_etat_tache(task.id, main.TaskStatusUpdate(status="DONE"), self.db, member)
        self.assertEqual(changed.status, "DONE")
        with self.assertRaises(HTTPException) as denied:
            main.modifier_tache(task.id, main.TaskUpdate(title="Tampered"), self.db, member)
        self.assertEqual(denied.exception.status_code, 403)

    def test_project_scoped_task_manager_cannot_delete_task_in_another_project(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        member = self.db.get(database.UtilisateurDB, 2)
        membership = self.db.query(database.WorkspaceMembershipDB).filter_by(user_id=member.id).one()
        membership.role = "SOUS_CHEF_DE_PROJET"
        membership.project_id = 7
        membership.can_manage_tasks = True
        member.role = "SOUS_CHEF_DE_PROJET"
        other_project = main.ajouter_projet(main.ProjetCreate(titre="Other project"), self.db, lead)
        task = main.creer_tache(main.TaskCreate(project_id=other_project.id, title="Protected task"), self.db, lead)

        with self.assertRaises(HTTPException) as denied:
            main.supprimer_tache(task.id, self.db, member)
        self.assertEqual(denied.exception.status_code, 404)
        self.assertIsNotNone(self.db.get(database.TaskDB, task.id))

    def test_task_status_endpoint_rejects_unknown_status(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        with self.assertRaises(HTTPException) as denied:
            main.changer_etat_tache(7, main.TaskStatusUpdate(status="ADMIN"), self.db, lead)
        self.assertEqual(denied.exception.status_code, 422)

    def test_message_read_state_is_per_user_and_workspace_scoped(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        member = self.db.get(database.UtilisateurDB, 2)
        message = main.publier_message_partage(main.MessageCreate(contenu="hello"), self.db, lead)
        self.assertEqual(main.compter_messages_non_lus("all", None, self.db, member)["count"], 1)
        self.assertEqual(main.marquer_messages_lus(main.MessageReadRequest(message_ids=[message["id"]]), self.db, member)["marked"], 1)
        self.assertEqual(main.compter_messages_non_lus("all", None, self.db, member)["count"], 0)
        self.assertEqual(main.compter_messages_non_lus("all", None, self.db, lead)["count"], 1)

    def test_ai_requires_provider_configuration(self):
        lead = self.db.get(database.UtilisateurDB, 1)
        os.environ.pop("AI_API_KEY", None)
        request = main.AssistantRequest(messages=[main.AssistantMessage(role="user", content="Plan")], project_id=7)
        with self.assertRaises(HTTPException) as unavailable:
            main.assistant_chat(request, self.db, lead)
        self.assertEqual(unavailable.exception.status_code, 503)

if __name__ == "__main__":
    unittest.main()
