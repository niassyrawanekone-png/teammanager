import unittest

from sqlalchemy import (
    Column,
    ForeignKey,
    func,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    select,
)
from scripts.purge_production_data import (
    _deletion_order,
    _postgres_url,
    inspect_production_data,
    purge_production_data,
)


def _test_schema():
    metadata = MetaData()
    users = Table(
        "utilisateurs",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("email", String, nullable=False),
        Column("role", String, nullable=False),
    )
    workspaces = Table(
        "workspaces",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("owner_user_id", ForeignKey("utilisateurs.id", ondelete="RESTRICT")),
    )
    projects = Table(
        "projets",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("workspace_id", ForeignKey("workspaces.id", ondelete="CASCADE")),
    )
    memberships = Table(
        "workspace_memberships",
        metadata,
        Column("user_id", ForeignKey("utilisateurs.id", ondelete="CASCADE"), primary_key=True),
        Column("workspace_id", ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True),
    )
    messages = Table(
        "messages_partage",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("workspace_id", ForeignKey("workspaces.id", ondelete="CASCADE")),
    )
    Table(
        "message_attachments",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("message_id", ForeignKey("messages_partage.id", ondelete="CASCADE")),
    )
    migrations = Table(
        "schema_migrations",
        metadata,
        Column("revision", String, primary_key=True),
    )
    return metadata, users, workspaces, projects, memberships, messages, migrations


class PurgeProductionDataTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        event.listen(
            self.engine,
            "connect",
            lambda dbapi_connection, _: dbapi_connection.execute("PRAGMA foreign_keys=ON"),
        )
        (
            self.metadata,
            self.users,
            self.workspaces,
            self.projects,
            self.memberships,
            self.messages,
            self.migrations,
        ) = _test_schema()
        self.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.execute(
                self.users.insert(),
                [
                    {"id": 1, "email": "owner@example.com", "role": "SUPER_ADMIN"},
                    {"id": 2, "email": "member@example.com", "role": "MEMBRE"},
                ],
            )
            connection.execute(self.workspaces.insert(), {"id": 1, "owner_user_id": 1})
            connection.execute(self.projects.insert(), {"id": 1, "workspace_id": 1})
            connection.execute(
                self.memberships.insert(),
                [{"user_id": 1, "workspace_id": 1}, {"user_id": 2, "workspace_id": 1}],
            )
            connection.execute(self.messages.insert(), {"id": 1, "workspace_id": 1})
            connection.execute(
                self.metadata.tables["message_attachments"].insert(),
                {"id": 1, "message_id": 1},
            )
            connection.execute(self.migrations.insert(), {"revision": "0004_database_attachments"})

    def tearDown(self):
        self.engine.dispose()

    def test_purge_removes_application_data_and_preserves_only_target_admin(self):
        preview = inspect_production_data(self.engine, "OWNER@example.com")
        self.assertEqual(preview["admin_id"], 1)
        self.assertEqual(preview["counts"]["utilisateurs"], 2)
        result = purge_production_data(self.engine, "owner@example.com")
        self.assertEqual(result["admin_id"], 1)

        with self.engine.connect() as connection:
            users = connection.execute(select(self.users)).mappings().all()
            self.assertEqual(
                [(user["email"], user["role"]) for user in users],
                [("owner@example.com", "SUPER_ADMIN")],
            )
            for table in self.metadata.sorted_tables:
                if table.name not in {"utilisateurs", "schema_migrations"}:
                    self.assertEqual(
                        connection.scalar(select(func.count()).select_from(table)),
                        0,
                    )
            self.assertEqual(
                connection.scalar(
                    select(func.count()).select_from(self.migrations)
                ),
                1,
            )

    def test_wrong_target_role_aborts_without_deleting_data(self):
        with self.engine.begin() as connection:
            connection.execute(
                self.users.update()
                .where(self.users.c.id == 1)
                .values(role="MEMBRE")
            )
        with self.assertRaises(RuntimeError):
            purge_production_data(self.engine, "owner@example.com")
        with self.engine.connect() as connection:
            self.assertEqual(
                connection.scalar(select(func.count()).select_from(self.users)),
                2,
            )
            self.assertEqual(
                connection.scalar(select(func.count()).select_from(self.projects)),
                1,
            )

    def test_deletion_order_places_children_before_foreign_key_parents(self):
        order = [
            table.name for table in _deletion_order(self.metadata.tables)
        ]
        self.assertLess(order.index("message_attachments"), order.index("messages_partage"))
        self.assertLess(order.index("messages_partage"), order.index("workspaces"))
        self.assertLess(order.index("workspace_memberships"), order.index("utilisateurs"))

    def test_only_postgresql_urls_are_accepted_and_normalized(self):
        for url in (
            "postgres://db.example/team_manager",
            "postgresql://db.example/team_manager",
        ):
            with self.subTest(url=url.split(":")[0]):
                self.assertEqual(
                    _postgres_url(url).drivername,
                    "postgresql+psycopg",
                )
        with self.assertRaises(ValueError):
            _postgres_url("sqlite:///local.db")


if __name__ == "__main__":
    unittest.main()
