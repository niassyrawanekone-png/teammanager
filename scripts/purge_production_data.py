"""Transactionally clear production data while preserving one super-admin."""

from getpass import getpass

from sqlalchemy import MetaData, Table, create_engine, func, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import SQLAlchemyError


_PRESERVED_TABLES = {"schema_migrations", "alembic_version"}
_REQUIRED_TABLES = {"utilisateurs", "schema_migrations"}
_CONFIRMATION = "PURGER PRODUCTION"


def _postgres_url(value: str):
    url = make_url(value)
    if url.get_backend_name() not in {"postgres", "postgresql"}:
        raise ValueError("La base indiquée n'est pas une base PostgreSQL.")
    if url.drivername in {"postgres", "postgresql", "postgresql+psycopg2"}:
        url = url.set(drivername="postgresql+psycopg")
    return url


def _reflect_data_tables(connection):
    metadata = MetaData()
    metadata.reflect(bind=connection)
    missing = _REQUIRED_TABLES - set(metadata.tables)
    if missing:
        raise RuntimeError(
            "Purge interrompue : schéma incomplet, table(s) absente(s): "
            + ", ".join(sorted(missing))
        )
    return metadata


def _find_target(connection, users: Table, target_email: str):
    normalized_email = target_email.strip().lower()
    matching = connection.execute(
        select(users.c.id, users.c.email, users.c.role).where(
            func.lower(users.c.email) == normalized_email
        )
    ).mappings().all()
    if len(matching) != 1 or matching[0]["role"] != "SUPER_ADMIN":
        raise RuntimeError(
            "Purge interrompue : le compte cible doit exister une seule fois "
            "et avoir exactement le rôle SUPER_ADMIN."
        )

    admin_roles = connection.execute(
        select(users.c.id, users.c.role).where(
            func.upper(
                func.replace(
                    func.replace(func.trim(users.c.role), " ", "_"),
                    "-",
                    "_",
                )
            ).in_(
                ("SUPER_ADMIN", "SUPERADMIN")
            )
        )
    ).all()
    if len(admin_roles) != 1 or admin_roles[0].id != matching[0]["id"]:
        raise RuntimeError(
            "Purge interrompue : les comptes super-administrateur sont ambigus."
        )
    return matching[0]


def _deletion_order(tables):
    data_tables = {
        name: table
        for name, table in tables.items()
        if name not in _PRESERVED_TABLES
    }
    children = {name: set() for name in data_tables}
    for table in data_tables.values():
        for foreign_key in table.foreign_keys:
            parent = foreign_key.column.table.name
            if parent in data_tables:
                children[parent].add(table.name)

    ordered = []
    visiting = set()
    visited = set()

    def visit(name):
        if name in visiting:
            raise RuntimeError(
                "Purge interrompue : cycle de clés étrangères non pris en charge."
            )
        if name in visited:
            return
        visiting.add(name)
        for child in sorted(children[name]):
            visit(child)
        visiting.remove(name)
        visited.add(name)
        ordered.append(data_tables[name])

    for name in sorted(data_tables):
        visit(name)
    return ordered


def inspect_production_data(engine: Engine, target_email: str):
    with engine.connect() as connection:
        metadata = _reflect_data_tables(connection)
        users = metadata.tables["utilisateurs"]
        target = _find_target(connection, users, target_email)
        counts = {
            table.name: connection.scalar(select(func.count()).select_from(table))
            for table in _deletion_order(metadata.tables)
        }
    return {"admin_id": target["id"], "counts": counts}


def purge_production_data(engine: Engine, target_email: str):
    with engine.begin() as connection:
        metadata = _reflect_data_tables(connection)
        tables = _deletion_order(metadata.tables)

        if connection.dialect.name == "postgresql":
            lock_tables = sorted(
                table for table in tables if table.name != "utilisateurs"
            )
            if lock_tables:
                preparer = connection.dialect.identifier_preparer
                names = ", ".join(
                    preparer.format_table(table) for table in lock_tables
                )
                connection.execute(
                    text(f"LOCK TABLE {names} IN ACCESS EXCLUSIVE MODE")
                )
        users = metadata.tables["utilisateurs"]
        if connection.dialect.name == "postgresql":
            preparer = connection.dialect.identifier_preparer
            connection.execute(
                text(
                    f"LOCK TABLE {preparer.format_table(users)} "
                    "IN ACCESS EXCLUSIVE MODE"
                )
            )

        target = _find_target(connection, users, target_email)
        for table in tables:
            if table.name == "utilisateurs":
                connection.execute(
                    table.delete().where(users.c.id != target["id"])
                )
            else:
                connection.execute(table.delete())

        remaining_users = connection.execute(
            select(users.c.id, users.c.email, users.c.role)
        ).mappings().all()
        if (
            len(remaining_users) != 1
            or remaining_users[0]["id"] != target["id"]
            or remaining_users[0]["email"].lower() != target_email.strip().lower()
            or remaining_users[0]["role"] != "SUPER_ADMIN"
        ):
            raise RuntimeError(
                "Purge annulée : vérification du compte super-administrateur échouée."
            )

        remaining_data = {
            table.name: connection.scalar(
                select(func.count()).select_from(table)
            )
            for table in tables
            if table.name != "utilisateurs"
        }
        nonempty = {name: count for name, count in remaining_data.items() if count}
        if nonempty:
            raise RuntimeError(
                "Purge annulée : des données subsistent dans "
                + ", ".join(sorted(nonempty))
                + "."
            )

    with engine.connect() as connection:
        metadata = _reflect_data_tables(connection)
        users = metadata.tables["utilisateurs"]
        remaining_users = connection.execute(
            select(users.c.id, users.c.email, users.c.role)
        ).mappings().all()
        remaining_data = {
            table.name: connection.scalar(
                select(func.count()).select_from(table)
            )
            for table in _deletion_order(metadata.tables)
            if table.name != "utilisateurs"
        }
        if (
            len(remaining_users) != 1
            or remaining_users[0]["id"] != target["id"]
            or remaining_users[0]["email"].lower() != target_email.strip().lower()
            or remaining_users[0]["role"] != "SUPER_ADMIN"
            or any(remaining_data.values())
        ):
            raise RuntimeError(
                "Purge validée, mais le contrôle après commit a détecté "
                "des données inattendues. Gardez le service en pause et vérifiez la base."
            )

    return {"admin_id": target["id"], "deleted": "all other application data"}


def main():
    database_url = getpass("URL PostgreSQL Render (saisie masquée) : ")
    target_email = input("Adresse exacte du super-administrateur à conserver : ").strip()
    if not target_email or "@" not in target_email:
        raise SystemExit("Adresse e-mail invalide.")

    engine = None
    try:
        engine = create_engine(_postgres_url(database_url), pool_pre_ping=True)
        preview = inspect_production_data(engine, target_email)
        print(f"Compte super-admin vérifié (id {preview['admin_id']}).")
        print(f"Comptes présents : {preview['counts'].get('utilisateurs', 0)}")
        print("Lignes à supprimer par table :")
        for table_name, count in sorted(preview["counts"].items()):
            if count:
                print(f"  {table_name}: {count}")
        print(
            "Assurez-vous que le backend n'accepte pas de nouvelles écritures "
            "jusqu'à la vérification de la purge."
        )
        confirmation = input(
            f"Tapez exactement « {_CONFIRMATION} » pour continuer : "
        )
        if confirmation != _CONFIRMATION:
            raise SystemExit("Purge annulée.")
        result = purge_production_data(engine, target_email)
        print(
            f"Purge terminée. Compte super-admin conservé (id {result['admin_id']}); "
            "aucune donnée applicative restante."
        )
    except (SQLAlchemyError, ValueError) as exc:
        raise SystemExit(
            "Opération annulée ou connexion impossible "
            f"({type(exc).__name__}). L'URL de base n'a pas été affichée."
        ) from None
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    main()
