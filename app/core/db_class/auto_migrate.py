"""
Auto-stamp-or-upgrade helper for Flask-Migrate.

Handles the "migrations introduced mid-project" problem automatically:
- Fresh DB (no tables at all)        -> flask db upgrade   (creates everything)
- Existing DB with tables, but no
  alembic_version table yet         -> flask db stamp head (mark baseline as done)
- Existing DB already tracked by
  Alembic (alembic_version exists)  -> flask db upgrade   (apply any new migrations)

Usage:
    flask auto-migrate

Wire this into your container entrypoint instead of calling
`flask db upgrade` directly:

    flask auto-migrate

Assumes a single-head migration history and a single Postgres database.
Safe to run every time the container starts - it's idempotent.
"""

import click
from flask import current_app
from flask.cli import with_appcontext
from flask_migrate import upgrade, stamp
from sqlalchemy import inspect


def _table_exists(connection, table_name: str) -> bool:
    inspector = inspect(connection)
    return table_name in inspector.get_table_names()


def register_auto_migrate(app):
    """Call this once in create_app(), e.g. register_auto_migrate(app)"""

    @app.cli.command("auto-migrate")
    @with_appcontext
    def auto_migrate():
        """Detect DB state and either stamp the baseline or run migrations."""
        from flask import current_app as capp
        db = capp.extensions["sqlalchemy"].db if "sqlalchemy" in capp.extensions else None
        # Fallback for older Flask-SQLAlchemy versions
        if db is None:
            from flask_sqlalchemy import SQLAlchemy
            db = capp.extensions["sqlalchemy"]

        engine = db.engine
        with engine.connect() as connection:
            alembic_tracked = _table_exists(connection, "alembic_version")
            # Pick one or two core tables you know exist from the start
            # of your project to detect a pre-existing, un-migrated schema.
            # Replace "users" with a real table name from your app.
            has_existing_tables = _table_exists(connection, "users")

        if alembic_tracked:
            click.echo("[auto-migrate] alembic_version found - running upgrade().")
            upgrade()

        elif has_existing_tables:
            click.echo(
                "[auto-migrate] Existing tables found but no alembic_version - "
                "stamping current schema as baseline (head)."
            )
            stamp()

        else:
            click.echo("[auto-migrate] No existing tables - running upgrade() from scratch.")
            upgrade()

        click.echo("[auto-migrate] Done.")