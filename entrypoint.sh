#!/bin/sh
set -e

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
MAX_WAIT=60

# ── Wait for PostgreSQL ──────────────────────────────────────────────────────
echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
elapsed=0
until python3 -c "
import socket, sys
try:
    socket.create_connection(('$DB_HOST', $DB_PORT), timeout=1).close()
except OSError:
    sys.exit(1)
" 2>/dev/null; do
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "ERROR: PostgreSQL not available after ${MAX_WAIT}s" >&2
        exit 1
    fi
    sleep 1
done
echo "PostgreSQL is ready."

# ── Seed on first run only ───────────────────────────────────────────────────
echo "Checking if database needs seeding..."
python3 - <<'EOF'
from sqlalchemy import create_engine, MetaData, Table
from app import create_app, db
from app.core.utils.init_db import (
    create_admin, create_default_user,
    insert_default_formats, show_admin_first_connection,
)
from app.core.db_class.db import User

app = create_app()
metadata = MetaData()

with app.app_context():
    metadata.reflect(bind=db.engine)
    print("Checking DB for user table.")
    if isinstance(metadata.tables.get('user'), Table):
        print("Database already has User table, checking for admin user.")
        if not User.query.filter_by(email="admin@admin.admin").first():
            db.create_all()
            admin, raw_password = create_admin()
            create_default_user()
            insert_default_formats()
            show_admin_first_connection(admin, raw_password)
        else:
            print("Database already seeded — skipping.")
    else:
        db.create_all()
        admin, raw_password = create_admin()
        create_default_user()
        insert_default_formats()
        show_admin_first_connection(admin, raw_password)
EOF

# ── Start application ────────────────────────────────────────────────────────
exec gunicorn -w 4 -b 0.0.0.0:7009 wsgi:app
