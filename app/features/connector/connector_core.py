"""
connector_core.py — Business logic for the Connector feature.

All DB interactions stay here. Blueprints and API namespaces call these
functions and never touch the session directly.
"""

import datetime
import uuid as uuid_mod

import requests as http_requests

from app import db
from app.core.db_class.db import (
    Bundle, Connector, Rule, User,
    RuleTagAssociation, Tag, ActivityLog,
)
from app.core.utils.activity_log import log_activity
from app.features.jobs.jobs_core import create_job


# ─── Shadow user ──────────────────────────────────────────────────────────────

def _get_or_create_shadow_user(connector: Connector) -> User:
    """Return (and lazily create) the ghost user that owns imported content."""
    if connector.shadow_user_id:
        user = User.query.get(connector.shadow_user_id)
        if user:
            return user

    shadow_email = f"shadow_{connector.uuid[:8]}@connector.local"
    existing = User.query.filter_by(email=shadow_email).first()
    if existing:
        connector.shadow_user_id = existing.id
        db.session.commit()
        return existing

    shadow = User(
        first_name=connector.name,
        last_name=f"[{connector.connector_type}]",
        email=shadow_email,
        username=f"connector_{connector.uuid[:8]}",
        is_verified=False,
        admin=False,
    )
    shadow.password = uuid_mod.uuid4().hex   # random password — cannot login
    db.session.add(shadow)
    db.session.flush()

    connector.shadow_user_id = shadow.id
    db.session.commit()
    return shadow


# ─── CRUD ─────────────────────────────────────────────────────────────────────

def get_connectors(owner_id: int) -> list:
    """Return user's own connectors + all system connectors."""
    from sqlalchemy import or_
    return (Connector.query
            .filter(or_(Connector.owner_id == owner_id, Connector.is_system == True))
            .order_by(Connector.is_system.desc(), Connector.created_at.desc())
            .all())


def get_connector_by_uuid(connector_uuid: str, owner_id: int = None) -> Connector | None:
    q = Connector.query.filter_by(uuid=connector_uuid)
    if owner_id is not None:
        q = q.filter_by(owner_id=owner_id)
    return q.first()


def create_connector(owner_id: int, name: str, instance_url: str,
                     connector_type: str = 'rulezet',
                     api_key_outbound: str = None,
                     description: str = None,
                     icon: str = None,
                     sync_rules: bool = True,
                     sync_bundles: bool = False,
                     owner_mode: str = 'shadow') -> Connector | None:
    try:
        url = instance_url.rstrip('/')
        connector = Connector(
            uuid=str(uuid_mod.uuid4()),
            name=name.strip(),
            description=description,
            icon=icon,
            connector_type=connector_type,
            instance_url=url,
            api_key_outbound=api_key_outbound,
            owner_id=owner_id,
            sync_rules=sync_rules,
            sync_bundles=sync_bundles,
            owner_mode=owner_mode,
        )
        db.session.add(connector)
        db.session.flush()
        _get_or_create_shadow_user(connector)   # eagerly create shadow user
        db.session.commit()

        log_activity('connector.create',
                     f"Created connector '{name}' → {url}",
                     target_type='connector', target_id=connector.id,
                     target_uuid=connector.uuid)
        return connector
    except Exception as e:
        db.session.rollback()
        print(f"[connector_core] create_connector error: {e}")
        return None


def update_connector(connector: Connector, data: dict) -> bool:
    if connector.is_system:
        return False
    try:
        allowed = ('name', 'description', 'icon', 'instance_url', 'api_key_outbound',
                   'sync_rules', 'sync_bundles', 'is_active', 'owner_mode')
        for key in allowed:
            if key in data:
                val = data[key]
                if key == 'instance_url' and val:
                    val = val.rstrip('/')
                setattr(connector, key, val)
        connector.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()
        log_activity('connector.update', f"Updated connector '{connector.name}'",
                     target_type='connector', target_id=connector.id,
                     target_uuid=connector.uuid)
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[connector_core] update_connector error: {e}")
        return False


def delete_connector(connector: Connector) -> bool:
    if connector.is_system:
        return False
    try:
        name = connector.name
        cid  = connector.id
        cuuid = connector.uuid
        # Nullify FK on rules/bundles so we don't lose data
        Rule.query.filter_by(connector_id=cid).update({'connector_id': None}, synchronize_session=False)
        Bundle.query.filter_by(connector_id=cid).update({'connector_id': None}, synchronize_session=False)
        db.session.delete(connector)
        db.session.commit()
        log_activity('connector.delete', f"Deleted connector '{name}'",
                     extra={'connector_uuid': cuuid})
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[connector_core] delete_connector error: {e}")
        return False


# ─── Connection test ──────────────────────────────────────────────────────────

def test_connector(connector: Connector) -> tuple[bool, str, dict]:
    """
    Ping the remote /api/sync/manifest then /api/sync/stats.
    Returns (success: bool, message: str, stats: dict).
    stats contains 'rules' and 'bundles' counts from the remote (or {}).
    """
    base    = connector.instance_url
    headers = {}
    if connector.api_key_outbound:
        headers['X-API-KEY'] = connector.api_key_outbound
    try:
        resp = http_requests.get(f"{base}/api/sync/manifest", headers=headers, timeout=8)
        if resp.status_code != 200:
            msg = f"Remote returned HTTP {resp.status_code}."
            connector.last_error = msg
            db.session.commit()
            return False, msg, {}

        remote_name = resp.json().get('instance', {}).get('name', 'unknown')

        # Fetch public stats (best-effort — non-fatal if absent)
        stats: dict = {}
        try:
            sr = http_requests.get(f"{base}/api/sync/stats", headers=headers, timeout=5)
            if sr.status_code == 200:
                sd = sr.json()
                stats = {'rules': sd.get('rules'), 'bundles': sd.get('bundles')}
        except Exception:
            pass

        connector.is_verified = True
        connector.last_error  = None
        db.session.commit()

        stats_str = ''
        if stats.get('rules') is not None:
            stats_str = f" — {stats['rules']:,} rules, {stats['bundles']:,} bundles"

        log_activity('connector.test_ok',
                     f"Connection test OK for '{connector.name}' → {remote_name}{stats_str}",
                     target_type='connector', target_id=connector.id,
                     target_uuid=connector.uuid)
        return True, f"Connected to \"{remote_name}\"{stats_str}.", stats

    except Exception as e:
        msg = f"Connection error: {e}"
        connector.last_error = msg
        db.session.commit()
        return False, msg, {}


# ─── Pull (trigger background job) ───────────────────────────────────────────

def get_connector_history(connector: Connector) -> list:
    """Return the last 30 activity log entries for this connector."""
    entries = (ActivityLog.query
               .filter(
                   ActivityLog.target_type == 'connector',
                   ActivityLog.target_id == connector.id,
               )
               .order_by(ActivityLog.created_at.desc())
               .limit(30)
               .all())
    return [
        {
            'action':      e.action,
            'description': e.description,
            'timestamp':   e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else None,
            'extra':       e.extra or {},
        }
        for e in entries
    ]


def seed_official_connector() -> None:
    """Create the read-only official Rulezet connector if it doesn't exist yet."""
    try:
        if Connector.query.filter_by(is_system=True).first():
            return
        admin = User.query.filter_by(admin=True).first()
        if not admin:
            return
        c = Connector(
            uuid=str(uuid_mod.uuid4()),
            name='Rulezet Official',
            description='The official Rulezet community — rulezet.org.',
            icon='fa-solid fa-shield-halved',
            connector_type='rulezet',
            instance_url='https://rulezet.org',
            owner_id=admin.id,
            sync_rules=True,
            sync_bundles=True,
            is_system=True,
            owner_mode='shadow',
        )
        db.session.add(c)
        db.session.commit()
    except Exception:
        db.session.rollback()


def trigger_pull(connector: Connector, triggered_by: int) -> object | None:
    """Enqueue a connector_pull background job and return the job object."""
    if not connector.is_active:
        return None
    label = f"Pull from '{connector.name}'"
    job = create_job(
        job_type='connector_pull',
        payload={'connector_id': connector.id},
        label=label,
        created_by=triggered_by,
    )
    log_activity('connector.pull_triggered',
                 f"Pull queued for connector '{connector.name}'",
                 target_type='connector', target_id=connector.id,
                 target_uuid=connector.uuid,
                 extra={'job_uuid': job.uuid if job else None})
    return job


# ─── Sync helpers (called from job handler) ───────────────────────────────────

def _upsert_rule(connector: Connector, shadow_user_id: int, remote: dict) -> bool:
    """
    Create or update a Rule from a remote payload dict.
    Returns True if a change was made.
    """
    remote_uuid = remote.get('uuid')
    if not remote_uuid:
        return False

    existing = Rule.query.filter_by(
        connector_id=connector.id,
        remote_rule_uuid=remote_uuid,
    ).first()

    now = datetime.datetime.now(datetime.timezone.utc)

    if existing:
        # Only update if remote is newer
        remote_ts = remote.get('last_modif')
        if remote_ts and existing.last_modif:
            try:
                remote_dt = datetime.datetime.fromisoformat(remote_ts.replace('Z', '+00:00'))
                if remote_dt <= existing.last_modif.replace(tzinfo=datetime.timezone.utc):
                    return False
            except ValueError:
                pass
        existing.title       = remote.get('title', existing.title)
        existing.description = remote.get('description', existing.description)
        existing.to_string   = remote.get('to_string', existing.to_string)
        existing.author      = remote.get('author', existing.author)
        existing.last_modif  = now
        db.session.flush()
        _sync_tags(existing, remote.get('tags', []), shadow_user_id)
        return True

    # New rule
    rule = Rule(
        uuid=str(uuid_mod.uuid4()),           # fresh local UUID
        remote_rule_uuid=remote_uuid,
        connector_id=connector.id,
        user_id=shadow_user_id,
        format=remote.get('format', 'unknown'),
        title=remote.get('title', ''),
        description=remote.get('description'),
        to_string=remote.get('to_string', ''),
        author=remote.get('author', connector.name),
        source=connector.instance_url,
        version=remote.get('version'),
        license=remote.get('license'),
        vote_up=0,
        vote_down=0,
        creation_date=now,
        last_modif=now,
        is_deleted=False,
    )
    db.session.add(rule)
    db.session.flush()
    _sync_tags(rule, remote.get('tags', []), shadow_user_id)
    return True


def _sync_tags(rule: Rule, tag_names: list, user_id: int) -> None:
    """Attach tags that already exist locally; silently skip unknown ones."""
    for name in tag_names:
        tag = Tag.query.filter(Tag.name.ilike(name)).first()
        if not tag:
            continue
        already = RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first()
        if not already:
            db.session.add(RuleTagAssociation(
                uuid=str(uuid_mod.uuid4()),
                rule_id=rule.id,
                tag_id=tag.id,
                user_id=user_id,
                added_at=datetime.datetime.now(datetime.timezone.utc),
            ))


def _upsert_bundle(connector: Connector, shadow_user_id: int, remote: dict) -> bool:
    """Create or update a Bundle from a remote payload dict."""
    remote_uuid = remote.get('uuid')
    if not remote_uuid:
        return False

    existing = Bundle.query.filter_by(
        connector_id=connector.id,
        remote_bundle_uuid=remote_uuid,
    ).first()

    now = datetime.datetime.now(datetime.timezone.utc)

    if existing:
        remote_ts = remote.get('updated_at')
        if remote_ts and existing.updated_at:
            try:
                remote_dt = datetime.datetime.fromisoformat(remote_ts.replace('Z', '+00:00'))
                if remote_dt <= existing.updated_at.replace(tzinfo=datetime.timezone.utc):
                    return False
            except ValueError:
                pass
        existing.name        = remote.get('name', existing.name)
        existing.description = remote.get('description', existing.description)
        existing.updated_at  = now
        return True

    bundle = Bundle(
        uuid=str(uuid_mod.uuid4()),
        remote_bundle_uuid=remote_uuid,
        connector_id=connector.id,
        user_id=shadow_user_id,
        name=remote.get('name', ''),
        description=remote.get('description'),
        created_by='connector',
        access=True,
        vote_up=0,
        vote_down=0,
        created_at=now,
        updated_at=now,
    )
    db.session.add(bundle)
    return True
