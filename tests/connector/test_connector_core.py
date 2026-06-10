"""
Unit tests for connector_core.py business logic functions.
Tests run in app context directly against the SQLite test DB.
"""

import datetime
import uuid

import pytest

from app import db
from app.core.db_class.db import (
    Bundle, Connector, Rule, RuleTagAssociation, RuleUpdateHistory, Tag, User,
)
from app.features.connector import connector_core as core


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(app):
    with app.app_context():
        yield User.query.filter_by(email="admin@admin.admin").first()


@pytest.fixture
def connector(app, admin):
    """Create a fresh connector for each test."""
    with app.app_context():
        c = core.create_connector(
            owner_id=admin.id,
            name="UnitTestConn",
            instance_url="http://unit.test.example.com",
        )
        yield c
        # Teardown: delete if still exists
        existing = Connector.query.filter_by(uuid=c.uuid).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()


def _remote_rule(title="Remote Rule", to_string="rule r { condition: true }",
                 fmt="yara", rule_uuid=None):
    return {
        "uuid":           rule_uuid or str(uuid.uuid4()),
        "format":         fmt,
        "title":          title,
        "description":    "A remote rule",
        "to_string":      to_string,
        "author":         "remote-author",
        "source":         "https://github.com/remote/repo",
        "version":        1,
        "license":        "MIT",
        "tags":           [],
        "update_history": [],
    }


# ── _get_or_create_shadow_user ────────────────────────────────────────────────

def test_shadow_user_created_on_first_call(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        assert shadow is not None
        assert shadow.id is not None
        assert "@connector.local" in shadow.email


def test_shadow_user_idempotent(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        s1 = core._get_or_create_shadow_user(c)
        s2 = core._get_or_create_shadow_user(c)
        assert s1.id == s2.id


def test_shadow_user_cannot_login(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        # Password is a random UUID hex — not a real password
        assert not shadow.verify_password("password")
        assert not shadow.verify_password("")


def test_shadow_user_is_not_admin(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        assert shadow.admin is False


def test_shadow_user_not_verified(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        assert shadow.is_verified is False


# ── _upsert_rule — soft mode ──────────────────────────────────────────────────

def test_soft_upsert_creates_new_rule(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Brand New Rule")
        result = core._upsert_rule(c, shadow.id, remote, mode="soft")
        assert result == "created"
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assert rule is not None
        assert rule.title == "Brand New Rule"


def test_soft_upsert_skips_existing_by_uuid(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Existing Rule")
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        result = core._upsert_rule(c, shadow.id, remote, mode="soft")
        assert result == "skipped"


def test_soft_upsert_skips_existing_by_content(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        content = "rule same_content { condition: true }"
        remote1 = _remote_rule(title="Original", to_string=content)
        remote2 = _remote_rule(title="Duplicate Content", to_string=content)
        core._upsert_rule(c, shadow.id, remote1, mode="soft")
        result = core._upsert_rule(c, shadow.id, remote2, mode="soft")
        assert result == "skipped"


def test_soft_upsert_invalid_without_uuid(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule()
        remote["uuid"] = None
        result = core._upsert_rule(c, shadow.id, remote, mode="soft")
        assert result == "invalid"


def test_soft_upsert_sets_connector_id(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Connector Tag Test")
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assert rule.connector_id == c.id


def test_soft_upsert_preserves_source(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Source Test")
        remote["source"] = "https://github.com/original/source"
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        # Source from remote must be preserved, not overwritten with connector URL
        assert rule.source == "https://github.com/original/source"
        assert rule.sync_instance_url == c.instance_url


def test_soft_upsert_shadow_owner(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Shadow Owner Test")
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assert rule.user_id == shadow.id


# ── _upsert_rule — hard mode ──────────────────────────────────────────────────

def test_hard_upsert_creates_when_no_match(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Hard New Rule")
        result = core._upsert_rule(c, shadow.id, remote, mode="hard")
        assert result == "created"


def test_hard_upsert_returns_updated_when_replacing(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Will Be Replaced")
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        result = core._upsert_rule(c, shadow.id, remote, mode="hard")
        assert result == "updated"


def test_hard_upsert_soft_deletes_old_rule(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Old Version")
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        old_rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        old_id = old_rule.id

        core._upsert_rule(c, shadow.id, remote, mode="hard")

        old_rule = Rule.query.get(old_id)
        assert old_rule.is_deleted is True
        assert old_rule.deleted_at is not None


def test_hard_upsert_creates_fresh_rule(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Fresh After Hard")
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        old_rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        old_id = old_rule.id

        core._upsert_rule(c, shadow.id, remote, mode="hard")

        new_rule = Rule.query.filter_by(
            remote_rule_uuid=remote["uuid"], is_deleted=False
        ).first()
        assert new_rule is not None
        assert new_rule.id != old_id


def test_hard_upsert_imports_remote_history(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="History Rule")
        remote["update_history"] = [
            {"old_content": "old", "new_content": "new",
             "message": "fix", "success": True,
             "analyzed_at": "2024-01-15T10:00:00", "manuel_submit": False}
        ]
        core._upsert_rule(c, shadow.id, remote, mode="hard")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        history = RuleUpdateHistory.query.filter_by(rule_id=rule.id).all()
        assert len(history) == 1
        assert history[0].message == "fix"


# ── _upsert_bundle ────────────────────────────────────────────────────────────

def _remote_bundle(name="Remote Bundle", bundle_uuid=None):
    now = datetime.datetime.utcnow().isoformat()
    return {
        "uuid":        bundle_uuid or str(uuid.uuid4()),
        "name":        name,
        "description": "A remote bundle",
        "updated_at":  now,
        "created_at":  now,
    }


def test_upsert_bundle_creates_new(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="New Bundle")
        result = core._upsert_bundle(c, shadow.id, remote, mode="soft")
        assert result == "created"
        b = Bundle.query.filter_by(remote_bundle_uuid=remote["uuid"]).first()
        assert b is not None
        assert b.name == "New Bundle"


def test_upsert_bundle_soft_skips_existing(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="Existing Bundle")
        core._upsert_bundle(c, shadow.id, remote, mode="soft")
        result = core._upsert_bundle(c, shadow.id, remote, mode="soft")
        assert result == "skipped"


def test_upsert_bundle_hard_updates_existing(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="Original Name")
        core._upsert_bundle(c, shadow.id, remote, mode="soft")

        remote["name"] = "Updated Name"
        remote["updated_at"] = datetime.datetime(2099, 1, 1).isoformat()
        result = core._upsert_bundle(c, shadow.id, remote, mode="hard")
        assert result == "updated"

        b = Bundle.query.filter_by(remote_bundle_uuid=remote["uuid"]).first()
        assert b.name == "Updated Name"


def test_upsert_bundle_invalid_without_uuid(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle()
        remote["uuid"] = None
        result = core._upsert_bundle(c, shadow.id, remote, mode="soft")
        assert result == "invalid"


def test_upsert_bundle_sets_connector_id(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_bundle(name="Connector Bundle")
        core._upsert_bundle(c, shadow.id, remote, mode="soft")
        b = Bundle.query.filter_by(remote_bundle_uuid=remote["uuid"]).first()
        assert b.connector_id == c.id


# ── _sync_tags ────────────────────────────────────────────────────────────────

def _make_tag(app, name="test:tag", color="#ff0000"):
    with app.app_context():
        import uuid as _uuid_helper
        admin_id = User.query.filter_by(email="admin@admin.admin").first().id
        tag = Tag(
            uuid=str(_uuid_helper.uuid4()),
            name=name,
            color=color,
            visibility=True,
            created_by=admin_id,
        )
        db.session.add(tag)
        db.session.commit()
        return tag.id


def test_sync_tags_attaches_existing_tag(app, connector):
    tag_id = _make_tag(app, name="tlp:clear")
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Tag Test Rule")
        remote["tags"] = ["tlp:clear"]
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assoc = RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag_id).first()
        assert assoc is not None


def test_sync_tags_ignores_unknown_tags(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Unknown Tag Rule")
        remote["tags"] = ["nonexistent:tag-xyz"]
        result = core._upsert_rule(c, shadow.id, remote, mode="soft")
        # Must not crash; rule is still created
        assert result == "created"


def test_sync_tags_no_duplicates(app, connector):
    tag_id = _make_tag(app, name="sigma:high")
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Dup Tag Rule")
        remote["tags"] = ["sigma:high", "sigma:high"]  # intentional duplicate
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        assocs = RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag_id).all()
        assert len(assocs) == 1


# ── _import_rule_history ──────────────────────────────────────────────────────

def test_import_history_adds_entries(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="History Import Rule")
        remote["update_history"] = [
            {"old_content": "v1", "new_content": "v2", "message": "update1",
             "success": True, "analyzed_at": "2024-03-01T12:00:00", "manuel_submit": False},
            {"old_content": "v2", "new_content": "v3", "message": "update2",
             "success": True, "analyzed_at": "2024-04-01T12:00:00", "manuel_submit": True},
        ]
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        history = RuleUpdateHistory.query.filter_by(rule_id=rule.id).all()
        assert len(history) == 2


def test_import_history_deduplicates_by_timestamp(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Dup History Rule")
        same_ts = "2024-05-01T08:00:00"
        remote["update_history"] = [
            {"old_content": "a", "new_content": "b", "message": "first",
             "success": True, "analyzed_at": same_ts, "manuel_submit": False},
            {"old_content": "a", "new_content": "b", "message": "duplicate",
             "success": True, "analyzed_at": same_ts, "manuel_submit": False},
        ]
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        history = RuleUpdateHistory.query.filter_by(rule_id=rule.id).all()
        assert len(history) == 1


def test_import_history_empty_list_is_ok(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="No History Rule")
        remote["update_history"] = []
        result = core._upsert_rule(c, shadow.id, remote, mode="soft")
        assert result == "created"


# ── create_connector / delete_connector CRUD ──────────────────────────────────

def test_create_connector_strips_trailing_slash(app, admin):
    with app.app_context():
        c = core.create_connector(
            owner_id=admin.id,
            name="SlashTest",
            instance_url="http://example.com/",
        )
        assert c.instance_url == "http://example.com"
        db.session.delete(c)
        db.session.commit()


def test_create_connector_default_active(app, admin):
    with app.app_context():
        c = core.create_connector(
            owner_id=admin.id,
            name="ActiveTest",
            instance_url="http://active.example.com",
        )
        assert c.is_active is True
        db.session.delete(c)
        db.session.commit()


def test_delete_connector_nullifies_rule_connector_id(app, connector):
    with app.app_context():
        c = Connector.query.filter_by(uuid=connector.uuid).first()
        shadow = core._get_or_create_shadow_user(c)
        remote = _remote_rule(title="Orphan After Delete")
        core._upsert_rule(c, shadow.id, remote, mode="soft")
        rule = Rule.query.filter_by(remote_rule_uuid=remote["uuid"]).first()
        rule_id = rule.id

        core.delete_connector(c)

        rule = Rule.query.get(rule_id)
        assert rule is not None
        assert rule.connector_id is None


def test_system_connector_cannot_be_deleted(app):
    with app.app_context():
        sys_conn = Connector.query.filter_by(is_system=True).first()
        if sys_conn is None:
            pytest.skip("No system connector")
        result = core.delete_connector(sys_conn)
        assert result is False
        assert Connector.query.filter_by(uuid=sys_conn.uuid).first() is not None
