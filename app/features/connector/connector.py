"""
connector.py — Blueprint for the Connector feature (UI routes).
All DB logic lives in connector_core.py.
"""

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

import app.features.connector.connector_core as ConnectorModel
from app.core.utils.activity_log import log_activity

connector_blueprint = Blueprint(
    'connector',
    __name__,
    template_folder='templates',
)


# ─── List ─────────────────────────────────────────────────────────────────────

@connector_blueprint.route('/list', methods=['GET'])
@login_required
def connector_list():
    return render_template('connector/connector_list.html')


# ─── CRUD (JSON API used by the Vue app) ──────────────────────────────────────

@connector_blueprint.route('/get', methods=['GET'])
@login_required
def get_connectors():
    connectors = ConnectorModel.get_connectors(current_user.id)
    return jsonify([c.to_json() for c in connectors]), 200


@connector_blueprint.route('/create', methods=['POST'])
@login_required
def create_connector():
    data = request.get_json() or {}
    name         = (data.get('name') or '').strip()
    instance_url = (data.get('instance_url') or '').strip()
    if not name or not instance_url:
        return jsonify({'success': False, 'error': 'Name and URL are required.'}), 400

    connector = ConnectorModel.create_connector(
        owner_id=current_user.id,
        name=name,
        instance_url=instance_url,
        connector_type=data.get('connector_type', 'rulezet'),
        api_key_outbound=data.get('api_key_outbound') or None,
        description=data.get('description') or None,
        icon=data.get('icon') or None,
        sync_rules=data.get('sync_rules', True),
        sync_bundles=data.get('sync_bundles', False),
        owner_mode=data.get('owner_mode', 'shadow'),
    )
    if not connector:
        return jsonify({'success': False, 'error': 'Could not create connector.'}), 500

    return jsonify({'success': True, 'connector': connector.to_json()}), 200


@connector_blueprint.route('/update/<string:connector_uuid>', methods=['POST'])
@login_required
def update_connector(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid, owner_id=current_user.id)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    if connector.is_system:
        return jsonify({'success': False, 'error': 'System connectors cannot be modified.'}), 403

    data = request.get_json() or {}
    ok = ConnectorModel.update_connector(connector, data)
    return jsonify({'success': ok}), 200 if ok else 500


@connector_blueprint.route('/delete/<string:connector_uuid>', methods=['POST'])
@login_required
def delete_connector(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid, owner_id=current_user.id)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    if connector.is_system:
        return jsonify({'success': False, 'error': 'System connectors cannot be deleted.'}), 403

    ok = ConnectorModel.delete_connector(connector)
    return jsonify({'success': ok}), 200 if ok else 500


# ─── Actions ──────────────────────────────────────────────────────────────────

@connector_blueprint.route('/test/<string:connector_uuid>', methods=['POST'])
@login_required
def test_connector(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    ok, msg = ConnectorModel.test_connector(connector)
    return jsonify({'success': ok, 'message': msg}), 200


@connector_blueprint.route('/history/<string:connector_uuid>', methods=['GET'])
@login_required
def connector_history(connector_uuid):
    connector = ConnectorModel.get_connector_by_uuid(connector_uuid, owner_id=current_user.id)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404
    return jsonify(ConnectorModel.get_connector_history(connector)), 200


@connector_blueprint.route('/pull/<string:connector_uuid>', methods=['POST'])
@login_required
def pull_connector(connector_uuid):
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Admin access required to trigger pulls.'}), 403

    connector = ConnectorModel.get_connector_by_uuid(connector_uuid)
    if not connector:
        return jsonify({'success': False, 'error': 'Not found.'}), 404

    if not connector.is_active:
        return jsonify({'success': False, 'error': 'Connector is disabled.'}), 400

    job = ConnectorModel.trigger_pull(connector, triggered_by=current_user.id)
    if not job:
        return jsonify({'success': False, 'error': 'Could not queue pull job.'}), 500

    return jsonify({
        'success': True,
        'message': 'Pull queued as background job.',
        'job_uuid': job.uuid,
    }), 200
