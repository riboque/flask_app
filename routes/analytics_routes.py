"""
Rotas para Analytics Dashboard
"""
from flask import Blueprint, jsonify, request, render_template
from datetime import datetime

from analytics import analytics, get_ip_geolocation_sync
from security_advanced import audit_log, require_rate_limit

# Criar blueprint
analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/analytics')


@analytics_bp.route('/dashboard')
def get_dashboard():
    """Retorna dados do dashboard"""
    try:
        stats = analytics.get_dashboard_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/geo')
def get_geo_stats():
    """Retorna estatísticas de geolocalização"""
    try:
        stats = analytics.get_geo_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/geo/lookup/<ip>')
@require_rate_limit
def lookup_ip_geo(ip):
    """Busca geolocalização de um IP"""
    try:
        geo = get_ip_geolocation_sync(ip)
        analytics.set_geo_data(ip, geo)
        return jsonify(geo), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/track/pageview', methods=['POST'])
def track_pageview():
    """Registra visualização de página"""
    try:
        data = request.get_json() or {}
        page = data.get('page', '/')
        ip = request.remote_addr
        
        analytics.track_page_view(page, ip)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/events')
def get_events():
    """Retorna eventos recentes"""
    try:
        limit = request.args.get('limit', 50, type=int)
        events = analytics.get_dashboard_stats()['recent_events'][-limit:]
        return jsonify({'events': events}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
