"""
Rotas de Segurança Avançada
"""
from flask import Blueprint, jsonify, request
from datetime import datetime

from security_advanced import (
    ip_blocker, audit_log, rate_limiter, vpn_detector,
    require_not_blocked, require_rate_limit
)
from auth import require_admin

# Criar blueprint
security_bp = Blueprint('security', __name__, url_prefix='/api/security')


@security_bp.route('/blocked-ips')
@require_admin
def get_blocked_ips():
    """Lista IPs bloqueados"""
    try:
        blocked = ip_blocker.get_blocked_list()
        return jsonify({'blocked_ips': blocked}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/block-ip', methods=['POST'])
@require_admin
def block_ip():
    """Bloqueia um IP"""
    try:
        data = request.get_json() or {}
        ip = data.get('ip')
        reason = data.get('reason', 'Bloqueio manual')
        duration = data.get('duration_hours', 24)
        
        if not ip:
            return jsonify({'error': 'IP é obrigatório'}), 400
        
        ip_blocker.block_ip(ip, reason, duration)
        return jsonify({'success': True, 'message': f'IP {ip} bloqueado'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/unblock-ip', methods=['POST'])
@require_admin
def unblock_ip():
    """Desbloqueia um IP"""
    try:
        data = request.get_json() or {}
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'error': 'IP é obrigatório'}), 400
        
        ip_blocker.unblock_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} desbloqueado'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/audit-logs')
@require_admin
def get_audit_logs():
    """Lista logs de auditoria"""
    try:
        limit = request.args.get('limit', 100, type=int)
        action = request.args.get('action')
        ip = request.args.get('ip')
        
        logs = audit_log.get_logs(limit, action, ip)
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/audit-stats')
@require_admin
def get_audit_stats():
    """Estatísticas de auditoria"""
    try:
        stats = audit_log.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/check-vpn/<ip>')
@require_rate_limit
def check_vpn(ip):
    """Verifica se IP é VPN/Proxy"""
    try:
        from analytics import get_ip_geolocation_sync
        geo = get_ip_geolocation_sync(ip)
        vpn_result = vpn_detector.check_ip(ip, geo.get('isp'), geo.get('org'))
        
        return jsonify({
            'ip': ip,
            'geo': geo,
            'vpn_check': vpn_result
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/rate-limit-status')
def rate_limit_status():
    """Status do rate limit para o IP atual"""
    try:
        ip = request.remote_addr
        remaining = rate_limiter.get_remaining(ip)
        return jsonify({
            'ip': ip,
            'remaining_requests': remaining,
            'max_requests': rate_limiter.max_requests,
            'window_seconds': rate_limiter.window_seconds
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
