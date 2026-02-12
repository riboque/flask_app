"""
Rotas de Notificações
"""
from flask import Blueprint, jsonify, request
from datetime import datetime

from notifications import notification_manager

# Criar blueprint
notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')


@notifications_bp.route('/')
def get_notifications():
    """Lista notificações do usuário"""
    try:
        username = request.args.get('username')
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        limit = request.args.get('limit', 50, type=int)
        
        notifications = notification_manager.get_notifications(username, unread_only, limit)
        unread_count = notification_manager.get_unread_count(username)
        
        return jsonify({
            'notifications': notifications,
            'unread_count': unread_count
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/unread-count')
def get_unread_count():
    """Conta notificações não lidas"""
    try:
        username = request.args.get('username')
        count = notification_manager.get_unread_count(username)
        return jsonify({'unread_count': count}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/<notif_id>/read', methods=['POST'])
def mark_as_read(notif_id):
    """Marca notificação como lida"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        
        if notification_manager.mark_as_read(notif_id, username):
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Notificação não encontrada'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/read-all', methods=['POST'])
def mark_all_as_read():
    """Marca todas notificações como lidas"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        
        notification_manager.mark_all_as_read(username)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/subscribe', methods=['POST'])
def subscribe_push():
    """Registra subscription para push notifications"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        subscription = data.get('subscription')
        
        if not username or not subscription:
            return jsonify({'error': 'Username e subscription são obrigatórios'}), 400
        
        notification_manager.subscribe_push(username, subscription)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/unsubscribe', methods=['POST'])
def unsubscribe_push():
    """Remove subscription de push"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        
        if not username:
            return jsonify({'error': 'Username é obrigatório'}), 400
        
        notification_manager.unsubscribe_push(username)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/stats')
def get_stats():
    """Estatísticas de notificações"""
    try:
        stats = notification_manager.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/test', methods=['POST'])
def test_notification():
    """Envia notificação de teste"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        
        notification_manager.notify_system(
            'Teste',
            'Esta é uma notificação de teste!',
            target_user=username
        )
        
        return jsonify({'success': True, 'message': 'Notificação de teste enviada'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
