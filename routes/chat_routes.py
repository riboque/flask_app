"""
Rotas de Chat
"""
from flask import Blueprint, jsonify, request
from datetime import datetime

# Criar blueprint
chat_bp = Blueprint('chat', __name__, url_prefix='/api/chat')

# Referência aos dados compartilhados
shared_data = {
    'connected_clients': {},
    'chat_messages': []
}


def init_shared_data(connected_clients, chat_messages):
    """Inicializa referências aos dados compartilhados"""
    shared_data['connected_clients'] = connected_clients
    shared_data['chat_messages'] = chat_messages


def get_socketio():
    """Obtém instância do SocketIO (lazy loading)"""
    from flask import current_app
    return current_app.extensions.get('socketio')


@chat_bp.route('/send', methods=['POST'])
def api_chat_send():
    """API para enviar mensagens via HTTP POST"""
    try:
        data = request.get_json() or {}
        username = str(data.get('username', 'Anônimo')).strip() or 'Anônimo'
        message = str(data.get('message', '')).strip()
        
        if not message:
            return jsonify({'erro': 'Mensagem vazia'}), 400
        
        # Limitar tamanho
        username = username[:50]
        message = message[:500]
        
        # Armazenar mensagem em memória (últimas 100)
        msg_obj = {
            'username': username,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'id': len(shared_data['chat_messages']) + 1
        }
        shared_data['chat_messages'].append(msg_obj)
        if len(shared_data['chat_messages']) > 100:
            shared_data['chat_messages'].pop(0)
        
        # Tentar emitir via Socket.IO
        try:
            socketio = get_socketio()
            if socketio:
                socketio.emit('message', {'username': username, 'message': message}, broadcast=True)
        except:
            pass
        
        return jsonify({'ok': True, 'mensagem': 'Mensagem enviada', 'id': msg_obj['id']}), 201
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@chat_bp.route('/users-count')
def api_chat_users_count():
    """API para obter contagem de usuários conectados"""
    try:
        return jsonify({
            'total': len(shared_data['connected_clients']),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@chat_bp.route('/messages')
def api_chat_messages():
    """API para obter mensagens recentes (polling)"""
    try:
        since_id = request.args.get('since_id', 0, type=int)
        filtered = [m for m in shared_data['chat_messages'] if m['id'] > since_id]
        return jsonify({
            'mensagens': filtered[-50:],
            'total': len(filtered),
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@chat_bp.route('/status')
def api_chat_status():
    """API para obter status do chat"""
    try:
        return jsonify({
            'usuarios': len(shared_data['connected_clients']),
            'mensagens_total': len(shared_data['chat_messages']),
            'timestamp': datetime.now().isoformat(),
            'status': 'online'
        }), 200
    except Exception as e:
        return jsonify({'erro': str(e)}), 500
