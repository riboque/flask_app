"""
Rotas de Chat Avançado
"""
from flask import Blueprint, jsonify, request
from datetime import datetime
import os

from chat_advanced import chat_manager
from notifications import notification_manager, NotificationType
from security_advanced import audit_log, require_rate_limit

# Criar blueprint
chat_advanced_bp = Blueprint('chat_advanced', __name__, url_prefix='/api/chat/v2')

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'uploads')


# === SALAS ===

@chat_advanced_bp.route('/rooms')
def get_rooms():
    """Lista salas disponíveis"""
    try:
        username = request.args.get('username', '')
        rooms = chat_manager.get_rooms(username)
        return jsonify(rooms), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/rooms', methods=['POST'])
@require_rate_limit
def create_room():
    """Cria uma nova sala"""
    try:
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        created_by = data.get('username', 'Anônimo')
        is_private = data.get('is_private', False)
        
        if not name:
            return jsonify({'error': 'Nome da sala é obrigatório'}), 400
        
        if len(name) > 50:
            return jsonify({'error': 'Nome muito longo (máx 50 caracteres)'}), 400
        
        room = chat_manager.create_room(name, created_by, is_private)
        audit_log.log('room_created', {'room_id': room.id, 'name': name})
        
        return jsonify({'success': True, 'room': room.to_dict()}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/rooms/<room_id>/join', methods=['POST'])
def join_room(room_id):
    """Entra em uma sala"""
    try:
        data = request.get_json() or {}
        username = data.get('username', 'Anônimo')
        
        if chat_manager.join_room(room_id, username):
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Não foi possível entrar na sala'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/rooms/<room_id>/leave', methods=['POST'])
def leave_room(room_id):
    """Sai de uma sala"""
    try:
        data = request.get_json() or {}
        username = data.get('username', 'Anônimo')
        
        if chat_manager.leave_room(room_id, username):
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Não foi possível sair da sala'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# === MENSAGENS ===

@chat_advanced_bp.route('/rooms/<room_id>/messages')
def get_messages(room_id):
    """Obtém mensagens de uma sala"""
    try:
        limit = request.args.get('limit', 50, type=int)
        before_id = request.args.get('before_id')
        
        messages = chat_manager.get_messages(room_id, limit, before_id)
        return jsonify(messages), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/rooms/<room_id>/messages', methods=['POST'])
def send_message(room_id):
    """Envia mensagem para uma sala"""
    try:
        # Aceitar tanto JSON quanto FormData
        if request.is_json:
            data = request.get_json() or {}
            username = data.get('username', 'Anônimo')
            content = data.get('content', '').strip()
            msg_type = data.get('type', 'text')
            reply_to = data.get('reply_to')
            file_url = None
        else:
            # FormData
            username = request.form.get('username', 'Anônimo')
            content = request.form.get('content', '').strip()
            msg_type = request.form.get('type', 'text')
            reply_to = request.form.get('reply_to')
            file_url = None
            
            # Handle file upload
            if 'file' in request.files:
                file = request.files['file']
                if file and file.filename:
                    import uuid
                    from werkzeug.utils import secure_filename
                    filename = secure_filename(f"{uuid.uuid4().hex[:8]}_{file.filename}")
                    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(filepath)
                    file_url = f'/static/uploads/{filename}'
                    msg_type = 'file'
        
        if not content and not file_url:
            return jsonify({'error': 'Mensagem vazia'}), 400
        
        if content and len(content) > 2000:
            return jsonify({'error': 'Mensagem muito longa (máx 2000 caracteres)'}), 400
        
        msg = chat_manager.send_message(room_id, username, content, msg_type, reply_to, file_url)
        
        # Emitir via Socket.IO para tempo real
        try:
            from app import socketio
            msg_data = msg.to_dict()
            msg_data['room_id'] = room_id
            socketio.emit('chat_message', msg_data, broadcast=True)
        except Exception as e:
            print(f"[WARN] Socket emit failed: {e}")
        
        # Notificar sobre nova mensagem (para outros usuários na sala)
        notification_manager.notify_new_message(room_id, username, content[:50] if content else '[arquivo]')
        
        # Verificar menções (@username)
        if content:
            import re
            mentions = re.findall(r'@(\w+)', content)
            for mentioned in mentions:
                notification_manager.notify_mention(mentioned, username, room_id, content[:100])
        
        return jsonify({'success': True, 'message': msg.to_dict()}), 201
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/messages/<msg_id>', methods=['PUT'])
def edit_message(msg_id):
    """Edita uma mensagem"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        new_content = data.get('content', '').strip()
        
        if not new_content:
            return jsonify({'error': 'Conteúdo vazio'}), 400
        
        if chat_manager.edit_message(msg_id, username, new_content):
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Não foi possível editar'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/messages/<msg_id>', methods=['DELETE'])
def delete_message(msg_id):
    """Apaga uma mensagem"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        
        if chat_manager.delete_message(msg_id, username):
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Não foi possível apagar'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# === REAÇÕES ===

@chat_advanced_bp.route('/messages/<msg_id>/reactions', methods=['POST'])
def add_reaction(msg_id):
    """Adiciona reação a uma mensagem"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        emoji = data.get('emoji')
        
        if not emoji:
            return jsonify({'error': 'Emoji é obrigatório'}), 400
        
        if chat_manager.add_reaction(msg_id, username, emoji):
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Emoji inválido ou já reagido'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/messages/<msg_id>/reactions', methods=['DELETE'])
def remove_reaction(msg_id):
    """Remove reação de uma mensagem"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        emoji = data.get('emoji')
        
        if chat_manager.remove_reaction(msg_id, username, emoji):
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Reação não encontrada'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/emojis')
def get_emojis():
    """Lista emojis disponíveis"""
    return jsonify({'emojis': chat_manager.EMOJI_LIST}), 200


# === TYPING ===

@chat_advanced_bp.route('/rooms/<room_id>/typing', methods=['POST'])
def set_typing(room_id):
    """Indica que usuário está digitando"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        
        chat_manager.set_typing(room_id, username)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/rooms/<room_id>/typing')
def get_typing(room_id):
    """Obtém quem está digitando"""
    try:
        typing_users = chat_manager.get_typing_users(room_id)
        return jsonify({'typing': typing_users}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# === MENSAGENS PRIVADAS ===

@chat_advanced_bp.route('/dm')
def get_private_chats():
    """Lista chats privados do usuário"""
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({'error': 'Username é obrigatório'}), 400
        
        chats = chat_manager.get_private_chats(username)
        return jsonify({'chats': chats}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@chat_advanced_bp.route('/dm/<to_user>', methods=['POST'])
@require_rate_limit
def send_private_message(to_user):
    """Envia mensagem privada"""
    try:
        data = request.get_json() or {}
        from_user = data.get('username')
        content = data.get('content', '').strip()
        
        if not from_user or not content:
            return jsonify({'error': 'Username e conteúdo são obrigatórios'}), 400
        
        msg = chat_manager.send_private_message(from_user, to_user, content)
        
        # Notificar destinatário
        notification_manager.notify_private_message(to_user, from_user, content[:50])
        
        return jsonify({'success': True, 'message': msg.to_dict()}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# === UPLOAD DE ARQUIVOS ===

@chat_advanced_bp.route('/upload', methods=['POST'])
@require_rate_limit
def upload_file():
    """Upload de arquivo para o chat"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
        
        # Validar extensão
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'txt', 'zip'}
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if ext not in allowed_extensions:
            return jsonify({'error': f'Tipo de arquivo não permitido. Permitidos: {", ".join(allowed_extensions)}'}), 400
        
        # Validar tamanho (máx 5MB)
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        
        if size > 5 * 1024 * 1024:
            return jsonify({'error': 'Arquivo muito grande (máx 5MB)'}), 400
        
        # Salvar arquivo
        import uuid
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filename = f"{uuid.uuid4()}.{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        file_url = f"/static/uploads/{filename}"
        
        return jsonify({
            'success': True,
            'file_url': file_url,
            'filename': file.filename,
            'size': size
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# === STATS ===

@chat_advanced_bp.route('/stats')
def get_stats():
    """Estatísticas do chat"""
    try:
        stats = chat_manager.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
