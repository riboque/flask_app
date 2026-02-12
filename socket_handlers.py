"""
Handlers de eventos Socket.IO
Integrado com sistema de usuários por IP
"""
from datetime import datetime


class SocketHandlers:
    """Classe para gerenciar handlers de Socket.IO"""
    
    def __init__(self, socketio, connected_clients, registered_systems, chat_messages):
        self.socketio = socketio
        self.connected_clients = connected_clients
        self.registered_systems = registered_systems
        self.chat_messages = chat_messages
        
        # Registrar handlers
        self._register_handlers()
    
    def _register_handlers(self):
        """Registra os event handlers do Socket.IO"""
        
        @self.socketio.on('connect')
        def handle_connect():
            from flask import request
            from ip_users import ip_user_manager
            from data_collector import data_collector
            
            sid = request.sid
            ip = request.remote_addr or 'desconhecido'
            user_agent = request.headers.get('User-Agent', '')
            
            # Registrar no sistema de usuários por IP
            user, is_new = ip_user_manager.get_or_create_user(ip, user_agent)
            
            info = {
                "ip": ip,
                "user_agent": user_agent,
                "connected_at": datetime.now().isoformat(),
                "username": user['username'],
                "is_new": is_new
            }
            
            self.connected_clients[sid] = info
            data_collector.register_session(sid, ip, user_agent)
            
            # Notificar todos sobre novo cliente
            merged = self._get_merged_clients()
            self.socketio.emit('clients_update', merged, broadcast=True)
            
            status = "Novo" if is_new else "Retornando"
            print(f"[CONNECT] {status}: {user['username']} ({ip})")
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            from flask import request
            from data_collector import data_collector
            
            sid = request.sid
            ip = 'desconhecido'
            username = 'desconhecido'
            
            if sid in self.connected_clients:
                ip = self.connected_clients[sid].get('ip', 'desconhecido')
                username = self.connected_clients[sid].get('username', 'desconhecido')
                self.connected_clients.pop(sid, None)
            
            data_collector.remove_session(sid)
            
            # Atualizar clients_update removendo desconectado
            merged = self._get_merged_clients()
            self.socketio.emit('clients_update', merged, broadcast=True)
            
            print(f"[DISCONNECT] {username} ({ip})")
        
        @self.socketio.on('register_system')
        def handle_register_system(data):
            """Cliente envia informações do sistema para registro no servidor."""
            from flask import request
            from ip_users import ip_user_manager
            from data_collector import data_collector
            
            sid = request.sid
            ip = request.remote_addr
            
            try:
                system_info = data if isinstance(data, dict) else {}
                
                # Atualizar no sistema de usuários por IP
                ip_user_manager.update_system_info(ip, system_info)
                data_collector.update_session(sid, system_info)
                
                self.registered_systems[sid] = {
                    'system_info': system_info,
                    'registered_at': datetime.now().isoformat(),
                    'ip': ip
                }
                
                # Notificar o dashboard com dados atualizados
                merged = self._get_merged_clients()
                self.socketio.emit('clients_update', merged, broadcast=True)
                
                print(f"[SYSTEM] Dados recebidos de {ip}: {system_info.get('platform', 'N/A')}")
                return True
            except Exception as e:
                print(f"[ERRO] register_system: {e}")
                return False
        
        @self.socketio.on('message')
        def handle_message(data):
            """Recebe mensagem do chat e retransmite para todos."""
            username = data.get('username', 'Anônimo')
            message = data.get('message', '')
            
            # Armazenar mensagem
            msg_obj = {
                'username': username,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'id': len(self.chat_messages) + 1
            }
            self.chat_messages.append(msg_obj)
            
            # Manter apenas últimas 100 mensagens
            if len(self.chat_messages) > 100:
                self.chat_messages.pop(0)
            
            self.socketio.emit('message', {'username': username, 'message': message}, broadcast=True)
        
        @self.socketio.on('chat_message')
        def handle_chat_message(data):
            """Recebe mensagem do chat v2 e retransmite em tempo real."""
            from chat_advanced import chat_manager
            
            room_id = data.get('room_id', 'general')
            username = data.get('username', 'Anônimo')
            content = data.get('content', '')
            
            if not content.strip():
                return
            
            # Salvar mensagem no chat manager
            try:
                msg = chat_manager.send_message(room_id, username, content.strip())
                msg_data = msg.to_dict()
                msg_data['room_id'] = room_id
                
                # Emitir para todos na sala
                self.socketio.emit('chat_message', msg_data, broadcast=True)
            except Exception as e:
                print(f"[ERRO] chat_message: {e}")
        
        @self.socketio.on('user_join')
        def handle_user_join(data):
            """Usuário entrou no chat."""
            from flask import request
            
            username = data.get('username', 'Anônimo')
            room_id = data.get('room', 'general')
            sid = request.sid
            
            print(f"[CHAT] {username} entrou no chat (sala: {room_id})")
            
            # Notificar todos
            self.socketio.emit('user_joined', {
                'username': username,
                'room_id': room_id
            }, broadcast=True)
        
        @self.socketio.on('join_room')
        def handle_join_room(data):
            """Usuário entra em uma sala específica."""
            from flask import request
            from flask_socketio import join_room
            
            room_id = data.get('room_id', 'general')
            username = data.get('username', 'Anônimo')
            
            join_room(room_id)
            print(f"[CHAT] {username} entrou na sala {room_id}")
            
            self.socketio.emit('user_joined_room', {
                'username': username,
                'room_id': room_id
            }, room=room_id)
        
        @self.socketio.on('leave_room')
        def handle_leave_room(data):
            """Usuário sai de uma sala."""
            from flask import request
            from flask_socketio import leave_room
            
            room_id = data.get('room_id')
            if room_id:
                leave_room(room_id)
        
        @self.socketio.on('typing')
        def handle_typing(data):
            """Indicador de digitação."""
            from flask import request
            
            room_id = data.get('room_id', 'general')
            username = data.get('username', 'Alguém')
            is_typing = data.get('typing', False)
            
            self.socketio.emit('typing', {
                'room_id': room_id,
                'username': username,
                'typing': is_typing
            }, broadcast=True, include_self=False)
    
    def _client_info_from_request(self, req):
        """Extrai informações úteis do request para registrar o cliente."""
        ip = req.remote_addr or 'desconhecido'
        ua = req.headers.get('User-Agent', '') if req and hasattr(req, 'headers') else ''
        return {
            "ip": ip,
            "user_agent": ua,
            "connected_at": datetime.now().isoformat()
        }
    
    def _get_merged_clients(self):
        """Retorna lista de clientes mesclados com informações de sistema."""
        merged = []
        for s, v in self.connected_clients.items():
            entry = dict(v)
            if s in self.registered_systems:
                entry['system_info'] = self.registered_systems[s].get('system_info')
            merged.append(entry)
        return merged


def init_socket_handlers(socketio, connected_clients, registered_systems, chat_messages):
    """Inicializa os handlers de Socket.IO"""
    return SocketHandlers(socketio, connected_clients, registered_systems, chat_messages)
