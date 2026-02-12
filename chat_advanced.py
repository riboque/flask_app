"""
Sistema de Chat Avançado
- Salas de chat
- Mensagens privadas
- Reações/Emojis
- Upload de arquivos
- Histórico persistente
"""
import json
import os
import uuid
from datetime import datetime
from typing import Optional, List, Dict

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


class ChatRoom:
    """Representa uma sala de chat"""
    
    def __init__(self, room_id: str, name: str, created_by: str, is_private: bool = False):
        self.id = room_id
        self.name = name
        self.created_by = created_by
        self.created_at = datetime.now().isoformat()
        self.is_private = is_private
        self.members = [created_by]
        self.messages = []
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'name': self.name,
            'created_by': self.created_by,
            'created_at': self.created_at,
            'is_private': self.is_private,
            'members': self.members,
            'members_count': len(self.members),
            'member_count': len(self.members),  # Alias para compatibilidade
            'messages_count': len(self.messages)
        }


class ChatMessage:
    """Representa uma mensagem de chat"""
    
    def __init__(self, msg_id: str, room_id: str, username: str, content: str, 
                 msg_type: str = 'text', reply_to: str = None, file_url: str = None):
        self.id = msg_id
        self.room_id = room_id
        self.username = username
        self.content = content
        self.type = msg_type  # text, image, file, system
        self.reply_to = reply_to
        self.file_url = file_url
        self.reactions = {}  # emoji -> [usernames]
        self.created_at = datetime.now().isoformat()
        self.edited = False
        self.deleted = False
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'room_id': self.room_id,
            'username': self.username,
            'content': self.content if not self.deleted else '[Mensagem apagada]',
            'type': self.type,
            'reply_to': self.reply_to,
            'file_url': self.file_url,
            'reactions': self.reactions,
            'created_at': self.created_at,
            'edited': self.edited,
            'deleted': self.deleted
        }


class AdvancedChatManager:
    """Gerenciador de chat avançado"""
    
    EMOJI_LIST = ['👍', '❤️', '😂', '😮', '😢', '😡', '🎉', '🔥', '👀', '💯']
    
    def __init__(self):
        self.data_file = os.path.join(DATA_DIR, 'chat_data.json')
        self.rooms: Dict[str, ChatRoom] = {}
        self.messages: Dict[str, ChatMessage] = {}
        self.private_chats: Dict[str, List[str]] = {}  # user_key -> [other_users]
        self.typing_users: Dict[str, Dict[str, datetime]] = {}  # room_id -> {username: last_typing}
        self._load_data()
        self._ensure_default_rooms()
    
    def _ensure_default_rooms(self):
        """Cria salas padrão se não existirem"""
        default_rooms = [
            ('general', 'Geral', 'Sistema'),
            ('help', 'Ajuda', 'Sistema'),
            ('random', 'Random', 'Sistema')
        ]
        
        for room_id, name, creator in default_rooms:
            if room_id not in self.rooms:
                self.rooms[room_id] = ChatRoom(room_id, name, creator)
        
        self._save_data()
    
    def _load_data(self):
        """Carrega dados do chat"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Carregar salas
                    for room_data in data.get('rooms', []):
                        room = ChatRoom(
                            room_data['id'],
                            room_data['name'],
                            room_data['created_by'],
                            room_data.get('is_private', False)
                        )
                        room.members = room_data.get('members', [])
                        room.created_at = room_data.get('created_at', datetime.now().isoformat())
                        self.rooms[room.id] = room
                    
                    # Carregar mensagens (últimas 1000 por sala)
                    for msg_data in data.get('messages', [])[-5000:]:
                        msg = ChatMessage(
                            msg_data['id'],
                            msg_data['room_id'],
                            msg_data['username'],
                            msg_data['content'],
                            msg_data.get('type', 'text'),
                            msg_data.get('reply_to'),
                            msg_data.get('file_url')
                        )
                        msg.reactions = msg_data.get('reactions', {})
                        msg.created_at = msg_data.get('created_at', datetime.now().isoformat())
                        msg.edited = msg_data.get('edited', False)
                        msg.deleted = msg_data.get('deleted', False)
                        self.messages[msg.id] = msg
        except Exception as e:
            print(f"[CHAT] Erro ao carregar: {e}")
    
    def _save_data(self):
        """Salva dados do chat"""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'rooms': [r.to_dict() for r in self.rooms.values()],
                    'messages': [m.to_dict() for m in list(self.messages.values())[-5000:]]
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[CHAT] Erro ao salvar: {e}")
    
    # === SALAS ===
    
    def create_room(self, name: str, created_by: str, is_private: bool = False) -> ChatRoom:
        """Cria uma nova sala"""
        room_id = str(uuid.uuid4())[:8]
        room = ChatRoom(room_id, name, created_by, is_private)
        self.rooms[room_id] = room
        self._save_data()
        return room
    
    def get_room(self, room_id: str) -> Optional[ChatRoom]:
        """Obtém uma sala pelo ID"""
        return self.rooms.get(room_id)
    
    def get_rooms(self, username: str = None) -> List[dict]:
        """Lista salas disponíveis para o usuário"""
        rooms = []
        for room in self.rooms.values():
            if not room.is_private or username in room.members:
                rooms.append(room.to_dict())
        return rooms
    
    def join_room(self, room_id: str, username: str) -> bool:
        """Usuário entra em uma sala"""
        room = self.rooms.get(room_id)
        if room and username not in room.members:
            room.members.append(username)
            self._save_data()
            return True
        return False
    
    def leave_room(self, room_id: str, username: str) -> bool:
        """Usuário sai de uma sala"""
        room = self.rooms.get(room_id)
        if room and username in room.members:
            room.members.remove(username)
            self._save_data()
            return True
        return False
    
    # === MENSAGENS ===
    
    def send_message(self, room_id: str, username: str, content: str, 
                     msg_type: str = 'text', reply_to: str = None, 
                     file_url: str = None) -> ChatMessage:
        """Envia uma mensagem"""
        msg_id = str(uuid.uuid4())
        msg = ChatMessage(msg_id, room_id, username, content, msg_type, reply_to, file_url)
        self.messages[msg_id] = msg
        
        # Adicionar à sala
        room = self.rooms.get(room_id)
        if room:
            room.messages.append(msg_id)
        
        self._save_data()
        return msg
    
    def get_messages(self, room_id: str, limit: int = 50, before_id: str = None) -> List[dict]:
        """Obtém mensagens de uma sala"""
        room_messages = [
            m.to_dict() for m in self.messages.values()
            if m.room_id == room_id and not m.deleted
        ]
        room_messages.sort(key=lambda x: x['created_at'])
        
        if before_id:
            # Paginação: mensagens antes do ID especificado
            idx = next((i for i, m in enumerate(room_messages) if m['id'] == before_id), len(room_messages))
            room_messages = room_messages[max(0, idx - limit):idx]
        else:
            room_messages = room_messages[-limit:]
        
        return room_messages
    
    def edit_message(self, msg_id: str, username: str, new_content: str) -> bool:
        """Edita uma mensagem"""
        msg = self.messages.get(msg_id)
        if msg and msg.username == username and not msg.deleted:
            msg.content = new_content
            msg.edited = True
            self._save_data()
            return True
        return False
    
    def delete_message(self, msg_id: str, username: str) -> bool:
        """Apaga uma mensagem (soft delete)"""
        msg = self.messages.get(msg_id)
        if msg and msg.username == username:
            msg.deleted = True
            self._save_data()
            return True
        return False
    
    # === REAÇÕES ===
    
    def add_reaction(self, msg_id: str, username: str, emoji: str) -> bool:
        """Adiciona reação a uma mensagem"""
        if emoji not in self.EMOJI_LIST:
            return False
        
        msg = self.messages.get(msg_id)
        if not msg:
            return False
        
        if emoji not in msg.reactions:
            msg.reactions[emoji] = []
        
        if username not in msg.reactions[emoji]:
            msg.reactions[emoji].append(username)
            self._save_data()
            return True
        return False
    
    def remove_reaction(self, msg_id: str, username: str, emoji: str) -> bool:
        """Remove reação de uma mensagem"""
        msg = self.messages.get(msg_id)
        if msg and emoji in msg.reactions and username in msg.reactions[emoji]:
            msg.reactions[emoji].remove(username)
            if not msg.reactions[emoji]:
                del msg.reactions[emoji]
            self._save_data()
            return True
        return False
    
    # === TYPING ===
    
    def set_typing(self, room_id: str, username: str):
        """Marca usuário como digitando"""
        if room_id not in self.typing_users:
            self.typing_users[room_id] = {}
        self.typing_users[room_id][username] = datetime.now()
    
    def get_typing_users(self, room_id: str) -> List[str]:
        """Obtém usuários digitando (últimos 3 segundos)"""
        if room_id not in self.typing_users:
            return []
        
        now = datetime.now()
        typing = []
        to_remove = []
        
        for username, last_time in self.typing_users[room_id].items():
            if (now - last_time).total_seconds() < 3:
                typing.append(username)
            else:
                to_remove.append(username)
        
        for username in to_remove:
            del self.typing_users[room_id][username]
        
        return typing
    
    # === MENSAGENS PRIVADAS ===
    
    def get_private_room_id(self, user1: str, user2: str) -> str:
        """Gera ID de sala privada entre dois usuários"""
        users = sorted([user1, user2])
        return f"dm_{users[0]}_{users[1]}"
    
    def send_private_message(self, from_user: str, to_user: str, content: str) -> ChatMessage:
        """Envia mensagem privada"""
        room_id = self.get_private_room_id(from_user, to_user)
        
        # Criar sala privada se não existir
        if room_id not in self.rooms:
            room = ChatRoom(room_id, f"DM: {from_user} & {to_user}", from_user, is_private=True)
            room.members = [from_user, to_user]
            self.rooms[room_id] = room
        
        return self.send_message(room_id, from_user, content, 'text')
    
    def get_private_chats(self, username: str) -> List[dict]:
        """Lista chats privados do usuário"""
        chats = []
        for room in self.rooms.values():
            if room.is_private and username in room.members:
                other_user = [m for m in room.members if m != username]
                chats.append({
                    'room_id': room.id,
                    'other_user': other_user[0] if other_user else 'Desconhecido',
                    'last_message': self._get_last_message(room.id)
                })
        return chats
    
    def _get_last_message(self, room_id: str) -> Optional[dict]:
        """Obtém última mensagem de uma sala"""
        room_messages = [m for m in self.messages.values() if m.room_id == room_id and not m.deleted]
        if room_messages:
            room_messages.sort(key=lambda x: x.created_at)
            return room_messages[-1].to_dict()
        return None
    
    # === ESTATÍSTICAS ===
    
    def get_stats(self) -> dict:
        """Retorna estatísticas do chat"""
        return {
            'total_rooms': len(self.rooms),
            'total_messages': len(self.messages),
            'active_rooms': len([r for r in self.rooms.values() if r.messages]),
            'emojis_available': self.EMOJI_LIST
        }


# Instância global
chat_manager = AdvancedChatManager()
