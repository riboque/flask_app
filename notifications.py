"""
Sistema de Notificações Push
- Notificações no navegador
- Alertas em tempo real
"""
import json
import os
from datetime import datetime
from typing import List, Optional

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


class NotificationType:
    """Tipos de notificação"""
    NEW_MESSAGE = 'new_message'
    NEW_USER = 'new_user'
    MENTION = 'mention'
    SYSTEM = 'system'
    ALERT = 'alert'
    PRIVATE_MESSAGE = 'private_message'


class Notification:
    """Representa uma notificação"""
    
    def __init__(self, notif_id: str, notif_type: str, title: str, 
                 message: str, target_user: str = None, data: dict = None):
        self.id = notif_id
        self.type = notif_type
        self.title = title
        self.message = message
        self.target_user = target_user  # None = broadcast para todos
        self.data = data or {}
        self.created_at = datetime.now().isoformat()
        self.read = False
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'type': self.type,
            'title': self.title,
            'message': self.message,
            'target_user': self.target_user,
            'data': self.data,
            'created_at': self.created_at,
            'read': self.read
        }


class NotificationManager:
    """Gerenciador de notificações"""
    
    def __init__(self):
        self.data_file = os.path.join(DATA_DIR, 'notifications.json')
        self.notifications: List[Notification] = []
        self.subscriptions = {}  # username -> subscription_info
        self._notification_counter = 0
        self._load_data()
    
    def _load_data(self):
        """Carrega notificações salvas"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for n_data in data.get('notifications', [])[-1000:]:
                        n = Notification(
                            n_data['id'],
                            n_data['type'],
                            n_data['title'],
                            n_data['message'],
                            n_data.get('target_user'),
                            n_data.get('data', {})
                        )
                        n.created_at = n_data.get('created_at', datetime.now().isoformat())
                        n.read = n_data.get('read', False)
                        self.notifications.append(n)
                    self.subscriptions = data.get('subscriptions', {})
                    self._notification_counter = data.get('counter', len(self.notifications))
        except Exception as e:
            print(f"[NOTIF] Erro ao carregar: {e}")
    
    def _save_data(self):
        """Salva notificações"""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'notifications': [n.to_dict() for n in self.notifications[-1000:]],
                    'subscriptions': self.subscriptions,
                    'counter': self._notification_counter
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[NOTIF] Erro ao salvar: {e}")
    
    def create_notification(self, notif_type: str, title: str, message: str,
                           target_user: str = None, data: dict = None) -> Notification:
        """Cria uma nova notificação"""
        self._notification_counter += 1
        notif_id = f"notif_{self._notification_counter}"
        
        notif = Notification(notif_id, notif_type, title, message, target_user, data)
        self.notifications.append(notif)
        self._save_data()
        
        return notif
    
    def notify_new_user(self, username: str, ip: str):
        """Notifica sobre novo usuário"""
        return self.create_notification(
            NotificationType.NEW_USER,
            '👤 Novo Usuário',
            f'{username} entrou no sistema',
            data={'username': username, 'ip': ip}
        )
    
    def notify_new_message(self, room_id: str, username: str, preview: str, target_user: str = None):
        """Notifica sobre nova mensagem"""
        return self.create_notification(
            NotificationType.NEW_MESSAGE,
            f'💬 {username}',
            preview[:100],
            target_user=target_user,
            data={'room_id': room_id, 'username': username}
        )
    
    def notify_mention(self, mentioned_user: str, by_user: str, room_id: str, message: str):
        """Notifica sobre menção"""
        return self.create_notification(
            NotificationType.MENTION,
            f'📢 {by_user} mencionou você',
            message[:100],
            target_user=mentioned_user,
            data={'room_id': room_id, 'by_user': by_user}
        )
    
    def notify_private_message(self, to_user: str, from_user: str, preview: str):
        """Notifica sobre mensagem privada"""
        return self.create_notification(
            NotificationType.PRIVATE_MESSAGE,
            f'✉️ Mensagem de {from_user}',
            preview[:100],
            target_user=to_user,
            data={'from_user': from_user}
        )
    
    def notify_system(self, title: str, message: str, target_user: str = None):
        """Notificação do sistema"""
        return self.create_notification(
            NotificationType.SYSTEM,
            f'⚙️ {title}',
            message,
            target_user=target_user
        )
    
    def notify_alert(self, title: str, message: str, target_user: str = None):
        """Alerta importante"""
        return self.create_notification(
            NotificationType.ALERT,
            f'⚠️ {title}',
            message,
            target_user=target_user
        )
    
    def get_notifications(self, username: str = None, unread_only: bool = False, 
                         limit: int = 50) -> List[dict]:
        """Obtém notificações do usuário"""
        notifications = []
        
        for n in reversed(self.notifications):
            # Filtrar por usuário (notificações para ele ou broadcasts)
            if username and n.target_user and n.target_user != username:
                continue
            
            if unread_only and n.read:
                continue
            
            notifications.append(n.to_dict())
            
            if len(notifications) >= limit:
                break
        
        return notifications
    
    def mark_as_read(self, notif_id: str, username: str = None) -> bool:
        """Marca notificação como lida"""
        for n in self.notifications:
            if n.id == notif_id:
                if username and n.target_user and n.target_user != username:
                    return False
                n.read = True
                self._save_data()
                return True
        return False
    
    def mark_all_as_read(self, username: str = None):
        """Marca todas notificações como lidas"""
        for n in self.notifications:
            if not username or not n.target_user or n.target_user == username:
                n.read = True
        self._save_data()
    
    def get_unread_count(self, username: str = None) -> int:
        """Conta notificações não lidas"""
        count = 0
        for n in self.notifications:
            if not n.read:
                if not username or not n.target_user or n.target_user == username:
                    count += 1
        return count
    
    def subscribe_push(self, username: str, subscription_info: dict):
        """Registra subscription para push notifications"""
        self.subscriptions[username] = {
            'subscription': subscription_info,
            'subscribed_at': datetime.now().isoformat()
        }
        self._save_data()
    
    def unsubscribe_push(self, username: str):
        """Remove subscription"""
        if username in self.subscriptions:
            del self.subscriptions[username]
            self._save_data()
    
    def get_stats(self) -> dict:
        """Estatísticas de notificações"""
        type_count = {}
        for n in self.notifications:
            type_count[n.type] = type_count.get(n.type, 0) + 1
        
        return {
            'total': len(self.notifications),
            'unread': self.get_unread_count(),
            'by_type': type_count,
            'subscribed_users': len(self.subscriptions)
        }


# Instância global
notification_manager = NotificationManager()
