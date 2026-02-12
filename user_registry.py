"""
Sistema de Registro de Usuários - User Registry System
Gerencia conexões, status online/offline e histórico de usuários
"""

from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time

class UserRegistry:
    """Classe principal para gerenciar registro de usuários conectados"""

    def __init__(self):
        # Dicionário de usuários registrados: username -> user_data
        self.registered_users = {}

        # Dicionário de usuários online: username -> connection_info
        self.online_users = {}

        # Histórico de conexões: username -> list of connection_events
        self.connection_history = defaultdict(list)

        # Lock para thread safety
        self.lock = threading.Lock()

        # Configurações
        self.offline_timeout = 300  # 5 minutos sem atividade = offline
        self.cleanup_interval = 3600  # Limpeza a cada hora

        # Iniciar thread de limpeza automática
        self.cleanup_thread = threading.Thread(target=self._auto_cleanup, daemon=True)
        self.cleanup_thread.start()

    def register_user(self, username, user_data=None):
        """Registrar novo usuário no sistema"""
        with self.lock:
            username = username.lower().strip()
            if username not in self.registered_users:
                self.registered_users[username] = {
                    'username': username,
                    'registered_at': datetime.now(),
                    'last_login': None,
                    'last_logout': None,
                    'total_connections': 0,
                    'total_time_online': 0,  # em segundos
                    'current_session_start': None,
                    'status': 'offline',
                    'ip': None,
                    'user_agent': None,
                    'metadata': user_data or {}
                }
                self._log_connection_event(username, 'registered', 'Usuário registrado no sistema')
                return True, "Usuário registrado com sucesso"
            return False, "Usuário já existe"

    def user_login(self, username, ip=None, user_agent=None):
        """Registrar login do usuário"""
        with self.lock:
            username = username.lower().strip()

            # Registrar usuário se não existir
            if username not in self.registered_users:
                self.register_user(username)

            user = self.registered_users[username]

            # Atualizar informações
            user['last_login'] = datetime.now()
            user['ip'] = ip
            user['user_agent'] = user_agent
            user['status'] = 'online'
            user['current_session_start'] = datetime.now()
            user['total_connections'] += 1

            # Registrar como online
            self.online_users[username] = {
                'login_time': datetime.now(),
                'ip': ip,
                'user_agent': user_agent,
                'last_activity': datetime.now()
            }

            self._log_connection_event(username, 'login', f'Login de {ip}')
            return True

    def user_logout(self, username, reason="logout"):
        """Registrar logout do usuário"""
        with self.lock:
            username = username.lower().strip()

            if username in self.registered_users:
                user = self.registered_users[username]
                user['last_logout'] = datetime.now()
                user['status'] = 'offline'

                # Calcular tempo da sessão
                if user['current_session_start']:
                    session_time = (datetime.now() - user['current_session_start']).total_seconds()
                    user['total_time_online'] += session_time
                    user['current_session_start'] = None

                # Remover da lista online
                if username in self.online_users:
                    del self.online_users[username]

                self._log_connection_event(username, 'logout', f'Logout: {reason}')
                return True

            return False

    def update_user_activity(self, username, ip=None):
        """Atualizar atividade do usuário (manter online)"""
        with self.lock:
            username = username.lower().strip()

            if username in self.online_users:
                self.online_users[username]['last_activity'] = datetime.now()
                if ip:
                    self.online_users[username]['ip'] = ip
                return True
            return False

    def get_user_status(self, username):
        """Obter status atual de um usuário"""
        with self.lock:
            username = username.lower().strip()

            if username not in self.registered_users:
                return {'status': 'unknown', 'message': 'Usuário não registrado'}

            user = self.registered_users[username]

            # Verificar se ainda está online
            if username in self.online_users:
                last_activity = self.online_users[username]['last_activity']
                if (datetime.now() - last_activity).total_seconds() > self.offline_timeout:
                    # Marcar como offline por inatividade
                    self.user_logout(username, "timeout")
                    user['status'] = 'offline'

            return {
                'username': username,
                'status': user['status'],
                'last_login': user['last_login'].isoformat() if user['last_login'] else None,
                'last_logout': user['last_logout'].isoformat() if user['last_logout'] else None,
                'ip': user.get('ip'),
                'total_connections': user['total_connections'],
                'total_time_online': user['total_time_online'],
                'registered_at': user['registered_at'].isoformat(),
                'metadata': user['metadata']
            }

    def get_online_users(self):
        """Obter lista de usuários online"""
        with self.lock:
            online_list = []

            for username in list(self.online_users.keys()):
                status = self.get_user_status(username)
                if status['status'] == 'online':
                    online_list.append({
                        'username': username,
                        'login_time': self.online_users[username]['login_time'].isoformat(),
                        'last_activity': self.online_users[username]['last_activity'].isoformat(),
                        'ip': self.online_users[username]['ip'],
                        'user_agent': self.online_users[username]['user_agent']
                    })

            return sorted(online_list, key=lambda x: x['last_activity'], reverse=True)

    def get_all_users(self):
        """Obter lista de todos os usuários registrados"""
        with self.lock:
            users_list = []
            for username, user_data in self.registered_users.items():
                status = self.get_user_status(username)
                users_list.append(status)

            return sorted(users_list, key=lambda x: x['registered_at'], reverse=True)

    def get_connection_history(self, username, limit=50):
        """Obter histórico de conexões de um usuário"""
        with self.lock:
            username = username.lower().strip()
            if username not in self.connection_history:
                return []

            return self.connection_history[username][-limit:]

    def get_registry_stats(self):
        """Obter estatísticas do registro"""
        with self.lock:
            total_users = len(self.registered_users)
            online_users = len(self.get_online_users())
            total_connections = sum(user['total_connections'] for user in self.registered_users.values())
            total_time_online = sum(user['total_time_online'] for user in self.registered_users.values())

            return {
                'total_users': total_users,
                'online_users': online_users,
                'offline_users': total_users - online_users,
                'total_connections': total_connections,
                'total_time_online_hours': round(total_time_online / 3600, 2),
                'timestamp': datetime.now().isoformat()
            }

    def _log_connection_event(self, username, event_type, details=""):
        """Registrar evento de conexão no histórico"""
        event = {
            'timestamp': datetime.now(),
            'event_type': event_type,
            'details': details
        }
        self.connection_history[username].append(event)

        # Manter apenas últimas 100 entradas por usuário
        if len(self.connection_history[username]) > 100:
            self.connection_history[username].pop(0)

    def _auto_cleanup(self):
        """Thread para limpeza automática de usuários offline"""
        while True:
            time.sleep(self.cleanup_interval)
            try:
                with self.lock:
                    # Verificar usuários online inativos
                    to_remove = []
                    for username, data in self.online_users.items():
                        if (datetime.now() - data['last_activity']).total_seconds() > self.offline_timeout:
                            self.user_logout(username, "auto_cleanup_timeout")

                    # Limpar histórico antigo (mais de 30 dias)
                    cutoff = datetime.now() - timedelta(days=30)
                    for username in self.connection_history:
                        self.connection_history[username] = [
                            event for event in self.connection_history[username]
                            if event['timestamp'] > cutoff
                        ]

            except Exception as e:
                print(f"[UserRegistry] Erro na limpeza automática: {e}")

# Instância global do registro
user_registry = UserRegistry()

# Funções de conveniência para uso direto
def register_user(username, user_data=None):
    return user_registry.register_user(username, user_data)

def user_login(username, ip=None, user_agent=None):
    return user_registry.user_login(username, ip, user_agent)

def user_logout(username, reason="logout"):
    return user_registry.user_logout(username, reason)

def update_user_activity(username, ip=None):
    return user_registry.update_user_activity(username, ip)

def get_user_status(username):
    return user_registry.get_user_status(username)

def get_online_users():
    return user_registry.get_online_users()

def get_all_users():
    return user_registry.get_all_users()

def get_connection_history(username, limit=50):
    return user_registry.get_connection_history(username, limit)

def get_registry_stats():
    return user_registry.get_registry_stats()
