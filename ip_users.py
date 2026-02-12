"""
Sistema de Usuários por IP - Contas fixas baseadas no endereço IP
Cada IP tem uma conta única e persistente
"""

import json
import os
import hashlib
import threading
from datetime import datetime
from pathlib import Path


class IPUserManager:
    """Gerenciador de usuários baseado em IP"""
    
    DATA_FILE = 'data/ip_users.json'
    
    def __init__(self):
        self.users = {}  # ip -> user_data
        self.lock = threading.Lock()
        self._ensure_data_dir()
        self._load_data()
    
    def _ensure_data_dir(self):
        """Garantir que o diretório de dados existe"""
        Path('data').mkdir(exist_ok=True)
    
    def _load_data(self):
        """Carregar dados do arquivo JSON"""
        try:
            if os.path.exists(self.DATA_FILE):
                with open(self.DATA_FILE, 'r', encoding='utf-8') as f:
                    self.users = json.load(f)
                print(f"[IPUserManager] Carregados {len(self.users)} usuários")
        except Exception as e:
            print(f"[IPUserManager] Erro ao carregar dados: {e}")
            self.users = {}
    
    def _save_data(self):
        """Salvar dados no arquivo JSON"""
        try:
            with open(self.DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print(f"[IPUserManager] Erro ao salvar dados: {e}")
    
    def _generate_username(self, ip):
        """Gerar username único baseado no IP"""
        # Hash do IP para criar ID curto
        ip_hash = hashlib.md5(ip.encode()).hexdigest()[:8]
        return f"user_{ip_hash}"
    
    def get_or_create_user(self, ip, user_agent='', system_info=None):
        """
        Obter usuário existente ou criar novo baseado no IP
        Retorna: (user_data, is_new)
        """
        with self.lock:
            now = datetime.now().isoformat()
            
            if ip in self.users:
                # Usuário existe - atualizar dados
                user = self.users[ip]
                user['last_seen'] = now
                user['total_visits'] += 1
                user['user_agent'] = user_agent
                
                # Atualizar system_info se fornecido
                if system_info:
                    user['system_info'] = self._merge_system_info(
                        user.get('system_info', {}), 
                        system_info
                    )
                
                self._save_data()
                return user, False
            
            # Criar novo usuário
            username = self._generate_username(ip)
            user = {
                'ip': ip,
                'username': username,
                'created_at': now,
                'last_seen': now,
                'first_visit': now,
                'total_visits': 1,
                'user_agent': user_agent,
                'system_info': system_info or {},
                'terms_accepted': now,
                'status': 'active',
                'sessions': []
            }
            
            self.users[ip] = user
            self._save_data()
            print(f"[IPUserManager] Novo usuário criado: {username} ({ip})")
            return user, True
    
    def _merge_system_info(self, existing, new):
        """Mesclar informações do sistema, mantendo dados mais recentes"""
        if not existing:
            return new
        if not new:
            return existing
        
        # Mesclar, preferindo novos valores não-nulos
        merged = existing.copy()
        for key, value in new.items():
            if value and value != 'N/A':
                merged[key] = value
        
        return merged
    
    def update_user(self, ip, data):
        """Atualizar dados do usuário"""
        with self.lock:
            if ip in self.users:
                self.users[ip].update(data)
                self.users[ip]['last_seen'] = datetime.now().isoformat()
                self._save_data()
                return True
            return False
    
    def update_system_info(self, ip, system_info):
        """Atualizar informações do sistema do usuário"""
        with self.lock:
            if ip in self.users:
                self.users[ip]['system_info'] = self._merge_system_info(
                    self.users[ip].get('system_info', {}),
                    system_info
                )
                self.users[ip]['last_seen'] = datetime.now().isoformat()
                self._save_data()
                return True
            return False
    
    def get_user(self, ip):
        """Obter usuário por IP"""
        with self.lock:
            return self.users.get(ip)
    
    def get_user_by_username(self, username):
        """Obter usuário por username"""
        with self.lock:
            for ip, user in self.users.items():
                if user['username'] == username:
                    return user
            return None
    
    def get_all_users(self):
        """Obter todos os usuários"""
        with self.lock:
            return list(self.users.values())
    
    def get_users_count(self):
        """Obter contagem de usuários"""
        with self.lock:
            return len(self.users)
    
    def get_active_users(self, minutes=30):
        """Obter usuários ativos nos últimos N minutos"""
        with self.lock:
            from datetime import timedelta
            cutoff = datetime.now() - timedelta(minutes=minutes)
            
            active = []
            for user in self.users.values():
                try:
                    last_seen = datetime.fromisoformat(user['last_seen'])
                    if last_seen >= cutoff:
                        active.append(user)
                except:
                    pass
            
            return active
    
    def export_for_csv(self):
        """
        Exportar dados otimizados para CSV
        Retorna lista de dicts com campos achatados
        """
        with self.lock:
            rows = []
            for user in self.users.values():
                sys_info = user.get('system_info', {})
                
                row = {
                    'ip': user['ip'],
                    'username': user['username'],
                    'created_at': user['created_at'],
                    'last_seen': user['last_seen'],
                    'total_visits': user['total_visits'],
                    'platform': sys_info.get('platform', 'N/A'),
                    'language': sys_info.get('language', 'N/A'),
                    'cores': sys_info.get('cores', 'N/A'),
                    'memory': sys_info.get('memory', 'N/A'),
                    'screen': f"{sys_info.get('screenWidth', 'N/A')}x{sys_info.get('screenHeight', 'N/A')}",
                    'timezone': sys_info.get('timezone', 'N/A'),
                    'ip_publico': sys_info.get('ipPublico', 'N/A'),
                    'user_agent': user.get('user_agent', 'N/A')[:100]
                }
                rows.append(row)
            
            return rows
    
    def export_for_json(self):
        """Exportar dados completos para JSON"""
        with self.lock:
            return {
                'exported_at': datetime.now().isoformat(),
                'total_users': len(self.users),
                'users': list(self.users.values())
            }
    
    def get_stats(self):
        """Obter estatísticas gerais"""
        with self.lock:
            total = len(self.users)
            active_30m = len(self.get_active_users(30))
            active_24h = len(self.get_active_users(60 * 24))
            
            total_visits = sum(u.get('total_visits', 0) for u in self.users.values())
            
            return {
                'total_users': total,
                'active_last_30min': active_30m,
                'active_last_24h': active_24h,
                'total_visits': total_visits,
                'avg_visits_per_user': round(total_visits / max(total, 1), 2)
            }


# Instância global
ip_user_manager = IPUserManager()
