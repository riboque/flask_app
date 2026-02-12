"""
Sistema de Segurança Avançada
- Rate Limiting
- Bloqueio de IP
- Logs de Auditoria
- Detecção de VPN/Proxy
"""
import json
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from flask import request, jsonify

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


class RateLimiter:
    """Rate limiting por IP com limites diferentes por tipo de rota"""
    
    def __init__(self, max_requests: int = 500, window_seconds: int = 60):
        self.max_requests = max_requests  # Limite para suportar 30 dispositivos
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, ip: str, cost: int = 1) -> tuple:
        """Verifica se IP pode fazer requisição"""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Limpar requisições antigas
        self.requests[ip] = [t for t in self.requests[ip] if t > window_start]
        
        if len(self.requests[ip]) >= self.max_requests:
            remaining_time = int(self.window_seconds - (now - min(self.requests[ip]))) if self.requests[ip] else self.window_seconds
            return False, f"Limite de requisições excedido. Aguarde {remaining_time}s"
        
        # Adicionar requisições baseado no custo
        for _ in range(cost):
            self.requests[ip].append(now)
        return True, None
    
    def get_remaining(self, ip: str) -> int:
        """Retorna requisições restantes"""
        now = time.time()
        window_start = now - self.window_seconds
        self.requests[ip] = [t for t in self.requests[ip] if t > window_start]
        return max(0, self.max_requests - len(self.requests[ip]))
    
    def reset(self, ip: str):
        """Reseta o contador para um IP"""
        if ip in self.requests:
            del self.requests[ip]


class IPBlocker:
    """Sistema de bloqueio de IPs"""
    
    def __init__(self):
        self.blocked_file = os.path.join(DATA_DIR, 'blocked_ips.json')
        self.blocked_ips = {}
        self.suspicious_activity = defaultdict(int)
        self._load_data()
    
    def _load_data(self):
        try:
            if os.path.exists(self.blocked_file):
                with open(self.blocked_file, 'r') as f:
                    self.blocked_ips = json.load(f)
        except:
            pass
    
    def _save_data(self):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(self.blocked_file, 'w') as f:
                json.dump(self.blocked_ips, f, indent=2)
        except:
            pass
    
    def block_ip(self, ip: str, reason: str, duration_hours: int = 24):
        """Bloqueia um IP"""
        self.blocked_ips[ip] = {
            'reason': reason,
            'blocked_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(hours=duration_hours)).isoformat(),
            'permanent': duration_hours == 0
        }
        self._save_data()
        audit_log.log('ip_blocked', {'ip': ip, 'reason': reason, 'duration_hours': duration_hours})
    
    def unblock_ip(self, ip: str):
        """Desbloqueia um IP"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self._save_data()
            audit_log.log('ip_unblocked', {'ip': ip})
    
    def is_blocked(self, ip: str) -> tuple:
        """Verifica se IP está bloqueado"""
        if ip not in self.blocked_ips:
            return False, None
        
        block_info = self.blocked_ips[ip]
        
        # Verificar expiração
        if not block_info.get('permanent'):
            expires = datetime.fromisoformat(block_info['expires_at'])
            if datetime.now() > expires:
                self.unblock_ip(ip)
                return False, None
        
        return True, block_info['reason']
    
    def report_suspicious(self, ip: str, activity: str):
        """Reporta atividade suspeita"""
        self.suspicious_activity[ip] += 1
        audit_log.log('suspicious_activity', {'ip': ip, 'activity': activity, 'count': self.suspicious_activity[ip]})
        
        # Auto-bloqueio após 10 atividades suspeitas
        if self.suspicious_activity[ip] >= 10:
            self.block_ip(ip, 'Auto-block: Múltiplas atividades suspeitas', 24)
    
    def get_blocked_list(self) -> list:
        """Retorna lista de IPs bloqueados"""
        return [{'ip': ip, **info} for ip, info in self.blocked_ips.items()]


class AuditLog:
    """Sistema de logs de auditoria"""
    
    def __init__(self):
        self.log_file = os.path.join(DATA_DIR, 'audit_log.json')
        self.logs = []
        self._load_data()
    
    def _load_data(self):
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    self.logs = json.load(f)[-5000:]  # Manter últimos 5000
        except:
            pass
    
    def _save_data(self):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(self.log_file, 'w') as f:
                json.dump(self.logs[-5000:], f, indent=2)
        except:
            pass
    
    def log(self, action: str, details: dict = None, ip: str = None, username: str = None):
        """Registra ação no log de auditoria"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'ip': ip or (request.remote_addr if request else None),
            'username': username,
            'details': details or {},
            'user_agent': request.headers.get('User-Agent', '') if request else None
        }
        self.logs.append(entry)
        
        if len(self.logs) % 50 == 0:  # Salvar a cada 50 logs
            self._save_data()
    
    def get_logs(self, limit: int = 100, action_filter: str = None, ip_filter: str = None) -> list:
        """Retorna logs filtrados"""
        filtered = self.logs
        
        if action_filter:
            filtered = [l for l in filtered if l['action'] == action_filter]
        if ip_filter:
            filtered = [l for l in filtered if l.get('ip') == ip_filter]
        
        return filtered[-limit:]
    
    def get_stats(self) -> dict:
        """Retorna estatísticas dos logs"""
        actions = defaultdict(int)
        ips = defaultdict(int)
        
        for log in self.logs:
            actions[log['action']] += 1
            if log.get('ip'):
                ips[log['ip']] += 1
        
        return {
            'total_logs': len(self.logs),
            'actions_count': dict(actions),
            'top_ips': sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]
        }


class VPNDetector:
    """Detecção de VPN/Proxy"""
    
    VPN_INDICATORS = [
        'vpn', 'proxy', 'hosting', 'datacenter', 'cloud',
        'digitalocean', 'aws', 'azure', 'google', 'linode',
        'vultr', 'ovh', 'hetzner'
    ]
    
    def __init__(self):
        self.cache = {}
    
    def check_ip(self, ip: str, isp: str = None, org: str = None) -> dict:
        """Verifica se IP parece ser VPN/Proxy"""
        if ip in self.cache:
            return self.cache[ip]
        
        result = {
            'is_vpn': False,
            'is_proxy': False,
            'is_datacenter': False,
            'confidence': 0,
            'indicators': []
        }
        
        # Verificar ISP/Org
        check_text = f"{isp or ''} {org or ''}".lower()
        
        for indicator in self.VPN_INDICATORS:
            if indicator in check_text:
                result['indicators'].append(indicator)
                result['confidence'] += 20
        
        if result['confidence'] >= 40:
            result['is_datacenter'] = True
        if result['confidence'] >= 60:
            result['is_vpn'] = True
        
        self.cache[ip] = result
        return result


# Instâncias globais
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
ip_blocker = IPBlocker()
audit_log = AuditLog()
vpn_detector = VPNDetector()


def require_not_blocked(f):
    """Decorator para verificar se IP está bloqueado"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        is_blocked, reason = ip_blocker.is_blocked(ip)
        if is_blocked:
            audit_log.log('blocked_access_attempt', {'reason': reason}, ip=ip)
            return jsonify({'error': f'Acesso bloqueado: {reason}'}), 403
        return f(*args, **kwargs)
    return decorated_function


def require_rate_limit(f):
    """Decorator para rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        allowed, message = rate_limiter.is_allowed(ip)
        if not allowed:
            audit_log.log('rate_limit_exceeded', {}, ip=ip)
            return jsonify({'error': message}), 429
        return f(*args, **kwargs)
    return decorated_function
