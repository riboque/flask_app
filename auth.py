"""
Módulo de Autenticação e Segurança Avançada
- Gerenciamento de sessões
- Proteção contra CSRF
- Rate limiting
- Cookies seguros
- Criptografia de dados sensíveis
"""

from flask import session, request, make_response
from functools import wraps
from datetime import datetime, timedelta
import secrets
import hashlib
import json
from collections import defaultdict
from time import time

# Importar criptografia profissional (Argon2id)
try:
    from crypto_professional import (
        hash_password as argon2_hash,
        verify_password as argon2_verify,
        generate_token as crypto_generate_token,
        get_password_hasher,
        migrate_legacy_hash
    )
    PROFESSIONAL_CRYPTO = True
except ImportError:
    PROFESSIONAL_CRYPTO = False
    print("[AVISO] crypto_professional não disponível, usando SHA256")

# ============================================================================
# CONFIGURAÇÕES DE SEGURANÇA
# ============================================================================

# Credenciais (em produção, usar banco de dados)
ADMIN_USER = "admin"
# ID e token fixos para a sessão do admin
ADMIN_FIXED_SESSION_ID = "admin_fixed_session"
ADMIN_FIXED_TOKEN = "admin_fixed_token"
ADMIN_PASSWORD = "admin123"

# Hash da senha - Argon2id (profissional) ou SHA256 (fallback)
import os
_ADMIN_HASH_FILE = 'keys/admin_auth.hash'

def _get_admin_password_hash():
    """Obter ou gerar hash Argon2id da senha admin"""
    os.makedirs('keys', exist_ok=True)
    
    if os.path.exists(_ADMIN_HASH_FILE):
        with open(_ADMIN_HASH_FILE, 'r') as f:
            stored_hash = f.read().strip()
            # Se já é Argon2id, retornar
            if stored_hash.startswith('$argon2'):
                return stored_hash
    
    # Gerar novo hash Argon2id
    if PROFESSIONAL_CRYPTO:
        hash_str = argon2_hash(ADMIN_PASSWORD)
        with open(_ADMIN_HASH_FILE, 'w') as f:
            f.write(hash_str)
        print("[AUTH] Senha admin atualizada para Argon2id")
        return hash_str
    else:
        # Fallback SHA256
        return hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

ADMIN_PASSWORD_HASH = _get_admin_password_hash()

# Token de sessão seguro
SESSION_TIMEOUT = 3600  # 1 hora em segundos
CSRF_TOKEN_EXPIRY = 3600  # 1 hora
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = 300  # 5 minutos

# ============================================================================
# GERENCIAMENTO DE USUÁRIOS
# ============================================================================

# Armazenamento de usuários (username -> {password_hash, email, created, ...})
users_db = {
    ADMIN_USER: {
        'password_hash': ADMIN_PASSWORD_HASH,
        'email': 'admin@sistema.local',
        'role': 'admin',
        'created': datetime.now().isoformat(),
        'last_login': None,
        'ip': None,
        'active': True
    }
}

# ============================================================================
# GERENCIAMENTO DE SESSÕES SEGURAS
# ============================================================================

# Dicionário de tentativas de login (IP -> lista de tentativas)
login_attempts = defaultdict(list)

# Dicionário de sessões ativas
active_sessions = {}

# Dicionário de usuários online: username -> {'last_seen': datetime, 'ip': ip}
online_users = {}

# Dicionário de tokens CSRF
csrf_tokens = {}

def get_client_ip():
    """Obter IP real do cliente (considerando proxies)"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def generate_secure_token(length=32):
    """Gerar token criptograficamente seguro"""
    if PROFESSIONAL_CRYPTO:
        return crypto_generate_token(length)
    return secrets.token_urlsafe(length)


def hash_password(password):
    """
    Hash seguro de senha.
    
    Usa Argon2id (padrão OWASP 2024) quando disponível,
    fallback para SHA256 apenas para compatibilidade.
    """
    if PROFESSIONAL_CRYPTO:
        return argon2_hash(password)
    # Fallback SHA256 (não recomendado)
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, password_hash):
    """
    Verificar senha contra hash.
    
    Suporta:
    - Argon2id (recomendado)
    - bcrypt
    - PBKDF2-SHA512
    - SHA256 legado (para migração)
    """
    if PROFESSIONAL_CRYPTO:
        return argon2_verify(password, password_hash)
    # Fallback SHA256
    return hash_password(password) == password_hash

def check_login_attempts(client_ip):
    """Verificar se cliente excedeu tentativas de login"""
    now = time()
    
    # Limpar tentativas antigas
    login_attempts[client_ip] = [
        attempt_time for attempt_time in login_attempts[client_ip]
        if now - attempt_time < LOGIN_ATTEMPT_WINDOW
    ]
    
    # Se ultrapassou limite, bloquear
    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        return False, "Muitas tentativas de login. Tente novamente em 5 minutos."
    
    return True, None

def record_login_attempt(client_ip):
    """Registrar tentativa de login falhada"""
    login_attempts[client_ip].append(time())

def create_session(username):
    """Criar nova sessão segura"""
    session_id = generate_secure_token()
    session_token = generate_secure_token()
    
    active_sessions[session_id] = {
        'username': username,
        'token': session_token,
        'created': datetime.now(),
        'last_access': datetime.now(),
        'ip': get_client_ip(),
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    
    return session_id, session_token

def create_admin_session():
    """Criar sessao fixa para o admin."""
    session_id = ADMIN_FIXED_SESSION_ID
    session_token = ADMIN_FIXED_TOKEN

    active_sessions[session_id] = {
        'username': ADMIN_USER,
        'token': session_token,
        'created': datetime.now(),
        'last_access': datetime.now(),
        'ip': get_client_ip(),
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }

    return session_id, session_token

def validate_session(session_id, session_token):
    """Validar sessão ativa - session_token pode ser None"""
    print(f'[DEBUG] validate_session chamada: session_id={session_id[:20] if session_id else None}..., token={session_token[:20] if session_token else "None"}...')
    
    if session_id not in active_sessions:
        print(f'[DEBUG] session_id não encontrada em active_sessions')
        return False, "Sessão inválida ou expirada"
    
    session_data = active_sessions[session_id]
    
    # Se token foi fornecido, verificar
    if session_token is not None and session_data['token'] != session_token:
        print(f'[DEBUG] Token não corresponde')
        return False, "Token de sessão inválido"
    
    # Verificar timeout
    elapsed = (datetime.now() - session_data['last_access']).total_seconds()
    if elapsed > SESSION_TIMEOUT:
        print(f'[DEBUG] Sessão expirada ({elapsed}s > {SESSION_TIMEOUT}s)')
        del active_sessions[session_id]
        return False, "Sessão expirada. Faça login novamente."
    
    # Verificar IP (proteção contra roubo de sessão)
    current_ip = get_client_ip()
    if session_data['ip'] != current_ip:
        print(f'[DEBUG] IP mudou: {session_data["ip"]} vs {current_ip}')
        del active_sessions[session_id]
        return False, "IP mudou. Sessão encerrada por segurança."
    
    # Atualizar último acesso
    session_data['last_access'] = datetime.now()
    
    print(f'[DEBUG] ✓ Sessão válida para usuário {session_data["username"]}')
    return True, session_data
def invalidate_session(session_id):
    """Invalidar sessão (logout)"""
    if session_id in active_sessions:
        del active_sessions[session_id]
        return True
    return False

# ============================================================================
# PROTEÇÃO CONTRA CSRF
# ============================================================================

def generate_csrf_token():
    """Gerar novo token CSRF"""
    token = generate_secure_token()
    csrf_tokens[token] = {
        'created': time(),
        'used': False
    }
    return token

def validate_csrf_token(token):
    """Validar token CSRF"""
    if token not in csrf_tokens:
        return False, "Token CSRF inválido ou ausente"
    
    token_data = csrf_tokens[token]
    
    # Verificar expiração
    if time() - token_data['created'] > CSRF_TOKEN_EXPIRY:
        del csrf_tokens[token]
        return False, "Token CSRF expirado"
    
    # Token já foi usado (proteção contra replay)
    if token_data['used']:
        return False, "Token CSRF já foi utilizado"
    
    # Marcar como usado
    token_data['used'] = True
    
    return True, "Token CSRF válido"

# ============================================================================
# DECORADORES DE AUTENTICAÇÃO
# ============================================================================

def require_login(f):
    """Decorator para exigir login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar cookies seguros
        session_id = request.cookies.get('session_id')
        session_token = request.cookies.get('session_token')
        
        if not session_id or not session_token:
            return {'erro': 'Não autenticado. Faça login primeiro.'}, 401
        
        # Validar sessão
        is_valid, result = validate_session(session_id, session_token)
        if not is_valid:
            return {'erro': result}, 401
        
        # Adicionar dados da sessão ao request
        request.session_data = result
        request.session_id = session_id
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_admin(f):
    """Decorator para exigir admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar autenticação primeiro
        session_id = request.cookies.get('session_id')
        session_token = request.cookies.get('session_token')
        
        if not session_id or not session_token:
            return {'erro': 'Não autenticado.'}, 401
        
        is_valid, result = validate_session(session_id, session_token)
        if not is_valid:
            return {'erro': result}, 401
        
        # Verificar se é admin
        if result['username'] != ADMIN_USER:
            return {'erro': 'Acesso negado. Privilégios de admin necessários.'}, 403
        
        request.session_data = result
        request.session_id = session_id
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_csrf(f):
    """Decorator para validar CSRF em POST/PUT/DELETE"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            # Token pode vir em header ou form data
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            
            if not token:
                return {'erro': 'Token CSRF ausente'}, 400
            
            is_valid, msg = validate_csrf_token(token)
            if not is_valid:
                return {'erro': msg}, 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# RATE LIMITING
# ============================================================================

rate_limit_store = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # 1 minuto
RATE_LIMIT_MAX_REQUESTS = 100  # Máximo de requisições por janela

def check_rate_limit():
    """Verificar rate limit por IP"""
    client_ip = get_client_ip()
    now = time()
    
    # Limpar requisições antigas
    rate_limit_store[client_ip] = [
        req_time for req_time in rate_limit_store[client_ip]
        if now - req_time < RATE_LIMIT_WINDOW
    ]
    
    # Verificar limite
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return False, "Taxa de requisição excedida. Tente novamente em alguns momentos."
    
    # Registrar nova requisição
    rate_limit_store[client_ip].append(now)
    
    return True, None

def rate_limit_decorator(f):
    """Decorator para rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_allowed, msg = check_rate_limit()
        if not is_allowed:
            return {'erro': msg}, 429  # Too Many Requests
        
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# COOKIES SEGUROS
# ============================================================================
def set_secure_cookies(response, session_id, session_token):
    """Configurar cookies - Funciona com HTTP e HTTPS"""
    
    print('[DEBUG] set_secure_cookies chamada')
    
    # Em desenvolvimento, usar secure=False para HTTP
    # Em produção, sempre usar secure=True para HTTPS
    is_secure = request.scheme == 'https'
    print(f'[DEBUG] scheme: {request.scheme}, is_secure: {is_secure}')

    # Cookie de ID de sessão
    print('[DEBUG] Adicionando cookie session_id...')
    response.set_cookie(
        'session_id',
        session_id,
        max_age=SESSION_TIMEOUT,
        secure=is_secure,           # False para HTTP, True para HTTPS
        httponly=True,
        samesite='Lax',
        path='/'
    )

    # Cookie de token de sessão
    print('[DEBUG] Adicionando cookie session_token...')
    response.set_cookie(
        'session_token',
        session_token,
        max_age=SESSION_TIMEOUT,
        secure=is_secure,
        httponly=True,
        samesite='Lax',
        path='/'
    )

    # Cookie de flag de autenticado
    print('[DEBUG] Adicionando cookie authenticated...')
    response.set_cookie(
        'authenticated',
        'true',
        max_age=SESSION_TIMEOUT,
        secure=is_secure,
        httponly=False,
        samesite='Lax',
        path='/'
    )
    
    print('[DEBUG] ✓ Cookies adicionados com sucesso')
    return response
def clear_cookies(response):
    """Limpar cookies na resposta (logout)"""
    response.delete_cookie('session_id', path='/')
    response.delete_cookie('session_token', path='/')
    response.delete_cookie('authenticated', path='/')
    return response

# ============================================================================
# LOGGING E AUDITORIA
# ============================================================================

auth_log = []

def log_auth_event(event_type, username, ip, success, details=""):
    """Registrar eventos de autenticação"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,  # login, logout, failed_login, session_expired, etc
        'username': username,
        'ip': ip,
        'success': success,
        'details': details
    }
    auth_log.append(log_entry)
    
    # Manter apenas últimas 1000 entradas
    if len(auth_log) > 1000:
        auth_log.pop(0)
    
    return log_entry

def get_auth_logs():
    """Obter logs de autenticação (últimos 100)"""
    return auth_log[-100:]

# ============================================================================
# GERENCIAMENTO DE USUÁRIOS COMUNS
# ============================================================================

def user_exists(username):
    """Verificar se usuário existe"""
    return username.lower() in users_db

def create_user(username, password, email, role='user'):
    """Criar novo usuário comum"""
    username = username.lower().strip()
    email = email.lower().strip()
    
    # Validações
    if len(username) < 3:
        return False, "Usuário deve ter pelo menos 3 caracteres"
    
    if len(username) > 20:
        return False, "Usuário não pode ter mais de 20 caracteres"
    
    if len(password) < 6:
        return False, "Senha deve ter pelo menos 6 caracteres"
    
    if '@' not in email:
        return False, "Email inválido"
    
    if user_exists(username):
        return False, "Usuário já existe"
    
    # Criar usuário
    users_db[username] = {
        'password_hash': hash_password(password),
        'email': email,
        'role': role,  # 'admin' ou 'user'
        'created': datetime.now().isoformat(),
        'last_login': None,
        'ip': None,
        'active': True,
        'chat_messages_count': 0
    }
    
    return True, "Usuário criado com sucesso"

def verify_user_password(username, password):
    """Verificar credenciais de usuário"""
    username = username.lower().strip()
    
    if username not in users_db:
        return False, "Usuário não existe"
    
    user = users_db[username]
    
    if not user.get('active', False):
        return False, "Usuário inativo"
    
    if hash_password(password) != user['password_hash']:
        return False, "Senha incorreta"
    
    return True, user

def get_user_info(username):
    """Obter informações do usuário"""
    username = username.lower().strip()
    
    if username not in users_db:
        return None
    
    user = users_db[username]
    
    # Retornar sem hash de senha
    return {
        'username': username,
        'email': user['email'],
        'role': user['role'],
        'created': user['created'],
        'last_login': user['last_login'],
        'ip': user['ip'],
        'active': user['active'],
        'chat_messages_count': user.get('chat_messages_count', 0)
    }

def update_user_login(username, ip):
    """Atualizar informações de login do usuário"""
    username = username.lower().strip()
    
    if username in users_db:
        users_db[username]['last_login'] = datetime.now().isoformat()
        users_db[username]['ip'] = ip

def get_all_users():
    """Obter lista de todos os usuários (para monitor)"""
    users_list = []
    for username, user_data in users_db.items():
        users_list.append({
            'username': username,
            'email': user_data['email'],
            'role': user_data['role'],
            'created': user_data['created'],
            'last_login': user_data['last_login'],
            'ip': user_data['ip'],
            'active': user_data['active'],
            'chat_messages_count': user_data.get('chat_messages_count', 0)
        })
    return sorted(users_list, key=lambda x: x['username'])

# ============================================================================
# REGISTRO DE USUÁRIOS ONLINE
# ============================================================================

def mark_user_online(username, ip):
    """Marcar usuário como online"""
    username = username.lower().strip()
    online_users[username] = {
        'last_seen': datetime.now(),
        'ip': ip,
        'status': 'online'
    }

def mark_user_offline(username):
    """Marcar usuário como offline"""
    username = username.lower().strip()
    if username in online_users:
        online_users[username]['status'] = 'offline'
        online_users[username]['last_seen'] = datetime.now()

def update_user_activity(username, ip):
    """Atualizar atividade do usuário online"""
    username = username.lower().strip()
    if username in online_users:
        online_users[username]['last_seen'] = datetime.now()
        online_users[username]['ip'] = ip

def get_online_users():
    """Obter lista de usuários online"""
    online_list = []
    now = datetime.now()

    for username, data in online_users.items():
        # Considerar offline se não visto há mais de 5 minutos
        if (now - data['last_seen']).total_seconds() > 300:  # 5 minutos
            data['status'] = 'offline'

        if data['status'] == 'online':
            online_list.append({
                'username': username,
                'last_seen': data['last_seen'].isoformat(),
                'ip': data['ip'],
                'status': data['status']
            })

    return sorted(online_list, key=lambda x: x['last_seen'], reverse=True)

def get_user_online_status(username):
    """Obter status online de um usuário específico"""
    username = username.lower().strip()
    if username not in online_users:
        return {'status': 'offline', 'last_seen': None, 'ip': None}

    data = online_users[username]
    now = datetime.now()

    # Verificar se ainda está online (última atividade < 5 minutos)
    if (now - data['last_seen']).total_seconds() > 300:
        data['status'] = 'offline'

    return {
        'status': data['status'],
        'last_seen': data['last_seen'].isoformat(),
        'ip': data['ip']
    }

def cleanup_offline_users():
    """Limpar usuários offline há muito tempo (mais de 1 hora)"""
    now = datetime.now()
    to_remove = []

    for username, data in online_users.items():
        if (now - data['last_seen']).total_seconds() > 3600:  # 1 hora
            to_remove.append(username)

    for username in to_remove:
        del online_users[username]

    return len(to_remove)

# ============================================================================
# AUTENTICAÇÃO DE USUÁRIOS
# ============================================================================

def authenticate_user(username, password_or_user_id):
    """Autenticar usuário com username e senha ou user_id"""
    username = username.lower().strip()

    if username not in users_db:
        return False, "Usuário não encontrado"

    user = users_db[username]

    if not user.get('active', False):
        return False, "Usuário inativo"

    # Verificar se é senha ou user_id (para auto-login)
    if len(password_or_user_id) == 16 and password_or_user_id.startswith('user_'):
        # É um user_id gerado automaticamente
        if user.get('auto_generated', False):
            return True, user
        else:
            return False, "Credenciais inválidas"
    else:
        # É uma senha normal
        if hash_password(password_or_user_id) == user['password_hash']:
            return True, user
        else:
            return False, "Senha incorreta"

    return False, "Erro de autenticação"
