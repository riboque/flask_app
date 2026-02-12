"""
Módulo de segurança: encriptação, autenticação e proteção

ATUALIZADO: Usa criptografia profissional (AES-256-GCM, Argon2id)
"""

from functools import wraps
from flask import request, jsonify
import os
import json
from datetime import datetime

# Importar módulo de criptografia profissional
from crypto_professional import (
    encrypt_data as professional_encrypt,
    decrypt_data as professional_decrypt,
    hash_password as professional_hash,
    verify_password as professional_verify,
    generate_token,
    generate_api_key,
    get_crypto_info,
    key_manager
)

# Credenciais (agora com hash Argon2id)
ADMIN_USERNAME = os.environ.get('MONITOR_ADMIN_USER', 'admin')
_ADMIN_PASSWORD_PLAIN = os.environ.get('MONITOR_ADMIN_PASS', 'admin123')

# Hash da senha com Argon2id (gerado na primeira execução)
_ADMIN_PASSWORD_HASH_FILE = 'keys/admin_password.hash'

def _get_admin_password_hash():
    """Obter ou gerar hash Argon2id da senha admin"""
    os.makedirs('keys', exist_ok=True)
    if os.path.exists(_ADMIN_PASSWORD_HASH_FILE):
        with open(_ADMIN_PASSWORD_HASH_FILE, 'r') as f:
            return f.read().strip()
    # Gerar hash Argon2id
    hash_str = professional_hash(_ADMIN_PASSWORD_PLAIN)
    with open(_ADMIN_PASSWORD_HASH_FILE, 'w') as f:
        f.write(hash_str)
    return hash_str

ADMIN_PASSWORD_HASH = _get_admin_password_hash()

# API Key segura (gerada automaticamente se não definida)
_DEFAULT_API_KEY = generate_api_key('sk')
API_KEY = os.environ.get('MONITOR_API_KEY', _DEFAULT_API_KEY)

# Log de auditoria
AUDIT_LOG = []
MAX_AUDIT_LOG = 1000

def encrypt_data(data):
    """
    Encriptar dados com AES-256-GCM.
    
    Segurança:
    - AES-256-GCM (padrão NIST)
    - Nonce único por encriptação
    - Autenticação integrada (AEAD)
    """
    try:
        return professional_encrypt(data)
    except Exception as e:
        print(f"[CRYPTO] Erro ao encriptar: {e}")
        return None


def decrypt_data(encrypted_str):
    """
    Desencriptar dados de AES-256-GCM.
    
    Verifica autenticidade antes de desencriptar.
    """
    try:
        return professional_decrypt(encrypted_str)
    except Exception as e:
        print(f"[CRYPTO] Erro ao desencriptar: {e}")
        return None

def log_audit(action, user, status, details=""):
    """Registrar ação de auditoria."""
    global AUDIT_LOG
    entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user,
        'status': status,
        'details': details,
        'ip': request.remote_addr if request else 'unknown'
    }
    AUDIT_LOG.append(entry)
    if len(AUDIT_LOG) > MAX_AUDIT_LOG:
        AUDIT_LOG.pop(0)
    print(f"[AUDIT] {entry}")

def require_api_key(f):
    """Decorator para requerer chave de API válida."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if not key or key != API_KEY:
            log_audit('API_ACCESS', 'unknown', 'DENIED', 'Invalid API key')
            return jsonify({'erro': 'Chave de API inválida'}), 403
        return f(*args, **kwargs)
    return decorated_function

def require_auth(f):
    """
    Decorator para requerer autenticação básica.
    
    Usa verificação Argon2id para senhas.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth:
            log_audit('AUTH_FAILED', 'none', 'DENIED', 'No credentials provided')
            return jsonify({'erro': 'Autenticação necessária'}), 401
        
        # Verificar usuário
        if auth.username != ADMIN_USERNAME:
            log_audit('AUTH_FAILED', auth.username, 'DENIED', 'Invalid username')
            return jsonify({'erro': 'Autenticação necessária'}), 401
        
        # Verificar senha com Argon2id
        if not professional_verify(auth.password, ADMIN_PASSWORD_HASH):
            log_audit('AUTH_FAILED', auth.username, 'DENIED', 'Invalid password')
            return jsonify({'erro': 'Autenticação necessária'}), 401
        
        log_audit('AUTH_SUCCESS', auth.username, 'ALLOWED', 'Login bem-sucedido (Argon2id)')
        return f(*args, **kwargs)
    return decorated_function

def validate_json_input(data, required_fields=None):
    """Validar entrada JSON."""
    if not isinstance(data, dict):
        return False, "Dados devem ser um objeto JSON"
    if required_fields:
        for field in required_fields:
            if field not in data:
                return False, f"Campo obrigatório faltando: {field}"
    return True, "OK"

def sanitize_string(s, max_length=1000):
    """Sanitizar string de entrada."""
    if not isinstance(s, str):
        return ""
    s = s.strip()
    if len(s) > max_length:
        s = s[:max_length]
    # Remover caracteres perigosos
    dangerous = ['<script', '<?php', 'javascript:', 'onerror=', 'onclick=']
    s_lower = s.lower()
    for char_set in dangerous:
        if char_set in s_lower:
            return ""
    return s
