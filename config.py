"""
Configurações centralizadas da aplicação Flask
"""
import os
import secrets
from datetime import timedelta


class Config:
    """Configurações base"""
    
    # Gerar secret key segura
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
    
    # JSON
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = False
    
    # Sessão
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # SocketIO
    SOCKETIO_ASYNC_MODE = 'eventlet'
    SOCKETIO_CORS_ALLOWED_ORIGINS = "*"
    SOCKETIO_PING_TIMEOUT = 120
    SOCKETIO_PING_INTERVAL = 30


class DevelopmentConfig(Config):
    """Configurações de desenvolvimento"""
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """Configurações de produção"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


def get_config():
    """Retorna configuração baseada no ambiente"""
    env = os.environ.get('FLASK_ENV', 'development')
    if env == 'production':
        return ProductionConfig
    return DevelopmentConfig
