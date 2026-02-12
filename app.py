"""
Aplicação Flask para exportar conexões entre máquina virtual e física
Com autenticação completa e segurança avançada

VERSÃO REFATORADA - Código organizado em módulos
"""

# ========================================
# CONFIGURAÇÃO DE ENCODING (Windows)
# ========================================
import sys
import os

if sys.platform == 'win32':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')

# ========================================
# IMPORTS
# ========================================
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from datetime import timedelta

from config import get_config
from auth import active_sessions

# ========================================
# CRIAÇÃO DA APLICAÇÃO
# ========================================
app = Flask(__name__)

# Carregar configurações
config = get_config()
app.config.from_object(config)

# Configurações adicionais
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# ========================================
# SOCKET.IO - Configurado para 30+ dispositivos
# ========================================
socketio = SocketIO(
    app,
    async_mode='threading',
    cors_allowed_origins="*",
    engineio_logger=False,
    logger=False,
    ping_timeout=120,
    ping_interval=30,
    max_http_buffer_size=1e6,
    max_decode_packets=50  # Aumentado para mais dispositivos
)

# ========================================
# DADOS COMPARTILHADOS (em memória)
# ========================================
connected_clients = {}
chat_messages = []
registered_systems = {}

# ========================================
# REGISTRAR BLUEPRINTS
# ========================================
from routes.api_routes import api_bp, init_shared_data as init_api_data
from routes.chat_routes import chat_bp, init_shared_data as init_chat_data
from routes.export_routes import export_bp, init_shared_data as init_export_data
from routes.monitor_routes import monitor_bp, init_shared_data as init_monitor_data
from routes.main_routes import main_bp, init_shared_data as init_main_data

# Novos blueprints (funcionalidades avançadas)
from routes.analytics_routes import analytics_bp
from routes.security_routes import security_bp
from routes.chat_advanced_routes import chat_advanced_bp
from routes.notifications_routes import notifications_bp

# Inicializar dados compartilhados nos blueprints
init_api_data(connected_clients, registered_systems, chat_messages, active_sessions)
init_chat_data(connected_clients, chat_messages)
init_export_data(registered_systems)
init_monitor_data(connected_clients, registered_systems, chat_messages)
init_main_data(registered_systems)

# Registrar blueprints originais
app.register_blueprint(api_bp)
app.register_blueprint(chat_bp)
app.register_blueprint(export_bp)
app.register_blueprint(monitor_bp)
app.register_blueprint(main_bp)

# Registrar blueprints avançados
app.register_blueprint(analytics_bp)
app.register_blueprint(security_bp)
app.register_blueprint(chat_advanced_bp)
app.register_blueprint(notifications_bp)

# ========================================
# INICIALIZAR SOCKET HANDLERS
# ========================================
from socket_handlers import init_socket_handlers
init_socket_handlers(socketio, connected_clients, registered_systems, chat_messages)

# ========================================
# MIDDLEWARE: Headers de Segurança
# ========================================

@app.before_request
def security_check():
    """Verificações de segurança básicas"""
    from security_advanced import ip_blocker, rate_limiter, audit_log
    from analytics import analytics
    
    ip = request.remote_addr
    
    # Bloquear métodos HTTP perigosos
    if request.method in ['TRACE', 'CONNECT']:
        return jsonify({'erro': 'Método HTTP não permitido'}), 405
    
    # IPs da rede local são isentos de bloqueio e rate limiting
    local_prefixes = ('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                      '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
    is_local_ip = ip.startswith(local_prefixes) or ip == '::1'
    
    # Verificar se IP está bloqueado (exceto IPs locais)
    if not is_local_ip:
        is_blocked, reason = ip_blocker.is_blocked(ip)
        if is_blocked:
            return jsonify({'error': f'Acesso bloqueado: {reason}'}), 403
    
    # Rotas isentas de rate limiting (polling frequente)
    exempt_paths = [
        '/api/chat/messages',
        '/api/chat/users-count',
        '/api/chat/v2/rooms',
        '/api/chat/v2/messages',
        '/api/monitor/devices',
        '/api/monitor/stats',
        '/api/notifications',
        '/static',
        '/favicon.ico',
        '/socket.io'
    ]
    
    # Rate limiting (exceto para rotas isentas e IPs locais)
    is_exempt = any(request.path.startswith(p) for p in exempt_paths)
    if not is_exempt and not is_local_ip:
        allowed, message = rate_limiter.is_allowed(ip)
        if not allowed:
            audit_log.log('rate_limit_exceeded', {'path': request.path}, ip=ip)
            return jsonify({'error': message}), 429
    
    # Rastrear analytics (apenas páginas, não APIs de polling)
    if request.path not in ['/favicon.ico'] and not request.path.startswith('/static') and not request.path.startswith('/api/chat/messages'):
        analytics.track_page_view(request.path, ip)
        analytics.track_connection(ip)


@app.after_request
def set_security_headers(response):
    """Adiciona headers de segurança e cache-busting"""
    # Headers de proteção
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy (CSP)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self' wss: ws: https://api.ipify.org; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    # Esconder informações do servidor
    response.headers['Server'] = 'Secure-Server/1.0'
    response.headers.pop('X-Powered-By', None)
    
    # Cache-busting para HTML
    if response.content_type and 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

# ========================================
# ERROR HANDLERS
# ========================================

@app.errorhandler(500)
def handle_500_error(error):
    """Capturar e logar erros 500"""
    try:
        error_str = str(error).encode('ascii', 'ignore').decode('ascii')
        print(f"[ERROR 500] {type(error).__name__}: {error_str}")
        print(f"[ERROR 500] Request: {request.method} {request.path}")
    except:
        pass
    
    return jsonify({
        'success': False,
        'error': 'Erro interno do servidor'
    }), 500


@app.errorhandler(Exception)
def handle_general_error(error):
    """Capturar exceções não tratadas"""
    try:
        error_str = str(error).encode('ascii', 'ignore').decode('ascii')
        print(f"[ERROR] {type(error).__name__}: {error_str}")
        print(f"[ERROR] Request: {request.method} {request.path}")
    except:
        pass
    
    return jsonify({
        'success': False,
        'error': 'Erro não tratado'
    }), 500


# Exportar app e socketio para uso externo (run.py)
__all__ = ['app', 'socketio']
