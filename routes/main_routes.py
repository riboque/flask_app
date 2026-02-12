"""
Rotas Principais (index, terms, chat, admin)
Sistema de contas fixas por IP
"""
from flask import Blueprint, jsonify, request, redirect, url_for, render_template, make_response
from datetime import datetime

from auth import (
    validate_session, create_session, set_secure_cookies,
    generate_secure_token, log_auth_event, require_admin,
    create_admin_session, active_sessions
)
from ip_users import ip_user_manager
from data_collector import data_collector
from utils.network import get_client_ip

# Criar blueprint
main_bp = Blueprint('main', __name__)

# Referência aos dados compartilhados
shared_data = {
    'registered_systems': {}
}


def init_shared_data(registered_systems):
    """Inicializa referências aos dados compartilhados"""
    shared_data['registered_systems'] = registered_systems


@main_bp.route('/favicon.ico')
def favicon():
    """Retorna um favicon simples"""
    # SVG favicon simples (chat icon)
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="45" fill="#667eea"/>
        <path d="M30 35h40v25H45l-10 10v-10h-5z" fill="white"/>
    </svg>'''
    response = make_response(svg)
    response.headers['Content-Type'] = 'image/svg+xml'
    response.headers['Cache-Control'] = 'public, max-age=86400'
    return response


@main_bp.route('/')
def index():
    """Página principal - redirecionar para termos se não autenticado"""
    session_id = request.cookies.get('session_id')
    if session_id:
        try:
            is_valid, _ = validate_session(session_id, None)
            if is_valid:
                return render_template('chat_v3.html')
        except:
            pass
    return redirect(url_for('main.terms'))


@main_bp.route('/terms', methods=['GET'])
def terms():
    """Página de termos de uso"""
    try:
        return render_template('terms.html'), 200
        
    except Exception as e:
        return f"Erro ao carregar termos: {str(e)}", 500


@main_bp.route('/accept_terms', methods=['POST'])
def accept_terms():
    """
    Aceita termos e cria/recupera conta baseada no IP.
    Cada IP tem uma conta fixa e persistente.
    """
    try:
        client_ip = get_client_ip(request)
        user_agent = request.headers.get('User-Agent', '')
        
        # Obter dados do sistema enviados pelo cliente
        client_system_info = {}
        if request.is_json:
            data = request.get_json() or {}
            client_system_info = data.get('system_info', {})
        
        # Montar system_info
        system_info = {
            'timestamp': client_system_info.get('timestamp', datetime.now().isoformat()),
            'userAgent': client_system_info.get('userAgent', user_agent),
            'platform': client_system_info.get('platform', 'N/A'),
            'language': client_system_info.get('language', 'N/A'),
            'cookieEnabled': client_system_info.get('cookieEnabled', True),
            'online': client_system_info.get('online', True),
            'cores': client_system_info.get('cores', 'N/A'),
            'memory': client_system_info.get('memory', 'N/A'),
            'screenWidth': client_system_info.get('screenWidth', 'N/A'),
            'screenHeight': client_system_info.get('screenHeight', 'N/A'),
            'colorDepth': client_system_info.get('colorDepth', 'N/A'),
            'timezone': client_system_info.get('timezone', 'N/A'),
            'ipPublico': client_system_info.get('ipPublico', client_ip)
        }
        
        # CONTA FIXA POR IP: Obter ou criar usuário
        user, is_new = ip_user_manager.get_or_create_user(client_ip, user_agent, system_info)
        username = user['username']
        
        # Criar sessão
        session_id, session_token = create_session(username)
        
        # Salvar em registered_systems para compatibilidade
        shared_data['registered_systems'][username] = {
            'ip': client_ip,
            'registered_at': datetime.now().isoformat(),
            'system_info': system_info
        }
        
        # Log
        action = 'novo_usuario' if is_new else 'usuario_retornando'
        log_auth_event(action, username, client_ip, True, f"Visitas: {user['total_visits']}")
        
        print(f"[OK] {'Novo usuário' if is_new else 'Usuário retornando'}: {username} ({client_ip}) - Visitas: {user['total_visits']}")
        
        response = jsonify({
            'success': True,
            'redirect': '/chat',
            'username': username,
            'is_new_user': is_new,
            'total_visits': user['total_visits']
        })
        
        set_secure_cookies(response, session_id, session_token)
        return response, 200
        
    except Exception as e:
        print(f'[ERRO] /accept_terms: {e}')
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Erro ao criar sessão'}), 500


@main_bp.route('/api/accept_terms', methods=['POST'])
def api_accept_terms():
    """API pura para aceitação de termos (JSON-only)"""
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'message': 'Esta rota aceita apenas JSON'
            }), 400

        data = request.get_json()

        if not data.get('accept_terms', False):
            return jsonify({
                'success': False,
                'message': 'Você deve aceitar os termos para continuar'
            }), 400

        client_ip = get_client_ip(request)
        user_agent = request.headers.get('User-Agent', '')[:100]
        
        # Obter system_info do request
        system_info = data.get('system_info', {})
        
        # CONTA FIXA POR IP
        user, is_new = ip_user_manager.get_or_create_user(client_ip, user_agent, system_info)
        username = user['username']
        
        session_id, session_token = create_session(username)
        
        log_auth_event('terms_accepted_api', username, client_ip, True)
        
        response = jsonify({
            'success': True,
            'message': f'Bem-vindo, {username}!',
            'username': username,
            'is_new_user': is_new,
            'total_visits': user['total_visits'],
            'session_id': session_id[:16] + '...',
            'redirect_url': url_for('main.chat_page', _external=True),
            'timestamp': datetime.now().isoformat()
        })
        
        set_secure_cookies(response, session_id, session_token)
        return response, 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Erro interno: {str(e)}'
        }), 500


@main_bp.route('/api/user_info', methods=['GET'])
def api_user_info():
    """API para obter informações do usuário atual baseado no IP"""
    try:
        client_ip = get_client_ip(request)
        user = ip_user_manager.get_user(client_ip)
        
        if user:
            return jsonify({
                'exists': True,
                'username': user['username'],
                'ip': client_ip,
                'total_visits': user['total_visits'],
                'first_visit': user.get('first_visit'),
                'last_seen': user.get('last_seen')
            }), 200
        else:
            return jsonify({
                'exists': False,
                'ip': client_ip,
                'message': 'Usuário será criado ao aceitar os termos'
            }), 200
            
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@main_bp.route('/api/my_data', methods=['GET'])
def api_my_data():
    """API para o usuário ver seus próprios dados coletados"""
    try:
        client_ip = get_client_ip(request)
        user = ip_user_manager.get_user(client_ip)
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'Nenhum dado encontrado para seu IP'
            }), 404
        
        return jsonify({
            'success': True,
            'data': {
                'username': user['username'],
                'ip': user['ip'],
                'created_at': user['created_at'],
                'last_seen': user['last_seen'],
                'total_visits': user['total_visits'],
                'system_info': user.get('system_info', {})
            }
        }), 200
        
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@main_bp.route('/certificado')
def certificado():
    """Página com instruções para confiar no certificado"""
    try:
        with open('confiar_certificado.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return '''
        <h1>✅ Certificado Aceito!</h1>
        <p>Você está acessando o servidor com segurança HTTPS.</p>
        <a href="/">Voltar ao Dashboard</a>
        ''', 200, {'Content-Type': 'text/html; charset=utf-8'}


@main_bp.route('/chat', methods=['GET'])
def chat_page():
    """Página do chat - validar sessão via cookies"""
    try:
        session_id = request.cookies.get('session_id')
        session_token = request.cookies.get('session_token')
        
        if not session_id or not session_token:
            return redirect(url_for('main.terms'))
        
        is_valid, session_data = validate_session(session_id, session_token)
        
        if not is_valid:
            return redirect(url_for('main.terms'))
        
        # Atualizar última atividade do usuário
        client_ip = get_client_ip(request)
        ip_user_manager.update_user(client_ip, {'status': 'online'})
        
        # Usar chat_v3.html como padrão (versão híbrida)
        return render_template('chat_v3.html'), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return redirect(url_for('main.terms'))


@main_bp.route('/chat/v1', methods=['GET'])
def chat_v1_page():
    """Página do chat original v1 - simples com polling"""
    try:
        session_id = request.cookies.get('session_id')
        session_token = request.cookies.get('session_token')
        
        if not session_id or not session_token:
            return redirect(url_for('main.terms'))
        
        is_valid, session_data = validate_session(session_id, session_token)
        
        if not is_valid:
            return redirect(url_for('main.terms'))
        
        client_ip = get_client_ip(request)
        ip_user_manager.update_user(client_ip, {'status': 'online'})
        
        return render_template('chat.html'), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return redirect(url_for('main.terms'))


@main_bp.route('/chat/v2', methods=['GET'])
def chat_v2_page():
    """Página do chat avançado v2 - com salas, reações e DMs"""
    try:
        session_id = request.cookies.get('session_id')
        session_token = request.cookies.get('session_token')
        
        if not session_id or not session_token:
            return redirect(url_for('main.terms'))
        
        is_valid, session_data = validate_session(session_id, session_token)
        
        if not is_valid:
            return redirect(url_for('main.terms'))
        
        client_ip = get_client_ip(request)
        ip_user_manager.update_user(client_ip, {'status': 'online'})
        
        return render_template('chat_v2.html'), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return redirect(url_for('main.terms'))


@main_bp.route('/chat/public', methods=['GET'])
def chat_public_page():
    """Página do chat sem autenticação - para testes"""
    return render_template('chat_v3.html'), 200


@main_bp.route('/dashboard', methods=['GET'])
def dashboard_page():
    """Página de Dashboard Analytics"""
    try:
        session_id = request.cookies.get('session_id')
        session_token = request.cookies.get('session_token')
        
        if not session_id or not session_token:
            return redirect(url_for('main.terms'))
        
        is_valid, session_data = validate_session(session_id, session_token)
        
        if not is_valid:
            return redirect(url_for('main.terms'))
        
        return render_template('dashboard.html'), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return redirect(url_for('main.terms'))


@main_bp.route('/sw.js')
def service_worker():
    """Service Worker para PWA"""
    from flask import send_from_directory
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')


@main_bp.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """Login de administrador"""
    if request.method == 'GET':
        html = """
        <html><head><title>Admin Login</title>
        <style>
            body { font-family: Arial; margin: 0; display: flex; justify-content: center; 
                   align-items: center; height: 100vh; background: #1a1a2e; color: #fff; }
            .box { background: #16213e; padding: 40px; border-radius: 10px; text-align: center; }
            button { padding: 15px 40px; font-size: 16px; background: #00d4ff; color: #000; 
                     border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #00a8cc; }
        </style>
        </head>
        <body>
            <div class="box">
                <h2>🔐 Login Admin</h2>
                <form method='POST' action='/admin_login'>
                    <button type='submit'>Entrar como Admin</button>
                </form>
            </div>
        </body></html>
        """
        return html

    try:
        session_id, session_token = create_admin_session()
        response = make_response(redirect(url_for('main.admin_panel')))
        set_secure_cookies(response, session_id, session_token)
        return response
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erro ao autenticar admin'}), 500


@main_bp.route('/admin', methods=['GET'])
@require_admin
def admin_panel():
    """Painel administrativo"""
    stats = ip_user_manager.get_stats()
    
    html = f"""
    <html><head><title>Painel Admin</title>
    <style>
        body {{ font-family: Arial; margin: 0; padding: 20px; background: #1a1a2e; color: #fff; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .stat {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-value {{ font-size: 2em; color: #00d4ff; }}
        a {{ color: #00d4ff; text-decoration: none; display: inline-block; margin: 10px 15px 10px 0; 
             padding: 10px 20px; background: #16213e; border-radius: 5px; }}
        a:hover {{ background: #0f3460; }}
    </style>
    </head>
    <body>
        <div class="container">
            <h1>🛠️ Painel Admin</h1>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">{stats['total_users']}</div>
                    <div>Total Usuários</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{stats['active_last_30min']}</div>
                    <div>Ativos (30min)</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{stats['total_visits']}</div>
                    <div>Total Visitas</div>
                </div>
            </div>
            
            <h3>🔗 Links</h3>
            <a href='/monitor'>📊 Monitor</a>
            <a href='/chat'>💬 Chat</a>
            <a href='/export/users/csv'>📥 Exportar CSV</a>
            <a href='/export/users/json'>📥 Exportar JSON</a>
            <a href='/export/users/html'>📥 Relatório HTML</a>
        </div>
    </body></html>
    """
    return html


@main_bp.route('/monitor', methods=['GET'])
def monitor_page():
    """Serve o monitor - acesso simplificado"""
    return render_template('monitor.html')


@main_bp.route('/test_post', methods=['POST'])
def test_post():
    """Rota de teste"""
    return jsonify({'ok': True}), 200


@main_bp.route('/debug/cookies', methods=['GET'])
def debug_cookies():
    """Rota de debug para verificar cookies"""
    cookies = request.cookies
    session_id = request.cookies.get('session_id')
    session_token = request.cookies.get('session_token')
    
    valid_session = False
    username = None
    if session_id and session_token:
        is_valid, data = validate_session(session_id, session_token)
        valid_session = is_valid
        if is_valid:
            username = data.get("username")
    
    return jsonify({
        'cookies': dict(cookies),
        'has_session_id': session_id is not None,
        'has_session_token': session_token is not None,
        'valid_session': valid_session,
        'username': username,
        'active_sessions_count': len(active_sessions)
    }), 200


@main_bp.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug: listar todos os usuários por IP"""
    users = ip_user_manager.get_all_users()
    return jsonify({
        'total': len(users),
        'users': users
    })
