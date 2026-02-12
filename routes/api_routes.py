"""
Rotas de API para informações do sistema
"""
from flask import Blueprint, jsonify, request
from datetime import datetime

from utils.network import (
    obter_ip_local, obter_ip_publico, obter_interfaces_rede,
    obter_conexoes_ativas, detect_virtual_machine, obter_uso_recursos,
    coletar_informacoes_completas, get_client_ip
)
from auth import require_login

# Criar blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Referência aos dados compartilhados (serão injetados pelo app principal)
shared_data = {
    'connected_clients': {},
    'registered_systems': {},
    'chat_messages': [],
    'active_sessions': {}
}


def init_shared_data(connected_clients, registered_systems, chat_messages, active_sessions):
    """Inicializa referências aos dados compartilhados"""
    shared_data['connected_clients'] = connected_clients
    shared_data['registered_systems'] = registered_systems
    shared_data['chat_messages'] = chat_messages
    shared_data['active_sessions'] = active_sessions


@api_bp.route('/info')
def api_info():
    """API para obter informações de rede"""
    try:
        info = coletar_informacoes_completas()
        return jsonify(info)
    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@api_bp.route('/ip-local')
def api_ip_local():
    """API para obter IP local"""
    return jsonify({"ip_local": obter_ip_local()})


@api_bp.route('/ip-publico')
def api_ip_publico():
    """API para obter IP público"""
    return jsonify({"ip_publico": obter_ip_publico()})


@api_bp.route('/maquina-virtual')
def api_maquina_virtual():
    """API para detectar se é máquina virtual"""
    return jsonify(detect_virtual_machine())


@api_bp.route('/interfaces')
def api_interfaces():
    """API para obter interfaces de rede"""
    return jsonify({"interfaces": obter_interfaces_rede()})


@api_bp.route('/conexoes')
def api_conexoes():
    """API para obter conexões ativas"""
    return jsonify({"conexoes": obter_conexoes_ativas()})


@api_bp.route('/recursos')
def api_recursos():
    """API para obter uso de recursos"""
    return jsonify(obter_uso_recursos())


@api_bp.route('/stats')
@require_login
def api_stats():
    """API para estatísticas do sistema (requer login)"""
    try:
        from auth import users_db
        stats = {
            'timestamp': datetime.now().isoformat(),
            'total_clients': len(shared_data['connected_clients']),
            'total_registered_systems': len(shared_data['registered_systems']),
            'active_sessions': len(shared_data['active_sessions']),
            'system_resources': obter_uso_recursos(),
            'users_count': len(users_db)
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@api_bp.route('/clients')
@require_login
def api_clients():
    """API para listar clientes conectados via Socket.IO"""
    try:
        merged = []
        for s, v in shared_data['connected_clients'].items():
            entry = dict(v)
            if s in shared_data['registered_systems']:
                entry['system_info'] = shared_data['registered_systems'][s].get('system_info')
                entry['registered_at'] = shared_data['registered_systems'][s].get('registered_at')
            merged.append(entry)
        return jsonify({"clients": merged})
    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@api_bp.route('/register', methods=['POST'])
def api_register():
    """Registrar informações de sistema via HTTP POST"""
    try:
        data = request.get_json() or {}
        
        client_id = data.get('client_id', request.remote_addr)
        system_info = data.get('system_info') or {}
        
        key = client_id or request.remote_addr
        
        shared_data['registered_systems'][key] = {
            'system_info': system_info,
            'registered_at': datetime.now().isoformat(),
            'ip': request.remote_addr
        }
        
        return jsonify({'ok': True}), 201
    except Exception as e:
        print(f'[ERRO] api_register: {e}')
        return jsonify({'erro': str(e)}), 500


@api_bp.route('/collect')
def api_collect():
    """Retornar todos os sistemas registrados"""
    try:
        result = []
        for k, v in shared_data['registered_systems'].items():
            item = {
                'client_key': k,
                'ip': v.get('ip'),
                'registered_at': v.get('registered_at'),
                'system_info': v.get('system_info')
            }
            result.append(item)
        return jsonify({'devices': result})
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@api_bp.route('/user_info', methods=['GET'])
def api_user_info():
    """API para obter informações básicas do usuário"""
    try:
        import secrets
        client_ip = get_client_ip(request)
        user_id = secrets.token_hex(8)
        
        return jsonify({
            'user_id': user_id,
            'ip': client_ip,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            'erro': str(e),
            'user_id': 'erro',
            'ip': '0.0.0.0'
        }), 500
