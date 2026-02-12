"""
Rotas de Monitoramento
"""
import io
import csv
import json
from flask import Blueprint, jsonify, request, send_file
from datetime import datetime

from auth import require_login, get_all_users, get_auth_logs
from user_registry import user_registry

# Criar blueprint
monitor_bp = Blueprint('monitor', __name__, url_prefix='/api/monitor')

# Referência aos dados compartilhados
shared_data = {
    'connected_clients': {},
    'registered_systems': {},
    'chat_messages': []
}


def init_shared_data(connected_clients, registered_systems, chat_messages):
    """Inicializa referências aos dados compartilhados"""
    shared_data['connected_clients'] = connected_clients
    shared_data['registered_systems'] = registered_systems
    shared_data['chat_messages'] = chat_messages


@monitor_bp.route('/devices')
def api_monitor_devices():
    """API para obter informações dos dispositivos conectados"""
    try:
        devices = []
        for sid, client_info in shared_data['connected_clients'].items():
            device = {
                'id': sid,
                'ip': client_info.get('ip', 'desconhecido'),
                'user_agent': client_info.get('user_agent', ''),
                'connected_at': client_info.get('connected_at', ''),
                'system_info': None
            }
            
            if sid in shared_data['registered_systems']:
                sys_info = shared_data['registered_systems'][sid].get('system_info', {})
                device['system_info'] = {
                    'hostname': sys_info.get('hostname', 'N/A'),
                    'sistema': sys_info.get('sistema_operacional', {}).get('sistema', 'N/A'),
                    'versao': sys_info.get('sistema_operacional', {}).get('versao', 'N/A'),
                    'arquitetura': sys_info.get('sistema_operacional', {}).get('arquitetura', 'N/A'),
                    'processador': sys_info.get('sistema_operacional', {}).get('processador', 'N/A'),
                    'ip_local': sys_info.get('ip_local', 'N/A'),
                    'eh_vm': sys_info.get('maquina_virtual', {}).get('eh_vm', False),
                    'tipo_vm': sys_info.get('maquina_virtual', {}).get('tipo', 'Física')
                }
            
            devices.append(device)
        
        return jsonify({
            'dispositivos': devices,
            'total': len(devices),
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@monitor_bp.route('/messages/export')
def api_monitor_messages_export():
    """Exportar mensagens do chat em JSON"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'total_mensagens': len(shared_data['chat_messages']),
            'mensagens': shared_data['chat_messages']
        }
        
        json_data = json.dumps(export_data, indent=2, ensure_ascii=False)
        
        return send_file(
            io.BytesIO(json_data.encode('utf-8')),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"chat_mensagens_{timestamp}.json"
        )
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@monitor_bp.route('/devices/export/csv')
def api_monitor_devices_export_csv():
    """Exportar dispositivos conectados em CSV"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'ID Session', 'IP', 'User Agent', 'Conectado em', 
            'Hostname', 'Sistema', 'Versão', 'Arquitetura', 
            'Processador', 'IP Local', 'É VM', 'Tipo'
        ])
        
        for sid, client_info in shared_data['connected_clients'].items():
            sys_info = {}
            if sid in shared_data['registered_systems']:
                sys_info = shared_data['registered_systems'][sid].get('system_info', {})
            
            writer.writerow([
                sid,
                client_info.get('ip', 'N/A'),
                client_info.get('user_agent', '')[:50],
                client_info.get('connected_at', 'N/A'),
                sys_info.get('hostname', 'N/A'),
                sys_info.get('sistema_operacional', {}).get('sistema', 'N/A'),
                sys_info.get('sistema_operacional', {}).get('versao', 'N/A'),
                sys_info.get('sistema_operacional', {}).get('arquitetura', 'N/A'),
                sys_info.get('sistema_operacional', {}).get('processador', 'N/A'),
                sys_info.get('ip_local', 'N/A'),
                sys_info.get('maquina_virtual', {}).get('eh_vm', 'N/A'),
                sys_info.get('maquina_virtual', {}).get('tipo', 'N/A')
            ])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"dispositivos_{timestamp}.csv"
        )
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@monitor_bp.route('/stats')
def api_monitor_stats():
    """API para obter estatísticas do monitor"""
    try:
        stats = {
            'total_dispositivos': len(shared_data['connected_clients']),
            'total_sistemas_registrados': len(shared_data['registered_systems']),
            'total_mensagens': len(shared_data['chat_messages']),
            'timestamp': datetime.now().isoformat(),
            'uptime': 'Running'
        }
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@monitor_bp.route('/users')
@require_login
def api_monitor_users():
    """API para obter lista de usuários para o monitor"""
    try:
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')

        users = get_all_users()

        if role_filter:
            users = [u for u in users if u['role'] == role_filter]

        if status_filter:
            active = status_filter == 'active'
            users = [u for u in users if u['active'] == active]

        return jsonify({'users': users}), 200
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@monitor_bp.route('/auth_logs')
@require_login
def api_monitor_auth_logs():
    """API para obter logs de autenticação para o monitor"""
    try:
        logs = get_auth_logs()
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@monitor_bp.route('/registered_users')
def api_monitor_registered_users():
    """API para obter dados dos usuários registrados"""
    try:
        users_data = []
        
        all_users = user_registry.get_all_users()
        
        for user in all_users:
            metadata = user.get('metadata', {})
            so = metadata.get('sistema_operacional', {})
            vm = metadata.get('maquina_virtual', {})
            
            user_entry = {
                'username': user.get('username', 'N/A'),
                'status': user.get('status', 'offline'),
                'ip': user.get('ip', 'N/A'),
                'registered_at': user.get('registered_at', 'N/A'),
                'last_login': user.get('last_login', 'N/A'),
                'total_connections': user.get('total_connections', 0),
                'user_agent': metadata.get('user_agent', 'N/A'),
                'terms_accepted': metadata.get('terms_accepted', 'N/A'),
                'hostname': metadata.get('hostname', 'N/A'),
                'ip_local': metadata.get('ip_local', 'N/A'),
                'ip_publico': metadata.get('ip_publico', 'N/A'),
                'sistema': so.get('sistema', 'N/A'),
                'versao_so': so.get('versao', 'N/A'),
                'arquitetura': so.get('arquitetura', 'N/A'),
                'processador': so.get('processador', 'N/A'),
                'eh_vm': vm.get('eh_vm', False),
                'tipo_vm': vm.get('tipo', 'Fisica')
            }
            
            users_data.append(user_entry)
        
        # Adicionar dados de registered_systems
        for username, sys_data in shared_data['registered_systems'].items():
            existing = next((u for u in users_data if u['username'] == username), None)
            if not existing:
                sys_info = sys_data.get('system_info', {})
                so = sys_info.get('sistema_operacional', {})
                vm = sys_info.get('maquina_virtual', {})
                users_data.append({
                    'username': username,
                    'status': 'online',
                    'ip': sys_data.get('ip', 'N/A'),
                    'user_agent': sys_data.get('user_agent', 'N/A'),
                    'connected_at': sys_data.get('connected_at', 'N/A'),
                    'hostname': sys_info.get('hostname', 'N/A'),
                    'ip_local': sys_info.get('ip_local', 'N/A'),
                    'ip_publico': sys_info.get('ip_publico', 'N/A'),
                    'sistema': so.get('sistema', 'N/A'),
                    'versao_so': so.get('versao', 'N/A'),
                    'arquitetura': so.get('arquitetura', 'N/A'),
                    'processador': so.get('processador', 'N/A'),
                    'eh_vm': vm.get('eh_vm', False),
                    'tipo_vm': vm.get('tipo', 'Fisica')
                })
        
        return jsonify({
            'users': users_data,
            'total': len(users_data),
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'erro': str(e)}), 500


@monitor_bp.route('/registered_users/export/csv')
def api_monitor_registered_users_export_csv():
    """Exportar usuários registrados em CSV"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(["client_key", "ip", "registered_at", "system_info"])
        
        all_users = user_registry.get_all_users()
        
        for user in all_users:
            metadata = user.get('metadata', {})
            system_info = {
                'timestamp': user.get('registered_at', ''),
                'userAgent': metadata.get('user_agent', ''),
                'platform': metadata.get('platform', ''),
                'language': metadata.get('language', ''),
                'cookieEnabled': metadata.get('cookie_enabled', True),
                'online': user.get('status', 'offline') == 'online',
                'hostname': metadata.get('hostname', ''),
                'ip_local': metadata.get('ip_local', ''),
                'ipPublico': metadata.get('ip_publico', ''),
                'sistema_operacional': metadata.get('sistema_operacional', {}),
                'maquina_virtual': metadata.get('maquina_virtual', {}),
                'total_connections': user.get('total_connections', 0),
                'last_login': user.get('last_login', '')
            }
            
            writer.writerow([
                user.get('username', 'N/A'),
                user.get('ip', 'N/A'),
                user.get('registered_at', 'N/A'),
                json.dumps(system_info, ensure_ascii=False)
            ])
        
        for client_key, sys_data in shared_data['registered_systems'].items():
            existing = next((u for u in all_users if u.get('username') == client_key), None)
            if not existing:
                writer.writerow([
                    client_key,
                    sys_data.get('ip', 'N/A'),
                    sys_data.get('registered_at', 'N/A'),
                    json.dumps(sys_data.get('system_info', {}), ensure_ascii=False)
                ])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"dados_coletados_{timestamp}.csv"
        )
    except Exception as e:
        return jsonify({'erro': str(e)}), 500
