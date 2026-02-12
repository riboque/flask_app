"""
Sistema de Coleta de Dados Otimizado
Coleta eficiente de informações do cliente e servidor
"""

import json
import csv
import io
from datetime import datetime
from flask import send_file, jsonify

from ip_users import ip_user_manager


class DataCollector:
    """Coletor de dados centralizado e otimizado"""
    
    def __init__(self):
        self.sessions = {}  # sid -> session_data (para Socket.IO)
    
    def register_session(self, sid, ip, user_agent, system_info=None):
        """Registrar sessão de cliente (Socket.IO)"""
        now = datetime.now().isoformat()
        
        # Obter ou criar usuário por IP
        user, is_new = ip_user_manager.get_or_create_user(ip, user_agent, system_info)
        
        self.sessions[sid] = {
            'sid': sid,
            'ip': ip,
            'username': user['username'],
            'connected_at': now,
            'last_activity': now,
            'system_info': system_info or {}
        }
        
        return user
    
    def update_session(self, sid, system_info):
        """Atualizar informações da sessão"""
        if sid in self.sessions:
            session = self.sessions[sid]
            session['system_info'] = system_info
            session['last_activity'] = datetime.now().isoformat()
            
            # Atualizar dados do usuário por IP
            ip_user_manager.update_system_info(session['ip'], system_info)
    
    def remove_session(self, sid):
        """Remover sessão (desconexão)"""
        if sid in self.sessions:
            del self.sessions[sid]
    
    def get_active_sessions(self):
        """Obter sessões ativas"""
        return list(self.sessions.values())
    
    def get_all_data(self):
        """Obter todos os dados coletados (usuários + sessões ativas)"""
        return {
            'users': ip_user_manager.get_all_users(),
            'active_sessions': self.get_active_sessions(),
            'stats': ip_user_manager.get_stats(),
            'exported_at': datetime.now().isoformat()
        }


# Instância global
data_collector = DataCollector()


# ============================================================================
# FUNÇÕES DE EXPORTAÇÃO OTIMIZADAS
# ============================================================================

def export_users_csv():
    """Exportar usuários em CSV otimizado"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    rows = ip_user_manager.export_for_csv()
    
    if not rows:
        return jsonify({'erro': 'Nenhum usuário registrado'}), 404
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'usuarios_{timestamp}.csv'
    )


def export_users_json():
    """Exportar usuários em JSON"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    data = ip_user_manager.export_for_json()
    json_data = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    
    return send_file(
        io.BytesIO(json_data.encode('utf-8')),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'usuarios_{timestamp}.json'
    )


def export_users_html():
    """Exportar usuários em HTML formatado"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    users = ip_user_manager.get_all_users()
    stats = ip_user_manager.get_stats()
    
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório de Usuários - {timestamp}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-value {{ font-size: 2em; color: #00d4ff; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #16213e; border-radius: 10px; overflow: hidden; }}
        th {{ background: #0f3460; color: #00d4ff; padding: 15px; text-align: left; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #333; }}
        tr:hover {{ background: #1f4068; }}
        .online {{ color: #00ff88; }}
        .offline {{ color: #888; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }}
        .badge-new {{ background: #00d4ff; color: #000; }}
        .badge-active {{ background: #00ff88; color: #000; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Relatório de Usuários</h1>
        <p>Gerado em: {timestamp}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{stats['total_users']}</div>
                <div class="stat-label">Total de Usuários</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['active_last_30min']}</div>
                <div class="stat-label">Ativos (30 min)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['active_last_24h']}</div>
                <div class="stat-label">Ativos (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['total_visits']}</div>
                <div class="stat-label">Total de Visitas</div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Usuário</th>
                    <th>IP</th>
                    <th>Visitas</th>
                    <th>Primeira Visita</th>
                    <th>Última Visita</th>
                    <th>Plataforma</th>
                    <th>Tela</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for user in sorted(users, key=lambda x: x.get('last_seen', ''), reverse=True):
        sys_info = user.get('system_info', {})
        screen = f"{sys_info.get('screenWidth', 'N/A')}x{sys_info.get('screenHeight', 'N/A')}"
        
        html += f"""
                <tr>
                    <td><strong>{user['username']}</strong></td>
                    <td>{user['ip']}</td>
                    <td>{user['total_visits']}</td>
                    <td>{user.get('first_visit', 'N/A')[:19]}</td>
                    <td>{user.get('last_seen', 'N/A')[:19]}</td>
                    <td>{sys_info.get('platform', 'N/A')}</td>
                    <td>{screen}</td>
                </tr>
"""
    
    html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        io.BytesIO(html.encode('utf-8')),
        mimetype='text/html',
        as_attachment=True,
        download_name=f'usuarios_{timestamp_file}.html'
    )


def export_full_report():
    """Exportar relatório completo (todos os dados)"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    data = data_collector.get_all_data()
    json_data = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    
    return send_file(
        io.BytesIO(json_data.encode('utf-8')),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'relatorio_completo_{timestamp}.json'
    )
