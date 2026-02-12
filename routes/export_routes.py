"""
Rotas de Exportação Otimizadas (JSON, CSV, HTML)
Usa o novo sistema de usuários por IP
"""
import io
import csv
import json
from flask import Blueprint, jsonify, send_file, request
from datetime import datetime

from utils.network import coletar_informacoes_completas
from ip_users import ip_user_manager
from data_collector import (
    export_users_csv, export_users_json, 
    export_users_html, export_full_report,
    data_collector
)

# Criar blueprint
export_bp = Blueprint('export', __name__, url_prefix='/export')

# Referência aos dados compartilhados
shared_data = {
    'registered_systems': {}
}


def init_shared_data(registered_systems):
    """Inicializa referências aos dados compartilhados"""
    shared_data['registered_systems'] = registered_systems


# ============================================================================
# EXPORTAÇÃO DE USUÁRIOS (Novo sistema por IP)
# ============================================================================

@export_bp.route('/users/csv')
def route_export_users_csv():
    """Exportar usuários em CSV"""
    return export_users_csv()


@export_bp.route('/users/json')
def route_export_users_json():
    """Exportar usuários em JSON"""
    return export_users_json()


@export_bp.route('/users/html')
def route_export_users_html():
    """Exportar usuários em HTML formatado"""
    return export_users_html()


@export_bp.route('/full')
def route_export_full():
    """Exportar relatório completo"""
    return export_full_report()


# ============================================================================
# EXPORTAÇÃO DO SISTEMA LOCAL
# ============================================================================

@export_bp.route('/json')
def export_json():
    """Exportar informações do sistema local em JSON"""
    try:
        info = coletar_informacoes_completas()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        json_data = json.dumps(info, indent=2, ensure_ascii=False)
        
        return send_file(
            io.BytesIO(json_data.encode('utf-8')),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"sistema_{timestamp}.json"
        )
    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@export_bp.route('/csv')
def export_csv():
    """Exportar informações do sistema local em CSV"""
    try:
        info = coletar_informacoes_completas()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(["Categoria", "Propriedade", "Valor"])
        
        # Sistema
        writer.writerow(["Sistema", "Timestamp", info["timestamp"]])
        writer.writerow(["Sistema", "Hostname", info["hostname"]])
        writer.writerow(["Sistema", "IP Local", info["ip_local"]])
        writer.writerow(["Sistema", "IP Público", info["ip_publico"]])
        
        # SO
        so = info["sistema_operacional"]
        writer.writerow(["SO", "Sistema", so["sistema"]])
        writer.writerow(["SO", "Versão", so["versao"]])
        writer.writerow(["SO", "Arquitetura", so["arquitetura"]])
        
        # VM
        vm = info["maquina_virtual"]
        writer.writerow(["VM", "É VM?", vm.get("eh_vm", "N/A")])
        writer.writerow(["VM", "Tipo", vm.get("tipo", "N/A")])
        
        # Recursos
        rec = info["recursos"]
        writer.writerow(["Recursos", "CPU %", rec["cpu_percent"]])
        writer.writerow(["Recursos", "Memória %", rec["memoria"]["percentual"]])
        writer.writerow(["Recursos", "Disco %", rec["disco"]["percentual"]])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"sistema_{timestamp}.csv"
        )
    except Exception as e:
        return jsonify({"erro": str(e)}), 500



# ============================================================================
# EXPORTAÇÃO DE CLIENTES (Compatibilidade)
# ============================================================================

@export_bp.route('/clients/json')
def export_clients_json():
    """Exportar clientes registrados em JSON"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Combinar dados do novo sistema com o antigo
        all_data = {
            'ip_users': ip_user_manager.get_all_users(),
            'legacy_systems': list(shared_data['registered_systems'].values()),
            'active_sessions': data_collector.get_active_sessions()
        }
        
        json_data = json.dumps(all_data, indent=2, ensure_ascii=False, default=str)
        
        return send_file(
            io.BytesIO(json_data.encode('utf-8')),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"clientes_{timestamp}.json"
        )
    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@export_bp.route('/clients/csv')
def export_clients_csv():
    """Exportar clientes em CSV"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Usar dados do novo sistema por IP
        rows = ip_user_manager.export_for_csv()
        
        if not rows:
            # Fallback para sistema antigo
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["client_key", "ip", "registered_at", "system_info"])
            for k, v in shared_data['registered_systems'].items():
                writer.writerow([k, v.get('ip'), v.get('registered_at'), 
                               json.dumps(v.get('system_info'), ensure_ascii=False)])
            output.seek(0)
            data = output.getvalue()
        else:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
            output.seek(0)
            data = output.getvalue()
        
        return send_file(
            io.BytesIO(data.encode('utf-8')),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"clientes_{timestamp}.csv"
        )
    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@export_bp.route('/clients/html')
def export_clients_html():
    """Exportar clientes em HTML"""
    return export_users_html()


# ============================================================================
# API DE ESTATÍSTICAS
# ============================================================================

@export_bp.route('/stats')
def export_stats():
    """Retornar estatísticas de exportação"""
    try:
        stats = ip_user_manager.get_stats()
        stats['legacy_systems'] = len(shared_data['registered_systems'])
        stats['active_sessions'] = len(data_collector.get_active_sessions())
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({"erro": str(e)}), 500
