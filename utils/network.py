"""
Funções utilitárias para detecção de rede e sistema
"""
import socket
import subprocess
import platform
import psutil
from datetime import datetime


def obter_ip_local():
    """Obter IP local da máquina"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        return f"Erro: {str(e)}"


def obter_ip_publico():
    """Obter IP público da máquina"""
    try:
        import requests
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        return response.json().get("ip", "Não disponível")
    except Exception as e:
        return f"Não disponível: {str(e)}"


def obter_hostname():
    """Obter nome da máquina (host)"""
    return socket.gethostname()


def obter_sistema_operacional():
    """Obter informações do SO"""
    return {
        "sistema": platform.system(),
        "versao": platform.release(),
        "arquitetura": platform.machine(),
        "processador": platform.processor()
    }


def obter_interfaces_rede():
    """Obter todas as interfaces de rede"""
    interfaces = []
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        
        for interface_name, addrs in if_addrs.items():
            interface_info = {
                "nome": interface_name,
                "ativa": if_stats.get(interface_name, None).isup if interface_name in if_stats else False,
                "enderecos": []
            }
            
            for addr in addrs:
                interface_info["enderecos"].append({
                    "tipo": addr.family.name,
                    "endereco": addr.address,
                    "mascara": addr.netmask,
                    "broadcast": addr.broadcast
                })
            
            interfaces.append(interface_info)
    except Exception as e:
        interfaces.append({"erro": str(e)})
    
    return interfaces


def obter_conexoes_ativas(limite=100):
    """Obter conexões de rede ativas"""
    conexoes = []
    try:
        conns = psutil.net_connections()
        
        # CORRIGIDO: usar slice [:limite] ao invés de [limite]
        for conn in conns[:limite]:
            conexoes.append({
                "protocolo": conn.type,
                "ip_local": conn.laddr.ip if conn.laddr else "N/A",
                "porta_local": conn.laddr.port if conn.laddr else "N/A",
                "ip_remoto": conn.raddr.ip if conn.raddr else "N/A",
                "porta_remota": conn.raddr.port if conn.raddr else "N/A",
                "status": conn.status,
                "pid": conn.pid
            })
    except Exception as e:
        conexoes.append({"erro": str(e)})
    
    return conexoes


def detect_virtual_machine():
    """Detectar se é máquina virtual"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["wmic", "os", "get", "manufacturer"],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout.lower()
            
            vm_types = {
                "virtualbox": "VirtualBox",
                "vmware": "VMware",
                "hyperv": "Hyper-V",
                "kvm": "KVM",
                "xen": "Xen",
                "parallels": "Parallels",
                "qemu": "QEMU"
            }
            
            for key, name in vm_types.items():
                if key in output:
                    return {"eh_vm": True, "tipo": name}
        else:
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-manufacturer"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = result.stdout.lower()
                
                for vm in ["virtualbox", "vmware", "kvm", "xen", "hyperv"]:
                    if vm in output:
                        return {"eh_vm": True, "tipo": output.split()[0] if output else "Máquina Virtual"}
            except:
                pass
        
        return {"eh_vm": False, "tipo": "Máquina Física"}
    
    except Exception as e:
        return {"erro": str(e), "tipo": "Desconhecido"}


def obter_uso_recursos():
    """Obter uso de CPU, memória e disco"""
    disk_path = '/' if platform.system() != 'Windows' else 'C:\\'
    
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memoria": {
            "total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "usada_gb": round(psutil.virtual_memory().used / (1024**3), 2),
            "disponivel_gb": round(psutil.virtual_memory().available / (1024**3), 2),
            "percentual": psutil.virtual_memory().percent
        },
        "disco": {
            "total_gb": round(psutil.disk_usage(disk_path).total / (1024**3), 2),
            "usado_gb": round(psutil.disk_usage(disk_path).used / (1024**3), 2),
            "disponivel_gb": round(psutil.disk_usage(disk_path).free / (1024**3), 2),
            "percentual": psutil.disk_usage(disk_path).percent
        }
    }


def coletar_informacoes_completas():
    """Coletar todas as informações do sistema"""
    return {
        "timestamp": datetime.now().isoformat(),
        "hostname": obter_hostname(),
        "ip_local": obter_ip_local(),
        "ip_publico": obter_ip_publico(),
        "sistema_operacional": obter_sistema_operacional(),
        "maquina_virtual": detect_virtual_machine(),
        "interfaces_rede": obter_interfaces_rede(),
        "conexoes_ativas": obter_conexoes_ativas(),
        "recursos": obter_uso_recursos()
    }


def get_client_ip(request):
    """Obter IP do cliente com suporte a proxy"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr
