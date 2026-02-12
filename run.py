#!/usr/bin/env python3
"""
Script para iniciar o servidor Flask
Execute: python run.py
"""

import os
import sys

# Garantir que o diretório de trabalho é a pasta flask_app
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)
sys.path.insert(0, script_dir)

from app import app, socketio

if __name__ == '__main__':
    print("\n" + "="*50)
    print("[INIT] Iniciando servidor Flask com Socket.IO...")
    print(f"[INFO] Diretório: {os.getcwd()}")
    print("[INFO] MODO: HTTP (DESENVOLVIMENTO)")
    print("="*50)

    port = 3000

    print(f"\n[INFO] Acesse http://localhost:{port}")
    print(f"[INFO] Ou http://192.168.1.3:{port} (rede local)\n")

    while True:
        try:
            print(f"[OK] Servidor iniciando na porta {port}...")
            socketio.run(
                app,
                debug=False,
                host='0.0.0.0',
                port=port,
                ssl_context=None,
                allow_unsafe_werkzeug=True
            )
            break
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:
                print(f"[WARN] Porta {port} em uso, tentando {port + 1}...")
                port += 1
            else:
                print(f"[ERRO] Falha ao iniciar servidor: {e}")
                raise
