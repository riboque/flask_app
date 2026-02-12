# Flask App - Sistema de Monitoramento e Chat

## Estrutura do Projeto

```
flask_app/
├── run.py                  # Script para iniciar o servidor
├── app.py                  # Aplicação Flask principal
├── config.py               # Configurações centralizadas
├── auth.py                 # Sistema de autenticação
├── security.py             # Funções de segurança/criptografia
├── user_registry.py        # Registro de usuários
├── socket_handlers.py      # Handlers Socket.IO
├── confiar_certificado.html
├── requirements.txt
│
├── routes/                 # Blueprints Flask
│   ├── __init__.py
│   ├── api_routes.py       # APIs de sistema (/api/*)
│   ├── chat_routes.py      # APIs de chat (/api/chat/*)
│   ├── export_routes.py    # Exportação (/export/*)
│   ├── monitor_routes.py   # Monitoramento (/api/monitor/*)
│   └── main_routes.py      # Rotas principais (/, /chat, /terms)
│
├── utils/                  # Utilitários
│   ├── __init__.py
│   └── network.py          # Funções de rede e sistema
│
├── templates/              # Templates HTML (Frontend)
│   ├── chat.html
│   ├── terms.html
│   ├── monitor.html
│   ├── login.html
│   └── ...
│
└── static/                 # Arquivos estáticos
    ├── css/
    │   └── style.css
    └── js/
        └── script.js
```

## Como Executar

1. Ative o ambiente virtual:
   ```bash
   cd flask_app
   ..\\.venv\\Scripts\\activate  # Windows
   source ../.venv/bin/activate  # Linux/Mac
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

3. Execute o servidor:
   ```bash
   python run.py
   ```

4. Acesse no navegador:
   - http://localhost:3000

## Rotas Principais

| Rota | Descrição |
|------|-----------|
| `/` | Página inicial (redireciona para /terms ou /chat) |
| `/terms` | Termos de uso |
| `/chat` | Chat em tempo real |
| `/monitor` | Painel de monitoramento (admin) |
| `/admin` | Painel administrativo |
| `/api/info` | Informações do sistema |
| `/export/json` | Exportar dados em JSON |
