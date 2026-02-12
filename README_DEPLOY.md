# Deploy no Render

Este guia explica como colocar o projeto Flask online usando o Render.

## Pré-requisitos

1. Conta no [Render](https://render.com)
2. Repositório Git (GitHub, GitLab, etc.) com o código do projeto

## Passos para Deploy

### 1. Preparar o Repositório

Certifique-se de que os seguintes arquivos estão no repositório:
- `requirements.txt` (atualizado com gunicorn e eventlet)
- `render.yaml` (arquivo de configuração do Render)
- Todo o código da aplicação

### 2. Conectar ao Render

1. Acesse [dashboard.render.com](https://dashboard.render.com)
2. Clique em "New" > "Web Service"
3. Conecte seu repositório Git
4. Configure o serviço:

**Build Settings:**
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn --worker-class eventlet -w 1 app:app`

**Environment:**
- **Environment:** `Python 3`
- **Add Environment Variable:**
  - `FLASK_ENV`: `production`
  - `FLASK_SECRET_KEY`: (gere uma chave segura ou deixe o Render gerar)

### 3. Deploy

1. Clique em "Create Web Service"
2. O Render irá buildar e deployar automaticamente
3. Aguarde a conclusão do deploy

### 4. Acessar a Aplicação

Após o deploy, você receberá uma URL como: `https://your-app-name.onrender.com`

## Notas Importantes

- **WebSockets:** O Render suporta WebSockets, mas pode haver limitações no plano gratuito
- **Banco de Dados:** Se precisar de persistência, considere usar o PostgreSQL do Render
- **Domínio Customizado:** Disponível em planos pagos
- **SSL:** Automático no Render

## Troubleshooting

- Verifique os logs no dashboard do Render
- Certifique-se de que todas as dependências estão em `requirements.txt`
- Para WebSockets, use `eventlet` como worker class no gunicorn

## Alternativa: Usar render.yaml

Se preferir usar o arquivo `render.yaml` incluído:

1. No Render, selecione "Blueprint" ao criar o serviço
2. O Render lerá automaticamente as configurações do `render.yaml`
