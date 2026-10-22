# iPhone VPN API (a-Shell)

API REST em Python para uso experimental no iPhone, com banco SQLite, autenticação Bearer e gerenciamento de Services, Commands e Toolbox.

## Limitações importantes

- O iOS pode suspender processos em segundo plano. Trate o servidor como uma ferramenta de uso em primeiro plano, não como um daemon 24/7.
- O a-Shell não é um Linux completo: comandos disponíveis e suporte a `subprocess`/`sh` dependem da versão e do ambiente. O executor tenta chamar `sh`, mas isso precisa ser validado no próprio iPhone.
- Para disponibilidade contínua, hospede a API em uma VPS dentro da tailnet e use o iPhone como cliente.
- Não exponha esta API à internet pública. Use Tailscale ACLs e, idealmente, HTTPS. O token é um segredo de administrador.

## Arquivos

- `api.py`: servidor HTTP, endpoints REST e SQLite (somente biblioteca padrão Python).
- `requirements.txt`: nenhuma dependência externa.
- `install.sh`: inicialização e geração da credencial.
- `commands.sh`: comandos administrativos.

## Instalação no a-Shell

Com o repositório público, instalação direta via sh:

```sh
curl -fsSL https://raw.githubusercontent.com/vinihss/iphone-vpn-api/main/install.sh | sh
```

Depois, inicie o servidor:

```sh
python3 api.py serve --host 0.0.0.0 --port 8765
```

Copie os arquivos para uma pasta acessível no a-Shell. Depois:

```sh
python3 api.py init
python3 api.py rotate-token
python3 api.py serve --host 0.0.0.0 --port 8765
```

A primeira inicialização cria `data/api.sqlite3` e `data/token.txt`. Guarde o token em local seguro. `token.txt` contém a credencial em texto puro para facilitar o uso local; proteja o arquivo e não o sincronize publicamente.

Se `python3` não estiver disponível com esse nome, tente `python`.

## Autenticação

Todas as rotas `/api/v1/*`, exceto `/api/v1/health`, exigem:

```http
Authorization: Bearer SEU_TOKEN
Content-Type: application/json
```

## Endpoints

### Services
- `POST /api/v1/service/add`
- `GET /api/v1/service/list`
- `GET /api/v1/service/{service_id}`
- `PATCH /api/v1/service/{service_id}`
- `DELETE /api/v1/service/{service_id}`
- `POST /api/v1/service/{service_id}/run`

Service JSON:
```json
{
  "name": "status-vps",
  "base_url": "http://100.64.0.10:8080",
  "method": "GET",
  "path": "/health",
  "headers": {},
  "timeout": 10
}
```

`run` envia uma requisição HTTP para o serviço cadastrado. Somente cadastre URLs de confiança; o acesso é restrito à rede do iPhone/Tailscale conforme a configuração da rede.

### Commands
- `POST /api/v1/command/add`
- `GET /api/v1/command/list`
- `GET /api/v1/command/{command_id}`
- `PATCH /api/v1/command/{command_id}`
- `DELETE /api/v1/command/{command_id}`
- `POST /api/v1/command/{command_id}/run`

Command JSON:
```json
{
  "name": "listar-arquivos",
  "script": "pwd && ls",
  "description": "Lista arquivos no diretório atual",
  "enabled": true
}
```

### Toolbox
- `POST /api/v1/toolbox/exec` — execução pontual: `{"command":"pwd"}`
- `POST /api/v1/toolbox/add`
- `GET /api/v1/toolbox/list`
- `GET /api/v1/toolbox/{tool_id}`
- `PATCH /api/v1/toolbox/{tool_id}`
- `DELETE /api/v1/toolbox/{tool_id}`
- `POST /api/v1/toolbox/{tool_id}/run`

**Segurança:** `toolbox/exec` executa comandos arbitrários e equivale a acesso administrativo ao processo. Use apenas em ambiente confiável, nunca exponha a API publicamente e prefira Commands/Tools cadastrados. O endpoint aceita apenas um comando por requisição, mas não é um sandbox.

## Exemplos

Defina o token em uma variável local:
```sh
TOKEN='cole-o-token-aqui'
```

Criar service:
```sh
curl -X POST http://IP_DO_IPHONE:8765/api/v1/service/add \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"health-vps","base_url":"http://100.64.0.10:8080","method":"GET","path":"/health"}'
```

Executar comando cadastrado:
```sh
curl -X POST http://IP_DO_IPHONE:8765/api/v1/command/1/run \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
```

Rotacionar token localmente:
```sh
python3 api.py rotate-token
```
A rotação invalida imediatamente o token anterior. Reinicie o servidor se necessário.

## Observações de segurança

- O servidor escuta em `0.0.0.0` por padrão para permitir conexões na rede; restrinja o acesso com firewall/Tailscale ACL.
- Não há usuários/roles; o token concede acesso administrativo completo.
- Scripts podem alterar dados e arquivos acessíveis ao processo.
- Para uso sério, adicione allowlist de comandos, limite de tamanho de saída, rate limiting e HTTPS.
