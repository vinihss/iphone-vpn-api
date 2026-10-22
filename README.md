# iPhone VPN API (modo CLI para a-Shell)

Utilitários de linha de comando em Python (somente biblioteca padrão) para
gerenciar e executar **services**, **commands** e **tools**, além de um
servidor REST **opcional**.

O modo padrão é o CLI: cada utilitário sobe, executa e encerra — porque o iOS
encerra processos em segundo plano. Nada depende de um daemon vivo no iPhone.

## Limitações importantes

- O iOS suspende/mata processos em segundo plano. No iPhone, use o modo CLI.
  O servidor (`serve`) existe para o caso de uso com VPS dentro da tailnet.
- O a-Shell não é um Linux completo: os scripts rodam via `sh` (`subprocess`).
  Se o shell não estiver no caminho padrão, defina
  `export IPHONE_VPN_API_SHELL=sh` (ou o caminho completo). Valide no iPhone.
- Não exponha o servidor à internet pública. Use Tailscale ACLs e, idealmente,
  HTTPS. O token é um segredo de administrador.

## Arquivos

- `api.py`: CLI + servidor HTTP e SQLite (somente biblioteca padrão).
- `commands.sh`: atalhos — `./commands.sh <argumentos>` repassa para `api.py`.
- `install.sh`: download e inicialização.
- `tests/cli.sh`: testes do modo CLI (padrão, sem servidor externo).
- `tests/integration.sh`: testes do modo HTTP (servidor no ar).
- `requirements.txt`: nenhuma dependência externa.
- `data/`: `api.sqlite3` e `token.txt`, criados no `init`.

## Instalação no a-Shell

Com o repositório público, instalação direta via sh:

```sh
curl -fsSL https://raw.githubusercontent.com/vinihss/iphone-vpn-api/main/install.sh | sh
```

Ou manualmente, com os arquivos numa pasta acessível:

```sh
python3 api.py init
python3 api.py rotate-token
python3 api.py --help
```

A primeira inicialização cria `data/api.sqlite3` e `data/token.txt`. Guarde o
token em local seguro; `token.txt` fica em texto puro para uso local, proteja o
arquivo e não o sincronize publicamente. Se `python3` não existir com esse
nome, tente `python`.

## Modo CLI (padrão)

`python3 api.py` sem argumentos mostra a ajuda completa. Todos os exemplos
funcionam igual com `./commands.sh ...`.

### Executar

```sh
python3 api.py run-command 1                  # executa um command pelo id
python3 api.py toolbox-exec "df -h"           # comando arbitrário
python3 api.py toolbox-exec "ping -c 3 1.1.1.1" --timeout 20
```

- o banner (`Executando ...`) vai para **stderr**; a saída do script vai para
  **stdout**, então dá para usar `$(python3 api.py run-command 1)`;
- o código de saída do processo é o do próprio script;
- `Ctrl+C` encerra o processo e o script (código 130).

### Códigos de saída

| Código | Significado |
| --- | --- |
| 0 | sucesso |
| 1 | erro (registro inexistente, JSON inválido, falha de rede) |
| 2 | uso inválido (argumentos) |
| 3 | o registro existe, mas está desativado |
| 124 | timeout de execução (`--timeout`) |
| 130 | interrompido pelo usuário (Ctrl+C) |
| outro | código de saída do script/comando executado |

### Commands

```sh
python3 api.py command add listar "pwd && ls" --description "Lista arquivos"
python3 api.py command list            # tabela; use --json para JSON
python3 api.py command show 1
python3 api.py command update 1 --script "ls -la" --description "novo script"
python3 api.py command disable 1       # e: command enable 1
python3 api.py command run 1 --timeout 30
python3 api.py command delete 1
```

### Services (chamadas HTTP a outros sistemas)

```sh
python3 api.py service add health-vps http://100.64.0.10:8080 --path /health
python3 api.py service add post-api https://api.exemplo.com --method POST \
  --header "Authorization: Bearer TOKEN" --timeout 20
python3 api.py service list
python3 api.py service run 1 '{"ping": true}'   # corpo JSON opcional
python3 api.py service update 1 --header "X-Novo: 1"   # merge nos headers
python3 api.py service delete 1
```

`service run` imprime `HTTP <status>` em stderr e o corpo em stdout. Sai com 0
quando a resposta é < 400 e com 1 no resto (falha de rede também é 1). Só são
aceitas URLs `http(s)://` sem credenciais embutidas, validadas já no `add`.

### Toolbox

```sh
python3 api.py toolbox-exec "echo ola"          # execução pontual
python3 api.py toolbox add disco "df -h"        # tool reutilizável
python3 api.py toolbox list
python3 api.py toolbox run 1
python3 api.py toolbox disable 1                # e: toolbox enable 1
python3 api.py toolbox delete 1
```

**Segurança:** `toolbox-exec` executa comandos arbitrários e equivale a acesso
administrativo ao processo. Não é um sandbox. Prefira commands/tools
cadastrados e use apenas em ambiente confiável.

### Token

```sh
python3 api.py rotate-token   # token novo; o anterior é invalidado na hora
cat data/token.txt            # token atual
```

## Servidor HTTP (opcional)

Para disponibilidade contínua, hospede a API em uma VPS dentro da tailnet e use
o iPhone como cliente:

```sh
python3 api.py serve --host 0.0.0.0 --port 8765
```

Todas as rotas `/api/v1/*`, exceto `/api/v1/health`, exigem:

```http
Authorization: Bearer SEU_TOKEN
Content-Type: application/json
```

Equivalência CLI ↔ HTTP:

| CLI | Rota HTTP |
| --- | --- |
| `run-command <id>` | `POST /api/v1/command/{id}/run` |
| `toolbox-exec "<cmd>"` | `POST /api/v1/toolbox/exec` |
| `command add/list/show/delete` | `POST/GET/DELETE /api/v1/command/...` |
| `command update <id>` | `PATCH /api/v1/command/{id}` |
| `command enable/disable <id>` | `PATCH /api/v1/command/{id}` com `{"enabled": bool}` |
| `service add/list/show/delete` | `POST/GET/DELETE /api/v1/service/...` |
| `service run <id>` | `POST /api/v1/service/{id}/run` |
| `service update <id>` | `PATCH /api/v1/service/{id}` |
| `toolbox add/list/show/delete/run` | `/api/v1/toolbox/...` |
| `init`, `rotate-token` | rotas locais, sem endpoint |

Exemplos HTTP:

```sh
TOKEN="$(cat data/token.txt)"

curl http://100.90.99.113:8765/api/v1/health
# {"ok": true, "service": "iphone-vpn-api"}

curl -X POST http://100.90.99.113:8765/api/v1/service/1/run \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
```

## Testes

```sh
./commands.sh test       # modo CLI (padrão)
./commands.sh test-http  # modo HTTP: precisa do servidor no ar
```

Ou diretamente: `sh tests/cli.sh` e `sh tests/integration.sh`.

- `tests/cli.sh`: só `python3` + sh. Sobe um servidor temporário numa porta
  alta para exercitar `service run` e o encerra ao final (nenhum processo
  sobra; os registros criados são removidos no `trap`).
- `tests/integration.sh`: `curl` + `jq`, servidor `python3 api.py serve`
  rodando e token em `IPHONE_VPN_API_TOKEN` (ou
  `IPHONE_VPN_API_BASE_URL` para outro host/porta).

## Observações de segurança

- O servidor escuta em `0.0.0.0` por padrão para permitir conexões na rede;
  restrinja o acesso com firewall/Tailscale ACL.
- Não há usuários/roles: o token concede acesso administrativo completo.
- Scripts podem alterar dados e arquivos acessíveis ao processo.
- Para uso sério no modo HTTP, adicione allowlist de comandos, limite de
  tamanho de saída, rate limiting e HTTPS.
