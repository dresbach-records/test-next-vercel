# DEEVO Dev Bridge

MCP server local para conectar agentes de IA a um workspace controlado no VS Code ou GitHub Codespaces.

## Capacidades

- leitura, escrita e exclusão controlada de arquivos;
- `npm install` e `npm run`;
- Git status, diff, commit e push;
- CMD, PowerShell e Bash;
- Docker ps, logs, Compose e exec;
- leitura de variáveis de ambiente explicitamente allowlisted;
- auditoria JSONL das operações;
- transporte MCP stdio para VS Code;
- transporte MCP Streamable HTTP local para uso através de túnel autenticado.

## Segurança

As permissões ficam em `config/permissions.json`. Operações perigosas são desabilitadas por padrão. O servidor não permite caminhos absolutos nem acesso fora do workspace configurado.

Credenciais nunca ficam no repositório. Para permitir uma variável de ambiente, adicione apenas o nome dela em `allowedEnv` e habilite `system.env`.

No modo HTTP, o servidor escuta somente em `127.0.0.1` e exige `Authorization: Bearer <DEEVO_MCP_TOKEN>`.

## VS Code

O workspace já possui `.vscode/mcp.json`. Depois de instalar as dependências, use `MCP: List Servers` e confirme a confiança do servidor.

## Instalação

```bash
cd deevo-dev-bridge
npm install
npm run build
```

## Execução local

```bash
npm run dev
```

## HTTP + túnel

```bash
DEEVO_MCP_TOKEN="gere-um-token-forte" npm run http
```

O endpoint local será `http://127.0.0.1:4318/mcp`. Um túnel HTTPS autenticado pode encaminhar somente essa porta.

## Próximas evoluções

- aprovação interativa por operação;
- UI de permissões;
- integração de auditoria com OpenTelemetry;
- sandbox por processo/container;
- instalação como extensão VS Code;
- integração com GitHub Codespaces/Dev Containers;
- políticas por projeto e por usuário.
