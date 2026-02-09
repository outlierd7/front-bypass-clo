# Checklist – Integração Supabase + Railway (o que você precisa fazer)

O código já está no **GitHub**. O que falta é configurar variáveis no **Railway** e, se quiser migrar dados, rodar a migração (de preferência com a URL **Session pooler** do Supabase).

---

## 1. GitHub

- **Status:** repositório atualizado (branch `main`).
- Nada a fazer.

---

## 2. Supabase – connection string

- O app já está preparado para usar `DATABASE_URL`.
- No painel do Supabase: **Connect** → **Connection string**.
- Se a **Direct connection** falhar (erro de rede / DNS no seu PC ou no Railway), use o **Session pooler** (porta 6543, host tipo `...pooler.supabase.com`). Copie a URL e troque `[YOUR-PASSWORD]` pela senha do banco.
- Exemplo de formato (troque a senha):  
  `postgresql://postgres.[PROJECT-REF]:SUA_SENHA@aws-0-us-west-2.pooler.supabase.com:6543/postgres?sslmode=require`

Guarde essa URL para o passo 3.

---

## 3. Railway – variáveis e deploy

1. Acesse **railway.com** → seu projeto → serviço do **Cloaker**.
2. Abra **Variables** (variáveis de ambiente).
3. Adicione:
   - **Nome:** `DATABASE_URL`  
   - **Valor:** a connection string do Supabase (a que você guardou no passo 2, com Session pooler se a Direct não funcionar).
4. Salve e faça **Redeploy** do serviço (ou aguarde o deploy automático se estiver ligado ao GitHub).

Depois do deploy, o app passa a usar o Supabase. Na primeira requisição, as tabelas são criadas se ainda não existirem.

**Login com várias réplicas:** Com `DATABASE_URL` definido, as sessões de login são salvas no **PostgreSQL** (Supabase). Assim o login funciona em todas as réplicas. Se definir `SESSION_SECRET` no Railway, use um valor fixo e não mude entre deploys.

---

## 4. (Opcional) Migrar dados do banco antigo para o Supabase

- Se o app ainda estava com **SQLite** (volume) e você quer levar usuários/sites/visitantes para o Supabase:
  1. No painel do site (antes de trocar para Supabase), entre como admin → **Configurações** → **Backup do banco** → **Download backup (JSON)**.
  2. Salve o arquivo na pasta do projeto (ex.: `cloaker-backup-2025-02-02.json`).
  3. No PowerShell, na pasta do projeto, rode (use a **mesma** URL do passo 2, entre aspas):
     ```powershell
     $env:DATABASE_URL = "postgresql://postgres.xxxx:SUA_SENHA@...pooler.supabase.com:6543/postgres?sslmode=require"
     node scripts/migrate-json-to-pg.js "cloaker-backup-2025-02-02.json"
     ```
  4. Se a conexão do seu PC falhar (rede/DNS), faça o deploy no Railway com `DATABASE_URL` (passo 3), depois use **Railway → Runs** (ou um job único) para rodar o script de migração com o backup, ou rode de outro lugar com acesso à internet que consiga alcançar o Supabase.

---

## 5. (Opcional) Domínios pelo painel – sync com Railway

Para que, ao cadastrar um domínio no painel (como admin), o app tente adicionar também no Railway:

1. Railway → **Account** → **Tokens** → crie um token (Account ou do workspace).
2. No dashboard, **Cmd/Ctrl+K** e copie: **Service ID**, **Project ID**, **Environment ID**.
3. Em **Variables** do serviço, adicione:
   - `RAILWAY_API_TOKEN` = token do passo 1  
   - `RAILWAY_SERVICE_ID` = Service ID  
   - `RAILWAY_PROJECT_ID` = Project ID  
   - `RAILWAY_ENVIRONMENT_ID` = Environment ID  
4. Redeploy. Ao cadastrar um domínio como admin no painel, o app adiciona o domínio no Railway pela API.

---

## Resumo

| Onde      | Ação |
|----------|------|
| GitHub   | Já feito. |
| Supabase | Copiar connection string (Session pooler se precisar). |
| Railway  | Colar em `DATABASE_URL`, redeploy; opcionalmente `RAILWAY_*` para domínios. |
| Migração | Baixar backup do painel, rodar `node scripts/migrate-json-to-pg.js backup.json` com `DATABASE_URL` no PowerShell (ou no Railway). |

Se quiser, na próxima mensagem diga: “já coloquei a DATABASE_URL no Railway e fiz redeploy” ou “rodei a migração e deu erro: …” que eu te ajudo no próximo passo.
