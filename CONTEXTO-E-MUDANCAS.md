# Contexto do projeto Cloaker Pro e o que foi feito nesta conversa

Este arquivo resume o estado atual do projeto e tudo que foi implementado nesta sessão, para você (ou outra aba do Cursor) continuar as modificações no clone sem perder o contexto.

---

## Visão geral do projeto

- **Nome:** GhostVic – painel de controle para cloaking de links (proteção de landing em campanhas de ads).
- **Stack:** Backend Node.js (Express, sql.js/SQLite), frontend HTML/CSS/JS puro (sem framework), deploy no **Railway**, código no **GitHub** (repositório: `outlierd7/front-bypass-clo`, branch `main`).
- **Fluxo principal:** Usuário cadastra a URL da landing → sistema gera um link (`/go/:code`) → quem clica passa pelo cloaker (checagem de IP, User-Agent, país, bot, desktop, etc.) e é redirecionado para a landing (permitido) ou para uma URL de bloqueio (ex.: Google). UTMs e parâmetros dos ads são repassados. Visitantes são registrados na tabela `visitors`.

---

## O que já existe (antes desta conversa)

- **Autenticação:** Login, logout, sessão (express-session, bcrypt). Primeiro usuário criado via “Criar administrador” (setup). Solicitação de conta (`/api/signup`) com status `pending`, aprovação/rejeição pelo admin.
- **Painel:** Dashboard (estatísticas por período: Hoje, Ontem, 7/15/30 dias; gráficos por hora, navegador, país, motivos de bloqueio), Meus Sites, Visitantes, Permitidos e Bloqueados, Link para Ads, Configurações (domínio do cloaker por usuário).
- **Tabelas:** `users` (id, username, password_hash, role, status, cloaker_base_url, created_at), `sites` (site_id, link_code, name, domain, target_url, redirect_url, regras de bloqueio, allowed/blocked_countries, is_active), `visitors` (dados de cada acesso), `settings`.
- **Rota pública:** `/go/:code` – redirecionamento com regras de cloaking e registro do visitante.

---

## O que foi implementado nesta conversa

### 1. Isolamento por usuário (multi-tenant)

- **Problema:** Qualquer usuário logado via acesso a todos os links/sites da plataforma.
- **Solução:**
  - Coluna **`user_id`** na tabela **`sites`**. Sites antigos foram atribuídos ao primeiro admin (migração no `initDb`).
  - **APIs filtradas por dono:**
    - `GET /api/sites` – só sites do usuário logado.
    - `POST /api/sites` – novo site recebe `user_id` da sessão.
    - `PUT /api/sites/:siteId` e `DELETE /api/sites/:siteId` – só se o site pertencer ao usuário.
    - `GET /api/visitors`, `GET /api/stats`, `GET /api/visitors/:id`, `DELETE /api/visitors`, `DELETE /api/visitors/all`, `GET /api/export` – apenas dados de visitantes dos **sites do usuário** (join com `sites` onde `user_id = sessão`).
  - Cada usuário vê apenas seus próprios sites, visitantes, estatísticas e exportação.

### 2. Gerenciamento de usuários (admin)

- **Novos status de usuário:** `active`, `pending`, **`banned`**, **`paused`**. No login, mensagens específicas para conta pendente, bloqueada ou pausada.
- **Novas rotas (apenas admin):**
  - `DELETE /api/users/:id` – excluir usuário e, em cascata, todos os sites e visitantes dele. Não é possível excluir a própria conta.
  - `POST /api/users/:id/ban` – status `banned` (não pode logar).
  - `POST /api/users/:id/pause` – status `paused` (não pode logar até ativar).
  - `POST /api/users/:id/activate` – volta status para `active`.
  - `PUT /api/users/:id/password` – admin define nova senha (body: `{ password }`, mín. 6 caracteres).
- **Frontend (seção Usuários):** Tabela de usuários (ativos, pausados, bloqueados) com coluna **Status** e coluna **Ações**: Alterar senha (ícone chave), Pausar/Banir ou Ativar, Excluir. Modal “Alterar senha” com campo nova senha. Não é possível alterar/banir/excluir a própria conta.

### 3. Instruções de domínio

- **Arquivo `DOMINIO-CLOAKER.md`:** Adicionada seção **“Como integrar um novo domínio (4 passos)”** no início (tabela resumida: DNS CNAME → propagação → Configurações no painel → URL base sem barra). Cada usuário configura **seu próprio** domínio em Configurações.

### 4. Verificar propagação DNS

- **Backend:** Rota `GET /api/settings/check-propagation?url=...`. Usa `dns.promises` (resolveCname, resolve4) para checar se o hostname resolve; faz `fetch` na URL para ver se o domínio responde. Resposta: `{ ok, message, details }` (details com hostname, cname, ips, reachable).
- **Frontend (Configurações):** Nova seção **“Verificar propagação”** com botão **“Testar propagação”**. Usa a URL salva em “Meu domínio do Cloaker” (ou a digitada). Exibe mensagem (verde = OK; amarelo = DNS resolveu mas não responde; vermelho = erro) e, quando houver, detalhes técnicos (CNAME, IPs, “Responde: sim/não”).
- **Observação:** O teste roda **no servidor** (Railway). Se o domínio estiver atrás do Cloudflare, pode aparecer “DNS resolveu, mas o domínio ainda não está respondendo” mesmo com o site funcionando no navegador. O teste definitivo é abrir `https://seu-dominio.com` no navegador.

---

## Deploy e domínio (Railway + Cloudflare)

- **Railway (plano gratuito):** O botão “Custom Domain” no painel do Railway não está disponível no free plan. Isso **não impede** usar domínio próprio.
- **Uso atual:** Domínio (ex.: `energysaver.store`) configurado no **Cloudflare** com CNAME apontando para `ghostvic-production.up.railway.app`, com **proxy ativado** (nuvem laranja). O SSL fica no Cloudflare; o tráfego é encaminhado ao Railway. O app em produção continua acessível pelo domínio `.up.railway.app` e pelo domínio customizado.
- **No painel do Cloaker:** Em Configurações → “Meu domínio do Cloaker”, o usuário coloca a URL completa (ex.: `https://energysaver.store`) **sem barra no final**. Os links gerados (Meus Sites, Link para Ads) usam essa base.

---

## Estrutura de arquivos relevante

- **`server.js`** – Express, sql.js, sessão, todas as rotas (auth, users, settings, sites, visitors, stats, export, /go/:code, check-propagation).
- **`public/index.html`** – SPA do painel (dashboard, sites, visitantes, relatórios, script, configurações, usuários), modais (site, visitante, usuário, alterar senha), funções JS (apiGet, loadSites, loadUsers, checkPropagation, etc.).
- **`public/login.html`** – Tela de login / criar admin.
- **`DOMINIO-CLOAKER.md`** – Passo a passo de integração de domínio.
- **`package.json`** – Dependências (express, sql.js, bcryptjs, express-session, cors, ua-parser-js, etc.).

---

## Como usar este arquivo no clone

1. Coloque este `CONTEXTO-E-MUDANCAS.md` na **pasta do clone** (raiz do projeto).
2. Na outra aba do Cursor (workspace do clone), abra ou referencie este arquivo (@CONTEXTO-E-MUDANCAS.md) quando for pedir modificações.
3. Assim o assistente (ou você) tem o resumo do que já foi feito e do que ainda quer modificar, sem depender só do histórico desta conversa.

**Convenção:** Toda alteração feita pelo assistente deve ser commitada e enviada ao GitHub (`git add .` → `git commit` → `git push origin main`) sem pedir autorização ao usuário.

---

### 5. Parâmetro de rastreamento (Meta Ads) – só permitir quem vem do Ads

- **Objetivo:** Quem tiver apenas o link (sem o parâmetro) não consegue acessar a landing; só quem clicar no anúncio (com o parâmetro configurado no Meta Ads) é permitido.
- **Backend:**
  - Coluna **`required_ref_token`** na tabela **`sites`**. Ao criar site, é gerado um token único (ex.: `a1b2c3d4e5...`).
  - Em **`/go/:code`:** se o site tiver `required_ref_token`, exige que a URL tenha **`ref=TOKEN`**. Quem acessar sem esse parâmetro ou com valor errado é bloqueado (redirect para URL de bloqueio) e registrado com motivo "Acesso sem parâmetro de rastreamento (não veio do Ads)".
  - **POST /api/sites:** gera e salva `required_ref_token` automaticamente.
  - **PUT /api/sites:** aceita `regenerate_ref_token: true` (gerar novo token) e `required_ref_token: ''` (desativar exigência).
- **Frontend:**
  - No modal do site: seção **"Parâmetro de rastreamento (Meta Ads)"** com checkbox "Exigir parâmetro de rastreamento", exibição de **`ref=TOKEN`** (copiar) e botão "Gerar novo token".
  - Em **Link para Ads:** ao selecionar um site, mostra o link e, se houver token, o parâmetro para colar no Meta Ads (Rastreamento → Parâmetros de URL).
- **Uso no Meta Ads:** Em Rastreamento → Parâmetros de URL, adicionar ex.: `ref=TOKEN` (o mesmo valor exibido no painel). A URL final do anúncio fica `https://seu-cloaker.com/go/CODE?ref=TOKEN&utm_source=FB&...`.

---

### 6. Melhorias visuais e UX (design futurista)

- **Visual moderno e profissional:** Nova paleta de cores (azul neon, roxo, gradientes), fontes Inter, animações suaves, sombras neon.
- **Dashboard responsivo:** Menu lateral em drawer no mobile, stats grid 2 colunas em tablet e 1 em mobile, tabelas com scroll horizontal.
- **Seletor de países:** Trocado de inputs texto para **checkboxes** com lista completa de países (Brasil, Argentina, EUA, etc.). Botões **"Marcar todos"** e **"Desmarcar todos"** em cada seção (Permitidos e Bloqueados).
- **Seção Domínios (admin):** Lista de domínios cadastrados (allowed_domains). Admin pode adicionar/remover. **Importante:** domínio só funciona na internet se adicionado no Railway (Networking → Custom Domain) e no DNS (CNAME). A lista no painel é só organização interna.
- **Dashboard:** "Última atualização: HH:MM (Brasília)" com animação de pulso (•) verde. Título com gradiente.
- **Cards, buttons, badges:** Efeitos hover com elevação, sombras neon, gradientes, animações de fadeIn nas seções.

---

## Próximos passos (exemplos – ajuste ao que você quiser)

- Listar aqui as modificações que você ainda quer fazer no clone (ex.: novos relatórios, novos campos em sites, mudanças no fluxo de login, etc.).
- Quando terminar as alterações no clone: fazer merge da branch de desenvolvimento em `main` e deixar o Railway (ou seu pipeline) fazer o deploy a partir do `main`.