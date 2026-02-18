# 🚂 Deploy no Railway – Passo a Passo Detalhado

Guia para publicar o **Cloaker Pro** no [Railway](https://railway.com/) sem erros.

---

## 📋 O que você vai precisar

- [ ] Conta no **GitHub** (grátis): [github.com](https://github.com)
- [ ] Conta no **Railway** (grátis): [railway.com](https://railway.com)
- [ ] Pasta do projeto **Cloaker Pro** no seu PC

---

## PARTE 1: Colocar o projeto no GitHub

O Railway faz o deploy a partir de um repositório no GitHub. Primeiro precisamos subir o código.

### Passo 1.1: Criar conta no GitHub (se ainda não tiver)

1. Acesse **https://github.com**
2. Clique em **Sign up**
3. Crie sua conta (e-mail, senha, nome de usuário)
4. Confirme o e-mail se pedirem

### Passo 1.2: Instalar o Git no seu PC (se ainda não tiver)

1. Acesse **https://git-scm.com/download/win**
2. Baixe o **Git for Windows**
3. Instale (pode deixar as opções padrão)
4. Feche e abra de novo o terminal/PowerShell

### Passo 1.3: Criar um repositório novo no GitHub

1. Logado no GitHub, clique no **+** (canto superior direito) → **New repository**
2. **Repository name:** `cloaker-pro` (ou outro nome que quiser)
3. Deixe **Public**
4. **Não** marque "Add a README file"
5. Clique em **Create repository**
6. Anote a URL que aparecer, algo como: `https://github.com/SEU-USUARIO/cloaker-pro.git`

### Passo 1.4: Enviar o projeto do seu PC para o GitHub

O projeto já tem um arquivo **.gitignore** que evita enviar `node_modules` e `cloaker.db`. Só o necessário vai para o GitHub.

Abra o **PowerShell** ou **Prompt de Comando** e rode os comandos **na ordem** (troque `SEU-USUARIO` e `cloaker-pro` pelo seu usuário e nome do repositório):

```powershell
cd "C:\Users\drrod\Downloads\cloaker teste"
```

```powershell
git init
```

```powershell
git add .
```

```powershell
git commit -m "Cloaker Pro - deploy Railway"
```

```powershell
git branch -M main
```

```powershell
git remote add origin https://github.com/SEU-USUARIO/cloaker-pro.git
```

```powershell
git push -u origin main
```

- Se pedir **usuário e senha**: use seu usuário do GitHub e um **Personal Access Token** (não a senha normal).
- Para criar o token: GitHub → **Settings** → **Developer settings** → **Personal access tokens** → **Generate new token (classic)** → marque **repo** → Generate → copie e use como senha quando o Git pedir.

Depois disso, o projeto deve aparecer no repositório no GitHub.

---

## PARTE 2: Deploy no Railway

### Passo 2.1: Criar conta no Railway

1. Acesse **https://railway.com**
2. Clique em **Login** (canto superior direito)
3. Escolha **Login with GitHub**
4. Autorize o Railway a acessar sua conta GitHub
5. Aceite os termos se aparecerem

### Passo 2.2: Criar um projeto novo

1. No painel do Railway, clique em **New Project**
2. Escolha **Deploy from GitHub repo**
3. Se pedir, clique em **Configure GitHub App** e autorize o Railway a ver seus repositórios
4. Na lista, selecione o repositório **cloaker-pro** (ou o nome que você usou)
5. Clique nele para selecionar

### Passo 2.3: Configurar o serviço

O Railway vai detectar que é um projeto **Node.js** e começar o deploy.

1. Aguarde o primeiro deploy terminar (pode levar 1–2 minutos)
2. Clique no **serviço** (retângulo com o nome do projeto) para abrir as configurações

### Passo 2.4: Gerar a URL pública (domínio)

1. Na tela do serviço, vá na aba **Settings**
2. Role até **Networking** → **Public Networking**
3. Clique em **Generate Domain**
4. Vai aparecer uma URL tipo: `front-bypass-clo-production.up.railway.app`
5. **Copie e guarde essa URL** – é o endereço do seu painel

### Passo 2.5: Verificar se está no ar

1. Abra essa URL no navegador (use **https**)
2. Deve abrir o **painel do Cloaker Pro**
3. Se abrir, o deploy está certo

---

## 💾 3. Configurar Banco de Dados (Blindado)

O sistema agora usa **PostgreSQL** para garantir que você **nunca perca dados**, mesmo se reiniciar o servidor.

1.  No painel do Railway, clique em **+ New** -> **Database** -> **Add PostgreSQL**.
2.  Aguarde o banco ser criado.
3.  Clique no banco **PostgreSQL** criado -> aba **Connect**.
4.  Copie a **DATABASE_URL** (começa com `postgresql://...`).
5.  Vá no seu projeto do **Cloaker** -> aba **Variables**.
6.  Adicione uma nova variável:
    -   **Variable Name:** `DATABASE_URL`
    -   **Value:** (Cole a URL que você copiou)
7.  O Railway vai reiniciar o projeto automaticamente. Pronto! Seu banco está blindado. 🛡️

### Passo 3.3: Fazer um novo deploy

1. Vá na aba **Deployments**
2. Clique nos **três pontinhos** do último deploy
3. **Redeploy**
4. Espere terminar

A partir daí o arquivo do banco (`cloaker.db`) fica em `/data` e **não é apagado** nos próximos deploys.

---

## PARTE 4: Configurar domínio para exibir no painel (Importante)

Para que o painel mostre aos seus clientes o domínio correto para apontamento (CNAME), configure esta variável:

1. Vá no **Railway** → Projeto → **Variables**.
2. Adicione **APP_CNAME_TARGET** = `front-bypass-clo-production.up.railway.app`
3. O Railway vai reiniciar o site.
4. Agora o painel mostrará a instrução correta para quem for configurar domínios.

---

## PARTE 5: Configurar Domínio Padrão (Recomendado)

Para que os links gerados usem um domínio profissional (ex: `ghostvic.life`) em vez da URL do Railway:

1. Vá no **Railway** → Projeto → **Variables**.
2. Crie uma variável `DEFAULT_DOMAIN` com o seu domínio principal (ex: `ghostvic.life` ou `*.ghostvic.life`).
3. No seu DNS (Cloudflare/Registro.br), crie um registro **CNAME** (ou **ALIAS** se for raiz) apontando para o seu domínio Railway (`front-bypass-clo-production.up.railway.app`).
4. O painel passará a mostrar **"Padrão (ghostvic.life)"** ao criar sites e os links usarão esse domínio automaticamente.

---

## PARTE 6: Usar o painel nos seus sites

A URL do painel é a que você gerou no Passo 2.4, por exemplo:

`https://front-bypass-clo-production.up.railway.app`

### No painel (nessa URL):

1. Acesse o painel
2. Vá em **Meus Sites**
3. Clique em **Novo Site**
4. Preencha nome e domínio, salve
5. Copie o script que aparecer, algo como:

```html
<script src="https://front-bypass-clo-production.up.railway.app/t/SEU_SITE_ID.js"></script>
```

### Nos seus sites (landing pages):

1. Abra o HTML da sua página
2. Cole esse `<script>` dentro do `<head>`, por exemplo:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Minha Página</title>
  <script src="https://front-bypass-clo-production.up.railway.app/t/SEU_SITE_ID.js"></script>
</head>
<body>
  Seu conteúdo aqui
</body>
</html>
```

3. Salve e publique a página

A partir daí, os acessos serão registrados e você vê tudo no painel.

---

## ⚠️ Erros comuns e soluções

### "Application failed to respond"

- O Railway espera o app na porta que ele define em `PORT`.
- O projeto já usa `process.env.PORT` no `server.js`.
- Se ainda falhar, em **Settings** → **Variables** confira se não há variável `PORT` conflitando; se houver, apague e deixe o Railway definir.

### Deploy falha com erro de "npm install"

- Confira se no GitHub estão:
  - `server.js`
  - `package.json`
  - Pasta `public` com `index.html` e `tracker.js`
- Não inclua a pasta `node_modules` no repositório.

### Página em branco ao abrir a URL

- Use **https** na URL (não http).
- Espere 1–2 minutos após o deploy e atualize a página.
- Em **Deployments**, veja os **Logs** e confira se aparece "Servidor rodando" ou algum erro.

### Banco de dados some depois de um tempo

- Isso acontece se você **não** tiver configurado o **Volume** (Parte 3).
- Siga a Parte 3 para criar o volume em `/data` e a variável `RAILWAY_VOLUME_MOUNT_PATH=/data`, e faça um redeploy.

### Script nos sites não carrega (erro de CORS ou bloqueio)

- A URL do script deve ser **https** e igual à do painel.
- Exemplo: se o painel é `https://front-bypass-clo-production.up.railway.app`, o script deve ser `https://front-bypass-clo-production.up.railway.app/t/SEU_SITE_ID.js`.

---

## 📌 Resumo rápido

| Etapa | O que fazer |
|-------|-------------|
| 1 | Ter projeto no **GitHub** (Parte 1) |
| 2 | **Railway** → New Project → Deploy from GitHub → escolher o repositório |
| 3 | Em **Settings** → **Generate Domain** e copiar a URL |
| 4 | (Opcional) **Add Volume** com mount path `/data` e variável `RAILWAY_VOLUME_MOUNT_PATH=/data` |
| 5 | No painel (URL gerada), criar sites e copiar o script para colar no `<head>` das suas páginas |

Se seguir essa ordem, o deploy no Railway tende a funcionar sem erros. Se algo falhar, use a seção "Erros comuns" acima e os **Logs** do deploy no Railway para identificar o problema.
