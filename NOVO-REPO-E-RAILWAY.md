# Repositório novo (isolado) e deploy no Railway

Este clone **não está mais ligado** ao repositório em produção. O remote do repo antigo foi renomeado para `antigo` — assim nada é enviado para o que já está rodando.

---

## 1. Criar o repositório novo no GitHub

1. Acesse **https://github.com/new**
2. **Repository name:** por exemplo `cloaker-pro-novo` ou `cloaker-pro-v2`
3. Deixe **Public**
4. **Não** marque "Add a README file", "Add .gitignore" nem "Choose a license" (repositório vazio)
5. Clique em **Create repository**
6. Copie a URL do repositório, algo como:  
   `https://github.com/MRGC2024/cloaker-pro-novo.git`

---

## 2. Conectar este projeto ao repositório novo e enviar o código

No PowerShell, na pasta do projeto, rode (troque pela **sua** URL do passo 1):

```powershell
cd "c:\Users\drrod\Downloads\blokbot v2"

git remote add origin https://github.com/SEU-USUARIO/NOME-DO-REPO-NOVO.git

git push -u origin main
```

Se pedir autenticação: use seu usuário do GitHub e um **Personal Access Token** (não a senha).  
Token: GitHub → Settings → Developer settings → Personal access tokens → Generate new token (classic) → marque **repo** → Generate.

---

## 3. Deploy no Railway (novo projeto)

1. Acesse **https://railway.com** e faça login com GitHub.
2. **New Project** → **Deploy from GitHub repo**.
3. Selecione o **repositório novo** (ex.: `cloaker-pro-novo`), não o `cloaktest`.
4. Aguarde o deploy. Em **Settings** do serviço → **Networking** → **Generate Domain** para obter a URL.
5. (Recomendado) Em **Settings** → **Volumes** → **Add Volume** com mount path `/data` e variável `RAILWAY_VOLUME_MOUNT_PATH` = `/data` para persistir o banco.

---

## Resumo

| Remote   | Repositório              | Uso                          |
|----------|--------------------------|------------------------------|
| `antigo` | MRGC2024/cloaktest       | Produção atual — **não usar** |
| `origin` | Seu repo novo (após add) | Desenvolvimento e Railway novo |

Depois de rodar `git remote add origin ...` e `git push -u origin main`, o código deste clone estará só no repo novo e você pode conectar um **novo** projeto no Railway a esse repo, sem mexer no que já está rodando.

---

## Recuperar acesso (conta “aguardando aprovação”)

Se você criou a conta por **“Solicitar acesso”** em vez de **“Criar administrador”**, ficou como usuário pendente e não há admin para aprovar. Use a **rota de recuperação**:

1. No **Railway** → seu projeto → **Variables** → adicione:
   - Nome: `SETUP_RECOVERY_TOKEN`
   - Valor: uma senha secreta (ex.: `minha-senha-recuperacao-123`)
2. Faça **Redeploy** do serviço (para carregar a variável e o código novo).
3. No navegador, abra (troque o token pelo mesmo valor):
   ```
   https://SEU-APP.up.railway.app/api/setup/promote-first-admin?token=minha-senha-recuperacao-123
   ```
4. Se der certo, aparecerá uma mensagem de sucesso. A partir daí faça **login** com o usuário e senha que você criou.
5. (Opcional) Depois de entrar, remova ou altere a variável `SETUP_RECOVERY_TOKEN` no Railway para evitar uso indevido.

---

## Backup do banco (não perder dados)

- **No painel:** Admin → Configurações → card **Backup do banco**. Use **Download backup (JSON)** para baixar uma cópia dos dados.
- **Envio automático:** No Railway, em **Variables**, adicione `BACKUP_WEBHOOK_URL` = URL de um endpoint que aceite POST com JSON (ex: um webhook do Pipedream, Zapier ou um servidor seu). O sistema envia um backup a cada 6 horas.
- **Destino CNAME:** Para os links usarem seu domínio, em **Variables** você pode definir `APP_CNAME_TARGET` = o host do seu app (ex: `seu-app.up.railway.app`). Assim a seção Domínios mostra para onde apontar o CNAME no DNS.
