# Como associar seu domínio ao Cloaker (por usuário)

Cada usuário cadastrado pode configurar **seu próprio domínio** no painel. Assim, os links gerados em "Meus Sites" e "Link para Ads" usam o domínio da sua conta, e não o domínio padrão do painel.

---

## Onde cadastrar o domínio

- **No painel do site (Domínios):** você cadastra o domínio e vê as **instruções** (CNAME e valor) para configurar no provedor do domínio.
- **No Railway:** o tráfego do domínio precisa estar associado ao seu serviço. Você pode:
  - **Automático (recomendado):** configurar no painel as variáveis **Railway** (veja abaixo). Quando um **admin** adiciona um domínio na seção Domínios, o app tenta **registrar esse domínio também no Railway** pela API. Assim você faz tudo pelo painel, sem abrir o Railway.
  - **Manual:** em **Railway** → **Networking** → **+ Custom Domain**, adicione cada domínio uma vez.

### Fazer tudo pelo painel (adicionar domínio no Railway ao cadastrar)

1. No **Railway** → [Account / Tokens](https://railway.com/account/tokens) → crie um **Account token** (ou Workspace token do workspace do projeto).
2. No projeto Railway → seu **serviço** → **Settings** → anote o **Service ID** (ou use **Cmd/Ctrl+K** no dashboard e “Copy Service ID”).
3. No **Railway** → serviço → **Variables** → adicione:
   - `RAILWAY_API_TOKEN` = o token do passo 1  
   - `RAILWAY_SERVICE_ID` = o ID do serviço do passo 2  
4. Faça **Redeploy** do serviço.
5. No **painel do site**, entre como **admin** e em **Domínios** cadastre o domínio (ex: `iniiciopropo.sbs`). O app salva no painel e tenta registrar no Railway; se der certo, o domínio já fica disponível no Railway e você só precisa configurar o CNAME no seu provedor conforme as instruções que aparecem no painel.

Se a sincronização com o Railway falhar (ex.: token inválido ou API alterada), o domínio continua salvo no painel e você pode adicioná-lo manualmente em Railway → Networking → + Custom Domain.

---

## Como integrar um novo domínio (4 passos)

| Passo | O que fazer |
|-------|-------------|
| **1** | No **DNS** do seu domínio (onde você gerencia os registros), crie um registro **CNAME**: **Nome** = subdomínio (ex: `cloaker`) → **Destino** = endereço do servidor do painel (ex: `seu-app.up.railway.app`). |
| **2** | Aguarde a propagação do DNS (alguns minutos até 48h). Teste com `nslookup cloaker.seudominio.com`. |
| **3** | No painel do Cloaker, faça login e vá em **Configurações** → **Meu domínio do Cloaker**. |
| **4** | No campo **URL base do seu Cloaker**, digite a URL completa (ex: `https://cloaker.seudominio.com`) **sem barra no final** e clique em **Salvar**. |

Pronto. A partir daí, todos os links que você gerar (em Meus Sites e Link para Ads) usarão esse domínio. **Cada usuário** configura o domínio **da própria conta**; o que você salva vale só para você.

---

## Resumo

1. Você tem um domínio (ex: `minhaempresa.com`).
2. No DNS desse domínio, você cria um **CNAME** apontando para o servidor do painel (ex: Railway).
3. No painel, em **Configurações** → **Meu domínio do Cloaker**, você informa a URL completa (ex: `https://cloaker.minhaempresa.com`) e salva.
4. Todos os links gerados na sua conta passam a usar esse domínio.

---

## Passo a passo detalhado

### 1. Ter um domínio e decidir o subdomínio

- Você precisa de um domínio registrado (ex: Registro.br, GoDaddy, Cloudflare, etc.).
- Decida qual endereço vai usar para o cloaker. O mais comum é um **subdomínio**, por exemplo:
  - `cloaker.minhaempresa.com`
  - `go.minhaempresa.com`
  - `links.minhaempresa.com`

### 2. Descobrir o endereço do servidor do painel

- O painel está hospedado em um servidor (ex: **Railway**).
- A URL do painel é algo como: `https://cloaktest-production.up.railway.app` (ou o nome do seu projeto no Railway).
- O **host** que você vai usar no DNS é a parte sem `https://`, por exemplo:
  - `cloaktest-production.up.railway.app`

Guarde esse host; você vai usá-lo no próximo passo.

### 3. Configurar o DNS (CNAME)

Acesse o painel do **provedor de DNS** do seu domínio (onde você gerencia os registros DNS).

1. Encontre a opção para **adicionar registro** (Add record, Novo registro, etc.).
2. Escolha o tipo **CNAME**.
3. Preencha:
   - **Nome / Host / Subdomínio:**  
     O que vem antes do seu domínio.  
     - Para `cloaker.minhaempresa.com` → use `cloaker`.  
     - Para `go.minhaempresa.com` → use `go`.  
     - Em alguns painéis você digita só o nome; em outros, o sistema já adiciona o domínio.
   - **Valor / Destino / Target / Aponta para:**  
     O host do servidor do painel, por exemplo:  
     `cloaktest-production.up.railway.app`  
     (sem `https://` e sem barra no final).
4. Salve o registro.

**Exemplo (Cloudflare):**

- Type: `CNAME`
- Name: `cloaker` (ou `go`, etc.)
- Target: `cloaktest-production.up.railway.app`
- Proxy status: pode deixar ativado (laranja) se quiser usar o SSL do Cloudflare.

**Exemplo (Registro.br / painel genérico):**

- Tipo: CNAME
- Nome: `cloaker`
- Valor/Destino: `cloaktest-production.up.railway.app`

### 4. Aguardar a propagação do DNS

- A alteração pode levar de **alguns minutos** a **até 48 horas**.
- Para testar no computador:
  - Windows (Prompt de Comando): `nslookup cloaker.seudominio.com`
  - Linux/Mac: `dig cloaker.seudominio.com` ou `nslookup cloaker.seudominio.com`
- Quando o resultado apontar para o servidor do Railway (ou para o IP que o Railway indicar), está propagado.

### 5. Usar HTTPS

- O ideal é acessar o cloaker sempre por **HTTPS** (ex: `https://cloaker.minhaempresa.com`).
- Se usar **Cloudflare**, ative o proxy (ícone laranja) e escolha SSL “Flexible” ou “Full” conforme a documentação deles.
- Em outros provedores, use o SSL que eles oferecem para o domínio/subdomínio.

### 6. Configurar no painel do Cloaker

1. Faça login no painel.
2. No menu, vá em **Configurações**.
3. No campo **URL base do seu Cloaker**, coloque a URL completa do domínio que você configurou no DNS, por exemplo:
   - `https://cloaker.minhaempresa.com`
   - Ou `https://go.minhaempresa.com`
4. Não coloque barra no final.
5. Clique em **Salvar**.

A partir daí, todos os links gerados na **sua conta** (em Meus Sites e Link para Ads) usarão esse domínio.

---

## Exemplo completo

| Item | Exemplo |
|------|--------|
| Seu domínio | `minhaempresa.com` |
| Subdomínio escolhido | `cloaker` |
| URL final do cloaker | `https://cloaker.minhaempresa.com` |
| Servidor do painel (Railway) | `cloaktest-production.up.railway.app` |
| Registro CNAME | Nome: `cloaker` → Destino: `cloaktest-production.up.railway.app` |
| No painel (Configurações) | Campo preenchido: `https://cloaker.minhaempresa.com` |
| Link gerado para um site | `https://cloaker.minhaempresa.com/go/abc12xyz` |

---

## Domínio por usuário

- **Cada usuário** tem seu próprio domínio nas Configurações.
- O que você salva em **Configurações** vale só para **sua conta**.
- Outros usuários podem configurar domínios diferentes nas contas deles.
- Assim, cada um usa seu próprio domínio nos links que gera.

---

## Problemas comuns

- **“Não carrega” ou “não abre” depois de configurar**  
  - Confirme se o CNAME está correto e se a propagação já ocorreu (`nslookup` ou `dig`).  
  - Confira se no painel você colocou a URL com `https://` e sem barra no final.

- **Erro de SSL / certificado**  
  - No Railway, o certificado costuma ser para `*.up.railway.app`. Para usar seu domínio próprio, pode ser necessário configurar “Custom Domain” no projeto do Railway e, em alguns casos, usar um proxy (ex: Cloudflare) na frente.

- **Domínio raiz (ex: minhaempresa.com)**  
  - Alguns DNS não permitem CNAME no domínio raiz. Nesse caso use um subdomínio (ex: `cloaker.minhaempresa.com`) ou consulte a documentação do seu provedor para uso de A/ALIAS.

---

Para mais detalhes, use no painel a seção **Configurações** → **Como associar meu domínio (passo a passo)**.
