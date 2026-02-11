# 🔒 Cloaker Pro - Sistema de Proteção Multi-Sites

Sistema completo de cloaking com painel de controle para monitorar **múltiplos sites** em uma única instalação.

## ✨ Funcionalidades

- 📊 **Dashboard** com estatísticas em tempo real
- 🌐 **Multi-Sites** - Gerencie quantos sites quiser
- 👥 **50+ dados** coletados de cada visitante
- 🛡️ **Proteção** contra desktops, bots, DevTools
- 📈 **Gráficos** de visitas, países, navegadores
- 📥 **Exportação** de dados (JSON/CSV)
- ⚙️ **Configurações** individuais por site

## 🚀 Instalação

```bash
# 1. Entre na pasta
cd "cloaker teste"

# 2. Instale as dependências (já feito!)
npm install

# 3. Inicie o servidor
npm start
```

Acesse: **http://localhost:3000**

## 📱 Como Usar em Múltiplos Sites

### Passo 1: Criar um Site no Painel
1. Acesse o painel em `http://localhost:3000`
2. Clique em **"Meus Sites"**
3. Clique em **"Novo Site"**
4. Preencha o nome e domínio
5. Configure as regras de bloqueio
6. Salve

### Passo 2: Copiar o Script
Cada site terá um script único, por exemplo:
```html
<script src="https://SEU-SERVIDOR.com/t/site_abc123.js"></script>
```

### Passo 3: Colar na Landing Page
Cole o script no `<head>` de cada landing page:
```html
<!DOCTYPE html>
<html>
<head>
  <script src="https://SEU-SERVIDOR.com/t/site_abc123.js"></script>
</head>
<body>
  <!-- Seu conteúdo -->
</body>
</html>
```

## 🔄 Fluxo de Funcionamento

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Seu Site A    │     │   Seu Site B    │     │   Seu Site C    │
│  (landing page) │     │  (landing page) │     │  (landing page) │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │    Cada site tem      │                       │
         │    seu próprio ID     │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Servidor Cloaker     │
                    │   (único servidor)     │
                    └────────────┬───────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Painel de Controle   │
                    │  (monitora todos)      │
                    └────────────────────────┘
```

## ☁️ Deploy em Hospedagem

Este projeto está configurado para rodar em:

### Opção 1: Vercel (Gratuito)
- Requer banco de dados externo (PostgreSQL).
- **[Ver Guia de Deploy no Vercel](./DEPLOY_VERCEL.md)**

### Opção 2: Railway (Recomendado)
- Pode usar banco interno (SQLite) ou externo (Postgres).
- **[Ver Guia de Deploy no Railway](./NOVO-REPO-E-RAILWAY.md)**

### Opção 3: VPS
- Requer Node.js e PM2.
```bash
npm install
npm install -g pm2
pm2 start server.js --name cloaker
pm2 save
```

## 📁 Arquivos do Projeto

```
cloaker teste/
├── server.js          # Servidor principal
├── package.json       # Dependências
├── cloaker.db         # Banco de dados (criado automaticamente)
├── README.md          # Este arquivo
└── public/
    ├── index.html     # Painel de controle
    └── tracker.js     # Script de proteção
```

## ⚠️ Avisos Importantes

1. Este sistema é apenas para fins educacionais
2. Cloaking pode violar termos de serviço de plataformas de anúncios
3. Use com responsabilidade

## 📞 Problemas Comuns

**Erro de porta em uso:**
```bash
# Mude a porta no server.js ou use:
PORT=3001 npm start
```

**Banco de dados corrompido:**
```bash
# Delete o arquivo e reinicie:
del cloaker.db
npm start
```

---

**Pronto para usar!** 🚀
