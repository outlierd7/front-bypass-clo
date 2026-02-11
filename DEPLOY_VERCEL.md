# Guia de Deploy no Vercel

Este projeto foi configurado para rodar no **Vercel** (hospedagem gratuita e rápida).

Como o Vercel utiliza funções serverless (o servidor "dorme" quando não tem acesso), você **obrigatoriamente** precisa de um banco de dados externo (PostgreSQL), pois arquivos locais (como o banco SQLite) são apagados quando o servidor dorme.

---

## 1. Preparar o Banco de Dados (PostgreSQL)

Você precisa de uma URL de conexão Postgres (`DATABASE_URL`).
Recomendo criar um banco gratuito no **Neon.tech** ou **Supabase**.

1.  Crie uma conta no [Neon.tech](https://neon.tech/) (ou Supabase).
2.  Crie um novo projeto.
3.  Copie a **Connection String** (algo como `postgresql://usuario:senha@ep-xyz.us-east-2.aws.neon.tech/neondb?sslmode=require`).

---

## 2. Enviar código para o GitHub

Certifique-se de que este código está no seu GitHub (no repositório novo que você criou).

```bash
git add .
git commit -m "Configuração para Vercel"
git push origin main
```

---

## 3. Criar projeto no Vercel

1.  Acesse [vercel.com](https://vercel.com) e faça login com seu GitHub.
2.  Clique em **Add New...** -> **Project**.
3.  Selecione o repositório `cloaker-pro-novo` e clique em **Import**.
4.  Em **Environment Variables**, adicione as seguintes variáveis:

    | Nome | Valor | Descrição |
    | :--- | :--- | :--- |
    | `DATABASE_URL` | `postgresql://...` | A URL do seu banco Postgres (passo 1). |
    | `SESSION_SECRET` | `uma-senha-secreta-longa` | Senha para criptografar sessões. |
    | `NODE_ENV` | `production` | Define modo de produção. |
    | `PANEL_DOMAIN` | `exemplo.com` | (Opcional) Se quiser restringir o painel a um domínio. |

5.  Clique em **Deploy**.

---

## 4. Configurar Domínio Personalizado

Após o deploy:
1.  Vá em **Settings** -> **Domains** no seu projeto na Vercel.
2.  Adicione seu domínio (ex: `seusite.com`).
3.  Configure os registros DNS (CNAME ou A) no seu provedor de domínio conforme a Vercel instruir.

---

## 📝 Observações Importantes sobre Vercel

-   **Backups Automáticos**: O sistema de backup automático a cada 6 horas (que existia no `server.js`) **NÃO FUNCIONA** no Vercel, pois o servidor não fica rodando o tempo todo. Você deve fazer backups manuais pelo botão "Backup" no painel.
-   **Arquivos**: Não salve arquivos (como uploads) na pasta do projeto, eles serão perdidos. O banco de dados externo persistirá seus dados (usuários, cliques, sites) seguramente.

## 5. Limites e Escala (Importante para Alto Volume)

Se você vai ter **muito tráfego**, fique atento aos planos gratuitos:

### Vercel (Plano Hobby - Grátis)
-   **Análise:** Ótimo para começar.
-   **Limite:** 100GB de banda e 100GB-horas de execução de função por mês.
-   **Se estourar:** O site pode sair do ar ou ficar lento. O plano Pro começa em $20/mês.

### Neon (Plano Free)
-   **Armazenamento:** 0.5 GB (cabe milhares de registros de texto/cliques).
-   **Limite:** O banco "dorme" após inatividade (pode demorar uns 3s para acordar no primeiro acesso).
-   **Se estourar:** O plano Pro começa em $19/mês e escala automaticamente.

**Recomendação:** Comece no grátis. Se o negócio escalar e você começar a lucrar, o custo dos planos pagos ($20 + $19) será pequeno perto do faturamento.
