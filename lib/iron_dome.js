/**
 * 🛡️ IRON DOME - Server Side Security Module
 * 
 * Responsibilities:
 * 1. Datacenter IP Blocking (Local CIDR Check)
 * 2. Honeypot Trap (Bans malicious scanners)
 * 3. Header Fingerprinting (Detects lazy bots)
 */

// const ipRangeCheck = require('ip-range-check'); // Removed dependency
// Actually, to be robust without external deps, let's implement a simple CIDR checker.

class IronDome {
    constructor(db) {
        this.db = db;

        // Lista de faixas de IP conhecidas de Datacenters (Amostra para AWS/Google/Azure)
        // Em produção real, isso deve ser carregado de um arquivo externo atualizado.
        // Aqui colocamos ranges comuns de bot/crawler.
        this.datacenterRanges = [
            '3.0.0.0/8', '18.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8', // AWS
            '104.196.0.0/14', '35.192.0.0/12', // Google Cloud
            '13.64.0.0/11', '20.0.0.0/8', // Azure
            '66.249.0.0/16', '72.14.192.0/18', // Googlebot (Official) - cuidado se quiser bloquear SEO
            '157.55.39.0/24', // Bingbot
            '40.77.167.0/24'  // Bingbot
        ];

        this.honeypotRoutes = [
            '/wp-login.php', '/wp-admin', '/.env', '/config.json',
            '/admin.php', '/bkp.zip', '/id_rsa', '/.git/HEAD'
        ];
    }

    // Helper: Verifica se IP está no Range CIDR
    ipInCidr(ip, cidr) {
        try {
            const [range, bits = 32] = cidr.split('/');
            const mask = ~(2 ** (32 - bits) - 1);

            const ip4toInt = (ip) => ip.split('.').reduce((int, oct) => (int << 8) + parseInt(oct, 10), 0) >>> 0;

            return (ip4toInt(ip) & mask) === (ip4toInt(range) & mask);
        } catch (e) { return false; } // Fail safe for IPv6 or malformed
    }

    async check(req) {
        // Express 'trust proxy' (server.js) handles this correctly for Railway/Vercel
        const ip = req.ip || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.connection.remoteAddress;
        const ua = (req.headers['user-agent'] || '').toLowerCase();
        const headers = req.headers;
        const path = req.path.toLowerCase();

        // 1. HONEYPOT TRAP (Banimento Imediato)
        if (this.honeypotRoutes.some(r => path.includes(r))) {
            await this.banIp(ip, 'Honeypot Access: ' + path);
            return { block: true, reason: 'Honeypot', status: 404 }; // Fake 404 to confuse scanner
        }

        // 2. CHECK DATABASE BAN (Persistent)
        const isBanned = await this.db.get('SELECT 1 FROM visitors WHERE ip = ? AND was_blocked = 1 AND block_reason LIKE "Honeypot%" LIMIT 1', [ip]);
        if (isBanned) return { block: true, reason: 'Previously Banned (Honeypot)', status: 403 };

        // 3. DATACENTER / ASN BLOCK (Local CIDR)
        // Só bloqueia se NÃO for um bot de busca "bom" que queremos permitir (se for cloaking Black Hat, bloqueia tudo).
        // Assumindo Black Hat total: Bloqueia tudo.
        const isDatacenter = this.datacenterRanges.some(range => this.ipInCidr(ip, range));
        if (isDatacenter) {
            return { block: true, reason: 'Datacenter IP (ASN)', status: 403 };
        }

        // 4. HEADER INTEGRITY (Anti-Script)
        // Browsers modernos mandam: sec-fetch-*, accept-language, accept-encoding
        // Bots simples (curl, python) muitas vezes não mandam.
        const isBrowser = headers['sec-fetch-mode'] || headers['sec-fetch-site'] || headers['sec-fetch-dest'];
        const hasLang = headers['accept-language'];

        // Se não tem headers básicos de browser E não é um bot conhecido (opcional, aqui estamos sendo rígidos)
        if (!isBrowser && !hasLang && !ua.includes('bot')) {
            // Pode ser um script python ou curl
            // return { block: true, reason: 'Suspicious Headers (No Sec-Fetch/Lang)', status: 403 };
            // *Comentado por segurança: alguns browsers móveis antigos podem falhar aqui. Deixar logar por enquanto.*
        }

        return { block: false };
    }

    async banIp(ip, reason) {
        try {
            // Registra o banimento. Em um sistema real, teríamos uma tabela 'banned_ips'. 
            // Por enquanto, salvamos no visitors com flag de bloqueio para reutilizar a tabela.
            await this.db.run(
                `INSERT INTO visitors (ip, was_blocked, block_reason, user_agent, created_at) VALUES (?, 1, ?, 'IronDome', CURRENT_TIMESTAMP)`,
                [ip, reason]
            );
        } catch (e) {
            console.error('IronDome Ban Error:', e);
        }
    }
    // 🛡️ TRAFFIC GUARD V4: ASN INTELLIGENCE
    isHostingProvider(isp) {
        if (!isp) return false;
        const s = isp.toLowerCase();
        const hosts = [
            'amazon', 'aws', 'google cloud', 'google llc', 'microsoft', 'azure',
            'digitalocean', 'hetzner', 'ovh', 'linode', 'vultr', 'alibaba',
            'oracle', 'facebook', 'tiktok', 'bytedance', 'tencent', 'fastly',
            'cloudflare', 'akamai', 'cdn77', 'datacenter', 'hosting', 'server',
            'm247', 'leaseweb', 'softlayer', 'choopa', 'colocrossing'
        ];
        return hosts.some(h => s.includes(h));
    }
}

module.exports = IronDome;
