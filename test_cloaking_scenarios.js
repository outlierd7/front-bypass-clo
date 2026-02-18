/**
 * ⚔️ GHOST VIC - COMBAT SIMULATION ("Battle Tested")
 * 
 * Simula cenários reais de tráfego para validar a "TrafficGuard V4".
 * Testa: Redirecionamento, Bloqueio de Bots, Preservação de Parâmetros e Detecção de ASN.
 */

const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');

// Configurar ambiente de teste ISOLADO (evita travar o banco de produção)
const TEST_DIR = path.join(__dirname, 'test_data');
if (!fs.existsSync(TEST_DIR)) fs.mkdirSync(TEST_DIR);
process.env.RAILWAY_VOLUME_MOUNT_PATH = TEST_DIR;

const db = require('./db');

const PORT = 3002;
const BASE_URL = `http://localhost:${PORT}`;
const TEST_CODE = 'combat-test';
const TARGET_URL = 'https://money-page.com/offer';
const SAFE_PAGE = 'https://safe-page.com/article';

// Configuração do Teste
const scenarios = [
    {
        name: '📱 Usuário Real (Mobile + Facebook)',
        description: 'iPhone 13 vindo do Facebook App. Deve ser aprovado.',
        headers: {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBDV/iPhone13,2;FBMD/iPhone;FBSN/iOS;FBSV/16.0;FBSS/3;]',
            'Referer': 'https://l.facebook.com/',
            'X-Forwarded-For': '177.1.2.3', // IP Residencial (Vivo)
            'Sec-Fetch-Mode': 'navigate',
            'Accept-Language': 'pt-BR,pt;q=0.9'
        },
        expectBlock: false
    },
    {
        name: '🤖 Bot do Facebook (Crawler)',
        description: 'Crawler oficial do FB. Deve ser bloqueado ou ver Safe Page.',
        headers: {
            'User-Agent': 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
            'X-Forwarded-For': '69.63.176.13', // IP Facebook
        },
        expectBlock: true // Server deve mandar para safe page
    },
    {
        name: '🖥️ Espião Desktop (Direct)',
        description: 'Usuário Windows acessando direto sem referer. Deve ser bloqueado.',
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
            'X-Forwarded-For': '189.1.2.3',
        },
        expectBlock: true // Rule: Block Desktop = true
    },
    {
        name: '🏢 Hosting IP (AWS) - ASN Check',
        description: 'Bot tentando se passar por Chrome user, mas vindo da AWS.',
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
            'X-Forwarded-For': '3.5.5.5', // Range AWS
        },
        expectBlock: true // ASN Intelligence deve pegar
    }
];

// Utilitário de Request
function request(path, headers) {
    return new Promise((resolve, reject) => {
        const opts = {
            method: 'GET',
            headers: headers
        };
        const req = http.request(`${BASE_URL}${path}`, opts, (res) => {
            resolve({ status: res.statusCode, location: res.headers.location });
        });
        req.on('error', reject);
        req.end();
    });
}

// Setup do Ambiente
async function setup() {
    const log = (msg) => fs.appendFileSync('test_debug.log', msg + '\n');
    log('🚧 Inicializando Base de Dados de Teste...');

    try {
        await db.initDb();

        // 0. Garantir usuário ID 1
        const user = await db.get('SELECT id FROM users WHERE id = 1');
        if (!user) {
            await db.run("INSERT INTO users (id, username, password_hash, role, status) VALUES (1, 'tester', 'hash', 'admin', 'active')");
            log('✅ Usuário de teste criado (ID 1)');
        }

        // Inserir campanha de teste
        const siteId = 'site_' + Math.floor(Math.random() * 100000);

        // Limpar anterior
        await db.run('DELETE FROM sites WHERE link_code = ?', [TEST_CODE]);

        await db.run(`INSERT INTO sites 
            (site_id, user_id, link_code, target_url, redirect_url, name, block_bots, block_desktop, block_behavior, created_at, is_active) 
            VALUES (?, 1, ?, ?, ?, 'Combat Test', 1, 1, 'redirect', datetime('now'), 1)`,
            [siteId, TEST_CODE, TARGET_URL, SAFE_PAGE]);

        log('✅ Campanha de teste criada: /go/' + TEST_CODE + ' (SiteID: ' + siteId + ')');
    } catch (e) {
        log('❌ ERRO NO SETUP: ' + e.message);
        console.error(e);
        process.exit(1);
    }
}

// Execução
async function run() {
    // 1. Start Server
    console.log('🚀 Iniciando Servidor de Teste na porta ' + PORT + '...');
    const env = Object.assign({}, process.env, { PORT: PORT, NODE_ENV: 'test' });
    const serverProcess = spawn('node', ['server.js'], { env });

    serverProcess.stdout.on('data', (d) => {
        fs.appendFileSync('test_debug.log', `[SERVER] ${d}`);
        if (d.toString().includes('Servidor rodando')) {
            // Server ready
            startTests(serverProcess);
        }
    });

    serverProcess.stderr.on('data', (d) => {
        fs.appendFileSync('test_debug.log', `[SERVER ERROR] ${d}`);
    });

    // Fallback timeout
    setTimeout(() => startTests(serverProcess), 3000);
}

async function startTests(serverProcess) {
    console.log('\n🦅 INICIANDO SIMULAÇÃO DE COMBATE...\n');
    let passed = 0;
    let failed = 0;

    for (const s of scenarios) {
        console.log(`🔹 Testando: ${s.name}`);
        try {
            const res = await request(`/go/${TEST_CODE}`, s.headers);

            // Lógica de "Block" no servidor geralmente é Redirect 302 para Safe Page
            // Lógica de "Allow" é Redirect 302 para Target URL

            const isBlocked = res.location && res.location.includes(SAFE_PAGE);
            const isAllowed = res.location && res.location.includes(TARGET_URL);

            if (s.expectBlock) {
                if (isBlocked) {
                    console.log(`   ✅ SUCESSO! Bloqueado como esperado -> Safe Page`);
                    passed++;
                } else if (isAllowed) {
                    console.log(`   ❌ FALHA! Deveria ser bloqueado, mas foi para Money Page.`);
                    failed++;
                } else {
                    console.log(`   ⚠️  Resultado Incerto: ${res.statusCode} -> ${res.location}`);
                    // Se for 404 ou outro status, pode ser falha
                    if (res.status === 403 || res.status === 404) passed++; // Accept block codes
                    else failed++;
                }
            } else {
                if (isAllowed) {
                    console.log(`   ✅ SUCESSO! Acesso Permitido -> Money Page`);
                    passed++;
                } else {
                    console.log(`   ❌ FALHA! Usuário legítimo foi bloqueado -> ${res.location || res.status}`);
                    failed++;
                }
            }
        } catch (e) {
            console.log(`   ❌ ERRO DE CONEXÃO: ${e.message}`);
            failed++;
        }
        console.log('------------------------------------------------');
    }

    // TESTE DE PARÂMETROS
    console.log(`🔹 Testando: Preservação de UTMs (O Dinheiro)`);
    try {
        const params = '?utm_source=fb&utm_medium=cpc&fbclid=IwAR123';
        const headers = {
            'User-Agent': scenarios[0].headers['User-Agent'], // Mobile Real
            'X-Forwarded-For': '177.1.2.3'
        };
        const res = await request(`/go/${TEST_CODE}${params}`, headers);

        if (res.location && res.location.includes(TARGET_URL)) {
            if (res.location.includes('utm_source=fb') && res.location.includes('fbclid=IwAR123')) {
                console.log(`   ✅ SUCESSO! Parâmetros preservados: ${res.location}`);
                passed++;
            } else {
                console.log(`   ❌ FALHA! Parâmetros perdidos: ${res.location}`);
                failed++;
            }
        } else {
            console.log(`   ❌ FALHA! Redirecionamento incorreto: ${res.location}`);
            failed++;
        }
    } catch (e) {
        console.log(`   ❌ ERRO: ${e.message}`);
        failed++;
    }

    console.log(`\n📊 RELATÓRIO FINAL: ${passed} Aprovados, ${failed} Falhas`);

    // Cleanup
    serverProcess.kill();
    process.exit(failed > 0 ? 1 : 0);
}

setup().then(run).catch(e => {
    console.error(e);
    process.exit(1);
});
