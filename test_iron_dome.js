/**
 * 🧪 IRON DOME UNIT TESTS
 * 
 * Verifies the security logic without needing a live server.
 */

const IronDome = require('./lib/iron_dome');

// 🎭 Mock DB
const mockDb = {
    get: async (sql, params) => {
        // Simula check de banimento prévio
        // Se IP for 'banned_ip', retorna true
        if (params && params[0] === '1.2.3.4') return { 1: 1 };
        return null;
    },
    run: async (sql, params) => {
        console.log(`[MockDB] Executed: ${sql} | Params: ${JSON.stringify(params)}`);
        return true;
    }
};

const ironDome = new IronDome(mockDb);

async function runTests() {
    console.log('🛡️  STARTING IRON DOME SECURITY TESTS 🛡️\n');
    let passed = 0;
    let failed = 0;

    async function test(name, req, expectedBlock) {
        try {
            const result = await ironDome.check(req);
            const isBlocked = result.block;

            if (isBlocked === expectedBlock) {
                console.log(`✅ [PASS] ${name}`);
                passed++;
            } else {
                console.error(`❌ [FAIL] ${name} - Expected block: ${expectedBlock}, Got: ${isBlocked} (${result.reason})`);
                failed++;
            }
        } catch (e) {
            console.error(`❌ [ERROR] ${name}`, e);
            failed++;
        }
    }

    // TEST 1: Normal User (Vivo IP, Good Headers)
    await test('Normal User (Vivo IP)', {
        ip: '177.1.2.3',
        path: '/',
        headers: {
            'x-forwarded-for': '177.1.2.3', // Vivo CIDR example (not in blocklist)
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)',
            'sec-fetch-mode': 'navigate',
            'accept-language': 'pt-BR'
        },
        connection: { remoteAddress: '177.1.2.3' }
    }, false);

    // TEST 2: AWS Datacenter IP (Should be Blocked)
    // 3.0.0.0/8 is AWS
    await test('AWS Datacenter IP (3.5.5.5)', {
        ip: '3.5.5.5',
        path: '/',
        headers: {
            'x-forwarded-for': '3.5.5.5',
            'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1)' // Fake Googlebot coming from AWS
        },
        connection: { remoteAddress: '3.5.5.5' }
    }, true);

    // TEST 3: Google IP (Should be Blocked as "Datacenter" if strict)
    // 35.192.0.1 is Google Cloud
    await test('Google Cloud IP (35.192.0.1)', {
        ip: '35.192.0.1',
        path: '/',
        headers: {
            'x-forwarded-for': '35.192.0.1',
            'user-agent': 'Standard Browser'
        },
        connection: { remoteAddress: '35.192.0.1' }
    }, true);

    // TEST 4: Honeypot Access (Attempting to find WP Login)
    await test('Honeypot Access (/wp-login.php)', {
        ip: '100.100.100.100',
        path: '/wp-login.php',
        headers: {
            'x-forwarded-for': '100.100.100.100',
            'user-agent': 'BotScanner/1.0'
        },
        connection: { remoteAddress: '100.100.100.100' }
    }, true);

    // TEST 5: Suspicious Script (No Headers)
    // Note: IronDome strict check was commented out in code, so this should PASS for now unless uncommented.
    // We expect FALSE based on current code.
    await test('Script w/o Headers (Curl)', {
        ip: '200.200.200.200',
        path: '/',
        headers: {
            'x-forwarded-for': '200.200.200.200',
            'user-agent': 'curl/7.64.1'
        },
        connection: { remoteAddress: '200.200.200.200' }
    }, false);

    console.log(`\n📊 SUMMARY: ${passed} Passed, ${failed} Failed`);
}

runTests();
