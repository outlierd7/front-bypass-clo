/**
 * Migração: backup JSON (exportado do painel) → PostgreSQL (Supabase).
 * Uso: DATABASE_URL="postgresql://..." node scripts/migrate-json-to-pg.js backup.json
 * O backup é o JSON baixado em Admin → Configurações → Download backup (JSON).
 */

const fs = require('fs');
const path = require('path');

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('Defina DATABASE_URL (connection string do Supabase).');
  process.exit(1);
}

const file = process.argv[2];
if (!file || !fs.existsSync(file)) {
  console.error('Uso: DATABASE_URL="postgresql://..." node scripts/migrate-json-to-pg.js <arquivo-backup.json>');
  process.exit(1);
}

let data;
try {
  data = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (e) {
  console.error('Erro ao ler JSON:', e.message);
  process.exit(1);
}

process.env.DATABASE_URL = DATABASE_URL;
const db = require('../db');

async function run() {
  await db.initDb();
  const order = ['users', 'settings', 'sites', 'visitors', 'allowed_domains'];
  for (const table of order) {
    const rows = data[table];
    if (!Array.isArray(rows) || rows.length === 0) {
      console.log(`  ${table}: 0 registros`);
      continue;
    }
    const cols = Object.keys(rows[0]).filter(k => !/^undefined$/i.test(String(rows[0][k])));
    const conflict = table === 'settings' ? '(key)' : '(id)';
    const placeholders = cols.map(() => '?').join(', ');
    const colList = cols.join(', ');
    let n = 0;
    for (const row of rows) {
      const params = cols.map(c => row[c]);
      try {
        await db.run(
          `INSERT INTO ${table} (${colList}) VALUES (${placeholders}) ON CONFLICT ${conflict} DO NOTHING`,
          params
        );
      } catch (err) {
        if (err.code === '23505') continue;
        throw err;
      }
      n++;
    }
    console.log(`  ${table}: ${n} registros`);
  }
  console.log('Migração concluída.');
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
