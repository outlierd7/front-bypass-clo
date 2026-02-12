const fs = require('fs');
const initSqlJs = require('sql.js');
const path = require('path');

async function check() {
    const SQL = await initSqlJs();
    const dbPath = path.join(__dirname, 'cloaker.db');
    if (!fs.existsSync(dbPath)) {
        console.log('Database file not found');
        return;
    }
    const buffer = fs.readFileSync(dbPath);
    const db = new SQL.Database(buffer);
    const res = db.exec("SELECT sql FROM sqlite_master WHERE type='table' AND name='sites'");
    if (res.length > 0) {
        console.log(res[0].values[0][0]);
    } else {
        console.log('Table sites not found');
    }
}

check();
