const express = require('express');
const initSqlJs = require('sql.js');
const cors = require('cors');
const UAParser = require('ua-parser-js');
const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'cloaker-pro-secret-change-in-production';
const isProduction = process.env.NODE_ENV === 'production';
// Railway: atrás de proxy HTTPS – precisa confiar no proxy para cookie e sessão
if (isProduction) app.set('trust proxy', 1);
// Railway: usa volume para persistir o banco; local: usa a pasta do projeto
const DB_PATH = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'cloaker.db')
  : path.join(__dirname, 'cloaker.db');

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'cloaker.sid',
  cookie: {
    secure: isProduction,
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));
app.use(express.static('public'));

let db;

// Helper para queries
function run(sql, params = []) {
  try {
    db.run(sql, params);
    saveDb();
    return true;
  } catch (e) {
    console.error('SQL Error:', e.message);
    return false;
  }
}

function get(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row;
    }
    stmt.free();
    return null;
  } catch (e) {
    console.error('SQL Error:', e.message);
    return null;
  }
}

function all(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    if (params.length > 0) stmt.bind(params);
    const results = [];
    while (stmt.step()) {
      results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
  } catch (e) {
    console.error('SQL Error:', e.message);
    return [];
  }
}

function saveDb() {
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  } catch (e) {
    console.error('Save DB Error:', e.message);
  }
}

// Inicializar banco de dados
async function initDb() {
  const SQL = await initSqlJs();
  
  // Carregar banco existente ou criar novo
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  // Criar tabelas
  db.run(`
    CREATE TABLE IF NOT EXISTS sites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT UNIQUE,
      link_code TEXT UNIQUE,
      user_id INTEGER,
      name TEXT,
      domain TEXT,
      target_url TEXT,
      redirect_url TEXT DEFAULT 'https://www.google.com/',
      block_desktop INTEGER DEFAULT 1,
      block_facebook_library INTEGER DEFAULT 1,
      block_bots INTEGER DEFAULT 1,
      block_vpn INTEGER DEFAULT 0,
      block_devtools INTEGER DEFAULT 1,
      allowed_countries TEXT DEFAULT 'BR',
      blocked_countries TEXT DEFAULT '',
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  try { db.run('ALTER TABLE sites ADD COLUMN link_code TEXT'); } catch (e) {}
  try { db.run('ALTER TABLE sites ADD COLUMN target_url TEXT'); } catch (e) {}
  try { db.run('ALTER TABLE sites ADD COLUMN user_id INTEGER'); } catch (e) {}
  // Atribuir sites existentes ao primeiro admin (para migração)
  const firstAdmin = get('SELECT id FROM users WHERE role = ? ORDER BY id ASC LIMIT 1', ['admin']);
  if (firstAdmin) {
    run('UPDATE sites SET user_id = ? WHERE user_id IS NULL', [firstAdmin.id]);
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS visitors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT,
      visitor_id TEXT,
      ip TEXT,
      country TEXT,
      city TEXT,
      region TEXT,
      isp TEXT,
      timezone TEXT,
      user_agent TEXT,
      browser TEXT,
      browser_version TEXT,
      os TEXT,
      os_version TEXT,
      device_type TEXT,
      device_vendor TEXT,
      device_model TEXT,
      screen_width INTEGER,
      screen_height INTEGER,
      viewport_width INTEGER,
      viewport_height INTEGER,
      color_depth INTEGER,
      pixel_ratio REAL,
      language TEXT,
      languages TEXT,
      platform TEXT,
      cookies_enabled INTEGER,
      do_not_track INTEGER,
      online INTEGER,
      touch_support INTEGER,
      max_touch_points INTEGER,
      hardware_concurrency INTEGER,
      device_memory REAL,
      connection_type TEXT,
      connection_speed TEXT,
      referrer TEXT,
      page_url TEXT,
      page_title TEXT,
      utm_source TEXT,
      utm_medium TEXT,
      utm_campaign TEXT,
      utm_term TEXT,
      utm_content TEXT,
      facebook_params TEXT,
      is_bot INTEGER,
      bot_reason TEXT,
      was_blocked INTEGER,
      block_reason TEXT,
      webgl_vendor TEXT,
      webgl_renderer TEXT,
      canvas_fingerprint TEXT,
      audio_fingerprint TEXT,
      fonts_detected TEXT,
      plugins TEXT,
      battery_level REAL,
      battery_charging INTEGER,
      local_storage INTEGER,
      session_storage INTEGER,
      indexed_db INTEGER,
      ad_blocker INTEGER,
      webrtc_leak TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'user', status TEXT DEFAULT 'active', cloaker_base_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  try { db.run('ALTER TABLE users ADD COLUMN status TEXT DEFAULT \'active\''); } catch (e) {}
  try { db.run('ALTER TABLE users ADD COLUMN cloaker_base_url TEXT'); } catch (e) {}
  db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
  try { db.run("INSERT OR IGNORE INTO settings (key, value) VALUES ('cloaker_base_url', '')"); } catch (e) {}

  saveDb();
  console.log('✅ Banco de dados inicializado');
}

// Autenticação: exige sessão para / e /api/* (exceto login, setup, config, go, t)
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.path === '/login' || req.path.startsWith('/go/') || req.path.startsWith('/t/')) return next();
  if (req.path === '/api/login' || req.path === '/api/logout' || req.path === '/api/setup' || req.path === '/api/config/') return next();
  if (req.path.startsWith('/api/') && req.method === 'GET' && req.path === '/api/config/' + (req.params && req.params.siteId ? req.params.siteId : '')) return next();
  if (req.path.startsWith('/api/')) {
    if (req.path === '/api/login' || req.path === '/api/setup') return next();
    return res.status(401).json({ error: 'Não autorizado' });
  }
  return res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const user = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
}

app.use((req, res, next) => {
  if (req.path === '/login' && req.method === 'GET') return next();
  if (req.path.startsWith('/go/') || req.path.startsWith('/t/')) return next();
  if (req.path.match(/^\/api\/config\//) && req.method === 'GET') return next();
  if (req.path === '/' && req.method === 'GET' && (!req.session || !req.session.userId)) return res.redirect('/login');
  if (req.path === '/api/login' || req.path === '/api/setup' || req.path === '/api/setup/check' || req.path === '/api/setup/promote-first-admin' || req.path === '/api/signup') return next();
  if (req.path.startsWith('/api/') && !req.session?.userId) return res.status(401).json({ error: 'Não autorizado' });
  next();
});

// Página de login
app.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// API: Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
  const user = get('SELECT id, username, role, status, password_hash FROM users WHERE username = ?', [username.trim()]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Usuário ou senha inválidos' });
  const status = user.status || 'active';
  if (status === 'pending') return res.status(403).json({ error: 'Conta aguardando aprovação do administrador.' });
  if (status === 'banned') return res.status(403).json({ error: 'Conta bloqueada pelo administrador.' });
  if (status === 'paused') return res.status(403).json({ error: 'Conta pausada. Entre em contato com o administrador.' });
  if (status !== 'active') return res.status(403).json({ error: 'Conta inativa.' });
  req.session.userId = user.id;
  req.session.userRole = user.role;
  res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
});

// API: Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {});
  res.json({ success: true });
});

// API: Usuário atual
app.get('/api/me', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const user = get('SELECT id, username, role, created_at FROM users WHERE id = ?', [req.session.userId]);
  if (!user) return res.status(401).json({ error: 'Não autorizado' });
  res.json(user);
});

// API: Verificar se precisa de setup (sem auth)
app.get('/api/setup/check', (req, res) => {
  const count = get('SELECT COUNT(*) as c FROM users');
  res.json({ setupRequired: !count || count.c === 0 });
});

// API: Setup inicial (criar primeiro admin se não existir usuários)
app.post('/api/setup', (req, res) => {
  const count = get('SELECT COUNT(*) as c FROM users');
  if (count && count.c > 0) return res.status(400).json({ error: 'Sistema já configurado' });
  const { username, password } = req.body || {};
  if (!username || !password || username.length < 2 || password.length < 6) return res.status(400).json({ error: 'Usuário (mín. 2 caracteres) e senha (mín. 6 caracteres) obrigatórios' });
  const hash = bcrypt.hashSync(password.trim(), 10);
  run('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', [username.trim(), hash, 'admin']);
  const user = get('SELECT id, username, role FROM users WHERE username = ?', [username.trim()]);
  req.session.userId = user.id;
  req.session.userRole = user.role;
  res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
});

// API: Recuperação – promover primeiro usuário a admin (quando não há admin e usuário criou conta por "Solicitar acesso")
// Use apenas quando estiver travado (conta pendente e nenhum admin). Requer token em SETUP_RECOVERY_TOKEN.
app.get('/api/setup/promote-first-admin', (req, res) => {
  const token = req.query.token || (req.body && req.body.token);
  const secret = process.env.SETUP_RECOVERY_TOKEN;
  if (!secret || token !== secret) return res.status(403).json({ error: 'Token inválido ou não configurado.' });
  const adminCount = get('SELECT COUNT(*) as c FROM users WHERE role = ?', ['admin']);
  if (adminCount && adminCount.c > 0) return res.status(400).json({ error: 'Já existe um administrador. Use o painel para aprovar usuários.' });
  const first = get('SELECT id, username FROM users ORDER BY id ASC LIMIT 1');
  if (!first) return res.status(404).json({ error: 'Nenhum usuário no banco.' });
  run('UPDATE users SET role = ?, status = ? WHERE id = ?', ['admin', 'active', first.id]);
  res.json({ success: true, message: 'Primeiro usuário promovido a administrador. Faça login com: ' + first.username });
});

// API: Configurações (domínio do cloaker – por usuário: cada user tem seu próprio domínio)
app.get('/api/settings', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const user = get('SELECT cloaker_base_url FROM users WHERE id = ?', [req.session.userId]);
  res.json({ cloaker_base_url: (user && user.cloaker_base_url) ? user.cloaker_base_url : '' });
});

app.put('/api/settings', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const { cloaker_base_url } = req.body || {};
  const val = (cloaker_base_url != null ? String(cloaker_base_url).trim() : '') || '';
  run('UPDATE users SET cloaker_base_url = ? WHERE id = ?', [val, req.session.userId]);
  res.json({ success: true });
});

// API: Verificar propagação DNS e se o domínio responde (Configurações)
app.get('/api/settings/check-propagation', async (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  let url = (req.query.url || '').trim();
  if (!url) {
    const user = get('SELECT cloaker_base_url FROM users WHERE id = ?', [req.session.userId]);
    url = (user && user.cloaker_base_url) ? user.cloaker_base_url.trim() : '';
  }
  if (!url) return res.status(400).json({ ok: false, message: 'Informe uma URL em "Meu domínio do Cloaker" e salve, ou passe ?url= na consulta.', details: {} });

  let hostname;
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    hostname = u.hostname;
    if (!hostname) throw new Error('Host inválido');
  } catch (e) {
    return res.json({ ok: false, message: 'URL inválida. Use algo como https://energysaver.store', details: {} });
  }

  const details = { hostname, resolved: false, cname: [], ips: [], reachable: false };

  try {
    try {
      const cnames = await dns.resolveCname(hostname);
      details.cname = Array.isArray(cnames) ? cnames : [cnames];
      details.resolved = true;
    } catch (e) {
      try {
        const ips = await dns.resolve4(hostname);
        details.ips = ips || [];
        details.resolved = details.ips.length > 0;
      } catch (e2) {
        details.resolved = false;
      }
    }

    const fetchUrl = url.startsWith('http') ? url : 'https://' + url;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const resp = await fetch(fetchUrl, { method: 'GET', redirect: 'follow', signal: controller.signal, headers: { 'User-Agent': 'CloakerPro-PropagationCheck/1.0' } });
      clearTimeout(timeout);
      details.reachable = resp.ok || resp.status === 302 || resp.status === 301;
    } catch (e) {
      clearTimeout(timeout);
      details.reachable = false;
    }
  } catch (e) {
    console.error('Check propagation error:', e.message);
  }

  const ok = details.reachable || (details.resolved && (details.cname.length > 0 || details.ips.length > 0));
  let message;
  if (details.reachable) message = 'Domínio está propagado e respondendo. Tudo certo.';
  else if (details.resolved) message = 'DNS resolveu, mas o domínio ainda não está respondendo. Pode ser propagação em andamento ou SSL/proxy. Tente de novo em alguns minutos.';
  else message = 'Domínio ainda não resolveu (propagação em andamento ou CNAME incorreto). Aguarde alguns minutos ou confira o registro no seu DNS.';

  res.json({ ok, message, details });
});

// API: Solicitar conta (público – cria usuário com status pending)
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || username.trim().length < 2 || password.length < 6) return res.status(400).json({ error: 'Usuário (mín. 2 caracteres) e senha (mín. 6 caracteres) obrigatórios' });
  const exists = get('SELECT id FROM users WHERE username = ?', [username.trim()]);
  if (exists) return res.status(400).json({ error: 'Este usuário já está cadastrado.' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    run('INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, ?, ?)', [username.trim(), hash, 'user', 'pending']);
    res.json({ success: true, message: 'Solicitação enviada. Aguarde a aprovação do administrador.' });
  } catch (e) {
    res.status(400).json({ error: 'Erro ao solicitar conta.' });
  }
});

// API: Listar usuários (admin – ativos e pendentes)
app.get('/api/users', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const user = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const users = all('SELECT id, username, role, status, created_at FROM users ORDER BY status ASC, created_at DESC');
  res.json(users);
});

// API: Aprovar usuário (admin)
app.post('/api/users/:id/approve', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'ID inválido' });
  run('UPDATE users SET status = ? WHERE id = ?', ['active', id]);
  const u = get('SELECT id, username, role, status, created_at FROM users WHERE id = ?', [id]);
  res.json(u || { success: true });
});

// API: Rejeitar/remover solicitação (admin)
app.post('/api/users/:id/reject', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'ID inválido' });
  run('DELETE FROM users WHERE id = ? AND status = ?', [id, 'pending']);
  res.json({ success: true });
});

// API: Excluir usuário (admin) – remove usuário e seus sites/visitantes
app.delete('/api/users/:id', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'ID inválido' });
  if (id === req.session.userId) return res.status(400).json({ error: 'Você não pode excluir sua própria conta.' });
  const user = get('SELECT id FROM users WHERE id = ?', [id]);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  const siteIds = all('SELECT site_id FROM sites WHERE user_id = ?', [id]).map(r => r.site_id);
  siteIds.forEach(sid => {
    run('DELETE FROM visitors WHERE site_id = ?', [sid]);
    run('DELETE FROM sites WHERE site_id = ?', [sid]);
  });
  run('DELETE FROM users WHERE id = ?', [id]);
  res.json({ success: true });
});

// API: Banir usuário (admin) – status = banned (não pode fazer login)
app.post('/api/users/:id/ban', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'ID inválido' });
  if (id === req.session.userId) return res.status(400).json({ error: 'Você não pode banir sua própria conta.' });
  run('UPDATE users SET status = ? WHERE id = ?', ['banned', id]);
  const u = get('SELECT id, username, role, status, created_at FROM users WHERE id = ?', [id]);
  res.json(u || { success: true });
});

// API: Pausar usuário (admin) – status = paused
app.post('/api/users/:id/pause', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'ID inválido' });
  if (id === req.session.userId) return res.status(400).json({ error: 'Você não pode pausar sua própria conta.' });
  run('UPDATE users SET status = ? WHERE id = ?', ['paused', id]);
  const u = get('SELECT id, username, role, status, created_at FROM users WHERE id = ?', [id]);
  res.json(u || { success: true });
});

// API: Ativar usuário (admin) – status = active
app.post('/api/users/:id/activate', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'ID inválido' });
  run('UPDATE users SET status = ? WHERE id = ?', ['active', id]);
  const u = get('SELECT id, username, role, status, created_at FROM users WHERE id = ?', [id]);
  res.json(u || { success: true });
});

// API: Alterar senha do usuário (admin)
app.put('/api/users/:id/password', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const id = parseInt(req.params.id, 10);
  const { password } = req.body || {};
  if (!id || !password || password.length < 6) return res.status(400).json({ error: 'Senha com pelo menos 6 caracteres obrigatória.' });
  const hash = bcrypt.hashSync(password, 10);
  run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, id]);
  res.json({ success: true });
});

// API: Criar usuário (admin – já ativo)
app.post('/api/users', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const admin = get('SELECT role FROM users WHERE id = ?', [req.session.userId]);
  if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const { username, password, role } = req.body || {};
  if (!username || !password || username.trim().length < 2 || password.length < 6) return res.status(400).json({ error: 'Usuário (mín. 2 caracteres) e senha (mín. 6 caracteres) obrigatórios' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    run('INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, ?, ?)', [username.trim(), hash, role === 'admin' ? 'admin' : 'user', 'active']);
    const u = get('SELECT id, username, role, status, created_at FROM users WHERE username = ?', [username.trim()]);
    res.json(u);
  } catch (e) {
    res.status(400).json({ error: 'Usuário já existe' });
  }
});

// API: Buscar configurações do site (para o script)
app.get('/api/config/:siteId', (req, res) => {
  const site = get('SELECT * FROM sites WHERE site_id = ? AND is_active = 1', [req.params.siteId]);
  if (!site) {
    return res.json({
      redirect_url: 'https://www.google.com/',
      block_desktop: 1,
      block_facebook_library: 1,
      block_bots: 1,
      block_devtools: 1,
      allowed_countries: 'BR',
      blocked_countries: ''
    });
  }
  res.json(site);
});

// API: Registrar visita
app.post('/api/track', (req, res) => {
  try {
    const data = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    
    const parser = new UAParser(data.userAgent);
    const ua = parser.getResult();

    const sql = `
      INSERT INTO visitors (
        site_id, visitor_id, ip, country, city, region, isp, timezone,
        user_agent, browser, browser_version, os, os_version,
        device_type, device_vendor, device_model,
        screen_width, screen_height, viewport_width, viewport_height,
        color_depth, pixel_ratio, language, languages, platform,
        cookies_enabled, do_not_track, online, touch_support, max_touch_points,
        hardware_concurrency, device_memory, connection_type, connection_speed,
        referrer, page_url, page_title,
        utm_source, utm_medium, utm_campaign, utm_term, utm_content,
        facebook_params, is_bot, bot_reason, was_blocked, block_reason,
        webgl_vendor, webgl_renderer, canvas_fingerprint, audio_fingerprint,
        fonts_detected, plugins, battery_level, battery_charging,
        local_storage, session_storage, indexed_db, ad_blocker, webrtc_leak, created_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?, datetime('now')
      )
    `;

    run(sql, [
      data.siteId || 'default',
      data.visitorId || null,
      ip,
      data.geo?.country || null,
      data.geo?.city || null,
      data.geo?.region || null,
      data.geo?.isp || null,
      data.timezone || null,
      data.userAgent || null,
      ua.browser?.name || null,
      ua.browser?.version || null,
      ua.os?.name || null,
      ua.os?.version || null,
      ua.device?.type || 'desktop',
      ua.device?.vendor || null,
      ua.device?.model || null,
      data.screen?.width || null,
      data.screen?.height || null,
      data.viewport?.width || null,
      data.viewport?.height || null,
      data.screen?.colorDepth || null,
      data.screen?.pixelRatio || null,
      data.language || null,
      JSON.stringify(data.languages || []),
      data.platform || null,
      data.cookiesEnabled ? 1 : 0,
      data.doNotTrack ? 1 : 0,
      data.online ? 1 : 0,
      data.touchSupport ? 1 : 0,
      data.maxTouchPoints || 0,
      data.hardwareConcurrency || null,
      data.deviceMemory || null,
      data.connection?.type || null,
      data.connection?.effectiveType || null,
      data.referrer || null,
      data.pageUrl || null,
      data.pageTitle || null,
      data.utm?.source || null,
      data.utm?.medium || null,
      data.utm?.campaign || null,
      data.utm?.term || null,
      data.utm?.content || null,
      JSON.stringify(data.facebookParams || {}),
      data.isBot ? 1 : 0,
      data.botReason || null,
      data.wasBlocked ? 1 : 0,
      data.blockReason || null,
      data.webgl?.vendor || null,
      data.webgl?.renderer || null,
      data.fingerprints?.canvas || null,
      data.fingerprints?.audio || null,
      JSON.stringify(data.fonts || []),
      JSON.stringify(data.plugins || []),
      data.battery?.level || null,
      data.battery?.charging ? 1 : 0,
      data.storage?.localStorage ? 1 : 0,
      data.storage?.sessionStorage ? 1 : 0,
      data.storage?.indexedDB ? 1 : 0,
      data.adBlocker ? 1 : 0,
      data.webrtcLeak || null
    ]);

    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao registrar visita:', error);
    res.status(500).json({ error: error.message });
  }
});

// Helper: IDs dos sites do usuário logado (cada usuário vê só seus sites)
function getMySiteIds(userId) {
  const rows = all('SELECT site_id FROM sites WHERE user_id = ?', [userId]);
  return rows.map(r => r.site_id).filter(Boolean);
}

// API: Listar sites (apenas do usuário logado)
app.get('/api/sites', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const userId = req.session.userId;
  const sites = all(`
    SELECT s.*, 
           (SELECT COUNT(*) FROM visitors WHERE site_id = s.site_id) as total_visits,
           (SELECT COUNT(*) FROM visitors WHERE site_id = s.site_id AND was_blocked = 1) as blocked_visits
    FROM sites s 
    WHERE s.user_id = ?
    ORDER BY s.created_at DESC
  `, [userId]);
  res.json(sites);
});

function generateLinkCode() {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  if (get('SELECT 1 FROM sites WHERE link_code = ?', [code])) return generateLinkCode();
  return code;
}

// API: Criar site (padrão: apenas Brasil; gera link para usar nos Ads) – pertence ao usuário logado
app.post('/api/sites', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const { name, domain, target_url, redirect_url, allowed_countries } = req.body;
  const siteId = 'site_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  const linkCode = generateLinkCode();
  const countries = allowed_countries !== undefined ? allowed_countries : 'BR';
  const target = (target_url || '').trim() || null;
  const userId = req.session.userId;
  try {
    run(`INSERT INTO sites (site_id, link_code, user_id, name, domain, target_url, redirect_url, allowed_countries, block_desktop, block_facebook_library, block_bots, block_vpn, block_devtools, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, 1, 1, datetime('now'))`,
      [siteId, linkCode, userId, name, domain, target, redirect_url || 'https://www.google.com/', countries]);
    const site = get('SELECT * FROM sites WHERE site_id = ?', [siteId]);
    res.json(site);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Atualizar site (apenas se o site pertencer ao usuário)
app.put('/api/sites/:siteId', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const existing = get('SELECT link_code, user_id FROM sites WHERE site_id = ?', [req.params.siteId]);
  if (!existing) return res.status(404).json({ error: 'Site não encontrado' });
  if (existing.user_id != null && Number(existing.user_id) !== Number(req.session.userId)) return res.status(403).json({ error: 'Acesso negado a este site' });
  const data = req.body;
  try {
    let linkCode = existing.link_code;
    if (!linkCode) linkCode = generateLinkCode();
    run(`
      UPDATE sites SET
        name = ?, domain = ?, link_code = ?, target_url = ?, redirect_url = ?,
        block_desktop = ?, block_facebook_library = ?, block_bots = ?,
        block_vpn = ?, block_devtools = ?,
        allowed_countries = ?, blocked_countries = ?, is_active = ?
      WHERE site_id = ?
    `, [
      data.name, data.domain, linkCode, (data.target_url || '').trim() || null, data.redirect_url,
      data.block_desktop ? 1 : 0, data.block_facebook_library ? 1 : 0, data.block_bots ? 1 : 0,
      data.block_vpn ? 1 : 0, data.block_devtools ? 1 : 0,
      data.allowed_countries || '', data.blocked_countries || '', data.is_active ? 1 : 0,
      req.params.siteId
    ]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Deletar site (apenas se pertencer ao usuário)
app.delete('/api/sites/:siteId', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const site = get('SELECT user_id FROM sites WHERE site_id = ?', [req.params.siteId]);
  if (!site) return res.status(404).json({ error: 'Site não encontrado' });
  if (site.user_id != null && Number(site.user_id) !== Number(req.session.userId)) return res.status(403).json({ error: 'Acesso negado' });
  try {
    run('DELETE FROM visitors WHERE site_id = ?', [req.params.siteId]);
    run('DELETE FROM sites WHERE site_id = ?', [req.params.siteId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Listar visitantes (apenas dos sites do usuário)
app.get('/api/visitors', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const userId = req.session.userId;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  const filter = req.query.filter || 'all';
  const siteId = req.query.site || null;

  let where = ["v.site_id IN (SELECT site_id FROM sites WHERE user_id = ?)"];
  const params = [userId];
  if (siteId && siteId !== 'all') {
    const myIds = getMySiteIds(userId);
    if (!myIds.includes(siteId)) {
      return res.json({ visitors: [], total: 0, page: 1, pages: 0 });
    }
    where.push('v.site_id = ?');
    params.push(siteId);
  }
  if (filter === 'blocked') where.push('v.was_blocked = 1');
  else if (filter === 'allowed') where.push('v.was_blocked = 0');
  else if (filter === 'bots') where.push('v.is_bot = 1');
  else if (filter === 'mobile') where.push("v.device_type IN ('mobile', 'tablet')");
  else if (filter === 'desktop') where.push("(v.device_type = 'desktop' OR v.device_type IS NULL)");

  const whereClause = 'WHERE ' + where.join(' AND ');
  const visitors = all(`SELECT v.* FROM visitors v ${whereClause} ORDER BY v.created_at DESC LIMIT ${limit} OFFSET ${offset}`, params);
  const total = get(`SELECT COUNT(*) as count FROM visitors v ${whereClause}`, params);

  res.json({
    visitors,
    total: total?.count || 0,
    page,
    pages: Math.ceil((total?.count || 0) / limit)
  });
});

// API: Estatísticas (apenas dos sites do usuário)
app.get('/api/stats', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const userId = req.session.userId;
  const period = req.query.period || 'today';
  const siteId = req.query.site || null;
  
  let dateCondition = '';
  switch (period) {
    case 'today':   dateCondition = "v.created_at >= date('now') AND v.created_at <= datetime('now')"; break;
    case 'yesterday': dateCondition = "v.created_at >= date('now', '-1 day') AND v.created_at < date('now')"; break;
    case '7d':      dateCondition = "v.created_at >= datetime('now', '-7 days')"; break;
    case '15d':     dateCondition = "v.created_at >= datetime('now', '-15 days')"; break;
    case '30d':     dateCondition = "v.created_at >= datetime('now', '-30 days')"; break;
    default:       dateCondition = "v.created_at >= date('now') AND v.created_at <= datetime('now')";
  }

  const userSites = "v.site_id IN (SELECT site_id FROM sites WHERE user_id = ?)";
  const siteFilter = siteId && siteId !== 'all' ? " AND v.site_id = ?" : '';
  const params = siteId && siteId !== 'all' ? [userId, siteId] : [userId];
  const baseWhere = `FROM visitors v WHERE (${dateCondition}) AND ${userSites}${siteFilter}`;

  const stats = {
    total: get(`SELECT COUNT(*) as count ${baseWhere}`, params)?.count || 0,
    blocked: get(`SELECT COUNT(*) as count ${baseWhere} AND v.was_blocked = 1`, params)?.count || 0,
    allowed: get(`SELECT COUNT(*) as count ${baseWhere} AND v.was_blocked = 0`, params)?.count || 0,
    bots: get(`SELECT COUNT(*) as count ${baseWhere} AND v.is_bot = 1`, params)?.count || 0,
    mobile: get(`SELECT COUNT(*) as count ${baseWhere} AND v.device_type IN ('mobile', 'tablet')`, params)?.count || 0,
    desktop: get(`SELECT COUNT(*) as count ${baseWhere} AND (v.device_type = 'desktop' OR v.device_type IS NULL)`, params)?.count || 0,
    
    byBrowser: all(`SELECT v.browser as browser, COUNT(*) as count ${baseWhere} AND v.browser IS NOT NULL GROUP BY v.browser ORDER BY count DESC LIMIT 10`, params),
    byOS: all(`SELECT v.os as os, COUNT(*) as count ${baseWhere} AND v.os IS NOT NULL GROUP BY v.os ORDER BY count DESC LIMIT 10`, params),
    byCountry: all(`SELECT v.country as country, COUNT(*) as count ${baseWhere} AND v.country IS NOT NULL GROUP BY v.country ORDER BY count DESC LIMIT 10`, params),
    byReferrer: all(`SELECT v.referrer as referrer, COUNT(*) as count ${baseWhere} AND v.referrer IS NOT NULL AND v.referrer != '' GROUP BY v.referrer ORDER BY count DESC LIMIT 10`, params),
    byHour: all(`SELECT strftime('%Y-%m-%d %H:00', v.created_at) as hour, COUNT(*) as total, SUM(CASE WHEN v.was_blocked = 1 THEN 1 ELSE 0 END) as blocked, SUM(CASE WHEN v.was_blocked = 0 THEN 1 ELSE 0 END) as allowed ${baseWhere} GROUP BY hour ORDER BY hour DESC LIMIT 24`, params),
    blockReasons: all(`SELECT v.block_reason as block_reason, COUNT(*) as count ${baseWhere} AND v.was_blocked = 1 AND v.block_reason IS NOT NULL GROUP BY v.block_reason ORDER BY count DESC`, params),
    bySite: all(`SELECT v.site_id as site_id, COUNT(*) as count FROM visitors v WHERE v.site_id IN (SELECT site_id FROM sites WHERE user_id = ?) AND (${dateCondition}) GROUP BY v.site_id ORDER BY count DESC`, [userId])
  };

  res.json(stats);
});

// API: Detalhes de um visitante (apenas se o visitante for de um site do usuário)
app.get('/api/visitors/:id', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const visitor = get('SELECT v.* FROM visitors v INNER JOIN sites s ON s.site_id = v.site_id AND s.user_id = ? WHERE v.id = ?', [req.session.userId, req.params.id]);
  if (!visitor) return res.status(404).json({ error: 'Visitante não encontrado' });
  res.json(visitor);
});

// API: Deletar visitantes (apenas dos sites do usuário)
app.delete('/api/visitors', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const { ids } = req.body;
  if (ids && ids.length > 0) {
    const placeholders = ids.map(() => '?').join(',');
    run(`DELETE FROM visitors WHERE id IN (${placeholders}) AND site_id IN (SELECT site_id FROM sites WHERE user_id = ?)`, [...ids, req.session.userId]);
  }
  res.json({ success: true });
});

// API: Limpar todos os dados (apenas visitantes dos sites do usuário)
app.delete('/api/visitors/all', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  run('DELETE FROM visitors WHERE site_id IN (SELECT site_id FROM sites WHERE user_id = ?)', [req.session.userId]);
  res.json({ success: true });
});

// API: Exportar dados (apenas visitantes dos sites do usuário)
app.get('/api/export', (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
  const visitors = all('SELECT v.* FROM visitors v INNER JOIN sites s ON s.site_id = v.site_id AND s.user_id = ? ORDER BY v.created_at DESC', [req.session.userId]);
  const format = req.query.format || 'json';
  
  if (format === 'csv') {
    if (visitors.length === 0) return res.send('');
    const headers = Object.keys(visitors[0]).join(',');
    const rows = visitors.map(v => Object.values(v).map(val => `"${(val || '').toString().replace(/"/g, '""')}"`).join(','));
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=visitors.csv');
    res.send([headers, ...rows].join('\n'));
  } else {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=visitors.json');
    res.json(visitors);
  }
});

// Helper: IP público (não localhost/VPN interna)
function isPrivateIP(ip) {
  if (!ip || ip === 'unknown') return true;
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('::ffff:127.')) return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') || ip.startsWith('172.19.') || ip.startsWith('172.2') || ip.startsWith('172.30.') || ip.startsWith('172.31.')) return true;
  return false;
}

// Helper: geolocalização por IP – retorna { country, city, region, isp } (ipapi.co + fallback ip-api.com)
async function getGeoByIP(ip) {
  const out = { country: null, city: null, region: null, isp: null };
  if (!ip || isPrivateIP(ip)) return out;
  const normalized = ip.replace(/^::ffff:/, '');
  const headers = { 'User-Agent': 'CloakerPro/1.0' };

  try {
    const res = await fetch(`https://ipapi.co/${normalized}/json/`, { signal: AbortSignal.timeout(5000), headers });
    if (res.ok) {
      const geo = await res.json();
      if (geo.country_code) {
        out.country = geo.country_code;
        out.city = geo.city || null;
        out.region = geo.region || null;
        out.isp = geo.org || geo.organisation || null;
        return out;
      }
    }
  } catch (e) {}

  try {
    const res = await fetch(`http://ip-api.com/json/${normalized}?fields=countryCode,city,regionName,isp`, { signal: AbortSignal.timeout(5000), headers });
    if (res.ok) {
      const geo = await res.json();
      if (geo.countryCode) {
        out.country = geo.countryCode;
        out.city = geo.city || null;
        out.region = geo.regionName || null;
        out.isp = geo.isp || null;
        return out;
      }
    }
  } catch (e) {}

  try {
    const res = await fetch(`https://ipwho.is/${normalized}`, { signal: AbortSignal.timeout(5000), headers });
    if (res.ok) {
      const geo = await res.json();
      if (geo.success && geo.country_code) {
        out.country = geo.country_code;
        out.city = geo.city || null;
        out.region = geo.region || null;
        out.isp = (geo.connection && (geo.connection.isp || geo.connection.org)) || null;
        return out;
      }
    }
  } catch (e) {}

  return out;
}

// ========== LINK PARA ADS: /go/:code ==========
// Você cola seu link no painel → o sistema gera um novo link → use esse link nos anúncios.
// Quem clica passa aqui: checamos (desktop, bot, emulador, país por IP) e redirecionamos.
app.get('/go/:code', async (req, res) => {
  const code = (req.params.code || '').toLowerCase();
  const site = get('SELECT * FROM sites WHERE link_code = ? AND is_active = 1', [code]);
  if (!site || !site.target_url) {
    return res.redirect(302, 'https://www.google.com/');
  }

  // IP: prioridade cf-connecting-ip (Cloudflare), true-client-ip, x-forwarded-for (1º = cliente), x-real-ip, socket
  let ip = (req.headers['cf-connecting-ip'] || req.headers['true-client-ip'] || req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '').toString();
  ip = ip.split(',')[0].trim();
  if (ip === '::1') ip = '127.0.0.1';
  if (!ip) ip = 'unknown';

  const userAgent = req.headers['user-agent'] || '';
  const referer = (req.headers['referer'] || req.headers['referrer'] || '').toLowerCase();
  const fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
  const parser = new UAParser(userAgent);
  const ua = parser.getResult();
  const deviceType = (ua.device && ua.device.type) ? ua.device.type : (userAgent.toLowerCase().match(/mobile|android|iphone|ipad/) ? 'mobile' : 'desktop');

  const geo = await getGeoByIP(ip);
  const country = geo.country;

  const allowedList = (site.allowed_countries || 'BR').split(',').map(c => c.trim().toUpperCase()).filter(Boolean);
  const blockedList = (site.blocked_countries || '').split(',').map(c => c.trim().toUpperCase()).filter(Boolean);

  function isDesktop() {
    const u = userAgent.toLowerCase();
    return !/mobile|android|iphone|ipad|webos|blackberry|iemobile|opera mini/i.test(u);
  }
  function isFromFacebook() {
    return referer.includes('facebook.com') || referer.includes('fb.com') || fullUrl.toLowerCase().includes('fbclid=');
  }
  function isBot() {
    const u = userAgent.toLowerCase();
    const bots = ['bot', 'crawler', 'spider', 'googlebot', 'facebookexternalhit', 'facebot', 'slurp', 'duckduckbot', 'bingbot', 'yandex', 'curl', 'wget', 'python-requests', 'python/', 'java/', 'headless', 'headlesschrome', 'puppeteer', 'phantom', 'selenium', 'playwright', 'chromedriver', 'geckodriver', 'phantomjs', 'lighthouse', 'gtmetrix', 'screaming frog'];
    return bots.some(b => u.includes(b)) || !!req.headers['x-purpose'];
  }
  function isEmulator() {
    const u = userAgent.toLowerCase();
    return /android sdk|sdk_gphone|emulator|generic.*android|build\/generic|model.*unknown|vbox|genymotion|bluestacks|nox|andy|droid4x|memu|koplayer|mumu/i.test(u) ||
      (ua.device && (ua.device.model === 'unknown' || ua.device.model === 'Emulator'));
  }

  let blockReason = null;
  if (site.block_bots && isBot()) blockReason = 'Bot detectado';
  else if (isEmulator()) blockReason = 'Emulador detectado (apenas celular real permitido)';
  else if (site.block_desktop && isDesktop()) blockReason = 'Desktop detectado';
  else if (site.block_facebook_library && isFromFacebook() && isDesktop()) blockReason = 'Biblioteca Facebook';
  else if (allowedList.length > 0) {
    const countryUpper = country ? country.toUpperCase() : null;
    if (!countryUpper) blockReason = 'País não identificado pelo IP (bloqueado por segurança)';
    else if (!allowedList.includes(countryUpper)) blockReason = `País não permitido: ${countryUpper}`;
    else if (blockedList.length > 0 && blockedList.includes(countryUpper)) blockReason = `País bloqueado: ${countryUpper}`;
  } else if (country && blockedList.includes(country.toUpperCase())) blockReason = `País bloqueado: ${country}`;

  const wasBlocked = !!blockReason;

  // UTMs e parâmetros dos Ads (vêm na URL do clique) – repassados para o link de oferta no redirect
  const utm_source = (req.query.utm_source || '').trim() || null;
  const utm_medium = (req.query.utm_medium || '').trim() || null;
  const utm_campaign = (req.query.utm_campaign || '').trim() || null;
  const utm_term = (req.query.utm_term || '').trim() || null;
  const utm_content = (req.query.utm_content || '').trim() || null;
  const fbclid = (req.query.fbclid || '').trim() || null;
  const facebookParams = fbclid ? JSON.stringify({ fbclid }) : null;

  run(`INSERT INTO visitors (site_id, ip, user_agent, referrer, page_url, country, city, region, isp, device_type, browser, os, was_blocked, block_reason, is_bot, utm_source, utm_medium, utm_campaign, utm_term, utm_content, facebook_params, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [site.site_id, ip, userAgent, referer, fullUrl, country || null, geo.city || null, geo.region || null, geo.isp || null, deviceType, ua.browser?.name || null, ua.os?.name || null, wasBlocked ? 1 : 0, blockReason, isBot() ? 1 : 0, utm_source, utm_medium, utm_campaign, utm_term, utm_content, facebookParams]);

  if (wasBlocked) {
    return res.redirect(302, site.redirect_url || 'https://www.google.com/');
  }

  // Redireciona para a oferta com a mesma query string (UTMs, fbclid, etc.) para a landing receber
  let dest = site.target_url;
  const qs = req.originalUrl.includes('?') ? req.originalUrl.split('?')[1] : '';
  if (qs) dest += (dest.includes('?') ? '&' : '?') + qs;
  return res.redirect(302, dest);
});

// Servir script dinâmico por site (opcional – modo antigo)
app.get('/t/:siteId.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'tracker.js'));
});

// Servir painel
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Iniciar servidor
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║           🔒 CLOAKER PRO - Painel de Controle             ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  🚀 Servidor rodando em: http://localhost:${PORT}            ║
║  📊 Painel de controle: http://localhost:${PORT}             ║
║                                                           ║
║  📝 Como usar:                                            ║
║     1. Acesse o painel → Link para Ads                    ║
║     2. Cole a URL da sua landing page → Gerar link        ║
║     3. Use o link gerado como URL de destino nos Ads      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
  });
}).catch(err => {
  console.error('Erro ao iniciar:', err);
});
