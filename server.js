const express = require('express');
const initSqlJs = require('sql.js');
const cors = require('cors');
const UAParser = require('ua-parser-js');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
// Railway: usa volume para persistir o banco; local: usa a pasta do projeto
const DB_PATH = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'cloaker.db')
  : path.join(__dirname, 'cloaker.db');

// Middleware
app.use(cors());
app.use(express.json());
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

  saveDb();
  console.log('✅ Banco de dados inicializado');
}

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

// API: Listar sites
app.get('/api/sites', (req, res) => {
  const sites = all(`
    SELECT s.*, 
           (SELECT COUNT(*) FROM visitors WHERE site_id = s.site_id) as total_visits,
           (SELECT COUNT(*) FROM visitors WHERE site_id = s.site_id AND was_blocked = 1) as blocked_visits
    FROM sites s 
    ORDER BY created_at DESC
  `);
  res.json(sites);
});

function generateLinkCode() {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  if (get('SELECT 1 FROM sites WHERE link_code = ?', [code])) return generateLinkCode();
  return code;
}

// API: Criar site (padrão: apenas Brasil; gera link para usar nos Ads)
app.post('/api/sites', (req, res) => {
  const { name, domain, target_url, redirect_url, allowed_countries } = req.body;
  const siteId = 'site_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  const linkCode = generateLinkCode();
  const countries = allowed_countries !== undefined ? allowed_countries : 'BR';
  const target = (target_url || '').trim() || null;
  
  try {
    run(`INSERT INTO sites (site_id, link_code, name, domain, target_url, redirect_url, allowed_countries, block_desktop, block_facebook_library, block_bots, block_vpn, block_devtools, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, 1, 1, 1, datetime('now'))`,
      [siteId, linkCode, name, domain, target, redirect_url || 'https://www.google.com/', countries]);
    
    const site = get('SELECT * FROM sites WHERE site_id = ?', [siteId]);
    res.json(site);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Atualizar site (se não tiver link_code, gera um)
app.put('/api/sites/:siteId', (req, res) => {
  const data = req.body;
  try {
    const existing = get('SELECT link_code FROM sites WHERE site_id = ?', [req.params.siteId]);
    let linkCode = existing?.link_code;
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

// API: Deletar site
app.delete('/api/sites/:siteId', (req, res) => {
  try {
    run('DELETE FROM visitors WHERE site_id = ?', [req.params.siteId]);
    run('DELETE FROM sites WHERE site_id = ?', [req.params.siteId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Listar visitantes
app.get('/api/visitors', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  const filter = req.query.filter || 'all';
  const siteId = req.query.site || null;

  let where = [];
  if (siteId && siteId !== 'all') where.push(`site_id = '${siteId}'`);
  if (filter === 'blocked') where.push('was_blocked = 1');
  else if (filter === 'allowed') where.push('was_blocked = 0');
  else if (filter === 'bots') where.push('is_bot = 1');
  else if (filter === 'mobile') where.push("device_type IN ('mobile', 'tablet')");
  else if (filter === 'desktop') where.push("(device_type = 'desktop' OR device_type IS NULL)");

  const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';

  const visitors = all(`SELECT * FROM visitors ${whereClause} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`);
  const total = get(`SELECT COUNT(*) as count FROM visitors ${whereClause}`);

  res.json({
    visitors,
    total: total?.count || 0,
    page,
    pages: Math.ceil((total?.count || 0) / limit)
  });
});

// API: Estatísticas
app.get('/api/stats', (req, res) => {
  const period = req.query.period || '24h';
  const siteId = req.query.site || null;
  
  let dateFilter = '';
  switch (period) {
    case '1h': dateFilter = "datetime('now', '-1 hour')"; break;
    case '24h': dateFilter = "datetime('now', '-1 day')"; break;
    case '7d': dateFilter = "datetime('now', '-7 days')"; break;
    case '30d': dateFilter = "datetime('now', '-30 days')"; break;
    default: dateFilter = "datetime('now', '-1 day')";
  }

  const siteFilter = siteId && siteId !== 'all' ? ` AND site_id = '${siteId}'` : '';
  const baseWhere = `WHERE created_at >= ${dateFilter}${siteFilter}`;

  const stats = {
    total: get(`SELECT COUNT(*) as count FROM visitors ${baseWhere}`)?.count || 0,
    blocked: get(`SELECT COUNT(*) as count FROM visitors ${baseWhere} AND was_blocked = 1`)?.count || 0,
    allowed: get(`SELECT COUNT(*) as count FROM visitors ${baseWhere} AND was_blocked = 0`)?.count || 0,
    bots: get(`SELECT COUNT(*) as count FROM visitors ${baseWhere} AND is_bot = 1`)?.count || 0,
    mobile: get(`SELECT COUNT(*) as count FROM visitors ${baseWhere} AND device_type IN ('mobile', 'tablet')`)?.count || 0,
    desktop: get(`SELECT COUNT(*) as count FROM visitors ${baseWhere} AND (device_type = 'desktop' OR device_type IS NULL)`)?.count || 0,
    
    byBrowser: all(`SELECT browser, COUNT(*) as count FROM visitors ${baseWhere} AND browser IS NOT NULL GROUP BY browser ORDER BY count DESC LIMIT 10`),
    byOS: all(`SELECT os, COUNT(*) as count FROM visitors ${baseWhere} AND os IS NOT NULL GROUP BY os ORDER BY count DESC LIMIT 10`),
    byCountry: all(`SELECT country, COUNT(*) as count FROM visitors ${baseWhere} AND country IS NOT NULL GROUP BY country ORDER BY count DESC LIMIT 10`),
    byReferrer: all(`SELECT referrer, COUNT(*) as count FROM visitors ${baseWhere} AND referrer IS NOT NULL AND referrer != '' GROUP BY referrer ORDER BY count DESC LIMIT 10`),
    byHour: all(`SELECT strftime('%Y-%m-%d %H:00', created_at) as hour, COUNT(*) as total, SUM(CASE WHEN was_blocked = 1 THEN 1 ELSE 0 END) as blocked, SUM(CASE WHEN was_blocked = 0 THEN 1 ELSE 0 END) as allowed FROM visitors ${baseWhere} GROUP BY hour ORDER BY hour DESC LIMIT 24`),
    blockReasons: all(`SELECT block_reason, COUNT(*) as count FROM visitors ${baseWhere} AND was_blocked = 1 AND block_reason IS NOT NULL GROUP BY block_reason ORDER BY count DESC`),
    bySite: all(`SELECT site_id, COUNT(*) as count FROM visitors WHERE created_at >= ${dateFilter} GROUP BY site_id ORDER BY count DESC`)
  };

  res.json(stats);
});

// API: Detalhes de um visitante
app.get('/api/visitors/:id', (req, res) => {
  const visitor = get('SELECT * FROM visitors WHERE id = ?', [req.params.id]);
  if (!visitor) return res.status(404).json({ error: 'Visitante não encontrado' });
  res.json(visitor);
});

// API: Deletar visitantes
app.delete('/api/visitors', (req, res) => {
  const { ids } = req.body;
  if (ids && ids.length > 0) {
    run(`DELETE FROM visitors WHERE id IN (${ids.join(',')})`);
  }
  res.json({ success: true });
});

// API: Limpar todos os dados
app.delete('/api/visitors/all', (req, res) => {
  run('DELETE FROM visitors');
  res.json({ success: true });
});

// API: Exportar dados
app.get('/api/export', (req, res) => {
  const format = req.query.format || 'json';
  const visitors = all('SELECT * FROM visitors ORDER BY created_at DESC');
  
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

  run(`INSERT INTO visitors (site_id, ip, user_agent, referrer, page_url, country, city, region, isp, device_type, browser, os, was_blocked, block_reason, is_bot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [site.site_id, ip, userAgent, referer, fullUrl, country || null, geo.city || null, geo.region || null, geo.isp || null, deviceType, ua.browser?.name || null, ua.os?.name || null, wasBlocked ? 1 : 0, blockReason, isBot() ? 1 : 0]);

  if (wasBlocked) {
    return res.redirect(302, site.redirect_url || 'https://www.google.com/');
  }

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
