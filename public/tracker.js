/**
 * 🕵️ SHERLOCK TRACKER V3 - Cloaker Pro Elite Tier
 * 
 * Features:
 * - Anti-Bot Comportamental & Fingerprint V2
 * - Trava de Parâmetros (UTM/FBCLID) via LocalStorage
 * - Detecção de Headless Chrome Avançada
 * - Proteção contra Engenharia Reversa
 */

(function () {
  'use strict';

  // 🛡️ 1. OBFUSCAÇÃO & PROTEÇÃO LISTENER
  // Impede que curiosos vejam o código facilmente via "View Source" na prática (embora JS seja visível)
  const _0x = {
    hide: 'none', vis: 'hidden', op: '0', imp: 'important',
    body: document.documentElement,
    loc: window.location,
    nav: navigator,
    doc: document,
    st: window.localStorage,
    ss: window.sessionStorage
  };

  // 🚨 2. BLOQUEIO VISUAL IMEDIATO
  (function h() {
    if (_0x.body) {
      _0x.body.style.setProperty('visibility', _0x.vis, _0x.imp);
      _0x.body.style.setProperty('opacity', _0x.op, _0x.imp);
    }
  })();

  // ⚙️ 3. CONFIGURAÇÃO INTELIGENTE
  const SCRIPT_SRC = _0x.doc.currentScript?.src || '';
  const URL_MATCH = SCRIPT_SRC.match(/\/t\/([^.]+)\.js/);

  const CFG = {
    API: SCRIPT_SRC ? new URL(SCRIPT_SRC).origin : 'http://localhost:3000',
    ID: URL_MATCH ? URL_MATCH[1] : 'default',
    SAFE_URL: 'https://www.google.com/',
    // Padrões de bloqueio (serão atualizados pelo servidor)
    RULES: { desktop: true, fb_lib: true, bots: true, vpn: false, devtools: true }
  };

  // 💾 4. PARAMETER LOCK (Trava de Parâmetros)
  // Salva UTMs e FBCLID antes que qualquer redirect limpe a URL
  function lockParams() {
    try {
      const p = new URLSearchParams(_0x.loc.search);
      const data = {};

      // Captura tudo que começa com utm_ ou fb_ ou gclid
      for (const [key, val] of p.entries()) {
        if (key.startsWith('utm_') || key.includes('clid') || key.startsWith('fb_')) {
          data[key] = val;
          _0x.st.setItem('_cp_' + key, val); // Persistência longa
          _0x.ss.setItem('_cp_' + key, val); // Persistência curta
        }
      }

      // Recupera se a URL estiver limpa (ex: após redirect interno)
      if (Object.keys(data).length === 0) {
        // Tenta re-injetar parâmetros perdidos na URL atual (visual apenas, ou para pixels)
        let restored = false;
        for (let i = 0; i < _0x.ss.length; i++) {
          const k = _0x.ss.key(i);
          if (k && k.startsWith('_cp_')) {
            const cleanKey = k.replace('_cp_', '');
            if (!p.has(cleanKey)) {
              p.set(cleanKey, _0x.ss.getItem(k));
              restored = true;
            }
          }
        }
        // Nota: Não forçamos reload para não gerar loop, apenas guardamos para envio ao backend
      }
    } catch (e) { }
  }
  lockParams();

  // 🕵️ 5. SHERLOCK BOT DETECTION (Fingerprint V2)
  function isBot() {
    const ua = _0x.nav.userAgent.toLowerCase();

    // A. Lista de Strings de Bots (Atualizada e Otimizada)
    const botSigs = [
      'bot', 'crawl', 'spider', 'slurp', 'facebookexternalhit', 'facebookcatalog',
      'headless', 'lighthouse', 'ptst', 'selenium', 'webdriver', 'puppeteer',
      'playwright', 'phantomjs', 'googlebot', 'bingbot', 'mediapartners'
    ];
    if (botSigs.some(s => ua.includes(s))) return { check: true, reason: 'User-Agent Signature' };

    // B. Teste de WebDriver (Padrão Ouro)
    if (_0x.nav.webdriver || window.domAutomation || window.domAutomationController) {
      return { check: true, reason: 'Automation/WebDriver' };
    }

    // C. Teste Humanidade (Plugins & Languages)
    // REMOVIDO: Alguns browsers (Brave, Tor, Privacy exts) escondem languages/plugins.
    // Bloquear por isso causa perda de tráfego real. Vamos focar apenas no WebDriver.

    // D. Teste de Resolução (Headless Check)
    if (window.outerWidth === 0 && window.outerHeight === 0) {
      return { check: true, reason: 'Zero Dimension Window' };
    }

    // E. Chrome Falso
    if (window.chrome && !window.chrome.runtime) {
      // Bots antigos emulam window.chrome mas esquecem do runtime
      // (Atual: modern headless chrome já tem runtime, mas pega os antigos)
    }

    return { check: false, reason: null };
  }

  // 📱 6. DEVICE FINGERPRINT (Com suporte a iPadOS)
  function getDevice() {
    const ua = _0x.nav.userAgent.toLowerCase();
    const touch = _0x.nav.maxTouchPoints > 0 || 'ontouchstart' in window;

    let type = 'desktop';
    if (/mobile|android|iphone|ipod/.test(ua)) type = 'mobile';
    else if (/ipad|tablet/.test(ua)) type = 'tablet';
    else if (ua.includes('macintosh') && touch) type = 'tablet'; // iPad Pro fingindo ser Mac

    return { type, isDesktop: type === 'desktop' };
  }

  // 🧠 7. LÓGICA DE BLOQUEIO (Atualizada)
  function shouldBlock(serverRules, geoData) {
    const dev = getDevice();
    const bot = isBot();

    // Regra 1: Bots Conhecidos = BAN
    if (serverRules.bots && bot.check) return { block: true, reason: `Bot: ${bot.reason}` };

    // Regra 2: Desktop (Se configurado)
    if (serverRules.desktop && dev.isDesktop) return { block: true, reason: 'Dispositivo Desktop' };

    // Regra 3: Facebook Library (Spy Tool)
    const ref = _0x.doc.referrer.toLowerCase();
    if (serverRules.fb_lib && (ref.includes('facebook') || ref.includes('fb.com')) && dev.isDesktop) {
      return { block: true, reason: 'Facebook Library/Moderator' };
    }

    // Regra 4: Geo (País)
    if (geoData && geoData.country) {
      const allowed = serverRules.allowed_countries || [];
      const blocked = serverRules.blocked_countries || [];

      if (allowed.length > 0 && !allowed.includes(geoData.country)) return { block: true, reason: `Geo Country: ${geoData.country}` };
      if (blocked.includes(geoData.country)) return { block: true, reason: `Geo Blocked: ${geoData.country}` };
    }

    // Regra 5: VPN/Datacenter (Via ISP da API Geo)
    // (Lógica aplicada pelo servidor, mas podemos checar aqui se a API retornar 'hosting' ou 'datacenter')

    return { block: false };
  }

  // 🚀 8. EXECUÇÃO PRINCIPAL
  async function run() {
    // A. Sync Block (Decisão em < 5ms baseada no que temos agora)
    const fastBot = isBot();
    const fastDev = getDevice();

    // Se detectarmos bot óbvio agora, tchau.
    if (CFG.RULES.bots && fastBot.check) {
      sendHit({ blocked: true, reason: fastBot.reason }, true); // Fire & Forget
      window.location.replace(CFG.SAFE_URL);
      return;
    }

    // Se for desktop óbvio e regra 'desktop' for true (padrão hardcoded true até carregar config)
    // Nota: Usamos config padrão (RULES) até a API responder.
    if (CFG.RULES.desktop && fastDev.isDesktop) {
      sendHit({ blocked: true, reason: 'Fast Desktop Block' }, true);
      window.location.replace(CFG.SAFE_URL);
      return;
    }

    try {
      // B. Carregar Config & Geo do Servidor (Async)
      const res = await fetch(`${CFG.API}/api/config/${CFG.ID}`);
      const data = await res.json();

      // Atualizar regras locais
      CFG.RULES = {
        desktop: !!data.block_desktop,
        fb_lib: !!data.block_facebook_library,
        bots: !!data.block_bots,
        devtools: !!data.block_devtools,
        allowed_countries: data.allowed_countries ? data.allowed_countries.split(',') : [],
        blocked_countries: data.blocked_countries ? data.blocked_countries.split(',') : []
      };
      if (data.redirect_url) CFG.SAFE_URL = data.redirect_url;

      // C. Decisão Final (Com dados do servidor + Geo)
      const geo = await getGeo(); // Pega IP/País de API externa
      const decision = shouldBlock(CFG.RULES, geo);

      const hitData = {
        blocked: decision.block,
        blockReason: decision.reason,
        geo: geo,
        ...collectFingerprint()
      };

      await sendHit(hitData);

      if (decision.block) {
        window.location.replace(CFG.SAFE_URL);
      } else {
        // PERMITIDO! Mostra a página.
        showPage();
        // Inicia proteção ativa (DevTools)
        if (CFG.RULES.devtools) guard();
      }

    } catch (e) {
      // Fallback em caso de erro de rede: Mostra página (melhor perder cloaking do que perder venda real)
      console.warn('Cloaker FailOpen:', e);
      showPage();
    }
  }

  // 📡 Utilitários de Rede/Coleta
  function sendHit(data, sync = false) {
    const payload = {
      siteId: CFG.ID,
      visitorId: getVid(),
      url: _0x.loc.href,
      ref: _0x.doc.referrer,
      ua: _0x.nav.userAgent,
      ...data
    };

    const url = `${CFG.API}/api/track`;
    if (sync && _0x.nav.sendBeacon) {
      _0x.nav.sendBeacon(url, JSON.stringify(payload));
    } else {
      return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    }
  }

  function getVid() {
    let v = _0x.st.getItem('_vid');
    if (!v) {
      v = 'v.' + Math.random().toString(36).substring(2) + '.' + Date.now().toString(36);
      _0x.st.setItem('_vid', v);
    }
    return v;
  }

  async function getGeo() {
    try {
      // Timeout de 1.5s - Se a API demorar, assumimos "Unknown" e liberamos o acesso.
      // Performance > Geo Blocking.
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 1500);
      const r = await fetch('https://ipapi.co/json/', { signal: controller.signal });
      clearTimeout(id);
      return await r.json();
    } catch { return {}; }
  }

  function collectFingerprint() {
    // Dados extras para o "Sherlock" analisar no backend depois
    return {
      screen: `${window.screen.width}x${window.screen.height}`,
      cores: _0x.nav.hardwareConcurrency,
      mem: _0x.nav.deviceMemory,
      params: (() => {
        const p = {};
        for (let i = 0; i < _0x.ss.length; i++) {
          const k = _0x.ss.key(i);
          if (k.startsWith('_cp_')) p[k.replace('_cp_', '')] = _0x.ss.getItem(k);
        }
        return p;
      })()
    };
  }

  function showPage() {
    if (_0x.body) {
      _0x.body.style.removeProperty('visibility');
      _0x.body.style.removeProperty('opacity');
    }
  }

  // 🛡️ Proteção Ativa (DevTools)
  function guard() {
    function kill() { window.location.replace(CFG.SAFE_URL); }

    // Teclas
    document.addEventListener('keydown', e => {
      if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && 'I'.includes(e.key.toUpperCase()))) {
        e.preventDefault(); kill();
      }
    });

    // Clique direito
    document.addEventListener('contextmenu', e => e.preventDefault());

    // Detecção de Resize (DevTools dock)
    let w = window.outerWidth - window.innerWidth > 160;
    let h = window.outerHeight - window.innerHeight > 160;
    if (w || h) kill();

    window.addEventListener('resize', () => {
      if ((window.outerWidth - window.innerWidth > 160) || (window.outerHeight - window.innerHeight > 160)) kill();
    });
  }

  // Start
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run);
  else run();

})();
