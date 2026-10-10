'use strict';
/* 全聚合网页版：与 APK 相同的节点、登录(sessionid)派生与接口。
   sessionid 算法（逆向自 Lj6/c;->b 与 LoginActivity.m0）：
   deviceJSON -> GZIP -> AES/CBC/PKCS7 加密，
   key = MD5(APP_KEY)[0:16]，iv = MD5(APP_KEY)[16:32]，输出 Base64。
   设备字段里的 ChipId/Random 在浏览器里用持久化随机值代替（APK 取自 /proc/cpuinfo 等）。 */
const APP_KEY = 'a0eb8ef7f1fcbc0559b1f02c00d5a1f8';
const DEFAULT_NODES = {
  https: ['https://mesh.vstvip.us', 'https://154.37.216.207', 'https://51.81.245.167',
          'https://54.39.18.51', 'https://149.56.243.28'],
  udp: ['udp://149.56.17.162:5950', 'udp://51.81.245.167:5812',
        'udp://149.56.243.28:5369', 'udp://54.39.18.51:5949']
};
const LS = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
  del(k) { try { localStorage.removeItem(k); } catch (e) {} }
};
let session = LS.get('vst_session', null);        // {node, sessionid, code}
let settings = LS.get('vst_settings', { proxy: '' });
let config = null;                                 // 点播配置（api/v3/json）
let curSite = null, curCat = '', curPage = 1, curKeyword = '';
let liveGroups = [], liveEpg = '';

function $(sel, el) { return (el || document).querySelector(sel); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function toast(msg) {
  const t = $('#toast'); if (!t) return;
  t.textContent = msg; t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 2200);
}
function persistId(key, gen) {
  let v = LS.get(key, '');
  if (!v) { v = gen(); LS.set(key, v); }
  return v;
}
function randHex(n) {
  const a = new Uint8Array(n);
  (window.crypto || {}).getRandomValues ? crypto.getRandomValues(a) : a.forEach((_, i) => a[i] = Math.floor(Math.random() * 256));
  return [...a].map(x => x.toString(16).padStart(2, '0')).join('');
}

/* ---------- MD5（浏览器 WebCrypto 不支持，纯 JS 实现） ---------- */
function md5(input) {
  function rl(n, c) { return (n << c) | (n >>> (32 - c)); }
  function add(x, y) { const l = (x & 0xffff) + (y & 0xffff), m = (x >> 16) + (y >> 16) + (l >> 16); return (m << 16) | (l & 0xffff); }
  function cm(q, a, b, x, s, t) { return add(rl(add(add(a, q), add(x, t)), s), b); }
  function ff(a, b, c, d, x, s, t) { return cm((b & c) | (~b & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cm((b & d) | (c & ~d), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cm(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cm(c ^ (b | ~d), a, b, x, s, t); }
  const bytes = new TextEncoder().encode(input);
  const bitLen = bytes.length * 8;
  const withPad = Array.from(bytes);
  withPad.push(0x80);
  while (withPad.length % 64 !== 56) withPad.push(0);
  for (let i = 0; i < 8; i++) withPad.push(Math.floor(bitLen / Math.pow(2, 8 * i)) % 256);
  const M = [];
  for (let i = 0; i < withPad.length; i += 4)
    M.push(withPad[i] | (withPad[i + 1] << 8) | (withPad[i + 2] << 16) | (withPad[i + 3] << 24));
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const K = [];
  for (let i = 0; i < 64; i++) K.push(Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296));
  const F = [
    (x, y, z) => (x & y) | (~x & z),
    (x, y, z) => (x & z) | (y & ~z),
    (x, y, z) => x ^ y ^ z,
    (x, y, z) => y ^ (x | ~z)
  ];
  for (let chunk = 0; chunk < M.length; chunk += 16) {
    const v = [a, b, c, d], ov = [a, b, c, d];
    for (let i = 0; i < 64; i++) {
      const round = Math.floor(i / 16);
      let g;
      if (round === 0) g = i;
      else if (round === 1) g = (5 * i + 1) % 16;
      else if (round === 2) g = (3 * i + 5) % 16;
      else g = (7 * i) % 16;
      const ti = [0, 3, 2, 1][i % 4], bi = (ti + 1) % 4, ci = (ti + 2) % 4, di = (ti + 3) % 4;
      const f = F[round](v[bi], v[ci], v[di]);
      v[ti] = add(v[bi], rl(add(add(v[ti], f), add(M[chunk + g], K[i])), S[round * 4 + (i % 4)]));
    }
    a = add(v[0], ov[0]); b = add(v[1], ov[1]); c = add(v[2], ov[2]); d = add(v[3], ov[3]);
  }
  return [a, b, c, d].map(n => {
    let s = '';
    for (let i = 0; i < 4; i++) s += ((n >> (8 * i)) & 0xff).toString(16).padStart(2, '0');
    return s;
  }).join('');
}

/* ---------- gzip / zlib / base64 ---------- */
async function streamBytes(text, mode) {
  const cs = mode === 'gzip' ? new CompressionStream('gzip') : new DecompressionStream('deflate');
  const stream = new Blob([text]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function gzipBytes(text) { return streamBytes(text, 'gzip'); }
async function inflateBytes(bytes) {
  const ds = new DecompressionStream('deflate');
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
function b64encode(bytes) {
  let s = '';
  bytes.forEach(b => s += String.fromCharCode(b));
  return btoa(s);
}
function b64decode(str) {
  const bin = atob(str.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
/* APK 的 "TV" 编码：整串 Base64 解码 -> 前两字节换成 zlib 头 0x78 0x9C -> 解压 */
async function decodeTV(text) {
  const raw = b64decode(text.trim());
  raw[0] = 0x78; raw[1] = 0x9c;
  return new TextDecoder().decode(await inflateBytes(raw));
}
async function maybeDecodeTV(text) {
  const t = (text || '').trim();
  return t.startsWith('TV') ? decodeTV(t) : text;
}

/* ---------- sessionid 派生（复刻 APK） ---------- */
function deviceJson(code) {
  const lang = (navigator.language || 'zh-CN').replace('_', '-');
  return JSON.stringify({
    Lan: '', Wifi: '',
    AndroidId: persistId('vst_android_id', () => randHex(8)),
    Model: (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || 'Web',
    AppVersion: '2.1.2', AppCode: 32, AppName: '全聚合',
    AndroidAPI: 0, CPU_ABI: 'web',
    Phone: code, Language: lang,
    BuildTime: '20260426204142', BetaTIME: '20260416001',
    ChipId: '',
    Random: persistId('vst_random', () => randHex(16))
  });
}
async function makeSessionId(code) {
  const hash = md5(APP_KEY);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(hash.slice(0, 16)), 'AES-CBC', false, ['encrypt']);
  const gz = await gzipBytes(deviceJson(code));
  const enc = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new TextEncoder().encode(hash.slice(16, 32)) }, key, gz);
  return b64encode(new Uint8Array(enc)).replace(/\n/g, '');
}

/* ---------- 网络 ---------- */
function proxied(url) {
  return settings.proxy ? settings.proxy + encodeURIComponent(url) : url;
}
async function fetchRaw(url, opts) {
  opts = opts || {};
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeout || 15000);
  try {
    const res = await fetch(proxied(url), { headers: opts.headers || {}, signal: ctl.signal });
    return res;
  } finally { clearTimeout(timer); }
}
async function fetchText(url, opts) {
  const res = await fetchRaw(url, opts);
  const text = await res.text();
  if (!res.ok && !text) throw new Error('HTTP ' + res.status + ' ' + url);
  return maybeDecodeTV(text);
}
function authHeaders(extra) {
  return Object.assign(session && session.sessionid ? { sessionid: session.sessionid } : {}, extra || {});
}

/* ---------- 点播配置（api/v3/json，回退 api/v2/api） ---------- */
async function loadConfig() {
  if (config) return config;
  let lastErr = null;
  for (const path of ['/api/v3/json', '/api/v2/api']) {
    try {
      const text = await fetchText(session.node + path, { headers: authHeaders() });
      const obj = JSON.parse(text);
      if (obj && (obj.sites || obj.lives)) { config = obj; return config; }
      lastErr = new Error(path + ' 返回的不是配置 JSON');
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('配置加载失败');
}
function vodSites() {
  if (!config || !config.sites) return [];
  return config.sites.filter(s => s && s.api && /^https?:\/\//.test(s.api) && [0, 1, undefined].includes(s.type));
}

/* ---------- CMS 接口（TVBox/MacCMS JSON 与 XML） ---------- */
function cmsUrl(site, params) {
  const sep = site.api.includes('?') ? '&' : '?';
  const qs = Object.entries(params).filter(([, v]) => v !== '' && v != null)
    .map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');
  return site.api + sep + qs;
}
function parseXmlList(text) {
  const doc = new DOMParser().parseFromString(text, 'text/xml');
  const classes = [...doc.querySelectorAll('class ty')].map(t => ({ type_id: t.getAttribute('id'), type_name: t.textContent }));
  const list = [...doc.querySelectorAll('list video')].map(v => {
    const g = t => { const n = v.querySelector(t); return n ? n.textContent : ''; };
    return { vod_id: g('id'), vod_name: g('name'), vod_pic: g('pic'), vod_remarks: g('note'),
             vod_actor: g('actor'), vod_director: g('director'), vod_content: g('des'),
             vod_play_from: g('source'), vod_play_url: (v.querySelector('dl dd') || {}).textContent || '' };
  });
  const pagecount = parseInt((doc.querySelector('list') || {}).getAttribute?.('pagecount') || '1', 10);
  return { class: classes, list, pagecount };
}
async function cmsList(site, params) {
  const text = await fetchText(cmsUrl(site, Object.assign({ ac: 'list' }, params)), { headers: authHeaders() });
  const t = text.trim();
  if (t.startsWith('<')) return parseXmlList(t);
  const obj = JSON.parse(t);
  return { class: obj.class || [], list: obj.list || [], pagecount: obj.pagecount || 1, total: obj.total || 0 };
}
async function cmsDetail(site, id) {
  const text = await fetchText(cmsUrl(site, { ac: 'detail', ids: id }), { headers: authHeaders() });
  const t = text.trim();
  if (t.startsWith('<')) { const r = parseXmlList(t); return r.list[0]; }
  const obj = JSON.parse(t);
  return (obj.list || [])[0];
}
function splitPlay(vod) {
  const froms = String(vod.vod_play_from || '').split('$$$');
  const groups = String(vod.vod_play_url || '').split('$$$');
  return froms.map((name, i) => ({
    name: name || ('线路' + (i + 1)),
    episodes: (groups[i] || '').split('#').filter(Boolean).map(ep => {
      const idx = ep.indexOf('$');
      return idx >= 0 ? { name: ep.slice(0, idx), url: ep.slice(idx + 1) } : { name: '正片', url: ep };
    })
  })).filter(g => g.episodes.length);
}
function addHistory(item) {
  const h = LS.get('vst_history', []).filter(x => x.key !== item.key);
  h.unshift(Object.assign({ at: Date.now() }, item));
  LS.set('vst_history', h.slice(0, 60));
}
function toggleFav(item) {
  let f = LS.get('vst_fav', []);
  if (f.some(x => x.key === item.key)) { f = f.filter(x => x.key !== item.key); toast('已取消收藏'); }
  else { f.unshift(item); toast('已收藏'); }
  LS.set('vst_fav', f);
}
function isFav(key) { return LS.get('vst_fav', []).some(x => x.key === key); }

/* ---------- 直播解析（JSON / M3U / TXT，兼容 FongMi 格式） ---------- */
function parseLiveText(text) {
  const t = (text || '').trim();
  if (!t) return [];
  if (t.startsWith('#EXTM3U')) return parseM3U(t);
  if (t.startsWith('{') || t.startsWith('[')) {
    const obj = JSON.parse(t);
    return parseLiveJson(obj);
  }
  return parseLiveTxt(t);
}
function parseLiveJson(obj) {
  const groups = [];
  const pushChan = (gname, ch) => {
    if (!ch) return;
    const name = ch.name || ch.title || '';
    let urls = ch.urls || ch.url || ch.address || [];
    if (typeof urls === 'string') urls = [urls];
    if (!name || !urls.length) return;
    let g = groups.find(x => x.name === gname);
    if (!g) { g = { name: gname, channels: [] }; groups.push(g); }
    g.channels.push({ name, urls, logo: ch.logo || ch.pic || '', id: ch.id || ch.tvgId || name });
  };
  if (Array.isArray(obj)) {
    obj.forEach(item => {
      if (item && item.channels) (item.channels || []).forEach(ch => pushChan(item.group || item.name || '默认', ch));
      else if (item && (item.url || item.urls)) pushChan('默认', item);
      else if (item && item.name && item.url) pushChan(item.name, { name: item.name, urls: [] }); // lives 型在上层处理
    });
    return groups;
  }
  if (obj.epg) liveEpg = obj.epg;
  (obj.groups || []).forEach(g => (g.channels || []).forEach(ch => pushChan(g.group || g.name || '默认', ch)));
  (obj.channels || []).forEach(ch => pushChan(ch.group || '默认', ch));
  return groups;
}
function parseM3U(text) {
  const groups = [], byName = {};
  let cur = null;
  text.split(/\r?\n/).forEach(line => {
    line = line.trim();
    if (line.startsWith('#EXTINF')) {
      const name = line.split(',').pop().trim();
      const g = (line.match(/group-title="([^"]*)"/) || [])[1] || '默认';
      const logo = (line.match(/tvg-logo="([^"]*)"/) || [])[1] || '';
      const id = (line.match(/tvg-id="([^"]*)"/) || [])[1] || name;
      cur = { name, urls: [], logo, id, group: g };
    } else if (line && !line.startsWith('#') && cur) {
      cur.urls.push(line);
      let g = byName[cur.group];
      if (!g) { g = { name: cur.group, channels: [] }; byName[cur.group] = g; groups.push(g); }
      g.channels.push(cur); cur = null;
    }
  });
  return groups;
}
function parseLiveTxt(text) {
  const groups = [];
  let cur = { name: '默认', channels: [] };
  groups.push(cur);
  text.split(/\r?\n/).forEach(line => {
    line = line.trim();
    if (!line) return;
    if (line.includes(',#genre#')) { cur = { name: line.split(',')[0], channels: [] }; groups.push(cur); return; }
    const idx = line.indexOf(',');
    if (idx > 0) {
      const name = line.slice(0, idx).trim(), url = line.slice(idx + 1).trim();
      if (url) cur.channels.push({ name, urls: [url], logo: '', id: name });
    }
  });
  return groups.filter(g => g.channels.length);
}
async function loadLiveGroups() {
  const text = await fetchText(session.node + '/api/v3/live', { headers: authHeaders() });
  let groups = parseLiveText(text);
  // lives 型配置：JSON 里 lives[].url 各自指向一份播放列表
  try {
    const obj = JSON.parse(text.trim());
    const lives = obj.lives || (Array.isArray(obj) ? obj.filter(x => x && x.url && !x.channels) : []);
    for (const live of lives) {
      if (live.epg && !liveEpg) liveEpg = live.epg;
      if (live.url && /^https?:\/\//.test(live.url)) {
        try {
          const sub = await fetchText(live.url, { headers: authHeaders() });
          groups = groups.concat(parseLiveText(sub));
        } catch (e) { /* 单个 lives 源失败不阻断 */ }
      }
    }
  } catch (e) { /* 非 JSON 忽略 */ }
  return groups;
}
/* 按频道换播放地址（api/v3/liveids，复刻 Ld6/f;->e） */
async function livePlayUrl(channel) {
  const first = (channel.urls || [])[0] || '';
  if (/^https?:\/\//.test(first) && /\.(m3u8|mp4|flv|ts)(\?|$)/i.test(first)) return { url: first };
  if (/^https?:\/\//.test(first) && channel.urls.length === 1 && !/tvbus/i.test(first)) return { url: first };
  const chid = channel.id || channel.name;
  const text = await fetchText(session.node + '/api/v3/liveids', {
    headers: authHeaders({ language: (navigator.language || 'zh-CN').replace('_', '-'), chid })
  });
  const obj = JSON.parse(text);
  if (obj.id && /^https?:\/\//.test(obj.id)) return { url: obj.id };
  if (obj.uuid) return { uuid: obj.uuid };
  if (first) return { url: first };
  throw new Error('liveids 未返回可播放地址');
}

/* ---------- 播放器 ---------- */
let hlsInst = null;
function attachStream(video, url) {
  if (hlsInst) { hlsInst.destroy(); hlsInst = null; }
  if (/\.m3u8(\?|$)/i.test(url) && window.Hls && Hls.isSupported()) {
    hlsInst = new Hls({ maxBufferLength: 30 });
    hlsInst.loadSource(url);
    hlsInst.attachMedia(video);
    hlsInst.on(Hls.Events.MANIFEST_PARSED, () => video.play().catch(() => {}));
  } else {
    video.src = url;
    video.play().catch(() => {});
  }
}

/* ---------- 界面骨架 ---------- */
const app = typeof document !== 'undefined' ? document.getElementById('app') : null;
function clockText() {
  const d = new Date();
  return d.toLocaleDateString('zh-CN') + ' ' + d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
}
function shell(active, title) {
  app.innerHTML = `
    <div class="topbar">
      <span class="logo">全聚合</span><span>${esc(title || '')}</span>
      <span class="clock">${clockText()}</span>
      <nav class="tabs">
        <button data-nav="home" class="${active === 'home' ? 'active' : ''}">首页</button>
        <button data-nav="live" class="${active === 'live' ? 'active' : ''}">直播</button>
        <button data-nav="search" class="${active === 'search' ? 'active' : ''}">搜索</button>
        <button data-nav="history" class="${active === 'history' ? 'active' : ''}">历史</button>
        <button data-nav="fav" class="${active === 'fav' ? 'active' : ''}">收藏</button>
        <button data-nav="settings" class="${active === 'settings' ? 'active' : ''}">设置</button>
      </nav>
    </div>
    <main id="view"></main>`;
  app.querySelectorAll('[data-nav]').forEach(b => b.addEventListener('click', () => views[b.dataset.nav]()));
  return $('#view');
}
function errorBox(view, e, hint) {
  view.innerHTML = `<div class="empty"><p class="error">${esc(e.message || e)}</p>
    <p>${esc(hint || '多半是服务器未开启跨域（CORS）：可在「设置」里填一个 CORS 代理前缀，或换节点重试。')}</p></div>`;
}

/* ---------- 登录（仿 APK LoginActivity） ---------- */
async function renderLogin(msg) {
  document.title = '全聚合 · 登录';
  app.innerHTML = `
  <div class="login-wrap"><div class="login-card">
    <h1>全聚合</h1><div class="ver">网页版 · 与 APK 相同的节点与登录方式（授权码 → sessionid）</div>
    <label>授权码（APK 里的登录码）</label>
    <input id="lg-code" type="text" placeholder="请输入授权码" value="${esc(session ? session.code : '')}">
    <label>服务器节点（登录时自动测速，也可手动指定）</label>
    <select id="lg-node">${DEFAULT_NODES.https.map(n => `<option ${session && session.node === n ? 'selected' : ''}>${n}</option>`).join('')}</select>
    <div class="row-btns">
      <button class="primary" id="lg-go">登录</button>
      <button id="lg-skip">先看看（不登录）</button>
    </div>
    <div class="node-test" id="lg-status">${esc(msg || '')}</div>
    <div class="warn">浏览器与电视盒不同：节点服务器若未开启 CORS，直连会被浏览器拦截，
      登录/加载失败时请到「设置」填 CORS 代理前缀再试；UDP/P2P（TVBus）频道流浏览器无法直接拉取，会给出提示。</div>
    <div class="login-foot">唯一TG電報群:@VSTSVIP　最新版APP下載網址:https://app.vstvip.us/</div>
  </div></div>`;
  $('#lg-go').addEventListener('click', async () => {
    const code = $('#lg-code').value.trim();
    const status = $('#lg-status');
    if (!code) { status.textContent = '请先输入授权码'; return; }
    try {
      status.textContent = '正在派生 sessionid 并测速节点…';
      const sid = await makeSessionId(code);
      const prefer = $('#lg-node').value;
      const nodes = [prefer, ...DEFAULT_NODES.https.filter(n => n !== prefer)];
      let chosen = null; const lines = [];
      for (const n of nodes) {
        const t0 = performance.now();
        try {
          await fetchText(n + '/v6/test.json', { headers: { sessionid: sid }, timeout: 8000 });
          lines.push('✓ ' + n + ' ' + Math.round(performance.now() - t0) + 'ms');
          if (!chosen) chosen = n;
        } catch (e) { lines.push('✗ ' + n + ' ' + (e.message || e)); }
        status.textContent = lines.join('\n');
      }
      if (!chosen) {
        status.textContent += '\n所有节点直连失败（多为 CORS 拦截）。已保存登录信息，可进设置填代理后重试，或点「先看看」进入。';
        session = { node: prefer, sessionid: sid, code };
        LS.set('vst_session', session);
        return;
      }
      session = { node: chosen, sessionid: sid, code };
      LS.set('vst_session', session);
      toast('登录成功，节点 ' + chosen);
      views.home();
    } catch (e) { status.textContent = '登录失败：' + (e.message || e); }
  });
  $('#lg-skip').addEventListener('click', () => {
    session = session || { node: $('#lg-node').value, sessionid: '', code: '' };
    LS.set('vst_session', session);
    views.home();
  });
}

/* ---------- 首页 / 点播 ---------- */
async function renderHome() {
  if (!session) return renderLogin();
  document.title = '全聚合 · 首页';
  const view = shell('home', '点播');
  view.innerHTML = '<p class="empty">正在加载配置…</p>';
  try {
    await loadConfig();
    const sites = vodSites();
    if (!sites.length) { view.innerHTML = '<p class="empty">配置里没有可用的点播站点（sites）</p>'; return; }
    if (!curSite || !sites.includes(curSite)) curSite = sites[0];
    view.innerHTML = `
      <div class="toolbar">
        <span>站点</span>
        <select id="site-sel">${sites.map(s => `<option value="${esc(s.key)}" ${s === curSite ? 'selected' : ''}>${esc(s.name)}</option>`).join('')}</select>
        <span class="spacer"></span>
        <input id="home-q" type="search" placeholder="搜索影片…" style="min-width:200px">
        <button id="home-search">搜索</button>
      </div>
      <div class="chips" id="cats"></div>
      <div class="grid" id="grid"></div>
      <div class="pager" id="pager"></div>`;
    $('#site-sel').addEventListener('change', e => {
      curSite = sites.find(s => s.key === e.target.value); curCat = ''; curPage = 1; loadList();
    });
    $('#home-search').addEventListener('click', () => { curKeyword = $('#home-q').value.trim(); views.search(curKeyword); });
    $('#home-q').addEventListener('keydown', e => { if (e.key === 'Enter') $('#home-search').click(); });
    loadList();
  } catch (e) { errorBox(view, e); }
}
async function loadList() {
  const grid = $('#grid'), pager = $('#pager'), cats = $('#cats');
  grid.innerHTML = '<p class="empty">加载中…</p>'; pager.innerHTML = '';
  try {
    const r = await cmsList(curSite, { t: curCat, pg: curPage });
    if (cats && !cats.dataset.done) {
      cats.dataset.done = '1';
      cats.innerHTML = [{ type_id: '', type_name: '全部' }, ...(r.class || [])].map(c =>
        `<button class="chip ${String(c.type_id) === String(curCat) ? 'active' : ''}" data-cat="${esc(c.type_id)}">${esc(c.type_name)}</button>`).join('');
      cats.querySelectorAll('[data-cat]').forEach(b => b.addEventListener('click', () => {
        curCat = b.dataset.cat; curPage = 1;
        cats.querySelectorAll('.chip').forEach(x => x.classList.toggle('active', x === b));
        loadList();
      }));
    }
    grid.innerHTML = r.list.length ? '' : '<p class="empty">没有数据</p>';
    r.list.forEach(v => grid.appendChild(vodCard(curSite, v)));
    const pc = r.pagecount || 1;
    pager.innerHTML = `<button id="pg-prev" ${curPage <= 1 ? 'disabled' : ''}>上一页</button>
      <span>第 ${curPage} / ${pc} 页</span>
      <button id="pg-next" ${curPage >= pc ? 'disabled' : ''}>下一页</button>`;
    const prev = $('#pg-prev'), next = $('#pg-next');
    if (prev) prev.addEventListener('click', () => { curPage--; loadList(); });
    if (next) next.addEventListener('click', () => { curPage++; loadList(); });
  } catch (e) { grid.innerHTML = `<p class="error">${esc(e.message || e)}</p>`; }
}
function vodCard(site, v) {
  const div = document.createElement('div');
  div.className = 'card'; div.tabIndex = 0;
  div.innerHTML = `<img loading="lazy" src="${esc(v.vod_pic || '')}" alt="" onerror="this.style.visibility='hidden'">
    <div class="name">${esc(v.vod_name)}</div><div class="remark">${esc(v.vod_remarks || v.vod_year || '')}</div>`;
  const open = () => views.detail(site, v.vod_id);
  div.addEventListener('click', open);
  div.addEventListener('keydown', e => { if (e.key === 'Enter') open(); });
  return div;
}

/* ---------- 搜索 ---------- */
async function renderSearch(keyword) {
  if (!session) return renderLogin();
  const view = shell('search', '搜索');
  view.innerHTML = `
    <div class="toolbar"><input id="q" type="search" placeholder="输入片名关键词" value="${esc(keyword || '')}" style="flex:1;min-width:200px">
    <button class="primary" id="go">搜索</button></div>
    <div class="grid" id="grid" style="margin-top:16px"></div>`;
  const run = async () => {
    const kw = $('#q').value.trim(); if (!kw) return;
    const grid = $('#grid'); grid.innerHTML = '<p class="empty">搜索中…</p>';
    try {
      if (!config) await loadConfig();
      const sites = vodSites();
      if (!curSite || !sites.includes(curSite)) curSite = sites[0];
      const r = await cmsList(curSite, { wd: kw, pg: 1 });
      grid.innerHTML = r.list.length ? '' : '<p class="empty">没有结果</p>';
      r.list.forEach(v => grid.appendChild(vodCard(curSite, v)));
    } catch (e) { grid.innerHTML = `<p class="error">${esc(e.message || e)}</p>`; }
  };
  $('#go').addEventListener('click', run);
  $('#q').addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  if (keyword) run();
}

/* ---------- 详情与播放 ---------- */
async function renderDetail(site, id) {
  const view = shell('home', '详情');
  view.innerHTML = '<p class="empty">加载详情…</p>';
  try {
    const vod = await cmsDetail(site, id);
    if (!vod) throw new Error('未取到详情');
    const groups = splitPlay(vod);
    const key = site.key + ':' + id;
    addHistory({ key, name: vod.vod_name, pic: vod.vod_pic, siteKey: site.key, vodId: id });
    view.innerHTML = `
      <div class="detail-head">
        <img src="${esc(vod.vod_pic || '')}" alt="" onerror="this.style.visibility='hidden'">
        <div class="detail-info">
          <h2>${esc(vod.vod_name)}</h2>
          <p>${esc(vod.vod_class || '')} ${esc(vod.vod_year || '')} ${esc(vod.vod_area || '')}</p>
          <p>主演：${esc(vod.vod_actor || '')}</p>
          <p>导演：${esc(vod.vod_director || '')}</p>
          <p>${esc(vod.vod_content || '')}</p>
          <p><button id="fav">${isFav(key) ? '已收藏' : '收藏'}</button></p>
        </div>
      </div>
      <div id="play-area"></div>
      ${groups.map((g, gi) => `<h3>${esc(g.name)}</h3><div class="eps">${g.episodes.map((ep, ei) =>
        `<button data-g="${gi}" data-e="${ei}">${esc(ep.name)}</button>`).join('')}</div>`).join('') || '<p class="empty">没有播放地址</p>'}`;
    $('#fav').addEventListener('click', e => {
      toggleFav({ key, name: vod.vod_name, pic: vod.vod_pic, siteKey: site.key, vodId: id });
      e.target.textContent = isFav(key) ? '已收藏' : '收藏';
    });
    view.querySelectorAll('[data-g]').forEach(b => b.addEventListener('click', () => {
      view.querySelectorAll('[data-g]').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      const ep = groups[+b.dataset.g].episodes[+b.dataset.e];
      playInto($('#play-area'), ep.url, vod.vod_name + ' · ' + ep.name);
    }));
  } catch (e) { errorBox(view, e, '详情加载失败，可换个站点或检查设置中的代理。'); }
}
function playInto(area, url, title) {
  if (!area) return;
  if (/tvbus:\/\//i.test(url)) {
    area.innerHTML = `<div class="warn">该地址是 TVBus/P2P 流（${esc(url)}），浏览器无法直接播放，请在 APK 里观看。</div>`;
    return;
  }
  area.innerHTML = `<h3>${esc(title || '')}</h3><video class="big" controls playsinline></video>
    <p class="now">地址：<code>${esc(url)}</code></p>`;
  attachStream(area.querySelector('video'), proxied(url));
}

/* ---------- 直播 ---------- */
async function renderLive() {
  if (!session) return renderLogin();
  document.title = '全聚合 · 直播';
  const view = shell('live', '直播');
  view.innerHTML = '<p class="empty">正在加载直播列表…</p>';
  try {
    liveGroups = await loadLiveGroups();
    if (!liveGroups.length) { view.innerHTML = '<p class="empty">没有取到直播频道（服务器可能要求登录，或被 CORS 拦截）</p>'; return; }
    view.innerHTML = `
      <div class="live-layout">
        <div class="live-side" id="live-side"></div>
        <div>
          <div class="player-box"><video id="live-video" controls playsinline></video></div>
          <div class="now" id="live-now">点左侧频道开始播放</div>
        </div>
      </div>`;
    const side = $('#live-side');
    liveGroups.forEach(g => {
      const h = document.createElement('h3'); h.textContent = g.name + '（' + g.channels.length + '）';
      side.appendChild(h);
      g.channels.forEach(ch => {
        const b = document.createElement('button');
        b.className = 'chan'; b.textContent = ch.name;
        b.addEventListener('click', async () => {
          side.querySelectorAll('.chan').forEach(x => x.classList.remove('active'));
          b.classList.add('active');
          const now = $('#live-now');
          now.innerHTML = '正在获取播放地址：<b>' + esc(ch.name) + '</b>';
          try {
            const r = await livePlayUrl(ch);
            if (r.uuid) {
              now.innerHTML = `<b>${esc(ch.name)}</b> 是 TVBus/P2P 频道（uuid=${esc(r.uuid)}），浏览器无法直接拉流，请在 APK 里观看。`;
              return;
            }
            now.innerHTML = '正在播放：<b>' + esc(ch.name) + '</b>　<code>' + esc(r.url) + '</code>';
            attachStream($('#live-video'), proxied(r.url));
          } catch (e) { now.innerHTML = '<span class="error">' + esc(e.message || e) + '</span>'; }
        });
        side.appendChild(b);
      });
    });
  } catch (e) { errorBox(view, e); }
}

/* ---------- 历史 / 收藏 ---------- */
function renderStored(kind) {
  if (!session) return renderLogin();
  const view = shell(kind, kind === 'history' ? '历史' : '收藏');
  const items = LS.get(kind === 'history' ? 'vst_history' : 'vst_fav', []);
  view.innerHTML = items.length ? '<div class="grid" id="grid"></div>' : '<p class="empty">暂无记录</p>';
  if (!items.length) return;
  const grid = $('#grid');
  items.forEach(it => {
    const site = (config && vodSites().find(s => s.key === it.siteKey)) || { key: it.siteKey, name: it.siteKey, api: '' };
    grid.appendChild(vodCard(site, { vod_id: it.vodId, vod_name: it.name, vod_pic: it.pic, vod_remarks: '' }));
  });
  if (!config) loadConfig().catch(() => {});
}

/* ---------- 设置 ---------- */
function renderSettings() {
  const view = shell('settings', '设置');
  view.innerHTML = `
    <dl class="kv">
      <dt>当前节点</dt><dd>${esc(session ? session.node : '未登录')}</dd>
      <dt>授权码</dt><dd>${esc(session ? session.code : '')}</dd>
      <dt>sessionid</dt><dd>${session && session.sessionid ? esc(session.sessionid.slice(0, 40)) + '…' : '无'}</dd>
    </dl>
    <h3>CORS 代理前缀</h3>
    <p style="color:var(--muted);font-size:14px">服务器没开跨域时，浏览器会拦截所有请求。可填一个你信任的代理前缀，
    请求会变成「前缀 + 编码后的真实地址」。注意：走代理时 sessionid 等请求头可能被丢弃，直播 liveids 可能受影响。</p>
    <p><input id="set-proxy" style="width:min(560px,90%)" placeholder="例如 https://corsproxy.io/?url=" value="${esc(settings.proxy)}">
    <button id="set-proxy-save">保存</button></p>
    <h3>数据</h3>
    <p><button id="set-logout">退出登录</button> <button id="set-clear">清除历史与收藏</button></p>
    <h3>节点一览（逆向自 APK）</h3>
    <p>${DEFAULT_NODES.https.map(n => '<code>' + n + '</code>').join('<br>')}</p>
    <p>${DEFAULT_NODES.udp.map(n => '<code>' + n + '</code>').join('<br>')}</p>`;
  $('#set-proxy-save').addEventListener('click', () => {
    settings.proxy = $('#set-proxy').value.trim();
    LS.set('vst_settings', settings); config = null; toast('已保存');
  });
  $('#set-logout').addEventListener('click', () => { session = null; config = null; LS.del('vst_session'); renderLogin(); });
  $('#set-clear').addEventListener('click', () => { LS.del('vst_history'); LS.del('vst_fav'); toast('已清除'); });
}

const views = {
  home: renderHome, live: renderLive, search: renderSearch,
  detail: renderDetail, history: () => renderStored('history'),
  fav: () => renderStored('fav'), settings: renderSettings
};
if (app) { session ? views.home() : renderLogin(); }
if (typeof module !== 'undefined') module.exports = { md5, parseLiveText, splitPlay, deviceJson, makeSessionId, decodeTV };
