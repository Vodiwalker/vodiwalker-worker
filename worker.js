import { connect } from 'cloudflare:sockets';

/* ─────────────────────────── ثابت‌ها ─────────────────────────── */
const VERSION = '2.3';
const WS_PATH = '/ws';
const KV_CLIENTS = 'vw_clients_v21';
const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const ALLOWED_PORTS = [443, 2053, 2083, 2087, 2096, 8443, 80, 8080, 8880, 2052, 2082, 2086, 2095];
const BG_IMAGE = 'https://z-cdn-media.chatglm.cn/files/d006b6a8-f1de-4a0f-8ba2-0c1c28d9e176.jpg?auth_key=1889289361-5c6ee6159b7b413cbb23f1a2ad42d602-0-49ea3365dc98f9f7159d8410c901ff2d';

/* ─────────────────────────── ابزارهای عمومی ─────────────────────────── */
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (ch) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
  });
}

function randomHex(len) {
  const bytes = new Uint8Array(Math.ceil(len / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').slice(0, len);
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
}

function strToB64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64ToBytes(b64) {
  let s = String(b64).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function wsToBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof data === 'string') return new TextEncoder().encode(data);
  if (data && typeof data.arrayBuffer === 'function') return new Uint8Array(await data.arrayBuffer());
  return new Uint8Array(0);
}

function getAddress(env, request, url) {
  // آدرس کانفیگ همیشه از همان Worker/دامنه‌ای که درخواست از آن آمده گرفته می‌شود؛
  // بدون هیچ مقدار ثابت یا فرضِ از پیش تعیین‌شده، پس روی هر Worker کلودفلری —
  // زیردامنه‌ی *.workers.dev، Custom Domain، یا Route روی یک Zone — بدون نیاز
  // به تغییر کد به همان آدرسی که کاربر واقعاً از آن وصل شده اشاره می‌کند.
  // اولویت با هدر Host است چون دقیقاً همان چیزی‌ست که کلاینت واقعاً درخواست
  // داده (استاندارد HTTP و همیشه در دسترس)؛ url.hostname و env.ADDRESS فقط
  // به‌عنوان بک‌آپ برای شرایط غیرمعمول نگه داشته شده‌اند.
  let addr = String(
    (request && request.headers && request.headers.get('Host')) ||
    (url && url.hostname) ||
    env.ADDRESS || ''
  ).trim().toLowerCase();
  addr = addr.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  return addr || 'localhost';
}

async function getConfiguredProxyIPs(env) {
  try {
    const settings = await loadSettings(env);
    if (settings.proxyIP && settings.proxyIP.host) {
      return [{ host: settings.proxyIP.host, port: Number(settings.proxyIP.port) || 443 }];
    }
  } catch (e) {}
  return [];
}

/* ─────────────────────────── SHA-224 (برای پروتکل Trojan) ─────────────────────────── */
const SHA224_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

function sha224hex(input) {
  const msg = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  const len = msg.length;
  const totalLen = (((len + 9) + 63) >> 6) << 6;
  const padded = new Uint8Array(totalLen);
  padded.set(msg);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(totalLen - 8, Math.floor(len / 536870912));
  dv.setUint32(totalLen - 4, (len * 8) >>> 0);

  const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const w = new Array(64);

  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2];
      const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      w[i] = (s0 + w[i - 16] + w[i - 7] + s1) | 0;
    }
    let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA224_K[i] + w[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
  }
  let out = '';
  for (let i = 0; i < 7; i++) out += (h[i] >>> 0).toString(16).padStart(8, '0');
  return out;
}

/* ─────────────────────────── مدیریت KV ─────────────────────────── */
async function loadClients(env) {
  const raw = await env.KV.get(KV_CLIENTS);
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) { return []; }
}

async function saveClients(env, clients) {
  await env.KV.put(KV_CLIENTS, JSON.stringify(clients));
}

/* ─────────────────────────── بافر مصرف (نسخه‌ی اصلاح‌شده) ─────────────────────────── */
/* این بخش دو باگ داشت که هر دو اینجا رفع شده‌اند:
   ۱) وقتی یک اتصال WebSocket بسته می‌شد، «flushUsage(true)» فراخوانی می‌شد اما
      پارامتر force عملاً نادیده گرفته می‌شد — فقط addUsage صدا زده می‌شد که
      خودش دوباره همان شرط آستانه‌ی ۵ مگابایت/۲ دقیقه را چک می‌کرد. نتیجه:
      اگر یک اتصال کوتاه (کمتر از آستانه) بسته می‌شد، مصرفش در بافرِ
      حافظه‌ای همان ایزوله می‌ماند و چون Cloudflare می‌تواند هر لحظه (به‌خصوص
      بعد از بی‌کاری) آن ایزوله را از حافظه خارج کند، آن مصرف کلاً گم می‌شد و
      هرگز در KV نوشته نمی‌شد — همان چیزی که باعث می‌شد «مصرف می‌کنم ولی از
      حجم کم نمی‌شود».
   ۲) قفل «flushing» به‌صورت یک boolean ساده بود: اگر یک flush دیگر هم‌زمان
      در حال اجرا بود، فراخوانی جدید بی‌سروصدا و بدون هیچ تلاش مجددی رد
      می‌شد؛ این هم می‌توانست مصرفِ بافرشده را گم کند.
   راه‌حل: flushUsageBuffer اکنون با یک زنجیره‌ی Promise سریالایز می‌شود (هیچ
   فراخوانی‌ای رد نمی‌شود، فقط صف می‌شود)، و بستن اتصال حالا واقعاً و
   بدون قید‌وشرط باعث یک نوشتن در KV می‌شود — نه فقط بافر کردن دوباره. */
const USAGE_BUFFER = globalThis.__vwUsageBuffer || (globalThis.__vwUsageBuffer = {});
const USAGE_STATE = globalThis.__vwUsageState || (globalThis.__vwUsageState = { lastFlush: 0, chain: Promise.resolve() });
const USAGE_FLUSH_THRESHOLD = 5 * 1024 * 1024; // ۵ مگابایت، مجموعِ همه‌ی کلاینت‌های در صف
const USAGE_FLUSH_INTERVAL_MS = 2 * 60 * 1000; // حداکثر هر ۲ دقیقه یک‌بار نوشتن (در حالت غیر-اجباری)

function bufferedUsageTotal() {
  let total = 0;
  for (const k in USAGE_BUFFER) total += USAGE_BUFFER[k] || 0;
  return total;
}

async function doFlushUsageBuffer(env) {
  const pendingIds = Object.keys(USAGE_BUFFER).filter(id => USAGE_BUFFER[id] > 0);
  if (pendingIds.length === 0) { USAGE_STATE.lastFlush = Date.now(); return; }
  const snapshot = {};
  for (const id of pendingIds) { snapshot[id] = USAGE_BUFFER[id]; USAGE_BUFFER[id] = 0; }
  try {
    const clients = await loadClients(env);
    let changed = false;
    for (const id in snapshot) {
      const c = clients.find(x => x.id === id);
      if (c) { c.usedBytes = (Number(c.usedBytes) || 0) + snapshot[id]; changed = true; }
    }
    if (changed) await saveClients(env, clients);
    USAGE_STATE.lastFlush = Date.now();
  } catch (e) {
    // نوشتن ناموفق بود (مثلاً سقف روزانه‌ی KV پر شده)؛ مقادیر را به بافر
    // برگردان تا در فرصت بعدی دوباره تلاش شود و داده گم نشود
    for (const id in snapshot) USAGE_BUFFER[id] = (USAGE_BUFFER[id] || 0) + snapshot[id];
  }
}

function flushUsageBuffer(env) {
  // همه‌ی فراخوانی‌های flush روی همین ایزوله با یک زنجیره‌ی Promise واحد
  // سریالایز می‌شوند: هر فراخوانی حتماً بعد از اتمام فراخوانی قبلی اجرا
  // می‌شود، نه اینکه به‌خاطر «در حال اجرا بودن یکی دیگر» نادیده گرفته شود.
  USAGE_STATE.chain = USAGE_STATE.chain.then(
    function () { return doFlushUsageBuffer(env); },
    function () { return doFlushUsageBuffer(env); }
  );
  return USAGE_STATE.chain;
}

async function addUsage(env, clientId, bytes) {
  try {
    if (!bytes || bytes <= 0) return;
    USAGE_BUFFER[clientId] = (USAGE_BUFFER[clientId] || 0) + bytes;
    const dueByTime = (Date.now() - USAGE_STATE.lastFlush) >= USAGE_FLUSH_INTERVAL_MS;
    const dueBySize = bufferedUsageTotal() >= USAGE_FLUSH_THRESHOLD;
    if (dueByTime || dueBySize) await flushUsageBuffer(env);
  } catch (e) {}
}

/* ─────────────────────────── ساخت لینک کانفیگ ─────────────────────────── */
/* connectHost: اگر یک «آی‌پی تمیز» انتخاب شده باشد، اتصال واقعی به آن IP برقرار
   می‌شود ولی Host/SNI همچنان روی دامنه‌ی خود Worker می‌ماند (چون کلودفلر بر اساس
   Host/SNI مسیریابی می‌کند، نه بر اساس IP مقصد؛ این دقیقاً همان تکنیک «کلین آی‌پی» است). */
function buildConfigLinkForPort(client, address, port, connectHost) {
  const host = connectHost || address;
  const name = encodeURIComponent(client.name + (port !== client.port ? ' [' + port + ']' : '') + (connectHost && connectHost !== address ? ' 🚀' : ''));
  const isTLS = TLS_PORTS.includes(Number(port));
  const path = encodeURIComponent(WS_PATH);
  const security = isTLS ? 'tls' : 'none';
  const tlsPart = isTLS ? '&sni=' + address + '&fp=chrome' : '';
  const common = 'security=' + security + tlsPart + '&type=ws&host=' + address + '&path=' + path;
  if (client.protocol === 'trojan') {
    return 'trojan://' + client.uuid + '@' + host + ':' + port + '?' + common + '#' + name;
  }
  return 'vless://' + client.uuid + '@' + host + ':' + port + '?encryption=none&' + common + '#' + name;
}

function buildConfigLink(client, address, connectHost) {
  return buildConfigLinkForPort(client, address, client.port, connectHost);
}

/* ─────────────────────────── تنظیمات پنل (KV) ─────────────────────────── */
const KV_SETTINGS = 'vw_settings_v21';

function defaultSettings() {
  return {
    passHash: null,
    defaultProtocol: 'vless',
    defaultPort: 443,
    remark: '',
    preferredIPs: [],
    proxyIP: null,
    theme: 'dark'
  };
}

async function loadSettings(env) {
  try {
    const raw = await env.KV.get(KV_SETTINGS);
    if (!raw) return defaultSettings();
    const s = JSON.parse(raw);
    const merged = Object.assign(defaultSettings(), s && typeof s === 'object' ? s : {});
    // سازگاری با نسخه‌های قبلی که فقط یک preferredIP تکی (رشته) ذخیره می‌کردند
    if (!Array.isArray(merged.preferredIPs)) merged.preferredIPs = [];
    if (merged.preferredIP && !merged.preferredIPs.length) {
      merged.preferredIPs = [String(merged.preferredIP)];
    }
    delete merged.preferredIP;
    return merged;
  } catch (e) { return defaultSettings(); }
}

async function saveSettings(env, settings) {
  await env.KV.put(KV_SETTINGS, JSON.stringify(settings));
}

/* پیام خطای انسانی برای شکست‌های KV — به‌خصوص وقتی سقف نوشتن روزانه پر شده باشد */
function friendlyKVError(e) {
  const msg = (e && e.message) ? String(e.message) : '';
  if (/limit exceeded/i.test(msg)) {
    return 'سقف روزانه‌ی نوشتن Workers KV (در پلن رایگان معمولاً ۱۰۰۰ نوشتن در روز) پر شده است. این پنل مصرف کاربران را در حافظه بافر می‌کند تا نوشتن‌ها کمینه شوند، اما در ترافیک بسیار سنگین ممکن است باز هم به این سقف برسید. چند دقیقه صبر کنید و دوباره امتحان کنید، یا برای رفع کامل، اکانت کلودفلر را روی پلن Paid ارتقا دهید.';
  }
  return msg || 'نامشخص';
}

/* رمز مؤثر پنل: اگر رمز سفارشی از داخل پنل ثبت شده باشد، همان اولویت دارد؛ در غیر این صورت متغیر ADMIN */
async function effectiveAdminHash(env, adminPass) {
  const settings = await loadSettings(env);
  if (settings.passHash) return settings.passHash;
  return sha256hex(adminPass);
}

async function checkLoginPassword(env, adminPass, input) {
  const settings = await loadSettings(env);
  if (settings.passHash) return (await sha256hex(String(input || ''))) === settings.passHash;
  return String(input || '') === adminPass;
}

/* ── پاک‌سازی کلیدهای واقعاً قدیمیِ نسخه‌های قبل (رفع‌شده) ──
   نسخه‌ی قبلی این تابع با یک «پرچم یک‌بارمصرف» در KV (vw_fresh_init_v21)
   تصمیم می‌گرفت که آیا پاک‌سازی انجام شده یا نه. مشکل این بود: نوشتن‌های
   Workers KV بین نقاط مختلف کلودفلر با تاخیر (eventual consistency، تا
   حدود ۶۰ ثانیه) همگام می‌شوند. اگر درخواست بعدی (مثلاً چند دقیقه بعد، یا
   از نودی دیگر) به پرچمِ هنوز-همگام‌نشده می‌رسید، کد فکر می‌کرد «هنوز
   مقداردهی اولیه نشده» و KV_CLIENTS و KV_SETTINGS — یعنی داده‌ی زنده و
   واقعی کاربر — را دوباره پاک می‌کرد. این همان باگِ «کلاینت‌ها بعد از خروج
   و ورود دوباره به پنل ناپدید می‌شوند» بود.
   نسخه‌ی جدید هیچ پرچمی ندارد و به کلیدهای نسخه‌ی فعلی (KV_CLIENTS/
   KV_SETTINGS) دست نمی‌زند؛ فقط بر اساس وجود واقعیِ کلیدهای خیلی قدیمیِ
   بدون‌پسوند تصمیم می‌گیرد که کاملاً idempotent است و به هیچ حافظه‌ی جداگانه‌ای
   نیاز ندارد. */
/* رفع باگ «هنگ کردن پنل»: این تابع قبلاً روی هر تک درخواست (هر بار باز شدن
   پنل، هر بار refresh خودکار مصرف هر ۱۵ ثانیه تا ۵ دقیقه، هر کلیک روی هر
   دکمه‌ای که به /api می‌زند) دو تا KV.get اضافه و کاملاً بی‌فایده انجام
   می‌داد — برای همیشه، حتی سال‌ها بعد از پاک شدن کلیدهای قدیمی. این یعنی
   هر درخواست پنل عملاً چند round-trip اضافه به KV می‌زد که با تأخیر شبکه
   جمع می‌شد و خصوصاً زیر بار refresh خودکار حس «پنل هنگ کرده» را می‌ساخت.
   حالا این پاک‌سازی فقط یک‌بار در طول عمر هر ایزوله (Worker instance)
   اجرا می‌شود، با یک پرچم سبک در globalThis — دقیقاً همان الگویی که خود
   کد برای بافر مصرف استفاده می‌کند. */
const VW_INIT_STATE = globalThis.__vwInitState || (globalThis.__vwInitState = { done: false });

async function initializeFreshPanel(env) {
  if (VW_INIT_STATE.done) return;
  if (!env.KV || typeof env.KV.get !== 'function') return;
  try {
    const [legacyClients, legacySettings] = await Promise.all([
      env.KV.get('vw_clients'),
      env.KV.get('vw_settings')
    ]);
    const tasks = [];
    if (legacyClients !== null) tasks.push(env.KV.delete('vw_clients'));
    if (legacySettings !== null) tasks.push(env.KV.delete('vw_settings'));
    if (tasks.length) await Promise.all(tasks);
    VW_INIT_STATE.done = true;
  } catch (e) {}
}

/* ═══════════════════════════ ورودی اصلی ═══════════════════════════ */
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();

      /* ── ترافیک پروکسی (WebSocket) — همیشه اول ── */
      if (upgrade === 'websocket') return await handleProxyWS(request, env, ctx);

      const adminPass = String(env.ADMIN || env.PASSWORD || '').trim();
      const hasKV = !!(env.KV && typeof env.KV.get === 'function');

      if (!adminPass || !hasKV) {
        return new Response(setupPage(!adminPass ? 'ADMIN' : 'KV'), {
          status: 500,
          headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' }
        });
      }

      await initializeFreshPanel(env);

      let path = url.pathname.replace(/\/+$/, '') || '/';
      const authed = await isAuthed(request, env);

      /* ── ورود ── */
      if (path === '/login') {
        if (request.method === 'POST') {
          const params = new URLSearchParams(await request.text());
          const pass = String(params.get('password') || '');
          const remember = params.get('remember') === '1';
          if (await checkLoginPassword(env, adminPass, pass)) {
            const secretHash = await effectiveAdminHash(env, adminPass);
            const maxAge = remember ? 2592000 : 86400;
            const res = new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
            res.headers.append('Set-Cookie', 'vw_auth=' + (await sha256hex('vw-session::' + secretHash)) + '; Path=/; Max-Age=' + maxAge + '; HttpOnly; SameSite=Strict');
            return res;
          }
          return new Response(JSON.stringify({ ok: false, error: 'رمز عبور نادرست است' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }
        if (authed) return new Response(null, { status: 302, headers: { Location: url.origin + '/admin' } });
        return html(loginPage());
      }

      /* ── خروج ── */
      if (path === '/logout') {
        return new Response(null, {
          status: 302,
          headers: {
            'Location': url.origin + '/login',
            'Set-Cookie': 'vw_auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict'
          }
        });
      }

      /* ── سابسکریپشن (عمومی) ── */
      if (path.startsWith('/sub/') || path.startsWith('/info/')) return await handleSubscription(request, env, url, path);

      /* ── موارد جزئی ── */
      if (path === '/robots.txt') return new Response('User-agent: *\nDisallow: /', { headers: { 'Content-Type': 'text/plain' } });
      if (path === '/favicon.ico') return new Response(faviconSVG(), { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } });

      /* ── پنل مدیریت ── */
      if (path === '/' || path === '/admin') {
        if (!authed) return new Response(null, { status: 302, headers: { Location: url.origin + '/login' } });
        return html(dashboardPage(getAddress(env, request, url)));
      }

      /* ── API (نیازمند لاگین) ── */
      if (path.startsWith('/api/')) {
        if (!authed) return new Response(JSON.stringify({ ok: false, error: 'لطفاً دوباره وارد شوید' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        try {
          return await handleAPI(request, env, url, path);
        } catch (apiErr) {
          // رفع باگ «پاسخ نامعتبر از سرور»: قبلاً یک خطای پیش‌بینی‌نشده در KV یا
          // پردازش بدنه‌ی درخواست باعث می‌شد کد به catch سراسری برسد و متن ساده
          // برگرداند؛ چون مرورگر همیشه انتظار JSON دارد، این متن ساده باعث خطای
          // parse در سمت کلاینت و پیام مبهم «پاسخ نامعتبر از سرور» می‌شد.
          return new Response(JSON.stringify({ ok: false, error: 'خطای سرور: ' + friendlyKVError(apiErr) }), { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        }
      }

      /* ── صفحه جعلی ۴۰۴ ── */
      return new Response(fakePage(), { status: 404, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    } catch (err) {
      // همین‌جا هم به‌جای متن ساده، JSON برمی‌گردانیم تا هر فراخوانی fetch از
      // سمت پنل (که همیشه r.json() صدا می‌زند) با خطای parse مواجه نشود.
      return new Response(JSON.stringify({ ok: false, error: 'خطای داخلی سرور: ' + friendlyKVError(err) }), { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
    }
  }
};

function html(page) {
  return new Response(page, { headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } });
}

/* ─────────────────────────── احراز هویت ─────────────────────────── */
async function getAuthValue(env) {
  const adminPass = String(env.ADMIN || env.PASSWORD || '').trim();
  const secretHash = await effectiveAdminHash(env, adminPass);
  return sha256hex('vw-session::' + secretHash);
}

async function isAuthed(request, env) {
  const cookies = request.headers.get('Cookie') || '';
  const m = cookies.match(/(?:^|;\s*)vw_auth=([^;]+)/);
  return !!(m && m[1] === (await getAuthValue(env)));
}

/* ─────────────────────────── API پنل ─────────────────────────── */
async function handleAPI(request, env, url, path) {
  const json = (obj, status) => new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
  const address = getAddress(env, request, url);

  if (path === '/api/clients') {
    if (request.method === 'GET') {
      // در حالت refresh دستی، مصرف بافرشده را همین لحظه در KV ثبت کن.
      if (url.searchParams.get('sync') === '1') await flushUsageBuffer(env);
      const clients = await loadClients(env);
      // حتی اگر flush به هر دلیل موفق نشد، مقدار بافر همین Worker در پنل دیده شود.
      const liveClients = clients.map(function (c) {
        const live = Math.max(0, Math.floor(Number(USAGE_BUFFER[c.id]) || 0));
        return Object.assign({}, c, { usedBytes: Math.max(0, Math.floor(Number(c.usedBytes) || 0) + live) });
      });
      return json({ ok: true, clients: liveClients, address, wsPath: WS_PATH });
    }
    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'درخواست نامعتبر است' }, 400); }
      const name = String(body.name || '').trim().slice(0, 40);
      if (!name) return json({ ok: false, error: 'نام کلاینت الزامی است' }, 400);
      const protocol = body.protocol === 'trojan' ? 'trojan' : 'vless';
      const port = ALLOWED_PORTS.includes(Number(body.port)) ? Number(body.port) : 443;
      const limitGB = Math.max(0, Number(body.limitGB) || 0);
      const expiryDays = Math.max(0, Math.min(3650, Math.round(Number(body.expiryDays) || 0)));
      const clients = await loadClients(env);
      if (clients.some(c => c.name === name)) return json({ ok: false, error: 'کلینتی با این نام از قبل وجود دارد' }, 400);
      const client = {
        id: 'c_' + randomHex(10),
        name, protocol, port, limitGB, expiryDays,
        uuid: crypto.randomUUID(),
        token: randomHex(24),
        usedBytes: 0,
        createdAt: Date.now(),
        active: true
      };
      clients.push(client);
      await saveClients(env, clients);
      return json({ ok: true, client });
    }
    return json({ ok: false, error: 'متد مجاز نیست' }, 405);
  }

  const m = path.match(/^\/api\/clients\/([A-Za-z0-9_]+)(\/(reset|regenerate))?$/);
  if (m) {
    const id = m[1], action = m[3] || null;
    const clients = await loadClients(env);
    const idx = clients.findIndex(c => c.id === id);
    if (idx === -1) return json({ ok: false, error: 'کلاینت یافت نشد' }, 404);

    if (request.method === 'DELETE') {
      clients.splice(idx, 1);
      await saveClients(env, clients);
      return json({ ok: true });
    }

    if (request.method === 'POST' && action === 'reset') {
      clients[idx].usedBytes = 0;
      // بافر محلی این کلاینت هم صفر شود تا مصرف قبلی بعد از ریست برنگردد.
      delete USAGE_BUFFER[id];
      await saveClients(env, clients);
      return json({ ok: true, client: clients[idx] });
    }

    if (request.method === 'POST' && action === 'regenerate') {
      clients[idx].uuid = crypto.randomUUID();
      clients[idx].token = randomHex(24);
      await saveClients(env, clients);
      return json({ ok: true, client: clients[idx] });
    }

    if (request.method === 'PUT' && !action) {
      let body;
      try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'درخواست نامعتبر است' }, 400); }
      const c = clients[idx];
      if (body.name !== undefined) {
        const name = String(body.name || '').trim().slice(0, 40);
        if (name && !clients.some((x, i) => i !== idx && x.name === name)) c.name = name;
      }
      if (body.protocol !== undefined) c.protocol = body.protocol === 'trojan' ? 'trojan' : 'vless';
      if (body.port !== undefined && ALLOWED_PORTS.includes(Number(body.port))) c.port = Number(body.port);
      if (body.limitGB !== undefined) c.limitGB = Math.max(0, Number(body.limitGB) || 0);
      if (body.expiryDays !== undefined) c.expiryDays = Math.max(0, Math.min(3650, Math.round(Number(body.expiryDays) || 0)));
      if (body.active !== undefined) c.active = !!body.active;
      await saveClients(env, clients);
      return json({ ok: true, client: c });
    }
    return json({ ok: false, error: 'متد مجاز نیست' }, 405);
  }

  /* ── کانفیگ آماده با تمامی پورت‌ها ── */
  const mAll = path.match(/^\/api\/clients\/([A-Za-z0-9_]+)\/all-ports$/);
  if (mAll) {
    if (request.method !== 'GET') return json({ ok: false, error: 'متد مجاز نیست' }, 405);
    const clients = await loadClients(env);
    const client = clients.find(c => c.id === mAll[1]);
    if (!client) return json({ ok: false, error: 'کلاینت یافت نشد' }, 404);
    const settingsForLinks = await loadSettings(env);
    const ips = (settingsForLinks.preferredIPs && settingsForLinks.preferredIPs.length) ? settingsForLinks.preferredIPs : [''];
    const configs = [];
    for (const ip of ips) {
      for (const p of ALLOWED_PORTS) {
        configs.push({
          port: p,
          tls: TLS_PORTS.includes(p),
          ip: ip || null,
          link: buildConfigLinkForPort(client, address, p, ip || '')
        });
      }
    }
    const combinedText = configs.map(c => c.link).join('\n');
    return json({ ok: true, client: { id: client.id, name: client.name, protocol: client.protocol }, address, ips: ips.filter(Boolean), configs, combinedBase64: strToB64(combinedText) });
  }

  /* ── تنظیمات پنل ── */
  if (path === '/api/settings') {
    const settings = await loadSettings(env);
    if (request.method === 'GET') {
      const proxyIP = settings.proxyIP || null;
      return json({
        ok: true,
        address,
        hasCustomPassword: !!settings.passHash,
        defaultProtocol: settings.defaultProtocol,
        defaultPort: settings.defaultPort,
        remark: settings.remark,
        preferredIPs: settings.preferredIPs || [],
        theme: settings.theme || 'dark',
        kvConnected: !!(env.KV && typeof env.KV.get === 'function'),
        proxyIpConfigured: !!(proxyIP && proxyIP.host),
        proxyIP: proxyIP ? { host: String(proxyIP.host), port: Number(proxyIP.port) || 443 } : null,
        allowedPorts: ALLOWED_PORTS,
        tlsPorts: TLS_PORTS,
        version: VERSION
      });
    }
    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'درخواست نامعتبر است' }, 400); }
      const adminPass = String(env.ADMIN || env.PASSWORD || '').trim();

      if (body.newPassword) {
        const cur = String(body.currentPassword || '');
        const ok = await checkLoginPassword(env, adminPass, cur);
        if (!ok) return json({ ok: false, error: 'رمز عبور فعلی نادرست است' }, 401);
        const np = String(body.newPassword);
        if (np.length < 4) return json({ ok: false, error: 'رمز جدید باید حداقل ۴ کاراکتر باشد' }, 400);
        settings.passHash = await sha256hex(np);
      }
      if (body.defaultProtocol !== undefined) settings.defaultProtocol = body.defaultProtocol === 'trojan' ? 'trojan' : 'vless';
      if (body.defaultPort !== undefined && ALLOWED_PORTS.includes(Number(body.defaultPort))) settings.defaultPort = Number(body.defaultPort);
      if (body.remark !== undefined) settings.remark = String(body.remark || '').trim().slice(0, 60);
      if (body.theme !== undefined) settings.theme = body.theme === 'light' ? 'light' : 'dark';

      await saveSettings(env, settings);
      const secretHash = await effectiveAdminHash(env, adminPass);
      const res = json({ ok: true });
      res.headers.append('Set-Cookie', 'vw_auth=' + (await sha256hex('vw-session::' + secretHash)) + '; Path=/; Max-Age=604800; HttpOnly; SameSite=Strict');
      return res;
    }
    return json({ ok: false, error: 'متد مجاز نیست' }, 405);
  }

  /* ── افزودن یک یا چند آی‌پی کلودفلر به کانفیگ‌ها — بدون تست یا بررسی سلامت ──
     ورودی می‌تواند body.ip (تکی، برای سازگاری قدیمی) یا body.ips (آرایه) باشد.
     تمام آی‌پی‌های ارسالی معتبر با یک نوشتن واحد (نه یکی‌یکی) به فهرست موجود
     اضافه می‌شوند تا هم UI بتواند چند آی‌پی را یک‌جا اعمال کند و هم مصرف KV کم بماند. */
  if (path === '/api/clean-ip/apply') {
    if (request.method !== 'POST') return json({ ok: false, error: 'متد مجاز نیست' }, 405);
    let body = {};
    try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'درخواست نامعتبر است' }, 400); }
    const rawList = Array.isArray(body.ips) ? body.ips : (body.ip !== undefined ? [body.ip] : []);
    const isValidIPv4 = (ip) => {
      const octets = String(ip).split('.');
      return octets.length === 4 && octets.every(x => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
    };
    const cleaned = [];
    const invalid = [];
    for (const raw of rawList) {
      const ip = String(raw || '').trim();
      if (!ip) continue;
      if (isValidIPv4(ip)) cleaned.push(ip); else invalid.push(ip);
    }
    if (!cleaned.length) {
      return json({ ok: false, error: invalid.length ? ('فرمت این آی‌پی‌ها صحیح نیست: ' + invalid.join('، ')) : 'هیچ آی‌پی معتبری ارسال نشده است' }, 400);
    }

    const settings = await loadSettings(env);
    const merged = (Array.isArray(settings.preferredIPs) ? settings.preferredIPs : []).slice();
    for (const ip of cleaned) if (!merged.includes(ip)) merged.push(ip);
    settings.preferredIPs = merged.slice(0, 30); // سقف منطقی برای جلوگیری از حجم بیش‌ازحد کانفیگ‌ها
    await saveSettings(env, settings);
    return json({ ok: true, preferredIPs: settings.preferredIPs, invalid: invalid.length ? invalid : undefined });
  }

  /* ── حذف یک آی‌پی مشخص از فهرست ── */
  if (path === '/api/clean-ip/remove') {
    if (request.method !== 'POST') return json({ ok: false, error: 'متد مجاز نیست' }, 405);
    let body = {};
    try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'درخواست نامعتبر است' }, 400); }
    const ip = String(body.ip || '').trim();
    const settings = await loadSettings(env);
    settings.preferredIPs = (Array.isArray(settings.preferredIPs) ? settings.preferredIPs : []).filter(x => x !== ip);
    await saveSettings(env, settings);
    return json({ ok: true, preferredIPs: settings.preferredIPs });
  }

  /* ── حذف همه‌ی آی‌پی‌های کلودفلر از کانفیگ‌ها ── */
  if (path === '/api/clean-ip/clear') {
    if (request.method !== 'POST') return json({ ok: false, error: 'متد مجاز نیست' }, 405);
    const settings = await loadSettings(env);
    settings.preferredIPs = [];
    await saveSettings(env, settings);
    return json({ ok: true });
  }

  /* ── ثبت PROXYIP و پورت ── */
  if (path === '/api/proxyip/apply') {
    if (request.method !== 'POST') return json({ ok: false, error: 'متد مجاز نیست' }, 405);
    let body = {};
    try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'درخواست نامعتبر است' }, 400); }

    const host = String(body.host || '').trim();
    const port = Number(body.port);
    const octets = host.split('.');
    const validIPv4 = octets.length === 4 && octets.every(x => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
    if (!validIPv4) return json({ ok: false, error: 'PROXYIP باید یک IPv4 معتبر باشد؛ نمونه: 1.2.3.4' }, 400);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return json({ ok: false, error: 'پورت باید بین 1 تا 65535 باشد' }, 400);

    const settings = await loadSettings(env);
    settings.proxyIP = { host, port };
    await saveSettings(env, settings);
    return json({ ok: true, proxyIP: settings.proxyIP });
  }

  /* ── حذف PROXYIP ── */
  if (path === '/api/proxyip/clear') {
    if (request.method !== 'POST') return json({ ok: false, error: 'متد مجاز نیست' }, 405);
    const settings = await loadSettings(env);
    settings.proxyIP = null;
    await saveSettings(env, settings);
    return json({ ok: true });
  }

  return json({ ok: false, error: 'یافت نشد' }, 404);
}

/* ═════════════════════ هسته پروکسی: VLESS / Trojan روی WebSocket ═════════════════════ */
async function handleProxyWS(request, env, ctx) {
  if (!env.KV || typeof env.KV.get !== 'function') {
    return new Response(null, { status: 503 });
  }

  const clients = await loadClients(env);

  const pair = new WebSocketPair();
  const [clientSocket, ws] = Object.values(pair);
  ws.accept();

  let firstProcessed = false;
  let stream = null;              // { socket, writer }
  let pendingWrites = [];
  let pendingBytes = 0;
  let streamReady = false;
  let dnsMode = false;
  let dnsVersion = 0;
  let clientRecord = null;
  let usage = 0;
  let reportedUsage = 0;
  let usageFlushed = false;
  let usageTimer = null;
  let closing = false;
  let sessionRef = null;

  /* رفع باگ «مصرف کم نمی‌شود»: قبلاً هنگام بستن اتصال (force=true) واقعاً به
     KV نوشته نمی‌شد، فقط دوباره بافر می‌شد و اگر ایزوله بین این و آستانه‌ی
     بعدی (۵MB / ۲دقیقه) از حافظه خارج می‌شد، مصرف کاملاً گم می‌شد. حالا در
     حالت force، بعد از افزودن به بافر، بدون هیچ شرطی flushUsageBuffer صدا
     زده می‌شود تا نوشتن واقعی در KV تضمین شود. */
  const flushUsage = (force) => {
    if (clientRecord && usage > reportedUsage) {
      const delta = usage - reportedUsage;
      // فقط اختلافِ جدید را ثبت کن؛ این باعث می‌شود یک اتصال طولانی هم
      // به‌صورت زنده در سابسکریپشن دیده شود و در close دوباره شمرده نشود.
      reportedUsage = usage;
      USAGE_BUFFER[clientRecord.id] = (USAGE_BUFFER[clientRecord.id] || 0) + delta;
    }
    if (force) {
      // نوشتن واقعی و بدون قید‌وشرط در KV — صرف‌نظر از آستانه‌ی زمانی/حجمی
      ctx.waitUntil(flushUsageBuffer(env));
    } else {
      const dueByTime = (Date.now() - USAGE_STATE.lastFlush) >= USAGE_FLUSH_INTERVAL_MS;
      const dueBySize = bufferedUsageTotal() >= USAGE_FLUSH_THRESHOLD;
      if (dueByTime || dueBySize) ctx.waitUntil(flushUsageBuffer(env));
    }
  };

  const scheduleUsageFlush = () => {
    if (usageTimer || closing) return;
    usageTimer = setTimeout(() => {
      usageTimer = null;
      if (closing) return;
      flushUsage();
      scheduleUsageFlush();
    }, 30000);
  };

  const closeAll = () => {
    if (closing) return;
    closing = true;
    if (usageTimer) { clearTimeout(usageTimer); usageTimer = null; }
    flushUsage(true);
    usageFlushed = true;
    sessionClose(sessionRef); sessionRef = null;
    try { ws.close(); } catch (e) {}
    if (stream) {
      try { stream.writer.releaseLock(); } catch (e) {}
      try { stream.socket.close(); } catch (e) {}
    }
  };

  const findClient = (parsed) => {
    for (const c of clients) {
      if (!c.active) continue;
      if (parsed.protocol === 'vless') {
        if (String(c.uuid).toLowerCase() === parsed.uuid) return c;
      } else if (parsed.protocol === 'trojan') {
        if (sha224hex(c.uuid) === parsed.passwordHash) return c;
      }
    }
    return null;
  };

  const isBlocked = (c) => {
    if (!c) return true;
    if (c.expiryDays > 0 && Date.now() > c.createdAt + c.expiryDays * 86400000) return true;
    // مصرفِ بافرشده (هنوز در KV نوشته‌نشده) هم باید در سقف حجم حساب شود،
    // وگرنه کاربر تا زمان flush بعدی می‌تواند از سقف عبور کند
    const liveUsed = (Number(c.usedBytes) || 0) + (USAGE_BUFFER[c.id] || 0);
    if (c.limitGB > 0 && liveUsed >= c.limitGB * 1073741824) return true;
    return false;
  };

  const tryAuth = (data) => {
    if (data.byteLength >= 58 && data[56] === 0x0d && data[57] === 0x0a) {
      const t = parseTrojanHeader(data);
      if (t) {
        const c = findClient(t);
        if (c && !isBlocked(c)) { clientRecord = c; return t; }
      }
    }
    const v = parseVlessHeader(data);
    if (v) {
      const c = findClient(v);
      if (c && !isBlocked(c)) { clientRecord = c; return v; }
    }
    return null;
  };

  async function pumpRemote(socket) {
    const reader = socket.readable.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          usage += value.byteLength;
          if (usage - reportedUsage >= 1024 * 1024) flushUsage();
          try { ws.send(value); } catch (e) { break; }
        }
      }
    } catch (e) {}
    closeAll();
  }

  const processFirstData = async (data) => {
    firstProcessed = true;
    const parsed = tryAuth(data);
    if (!parsed) { closeAll(); return; }
    if (clientRecord) {
      sessionRef = sessionOpen(clientRecord.id, request);
      scheduleUsageFlush();
    }

    /* UDP — فقط DNS (پورت ۵۳) پشتیبانی می‌شود */
    if (parsed.isUDP) {
      if (parsed.protocol === 'vless' && parsed.port === 53) {
        dnsMode = true;
        dnsVersion = parsed.version;
        // رفع باگ «مصرف DNS شمرده نمی‌شد»: قبلاً handleVlessDNSPacket فراخوانی
        // می‌شد ولی نتیجه‌اش (تعداد بایت واقعاً مصرف‌شده) هیچ‌وقت به usage
        // اضافه نمی‌شد؛ برای کاربرهایی که ترافیک DNS زیادی دارند این بخش از
        // مصرف کلاً گم می‌شد. حالا تابع تعداد بایت را برمی‌گرداند و همینجا
        // به usage اضافه می‌شود.
        handleVlessDNSPacket(ws, parsed.version, parsed.payload).then(function (n) {
          if (n > 0) {
            usage += n;
            if (usage - reportedUsage >= 1024 * 1024) flushUsage();
          }
        }).catch(() => {});
        return;
      }
      closeAll();
      return;
    }

    /* اتصال TCP به مقصد (+ تلاش مجدد از طریق ProxyIP در صورت خطا) */
    const establish = async (hostname, port) => {
      const socket = connect({ hostname, port }, { allowHalfOpen: false });
      const writer = socket.writable.getWriter();
      if (parsed.payload && parsed.payload.byteLength > 0) {
        await writer.write(parsed.payload);
      }
      return { socket, writer };
    };

    try {
      stream = await establish(parsed.hostname, parsed.port);
    } catch (e) {
      let ok = false;
      const proxyIPs = await getConfiguredProxyIPs(env);
      for (const p of proxyIPs) {
        try {
          stream = await establish(p.host, p.port || parsed.port);
          ok = true;
          break;
        } catch (e2) { continue; }
      }
      if (!ok) { closeAll(); return; }
    }

    /* رفع باگ «مصرف دوبار حساب می‌شد»: قبلاً شمارش بایت‌های payload اولیه
       داخل خود establish انجام می‌شد؛ چون establish هم برای تلاش مستقیم و
       هم (در صورت شکست) دوباره برای هر ProxyIP صدا زده می‌شود، همان
       payload اولیه می‌توانست چند بار به usage اضافه شود و عدد مصرف را
       واقعاً بیشتر از حد نشان دهد. حالا شمارش فقط یک‌بار، بعد از برقراری
       موفق اتصال (چه مستقیم چه از طریق ProxyIP)، انجام می‌شود. */
    if (parsed.payload && parsed.payload.byteLength > 0) {
      usage += parsed.payload.byteLength;
      if (usage - reportedUsage >= 1024 * 1024) flushUsage();
    }

    if (parsed.protocol === 'vless') {
      try { ws.send(new Uint8Array([parsed.version, 0])); } catch (e) { closeAll(); return; }
    }

    /* داده‌هایی که حین برقراری اتصال رسیده‌اند — تا وقتی صف کاملاً خالی نشده،
       پیام‌های تازه هم به همان صف می‌روند تا ترتیب بایت‌ها به‌هم نخورد */
    try {
      while (pendingWrites.length) {
        const pending = pendingWrites;
        pendingWrites = [];
        pendingBytes = 0;
        for (const p of pending) {
          if (p.byteLength > 0) {
            usage += p.byteLength;
            if (usage - reportedUsage >= 1024 * 1024) flushUsage();
            await stream.writer.write(p);
          }
        }
      }
      streamReady = true;
    } catch (e) { closeAll(); return; }

    pumpRemote(stream.socket);
  };

  ws.addEventListener('message', async (event) => {
    try {
      if (closing) return;
      const data = await wsToBytes(event.data);
      if (closing) return;
      if (!firstProcessed) {
        processFirstData(data).catch(() => closeAll());
        return;
      }
      if (dnsMode) {
        handleVlessDNSPacket(ws, dnsVersion, data).then(function (n) {
          if (n > 0) {
            usage += n;
            if (usage - reportedUsage >= 1024 * 1024) flushUsage();
          }
        }).catch(() => {});
        return;
      }
      if (!stream || !streamReady) {
        if (pendingBytes > 8388608) { closeAll(); return; }
        pendingBytes += data.byteLength;
        pendingWrites.push(data);
        return;
      }
      if (data.byteLength > 0) {
        usage += data.byteLength;
        if (usage - reportedUsage >= 1024 * 1024) flushUsage();
        await stream.writer.write(data);
      }
    } catch (e) {
      closeAll();
    }
  });

  ws.addEventListener('close', () => closeAll());
  ws.addEventListener('error', () => closeAll());

  /* دیتای اولیه (0-RTT) از طریق sec-websocket-protocol */
  const earlyData = request.headers.get('sec-websocket-protocol') || '';
  if (earlyData) {
    try {
      const decoded = b64ToBytes(earlyData);
      if (decoded.byteLength > 0 && peekParse(decoded)) {
        processFirstData(decoded).catch(() => closeAll());
      }
    } catch (e) {}
  }

  return new Response(null, { status: 101, webSocket: clientSocket });
}

/* ─────────────────── پارسر هدر VLESS ─────────────────── */
function parseVlessHeader(chunk) {
  try {
    if (chunk.byteLength < 24) return null;
    const version = chunk[0];
    let hex = '';
    for (let i = 1; i <= 16; i++) hex += chunk[i].toString(16).padStart(2, '0');
    const uuid = hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
    const optLen = chunk[17];
    let cursor = 18 + optLen;
    if (chunk.byteLength < cursor + 4) return null;
    const cmd = chunk[cursor];
    if (cmd !== 1 && cmd !== 2) return null;
    cursor += 1;
    const port = (chunk[cursor] << 8) | chunk[cursor + 1];
    cursor += 2;
    const atype = chunk[cursor];
    cursor += 1;
    let hostname = '';
    if (atype === 1) {
      if (chunk.byteLength < cursor + 4) return null;
      hostname = chunk[cursor] + '.' + chunk[cursor + 1] + '.' + chunk[cursor + 2] + '.' + chunk[cursor + 3];
      cursor += 4;
    } else if (atype === 2) {
      if (chunk.byteLength < cursor + 1) return null;
      const dLen = chunk[cursor];
      cursor += 1;
      if (chunk.byteLength < cursor + dLen) return null;
      hostname = new TextDecoder().decode(chunk.subarray(cursor, cursor + dLen));
      cursor += dLen;
    } else if (atype === 3) {
      if (chunk.byteLength < cursor + 16) return null;
      const parts = [];
      for (let i = 0; i < 8; i++) parts.push(((chunk[cursor + i * 2] << 8) | chunk[cursor + i * 2 + 1]).toString(16));
      hostname = parts.join(':');
      cursor += 16;
    } else return null;
    if (!hostname) return null;
    return { protocol: 'vless', version, uuid, isUDP: cmd === 2, port, hostname, payload: chunk.subarray(cursor) };
  } catch (e) { return null; }
}

/* ─────────────────── پارسر هدر Trojan ─────────────────── */
function parseTrojanHeader(chunk) {
  try {
    if (chunk.byteLength < 58) return null;
    const passwordHash = new TextDecoder().decode(chunk.subarray(0, 56));
    if (!/^[0-9a-fA-F]{56}$/.test(passwordHash)) return null;
    if (chunk[56] !== 0x0d || chunk[57] !== 0x0a) return null;
    const cmd = chunk[58];
    if (cmd !== 1 && cmd !== 3) return null;
    const atype = chunk[59];
    let cursor = 60;
    let hostname = '';
    if (atype === 1) {
      if (chunk.byteLength < cursor + 4) return null;
      hostname = chunk[cursor] + '.' + chunk[cursor + 1] + '.' + chunk[cursor + 2] + '.' + chunk[cursor + 3];
      cursor += 4;
    } else if (atype === 2) {
      if (chunk.byteLength < cursor + 1) return null;
      const dLen = chunk[cursor];
      cursor += 1;
      if (chunk.byteLength < cursor + dLen) return null;
      hostname = new TextDecoder().decode(chunk.subarray(cursor, cursor + dLen));
      cursor += dLen;
    } else if (atype === 4) {
      if (chunk.byteLength < cursor + 16) return null;
      const parts = [];
      for (let i = 0; i < 8; i++) parts.push(((chunk[cursor + i * 2] << 8) | chunk[cursor + i * 2 + 1]).toString(16));
      hostname = parts.join(':');
      cursor += 16;
    } else return null;
    if (!hostname) return null;
    if (chunk.byteLength < cursor + 4) return null;
    const port = (chunk[cursor] << 8) | chunk[cursor + 1];
    if (chunk[cursor + 2] !== 0x0d || chunk[cursor + 3] !== 0x0a) return null;
    cursor += 4;
    return { protocol: 'trojan', passwordHash: passwordHash.toLowerCase(), isUDP: cmd === 3, port, hostname, payload: chunk.subarray(cursor) };
  } catch (e) { return null; }
}

function peekParse(data) {
  if (data.byteLength >= 58 && data[56] === 0x0d && data[57] === 0x0a) {
    const t = parseTrojanHeader(data);
    if (t) return t;
  }
  return parseVlessHeader(data);
}

/* ─────────────────── پاسخ DNS از طریق DoH (فقط VLESS) ─────────────────── */
/* رفع باگ «مصرف DNS شمرده نمی‌شد»: این تابع اکنون تعداد بایت واقعاً
   رد و بدل شده (طول payload ورودی + طول پاسخی که به کلاینت فرستاده شد) را
   برمی‌گرداند تا فراخواننده بتواند آن را به usage اضافه کند. قبلاً این مقدار
   هیچ‌جا برگردانده نمی‌شد و ترافیک DNS کلاً از مصرف حذف بود. */
async function handleVlessDNSPacket(ws, version, payload) {
  try {
    if (!payload || payload.byteLength < 2) return 0;
    const qLen = (payload[0] << 8) | payload[1];
    if (qLen <= 0 || payload.byteLength < 2 + qLen) return 0;
    const query = payload.subarray(2, 2 + qLen);
    const resp = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: query
    });
    if (!resp.ok) return 0;
    const answer = new Uint8Array(await resp.arrayBuffer());
    if (answer.byteLength === 0) return 0;
    const out = new Uint8Array(4 + answer.byteLength);
    out[0] = version;
    out[1] = 0;
    out[2] = (answer.byteLength >>> 8) & 0xff;
    out[3] = answer.byteLength & 0xff;
    out.set(answer, 4);
    ws.send(out);
    return payload.byteLength + out.byteLength;
  } catch (e) { return 0; }
}

/* ═══════════════════════════════════════════════════════════════════
 *   بخش صفحات HTML (لاگین، داشبورد، راه‌اندازی، ۴۰۴)
 * ═══════════════════════════════════════════════════════════════════ */

function baseCSS() {
  return `
* { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Vazirmatn', Tahoma, sans-serif; }
:root {
  --bg: #050112;
  --card: rgba(21, 12, 43, 0.6);
  --border: rgba(168, 85, 247, 0.28);
  --purple: #a855f7;
  --purple2: #7c3aed;
  --cyan: #22d3ee;
  --pink: #e879f9;
  --text: #efeafc;
  --muted: #a79ac9;
  --green: #34d399;
  --red: #fb7185;
  --amber: #fbbf24;
  /* سطوحِ «شیشه‌ای تیره» (فیلد ورودی، مودال، منو، توست...) که باید در پوسته‌ی
     روشن هم قابل‌خواندن بمانند؛ قبلاً این رنگ‌ها به‌صورت ثابت (hardcoded)
     تیره نوشته شده بودند و چون متنِ رویشان از var(--text) استفاده می‌کرد،
     با روشن شدن پوسته، متنِ تیره روی پس‌زمینه‌ی هنوز تیره «مشکی روی مشکی»
     و نامرئی می‌شد. */
  --input-bg: rgba(8, 4, 20, 0.7);
  --input-border: rgba(168, 85, 247, 0.22);
  --surface-dark: rgba(18, 10, 38, 0.95);
  --surface-dark2: rgba(10, 5, 24, 0.8);
  --surface-dark-border: rgba(168, 85, 247, 0.35);
  --mono-accent: #67e8f9;
}
/* پوسته‌ی روشن — با data-theme="light" روی <html> فعال می‌شود */
html[data-theme="light"] {
  --bg: #f3f1fb;
  --card: rgba(255, 255, 255, 0.82);
  --border: rgba(124, 58, 237, 0.22);
  --purple: #7c3aed;
  --purple2: #6d28d9;
  --cyan: #0891b2;
  --pink: #c026d3;
  --text: #211a35;
  --muted: #6b6485;
  --green: #059669;
  --red: #e11d48;
  --amber: #b45309;
  --input-bg: rgba(255, 255, 255, 0.85);
  --input-border: rgba(124, 58, 237, 0.25);
  --surface-dark: rgba(255, 255, 255, 0.97);
  --surface-dark2: rgba(255, 255, 255, 0.9);
  --surface-dark-border: rgba(124, 58, 237, 0.25);
  --mono-accent: #0e7490;
}
html[data-theme="light"] .bg-img { opacity: .05; }
html[data-theme="light"] .bg-overlay { background:
    radial-gradient(ellipse 60% 40% at 70% -5%, rgba(124,58,237,.10), transparent 65%),
    radial-gradient(ellipse 50% 35% at 10% 105%, rgba(8,145,178,.08), transparent 60%),
    linear-gradient(180deg, rgba(255,255,255,.4) 0%, rgba(243,241,251,.92) 100%); }
html[data-theme="light"] ::-webkit-scrollbar-track { background: #e9e5f7; }
.btn-theme { border: 1px solid var(--border); background: rgba(168,85,247,.08); color: var(--text);
  width: 38px; height: 38px; border-radius: 12px; font-size: 16px; cursor: pointer; transition: .2s; }
.btn-theme:hover { background: rgba(168,85,247,.2); transform: translateY(-1px); }
html { scroll-behavior: smooth; }
body { background: var(--bg); color: var(--text); min-height: 100vh; transition: background-color .25s ease, color .25s ease; }
::selection { background: rgba(168, 85, 247, 0.4); color: #fff; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: #0a0518; }
::-webkit-scrollbar-thumb { background: linear-gradient(180deg, #7c3aed, #a855f7); border-radius: 8px; border: 2px solid #0a0518; }

/* پس‌زمینه */
.bg-img { position: fixed; inset: 0; background: url('${BG_IMAGE}') center / cover no-repeat fixed; opacity: 0.16; filter: saturate(1.5); pointer-events: none; }
.bg-overlay { position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background:
    radial-gradient(ellipse 60% 40% at 70% -5%, rgba(124, 58, 237, 0.28), transparent 65%),
    radial-gradient(ellipse 50% 35% at 10% 105%, rgba(34, 211, 238, 0.13), transparent 60%),
    linear-gradient(180deg, rgba(5, 1, 18, 0.6) 0%, rgba(5, 1, 18, 0.92) 100%);
}
.particles { position: fixed; inset: 0; overflow: hidden; pointer-events: none; z-index: 0; }
.particles span { position: absolute; border-radius: 50%; bottom: -12px; animation: pRise linear infinite; }
@keyframes pRise {
  0% { transform: translateY(0) translateX(0); opacity: 0; }
  10% { opacity: 0.9; }
  90% { opacity: 0.6; }
  100% { transform: translateY(-105vh) translateX(40px); opacity: 0; }
}

/* انیمیشن‌های مشترک */
@keyframes cardIn { from { opacity: 0; transform: translateY(48px) scale(0.95); filter: blur(4px); } to { opacity: 1; transform: none; filter: none; } }
@keyframes logoFloat { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-7px); } }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
@keyframes gradShift { 0%, 100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }
@keyframes shine { 0% { left: -75%; } 60%, 100% { left: 135%; } }
.btn-shine { position: absolute; top: 0; left: -75%; width: 45%; height: 100%; transform: skewX(-22deg); pointer-events: none;
  background: linear-gradient(105deg, transparent, rgba(255, 255, 255, 0.35), transparent); animation: shine 3.4s ease infinite; }

/* برچسب وضعیت عمومی */
.badge-pill { display: inline-flex; align-items: center; gap: 7px; font-size: 10.5px; letter-spacing: 1.2px;
  padding: 6px 14px; border-radius: 99px; background: rgba(5, 1, 18, 0.55); border: 1px solid rgba(168, 85, 247, 0.35);
  color: #d8ccf5; direction: ltr; }
.badge-pill .live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green);
  box-shadow: 0 0 10px var(--green); animation: blink 1.8s ease infinite; flex-shrink: 0; }

/* تب‌ها */
.tabs { display: flex; gap: 6px; overflow-x: auto; padding: 4px; margin: 22px 0 0;
  background: var(--surface-dark2); border: 1px solid rgba(168, 85, 247, 0.22); border-radius: 16px; }
.tab-btn { flex: 1; min-width: max-content; display: flex; align-items: center; justify-content: center; gap: 8px;
  padding: 12px 18px; border: none; border-radius: 12px; background: transparent; color: var(--muted);
  font-size: 13px; font-weight: 700; cursor: pointer; transition: 0.25s; font-family: inherit; white-space: nowrap; }
.tab-btn:hover { color: var(--text); background: rgba(168, 85, 247, 0.1); }
.tab-btn.active { color: #fff; background: linear-gradient(135deg, #7c3aed, #a855f7 65%, #22d3ee 150%);
  box-shadow: 0 6px 20px rgba(124, 58, 237, 0.45); }
.tab-panel { display: none; }
.tab-panel.active { display: block; animation: cardIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) both; }

/* حلقه پیشرفت کوچک (mini ring) */
.ring-wrap { position: relative; width: 62px; height: 62px; flex-shrink: 0; }
.ring-wrap svg { transform: rotate(-90deg); width: 100%; height: 100%; }
.ring-wrap .ring-bg { fill: none; stroke: rgba(168,85,247,0.14); stroke-width: 6; }
.ring-wrap .ring-fg { fill: none; stroke: url(#ringGrad); stroke-width: 6; stroke-linecap: round; transition: stroke-dashoffset 1s cubic-bezier(0.16,1,0.3,1); }
.ring-label { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
  font-size: 12px; font-weight: 800; }

/* جدول تست آی‌پی */
.ip-table-wrap { overflow-x: auto; border-radius: 16px; border: 1px solid var(--border); }
table.ip-table { width: 100%; border-collapse: collapse; font-size: 12.5px; min-width: 520px; }
table.ip-table th { text-align: right; padding: 12px 14px; background: rgba(124, 58, 237, 0.14); color: #d8ccf5;
  font-weight: 700; position: sticky; top: 0; }
table.ip-table td { padding: 11px 14px; border-top: 1px solid rgba(168, 85, 247, 0.14); direction: ltr; text-align: left; }
table.ip-table td:last-child, table.ip-table th:last-child { text-align: right; direction: rtl; }
table.ip-table tr.best td { background: rgba(52, 211, 153, 0.08); }
.lat-chip { display: inline-block; padding: 4px 10px; border-radius: 8px; font-size: 11.5px; font-weight: 700; direction: ltr; }
.lat-chip.good { background: rgba(52, 211, 153, 0.16); color: #6ee7b7; border: 1px solid rgba(52, 211, 153, 0.35); }
.lat-chip.mid { background: rgba(251, 191, 36, 0.16); color: #fcd34d; border: 1px solid rgba(251, 191, 36, 0.35); }
.lat-chip.bad { background: rgba(251, 113, 133, 0.16); color: #fda4af; border: 1px solid rgba(251, 113, 133, 0.35); }

/* کارت‌های وضعیت تنظیمات */
.settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }
.settings-card { padding: 22px; border-radius: 19px; background: var(--card); border: 1px solid var(--border);
  backdrop-filter: blur(16px); animation: cardIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) both; }
.settings-card h4 { font-size: 14px; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
.status-row { display: flex; align-items: center; justify-content: space-between; padding: 9px 0;
  border-bottom: 1px dashed rgba(168, 85, 247, 0.16); font-size: 12.5px; color: var(--muted); }
.status-row:last-child { border-bottom: none; }
.welcome-text p { font-size: 13px; line-height: 2.1; color: var(--text); margin-bottom: 14px; }
.welcome-text p:last-child { margin-bottom: 0; }
.support-card { padding: 22px; border-radius: 19px; background: var(--card); border: 1px solid var(--border);
  backdrop-filter: blur(16px); text-align: center; }
.support-card .s-icon { font-size: 34px; margin-bottom: 10px; }
.support-card h4 { font-size: 15px; margin-bottom: 8px; }
.support-card p { font-size: 12.5px; color: var(--muted); margin-bottom: 16px; line-height: 1.9; }
.support-links { display: flex; flex-direction: column; gap: 10px; }
.support-links a { display: flex; align-items: center; justify-content: center; gap: 8px;
  padding: 12px 16px; border-radius: 13px; text-decoration: none; font-size: 13px; font-weight: 600;
  border: 1px solid var(--border); color: var(--text); transition: .2s; }
.support-links a:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(124,58,237,.25); }
.support-links a.channel { background: linear-gradient(135deg, #0ea5e9, #0284c7); border-color: transparent; color: #fff; }
.support-links a.admin { background: linear-gradient(135deg, #7c3aed, #a855f7); border-color: transparent; color: #fff; }
.support-banner { margin-top: 22px; padding: 20px 24px; border-radius: 19px; background: linear-gradient(120deg, rgba(124,58,237,.14), rgba(34,211,238,.08));
  border: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.support-banner .sb-text { display: flex; flex-direction: column; gap: 4px; }
.support-banner .sb-text b { font-size: 14px; }
.support-banner .sb-text span { font-size: 12px; color: var(--muted); }
.support-banner .sb-actions { display: flex; gap: 10px; flex-wrap: wrap; }
.support-banner .sb-actions a { padding: 10px 18px; border-radius: 12px; text-decoration: none; font-size: 12.5px; font-weight: 700; transition: .2s; }
.support-banner .sb-actions a.channel { background: linear-gradient(135deg, #0ea5e9, #0284c7); color: #fff; }
.support-banner .sb-actions a.admin { background: linear-gradient(135deg, #7c3aed, #a855f7); color: #fff; }
.support-banner .sb-actions a:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(124,58,237,.3); }
.gh-source-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
  padding: 12px 16px; margin-bottom: 16px; border-radius: 13px; background: rgba(34,211,238,.06); border: 1px solid rgba(34,211,238,.25); font-size: 12.5px; }
.gh-source-row a { color: var(--cyan); font-weight: 700; }
.status-row b { color: var(--text); direction: ltr; }
.status-ok { color: #6ee7b7; }
.status-warn { color: #fcd34d; }
.status-bad { color: #fda4af; }

/* آی‌پی‌های تمیز — لیست موقتِ در حالِ افزودن و لیست فعال */
.pending-ip-box { display: flex; flex-wrap: wrap; gap: 8px; margin: 4px 0 14px; }
.pending-ip-box:empty { margin: 0; }
.ip-chip { display: inline-flex; align-items: center; gap: 8px; padding: 7px 8px 7px 12px; border-radius: 10px;
  background: rgba(34, 211, 238, 0.1); border: 1px solid rgba(34, 211, 238, 0.35); font-size: 12px;
  direction: ltr; color: var(--cyan); font-family: monospace; }
.ip-chip button { background: rgba(251, 113, 133, 0.16); border: 1px solid rgba(251, 113, 133, 0.35); color: #fda4af;
  width: 20px; height: 20px; border-radius: 50%; cursor: pointer; font-size: 11px; line-height: 1; font-family: inherit; }
.ip-chip button:hover { background: rgba(251, 113, 133, 0.32); }
.active-ip-list { display: flex; flex-wrap: wrap; gap: 8px; }
.active-ip-chip { display: inline-flex; align-items: center; gap: 8px; padding: 8px 8px 8px 14px; border-radius: 12px;
  background: rgba(52, 211, 153, 0.1); border: 1px solid rgba(52, 211, 153, 0.32); font-size: 12.5px;
  direction: ltr; color: var(--green); font-family: monospace; }
.active-ip-chip button { background: rgba(251, 113, 133, 0.16); border: 1px solid rgba(251, 113, 133, 0.35); color: #fda4af;
  width: 22px; height: 22px; border-radius: 50%; cursor: pointer; font-size: 12px; line-height: 1; font-family: inherit; }
.active-ip-chip button:hover { background: rgba(251, 113, 133, 0.32); }
.ap-group-label { font-size: 11.5px; color: var(--cyan); font-weight: 700; margin: 12px 0 6px; direction: ltr; text-align: left; }
.ap-group-label:first-child { margin-top: 0; }
`;
}

function particlesJS(id) {
  return `<script>
(function () {
  var c = document.getElementById('${id}');
  if (!c) return;
  var colors = ['#a855f7', '#22d3ee', '#e879f9'];
  for (var i = 0; i < 30; i++) {
    var p = document.createElement('span');
    var s = Math.random() * 3 + 1.5;
    p.style.width = s + 'px';
    p.style.height = s + 'px';
    p.style.left = (Math.random() * 100) + '%';
    p.style.background = colors[i % 3];
    p.style.boxShadow = '0 0 ' + (s * 3) + 'px ' + colors[i % 3];
    p.style.opacity = '0';
    p.style.animationDuration = (Math.random() * 16 + 12) + 's';
    p.style.animationDelay = (Math.random() * 18) + 's';
    c.appendChild(p);
  }
})();
</script>`;
}

/* ─────────────────────────── صفحه ورود ─────────────────────────── */
function loginPage() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#0a0518">
<script>(function(){try{if(localStorage.getItem('vw_theme')==='light')document.documentElement.setAttribute('data-theme','light');}catch(e){}})();</script>
<title>ورود | VODIWALKER VPN</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
 ${baseCSS()}
body { display: flex; align-items: center; justify-content: center; overflow: hidden; position: relative; padding: 20px; }

.login-shell { position: relative; z-index: 2; width: min(430px, 100%); display: flex; flex-direction: column; align-items: center; gap: 14px; }
.brand-top { display: flex; flex-direction: column; align-items: center; gap: 10px; animation: cardIn 0.8s cubic-bezier(0.16,1,0.3,1) both; }
.brand-top .logo-ring { width: 68px; height: 68px; border-radius: 22px; display: grid; place-items: center; font-size: 30px;
  background: linear-gradient(135deg, #7c3aed, #a855f7 55%, #22d3ee); box-shadow: 0 0 34px rgba(168,85,247,0.55), inset 0 1px 0 rgba(255,255,255,0.25);
  animation: logoFloat 3.5s ease-in-out infinite; }
.brand-top .brand-name { font-size: 12px; letter-spacing: 5px; color: #b7a8dd; direction: ltr; }

.login-card {
  position: relative; z-index: 2; width: 100%;
  border-radius: 26px;
  background: var(--surface-dark);
  backdrop-filter: blur(28px); -webkit-backdrop-filter: blur(28px);
  border: 1px solid rgba(168, 85, 247, 0.3);
  box-shadow: 0 25px 70px rgba(88, 28, 135, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.06);
  overflow: hidden;
  animation: cardIn 1s 0.1s cubic-bezier(0.16, 1, 0.3, 1) both;
}
.login-card::before {
  content: ''; position: absolute; inset: -1px; z-index: 3; border-radius: 27px; padding: 1.5px;
  background: linear-gradient(130deg, rgba(168, 85, 247, 0.9), rgba(34, 211, 238, 0.75), rgba(232, 121, 249, 0.85));
  background-size: 300% 300%;
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor; mask-composite: exclude;
  animation: gradShift 7s ease infinite;
  pointer-events: none;
}

.hero { position: relative; height: 200px; overflow: hidden; }
.hero img { width: 100%; height: 100%; object-fit: cover; object-position: center 22%;
  filter: contrast(1.08) saturate(1.35); animation: heroZoom 18s ease-in-out infinite alternate; }
@keyframes heroZoom { from { transform: scale(1); } to { transform: scale(1.08); } }
.hero::after { content: ''; position: absolute; inset: 0;
  background: linear-gradient(180deg, rgba(5,1,18,0.05) 0%, rgba(5,1,18,0.55) 55%, rgba(18,10,38,0.98) 100%),
              radial-gradient(circle at 50% 30%, rgba(124,58,237,0.35), transparent 70%); }
.scanline { position: absolute; left: 0; right: 0; height: 70px; top: -70px; z-index: 2;
  background: linear-gradient(180deg, transparent, rgba(34, 211, 238, 0.16), transparent);
  animation: scan 4s linear infinite; }
@keyframes scan { from { top: -70px; } to { top: 100%; } }
.hero-content { position: absolute; inset: 0; z-index: 2; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 9px; padding: 0 16px; text-align: center; }
.hero-title { font-size: clamp(23px, 6.4vw, 29px); font-weight: 900; letter-spacing: 2.5px; color: #fff; direction: ltr;
  animation: titleGlow 2.8s ease-in-out infinite; }
@keyframes titleGlow {
  0%, 100% { text-shadow: 0 0 12px rgba(168,85,247,0.75), 0 0 32px rgba(168,85,247,0.4); }
  50% { text-shadow: 0 0 20px rgba(168,85,247,1), 0 0 56px rgba(34,211,238,0.65); }
}
.hero-title b { color: transparent; background: linear-gradient(90deg, #c084fc, #22d3ee);
  -webkit-background-clip: text; background-clip: text; }

.login-form { padding: 24px 28px 28px; position: relative; }
.form-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px; }
.form-head span.tag { font-size: 10.5px; letter-spacing: 2px; color: #93c5fd; direction: ltr; }
.form-head h2 { font-size: 15.5px; }
.field-label { font-size: 12.5px; color: var(--muted); margin: 18px 4px 9px; display: flex; align-items: center; gap: 6px; }
.input-wrap { position: relative; display: flex; align-items: center; }
.input-wrap .icon { position: absolute; right: 15px; font-size: 15px; opacity: 0.75; pointer-events: none; }
.input-wrap input {
  width: 100%; padding: 15px 46px; font-size: 15px; color: var(--text);
  background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 15px;
  outline: none; transition: border-color 0.25s, box-shadow 0.25s, background 0.25s;
}
.input-wrap input[disabled] { color: #9186b3; cursor: default; }
.input-wrap input::placeholder { color: #6b5e8d; }
.input-wrap input:focus { border-color: var(--purple); background: rgba(13, 7, 32, 0.9);
  box-shadow: 0 0 0 4px rgba(168, 85, 247, 0.15), 0 0 26px rgba(168, 85, 247, 0.28); }
.input-wrap.focused .icon { opacity: 1; filter: drop-shadow(0 0 6px rgba(168,85,247,.7)); }
.caps-warn { display: none; align-items: center; gap: 6px; font-size: 11.5px; color: var(--amber);
  margin-top: 8px; background: rgba(251,191,36,.1); border: 1px solid rgba(251,191,36,.3);
  padding: 6px 12px; border-radius: 10px; }
.eye { position: absolute; left: 13px; background: none; border: none; cursor: pointer; font-size: 15px;
  opacity: 0.55; transition: 0.2s; }
.eye:hover { opacity: 1; transform: scale(1.15); }
.err { color: var(--red); font-size: 12.5px; min-height: 20px; margin-top: 9px; padding: 0 4px; }
.shake { animation: shakeX 0.45s; }
@keyframes shakeX { 0%, 100% { transform: translateX(0); } 20% { transform: translateX(-9px); }
  40% { transform: translateX(9px); } 60% { transform: translateX(-5px); } 80% { transform: translateX(5px); } }

.remember-row { display: flex; align-items: center; justify-content: space-between; margin-top: 16px; padding: 0 4px; }
.remember-check { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); cursor: pointer; user-select: none; }
.remember-check input { width: 15px; height: 15px; accent-color: var(--purple); cursor: pointer; }

.btn-login {
  position: relative; width: 100%; margin-top: 18px; padding: 16px; border: none; border-radius: 15px; cursor: pointer;
  font-size: 15.5px; font-weight: 800; color: #fff; letter-spacing: 0.3px;
  background: linear-gradient(135deg, #6d28d9, #a855f7 52%, #22d3ee 135%);
  background-size: 220% 220%; box-shadow: 0 6px 26px rgba(124, 58, 237, 0.5), inset 0 1px 0 rgba(255,255,255,0.2);
  transition: transform 0.2s, box-shadow 0.25s; overflow: hidden; animation: gradShift 6s ease infinite;
}
.btn-login:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 10px 36px rgba(124, 58, 237, 0.7); }
.btn-login:active:not(:disabled) { transform: translateY(0) scale(0.99); }
.btn-login:disabled { opacity: 0.65; cursor: wait; }

.login-footer { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 22px;
  font-size: 11.5px; color: var(--muted); }
</style>
</head>
<body>
  <div class="bg-img"></div>
  <div class="bg-overlay"></div>
  <div class="particles" id="particles"></div>

  <div class="login-shell">
    <div class="brand-top">
      <span class="badge-pill"><span class="live-dot"></span> SECURE ADMIN CONSOLE</span>
      <button type="button" class="btn-theme" id="loginThemeToggle" title="تغییر پوسته (روشن/تاریک)">🌙</button>
    </div>

    <div class="login-card">
      <div class="hero">
        <img src="${BG_IMAGE}" alt="VODIWALKER VPN" onerror="this.style.display='none'">
        <div class="scanline"></div>
        <div class="hero-content">
          <div class="hero-title">VODIWALKER <b>VPN</b></div>
        </div>
      </div>
      <form class="login-form" id="loginForm" autocomplete="off">
        <div class="form-head">
          <h2>ورود به مرکز کنترل</h2>
          <span class="tag">v${VERSION}</span>
        </div>

        <div class="field-label">👤 نام کاربری</div>
        <div class="input-wrap">
          <span class="icon">🧑‍💻</span>
          <input type="text" value="admin" disabled>
        </div>

        <div class="field-label">🔒 رمز عبور مدیریت</div>
        <div class="input-wrap" id="inputWrap">
          <span class="icon">🔑</span>
          <input type="password" id="password" placeholder="رمز عبور را وارد کنید" required autofocus>
          <button type="button" class="eye" id="eyeBtn" title="نمایش/مخفی کردن">👁</button>
        </div>
        <div class="caps-warn" id="capsWarn">⚠️ کلید Caps Lock فعال است</div>

        <div class="remember-row">
          <label class="remember-check"><input type="checkbox" id="remember" checked> مرا به خاطر بسپار (۳۰ روز)</label>
        </div>

        <div class="err" id="err"></div>
        <button type="submit" class="btn-login" id="loginBtn">
          <span class="btn-shine"></span>
          <span id="loginBtnText">🔐 ورود به پنل مدیریت</span>
        </button>
        <div class="login-footer"><span class="live-dot" style="width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);"></span> اتصال امن برقرار است · نسخه ${VERSION}</div>
      </form>
    </div>
  </div>

 ${particlesJS('particles')}
<script>
(function () {
  var eyeBtn = document.getElementById('eyeBtn');
  var pw = document.getElementById('password');
  var inputWrap = document.getElementById('inputWrap');
  var capsWarn = document.getElementById('capsWarn');
  var loginThemeToggle = document.getElementById('loginThemeToggle');
  function applyLoginTheme(mode) {
    mode = mode === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', mode);
    if (loginThemeToggle) loginThemeToggle.textContent = mode === 'light' ? '☀️' : '🌙';
    try { localStorage.setItem('vw_theme', mode); } catch (e) {}
  }
  try {
    var savedTheme = localStorage.getItem('vw_theme');
    applyLoginTheme(savedTheme === 'light' ? 'light' : 'dark');
  } catch (e) { applyLoginTheme('dark'); }
  if (loginThemeToggle) loginThemeToggle.addEventListener('click', function () {
    var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    applyLoginTheme(cur === 'light' ? 'dark' : 'light');
  });
  eyeBtn.addEventListener('click', function () {
    pw.type = pw.type === 'password' ? 'text' : 'password';
    eyeBtn.textContent = pw.type === 'password' ? '👁' : '🙈';
    pw.focus();
  });
  pw.addEventListener('focus', function () { inputWrap.classList.add('focused'); });
  pw.addEventListener('blur', function () { inputWrap.classList.remove('focused'); });
  pw.addEventListener('keyup', function (e) {
    var on = typeof e.getModifierState === 'function' && e.getModifierState('CapsLock');
    capsWarn.style.display = on ? 'flex' : 'none';
  });

  document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var btn = document.getElementById('loginBtn');
    var btnText = document.getElementById('loginBtnText');
    var err = document.getElementById('err');
    var wrap = document.getElementById('inputWrap');
    var remember = document.getElementById('remember').checked;
    err.textContent = '';
    btn.disabled = true;
    btnText.textContent = 'در حال بررسی هویت …';
    fetch('/login', { method: 'POST', body: 'password=' + encodeURIComponent(pw.value) + '&remember=' + (remember ? '1' : '0') })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'خطای سرور' }; }); })
      .then(function (d) {
        if (d.ok) {
          btnText.textContent = '✓ خوش آمدید؛ در حال انتقال …';
          location.href = '/admin';
        } else {
          err.textContent = d.error || 'رمز عبور نادرست است';
          btn.disabled = false;
          btnText.textContent = '🔐 ورود به پنل مدیریت';
          wrap.classList.remove('shake');
          void wrap.offsetWidth;
          wrap.classList.add('shake');
          pw.select();
        }
      })
      .catch(function () {
        err.textContent = 'خطا در برقراری ارتباط با سرور';
        btn.disabled = false;
        btnText.textContent = '🔐 ورود به پنل مدیریت';
      });
  });
})();
</script>
</body>
</html>`;
}

/* ─────────────────────────── داشبورد مدیریت ─────────────────────────── */
function dashboardPage(address) {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#0a0518">
<script>(function(){try{if(localStorage.getItem('vw_theme')==='light')document.documentElement.setAttribute('data-theme','light');}catch(e){}})();</script>
<title>پنل مدیریت | VODIWALKER VPN</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
 ${baseCSS()}
body { position: relative; }
main { position: relative; z-index: 1; max-width: 1180px; margin: 0 auto; padding: 0 20px 70px; }

/* نوار بالا */
.topbar {
  position: sticky; top: 0; z-index: 50;
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 14px clamp(16px, 4vw, 40px);
  background: var(--surface-dark2);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid rgba(168, 85, 247, 0.22);
}
.topbar::after { content: ''; position: absolute; bottom: -1px; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(168,85,247,0.6), rgba(34,211,238,0.6), transparent); }
.brand { display: flex; align-items: center; gap: 11px; font-weight: 900; font-size: 19px;
  direction: ltr; letter-spacing: 1px; text-shadow: 0 0 18px rgba(168, 85, 247, 0.6); }
.brand .b-logo { width: 40px; height: 40px; display: grid; place-items: center; font-size: 19px; border-radius: 13px;
  background: linear-gradient(135deg, #7c3aed, #a855f7 60%, #22d3ee); box-shadow: 0 0 22px rgba(168, 85, 247, 0.5);
  animation: logoFloat 3.5s ease-in-out infinite; }
.brand b { background: linear-gradient(90deg, #c084fc, #22d3ee); -webkit-background-clip: text; background-clip: text; color: transparent; }
.topbar-left { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.addr-badge {
  display: inline-flex; align-items: center; gap: 7px; cursor: pointer; user-select: none;
  font-size: 11.5px; color: var(--purple); direction: ltr; font-family: monospace;
  background: rgba(124, 58, 237, 0.12); border: 1px solid rgba(168, 85, 247, 0.3);
  padding: 7px 12px; border-radius: 99px; transition: 0.2s;
  max-width: min(330px, 40vw); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.addr-badge:hover { background: rgba(124, 58, 237, 0.25); box-shadow: 0 0 16px rgba(168, 85, 247, 0.35); }
.btn-logout { text-decoration: none; font-size: 12.5px; color: #fecdd3; padding: 8px 16px; border-radius: 99px;
  background: rgba(190, 18, 60, 0.18); border: 1px solid rgba(244, 63, 94, 0.4); transition: 0.2s; }
.btn-logout:hover { background: rgba(190, 18, 60, 0.35); box-shadow: 0 0 18px rgba(244, 63, 94, 0.4); }

/* بنر */
.hero-banner {
  position: relative; margin-top: 26px; border-radius: 24px; overflow: hidden; min-height: 175px;
  display: flex; align-items: flex-start; padding: 22px clamp(20px, 5vw, 50px) 30px;
  background:
    linear-gradient(120deg, rgba(88, 28, 135, 0.55), rgba(30, 12, 60, 0.88)),
    url('${BG_IMAGE}') center / cover no-repeat;
  border: 1px solid rgba(168, 85, 247, 0.3);
  box-shadow: 0 20px 60px rgba(88, 28, 135, 0.35);
  animation: cardIn 0.9s cubic-bezier(0.16, 1, 0.3, 1) both;
}
.hero-banner::before { content: ''; position: absolute; inset: 0;
  background: radial-gradient(circle at 85% 20%, rgba(34, 211, 238, 0.25), transparent 50%),
              linear-gradient(90deg, rgba(10, 5, 24, 0.2), rgba(10, 5, 24, 0.85)); }
.hero-text { position: relative; z-index: 2; transform: translateY(-2px); }
.hero-text h1 { font-size: clamp(21px, 4.5vw, 30px); font-weight: 900; margin-bottom: 9px; color: #fff;
  text-shadow: 0 0 26px rgba(168, 85, 247, 0.55); }
.hero-text p { color: #cbbdf0; font-size: 13.5px; max-width: 560px; line-height: 2; }
.hero-badges { display: flex; gap: 8px; margin-top: 15px; flex-wrap: wrap; }
.hb { font-size: 10.5px; letter-spacing: 0.5px; padding: 6px 13px; border-radius: 99px; direction: ltr;
  background: rgba(5, 1, 18, 0.55); border: 1px solid rgba(168, 85, 247, 0.35); color: #d8ccf5; }
.hb.cy { border-color: rgba(34, 211, 238, 0.4); color: #a5f3fc; }

/* آمار */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 22px; }
.stat-card { display: flex; align-items: center; gap: 15px; padding: 19px 20px; border-radius: 19px;
  background: var(--card); border: 1px solid var(--border);
  backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
  animation: cardIn 0.7s cubic-bezier(0.16, 1, 0.3, 1) both;
  transition: transform 0.25s, box-shadow 0.25s, border-color 0.25s; }
.stat-card:nth-child(1) { animation-delay: 0.05s; } .stat-card:nth-child(2) { animation-delay: 0.1s; }
.stat-card:nth-child(3) { animation-delay: 0.15s; } .stat-card:nth-child(4) { animation-delay: 0.2s; }
.stat-card:nth-child(5) { animation-delay: 0.25s; } .stat-card:nth-child(6) { animation-delay: 0.3s; }
.stat-card:hover { transform: translateY(-4px); border-color: rgba(168, 85, 247, 0.55);
  box-shadow: 0 12px 34px rgba(124, 58, 237, 0.3); }
.stat-icon { width: 50px; height: 50px; flex-shrink: 0; display: grid; place-items: center; font-size: 21px; border-radius: 16px; }
.si-1 { background: linear-gradient(135deg, rgba(124,58,237,0.35), rgba(168,85,247,0.2)); box-shadow: 0 0 22px rgba(168,85,247,0.3); }
.si-2 { background: linear-gradient(135deg, rgba(16,185,129,0.3), rgba(34,211,238,0.15)); box-shadow: 0 0 22px rgba(52,211,153,0.28); }
.si-3 { background: linear-gradient(135deg, rgba(34,211,238,0.3), rgba(59,130,246,0.15)); box-shadow: 0 0 22px rgba(34,211,238,0.28); }
.si-4 { background: linear-gradient(135deg, rgba(232,121,249,0.3), rgba(168,85,247,0.15)); box-shadow: 0 0 22px rgba(232,121,249,0.28); }
.si-5 { background: linear-gradient(135deg, rgba(251,191,36,0.3), rgba(251,146,60,0.15)); box-shadow: 0 0 22px rgba(251,191,36,0.28); }
.si-6 { background: linear-gradient(135deg, rgba(251,113,133,0.3), rgba(190,18,60,0.15)); box-shadow: 0 0 22px rgba(251,113,133,0.28); }
.stat-value { font-size: 19px; font-weight: 900; line-height: 1.3; }
.stat-label { font-size: 11.5px; color: var(--muted); margin-top: 2px; }

/* بخش‌ها */
.section { margin-top: 34px; }
.section-title { display: flex; align-items: center; gap: 11px; font-size: 16.5px; font-weight: 800; margin-bottom: 16px; }
.st-icon { width: 38px; height: 38px; display: grid; place-items: center; font-size: 17px; border-radius: 12px;
  background: linear-gradient(135deg, rgba(124,58,237,0.4), rgba(34,211,238,0.2));
  box-shadow: 0 0 18px rgba(124,58,237,0.35); }
.section-title .count { color: var(--muted); font-size: 13px; font-weight: 400; }
.title-line { flex: 1; height: 1px; background: linear-gradient(90deg, rgba(168,85,247,0.4), transparent); }

/* ویجت‌های دو ستونه داشبورد */
.dash-grid { display: grid; grid-template-columns: 1.3fr 1fr; gap: 18px; margin-top: 22px; }
@media (max-width: 860px) { .dash-grid { grid-template-columns: 1fr; } }
.widget-card { padding: 22px; border-radius: 20px; background: var(--card); border: 1px solid var(--border);
  backdrop-filter: blur(16px); animation: cardIn 0.7s 0.1s cubic-bezier(0.16,1,0.3,1) both; }
.widget-card h4 { font-size: 14px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.usage-row { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
.usage-row:last-child { margin-bottom: 0; }
.usage-row .u-name { width: 92px; flex-shrink: 0; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.usage-row .u-bar { flex: 1; height: 10px; border-radius: 99px; background: var(--input-bg); overflow: hidden; border: 1px solid rgba(168,85,247,0.15); }
.usage-row .u-bar i { display: block; height: 100%; border-radius: 99px; background: linear-gradient(90deg, #7c3aed, #a855f7, #22d3ee); background-size: 200% 100%; animation: gradShift 4s linear infinite; }
.usage-row .u-val { width: 64px; flex-shrink: 0; text-align: left; direction: ltr; font-size: 11px; color: var(--muted); }
.recent-item { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 11px 0;
  border-bottom: 1px dashed rgba(168,85,247,0.16); font-size: 12.5px; }
.recent-item:last-child { border-bottom: none; }
.recent-item .r-name { font-weight: 700; }
.recent-item .r-meta { color: var(--muted); font-size: 11px; }
.empty-mini { text-align: center; color: var(--muted); font-size: 12.5px; padding: 20px 0; }

/* فرم ساخت */
.create-card { padding: 24px; border-radius: 21px; background: var(--card); border: 1px solid var(--border);
  backdrop-filter: blur(18px); animation: cardIn 0.8s 0.35s cubic-bezier(0.16, 1, 0.3, 1) both;
  position: relative; overflow: hidden; }
.create-card::after { content: '✦'; position: absolute; top: -30px; left: -30px; font-size: 130px;
  opacity: 0.05; pointer-events: none; }
.form-grid { display: grid; grid-template-columns: 2fr 1.6fr 1fr 1fr 1fr; gap: 14px; align-items: end; }
.fg label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 8px; }
.fg input, .fg select, .modal input, .modal select, .ipscan-card textarea, .ipscan-card select, .settings-card input, .settings-card select {
  width: 100%; padding: 12.5px 14px; font-size: 13.5px; color: var(--text);
  background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 12px;
  outline: none; transition: 0.25s; font-family: inherit;
}
.fg input:focus, .fg select:focus, .modal input:focus, .modal select:focus, .ipscan-card textarea:focus, .ipscan-card select:focus, .settings-card input:focus, .settings-card select:focus {
  border-color: var(--purple);
  box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.15), 0 0 20px rgba(168, 85, 247, 0.22); }
.fg input::placeholder { color: #5d5380; font-size: 12px; }
select option { background: #120a26; color: #efeafc; }
.seg { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; background: var(--input-bg);
  padding: 6px; border-radius: 12px; border: 1px solid var(--input-border); }
.seg-btn { padding: 8px 6px; border: none; border-radius: 8px; background: transparent; color: var(--muted);
  font-size: 12.5px; font-weight: 700; cursor: pointer; transition: 0.25s; direction: ltr; font-family: inherit; }
.seg-btn.active { background: linear-gradient(135deg, #7c3aed, #a855f7); color: #fff;
  box-shadow: 0 0 16px rgba(168, 85, 247, 0.45); }
.btn-create { position: relative; overflow: hidden; padding: 13px 22px; border: none; border-radius: 12px;
  cursor: pointer; font-size: 13.5px; font-weight: 800; color: #fff; font-family: inherit; white-space: nowrap;
  background: linear-gradient(135deg, #6d28d9, #a855f7 55%, #22d3ee 140%); background-size: 200% 200%;
  box-shadow: 0 6px 22px rgba(124, 58, 237, 0.45); transition: 0.25s; animation: gradShift 5s ease infinite; }
.btn-create:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 9px 30px rgba(124, 58, 237, 0.65); }
.btn-create:disabled { opacity: 0.6; cursor: wait; }
.btn-secondary { padding: 10px 16px; border-radius: 11px; cursor: pointer; font-size: 12.5px; font-weight: 700;
  color: var(--text); font-family: inherit; background: rgba(124,58,237,0.12); border: 1px solid rgba(168,85,247,0.3); transition: 0.2s; }
.btn-secondary:hover { background: rgba(124,58,237,0.28); }
.btn-secondary:disabled { opacity: 0.55; cursor: wait; }
.usage-controls .btn-secondary { color: #fff; background: linear-gradient(135deg, #6d28d9, #a855f7 55%, #22d3ee 140%); border-color: rgba(168,85,247,0.55); box-shadow: 0 5px 18px rgba(124,58,237,0.28); }
.usage-controls .btn-secondary:hover:not(:disabled) { background: linear-gradient(135deg, #7c3aed, #c084fc 55%, #22d3ee 140%); transform: translateY(-1px); box-shadow: 0 7px 22px rgba(124,58,237,0.4); }
.usage-controls .btn-secondary:disabled { opacity: 0.55; transform: none; }

/* جستجو و کارت‌ها */
.search-row { margin-bottom: 16px; }
.search-row input { width: 100%; max-width: 340px; padding: 12px 16px; font-size: 13px; color: var(--text);
  font-family: inherit; background: var(--input-bg); border: 1px solid var(--input-border);
  border-radius: 12px; outline: none; transition: 0.25s; }
.search-row input:focus { border-color: var(--purple); box-shadow: 0 0 0 3px rgba(168,85,247,0.15); }
.clients-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); gap: 16px; }
.client-card { padding: 20px; border-radius: 19px; background: var(--card); border: 1px solid var(--border);
  backdrop-filter: blur(16px); animation: cardIn 0.55s cubic-bezier(0.16, 1, 0.3, 1) both;
  transition: transform 0.22s, box-shadow 0.22s, border-color 0.22s; position: relative; overflow: visible; }
.client-card:hover { transform: translateY(-4px); box-shadow: 0 14px 40px rgba(124, 58, 237, 0.28);
  border-color: rgba(168, 85, 247, 0.5); }
.client-card::before { content: ''; position: absolute; top: 0; right: 0; left: 0; height: 2px; border-radius: 19px 19px 0 0;
  background: linear-gradient(90deg, transparent, var(--purple), var(--cyan), transparent); opacity: 0.7; }
.client-card.inactive { opacity: 0.55; }
.client-card.expired { border-color: rgba(251, 113, 133, 0.35); }
.client-card.expired::before { background: linear-gradient(90deg, transparent, var(--red), transparent); }
.cc-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 6px; }
.cc-name { font-size: 17px; font-weight: 800; word-break: break-word; }
.cc-badges { display: flex; align-items: center; gap: 7px; flex-shrink: 0; }
.proto-badge { font-size: 9.5px; font-weight: 800; letter-spacing: 0.8px; padding: 5px 10px; border-radius: 8px;
  direction: ltr; font-family: monospace; }
.proto-badge.vless { background: rgba(124, 58, 237, 0.25); color: #d8b4fe;
  border: 1px solid rgba(168, 85, 247, 0.5); box-shadow: 0 0 12px rgba(168, 85, 247, 0.25); }
.proto-badge.trojan { background: rgba(34, 211, 238, 0.12); color: #a5f3fc;
  border: 1px solid rgba(34, 211, 238, 0.45); box-shadow: 0 0 12px rgba(34, 211, 238, 0.2); }
.port-badge { font-size: 10.5px; color: #93c5fd; background: rgba(59, 130, 246, 0.12); padding: 5px 8px;
  border-radius: 8px; direction: ltr; font-family: monospace; border: 1px solid rgba(59,130,246,0.35); }
.status-dot { width: 9px; height: 9px; border-radius: 50%; }
.status-dot.active { background: var(--green); box-shadow: 0 0 10px var(--green); animation: blink 2s ease infinite; }
.status-dot.inactive { background: #6b7280; }
.status-dot.expired { background: var(--red); box-shadow: 0 0 10px var(--red); }
.cc-sub { font-size: 11px; color: var(--muted); margin-bottom: 13px; display: flex; flex-wrap: wrap; gap: 5px; }
.cc-sub .sep { opacity: 0.4; }
.usage-top { display: flex; justify-content: space-between; align-items: center; font-size: 11.5px;
  color: var(--muted); margin-bottom: 7px; }
.usage-top b { color: var(--text); }
.bar { height: 9px; border-radius: 99px; background: var(--input-bg); overflow: hidden;
  border: 1px solid rgba(168, 85, 247, 0.15); }
.bar-fill { height: 100%; border-radius: 99px; position: relative;
  background: linear-gradient(90deg, #7c3aed, #a855f7, #22d3ee); background-size: 200% 100%;
  animation: gradShift 3.5s linear infinite; box-shadow: 0 0 12px rgba(168, 85, 247, 0.6);
  transition: width 0.8s cubic-bezier(0.16, 1, 0.3, 1); }
.bar-fill.full { background: linear-gradient(90deg, #dc2626, #fb7185); box-shadow: 0 0 12px rgba(251, 113, 133, 0.6); }
.cc-actions { display: flex; gap: 8px; margin-top: 16px; align-items: stretch; }
.cc-actions .cc-primary { flex: 1; display: flex; align-items: center; justify-content: center; gap: 6px;
  padding: 10px 6px; font-size: 12px; font-weight: 700; cursor: pointer; font-family: inherit; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis;
  background: rgba(124, 58, 237, 0.14); border: 1px solid rgba(168, 85, 247, 0.3); color: var(--text);
  border-radius: 11px; transition: 0.2s; }
.cc-actions .cc-primary:hover { background: rgba(124, 58, 237, 0.32); transform: translateY(-2px);
  box-shadow: 0 4px 14px rgba(124, 58, 237, 0.35); }
.cc-actions .cc-primary.accent { background: linear-gradient(135deg, rgba(8,145,178,.28), rgba(34,211,238,.18));
  border-color: rgba(34,211,238,.4); }
.cc-actions .cc-primary.accent:hover { background: linear-gradient(135deg, rgba(8,145,178,.45), rgba(34,211,238,.3));
  box-shadow: 0 4px 14px rgba(34,211,238,.35); }
.cc-menu-wrap { position: relative; flex-shrink: 0; }
.cc-menu-btn { width: 38px; height: 100%; min-height: 38px; border-radius: 11px; cursor: pointer; font-size: 16px;
  background: rgba(124, 58, 237, 0.1); border: 1px solid rgba(168, 85, 247, 0.22); color: var(--text);
  transition: 0.2s; font-family: inherit; line-height: 1; }
.cc-menu-btn:hover, .cc-menu-btn.open { background: rgba(124, 58, 237, 0.32); }
.cc-menu { position: absolute; bottom: calc(100% + 8px); left: 0; min-width: 190px; z-index: 20;
  background: var(--surface-dark); border: 1px solid rgba(168, 85, 247, 0.35); border-radius: 13px;
  box-shadow: 0 14px 40px rgba(0,0,0,0.5); padding: 6px; display: none; flex-direction: column; gap: 2px; }
.cc-menu.open { display: flex; animation: cardIn 0.18s ease both; }
.cc-menu button { display: flex; align-items: center; gap: 9px; width: 100%; padding: 9px 11px; font-size: 12.5px;
  background: transparent; border: none; border-radius: 9px; color: var(--text); cursor: pointer;
  font-family: inherit; text-align: right; transition: 0.15s; }
.cc-menu button:hover { background: rgba(124, 58, 237, 0.2); }
.cc-menu button.danger { color: #fda4af; }
.cc-menu button.danger:hover { background: rgba(190, 18, 60, 0.22); }
.cc-menu hr { border: none; border-top: 1px solid rgba(168,85,247,0.16); margin: 4px 2px; }

/* آی‌پی تمیز */
.ipscan-card { padding: 24px; border-radius: 21px; background: var(--card); border: 1px solid var(--border);
  backdrop-filter: blur(18px); animation: cardIn 0.7s cubic-bezier(0.16,1,0.3,1) both; }
.ipscan-grid { display: grid; grid-template-columns: 2.2fr 1fr auto; gap: 14px; align-items: end; margin-bottom: 18px; }
@media (max-width: 700px) { .ipscan-grid { grid-template-columns: 1fr; } }
.ipscan-card textarea { resize: vertical; min-height: 90px; font-family: monospace; direction: ltr; text-align: left; font-size: 12.5px; }
.ipscan-hint { font-size: 11.5px; color: var(--muted); margin-top: 8px; line-height: 1.9; }
.active-ip-box { margin-top: 16px; }
.active-ip-card { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; padding:14px 16px; border-radius:14px; background:var(--input-bg); border:1px solid rgba(52,211,153,.28); }
.active-ip-card .ip-value { direction:ltr; font-family:monospace; color:var(--mono-accent); font-size:13px; word-break:break-all; }
.active-ip-card .ip-label { color:var(--muted); font-size:11.5px; margin-bottom:4px; }
.btn-danger-soft { padding:9px 14px; border-radius:10px; cursor:pointer; font-size:12px; font-weight:700; color:#fda4af; background:rgba(190,18,60,.12); border:1px solid rgba(244,63,94,.35); font-family:inherit; transition:.2s; }
.btn-danger-soft:hover { background:rgba(190,18,60,.25); }

/* حالت خالی */
.empty-state { text-align: center; padding: 60px 20px; color: var(--muted); }
.empty-state .e-icon { font-size: 54px; margin-bottom: 18px; display: inline-block;
  animation: logoFloat 3s ease-in-out infinite; filter: drop-shadow(0 0 20px rgba(168,85,247,0.5)); }
.empty-state p { font-size: 14px; line-height: 2.1; }

/* مودال */
.overlay { position: fixed; inset: 0; z-index: 100; display: flex; align-items: center; justify-content: center;
  padding: 20px; background: rgba(5, 1, 18, 0.7); backdrop-filter: blur(10px);
  opacity: 0; visibility: hidden; transition: 0.28s; }
.overlay.show { opacity: 1; visibility: visible; }
.modal { width: min(560px, 100%); max-height: 88vh; overflow-y: auto; border-radius: 22px;
  background: var(--surface-dark); border: 1px solid rgba(168, 85, 247, 0.35);
  box-shadow: 0 30px 80px rgba(88, 28, 135, 0.5);
  transform: translateY(26px) scale(0.96); transition: 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
.modal.wide { width: min(760px, 100%); }
.overlay.show .modal { transform: none; }
.modal-head { display: flex; align-items: center; justify-content: space-between; padding: 18px 22px;
  border-bottom: 1px solid rgba(168, 85, 247, 0.2); position: sticky; top: 0;
  background: var(--surface-dark); z-index: 2; }
.modal-head h3 { font-size: 15.5px; }
.modal-close { background: none; border: none; color: var(--muted); font-size: 17px; cursor: pointer;
  width: 32px; height: 32px; border-radius: 9px; transition: 0.2s; }
.modal-close:hover { background: rgba(251, 113, 133, 0.15); color: var(--red); }
.modal-body { padding: 22px; }
.link-box { margin-bottom: 16px; }
.link-label { font-size: 12px; color: var(--muted); margin-bottom: 8px; }
.link-row { display: flex; gap: 8px; align-items: stretch; }
.link-row input, .link-row textarea { flex: 1; padding: 11.5px 13px; font-size: 11.5px; color: var(--mono-accent);
  direction: ltr; text-align: left; font-family: monospace; background: var(--input-bg);
  border: 1px solid rgba(34, 211, 238, 0.3); border-radius: 11px; outline: none; resize: none; line-height: 1.8; }
.link-row input:focus, .link-row textarea:focus { border-color: var(--cyan);
  box-shadow: 0 0 16px rgba(34, 211, 238, 0.25); }
.mini-btn { padding: 0 18px; border: none; border-radius: 11px; cursor: pointer; font-size: 12.5px;
  font-weight: 700; color: #fff; font-family: inherit; white-space: nowrap;
  background: linear-gradient(135deg, #0891b2, #22d3ee); box-shadow: 0 4px 16px rgba(34, 211, 238, 0.35); transition: 0.2s; }
.mini-btn:hover { box-shadow: 0 6px 22px rgba(34, 211, 238, 0.55); transform: translateY(-1px); }
.hint { font-size: 11.5px; color: var(--muted); line-height: 2.1;
  background: rgba(124, 58, 237, 0.08); border: 1px solid rgba(168, 85, 247, 0.18);
  border-radius: 13px; padding: 13px 16px; }
.modal label { display: block; font-size: 12px; color: var(--muted); margin: 14px 0 7px; }
.modal .btn-create { width: 100%; margin-top: 20px; }
.all-ports-list { display: flex; flex-direction: column; gap: 9px; max-height: 340px; overflow-y: auto; margin-bottom: 14px; }
.ap-row { display: flex; align-items: center; gap: 10px; background: var(--input-bg); border: 1px solid rgba(168,85,247,0.18);
  border-radius: 11px; padding: 9px 12px; }
.ap-row .ap-port { width: 84px; flex-shrink: 0; font-size: 11.5px; direction: ltr; font-family: monospace; color: #93c5fd; }
.ap-row .ap-port b.tls-tag { color: var(--green); font-size: 9.5px; margin-right: 4px; }
.ap-row input { flex: 1; background: transparent; border: none; outline: none; color: var(--mono-accent); font-family: monospace;
  font-size: 11px; direction: ltr; text-align: left; }
.ap-row button { padding: 6px 12px; border-radius: 8px; border: none; cursor: pointer; font-size: 11px; font-weight: 700;
  background: rgba(34,211,238,0.18); color: var(--cyan); border: 1px solid rgba(34,211,238,0.35); }
.ap-row button:hover { background: rgba(34,211,238,0.32); }

/* توست */
#toasts { position: fixed; bottom: 22px; left: 22px; z-index: 200; display: flex; flex-direction: column; gap: 9px; }
.toast { display: flex; align-items: center; gap: 9px; padding: 13px 18px; border-radius: 13px;
  font-size: 13px; font-weight: 600; color: var(--text); background: var(--surface-dark);
  border: 1px solid rgba(168, 85, 247, 0.45);
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45), 0 0 20px rgba(124, 58, 237, 0.25);
  animation: toastIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) both; max-width: 340px; }
.toast.success { border-color: rgba(52, 211, 153, 0.55); box-shadow: 0 0 22px rgba(52, 211, 153, 0.25); }
.toast.error { border-color: rgba(251, 113, 133, 0.55); box-shadow: 0 0 22px rgba(251, 113, 133, 0.25); }
.toast.out { animation: toastOut 0.35s ease both; }
@keyframes toastIn { from { opacity: 0; transform: translateX(-40px); } to { opacity: 1; transform: none; } }
@keyframes toastOut { to { opacity: 0; transform: translateX(-40px); } }

/* واکنش‌گرا */
@media (max-width: 900px) { .form-grid { grid-template-columns: 1fr 1fr; } .fg-btn { grid-column: span 2; } }
@media (max-width: 560px) {
  .form-grid { grid-template-columns: 1fr; } .fg-btn { grid-column: span 1; }
  .stats { grid-template-columns: 1fr 1fr; gap: 10px; }
  .stat-card { padding: 14px; gap: 10px; }
  .stat-icon { width: 42px; height: 42px; font-size: 19px; }
  .stat-value { font-size: 16px; }
  .topbar { flex-direction: column; align-items: stretch; }
  .topbar-left { justify-content: center; }
  .addr-badge { max-width: 100%; }
  .link-row { flex-direction: column; }
  .mini-btn { padding: 11px; }
  .ipscan-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
  <div class="bg-img"></div>
  <div class="bg-overlay"></div>
  <div class="particles" id="particles"></div>

  <header class="topbar">
    <div class="brand"><span class="b-logo">⚡</span>VODIWALKER&nbsp;<b>VPN</b></div>
    <div class="topbar-left">
      <span class="addr-badge" id="addrBadge" title="آدرس کانفیگ‌ها — برای کپی کلیک کنید">🌐 <span id="addrText"></span></span>
      <button type="button" class="btn-theme" id="themeToggle" title="تغییر پوسته (روشن/تاریک)">🌙</button>
      <a href="/logout" class="btn-logout">خروج ⎋</a>
    </div>
  </header>

  <main>
    <nav class="tabs" id="tabs">
      <button class="tab-btn active" data-tab="tabDash">📊 داشبورد</button>
      <button class="tab-btn" data-tab="tabClients">👥 کلاینت‌ها</button>
      <button class="tab-btn" data-tab="tabIP">🌐 آی‌پی تمیز</button>
      <button class="tab-btn" data-tab="tabSettings">⚙️ تنظیمات پنل</button>
      <button class="tab-btn" data-tab="tabNews">📰 اخبار</button>
    </nav>

    <!-- ═══════ تب داشبورد ═══════ -->
    <section class="tab-panel active" id="tabDash">
      <section class="hero-banner">
        <div class="hero-text">
          <h1>پنل مدیریت VODIWALKER</h1>
          <p>ساخت کلاینت اختصاصی با حجم و اعتبار دلخواه، دریافت لینک سابسکریپشن و کانفیگ اختصاصی برای تمامی پورت‌ها و مدیریت مصرف — همه‌چیز در یک پنل.</p>
          <div class="hero-badges">
            <span class="hb">VLESS</span>
            <span class="hb cy">TROJAN</span>
            <span class="hb">WEBSOCKET</span>
            <span class="hb cy">TLS 1.3</span>
            <span class="hb">${ALLOWED_PORTS.length} پورت فعال</span>
          </div>
        </div>
      </section>

      <section class="stats">
        <div class="stat-card"><div class="stat-icon si-1">👥</div><div><div class="stat-value" id="statTotal">…</div><div class="stat-label">کل کلاینت‌ها</div></div></div>
        <div class="stat-card"><div class="stat-icon si-2">🟢</div><div><div class="stat-value" id="statActive">…</div><div class="stat-label">کلاینت‌های فعال</div></div></div>
        <div class="stat-card"><div class="stat-icon si-3">📊</div><div><div class="stat-value" id="statUsed">…</div><div class="stat-label">مصرف کل</div></div></div>
      </section>

      <div class="dash-grid">
        <div class="widget-card">
          <h4>📈 پرمصرف‌ترین کلاینت‌ها</h4>
          <div id="topUsageBox"><div class="empty-mini">هنوز مصرفی ثبت نشده است</div></div>
        </div>
        <div class="widget-card">
          <h4>🆕 آخرین کلاینت‌های ساخته‌شده</h4>
          <div id="recentBox"><div class="empty-mini">هنوز کلاینتی نساخته‌اید</div></div>
        </div>
      </div>

      <section class="support-banner">
        <div class="sb-text">
          <b>💬 پشتیبانی و اطلاعیه‌های VodiWalker</b>
          <span>عضو کانال بشید تا از به‌روزرسانی‌ها باخبر بشید؛ برای مشکلات پنل هم مستقیم به پشتیبانی پیام بدید.</span>
        </div>
        <div class="sb-actions">
          <a class="channel" href="https://t.me/vodiwalkervpn03" target="_blank" rel="noopener">📢 کانال</a>
          <a class="admin" href="https://t.me/Vodiwalker02" target="_blank" rel="noopener">🧑‍💻 پشتیبانی</a>
        </div>
      </section>
    </section>

    <!-- ═══════ تب کلاینت‌ها ═══════ -->
    <section class="tab-panel" id="tabClients">
      <section class="section" style="margin-top:8px">
        <div class="section-title" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
          <span><span class="st-icon">✨</span> ساخت کلاینت جدید <span class="title-line"></span></span>
          <button type="button" class="btn-secondary" id="quickCreateBtn" style="white-space:nowrap">🚀 ساخت خودکار یک‌کلیکی (پیشنهادی)</button>
        </div>
        <form class="create-card" id="createForm">
          <div class="form-grid">
            <div class="fg">
              <label>نام کلاینت</label>
              <input type="text" id="fName" placeholder="مثلاً: علی" maxlength="40" required>
            </div>
            <div class="fg">
              <label>پروتکل</label>
              <div class="seg" id="fProtocol">
                <button type="button" class="seg-btn active" data-protocol="vless">VLESS</button>
                <button type="button" class="seg-btn" data-protocol="trojan">Trojan</button>
              </div>
            </div>
            <div class="fg">
              <label>پورت</label>
              <select id="fPort"></select>
            </div>
            <div class="fg">
              <label>حجم (GB)</label>
              <input type="number" id="fLimit" placeholder="0 = نامحدود" min="0" step="0.5">
            </div>
            <div class="fg">
              <label>اعتبار (روز)</label>
              <input type="number" id="fExpiry" placeholder="0 = نامحدود" min="0" step="1">
            </div>
            <div class="fg fg-btn">
              <label>&nbsp;</label>
              <button type="submit" class="btn-create" id="createBtn"><span class="btn-shine"></span>⚡ ساخت کلاینت و دریافت کانفیگ</button>
            </div>
          </div>
        </form>
        <div class="ipscan-hint" style="margin-top:14px">💡 نکته: با «ساخت خودکار» یک کلاینت با تنظیمات پیش‌فرض ساخته می‌شود و بلافاصله لینک سابسکریپشن و کانفیگ‌های آماده‌ی تمام پورت‌ها در اختیارتان قرار می‌گیرد؛ نیازی به پر کردن فرم نیست.</div>
      </section>

      <section class="section">
        <div class="section-title"><span class="st-icon">👥</span> کلاینت‌ها <span class="count" id="clientCount"></span><span class="title-line"></span><div class="usage-controls" style="margin-right:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span id="usageAutoStatus" class="usage-auto-status" style="font-size:12px;opacity:.8">⏱ بروزرسانی خودکار: روشن</span>
            <select id="usageInterval" class="input" style="width:auto;min-width:120px;padding:9px 12px">
              <option value="15000">هر ۱۵ ثانیه</option>
              <option value="30000">هر ۳۰ ثانیه</option>
              <option value="60000" selected>هر ۱ دقیقه</option>
              <option value="300000">هر ۵ دقیقه</option>
            </select>
            <button type="button" class="btn-secondary" id="usageAutoBtn" style="white-space:nowrap">⏸ غیرفعال کردن خودکار</button>
            <button type="button" class="btn-secondary" id="usageRefreshBtn" style="white-space:nowrap">🔄 بروزرسانی الان</button>
          </div></div>
        <div class="search-row"><input type="text" id="searchBox" placeholder="🔍 جستجوی کلاینت…"></div>
        <div class="clients-grid" id="clientsGrid"></div>
        <div class="empty-state" id="emptyState" style="display:none">
          <span class="e-icon">🛰️</span>
          <p>هنوز کلاینتی نساخته‌اید.<br>از فرم بالا اولین کلاینت خود را بسازید تا لینک سابسکریپشن و کانفیگ اختصاصی دریافت کنید.</p>
        </div>
        <div class="empty-state" id="noResult" style="display:none">
          <span class="e-icon">🔍</span>
          <p>کلایندی با این نام یا UUID پیدا نشد.</p>
        </div>
      </section>
    </section>

    <!-- ═══════ تب آی‌پی و PROXYIP ═══════ -->
    <section class="tab-panel" id="tabIP">
      <section class="section" style="margin-top:8px">
        <div class="section-title"><span class="st-icon">🌐</span> مدیریت آی‌پی‌های کلودفلر <span class="title-line"></span></div>
        <div class="ipscan-card">
          <div class="gh-source-row">
            <span>📄 آی‌پی‌های موردنظر را از فهرست زیر بردارید و یکی‌یکی به لیست پایین اضافه کنید؛ هیچ تست یا بررسی سلامتی انجام نمی‌شود.</span>
            <a class="btn-secondary" id="openGithubIpsBtn" href="https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.json" target="_blank" rel="noopener" style="text-decoration:none; display:inline-flex; align-items:center; gap:6px;">🌐 فهرست آی‌پی‌ها</a>
          </div>
          <div class="ipscan-grid" style="grid-template-columns:1fr auto;">
            <div class="fg">
              <label>آی‌پی کلودفلر</label>
              <input type="text" id="ipInput" placeholder="مثلاً 104.16.0.1 — بعد از تایپ، Enter یا «افزودن به لیست» را بزنید" inputmode="numeric" autocomplete="off" style="direction:ltr;text-align:left;">
            </div>
            <div class="fg fg-btn">
              <label>&nbsp;</label>
              <button type="button" class="btn-secondary" id="ipAddBtn" style="white-space:nowrap">➕ افزودن به لیست</button>
            </div>
          </div>
          <div class="ipscan-hint" style="margin-bottom:12px">هرچند آی‌پی که می‌خواهید یکی‌یکی وارد و به لیست زیر اضافه کنید؛ در پایان با یک کلیک، همه را یک‌جا به کانفیگ‌ها اضافه کنید.</div>
          <div id="pendingIpBox" class="pending-ip-box"></div>
          <button type="button" class="btn-create" id="ipApplyBtn" style="width:100%; margin-top:2px; display:none"><span class="btn-shine"></span>⚡ افزودن به کانفیگ‌ها</button>
          <div class="ipscan-hint">آی‌پی(های) فعال به‌عنوان مقصد اتصال کانفیگ‌ها استفاده می‌شوند و SNI/Host کانفیگ دست‌نخورده باقی می‌ماند؛ سابسکریپشن و «کانفیگ همه‌ی پورت‌ها» برای هر آی‌پی فعال، یک گروه کانفیگ جداگانه می‌سازند.</div>
          <div class="active-ip-box" id="activeIpBox"></div>
        </div>
      </section>

      <section class="section">
        <div class="section-title"><span class="st-icon">🛰️</span> PROXYIP <span class="title-line"></span></div>
        <div class="ipscan-card">
          <div class="ipscan-grid" style="grid-template-columns:2fr 1fr auto;">
            <div class="fg">
              <label>آدرس PROXYIP</label>
              <input type="text" id="proxyIpInput" placeholder="مثلاً 1.2.3.4" inputmode="numeric" autocomplete="off" style="direction:ltr;text-align:left;">
            </div>
            <div class="fg">
              <label>پورت</label>
              <input type="number" id="proxyPortInput" placeholder="مثلاً 443" min="1" max="65535" value="443" style="direction:ltr;text-align:left;">
            </div>
            <div class="fg fg-btn">
              <label>&nbsp;</label>
              <button type="button" class="btn-create" id="proxyApplyBtn"><span class="btn-shine"></span>🚀 ذخیره PROXYIP</button>
            </div>
          </div>
          <div class="ipscan-hint">PROXYIP فقط هنگام خطای اتصال مستقیم به‌عنوان مسیر جایگزین استفاده می‌شود. می‌توانید هر زمان آن را حذف کنید.</div>
          <div class="active-ip-box" id="proxyIpBox"></div>
        </div>
      </section>
    </section>

    <!-- ═══════ تب تنظیمات پنل ═══════ -->
    <section class="tab-panel" id="tabSettings">
      <section class="section" style="margin-top:8px">
        <div class="section-title"><span class="st-icon">⚙️</span> تنظیمات پنل <span class="title-line"></span></div>
        <div class="settings-grid">

          <div class="settings-card">
            <h4>🖥️ وضعیت سرور</h4>
            <div class="status-row"><span>آدرس کانفیگ‌ها</span><b id="stAddr">—</b></div>
            <div class="status-row"><span>اتصال KV</span><b id="stKV">—</b></div>
            <div class="status-row"><span>آی‌پی‌های فعال کانفیگ‌ها</span><b id="preferredIpStatus">—</b></div>
            <div class="status-row"><span>نسخه پنل</span><b>v${VERSION}</b></div>
            <div class="status-row"><span>مسیر وب‌سوکت</span><b style="direction:ltr">${WS_PATH}</b></div>
          </div>

          <div class="settings-card">
            <h4>🧩 مقادیر پیش‌فرض کلاینت جدید</h4>
            <label>پروتکل پیش‌فرض</label>
            <select id="setProtocol"><option value="vless">VLESS</option><option value="trojan">Trojan</option></select>
            <label>پورت پیش‌فرض</label>
            <select id="setPort"></select>
            <label>پیشوند نام پیشنهادی</label>
            <input type="text" id="setRemark" placeholder="مثلاً: کاربر-" maxlength="60">
            <button type="button" class="btn-create" id="saveDefaultsBtn" style="margin-top:16px"><span class="btn-shine"></span>💾 ذخیره مقادیر پیش‌فرض</button>
          </div>

          <div class="settings-card">
            <h4>🔐 امنیت پنل</h4>
            <label>رمز عبور فعلی</label>
            <input type="password" id="curPass" placeholder="رمز فعلی را وارد کنید" autocomplete="off">
            <label>رمز عبور جدید</label>
            <input type="password" id="newPass" placeholder="حداقل ۴ کاراکتر" autocomplete="off">
            <label>تکرار رمز جدید</label>
            <input type="password" id="newPass2" placeholder="تکرار رمز جدید" autocomplete="off">
            <button type="button" class="btn-create" id="savePassBtn" style="margin-top:16px"><span class="btn-shine"></span>🔑 تغییر رمز عبور</button>
          </div>

        </div>
      </section>
    </section>

    <!-- ═══════ تب اخبار ═══════ -->
    <section class="tab-panel" id="tabNews">
      <section class="section" style="margin-top:8px">
        <div class="section-title"><span class="st-icon">📰</span> اخبار و به‌روزرسانی‌های VodiWalker <span class="title-line"></span></div>
        <div class="settings-grid">

          <div class="support-card">
            <div class="s-icon">📢</div>
            <h4>کانال اطلاعیه‌ها</h4>
            <p>برای اطلاع از هر نسخه‌ی جدید پنل، قابلیت‌های تازه و اخبار مربوط به VodiWalker، عضو کانال بشید.</p>
            <div class="support-links">
              <a class="channel" href="https://t.me/vodiwalkervpn03" target="_blank" rel="noopener">📢 عضویت در کانال VodiWalker</a>
            </div>
          </div>

          <div class="support-card">
            <div class="s-icon">💬</div>
            <h4>پشتیبانی مستقیم</h4>
            <p>برای گزارش باگ، سؤال یا راهنمایی درباره‌ی نصب و تنظیم پنل، مستقیم پیام بدید.</p>
            <div class="support-links">
              <a class="admin" href="https://t.me/Vodiwalker02" target="_blank" rel="noopener">🧑‍💻 ارتباط با پشتیبانی (@Vodiwalker02)</a>
            </div>
          </div>

          <div class="support-card">
            <div class="s-icon">📄</div>
            <h4>منبع آی‌پی‌های تمیز</h4>
            <p>پنل از این مخزن گیت‌هاب برای دریافت آی‌پی‌های تمیز کلودفلر استفاده می‌کند؛ می‌توانید خودتان هم مستقیم بررسی کنید.</p>
            <div class="support-links">
              <a class="channel" href="https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.json" target="_blank" rel="noopener">📄 مشاهده‌ی فهرست خام (GitHub)</a>
            </div>
          </div>

        </div>
      </section>
    </section>
  </main>


  <!-- مودال جزئیات (لینک ساب + کانفیگ) -->
  <div class="overlay" id="detailOverlay">
    <div class="modal">
      <div class="modal-head"><h3 id="dTitle">کانفیگ کلاینت</h3><button class="modal-close" data-close="detailOverlay">✕</button></div>
      <div class="modal-body">
        <div class="link-box">
          <div class="link-label">🔗 لینک سابسکریپشن اختصاصی (برای قرار دادن در برنامه)</div>
          <div class="link-row">
            <input type="text" id="dSubLink" readonly>
            <button class="mini-btn" id="dCopySub">کپی</button>
          </div>
        </div>
        <div class="link-box">
          <div class="link-label">⚙️ کانفیگ اختصاصی</div>
          <div class="link-row">
            <textarea id="dConfig" rows="5" readonly></textarea>
            <button class="mini-btn" id="dCopyConfig">کپی</button>
          </div>
        </div>
        <button type="button" class="btn-secondary" id="dOpenAllPorts" style="width:100%; margin-bottom:10px;">📥 دریافت کانفیگ آماده با تمامی پورت‌ها</button>
        <a href="#" target="_blank" rel="noopener" id="dOpenInfoPage" class="btn-secondary" style="width:100%; margin-bottom:14px; display:flex; align-items:center; justify-content:center; text-decoration:none;">🎨 مشاهده صفحه‌ی سابسکریپشن (گرافیکی)</a>
        <div class="hint">💡 <b>راهنما:</b> لینک سابسکریپشن را در v2rayNG، Hiddify، Streisand، Shadowrocket و برنامه‌های
		مشابه در بخش Subscription قرار دهید تا کانفیگ‌ها به‌صورت خودکار دریافت و به‌روز شوند؛ کانفیگ اختصاصی را هم می‌توانید مستقیم کپی کرده و در برنامه Import کنید.</div>
        <div class="hint" id="dWarn" style="display:none; border-color:rgba(251,113,133,.45); color:#fecdd3;"></div>
      </div>
    </div>
  </div>

  <!-- مودال کانفیگ همه پورت‌ها -->
  <div class="overlay" id="allPortsOverlay">
    <div class="modal wide">
      <div class="modal-head"><h3 id="apTitle">کانفیگ تمامی پورت‌ها</h3><button class="modal-close" data-close="allPortsOverlay">✕</button></div>
      <div class="modal-body">
        <div class="link-box" id="apSubBox">
          <div class="link-label">🔗 لینک سابسکریپشن (شامل همه‌ی پورت‌ها و همه‌ی آی‌پی‌های فعال)</div>
          <div class="link-row">
            <input type="text" id="apSubLink" readonly>
            <button class="mini-btn" id="apCopySub">کپی</button>
          </div>
        </div>
        <div id="apList" class="all-ports-list"><div class="empty-mini">در حال بارگذاری…</div></div>
        <button type="button" class="mini-btn" id="apCopyAll" style="width:100%">📋 کپی همهٔ کانفیگ‌ها (یک‌جا)</button>
        <div class="hint" style="margin-top:14px">💡 هرکدام از این لینک‌ها روی یک پورت متفاوت (و در صورت داشتن چند آی‌پی فعال، روی یک آی‌پی متفاوت) اما با همان کاربر اجرا می‌شوند؛ اگر یکی در شبکهٔ شما فیلتر یا کند بود، گزینهٔ دیگری را امتحان کنید.</div>
      </div>
    </div>
  </div>

  <!-- مودال ویرایش کلاینت -->
  <div class="overlay" id="editOverlay">
    <div class="modal">
      <div class="modal-head"><h3>✏️ ویرایش کلاینت</h3><button class="modal-close" data-close="editOverlay">✕</button></div>
      <div class="modal-body">
        <label>نام کلاینت</label>
        <input type="text" id="eName" maxlength="40">
        <label>پروتکل (با تغییر پروتکل، لینک تغییر می‌کند اما UUID ثابت می‌ماند)</label>
        <select id="eProtocol">
          <option value="vless">VLESS</option>
          <option value="trojan">Trojan</option>
        </select>
        <label>پورت</label>
        <select id="ePort"></select>
        <label>حجم (گیگابایت) — صفر یعنی نامحدود</label>
        <input type="number" id="eLimit" min="0" step="0.5">
        <label>اعتبار (روز) — صفر یعنی نامحدود</label>
        <input type="number" id="eExpiry" min="0" step="1">
        <button type="button" class="btn-create" id="eSave">💾 ذخیره تغییرات</button>
      </div>
    </div>
  </div>

  <!-- اطلاعیه‌ی ورود — در هر ورود نمایش داده می‌شود -->
  <div class="overlay" id="welcomeOverlay">
    <div class="modal">
      <div class="modal-head"><h3>📢 اطلاعیه‌های VodiWalker</h3></div>
      <div class="modal-body">
        <div class="welcome-text">
          <p style="font-size:16px;font-weight:800;line-height:2">✨ برای باخبر شدن از آخرین به‌روزرسانی‌ها، قابلیت‌های جدید و اطلاعیه‌های مهم VodiWalker حتماً عضو کانال ما شوید.</p>
          <p style="color:var(--muted);font-size:13px;line-height:2">🔔 اطلاعیه‌های نسخه‌های جدید و تغییرات مهم از طریق کانال منتشر می‌شوند تا همیشه از آخرین وضعیت پنل باخبر باشید.</p>
        </div>
        <a class="btn-create" href="https://t.me/vodiwalkervpn03" target="_blank" rel="noopener" style="display:block;text-align:center;text-decoration:none;width:100%;margin-top:10px"><span class="btn-shine"></span>📢 عضویت در کانال VodiWalker</a>
        <button type="button" class="btn-secondary" id="welcomeOkBtn" style="width:100%;margin-top:10px">ادامه به پنل ←</button>
      </div>
    </div>
  </div>

  <div id="toasts"></div>

<script>
(function () {
  'use strict';
  var ADDRESS = ${JSON.stringify(String(address || ''))};
  var WS_PATH = ${JSON.stringify(WS_PATH)};
  var TLS_PORTS = ${JSON.stringify(TLS_PORTS)};
  var PORTS = ${JSON.stringify(ALLOWED_PORTS)};
  var clients = [];
  var currentProtocol = 'vless';
  var editId = null;
  var detailClient = null;

  function $(id) { return document.getElementById(id); }

  /* ───────── منوی کشویی هر کارت کلاینت ───────── */
  function closeAllCardMenus() {
    Array.prototype.forEach.call(document.querySelectorAll('.cc-menu.open'), function (m) { m.classList.remove('open'); });
    Array.prototype.forEach.call(document.querySelectorAll('.cc-menu-btn.open'), function (b) { b.classList.remove('open'); });
  }
  document.addEventListener('click', closeAllCardMenus);

  /* ───────── پوسته‌ی روشن/تاریک ───────── */
  function applyTheme(mode, persist) {
    mode = mode === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', mode);
    $('themeToggle').textContent = mode === 'light' ? '☀️' : '🌙';
    try { localStorage.setItem('vw_theme', mode); } catch (e) {}
    if (persist) api('POST', '/api/settings', { theme: mode });
  }
  (function () {
    var cached = null;
    try { cached = localStorage.getItem('vw_theme'); } catch (e) {}
    if (cached) document.documentElement.setAttribute('data-theme', cached);
  })();
  $('themeToggle').addEventListener('click', function () {
    var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    applyTheme(cur === 'light' ? 'dark' : 'light', true);
  });

  /* ───────── اطلاعیه‌ی ورود — در هر ورود نمایش داده شود ───────── */
  (function () {
    openOverlay('welcomeOverlay');
    $('welcomeOkBtn').addEventListener('click', function () {
      closeOverlay('welcomeOverlay');
    });
  })();

  /* ───────── آی‌پی(های) تمیزِ اعمال‌شده روی کانفیگ‌ها ───────── */
  var PREFERRED_IPS = [];
  function updatePreferredIPUI(ips) {
    PREFERRED_IPS = Array.isArray(ips) ? ips.slice() : [];
    var el = $('activeIpBox');
    var statusEl = $('preferredIpStatus');
    if (statusEl) statusEl.textContent = PREFERRED_IPS.length ? (PREFERRED_IPS.length + ' آی‌پی فعال') : 'خاموش (آدرس اصلی Worker)';
    if (!el) return;
    if (PREFERRED_IPS.length) {
      el.innerHTML = '<div class="ip-label" style="margin-bottom:8px">آی‌پی‌های فعال روی کانفیگ‌ها (' + PREFERRED_IPS.length + ')</div>' +
        '<div class="active-ip-list">' + PREFERRED_IPS.map(function (ip) {
          return '<span class="active-ip-chip">' + esc(ip) + '<button type="button" data-remove-ip="' + esc(ip) + '" title="حذف">✕</button></span>';
        }).join('') + '</div>';
      Array.prototype.forEach.call(el.querySelectorAll('[data-remove-ip]'), function (btn) {
        btn.addEventListener('click', function () {
          var ip = btn.getAttribute('data-remove-ip');
          btn.disabled = true;
          api('POST', '/api/clean-ip/remove', { ip: ip }).then(function (d) {
            if (d.ok) { toast('آی‌پی ' + ip + ' حذف شد ✓', 'success'); updatePreferredIPUI(d.preferredIPs || []); }
            else { btn.disabled = false; toast(d.error || 'خطا در حذف آی‌پی', 'error'); }
          }).catch(function () { btn.disabled = false; toast('خطا در ارتباط با سرور', 'error'); });
        });
      });
    } else {
      el.innerHTML = '<div class="active-ip-card" style="border-color:rgba(251,191,36,.22)"><div><div class="ip-label">وضعیت</div><div class="ip-value" style="color:var(--muted);font-family:inherit">هیچ آی‌پی کلودفلری فعال نیست؛ کانفیگ‌ها با آدرس اصلی Worker ساخته می‌شوند.</div></div></div>';
    }
  }

  /* ───────── لیست موقتِ آی‌پی‌های در حال افزودن (قبل از ذخیره‌ی نهایی) ───────── */
  var pendingIps = [];
  function renderPendingIps() {
    var box = $('pendingIpBox');
    var applyBtn = $('ipApplyBtn');
    if (!pendingIps.length) {
      box.innerHTML = '';
      applyBtn.style.display = 'none';
      return;
    }
    box.innerHTML = pendingIps.map(function (ip) {
      return '<span class="ip-chip">' + esc(ip) + '<button type="button" data-drop-pending="' + esc(ip) + '" title="حذف از لیست">✕</button></span>';
    }).join('');
    Array.prototype.forEach.call(box.querySelectorAll('[data-drop-pending]'), function (btn) {
      btn.addEventListener('click', function () {
        var ip = btn.getAttribute('data-drop-pending');
        pendingIps = pendingIps.filter(function (x) { return x !== ip; });
        renderPendingIps();
      });
    });
    applyBtn.style.display = '';
    applyBtn.innerHTML = '<span class="btn-shine"></span>⚡ افزودن همه‌ی این ' + pendingIps.length + ' آی‌پی به کانفیگ‌ها';
  }

  function addIpToPendingList() {
    var input = $('ipInput');
    var ip = (input.value || '').trim();
    if (!ip) { toast('یک آی‌پی وارد کنید', 'error'); return; }
    var octets = ip.split('.');
    var validIPv4 = octets.length === 4 && octets.every(function (x) { return /^\\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255; });
    if (!validIPv4) { toast('فرمت آی‌پی صحیح نیست؛ نمونه: 104.16.0.1', 'error'); return; }
    if (pendingIps.indexOf(ip) > -1 || PREFERRED_IPS.indexOf(ip) > -1) { toast('این آی‌پی از قبل در لیست وجود دارد', 'error'); input.value = ''; return; }
    pendingIps.push(ip);
    input.value = '';
    input.focus();
    renderPendingIps();
  }

  $('ipAddBtn').addEventListener('click', addIpToPendingList);
  $('ipInput').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); addIpToPendingList(); }
  });

  $('ipApplyBtn').addEventListener('click', function () {
    if (!pendingIps.length) return;
    var btn = this;
    var toSend = pendingIps.slice();
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-shine"></span>⏳ در حال ذخیره…';
    api('POST', '/api/clean-ip/apply', { ips: toSend }).then(function (d) {
      btn.disabled = false;
      if (d.ok) {
        toast((d.preferredIPs.length) + ' آی‌پی اکنون روی کانفیگ‌ها فعال است ✓', 'success');
        pendingIps = [];
        renderPendingIps();
        updatePreferredIPUI(d.preferredIPs || []);
      } else {
        toast(d.error || 'خطا در ذخیره آی‌پی‌ها', 'error');
        renderPendingIps();
      }
    }).catch(function () {
      btn.disabled = false;
      toast('خطا در ارتباط با سرور', 'error');
      renderPendingIps();
    });
  });

  /* ───────── تب‌ها ───────── */
  Array.prototype.forEach.call(document.querySelectorAll('.tab-btn'), function (btn) {
    btn.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('.tab-btn'), function (b) { b.classList.remove('active'); });
      Array.prototype.forEach.call(document.querySelectorAll('.tab-panel'), function (p) { p.classList.remove('active'); });
      btn.classList.add('active');
      $(btn.getAttribute('data-tab')).classList.add('active');
    });
  });

  /* ───────── ابزارها ───────── */
  function fmtBytes(b) {
    b = Number(b) || 0;
    if (b < 1024) return b + ' B';
    var u = ['KB', 'MB', 'GB', 'TB'];
    var i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return (b >= 100 ? Math.round(b) : b.toFixed(1)) + ' ' + u[i];
  }

  function fmtDate(ts) {
    try { return new Date(ts).toLocaleDateString('fa-IR'); } catch (e) { return '-'; }
  }

  function daysLeft(c) {
    if (!c.expiryDays || c.expiryDays <= 0) return -1;
    var end = c.createdAt + c.expiryDays * 86400000;
    return Math.max(0, Math.ceil((end - Date.now()) / 86400000));
  }

  function statusOf(c) {
    if (!c.active) return 'inactive';
    if (daysLeft(c) === 0) return 'expired';
    if (c.limitGB > 0 && (Number(c.usedBytes) || 0) >= c.limitGB * 1073741824) return 'expired';
    return 'active';
  }

  function statusTitle(st) {
    return st === 'active' ? 'فعال' : st === 'inactive' ? 'غیرفعال' : 'منقضی / حجم تمام‌شده';
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (ch) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
    });
  }

  function copyText(text, btn) {
    function done() {
      if (btn) {
        var old = btn.textContent;
        btn.textContent = '✓';
        setTimeout(function () { btn.textContent = old; }, 1400);
      }
      toast('در حافظه کپی شد ✓', 'success');
    }
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); done(); } catch (e) { toast('کپی ناموفق بود', 'error'); }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else fallback();
  }

  function toast(msg, type) {
    var box = $('toasts');
    var t = document.createElement('div');
    t.className = 'toast ' + (type || '');
    t.textContent = msg;
    box.appendChild(t);
    setTimeout(function () {
      t.classList.add('out');
      setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 380);
    }, 3200);
  }

  function api(method, url, body) {
    var opt = { method: method };
    if (body) {
      opt.headers = { 'Content-Type': 'application/json' };
      opt.body = JSON.stringify(body);
    }
    return fetch(url, opt).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'پاسخ نامعتبر از سرور' }; });
    });
  }

  /* ساخت لینک کانفیگ — دقیقاً هماهنگ با سمت سرور (برای مودال تکی از اولین آی‌پی فعال استفاده می‌شود) */
  function buildConfig(c, portOverride) {
    var host = PREFERRED_IPS.length ? PREFERRED_IPS[0] : ADDRESS;
    var name = encodeURIComponent(c.name + (PREFERRED_IPS.length ? ' 🚀' : ''));
    var port = portOverride || c.port;
    var isTLS = TLS_PORTS.indexOf(Number(port)) > -1;
    var path = encodeURIComponent(WS_PATH);
    var common = 'security=' + (isTLS ? 'tls&sni=' + ADDRESS + '&fp=chrome' : 'none') + '&type=ws&host=' + ADDRESS + '&path=' + path;
    if (c.protocol === 'trojan') {
      return 'trojan://' + c.uuid + '@' + host + ':' + port + '?' + common + '#' + name;
    }
    return 'vless://' + c.uuid + '@' + host + ':' + port + '?encryption=none&' + common + '#' + name;
  }

  /* ───────── آمار و ویجت‌های داشبورد ───────── */
  function updateStats() {
    var active = 0, used = 0;
    clients.forEach(function (c) {
      var st = statusOf(c);
      if (st === 'active') active++;
      used += Number(c.usedBytes) || 0;
    });
    $('statTotal').textContent = clients.length;
    $('statActive').textContent = active;
    $('statUsed').textContent = fmtBytes(used);

    /* پرمصرف‌ترین کلاینت‌ها */
    var top = clients.slice().sort(function (a, b) { return (Number(b.usedBytes) || 0) - (Number(a.usedBytes) || 0); }).slice(0, 5);
    var topBox = $('topUsageBox');
    if (!top.length || !top.some(function (c) { return (Number(c.usedBytes) || 0) > 0; })) {
      topBox.innerHTML = '<div class="empty-mini">هنوز مصرفی ثبت نشده است</div>';
    } else {
      var maxUsed = Math.max.apply(null, top.map(function (c) { return Number(c.usedBytes) || 0; })) || 1;
      topBox.innerHTML = top.map(function (c) {
        var used2 = Number(c.usedBytes) || 0;
        var pct = Math.max(3, Math.round(used2 / maxUsed * 100));
        return '<div class="usage-row"><span class="u-name">' + esc(c.name) + '</span>' +
          '<span class="u-bar"><i style="width:' + pct + '%"></i></span>' +
          '<span class="u-val">' + fmtBytes(used2) + '</span></div>';
      }).join('');
    }

    /* آخرین کلاینت‌ها */
    var recent = clients.slice().sort(function (a, b) { return b.createdAt - a.createdAt; }).slice(0, 5);
    var recentBox = $('recentBox');
    if (!recent.length) {
      recentBox.innerHTML = '<div class="empty-mini">هنوز کلاینتی نساخته‌اید</div>';
    } else {
      recentBox.innerHTML = recent.map(function (c) {
        return '<div class="recent-item"><span class="r-name">' + esc(c.name) + '</span>' +
          '<span class="r-meta">' + (c.protocol === 'trojan' ? 'TROJAN' : 'VLESS') + ' · ' + fmtDate(c.createdAt) + '</span></div>';
      }).join('');
    }
  }

  /* ───────── رندر کارت‌ها ───────── */
  function render() {
    var q = ($('searchBox').value || '').trim().toLowerCase();
    var list = clients.filter(function (c) {
      if (!q) return true;
      return c.name.toLowerCase().indexOf(q) > -1 || String(c.uuid).toLowerCase().indexOf(q) > -1;
    });

    var grid = $('clientsGrid');
    grid.innerHTML = '';
    $('clientCount').textContent = clients.length ? ' (' + clients.length + ')' : '';
    $('emptyState').style.display = clients.length === 0 ? '' : 'none';
    $('noResult').style.display = (clients.length > 0 && list.length === 0) ? '' : 'none';

    list.forEach(function (c, i) {
      var st = statusOf(c);
      var used = Number(c.usedBytes) || 0;
      var limit = (Number(c.limitGB) || 0) * 1073741824;
      var pct = limit > 0 ? Math.min(100, Math.round(used / limit * 1000) / 10) : 0;
      var dl = daysLeft(c);
      var expiryText = dl < 0 ? 'نامحدود' : (dl === 0 ? 'منقضی شده' : dl + ' روز مانده');

      var card = document.createElement('div');
      card.className = 'client-card' + (st === 'inactive' ? ' inactive' : '') + (st === 'expired' ? ' expired' : '');
      card.style.animationDelay = Math.min(i * 0.05, 0.5) + 's';

      card.innerHTML = ''
        + '<div class="cc-head">'
        +   '<div class="cc-name">' + esc(c.name) + '</div>'
        +   '<div class="cc-badges">'
        +     '<span class="proto-badge ' + esc(c.protocol) + '">' + (c.protocol === 'trojan' ? 'TROJAN' : 'VLESS') + '</span>'
        +     '<span class="port-badge">:' + esc(c.port) + '</span>'
        +     '<span class="status-dot ' + st + '" title="' + statusTitle(st) + '"></span>'
        +   '</div>'
        + '</div>'
        + '<div class="cc-sub">'
        +   '<span>📅 ' + fmtDate(c.createdAt) + '</span><span class="sep">·</span>'
        +   '<span>⏳ ' + expiryText + '</span><span class="sep">·</span>'
        +   '<span>' + statusTitle(st) + '</span>'
        + '</div>'
        + '<div class="usage-top"><span>مصرف: <b>' + fmtBytes(used) + '</b></span>'
        +   '<span>از ' + (limit > 0 ? fmtBytes(limit) + ' · ' + pct + '%' : 'نامحدود') + '</span></div>'
        + '<div class="bar"><div class="bar-fill' + (pct >= 100 ? ' full' : '') + '" style="width:' + pct + '%"></div></div>'
        + '<div class="cc-actions">'
        +   '<button class="cc-primary" data-act="detail" title="لینک ساب و کانفیگ">📋 لینک &amp; کانفیگ</button>'
        +   '<button class="cc-primary accent" data-act="allports" title="کانفیگ همهٔ پورت‌ها">📥 همه‌ی پورت‌ها</button>'
        +   '<div class="cc-menu-wrap">'
        +     '<button class="cc-menu-btn" data-act="menu" title="عملیات بیشتر">⋮</button>'
        +     '<div class="cc-menu">'
        +       '<button data-act="edit">✏️ ویرایش تنظیمات</button>'
        +       '<button data-act="toggle">' + (c.active ? '⏸ غیرفعال کردن' : '▶️ فعال کردن') + '</button>'
        +       '<button data-act="reset">♻️ ریست حجم مصرف‌شده</button>'
        +       '<button data-act="regen">🔁 تغییر لینک (UUID جدید)</button>'
        +       '<hr>'
        +       '<button data-act="del" class="danger">🗑 حذف کلاینت</button>'
        +     '</div>'
        +   '</div>'
        + '</div>';

      card.addEventListener('click', function (e) {
        var t = e.target;
        while (t && t !== card && !(t.tagName === 'BUTTON' && t.getAttribute('data-act'))) t = t.parentNode;
        if (!t || t === card) return;
        var act = t.getAttribute('data-act');
        if (act === 'menu') {
          e.stopPropagation();
          var menu = t.nextElementSibling;
          var wasOpen = menu.classList.contains('open');
          closeAllCardMenus();
          if (!wasOpen) { menu.classList.add('open'); t.classList.add('open'); }
          return;
        }
        closeAllCardMenus();
        if (act === 'detail') openDetail(c);
        else if (act === 'allports') openAllPorts(c);
        else if (act === 'regen') doRegen(c);
        else if (act === 'reset') doReset(c);
        else if (act === 'edit') openEdit(c);
        else if (act === 'toggle') doToggle(c);
        else if (act === 'del') doDelete(c);
      });

      grid.appendChild(card);
    });

    updateStats();
  }

  /* ───────── ارتباط با سرور: کلاینت‌ها ───────── */
  function refresh() {
    return api('GET', '/api/clients').then(function (d) {
      if (d.ok) {
        clients = d.clients || [];
        if (d.address) { ADDRESS = d.address; $('addrText').textContent = ADDRESS; }
        render();
      } else toast(d.error || 'خطا در دریافت کلاینت‌ها', 'error');
    }).catch(function () { toast('خطا در ارتباط با سرور', 'error'); });
  }

  var usageAutoEnabled = true;
  var usageAutoTimer = null;
  var savedUsageInterval = Number(localStorage.getItem('vw_usage_interval_ms'));
  if (!Number.isFinite(savedUsageInterval) || savedUsageInterval < 5000) savedUsageInterval = 60000;
  var savedUsageAuto = localStorage.getItem('vw_usage_auto');
  if (savedUsageAuto === '0') usageAutoEnabled = false;
  var usageRefreshBusy = false;

  function refreshUsageNow(silent) {
    var btn = $('usageRefreshBtn');
    if (usageRefreshBusy) return Promise.resolve();
    usageRefreshBusy = true;
    var old = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.innerHTML = '⏳ بروزرسانی…'; }
    return api('GET', '/api/clients?sync=1').then(function (d) {
      if (d.ok) {
        clients = d.clients || [];
        if (d.address) { ADDRESS = d.address; $('addrText').textContent = ADDRESS; }
        render();
        if (!silent) toast('مصرف کلاینت‌ها بروزرسانی شد ✓', 'success');
      } else if (!silent) toast(d.error || 'خطا در بروزرسانی مصرف', 'error');
    }).catch(function () {
      if (!silent) toast('خطا در ارتباط با سرور', 'error');
    }).finally(function () {
      usageRefreshBusy = false;
      if (btn) { btn.disabled = false; btn.innerHTML = old; }
    });
  }

  function updateUsageAutoUI() {
    var btn = $('usageAutoBtn');
    var status = $('usageAutoStatus');
    if (btn) btn.textContent = usageAutoEnabled ? '⏸ غیرفعال کردن خودکار' : '▶️ فعال کردن خودکار';
    if (status) status.textContent = usageAutoEnabled ? '⏱ بروزرسانی خودکار: روشن' : '⏸ بروزرسانی خودکار: خاموش';
  }

  function restartUsageAutoRefresh() {
    if (usageAutoTimer) { clearInterval(usageAutoTimer); usageAutoTimer = null; }
    if (!usageAutoEnabled) return;
    var select = $('usageInterval');
    var ms = select ? Number(select.value) : savedUsageInterval;
    if (!Number.isFinite(ms) || ms < 5000) ms = 60000;
    savedUsageInterval = ms;
    try { localStorage.setItem('vw_usage_interval_ms', String(ms)); } catch (e) {}
    usageAutoTimer = setInterval(function () { refreshUsageNow(true); }, ms);
  }

  function doRegen(c) {
    if (!confirm('لینک فعلی «' + c.name + '» باطل می‌شود و UUID و توکن جدید ساخته خواهد شد. ادامه می‌دهید؟')) return;
    api('POST', '/api/clients/' + c.id + '/regenerate').then(function (d) {
      if (d.ok) {
        toast('لینک جدید ساخته شد 🔁', 'success');
        var i = clients.findIndex(function (x) { return x.id === c.id; });
        if (i > -1) clients[i] = d.client;
        render();
        openDetail(d.client);
      } else toast(d.error || 'خطا در ساخت لینک جدید', 'error');
    });
  }

  function doReset(c) {
    if (!confirm('حجم مصرف‌شده «' + c.name + '» صفر شود؟')) return;
    api('POST', '/api/clients/' + c.id + '/reset').then(function (d) {
      if (d.ok) {
        toast('حجم با موفقیت ریست شد ♻️', 'success');
        var i = clients.findIndex(function (x) { return x.id === c.id; });
        if (i > -1) clients[i] = d.client;
        render();
      } else toast(d.error || 'خطا در ریست حجم', 'error');
    });
  }

  function doToggle(c) {
    api('PUT', '/api/clients/' + c.id, { active: !c.active }).then(function (d) {
      if (d.ok) {
        toast(c.active ? 'کلاینت غیرفعال شد ⏸' : 'کلاینت فعال شد ▶️', 'success');
        refresh();
      } else toast(d.error || 'خطا', 'error');
    });
  }

  function doDelete(c) {
    if (!confirm('کلاینت «' + c.name + '» برای همیشه حذف شود؟')) return;
    api('DELETE', '/api/clients/' + c.id).then(function (d) {
      if (d.ok) {
        toast('کلاینت حذف شد 🗑', 'success');
        clients = clients.filter(function (x) { return x.id !== c.id; });
        render();
      } else toast(d.error || 'خطا در حذف', 'error');
    });
  }

  /* ───────── مودال‌ها ───────── */
  function openOverlay(id) { $(id).classList.add('show'); }
  function closeOverlay(id) { $(id).classList.remove('show'); }

  function openDetail(c) {
    detailClient = c;
    $('dTitle').textContent = 'کانفیگ «' + c.name + '»';
    $('dSubLink').value = location.origin + '/sub/' + c.token;
    $('dConfig').value = buildConfig(c);
    $('dOpenInfoPage').href = location.origin + '/sub/' + c.token + '?web=1';
    var w = $('dWarn');
    var st = statusOf(c);
    if (st === 'inactive') {
      w.style.display = '';
      w.textContent = '⏸ این کلاینت غیرفعال است و اتصال آن پذیرفته نمی‌شود.';
    } else if (st === 'expired') {
      w.style.display = '';
      w.textContent = '⚠️ حجم یا اعتبار این کلاینت به پایان رسیده است؛ با «♻️ ریست حجم» یا «✏️ ویرایش» آن را تمدید کنید.';
    } else w.style.display = 'none';
    openOverlay('detailOverlay');
  }

  var lastAllPortsText = '';
  function openAllPorts(c) {
    $('apTitle').textContent = 'کانفیگ تمامی پورت‌ها — ' + c.name;
    $('apSubLink').value = location.origin + '/sub/' + c.token;
    $('apList').innerHTML = '<div class="empty-mini">در حال ساخت کانفیگ‌ها…</div>';
    openOverlay('allPortsOverlay');
    api('GET', '/api/clients/' + c.id + '/all-ports').then(function (d) {
      if (!d.ok) { $('apList').innerHTML = '<div class="empty-mini">' + esc(d.error || 'خطا') + '</div>'; return; }
      lastAllPortsText = d.configs.map(function (x) { return x.link; }).join('\\n');
      var groups = {};
      var order = [];
      d.configs.forEach(function (x) {
        var key = x.ip || '__direct__';
        if (!groups[key]) { groups[key] = []; order.push(key); }
        groups[key].push(x);
      });
      $('apList').innerHTML = order.map(function (key) {
        var label = key === '__direct__' ? '🌐 آدرس مستقیم Worker' : ('🚀 آی‌پی ' + esc(key));
        return '<div class="ap-group-label">' + label + '</div>' + groups[key].map(function (x) {
          return '<div class="ap-row"><span class="ap-port">:' + x.port + (x.tls ? ' <b class="tls-tag">TLS</b>' : '') + '</span>' +
            '<input type="text" readonly value="' + esc(x.link) + '">' +
            '<button data-copy-link="' + esc(x.link) + '">کپی</button></div>';
        }).join('');
      }).join('');
      Array.prototype.forEach.call($('apList').querySelectorAll('[data-copy-link]'), function (btn) {
        btn.addEventListener('click', function () { copyText(btn.getAttribute('data-copy-link'), btn); });
      });
    }).catch(function () { $('apList').innerHTML = '<div class="empty-mini">خطا در ارتباط با سرور</div>'; });
  }

  function fillPortSelect(sel, selected) {
    sel.innerHTML = '';
    PORTS.forEach(function (p) {
      var o = document.createElement('option');
      o.value = p;
      o.textContent = p + (TLS_PORTS.indexOf(p) > -1 ? ' (TLS)' : ' (بدون TLS)');
      if (Number(selected) === p) o.selected = true;
      sel.appendChild(o);
    });
  }

  function openEdit(c) {
    editId = c.id;
    $('eName').value = c.name;
    $('eProtocol').value = c.protocol;
    fillPortSelect($('ePort'), c.port);
    $('eLimit').value = c.limitGB || 0;
    $('eExpiry').value = c.expiryDays || 0;
    openOverlay('editOverlay');
  }

  /* ───────── رویدادها: تب کلاینت‌ها ───────── */
  fillPortSelect($('fPort'), 443);
  $('addrText').textContent = ADDRESS;
  $('addrBadge').addEventListener('click', function () { copyText(ADDRESS, null); });
  $('searchBox').addEventListener('input', render);

  Array.prototype.forEach.call(document.querySelectorAll('#fProtocol .seg-btn'), function (b) {
    b.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('#fProtocol .seg-btn'), function (x) { x.classList.remove('active'); });
      b.classList.add('active');
      currentProtocol = b.getAttribute('data-protocol');
    });
  });

  $('createForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var name = $('fName').value.trim();
    if (!name) { toast('نام کلاینت را وارد کنید', 'error'); return; }
    var btn = $('createBtn');
    btn.disabled = true;
    btn.textContent = '⏳ در حال ساخت …';
    api('POST', '/api/clients', {
      name: name,
      protocol: currentProtocol,
      port: Number($('fPort').value),
      limitGB: Number($('fLimit').value) || 0,
      expiryDays: Number($('fExpiry').value) || 0
    }).then(function (d) {
      btn.disabled = false;
      btn.innerHTML = '<span class="btn-shine"></span>⚡ ساخت کلاینت و دریافت کانفیگ';
      if (d.ok) {
        toast('کلاینت «' + name + '» ساخته شد ✨', 'success');
        $('fName').value = ''; $('fLimit').value = ''; $('fExpiry').value = '';
        clients.push(d.client);
        render();
        openDetail(d.client);
      } else toast(d.error || 'خطا در ساخت کلاینت', 'error');
    }).catch(function () {
      btn.disabled = false;
      btn.innerHTML = '<span class="btn-shine"></span>⚡ ساخت کلاینت و دریافت کانفیگ';
      toast('خطا در ارتباط با سرور', 'error');
    });
  });

  /* ───────── ساخت خودکار یک‌کلیکی ───────── */
  $('quickCreateBtn').addEventListener('click', function () {
    var btn = this;
    var autoName = 'کاربر-' + Math.floor(1000 + Math.random() * 9000);
    btn.disabled = true;
    btn.textContent = '⏳ در حال ساخت خودکار …';
    api('POST', '/api/clients', {
      name: autoName,
      protocol: currentProtocol || 'vless',
      port: Number($('fPort').value) || 443,
      limitGB: 0,
      expiryDays: 0
    }).then(function (d) {
      btn.disabled = false;
      btn.textContent = '🚀 ساخت خودکار یک‌کلیکی (پیشنهادی)';
      if (d.ok) {
        toast('کلاینت «' + d.client.name + '» به‌صورت خودکار ساخته شد ✨', 'success');
        clients.push(d.client);
        render();
        openAllPorts(d.client);
      } else toast(d.error || 'خطا در ساخت کلاینت', 'error');
    }).catch(function () {
      btn.disabled = false;
      btn.textContent = '🚀 ساخت خودکار یک‌کلیکی (پیشنهادی)';
      toast('خطا در ارتباط با سرور', 'error');
    });
  });

  $('eSave').addEventListener('click', function () {
    if (!editId) return;
    var name = $('eName').value.trim();
    if (!name) { toast('نام نمی‌تواند خالی باشد', 'error'); return; }
    api('PUT', '/api/clients/' + editId, {
      name: name,
      protocol: $('eProtocol').value,
      port: Number($('ePort').value),
      limitGB: Number($('eLimit').value) || 0,
      expiryDays: Number($('eExpiry').value) || 0
    }).then(function (d) {
      if (d.ok) {
        toast('تغییرات ذخیره شد 💾', 'success');
        closeOverlay('editOverlay');
        refresh();
      } else toast(d.error || 'خطا در ذخیره', 'error');
    });
  });

  $('dCopySub').addEventListener('click', function () { copyText($('dSubLink').value, this); });
  $('apCopySub').addEventListener('click', function () { copyText($('apSubLink').value, this); });
  $('dCopyConfig').addEventListener('click', function () { copyText($('dConfig').value, this); });
  $('dOpenAllPorts').addEventListener('click', function () { if (detailClient) openAllPorts(detailClient); });
  $('apCopyAll').addEventListener('click', function () { if (lastAllPortsText) copyText(lastAllPortsText, this); });

  Array.prototype.forEach.call(document.querySelectorAll('[data-close]'), function (b) {
    b.addEventListener('click', function () { closeOverlay(b.getAttribute('data-close')); });
  });
  Array.prototype.forEach.call(document.querySelectorAll('.overlay'), function (ov) {
    ov.addEventListener('click', function (e) { if (e.target === ov) closeOverlay(ov.id); });
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeOverlay('detailOverlay');
      closeOverlay('editOverlay');
      closeOverlay('allPortsOverlay');
      closeAllCardMenus();
    }
  });

  /* ───────── PROXYIP ───────── */
  function updateProxyIPUI(proxy) {
    var el = $('proxyIpBox');
    if (!el) return;
    if (proxy && proxy.host) {
      el.innerHTML = '<div class="active-ip-card"><div><div class="ip-label">PROXYIP فعال</div><div class="ip-value">' + esc(proxy.host) + ':' + Number(proxy.port || 443) + '</div></div><button type="button" class="btn-danger-soft" id="clearProxyIp">🗑 حذف PROXYIP</button></div>';
      var clearBtn = $('clearProxyIp');
      if (clearBtn) clearBtn.addEventListener('click', function () {
        clearBtn.disabled = true;
        api('POST', '/api/proxyip/clear').then(function (d) {
          clearBtn.disabled = false;
          if (d.ok) { toast('PROXYIP حذف شد ✓', 'success'); updateProxyIPUI(null); }
          else toast(d.error || 'خطا در حذف PROXYIP', 'error');
        }).catch(function () {
          clearBtn.disabled = false;
          toast('خطا در ارتباط با سرور', 'error');
        });
      });
    } else {
      el.innerHTML = '<div class="active-ip-card" style="border-color:rgba(124,58,237,.22)"><div><div class="ip-label">وضعیت</div><div class="ip-value" style="color:var(--muted);font-family:inherit">PROXYIP تنظیم نشده است.</div></div></div>';
    }
  }

  $('proxyApplyBtn').addEventListener('click', function () {
    var host = ($('proxyIpInput').value || '').trim();
    var port = Number($('proxyPortInput').value);
    if (!host) { toast('آی‌پی PROXYIP را وارد کنید', 'error'); return; }
    if (!Number.isInteger(port) || port < 1 || port > 65535) { toast('پورت را بین 1 تا 65535 وارد کنید', 'error'); return; }

    var btn = this;
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-shine"></span>⏳ در حال ذخیره…';
    api('POST', '/api/proxyip/apply', { host: host, port: port }).then(function (d) {
      btn.disabled = false;
      btn.innerHTML = '<span class="btn-shine"></span>🚀 ذخیره PROXYIP';
      if (d.ok) {
        $('proxyIpInput').value = '';
        updateProxyIPUI(d.proxyIP);
        toast('PROXYIP ذخیره شد ✓', 'success');
      } else toast(d.error || 'خطا در ذخیره PROXYIP', 'error');
    }).catch(function () {
      btn.disabled = false;
      btn.innerHTML = '<span class="btn-shine"></span>🚀 ذخیره PROXYIP';
      toast('خطا در ارتباط با سرور', 'error');
    });
  });

  /* ───────── تب تنظیمات پنل ───────── */
  fillPortSelect($('setPort'), 443);
  function loadSettings() {
    api('GET', '/api/settings').then(function (d) {
      if (!d.ok) return;
      $('stAddr').textContent = d.address;
      $('stKV').innerHTML = d.kvConnected ? '<span class="status-ok">متصل ✓</span>' : '<span class="status-bad">متصل نیست ✕</span>';
      applyTheme(d.theme || 'dark', false);
      updatePreferredIPUI(d.preferredIPs || []);
      updateProxyIPUI(d.proxyIP || null);
      $('setProtocol').value = d.defaultProtocol;
      fillPortSelect($('setPort'), d.defaultPort);
      $('setRemark').value = d.remark || '';
      fillPortSelect($('fPort'), d.defaultPort);
      Array.prototype.forEach.call(document.querySelectorAll('#fProtocol .seg-btn'), function (b) {
        b.classList.toggle('active', b.getAttribute('data-protocol') === d.defaultProtocol);
      });
      currentProtocol = d.defaultProtocol;
      if (d.remark && !$('fName').value) $('fName').placeholder = d.remark + '…';
    }).catch(function () {});
  }
  loadSettings();

  $('saveDefaultsBtn').addEventListener('click', function () {
    var btn = this;
    btn.disabled = true;
    api('POST', '/api/settings', {
      defaultProtocol: $('setProtocol').value,
      defaultPort: Number($('setPort').value),
      remark: $('setRemark').value.trim()
    }).then(function (d) {
      btn.disabled = false;
      if (d.ok) { toast('تنظیمات پیش‌فرض ذخیره شد 💾', 'success'); loadSettings(); }
      else toast(d.error || 'خطا در ذخیره تنظیمات', 'error');
    }).catch(function () { btn.disabled = false; toast('خطا در ارتباط با سرور', 'error'); });
  });

  $('savePassBtn').addEventListener('click', function () {
    var cur = $('curPass').value;
    var np = $('newPass').value;
    var np2 = $('newPass2').value;
    if (!cur) { toast('رمز عبور فعلی را وارد کنید', 'error'); return; }
    if (np.length < 4) { toast('رمز جدید باید حداقل ۴ کاراکتر باشد', 'error'); return; }
    if (np !== np2) { toast('تکرار رمز جدید مطابقت ندارد', 'error'); return; }
    var btn = this;
    btn.disabled = true;
    api('POST', '/api/settings', { currentPassword: cur, newPassword: np }).then(function (d) {
      btn.disabled = false;
      if (d.ok) {
        toast('رمز عبور با موفقیت تغییر کرد 🔑', 'success');
        $('curPass').value = ''; $('newPass').value = ''; $('newPass2').value = '';
      } else toast(d.error || 'خطا در تغییر رمز', 'error');
    }).catch(function () { btn.disabled = false; toast('خطا در ارتباط با سرور', 'error'); });
  });

  /* ───────── شروع ───────── */
  var usageRefreshBtn = $('usageRefreshBtn');
  if (usageRefreshBtn) usageRefreshBtn.addEventListener('click', function () { refreshUsageNow(false); });
  var usageAutoBtn = $('usageAutoBtn');
  if (usageAutoBtn) usageAutoBtn.addEventListener('click', function () {
    usageAutoEnabled = !usageAutoEnabled;
    try { localStorage.setItem('vw_usage_auto', usageAutoEnabled ? '1' : '0'); } catch (e) {}
    updateUsageAutoUI();
    restartUsageAutoRefresh();
    toast(usageAutoEnabled ? 'بروزرسانی خودکار فعال شد ✓' : 'بروزرسانی خودکار غیرفعال شد ⏸', 'success');
  });
  var usageInterval = $('usageInterval');
  if (usageInterval) {
    usageInterval.value = String(savedUsageInterval);
    usageInterval.addEventListener('change', restartUsageAutoRefresh);
  }
  updateUsageAutoUI();
  restartUsageAutoRefresh();

  refresh();
})();
</script>
 ${particlesJS('particles')}
</body>
</html>`;
}

/* ─────────────────────────── صفحه راه‌اندازی ─────────────────────────── */
function setupPage(missing) {
  const isKV = missing === 'KV';
  const title = isKV ? '⚠️ KV متصل نیست' : '⚠️ رمز مدیریت تنظیم نشده';
  const desc = isKV
    ? 'برای ذخیره کلاینت‌ها و شمارش مصرف، باید یک KV Namespace به این Worker وصل کنید.'
    : 'برای ورود به پنل، متغیر محیطی <b>ADMIN</b> را در تنظیمات Worker تنظیم کنید.';
  const steps = isKV
    ? '<li>در کلودفلر به بخش <b>Storage &amp; Databases → KV</b> بروید و یک Namespace بسازید</li><li>در تنظیمات Worker → بخش <b>Bindings</b>، KV را با نام متغیری <b>KV</b> وصل کنید</li><li>ذخیره و Deploy کنید و دوباره این صفحه را باز کنید</li>'
    : '<li>در تنظیمات Worker → بخش <b>Variables and Secrets</b>، متغیری با نام <b>ADMIN</b> بسازید</li><li>مقدار آن را رمز عبور دلخواه پنل قرار دهید</li><li>ذخیره و Deploy کنید و از طریق <b>/login</b> وارد شوید</li>';

  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>راه‌اندازی | VODIWALKER VPN</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
 ${baseCSS()}
body { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
.setup-card { position: relative; z-index: 2; width: min(520px, 100%); padding: 36px 32px; border-radius: 24px;
  background: rgba(18, 10, 38, 0.8); backdrop-filter: blur(24px); border: 1px solid rgba(251, 191, 36, 0.35);
  box-shadow: 0 25px 70px rgba(88, 28, 135, 0.45); animation: cardIn 0.9s cubic-bezier(0.16, 1, 0.3, 1) both; }
.setup-icon { font-size: 44px; text-align: center; margin-bottom: 14px; animation: logoFloat 3s ease-in-out infinite; }
h1 { font-size: 20px; text-align: center; margin-bottom: 12px; color: #fbbf24; }
.setup-desc { font-size: 13.5px; color: #cbbdf0; text-align: center; line-height: 2.1; margin-bottom: 22px; }
ol { padding-right: 20px; font-size: 13px; color: #d8ccf5; line-height: 2.4; }
ol li { margin-bottom: 6px; }
.code { direction: ltr; display: inline-block; font-family: monospace; background: rgba(8, 4, 20, 0.8);
  border: 1px solid rgba(168, 85, 247, 0.3); padding: 2px 9px; border-radius: 7px; color: #67e8f9; font-size: 12px; }
.brand-foot { text-align: center; margin-top: 24px; font-size: 11px; color: var(--muted); direction: ltr; letter-spacing: 2px; }
</style>
</head>
<body>
  <div class="bg-img"></div>
  <div class="bg-overlay"></div>
  <div class="particles" id="particles"></div>
  <div class="setup-card">
    <div class="setup-icon">🛠️</div>
    <h1>${title}</h1>
    <div class="setup-desc">${desc}</div>
    <ol>${steps}</ol>
    <div class="brand-foot">VODIWALKER VPN · v${VERSION}</div>
  </div>
 ${particlesJS('particles')}
</body>
</html>`;
}

/* ─────────────────────────── صفحه ۴۰۴ جعلی ─────────────────────────── */
function fakePage() {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>404 Not Found</title>
<style>
body { background: #0a0518; color: #a79ac9; font-family: Tahoma, sans-serif; display: flex;
  align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
.box { text-align: center; }
.code { font-size: 92px; font-weight: 900; color: rgba(168, 85, 247, 0.22); line-height: 1; }
p { font-size: 14px; }
</style>
</head>
<body>
<div class="box"><div class="code">404</div><p>Not Found</p></div>
</body>
</html>`;
}

/* ─────────────────────────── آیکون SVG ─────────────────────────── */
function faviconSVG() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs>
<linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#7c3aed"/>
<stop offset="1" stop-color="#22d3ee"/>
</linearGradient>
</defs>
<rect width="64" height="64" rx="14" fill="#120a26"/>
<path d="M36 6 16 36h12l-4 22 24-34H34l2-18z" fill="url(#g)"/>
</svg>`;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  VODIWALKER — سابسکریپشن یکپارچه (نسخه‌ی تک‌لینکی)
 *  این بلوک را عیناً به انتهای فایل Worker خودتان اضافه کنید.
 *  (۴ ویرایش کوچک هم در کد فعلی لازم است — در فایل «راهنما.md» توضیح داده شده)
 *
 *  یک لینک، دو رفتار:
 *    • باز شدن در اپ (v2rayNG / Hiddify / Streisand / …) → خروجی Base64 کانفیگ‌ها
 *    • باز شدن در مرورگر → صفحه‌ی گرافیکی Subscription Center
 *  آدرس اجباری: ?app=1 (کانفیگ)   |   ?web=1 (صفحه)   |   ?stats=1 (JSON زنده)
 * ═══════════════════════════════════════════════════════════════════════ */

const SUB_BRAND = 'VodiWalker';

/* ─────────── شمارنده‌ی اتصال‌های زنده (در حافظه‌ی ایزوله، بدون نوشتن در KV) ─────────── */
const VW_SESSIONS = globalThis.__vwSessions || (globalThis.__vwSessions = new Map());
let VW_SESSION_SEQ = 0;

function sessionOpen(clientId, request) {
  try {
    if (!clientId) return null;
    let bucket = VW_SESSIONS.get(clientId);
    if (!bucket) { bucket = new Map(); VW_SESSIONS.set(clientId, bucket); }
    const ip = String(request.headers.get('CF-Connecting-IP') || request.headers.get('X-Real-IP') || '?');
    const id = 's' + (++VW_SESSION_SEQ);
    bucket.set(id, { ip: ip, ts: Date.now() });
    return { clientId: clientId, id: id };
  } catch (e) { return null; }
}

function sessionClose(ref) {
  try {
    if (!ref) return;
    const bucket = VW_SESSIONS.get(ref.clientId);
    if (!bucket) return;
    bucket.delete(ref.id);
    if (bucket.size === 0) VW_SESSIONS.delete(ref.clientId);
  } catch (e) {}
}

function sessionStats(clientId) {
  try {
    const bucket = VW_SESSIONS.get(clientId);
    if (!bucket) return { count: 0, ips: 0 };
    const now = Date.now();
    const ips = new Set();
    for (const [k, v] of bucket) {
      if (now - v.ts > 21600000) { bucket.delete(k); continue; } // پاک‌سازی نشست‌های رهاشده (۶ ساعت)
      ips.add(v.ip);
    }
    return { count: bucket.size, ips: ips.size };
  } catch (e) { return { count: 0, ips: 0 }; }
}

/* ─────────── تشخیص مرورگر در برابر اپ وی‌پی‌ان ─────────── */

/* نمایش صفحه‌ی گرافیکی فقط با درخواست صریح — نه با حدس زدن از روی هدرها.
   لینک /sub/TOKEN که کاربر در اپ وارد می‌کند باید همیشه، با هر هدری و از
   هر کلاینتی، دقیقاً یک رفتار ثابت داشته باشد: کانفیگ خام. هرگونه تشخیص
   خودکارِ «این درخواست از مرورگر است یا اپ» (بر پایه‌ی User-Agent، Accept یا
   Sec-Fetch-Mode) در عمل غیرقابل‌اعتماد است — برخی اپ‌ها (به‌خصوص آن‌هایی که
   از WebView یا موتورهای شبکه‌ای مثل Cronet استفاده می‌کنند) همان هدرهایی را
   می‌فرستند که مرورگرهای واقعی می‌فرستند، و اگر اشتباه به‌عنوان «مرورگر»
   تشخیص داده شوند، به‌جای کانفیگ HTML می‌گیرند و افزودن سابسکریپشن در اپ
   شکست می‌خورد. برای همین صفحه‌ی گرافیکی فقط با پارامتر صریح ?web=1 یا از
   طریق مسیر /info/TOKEN (که همیشه همان ?web=1 را اعمال می‌کند) نمایش داده
   می‌شود؛ لینک خام /sub/TOKEN هرگز، تحت هیچ شرایطی، تغییر رفتار نمی‌دهد. */
function wantsWebPage(url, path) {
  if (path.startsWith('/info/')) return true;
  if (url.searchParams.get('app') === '1') return false;
  return url.searchParams.get('web') === '1';
}

/* ─────────── محاسبه‌ی وضعیت کلاینت ─────────── */
function subComputeState(client) {
  // مصرفِ بافرشده‌ی همین Worker را هم لحاظ کن تا صفحه‌ی سابسکریپشن در
  // زمان اتصال فعال منتظر flush بعدی KV نماند.
  const liveBuffered = Math.max(0, Math.floor(Number(USAGE_BUFFER[client.id]) || 0));
  const usedBytes = Math.max(0, Math.floor(Number(client.usedBytes) || 0) + liveBuffered);
  const limitBytes = client.limitGB > 0 ? Math.round(client.limitGB * 1073741824) : 0;
  const pct = limitBytes > 0 ? Math.min(100, Math.round((usedBytes / limitBytes) * 1000) / 10) : 0;
  const remaining = limitBytes > 0 ? Math.max(0, limitBytes - usedBytes) : -1;
  const daysLeft = client.expiryDays > 0
    ? Math.max(0, Math.ceil((client.createdAt + client.expiryDays * 86400000 - Date.now()) / 86400000))
    : -1;
  const expired = (client.expiryDays > 0 && daysLeft === 0) || (limitBytes > 0 && usedBytes >= limitBytes);
  const status = !client.active ? 'inactive' : (expired ? 'expired' : 'active');
  const expireTs = client.expiryDays > 0
    ? Math.floor((client.createdAt + client.expiryDays * 86400000) / 1000)
    : 32503680000;
  return { usedBytes, limitBytes, pct, remaining, daysLeft, status, expireTs };
}

/* ═══════════════ هندلر اصلی سابسکریپشن ═══════════════ */
async function handleSubscription(request, env, url, path) {
  const notFound = () => new Response(fakePage(), { status: 404, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });

  const token = String(path.split('/')[2] || '').trim();
  if (!token) return notFound();

  // قبل از تولید سابسکریپشن، مصرف بافرشده همین Worker را ثبت کن تا
  // عددی که اپ می‌گیرد با عدد پنل تا حد ممکن هم‌زمان باشد.
  await flushUsageBuffer(env);
  const clients = await loadClients(env);
  const client = clients.find(c => c.token === token);
  if (!client) return notFound();

  const address = getAddress(env, request, url);
  const settings = await loadSettings(env);
  const hosts = (settings.preferredIPs && settings.preferredIPs.length) ? settings.preferredIPs : [''];
  const st = subComputeState(client);
  const sess = sessionStats(client.id);

  /* ── خروجی JSON زنده برای به‌روزرسانی خودکار صفحه ── */
  if (url.searchParams.get('stats') === '1') {
    return new Response(JSON.stringify({
      ok: true,
      used: st.usedBytes,
      limit: st.limitBytes,
      remaining: st.remaining,
      pct: st.pct,
      daysLeft: st.daysLeft,
      status: st.status,
      sessions: sess.count,
      ips: sess.ips,
      ts: Date.now()
    }), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  /* ── ساخت همه‌ی کانفیگ‌ها (همه‌ی پورت‌ها × همه‌ی آی‌پی‌های فعال) ── */
  const configs = [];
  for (const h of hosts) {
    for (const p of ALLOWED_PORTS) {
      configs.push({
        ip: h || null,
        port: p,
        tls: TLS_PORTS.indexOf(Number(p)) > -1,
        link: buildConfigLinkForPort(client, address, p, h)
      });
    }
  }
  const plain = configs.map(c => c.link).join('\n');

  /* ── مرورگر → صفحه‌ی گرافیکی ── */
  if (wantsWebPage(url, path)) {
    return new Response(subPage({
      client: client,
      state: st,
      sess: sess,
      address: address,
      token: token,
      subUrl: url.origin + '/sub/' + token,
      configs: configs
    }), { headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } });
  }

  /* ── اپ وی‌پی‌ان → خروجی استاندارد Base64 ── */
  return new Response(strToB64(plain), {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Title': 'base64:' + strToB64(SUB_BRAND + ' | ' + client.name),
      'Subscription-Userinfo': 'upload=0; download=' + st.usedBytes + '; total=' + st.limitBytes + '; expire=' + st.expireTs,
      'Profile-Update-Interval': '6',
      'Profile-Web-Page-Url': url.origin + '/sub/' + token + '?web=1',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store'
    }
  });
}

/* ═══════════════ صفحه‌ی گرافیکی Subscription Center ═══════════════ */
function subPage(d) {
  const c = d.client, st = d.state;
  const name = escHtml(c.name);
  const initial = escHtml(String(c.name || 'V').trim().charAt(0) || 'V');
  const proto = c.protocol === 'trojan' ? 'TROJAN' : 'VLESS';
  const tlsOn = TLS_PORTS.indexOf(Number(c.port)) > -1;
  const protoLine = proto + ' · WebSocket (ws)' + (tlsOn ? ' · TLS' : '');
  const statusText = st.status === 'active' ? 'فعال' : (st.status === 'inactive' ? 'غیرفعال' : 'منقضی');
  const expiryText = st.daysLeft < 0 ? 'نامحدود' : (st.daysLeft === 0 ? 'پایان‌یافته' : st.daysLeft + ' روز');

  const fmt = (b) => {
    b = Number(b) || 0;
    if (b < 1024) return b + ' B';
    const u = ['KB', 'MB', 'GB', 'TB'];
    let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return (b >= 100 ? Math.round(b) : b.toFixed(2)) + ' ' + u[i];
  };

  const usedText = fmt(st.usedBytes);
  const limitText = st.limitBytes > 0 ? fmt(st.limitBytes) : 'نامحدود';
  const remainText = st.remaining < 0 ? 'نامحدود' : fmt(st.remaining);

  const groups = {};
  const order = [];
  for (const x of d.configs) {
    const key = x.ip || '__direct__';
    if (!groups[key]) { groups[key] = []; order.push(key); }
    groups[key].push(x);
  }
  const configHtml = order.map(function (key) {
    const label = key === '__direct__' ? '🌐 آدرس مستقیم سرویس' : ('🚀 آی‌پی ' + escHtml(key));
    return '<div class="cfg-group">' + label + '</div>' + groups[key].map(function (x) {
      return '<div class="cfg-row"><span class="cfg-port">:' + x.port + (x.tls ? '<b>TLS</b>' : '') + '</span>' +
        '<input type="text" readonly value="' + escHtml(x.link) + '">' +
        '<button type="button" data-copy="' + escHtml(x.link) + '">کپی</button></div>';
    }).join('');
  }).join('');

  const bootData = {
    token: d.token,
    name: c.name,
    used: st.usedBytes,
    limit: st.limitBytes,
    remaining: st.remaining,
    pct: st.pct,
    daysLeft: st.daysLeft,
    status: st.status,
    sessions: d.sess.count,
    ips: d.sess.ips,
    subUrl: d.subUrl,
    allConfigs: d.configs.map(function (x) { return x.link; }).join('\n')
  };

  return `<!DOCTYPE html>
<html lang="fa" dir="rtl" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#08050f">
<meta name="robots" content="noindex,nofollow">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%237c3aed'/%3E%3Cstop offset='1' stop-color='%2322d3ee'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='14' fill='%23120a26'/%3E%3Cpath d='M36 6 16 36h12l-4 22 24-34H34l2-18z' fill='url(%23g)'/%3E%3C/svg%3E">
<title>${SUB_BRAND} | ${name}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Vazirmatn',Tahoma,sans-serif}
:root{
  --bg:#08050f;--bg2:#0d0a1a;--panel:rgba(255,255,255,.035);--panel2:rgba(255,255,255,.055);
  --line:rgba(255,255,255,.09);--line2:rgba(255,255,255,.16);
  --accent:#a855f7;--accent2:#7c3aed;--green:#22c55e;--red:#fb7185;--amber:#fbbf24;
  --text:#f3f0fa;--sub:#9c93b5;--sub2:#655d7e;
}
html[data-theme="light"]{
  --bg:#f4f2fb;--bg2:#ffffff;--panel:rgba(255,255,255,.9);--panel2:rgba(124,58,237,.05);
  --line:rgba(24,16,48,.1);--line2:rgba(24,16,48,.18);
  --accent:#7c3aed;--accent2:#6d28d9;--green:#059669;--red:#e11d48;--amber:#b45309;
  --text:#1c1630;--sub:#6b6485;--sub2:#9a93b3;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);min-height:100vh;padding:26px 18px 54px;transition:background .25s,color .25s;position:relative;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(ellipse 55% 40% at 78% -8%,rgba(124,58,237,.30),transparent 62%),
             radial-gradient(ellipse 45% 35% at 5% 100%,rgba(34,197,94,.10),transparent 60%)}
html[data-theme="light"] body::before{background:radial-gradient(ellipse 55% 40% at 78% -8%,rgba(124,58,237,.12),transparent 62%)}
.wrap{position:relative;z-index:1;max-width:980px;margin:0 auto}
::selection{background:rgba(168,85,247,.35)}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:8px}

/* ── هدر ── */
.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:12px;order:2}
.brand .btxt{text-align:left;direction:ltr}
.brand .bname{font-size:19px;font-weight:900;letter-spacing:.3px}
.brand .bsub{font-size:9.5px;letter-spacing:2.6px;color:var(--sub2);margin-top:2px}
.brand .blogo{width:46px;height:46px;border-radius:15px;display:grid;place-items:center;font-size:19px;font-weight:900;color:#fff;direction:ltr;
  background:linear-gradient(140deg,#7c3aed,#a855f7 60%,#5b21b6);box-shadow:0 8px 26px rgba(124,58,237,.45)}
.pills{display:flex;align-items:center;gap:9px;order:1;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:8px;padding:10px 15px;border-radius:13px;font-size:12px;font-weight:700;
  background:var(--panel);border:1px solid var(--line);color:var(--text)}
.pill.on{background:rgba(34,197,94,.09);border-color:rgba(34,197,94,.3);color:var(--green)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 9px var(--green);animation:bl 2s ease infinite}
.dot.off{background:var(--sub2);box-shadow:none;animation:none}
.dot.bad{background:var(--red);box-shadow:0 0 9px var(--red)}
@keyframes bl{0%,100%{opacity:1}50%{opacity:.35}}
button.pill{cursor:pointer;transition:.18s}
button.pill:hover{border-color:var(--line2);transform:translateY(-1px)}

/* ── کارت قهرمان ── */
.hero{position:relative;overflow:hidden;border-radius:26px;padding:26px 28px;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;
  background:linear-gradient(115deg,rgba(124,58,237,.22),rgba(124,58,237,.05) 45%,transparent 75%),var(--panel);
  border:1px solid var(--line);box-shadow:0 20px 50px rgba(0,0,0,.28)}
.hero::after{content:'';position:absolute;top:-70px;right:-50px;width:230px;height:230px;border-radius:50%;
  background:radial-gradient(circle,rgba(168,85,247,.28),transparent 70%);pointer-events:none}
.hero-main{display:flex;align-items:center;gap:18px;position:relative;z-index:2;flex:1;min-width:250px}
.avatar{width:80px;height:80px;flex-shrink:0;border-radius:50%;display:grid;place-items:center;font-size:29px;font-weight:900;
  background:rgba(124,58,237,.14);border:2px solid rgba(168,85,247,.55);box-shadow:0 0 34px rgba(168,85,247,.35) inset,0 0 22px rgba(168,85,247,.25)}
.hero h1{font-size:clamp(20px,4.6vw,27px);font-weight:900;margin-bottom:11px;word-break:break-word}
.tags{display:flex;gap:8px;flex-wrap:wrap}
.tag{font-size:11px;font-weight:700;padding:8px 13px;border-radius:11px;background:var(--panel2);border:1px solid var(--line);color:var(--text)}
.tag span{color:var(--sub);font-weight:500;margin-left:5px}
.tag.ok{background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.3);color:var(--green)}
.tag.bad{background:rgba(251,113,133,.1);border-color:rgba(251,113,133,.32);color:var(--red)}
.tag.mono{direction:ltr;font-family:ui-monospace,Menlo,monospace;font-size:10.5px}
.btn{cursor:pointer;border:none;border-radius:15px;padding:15px 24px;font-size:13.5px;font-weight:800;color:#fff;font-family:inherit;
  background:linear-gradient(135deg,#7c3aed,#a855f7);box-shadow:0 10px 26px rgba(124,58,237,.4);transition:.2s;display:inline-flex;align-items:center;gap:9px;position:relative;z-index:2}
.btn:hover{transform:translateY(-2px);box-shadow:0 14px 34px rgba(124,58,237,.6)}
.btn.ghost{background:var(--panel);color:var(--text);border:1px solid var(--line);box-shadow:none}
.btn.ghost:hover{border-color:var(--line2);box-shadow:none}

/* ── شبکه‌ی کارت‌ها ── */
.grid{display:grid;grid-template-columns:1.15fr 1fr;gap:16px;margin-top:16px}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
.card{border-radius:22px;padding:22px;background:var(--panel);border:1px solid var(--line)}
.chead{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding-bottom:16px;margin-bottom:18px;border-bottom:1px solid var(--line)}
.chead h3{font-size:15px;font-weight:800;margin-bottom:5px}
.chead p{font-size:11.5px;color:var(--sub)}
.chead .clock{font-size:11px;color:var(--sub2);direction:ltr;font-family:ui-monospace,Menlo,monospace}

/* مصرف */
.usage{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.mini{display:grid;grid-template-columns:1fr 1fr;gap:10px;flex:1;min-width:190px}
.mbox{padding:14px;border-radius:15px;background:var(--panel2);border:1px solid var(--line);text-align:center}
.mbox label{display:block;font-size:10.5px;color:var(--sub);margin-bottom:7px}
.mbox b{font-size:17px;font-weight:900;direction:ltr;display:block}
.mbox b.g{color:var(--green)}
.mbox b.p{color:var(--accent)}
.ring{position:relative;width:150px;height:150px;flex-shrink:0;margin:0 auto}
.ring svg{transform:rotate(-90deg);width:100%;height:100%}
.ring .bgc{fill:none;stroke:var(--line);stroke-width:13}
.ring .fgc{fill:none;stroke:url(#rg);stroke-width:13;stroke-linecap:round;transition:stroke-dashoffset 1s cubic-bezier(.16,1,.3,1)}
.ring .lbl{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px}
.ring .lbl b{font-size:27px;font-weight:900;direction:ltr}
.ring .lbl span{font-size:10.5px;color:var(--sub)}
.note{margin-top:16px;padding:13px 15px;border-radius:14px;background:var(--panel2);border:1px solid var(--line);font-size:11.5px;color:var(--sub);line-height:2}

/* اتصال‌ها */
.conn{padding:16px;border-radius:15px;background:var(--panel2);border:1px solid rgba(34,197,94,.22);margin-bottom:11px}
.conn.plain{border-color:var(--line)}
.conn .top{display:flex;align-items:center;justify-content:space-between;gap:10px}
.conn .num{font-size:26px;font-weight:900;color:var(--green);direction:ltr}
.conn .k{font-size:12px;color:var(--text);font-weight:700;direction:ltr}
.conn .bot{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:8px;font-size:11px;color:var(--sub)}
.conn .big{font-size:16px;font-weight:800}
.acts{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
.acts .btn{flex:1;justify-content:center;padding:14px 12px;font-size:12.5px;white-space:nowrap}

/* نمودار */
.chart-card{margin-top:16px}
.chart{width:100%;height:170px;display:block}
.chart .area{fill:url(#ag)}
.chart .line{fill:none;stroke:var(--accent);stroke-width:2.4;stroke-linejoin:round;stroke-linecap:round}
.chart .grid-l{stroke:var(--line);stroke-width:1;stroke-dasharray:4 6}
.chart-empty{display:flex;align-items:center;justify-content:center;height:170px;color:var(--sub2);font-size:12.5px;text-align:center;line-height:2;padding:0 20px}

/* مودال */
.ov{position:fixed;inset:0;z-index:90;display:flex;align-items:center;justify-content:center;padding:18px;
  background:rgba(4,2,10,.75);backdrop-filter:blur(9px);opacity:0;visibility:hidden;transition:.25s}
.ov.show{opacity:1;visibility:visible}
.mod{width:min(680px,100%);max-height:88vh;overflow-y:auto;border-radius:24px;background:var(--bg2);border:1px solid var(--line2);
  transform:translateY(22px) scale(.97);transition:.28s cubic-bezier(.16,1,.3,1)}
.ov.show .mod{transform:none}
.mhead{position:sticky;top:0;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:10px;
  padding:18px 22px;background:var(--bg2);border-bottom:1px solid var(--line)}
.mhead h3{font-size:15px;font-weight:800}
.mclose{background:none;border:none;color:var(--sub);font-size:17px;cursor:pointer;width:34px;height:34px;border-radius:10px;transition:.18s}
.mclose:hover{background:rgba(251,113,133,.14);color:var(--red)}
.mbody{padding:22px}
.qr{display:flex;justify-content:center;align-items:center;min-height:212px;background:#fff;border-radius:18px;padding:14px;margin-bottom:18px}
.lbl2{font-size:11.5px;color:var(--sub);margin-bottom:8px;display:block}
.row{display:flex;gap:8px;margin-bottom:16px}
.row input{flex:1;min-width:0;padding:12px 13px;font-size:11px;color:var(--accent);direction:ltr;text-align:left;
  font-family:ui-monospace,Menlo,monospace;background:var(--panel2);border:1px solid var(--line);border-radius:12px;outline:none}
.row input:focus{border-color:var(--accent)}
.row button{padding:0 18px;border:none;border-radius:12px;cursor:pointer;font-size:12.5px;font-weight:700;color:#fff;font-family:inherit;
  background:linear-gradient(135deg,#7c3aed,#a855f7);white-space:nowrap}
.cfg-group{font-size:11.5px;font-weight:700;color:var(--accent);margin:16px 0 8px;direction:ltr;text-align:left}
.cfg-group:first-child{margin-top:0}
.cfg-row{display:flex;align-items:center;gap:9px;padding:9px 12px;margin-bottom:7px;border-radius:12px;background:var(--panel2);border:1px solid var(--line)}
.cfg-port{width:78px;flex-shrink:0;font-size:11px;direction:ltr;font-family:ui-monospace,Menlo,monospace;color:var(--sub)}
.cfg-port b{color:var(--green);font-size:9px;margin-right:4px}
.cfg-row input{flex:1;min-width:0;background:transparent;border:none;outline:none;color:var(--text);opacity:.85;
  font-family:ui-monospace,Menlo,monospace;font-size:10.5px;direction:ltr;text-align:left}
.cfg-row button{padding:7px 13px;border-radius:9px;border:1px solid var(--line2);cursor:pointer;font-size:11px;font-weight:700;
  background:var(--panel);color:var(--text);font-family:inherit}
.cfg-row button:hover{border-color:var(--accent);color:var(--accent)}
.kv{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 2px;border-bottom:1px dashed var(--line);font-size:12.5px;color:var(--sub)}
.kv:last-child{border-bottom:none}
.kv b{color:var(--text);direction:ltr;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-all;text-align:left}

/* توست */
.toast{position:fixed;bottom:22px;left:50%;transform:translate(-50%,16px);z-index:120;padding:12px 22px;border-radius:14px;
  background:var(--bg2);border:1px solid rgba(34,197,94,.45);color:var(--text);font-size:13px;font-weight:700;
  box-shadow:0 14px 34px rgba(0,0,0,.4);opacity:0;transition:.28s;pointer-events:none;white-space:nowrap}
.toast.show{opacity:1;transform:translate(-50%,0)}
.foot{text-align:center;margin-top:26px;font-size:11px;color:var(--sub2);letter-spacing:1.6px;direction:ltr}
</style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <div class="pills">
      <span class="pill on" id="svcPill"><span class="dot" id="svcDot"></span> سرویس آنلاین</span>
      <button type="button" class="pill" id="themeBtn">🌙 تاریک</button>
    </div>
    <div class="brand">
      <div class="btxt">
        <div class="bname">${SUB_BRAND}</div>
        <div class="bsub">SUBSCRIPTION CENTER</div>
      </div>
      <div class="blogo">V</div>
    </div>
  </div>

  <section class="hero">
    <div class="hero-main">
      <div class="avatar">${initial}</div>
      <div>
        <h1>${name}</h1>
        <div class="tags">
          <span class="tag mono"><span>پروتکل</span>${escHtml(protoLine)}</span>
          <span class="tag ${st.status === 'active' ? 'ok' : 'bad'}" id="statusTag"><span>وضعیت</span>${statusText}</span>
          <span class="tag"><span>انقضا</span><b id="expiryTag">${expiryText}</b></span>
        </div>
      </div>
    </div>
    <button type="button" class="btn" id="cfgBtn">⚙️ کانفیگ‌ها</button>
  </section>

  <div class="grid">
    <section class="card">
      <div class="chead">
        <div><h3>مصرف اشتراک</h3><p>نمایش مصرف واقعی ثبت‌شده روی سرویس</p></div>
        <span class="clock" id="clock">—</span>
      </div>
      <div class="usage">
        <div class="mini">
          <div class="mbox"><label>مصرف شده</label><b class="p" id="uUsed">${escHtml(usedText)}</b></div>
          <div class="mbox"><label>باقی‌مانده</label><b class="g" id="uRemain">${escHtml(remainText)}</b></div>
          <div class="mbox"><label>سقف اشتراک</label><b id="uLimit">${escHtml(limitText)}</b></div>
          <div class="mbox"><label>درصد مصرف</label><b id="uPct">${st.limitBytes > 0 ? st.pct + '%' : '—'}</b></div>
        </div>
        <div class="ring">
          <svg viewBox="0 0 120 120">
            <defs><linearGradient id="rg" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stop-color="#7c3aed"/><stop offset="1" stop-color="#a855f7"/>
            </linearGradient></defs>
            <circle class="bgc" cx="60" cy="60" r="50"></circle>
            <circle class="fgc" id="ringArc" cx="60" cy="60" r="50" stroke-dasharray="314.16" stroke-dashoffset="314.16"></circle>
          </svg>
          <div class="lbl"><b id="ringPct">0%</b><span>مصرف شده</span></div>
        </div>
      </div>
      <div class="note">عدد مصرف از شمارنده‌ی واقعی سرویس خوانده می‌شود؛ با هر بار افزایش ترافیک، مقدار و نمودار به‌صورت خودکار به‌روزرسانی می‌شوند.</div>
    </section>

    <section class="card">
      <div class="chead">
        <div><h3>اتصال‌های فعال</h3><p>کاربران آنلاین همین لحظه</p></div>
        <span class="pill on" id="connPill" style="padding:7px 12px;font-size:11px">فعال</span>
      </div>
      <div class="conn">
        <div class="top"><span class="k" id="sessLabel">session 0</span><span class="num" id="sessNum">0</span></div>
        <div class="bot"><span>بدون محدودیت اتصال</span><span>دستگاه / IP یکتا</span></div>
      </div>
      <div class="conn plain">
        <div class="top"><span class="big">بدون محدودیت</span><span style="font-size:11px;color:var(--sub)">محدودیت IP</span></div>
      </div>
      <div class="note">برای جلوگیری از نمایش عدد غیرواقعی، هر IP فقط یک کاربر فعال محسوب می‌شود؛ Session‌های فنی جداگانه نمایش داده می‌شوند.</div>
      <div class="acts">
        <button type="button" class="btn" id="copySubBtn">📋 کپی لینک اشتراک</button>
        <button type="button" class="btn ghost" id="dlBtn">⬇️ دانلود فایل ساب</button>
        <button type="button" class="btn ghost" id="infoBtn">ℹ️ اطلاعات سرویس</button>
      </div>
    </section>
  </div>

  <section class="card chart-card">
    <div class="chead">
      <div><h3>روند مصرف</h3><p>تغییرات ثبت‌شده مصرف اشتراک</p></div>
      <span class="clock" id="chartMeta">—</span>
    </div>
    <div id="chartBox"><div class="chart-empty">هنوز داده‌ای برای رسم نمودار ثبت نشده است.<br>این صفحه را باز نگه دارید تا روند مصرف ساخته شود.</div></div>
  </section>

  <div class="foot">${SUB_BRAND.toUpperCase()} · SECURE SUBSCRIPTION</div>
</div>

<!-- مودال کانفیگ‌ها -->
<div class="ov" id="cfgOv">
  <div class="mod">
    <div class="mhead"><h3>⚙️ کانفیگ‌ها و لینک اشتراک</h3><button class="mclose" data-close="cfgOv">✕</button></div>
    <div class="mbody">
      <div class="qr"><div id="qrBox" style="color:#555;font-size:12px">در حال ساخت QR…</div></div>
      <label class="lbl2">🔗 لینک اشتراک (این لینک را در برنامه‌ی خود وارد کنید)</label>
      <div class="row"><input type="text" id="subInput" readonly value="${escHtml(d.subUrl)}"><button type="button" id="copySub2">کپی</button></div>
      <label class="lbl2">📦 کانفیگ‌های تکی — در صورت کند بودن یکی، بعدی را امتحان کنید</label>
      ${configHtml}
      <button type="button" class="btn" id="copyAllBtn" style="width:100%;justify-content:center;margin-top:18px">📋 کپی همه‌ی کانفیگ‌ها</button>
    </div>
  </div>
</div>

<!-- مودال اطلاعات -->
<div class="ov" id="infoOv">
  <div class="mod" style="width:min(520px,100%)">
    <div class="mhead"><h3>ℹ️ اطلاعات سرویس</h3><button class="mclose" data-close="infoOv">✕</button></div>
    <div class="mbody">
      <div class="kv"><span>نام سرویس</span><b>${name}</b></div>
      <div class="kv"><span>پروتکل</span><b>${escHtml(protoLine)}</b></div>
      <div class="kv"><span>پورت پیش‌فرض</span><b>${escHtml(String(c.port))}</b></div>
      <div class="kv"><span>مسیر WebSocket</span><b>${escHtml(WS_PATH)}</b></div>
      <div class="kv"><span>تعداد کانفیگ‌ها</span><b>${d.configs.length}</b></div>
      <div class="kv"><span>سقف حجم</span><b>${escHtml(limitText)}</b></div>
      <div class="kv"><span>اعتبار</span><b>${escHtml(expiryText)}</b></div>
      <div class="note" style="margin-top:16px">لینک اشتراک را در v2rayNG، Hiddify، Streisand، Shadowrocket یا هر برنامه‌ی سازگار در بخش Subscription وارد کنید؛ کانفیگ‌ها خودکار دریافت و هر ۶ ساعت به‌روزرسانی می‌شوند.</div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<script>
(function(){
  'use strict';
  var D = ${JSON.stringify(bootData)};
  var $ = function(id){ return document.getElementById(id); };

  /* ── پوسته ── */
  function applyTheme(m){
    document.documentElement.setAttribute('data-theme', m);
    $('themeBtn').textContent = m === 'light' ? '☀️ روشن' : '🌙 تاریک';
    try{ localStorage.setItem('vw_sub_theme', m); }catch(e){}
  }
  (function(){ var t=null; try{ t=localStorage.getItem('vw_sub_theme'); }catch(e){} applyTheme(t==='light'?'light':'dark'); })();
  $('themeBtn').addEventListener('click', function(){
    applyTheme(document.documentElement.getAttribute('data-theme')==='light'?'dark':'light');
  });

  /* ── ابزار ── */
  function fmt(b){
    b = Number(b)||0;
    if(b < 1024) return b + ' B';
    var u=['KB','MB','GB','TB'], i=-1;
    do{ b/=1024; i++; } while(b>=1024 && i<u.length-1);
    return (b>=100? Math.round(b) : b.toFixed(2)) + ' ' + u[i];
  }
  var toastT = null;
  function toast(msg){
    var t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastT);
    toastT = setTimeout(function(){ t.classList.remove('show'); }, 2300);
  }
  function copy(text, btn){
    function done(){
      if(btn){ var o = btn.textContent; btn.textContent='✓'; setTimeout(function(){ btn.textContent=o; },1300); }
      toast('در حافظه کپی شد ✓');
    }
    function fb(){
      var ta = document.createElement('textarea');
      ta.value = text; ta.style.cssText='position:fixed;opacity:0;top:0';
      document.body.appendChild(ta); ta.select();
      try{ document.execCommand('copy'); done(); }catch(e){ toast('کپی ناموفق بود'); }
      document.body.removeChild(ta);
    }
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(done, fb);
    } else fb();
  }

  /* ── مودال ── */
  function open(id){ $(id).classList.add('show'); }
  function close(id){ $(id).classList.remove('show'); }
  Array.prototype.forEach.call(document.querySelectorAll('[data-close]'), function(b){
    b.addEventListener('click', function(){ close(b.getAttribute('data-close')); });
  });
  Array.prototype.forEach.call(document.querySelectorAll('.ov'), function(ov){
    ov.addEventListener('click', function(e){ if(e.target === ov) close(ov.id); });
  });
  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape'){ close('cfgOv'); close('infoOv'); }
  });

  var qrDone = false;
  $('cfgBtn').addEventListener('click', function(){
    open('cfgOv');
    if(qrDone) return;
    qrDone = true;
    var box = $('qrBox');
    try{
      box.textContent = '';
      if(window.QRCode){ new QRCode(box, { text: D.subUrl, width: 200, height: 200, colorDark:'#120a26', colorLight:'#ffffff' }); }
      else box.textContent = 'QR در دسترس نیست';
    }catch(e){ box.textContent = 'QR در دسترس نیست'; }
  });
  $('infoBtn').addEventListener('click', function(){ open('infoOv'); });
  $('copySubBtn').addEventListener('click', function(){ copy(D.subUrl, null); });
  $('dlBtn').addEventListener('click', function(){ location.href = D.subUrl + (D.subUrl.indexOf('?')>-1?'&':'?') + 'app=1'; });
  $('copySub2').addEventListener('click', function(){ copy(D.subUrl, this); });
  $('copyAllBtn').addEventListener('click', function(){ copy(D.allConfigs, null); });
  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function(b){
    b.addEventListener('click', function(){ copy(b.getAttribute('data-copy'), b); });
  });

  /* ── حلقه‌ی درصد ── */
  var CIRC = 2 * Math.PI * 50;
  function setRing(pct){
    var p = Math.max(0, Math.min(100, Number(pct)||0));
    $('ringArc').setAttribute('stroke-dashoffset', String(CIRC - (CIRC * p / 100)));
    $('ringPct').textContent = (Math.round(p*10)/10) + '%';
  }

  /* ── نمودار روند مصرف (نمونه‌های واقعی، ذخیره در همین مرورگر) ── */
  var HKEY = 'vw_hist_' + D.token;
  function loadHist(){
    try{ var v = JSON.parse(localStorage.getItem(HKEY) || '[]'); return Array.isArray(v) ? v : []; }
    catch(e){ return []; }
  }
  function saveHist(h){ try{ localStorage.setItem(HKEY, JSON.stringify(h.slice(-144))); }catch(e){} }
  function pushHist(used){
    var h = loadHist();
    var last = h[h.length-1];
    if(!last || last.u !== used || Date.now() - last.t > 300000){
      h.push({ t: Date.now(), u: used });
      saveHist(h);
    }
    return loadHist();
  }
  function drawChart(h){
    var box = $('chartBox');
    if(!h || h.length < 2){
      box.innerHTML = '<div class="chart-empty">هنوز داده‌ای برای رسم نمودار ثبت نشده است.<br>این صفحه را باز نگه دارید تا روند مصرف ساخته شود.</div>';
      $('chartMeta').textContent = h && h.length ? (h.length + ' نقطه') : '—';
      return;
    }
    var W = 700, H = 170, PAD = 12;
    var vals = h.map(function(x){ return x.u; });
    var min = Math.min.apply(null, vals), max = Math.max.apply(null, vals);
    if(max === min) max = min + 1;
    var pts = h.map(function(x, i){
      var px = PAD + (W - PAD*2) * (h.length===1 ? 1 : i/(h.length-1));
      var py = H - PAD - (H - PAD*2) * ((x.u - min)/(max - min));
      return [Math.round(px*100)/100, Math.round(py*100)/100];
    });
    var line = pts.map(function(p,i){ return (i?'L':'M') + p[0] + ' ' + p[1]; }).join(' ');
    var area = line + ' L ' + pts[pts.length-1][0] + ' ' + (H-PAD) + ' L ' + pts[0][0] + ' ' + (H-PAD) + ' Z';
    var gl = '';
    for(var g=1; g<4; g++){
      var y = PAD + (H - PAD*2) * g/4;
      gl += '<line class="grid-l" x1="'+PAD+'" y1="'+y+'" x2="'+(W-PAD)+'" y2="'+y+'"></line>';
    }
    box.innerHTML = '<svg class="chart" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">' +
      '<defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0" stop-color="#a855f7" stop-opacity=".35"/>' +
      '<stop offset="1" stop-color="#a855f7" stop-opacity="0"/></linearGradient></defs>' +
      gl + '<path class="area" d="'+area+'"></path><path class="line" d="'+line+'"></path></svg>';
    $('chartMeta').textContent = h.length + ' نقطه واقعی · آخرین مقدار ' + fmt(vals[vals.length-1]);
  }

  /* ── اعمال داده ── */
  function apply(s){
    $('uUsed').textContent = fmt(s.used);
    $('uRemain').textContent = s.remaining < 0 ? 'نامحدود' : fmt(s.remaining);
    $('uLimit').textContent = s.limit > 0 ? fmt(s.limit) : 'نامحدود';
    $('uPct').textContent = s.limit > 0 ? (s.pct + '%') : '—';
    setRing(s.limit > 0 ? s.pct : 0);

    $('sessNum').textContent = s.sessions;
    $('sessLabel').textContent = 'session ' + s.sessions;
    var pill = $('connPill');
    pill.textContent = s.sessions > 0 ? (s.ips + ' دستگاه آنلاین') : 'بدون اتصال فعال';
    pill.className = s.sessions > 0 ? 'pill on' : 'pill';
    pill.style.padding = '7px 12px'; pill.style.fontSize = '11px';

    $('expiryTag').textContent = s.daysLeft < 0 ? 'نامحدود' : (s.daysLeft === 0 ? 'پایان‌یافته' : s.daysLeft + ' روز');
    var tag = $('statusTag');
    tag.className = 'tag ' + (s.status === 'active' ? 'ok' : 'bad');
    tag.innerHTML = '<span>وضعیت</span>' + (s.status === 'active' ? 'فعال' : (s.status === 'inactive' ? 'غیرفعال' : 'منقضی'));
    var dot = $('svcDot'), sp = $('svcPill');
    if(s.status === 'active'){ dot.className = 'dot'; sp.className = 'pill on'; sp.lastChild.nodeValue = ' سرویس آنلاین'; }
    else { dot.className = 'dot bad'; sp.className = 'pill'; sp.lastChild.nodeValue = s.status === 'inactive' ? ' سرویس غیرفعال' : ' اشتراک پایان یافته'; }

    drawChart(pushHist(s.used));
  }

  function tickClock(){
    try{ $('clock').textContent = new Date().toLocaleTimeString('fa-IR'); }
    catch(e){ $('clock').textContent = new Date().toTimeString().slice(0,8); }
  }
  tickClock();
  setInterval(tickClock, 1000);

  apply(D);

  function poll(){
    fetch(location.pathname + '?stats=1', { cache: 'no-store' })
      .then(function(r){ return r.json(); })
      .then(function(s){ if(s && s.ok) apply(s); })
      .catch(function(){});
  }
  setInterval(poll, 20000);
  document.addEventListener('visibilitychange', function(){ if(!document.hidden) poll(); });
})();
</script>
</body>
</html>`;
}
