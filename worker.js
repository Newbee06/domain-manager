const COOKIE_NAME = "redirect_admin";
const SESSION_SECONDS = 12 * 60 * 60;
const DEFAULT_PAUSED = "此域名暂时不可用，请稍后再试。";
const DEFAULT_RETENTION_DAYS = 90;
const DEFAULT_HEALTH_LIMIT = 20;

const headersNoStore = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headersNoStore, "content-type": "application/json; charset=utf-8", ...extra }
  });
}
function html(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: { ...headersNoStore, "content-type": "text/html; charset=utf-8", ...extra }
  });
}
function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}
function bytesToB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64ToBytes(s) {
  const raw = atob(s);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function b64url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  return b64ToBytes(s);
}
async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value)));
  return b64url(new Uint8Array(digest));
}
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))));
}
function randomBytes(n = 24) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
function getCookie(request) {
  const raw = request.headers.get("Cookie") || "";
  const prefix = COOKIE_NAME + "=";
  for (const part of raw.split(";")) {
    const item = part.trim();
    if (item.startsWith(prefix)) return item.slice(prefix.length);
  }
  return "";
}
async function createSession(secret, user) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({
    sub: Number(user?.id || 0),
    username: String(user?.username || "admin"),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
  })));
  return payload + "." + await hmac(payload, secret);
}

async function getSession(request, env) {
  if (!env.SESSION_SECRET) return null;
  const parts = getCookie(request).split(".");
  if (parts.length !== 2) return null;
  if (!safeEqual(parts[1], await hmac(parts[0], env.SESSION_SECRET))) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
    if (Number(data.exp) <= Math.floor(Date.now() / 1000)) return null;
    if (Number(data.sub) !== 0 || String(data.username || "").toLowerCase() !== "admin") return null;
    return { id: 0, username: "admin", role: "admin", enabled: 1 };
  } catch { return null; }
}
async function authenticated(request, env) {
  return !!(await getSession(request, env));
}
function sessionCookie(value, maxAge = SESSION_SECONDS) {
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).host.toLowerCase() === new URL(request.url).host.toLowerCase(); }
  catch { return false; }
}
function normalizeHost(host) {
  return String(host || "").trim().toLowerCase().replace(/\.$/, "");
}
function validateTarget(value) {
  try {
    const u = new URL(String(value || "").trim());
    return ["http:", "https:"].includes(u.protocol) && !!u.hostname && !u.username && !u.password;
  } catch { return false; }
}
function validateRemark(value) {
  const remark = String(value ?? "").trim();
  return remark.length <= 100 ? remark : null;
}
function validateGroup(value) {
  const group = String(value ?? "").trim();
  return group.length <= 50 ? group : null;
}
function normalizeDomain(value) {
  const raw = String(value || "").trim().toLowerCase().replace(/\.$/, "");
  if (!raw || raw.includes("://") || raw.includes("/") || raw.includes("@") || raw.includes("*") || raw.includes(":")) return "";
  if (raw.length > 253 || !raw.includes(".")) return "";
  const labels = raw.split(".");
  if (labels.some(x => !x || x.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x))) return "";
  return raw;
}
function escapeHtml(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function parseRetention(env) {
  const n = Number(env.LOG_RETENTION_DAYS || DEFAULT_RETENTION_DAYS);
  return Number.isInteger(n) && n >= 1 && n <= 3650 ? n : DEFAULT_RETENTION_DAYS;
}

async function audit(env, actor, action, summary, domainId = null) {
  try {
    await env.DB.prepare("INSERT INTO audit_logs (actor,action,summary,domain_id) VALUES (?,?,?,?)")
      .bind(String(actor || "system").slice(0, 100), String(action || "").slice(0, 60), String(summary || "").slice(0, 500), domainId == null ? null : Number(domainId)).run();
  } catch {}
}
async function getDomain(env, host) {
  return env.DB.prepare("SELECT id, domain, remark, group_name, target_url, enabled, redirect_type, paused_message, health_status, health_code, health_checked_at, health_error, created_at, updated_at FROM domains WHERE domain = ?").bind(host).first();
}
async function recordVisit(env, request, domainId) {
  const ref = (request.headers.get("Referer") || "").slice(0, 500);
  let source = "direct";
  try { if (ref) source = new URL(ref).hostname.slice(0, 253); } catch {}
  const ua = (request.headers.get("User-Agent") || "").slice(0, 300);
  await env.DB.prepare("INSERT INTO visits (domain_id, source, referer, user_agent) VALUES (?, ?, ?, ?)")
    .bind(domainId, source, ref || null, ua || null).run();
}
async function checkTargetUrl(url) {
  const started = Date.now();
  let lastError = "";
  for (const method of ["HEAD", "GET"]) {
    try {
      const init = { method, redirect: "follow", headers: { "user-agent": "RedirectManager-HealthCheck/1.0" } };
      if (method === "GET") init.headers.range = "bytes=0-0";
      const response = await fetch(url, init);
      const status = response.status;
      try { response.body?.cancel(); } catch {}
      if (status >= 200 && status < 400) return { status: "ok", code: status, error: "", latency: Date.now() - started };
      if (status >= 400 && status < 500) return { status: "degraded", code: status, error: `HTTP ${status}`, latency: Date.now() - started };
      return { status: "down", code: status, error: `HTTP ${status}`, latency: Date.now() - started };
    } catch (e) { lastError = String(e?.message || e || "请求失败"); }
  }
  return { status: "down", code: null, error: lastError.slice(0, 300) || "请求失败", latency: Date.now() - started };
}
async function updateDomainHealth(env, id, url) {
  const result = await checkTargetUrl(url);
  await env.DB.prepare("UPDATE domains SET health_status=?,health_code=?,health_checked_at=CURRENT_TIMESTAMP,health_error=?,updated_at=updated_at WHERE id=?")
    .bind(result.status, result.code, result.error || null, id).run();
  return result;
}
async function cleanupOldVisits(env) {
  const days = parseRetention(env);
  const result = await env.DB.prepare("DELETE FROM visits WHERE visited_at < datetime('now', ?)").bind(`-${days} days`).run();
  return Number(result?.meta?.changes || 0);
}
async function cleanupOldAudits(env) {
  const days = Math.max(parseRetention(env), 30);
  const result = await env.DB.prepare("DELETE FROM audit_logs WHERE created_at < datetime('now', ?)").bind(`-${days} days`).run();
  return Number(result?.meta?.changes || 0);
}

function loginPage(error = "") {
  return html(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>域名管理系统</title>
<style>*{box-sizing:border-box}html{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:#f5f5f7;color:#1d1d1f;font:16px -apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",sans-serif}@media(prefers-color-scheme:dark){body{background:#000;color:#f5f5f7}.card{background:#1c1c1e!important;border-color:#38383c!important}.field{background:#2c2c2e!important;border-color:#48484d!important;color:#f5f5f7!important}}.card{width:min(430px,100%);background:rgba(255,255,255,.88);border:1px solid rgba(60,60,67,.15);border-radius:24px;padding:30px;box-shadow:0 20px 60px rgba(0,0,0,.08);backdrop-filter:blur(24px)}.brand{display:flex;gap:12px;align-items:center}.logo{width:46px;height:46px;border-radius:15px;background:#007aff;color:white;display:grid;place-items:center;font-size:22px}.brand h1{margin:0;font-size:25px}.muted{color:#86868b;font-size:13px;margin:6px 0 26px}.field{width:100%;padding:13px 14px;background:#fff;border:1px solid rgba(60,60,67,.15);border-radius:12px;font:inherit;margin-top:10px;outline:none}.field:focus{border-color:#007aff;box-shadow:0 0 0 3px rgba(0,122,255,.13)}button{width:100%;padding:13px;border:0;border-radius:12px;background:#007aff;color:white;font:inherit;font-weight:650;margin-top:18px;cursor:pointer}.login-account{padding:11px 13px;margin:14px 0 10px;border-radius:12px;background:var(--soft);color:var(--muted);font-size:13px}.error{min-height:20px;color:#ff453a;font-size:13px;margin-top:12px}</style>
<main class="card"><div class="brand"><div class="logo">↗</div><div><h1>域名管理系统</h1><div class="muted">管理员登录</div></div></div><div class="login-account">管理员：<b>admin</b></div><form id="f"><input class="field" id="p" type="password" placeholder="管理员密码" autocomplete="current-password" required><button>登录</button><div id="e" class="error">${escapeHtml(error)}</div></form></main>
<script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();let b=e.target.querySelector('button');b.disabled=true;try{let r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'admin',password:document.getElementById('p').value})});let d=await r.json().catch(()=>({}));if(r.ok)location.href='/admin';else document.getElementById('e').textContent=d.error||'登录失败'}catch{document.getElementById('e').textContent='网络错误'}finally{b.disabled=false}}</script></html>`);
}
function domainDetailPage(id) {
  return html(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>域名详情 · 域名管理系统</title>
<style>
:root{color-scheme:light dark;--bg:#f5f5f7;--surface:rgba(255,255,255,.82);--solid:#fff;--text:#1d1d1f;--muted:#86868b;--line:rgba(60,60,67,.14);--soft:rgba(118,118,128,.10);--blue:#007aff;--green:#30d158;--orange:#ff9f0a;--red:#ff453a;--shadow:0 14px 45px rgba(0,0,0,.06)}
@media(prefers-color-scheme:dark){:root{--bg:#000;--surface:rgba(28,28,30,.86);--solid:#1c1c1e;--text:#f5f5f7;--muted:#98989d;--line:rgba(84,84,88,.55);--soft:rgba(118,118,128,.18);--shadow:0 16px 48px rgba(0,0,0,.26)}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 5% 0%,rgba(0,122,255,.10),transparent 35%),var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}.wrap{width:min(1060px,100%);margin:0 auto;padding:clamp(18px,4vw,38px) clamp(14px,3vw,28px) 50px}.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:12px}.logo{width:44px;height:44px;border-radius:14px;background:var(--blue);color:#fff;display:grid;place-items:center;font-size:22px}.title{font-size:clamp(24px,4vw,34px);font-weight:750;letter-spacing:-.04em}.muted{color:var(--muted);font-size:13px}.btn{border:0;border-radius:12px;padding:10px 14px;background:var(--blue);color:#fff;font:inherit;font-weight:650;cursor:pointer}.secondary{background:var(--soft);color:var(--text)}.card{background:var(--surface);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid var(--line);border-radius:20px;padding:20px;margin:14px 0;box-shadow:var(--shadow)}.hero{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}.heroTitle{font-size:clamp(26px,5vw,40px);font-weight:760;letter-spacing:-.05em}.heroUrl{margin-top:6px;color:var(--muted);word-break:break-all}.pillrow{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.pill{display:inline-flex;align-items:center;gap:5px;padding:6px 9px;border-radius:999px;background:var(--soft);font-size:12px}.ok{background:rgba(48,209,88,.14);color:var(--green)}.warn{background:rgba(255,159,10,.14);color:var(--orange)}.bad{background:rgba(255,69,58,.14);color:var(--red)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.box{background:var(--soft);border-radius:16px;padding:15px}.box .k{font-size:12px;color:var(--muted)}.box .v{margin-top:4px;font-size:24px;font-weight:740}.sectionTitle{font-size:18px;font-weight:700;margin-bottom:10px}.tablewrap{overflow-x:auto;border-radius:12px}table{width:100%;border-collapse:collapse;min-width:680px;font-size:13px}th,td{text-align:left;padding:11px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}th{color:var(--muted);font-weight:600;white-space:nowrap}.empty{text-align:center;color:var(--muted);padding:24px}.foot{width:100%;display:flex;justify-content:center;align-items:center;text-align:center;color:var(--muted);font-size:12px;margin:24px 0 0;padding:6px 0 2px}.foot a{display:inline-flex;align-items:center;justify-content:center;color:inherit;text-decoration:none;min-height:24px;padding:0 8px;border-radius:8px}.foot a:hover{color:var(--blue);background:var(--soft)}@media(max-width:760px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.hero{display:block}.hero .btn{margin-top:12px}}@media(max-width:460px){.grid{grid-template-columns:1fr 1fr}.card{padding:16px}.top{align-items:flex-start}.top .btn{flex-shrink:0}}
</style><div class="wrap"><div class="top"><div class="brand"><div class="logo">↗</div><div><div class="title">域名详情</div><div class="muted">域名管理系统</div></div></div><button class="btn secondary" id="back">返回管理</button></div><section class="card"><div class="hero"><div><div class="heroTitle" id="name">加载中…</div><div class="heroUrl" id="url">—</div><div class="pillrow" id="pills"></div></div><button class="btn" id="copy">复制入口链接</button></div></section><section class="grid" id="stats"></section><section class="card"><div class="sectionTitle">访问记录</div><div class="tablewrap"><table><thead><tr><th>时间（UTC）</th><th>来源</th><th>Referer</th><th>User-Agent</th></tr></thead><tbody id="recent"><tr><td colspan="4" class="empty">加载中…</td></tr></tbody></table></div></section><section class="card"><div class="sectionTitle">目标网址修改历史</div><div class="tablewrap"><table><thead><tr><th>时间（UTC）</th><th>操作者</th><th>旧目标</th><th>新目标</th></tr></thead><tbody id="history"><tr><td colspan="4" class="empty">加载中…</td></tr></tbody></table></div></section><div class="foot"><a href="mailto:x@okx.run">邮箱：x@okx.run</a></div></div>
<script>
const ID=${Number(id)||0};const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
async function api(){const r=await fetch('/api/domains/'+ID+'/detail');if(r.status===401){location.href='/admin';return null}const d=await r.json();if(!r.ok)throw Error(d.error||'请求失败');return d}
function health(x){const code=x.health_code!=null?Number(x.health_code):null;if(code!=null&&code>=200&&code<400)return '<span class="pill ok">● 正常 · '+esc(code)+'</span>';if(code!=null&&code>=400&&code<500)return '<span class="pill warn">● 警告 · '+esc(code)+'</span>';if(code!=null&&code>=500)return '<span class="pill bad">● 异常 · '+esc(code)+'</span>';if(x.health_status==='ok')return '<span class="pill ok">● 正常 · '+esc(x.health_code||'2xx/3xx')+'</span>';if(x.health_status==='degraded')return '<span class="pill warn">● 警告 · '+esc(x.health_code||'4xx')+'</span>';if(x.health_status==='down')return '<span class="pill bad">● 异常'+(x.health_code?' · '+esc(x.health_code):'')+'</span>';return '<span class="pill">● 未检查</span>'}
(async()=>{try{const d=await api();if(!d)return;const x=d.domain;document.title=(x.remark||x.domain)+' · 域名详情';document.getElementById('name').textContent=x.remark||x.domain;document.getElementById('url').textContent=x.domain+' → '+x.target_url;document.getElementById('pills').innerHTML=health(x)+' <span class="pill">'+(x.enabled?'● 启用':'● 暂停')+'</span> <span class="pill">'+(x.redirect_type===301?'301 永久':'302 临时')+'</span> <span class="pill">分组：'+esc(x.group_name||'未分组')+'</span>';
const arr=[['今日访问',d.stats.today],['近 7 天',d.stats.week],['累计记录',d.stats.total],['最近检查',x.health_checked_at||'未检查']];document.getElementById('stats').innerHTML=arr.map(a=>'<div class="box"><div class="k">'+esc(a[0])+'</div><div class="v">'+esc(a[1])+'</div></div>').join('');
const rs=document.getElementById('recent');rs.innerHTML=d.recent?.length?d.recent.map(v=>'<tr><td>'+esc(v.visited_at)+'</td><td>'+esc(v.source||'direct')+'</td><td>'+esc(v.referer||'—')+'</td><td>'+esc(v.user_agent||'—')+'</td></tr>').join(''):'<tr><td colspan="4" class="empty">暂无访问记录</td></tr>';
const hs=document.getElementById('history');hs.innerHTML=d.history?.length?d.history.map(v=>'<tr><td>'+esc(v.changed_at)+'</td><td>'+esc(v.changed_by)+'</td><td>'+esc(v.old_target)+'</td><td>'+esc(v.new_target)+'</td></tr>').join(''):'<tr><td colspan="4" class="empty">暂无修改历史</td></tr>';
const u='https://'+x.domain;document.getElementById('copy').onclick=async()=>{try{await navigator.clipboard.writeText(u);document.getElementById('copy').textContent='已复制'}catch{prompt('复制入口链接',u)}};
document.getElementById('back').onclick=()=>location.href='/admin';
}catch(e){document.getElementById('name').textContent='加载失败';document.getElementById('url').textContent=e.message}})();</script></html>`);
}

function adminPage() {
  return html(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>域名管理系统</title>
<style>
:root{color-scheme:light dark;--bg:#f5f5f7;--surface:rgba(255,255,255,.86);--surface-solid:#fff;--text:#1d1d1f;--muted:#86868b;--line:rgba(60,60,67,.14);--field:#fff;--soft:#f0f0f3;--blue:#007aff;--blue-hover:#0066d6;--green:#248a3d;--red:#d70015;--orange:#b76e00;--shadow:0 8px 30px rgba(0,0,0,.035)}
@media(prefers-color-scheme:dark){:root{--bg:#000;--surface:rgba(28,28,30,.86);--surface-solid:#1c1c1e;--text:#f5f5f7;--muted:#98989d;--line:rgba(84,84,88,.6);--field:#2c2c2e;--soft:#2c2c2e;--blue:#0a84ff;--blue-hover:#409cff;--green:#30d158;--red:#ff453a;--orange:#ff9f0a;--shadow:0 8px 30px rgba(0,0,0,.16)}}
*{box-sizing:border-box}html{background:var(--bg);-webkit-text-size-adjust:100%}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 8% 0%,rgba(0,122,255,.075),transparent 34%),var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",sans-serif;letter-spacing:-.01em;-webkit-font-smoothing:antialiased}.wrap{width:min(1240px,100%);margin:0 auto;padding:clamp(18px,3vw,34px) clamp(14px,3vw,30px) max(40px,env(safe-area-inset-bottom))}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:12px}.logo{width:42px;height:42px;display:grid;place-items:center;border-radius:14px;background:var(--blue);color:white;font-size:21px;box-shadow:0 5px 14px rgba(0,122,255,.2)}h1{font-size:clamp(25px,3vw,34px);line-height:1.15;letter-spacing:-.04em;margin:0;font-weight:720}.subtitle{color:var(--muted);font-size:13px;margin-top:7px}.topright{display:flex;align-items:center;gap:10px}.date{text-align:right;color:var(--muted);font-size:12px}.btn{appearance:none;border:0;border-radius:11px;padding:10px 15px;background:var(--blue);color:#fff;font:inherit;font-size:14px;font-weight:600;cursor:pointer;transition:transform .15s,background .15s;min-height:40px}.btn:hover{background:var(--blue-hover)}.btn:active{transform:scale(.98)}.secondary{background:var(--soft);color:var(--text)}.secondary:hover{background:var(--line)}.danger{background:rgba(215,0,21,.1);color:var(--red)}.danger:hover{background:rgba(215,0,21,.17)}.orange{background:rgba(255,159,10,.12);color:var(--orange)}.hero{display:flex;justify-content:space-between;align-items:end;gap:16px;margin:6px 2px 18px}.greeting{font-size:clamp(23px,3.4vw,32px);font-weight:700;letter-spacing:-.04em;line-height:1.2}.greeting-sub{color:var(--muted);margin-top:8px;font-size:14px}.card{background:var(--surface);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid var(--line);border-radius:22px;padding:clamp(16px,2.2vw,23px);margin:15px 0;box-shadow:var(--shadow);overflow:hidden}.sectionhead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}.sectionhead h2{margin:0;font-size:19px;letter-spacing:-.02em}.sectionhead .btn{flex-shrink:0}.sectionhead .subline{color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.fieldwrap{min-width:0}.fieldlabel{display:block;font-size:13px;font-weight:600;color:var(--muted);margin:2px 0 7px}.input,select,textarea{width:100%;min-width:0;padding:12px 13px;border:1px solid var(--line);border-radius:12px;font:inherit;color:var(--text);background:var(--field);outline:none;transition:border .15s,box-shadow .15s}.input:focus,select:focus,textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(0,122,255,.13)}.input:disabled{opacity:.72;background:var(--soft);cursor:not-allowed}textarea{min-height:82px;resize:vertical}.actions{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-top:17px}.hint{font-size:12px;line-height:1.7;color:var(--muted);margin:15px 0 0}.msg{font-size:13px}.ok{color:var(--green)}.err{color:var(--red)}.badge{display:inline-flex;align-items:center;gap:5px;padding:5px 9px;border-radius:99px;background:rgba(48,209,88,.12);color:var(--green);font-size:12px;white-space:nowrap}.badge.off{background:rgba(255,159,10,.14);color:var(--orange)}.badge.unknown{background:rgba(142,142,147,.12);color:var(--muted)}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0 14px}.search{flex:1 1 260px}.filter{flex:0 1 150px}.bulkbar{display:none;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 12px;padding:10px 12px;border-radius:14px;background:var(--soft)}.bulkbar.show{display:flex}.bulkbar .count{font-size:13px;color:var(--muted);margin-right:auto}.tablewrap{width:100%;overflow-x:auto;border-radius:12px;-webkit-overflow-scrolling:touch}table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;min-width:840px}th,td{text-align:left;padding:13px 11px;border-bottom:1px solid var(--line);vertical-align:middle;overflow-wrap:anywhere}th{color:var(--muted);font-weight:650;font-size:12px;white-space:nowrap}tbody tr:last-child td{border-bottom:0}tbody tr{transition:background .15s ease,transform .15s ease}tbody tr:hover{background:rgba(127,127,127,.055)}tbody tr:hover td:first-child{border-radius:10px 0 0 10px}tbody tr:hover td:last-child{border-radius:0 10px 10px 0}td .btn{padding:7px 9px;min-height:32px;font-size:12px;border-radius:9px}.actionbar{display:flex;align-items:center;gap:7px;flex-wrap:wrap;padding:1px 0}.actionbar .btn{margin:0;min-width:56px}.actionbar .btn:focus-visible{outline:3px solid rgba(0,122,255,.2);outline-offset:2px}.actions-cell{min-width:300px}.domain-main{font-weight:650;white-space:nowrap}.target-main{max-width:320px;color:var(--muted);line-height:1.45}.toolbar{padding:2px;background:color-mix(in srgb,var(--surface-solid) 76%,transparent);border:1px solid var(--line);border-radius:14px}.toolbar .input{background:transparent;border-color:transparent}.toolbar .input:focus{border-color:var(--blue);background:var(--field)}.bulkbar{box-shadow:0 6px 20px rgba(0,0,0,.04)}.table-note{font-size:12px;color:var(--muted);margin-top:11px}.empty{text-align:center;color:var(--muted);padding:24px}.status-stack{display:flex;align-items:center;gap:5px;flex-wrap:wrap}.health{display:inline-flex;align-items:center;gap:5px;padding:4px 7px;border-radius:99px;font-size:11px;background:var(--soft);color:var(--muted);white-space:nowrap}.health.ok{background:rgba(48,209,88,.12);color:var(--green)}.health.degraded{background:rgba(255,159,10,.14);color:var(--orange)}.health.down{background:rgba(255,69,58,.12);color:var(--red)}.userbar{font-size:12px;color:var(--muted);margin-right:4px}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:16px 0 20px}.stat{background:var(--soft);border:1px solid transparent;border-radius:16px;padding:15px;min-width:0}.statlabel{color:var(--muted);font-size:13px}.num{font-size:clamp(24px,3vw,30px);font-weight:720;letter-spacing:-.04em;margin-top:5px;font-variant-numeric:tabular-nums}.visit-groups{display:grid;gap:10px}.visit-group{border:1px solid var(--line);border-radius:16px;background:color-mix(in srgb,var(--surface-solid) 72%,transparent);overflow:hidden}.visit-summary{list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 16px;cursor:pointer;user-select:none}.visit-summary::-webkit-details-marker{display:none}.visit-summary::after{content:"›";font-size:22px;line-height:1;color:var(--muted);transform:rotate(90deg);transition:transform .18s ease}.visit-group:not([open]) .visit-summary::after{transform:rotate(0deg)}.visit-summary-main{display:flex;align-items:center;gap:11px;min-width:0}.visit-domain-dot{width:9px;height:9px;border-radius:50%;background:var(--blue);box-shadow:0 0 0 4px rgba(0,122,255,.11);flex:0 0 auto}.visit-title-wrap{min-width:0}.visit-domain{font-weight:650;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.visit-domain-sub{color:var(--muted);font-size:12px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.visit-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;color:var(--muted);font-size:12px}.visit-chip{padding:4px 8px;border-radius:999px;background:var(--soft);white-space:nowrap}.visit-body{padding:0 12px 12px}.visit-body .tablewrap{border-top:1px solid var(--line)}.visit-body table{min-width:700px}.visit-empty{padding:14px 4px;color:var(--muted);font-size:13px}.toolbar-note{font-size:12px;color:var(--muted)}.dialogback{display:none;position:fixed;inset:0;background:rgba(0,0,0,.42);z-index:50;padding:20px;align-items:center;justify-content:center}.dialogback.show{display:flex}.dialog{width:min(850px,100%);max-height:min(88vh,900px);overflow:auto;background:var(--surface-solid);border:1px solid var(--line);border-radius:22px;padding:20px;box-shadow:0 24px 80px rgba(0,0,0,.25)}.dialoghead{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.dialogtitle{font-size:22px;font-weight:720}.detailgrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:16px 0}.detailbox{background:var(--soft);border-radius:14px;padding:13px}.detailbox .k{font-size:12px;color:var(--muted)}.detailbox .v{font-size:18px;font-weight:700;margin-top:4px}.pillrow{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.mini-title{font-weight:650;margin:18px 0 8px}.logtable{min-width:720px}.tokenbox{padding:12px;border:1px dashed var(--blue);border-radius:14px;background:rgba(0,122,255,.05);margin:10px 0}.tokenraw{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.copyrow{display:flex;gap:8px;align-items:center;margin-top:8px}.api-endpoints{display:grid;gap:8px}.endpoint{padding:11px 12px;border-radius:12px;background:var(--soft);font-size:12px}.endpoint code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.settingsgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.settingsgrid-single{grid-template-columns:1fr!important;max-width:760px}.settings-card{padding-bottom:18px}.settingsgrid-single h3{margin:2px 0 8px;font-size:16px;letter-spacing:-.02em}.settingsgrid-single .tokenbox{margin:0;padding:13px 14px}.settingsgrid-single .tokenbox .muted{margin:3px 0}.role{font-size:11px;padding:3px 7px;border-radius:99px;background:var(--soft);color:var(--muted)}.warn{color:var(--orange)}.foot{width:100%;display:flex;justify-content:center;align-items:center;text-align:center;color:var(--muted);font-size:12px;margin:24px 0 0;padding:8px 0}.foot a{display:inline-flex;align-items:center;justify-content:center;color:inherit;text-decoration:none;min-height:28px;padding:0 10px;border-radius:9px;transition:color .15s,background .15s}.foot a:hover{color:var(--blue);background:var(--soft)}
@media(max-width:820px){.settingsgrid{grid-template-columns:1fr}.detailgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:640px){.wrap{padding:18px 13px max(30px,env(safe-area-inset-bottom))}.top{align-items:flex-start;margin-bottom:20px}.topright{flex-direction:column;align-items:flex-end;gap:7px}.date{display:none}.hero{align-items:flex-start;flex-direction:column;margin-bottom:15px}.grid,.stats{grid-template-columns:1fr}.card{border-radius:17px;padding:16px;margin:12px 0}.stats{gap:9px}.stat{padding:13px 15px}.num{font-size:25px}.visit-summary{padding:14px 13px}.visit-meta{gap:6px}.visit-body{padding:0 8px 8px}.actions .btn{flex:1}.actionbar{gap:6px}.actionbar .btn{flex:0 0 auto}.sectionhead{align-items:flex-start}.sectionhead .btn{flex-shrink:0}.subtitle{max-width:210px}.detailgrid{grid-template-columns:1fr 1fr}.dialogback{padding:10px}.dialog{border-radius:18px;padding:15px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto}}
</style>
<div class="wrap"><header class="top"><div class="brand"><div class="logo" aria-hidden="true">↗</div><div><h1>域名管理系统</h1><div class="subtitle">轻松管理你的所有入口域名</div></div></div><div class="topright"><div class="date" id="date"></div><div class="userbar" id="userbar">管理员</div><button class="btn secondary" id="logout">退出登录</button></div></header>
<section class="hero"><div><div class="greeting" id="greeting">你好 👋</div><div class="greeting-sub" id="greetingSub">欢迎回来，今天也顺顺利利。</div></div></section>
<section class="card"><div class="sectionhead"><div><h2 id="formTitle">添加域名</h2><div class="subline">入口域名用于接收访问请求，备注用于快速区分用途，分组用于批量整理</div></div><span class="badge">● 实时配置</span></div><input id="id" type="hidden"><div class="grid"><div class="fieldwrap"><label class="fieldlabel" for="domain">入口域名 <span class="muted" id="domainHint"></span></label><input class="input" id="domain" placeholder="go.example.com" autocomplete="off" autocapitalize="none" spellcheck="false"></div><div class="fieldwrap"><label class="fieldlabel" for="remark">自定义备注</label><input class="input" id="remark" maxlength="100" placeholder="例如：主站入口 / 广告A / 项目1" autocomplete="off"></div><div class="fieldwrap"><label class="fieldlabel" for="groupName">域名分组</label><input class="input" id="groupName" maxlength="50" placeholder="例如：主站 / 广告 / 活动" autocomplete="off"></div><div class="fieldwrap"><label class="fieldlabel" for="target">目标网址</label><input class="input" id="target" type="url" placeholder="https://example.com" autocomplete="url"></div><div class="fieldwrap"><label class="fieldlabel" for="type">跳转类型</label><select id="type"><option value="302">302 · 临时跳转（推荐）</option><option value="301">301 · 永久跳转</option></select></div><div class="fieldwrap"><label class="fieldlabel" for="enabled">域名状态</label><select id="enabled"><option value="1">启用</option><option value="0">暂停</option></select></div></div><label class="fieldlabel" for="message">暂停时显示的提示</label><textarea id="message" maxlength="500">此域名暂时不可用，请稍后再试。</textarea><div class="actions"><button class="btn" id="save">保存配置</button><button class="btn secondary" id="reset">重置</button><span id="msg" class="msg" role="status"></span></div><p class="hint">提示：入口域名需要先在 Cloudflare DNS 中接入并绑定到此 Worker。这里只管理跳转规则，不会自动创建 DNS 记录。填写域名时无需添加协议、路径或端口。</p></section>
<section class="card"><div class="sectionhead"><div><h2>管理域名</h2><div class="subline">支持搜索、状态/分组筛选、批量启用/暂停/删除和健康检查</div></div><button class="btn secondary" id="refresh">刷新</button></div><div class="toolbar"><input class="input search" id="domainSearch" placeholder="搜索域名或备注…"><select class="input filter" id="statusFilter"><option value="all">全部状态</option><option value="1">仅启用</option><option value="0">仅暂停</option></select><select class="input filter" id="typeFilter"><option value="all">全部跳转</option><option value="302">302</option><option value="301">301</option></select><select class="input filter" id="groupFilter"><option value="all">全部分组</option></select></div><div class="bulkbar" id="bulkbar"><span class="count" id="selectedCount">已选 0 个</span><button class="btn" id="bulkEnable">批量启用</button><button class="btn orange" id="bulkDisable">批量暂停</button><button class="btn secondary" id="bulk302">批量 302</button><button class="btn secondary" id="bulk301">批量 301</button><button class="btn danger" id="bulkDelete">批量删除</button></div><div class="tablewrap"><table><thead><tr><th><input id="selectAll" type="checkbox" aria-label="全选"></th><th>入口域名</th><th>备注</th><th>分组</th><th>目标网址</th><th>状态</th><th>跳转</th><th>健康检查</th><th>访问量</th><th>操作</th></tr></thead><tbody id="domains"><tr><td colspan="10" class="empty">正在加载…</td></tr></tbody></table></div><div class="table-note">编辑时入口域名锁定不可修改；分组用于整理域名，健康检查由定时任务执行，也可手动触发。</div></section>
<section class="card"><div class="sectionhead"><div><h2>访问统计</h2><div class="subline">按 UTC 记录 · 以备注名称作为折叠标题 · 同一备注可自动归组；域名分组用于管理筛选</div></div><span class="muted" id="retentionText"></span></div><div class="stats"><div class="stat"><div class="statlabel">今日访问</div><div class="num" id="today">—</div></div><div class="stat"><div class="statlabel">近 7 天</div><div class="num" id="week">—</div></div><div class="stat"><div class="statlabel">累计记录</div><div class="num" id="total">—</div></div></div><div id="visitGroups" class="visit-groups"><div class="empty">正在加载…</div></div><div class="table-note">系统会定期清理超过保留期限的访问记录。</div></section>
<section class="card"><div class="sectionhead"><div><h2>操作日志</h2><div class="subline">记录管理员的关键操作，不记录密码等敏感信息</div></div><button class="btn secondary" id="refreshLogs">刷新</button></div><div class="tablewrap"><table class="logtable"><thead><tr><th>时间</th><th>操作者</th><th>操作</th><th>说明</th></tr></thead><tbody id="logs"><tr><td colspan="4" class="empty">正在加载…</td></tr></tbody></table></div></section>
<section class="card settings-card" id="settingsCard"><div class="sectionhead"><div><h2>系统设置</h2><div class="subline">定时任务和数据维护</div></div></div><div class="settingsgrid settingsgrid-single"><div><h3>定时任务</h3><div class="tokenbox"><b>自动健康检查</b><div class="muted">建议配置 Cron：每 15 分钟检查一批目标网址。</div><div class="muted">访问记录清理：每天 03:10 UTC 自动执行。</div><div class="muted">管理员：admin（登录密码由 Worker Secret 管理）</div><div class="muted" id="cronRetention"></div><button class="btn secondary" id="cleanupNow">立即清理旧访问记录</button></div></div></div></section>
<div class="foot"><a href="mailto:x@okx.run">邮箱：x@okx.run</a></div></div>
<div class="dialogback" id="detailBack"><div class="dialog"><div class="dialoghead"><div><div class="dialogtitle" id="detailTitle">域名详情</div><div class="muted" id="detailSub"></div></div><button class="btn secondary" id="detailClose">关闭</button></div><div class="detailgrid" id="detailStats"></div><div id="detailBody"></div></div></div>
<script>
const $=id=>document.getElementById(id);
let ALL_DOMAINS=[];
let SELECTED_IDS=new Set();
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function updateGreeting(){const now=new Date(),h=now.getHours();let g='你好 👋',s='欢迎回来，今天也顺顺利利。';if(h>=5&&h<11){g='早上好 ☀️';s='新的一天，慢慢来，一切都会有条理。'}else if(h>=11&&h<14){g='中午好 🌤️';s='忙里也记得休息一下。'}else if(h>=14&&h<18){g='下午好 👋';s='保持节奏，稳稳推进。'}else if(h>=18&&h<22){g='晚上好 🌙';s='辛苦一天了，来看看今天的情况。'}else{g='夜深了 🌙';s='还在忙吗？记得早点休息。'}$('greeting').textContent=g;$('greetingSub').textContent=s;$('date').textContent=new Intl.DateTimeFormat('zh-CN',{year:'numeric',month:'long',day:'numeric',weekday:'long'}).format(now)}
async function api(path,opts={}){const r=await fetch(path,{...opts,headers:{'content-type':'application/json',...(opts.headers||{})}});if(r.status===401){location.href='/admin';throw Error('登录已过期')}const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||'请求失败');return d}
function cell(tr,text){const td=document.createElement('td');td.textContent=text??'—';tr.appendChild(td);return td}
function reset(){ $('id').value=''; $('domain').value=''; $('domain').disabled=false; $('domainHint').textContent=''; $('remark').value=''; $('groupName').value=''; $('target').value=''; $('type').value='302'; $('enabled').value='1'; $('message').value=DEFAULT_PAUSED; $('formTitle').textContent='添加域名'; $('msg').textContent=''; }
const DEFAULT_PAUSED='此域名暂时不可用，请稍后再试。';
function healthLabel(x){const code=x.health_code!=null?Number(x.health_code):null;if(code!=null&&code>=200&&code<400)return '<span class="health ok">● 正常 · '+code+'</span>';if(code!=null&&code>=400&&code<500)return '<span class="health degraded">● 警告 · '+code+'</span>';if(code!=null&&code>=500)return '<span class="health down">● 异常 · '+code+'</span>';const hs=String(x.health_status||'unknown');if(hs==='ok')return '<span class="health ok">● 正常'+(x.health_code?' · '+x.health_code:'')+'</span>';if(hs==='degraded')return '<span class="health degraded">● 警告 · '+(x.health_code||'4xx')+'</span>';if(hs==='down')return '<span class="health down">● 异常'+(x.health_code?' · '+x.health_code:'')+'</span>';return '<span class="health">● 未检查</span>'}
function filteredDomains(){const q=$('domainSearch').value.trim().toLowerCase(),s=$('statusFilter').value,t=$('typeFilter').value,g=$('groupFilter').value;return ALL_DOMAINS.filter(x=>(!q||x.domain.toLowerCase().includes(q)||String(x.remark||'').toLowerCase().includes(q)||String(x.group_name||'').toLowerCase().includes(q))&&(s==='all'||String(x.enabled)===s)&&(t==='all'||String(x.redirect_type)===t)&&(g==='all'||String(x.group_name||'')===g))}
function selectedIds(){return [...document.querySelectorAll('.rowcheck:checked')].map(x=>Number(x.value))}
function syncBulk(){const ids=selectedIds();$('selectedCount').textContent='已选 '+ids.length+' 个';$('bulkbar').classList.toggle('show',ids.length>0)}
function renderDomains(){const list=filteredDomains();$('domains').innerHTML='';if(!list.length){$('domains').innerHTML='<tr><td colspan="10" class="empty">暂无匹配域名</td></tr>';$('selectAll').checked=false;syncBulk();return}for(const x of list){const tr=document.createElement('tr');const tdc=cell(tr,'');const cb=document.createElement('input');cb.type='checkbox';cb.className='rowcheck';cb.value=x.id;cb.checked=false;cb.onchange=syncBulk;tdc.appendChild(cb);const dcell=cell(tr,x.domain);dcell.className='domain-main';cell(tr,x.remark||'—');cell(tr,x.group_name||'—');const tcell=cell(tr,x.target_url);tcell.className='target-main';const status=cell(tr,'');const stack=document.createElement('div');stack.className='status-stack';const b=document.createElement('span');b.className='badge'+(x.enabled?'':' off');b.textContent=x.enabled?'● 启用':'● 暂停';const ty=document.createElement('span');ty.className='health';ty.textContent=x.redirect_type===301?'301 永久':'302 临时';stack.append(b,ty);status.appendChild(stack);cell(tr,x.redirect_type===301?'301':'302');const hc=cell(tr,'');hc.innerHTML=healthLabel(x);cell(tr,Number(x.visits||0).toLocaleString());const td=cell(tr,'');td.className='actions-cell';const actionbar=document.createElement('div');actionbar.className='actionbar';const detail=document.createElement('button');detail.className='btn secondary';detail.textContent='详情';detail.onclick=()=>{location.href='/admin/domain/'+x.id};const copy=document.createElement('button');copy.className='btn secondary';copy.style.marginLeft='5px';copy.textContent='复制链接';copy.onclick=async()=>{const u='https://'+x.domain;try{await navigator.clipboard.writeText(u);copy.textContent='已复制';setTimeout(()=>copy.textContent='复制链接',1200)}catch{prompt('复制入口链接',u)}};const edit=document.createElement('button');edit.className='btn secondary';edit.style.marginLeft='5px';edit.textContent='编辑';edit.onclick=()=>{ $('id').value=x.id;$('domain').value=x.domain;$('domain').disabled=true;$('domainHint').textContent='（编辑时不可修改）';$('remark').value=x.remark||'';$('groupName').value=x.group_name||'';$('target').value=x.target_url;$('type').value=x.redirect_type;$('enabled').value=x.enabled;$('message').value=x.paused_message;$('formTitle').textContent='编辑域名';window.scrollTo({top:0,behavior:'smooth'})};const health=document.createElement('button');health.className='btn secondary';health.style.marginLeft='5px';health.textContent='检查';health.onclick=async()=>{health.disabled=true;try{await api('/api/domains/'+x.id+'/health',{method:'POST',body:'{}'});await loadDomains()}catch(e){alert(e.message)}finally{health.disabled=false}};const del=document.createElement('button');del.className='btn danger';del.style.marginLeft='5px';del.textContent='删除';del.onclick=async()=>{if(!confirm('确定删除 '+x.domain+'？此操作会同时删除该入口的访问记录。'))return;try{await api('/api/domains/'+x.id,{method:'DELETE'});await loadDomains();await loadLogs()}catch(e){alert(e.message)}};actionbar.append(detail,copy,edit,health,del);td.appendChild(actionbar);$('domains').appendChild(tr)}syncBulk();}
async function loadDomains(){const d=await api('/api/domains');ALL_DOMAINS=d.domains||[];const groups=[...new Set(ALL_DOMAINS.map(x=>String(x.group_name||'').trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'zh'));const gf=$('groupFilter');const old=gf.value;gf.innerHTML='<option value="all">全部分组</option>'+groups.map(g=>'<option value="'+esc(g)+'">'+esc(g)+'</option>').join('');gf.value=groups.includes(old)?old:'all';renderDomains();}
function renderVisitGroups(recent,domains){const wrap=$('visitGroups');wrap.innerHTML='';const meta=new Map(domains.map(x=>[x.domain,{remark:String(x.remark||'').trim(),visits:Number(x.visits||0)}]));const groups=new Map();for(const v of recent){const domain=String(v.domain||'未知入口域名'),remark=String(v.remark||meta.get(domain)?.remark||'').trim(),key=remark||domain;if(!groups.has(key))groups.set(key,{remark,domains:new Set(),items:[]});const g=groups.get(key);g.domains.add(domain);g.items.push(v)}if(!groups.size){wrap.innerHTML='<div class="empty">暂无访问记录</div>';return}for(const [key,g] of groups){const details=document.createElement('details');details.className='visit-group';const summary=document.createElement('summary');summary.className='visit-summary';const main=document.createElement('div');main.className='visit-summary-main';const dot=document.createElement('span');dot.className='visit-domain-dot';const tw=document.createElement('div');tw.className='visit-title-wrap';const name=document.createElement('div');name.className='visit-domain';name.textContent=key;const sub=document.createElement('div');sub.className='visit-domain-sub';sub.textContent=Array.from(g.domains).join(' · ');tw.append(name,sub);main.append(dot,tw);const vm=document.createElement('div');vm.className='visit-meta';const all=g.items.reduce((n,v)=>n+1,0);const chip1=document.createElement('span');chip1.className='visit-chip';chip1.textContent='本页 '+all+' 条';const chip2=document.createElement('span');chip2.className='visit-chip';chip2.textContent='入口 '+g.domains.size+' 个';vm.append(chip1,chip2);summary.append(main,vm);const body=document.createElement('div');body.className='visit-body';const twrap=document.createElement('div');twrap.className='tablewrap';const table=document.createElement('table');const thead=document.createElement('thead');const trh=document.createElement('tr');['时间（UTC）','入口域名','来源','Referer'].forEach(h=>{const th=document.createElement('th');th.textContent=h;trh.appendChild(th)});thead.appendChild(trh);const tbody=document.createElement('tbody');for(const v of g.items){const tr=document.createElement('tr');cell(tr,v.visited_at);cell(tr,v.domain);cell(tr,v.source);cell(tr,v.referer);tbody.appendChild(tr)}table.append(thead,tbody);twrap.appendChild(table);body.appendChild(twrap);details.append(summary,body);wrap.appendChild(details)}}
async function loadStats(){const s=await api('/api/stats');$('today').textContent=Number(s.today||0).toLocaleString();$('week').textContent=Number(s.week||0).toLocaleString();$('total').textContent=Number(s.total||0).toLocaleString();renderVisitGroups(s.recent||[],ALL_DOMAINS);$('retentionText').textContent='访问日志保留 '+s.retention+' 天';$('cronRetention').textContent='当前访问日志保留：'+s.retention+' 天（由 LOG_RETENTION_DAYS 控制）。'}
async function loadLogs(){const d=await api('/api/audit-logs');$('logs').innerHTML='';if(!d.logs?.length){$('logs').innerHTML='<tr><td colspan="4" class="empty">暂无操作日志</td></tr>';return}for(const x of d.logs){const tr=document.createElement('tr');cell(tr,x.created_at);cell(tr,x.actor);cell(tr,x.action);cell(tr,x.summary);$('logs').appendChild(tr)}}
async function openDetail(id){$('detailBack').classList.add('show');$('detailTitle').textContent='加载中…';try{const d=await api('/api/domains/'+id+'/detail');const x=d.domain;$('detailTitle').textContent=x.remark||x.domain;$('detailSub').textContent=(x.group_name?('['+x.group_name+'] '):'')+x.domain+' → '+x.target_url;const stats=[['今日访问',d.stats.today],['近 7 天',d.stats.week],['累计记录',d.stats.total],['健康状态',x.health_status==='ok'?'正常':x.health_status==='degraded'?'可访问':'异常']];$('detailStats').innerHTML='';for(const [k,v] of stats){const b=document.createElement('div');b.className='detailbox';b.innerHTML='<div class="k">'+esc(k)+'</div><div class="v">'+esc(String(v??0))+'</div>';$('detailStats').appendChild(b)}let body='<div class="pillrow">'+healthLabel(x)+' <span class="health">'+(x.redirect_type===301?'301 永久':'302 临时')+'</span> <span class="health">'+(x.enabled?'启用':'暂停')+'</span> <span class="health">备注：'+esc(x.remark||'—')+'</span> <span class="health">分组：'+esc(x.group_name||'未分组')+'</span> <button class="btn secondary" id="detailCopy">复制入口链接</button></div>'; 
body+='<div class="mini-title">最近访问</div><div class="tablewrap"><table><thead><tr><th>时间</th><th>来源</th><th>Referer</th></tr></thead><tbody>'+(d.recent.length?d.recent.map(v=>'<tr><td>'+esc(v.visited_at)+'</td><td>'+esc(v.source||'—')+'</td><td>'+esc(v.referer||'—')+'</td></tr>').join(''):'<tr><td colspan="3" class="empty">暂无</td></tr>')+'</tbody></table></div>';
body+='<div class="mini-title">目标网址修改历史</div><div class="tablewrap"><table><thead><tr><th>时间</th><th>操作者</th><th>旧目标</th><th>新目标</th></tr></thead><tbody>'+(d.history.length?d.history.map(v=>'<tr><td>'+esc(v.changed_at)+'</td><td>'+esc(v.changed_by)+'</td><td>'+esc(v.old_target||'—')+'</td><td>'+esc(v.new_target||'—')+'</td></tr>').join(''):'<tr><td colspan="4" class="empty">暂无修改历史</td></tr>')+'</tbody></table></div>';$('detailBody').innerHTML=body;const dc=document.getElementById('detailCopy');if(dc)dc.onclick=async()=>{const u='https://'+x.domain;try{await navigator.clipboard.writeText(u);dc.textContent='已复制';setTimeout(()=>dc.textContent='复制入口链接',1200)}catch{prompt('复制入口链接',u)}}}catch(e){$('detailTitle').textContent='加载失败';$('detailBody').innerHTML='<div class="empty">'+esc(e.message)+'</div>'}}
$('detailClose').onclick=()=>$('detailBack').classList.remove('show');$('detailBack').onclick=e=>{if(e.target===$('detailBack'))$('detailBack').classList.remove('show')}
async function bulk(action){const ids=selectedIds();if(!ids.length)return;if(action==='delete'&&!confirm('确定删除选中的 '+ids.length+' 个域名？同时会删除这些域名的访问记录。'))return;try{await api('/api/domains/bulk',{method:'POST',body:JSON.stringify({ids,action})});await Promise.all([loadDomains(),loadStats(),loadLogs()]);$('selectAll').checked=false}catch(e){alert(e.message)}}
$('selectAll').onchange=()=>{document.querySelectorAll('.rowcheck').forEach(x=>x.checked=$('selectAll').checked);syncBulk()};$('domainSearch').oninput=renderDomains;$('statusFilter').onchange=renderDomains;$('typeFilter').onchange=renderDomains;$('groupFilter').onchange=renderDomains;$('bulkEnable').onclick=()=>bulk('enable');$('bulkDisable').onclick=()=>bulk('disable');$('bulk302').onclick=()=>bulk('302');$('bulk301').onclick=()=>bulk('301');$('bulkDelete').onclick=()=>bulk('delete');
$('save').onclick=async()=>{const payload={domain:$('domain').value,remark:$('remark').value,group_name:$('groupName').value,target_url:$('target').value,redirect_type:Number($('type').value),enabled:Number($('enabled').value),paused_message:$('message').value};$('msg').textContent='正在保存…';$('msg').className='msg';$('save').disabled=true;try{if($('id').value)await api('/api/domains/'+$('id').value,{method:'PUT',body:JSON.stringify(payload)});else await api('/api/domains',{method:'POST',body:JSON.stringify(payload)});$('msg').textContent='已保存';$('msg').className='msg ok';reset();await Promise.all([loadDomains(),loadStats(),loadLogs()])}catch(e){$('msg').textContent=e.message;$('msg').className='msg err'}finally{$('save').disabled=false}};
$('reset').onclick=reset;$('refresh').onclick=()=>loadAll().catch(e=>alert(e.message));$('refreshLogs').onclick=()=>loadLogs().catch(e=>alert(e.message));$('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST',body:'{}'})}finally{location.href='/admin'}};$('cleanupNow').onclick=async()=>{if(!confirm('立即删除超过保留期限的访问记录？'))return;try{const d=await api('/api/cleanup',{method:'POST',body:'{}'});alert('已清理 '+d.deleted+' 条访问记录');await Promise.all([loadStats(),loadLogs()])}catch(e){alert(e.message)}};
async function loadAll(){await loadDomains();await loadStats();await loadLogs();$('userbar').textContent='管理员'}
updateGreeting();loadAll().catch(e=>{if(e.message!=='登录已过期')alert(e.message)});reset();
</script></html>`);
}

function pausedPage(message) {
  return html(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>暂时无法访问</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#f5f5f7;color:#1d1d1f;font:16px -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",sans-serif}@media(prefers-color-scheme:dark){body{background:#000;color:#f5f5f7}.box{background:#1c1c1e!important;border-color:#38383c!important}}.box{max-width:560px;text-align:center;background:#fff;border:1px solid rgba(60,60,67,.14);border-radius:20px;padding:36px 26px;box-shadow:0 12px 45px rgba(0,0,0,.08)}.muted{color:#86868b}</style><main class="box"><h1>暂时无法访问</h1><p class="muted">${escapeHtml(message || DEFAULT_PAUSED)}</p></main></html>`, 503, { "retry-after": "300" });
}

async function apiHandler(request, env, pathname, ctx) {
  if (pathname === "/api/login" && request.method === "POST") {
    if (!sameOrigin(request)) return json({error:"请求来源不合法"},403);
    if (!env.SESSION_SECRET || !env.DB || !env.ADMIN_PASSWORD) return json({error:"系统尚未完成数据库、ADMIN_PASSWORD 和会话密钥配置"},500);
    let body; try { body=await request.json(); } catch { return json({error:"请求格式错误"},400); }
    const username=String(body.username||"admin").trim();
    const password=String(body.password||"");

    // Primary bootstrap login: authenticate the built-in admin directly with the Worker Secret.
    if (username.toLowerCase() === "admin" && safeEqual(password, env.ADMIN_PASSWORD)) {
      const bootstrapUser={id:0,username:"admin",role:"admin",enabled:1};
      await audit(env, "admin", "auth.login", "管理员登录成功");
      return json({ok:true},200,{"set-cookie":sessionCookie(await createSession(env.SESSION_SECRET,bootstrapUser))});
    }

  }
  if (pathname === "/api/logout" && request.method === "POST") {
    const session=await getSession(request,env);
    if (session) await audit(env, session.username, "auth.logout", "管理员退出登录");
    return json({ok:true},200,{"set-cookie":sessionCookie("",0)});
  }
  const session=await getSession(request,env);
  if (!session) return json({error:"未登录"},401);
  if (!sameOrigin(request)) return json({error:"请求来源不合法"},403);
  const actor=session.username;

  if (pathname === "/api/me" && request.method === "GET") return json({user:session});

  if (pathname === "/api/domains" && request.method === "GET") {
    const rows = await env.DB.prepare(`SELECT d.id,d.domain,d.remark,d.group_name,d.target_url,d.enabled,d.redirect_type,d.paused_message,d.health_status,d.health_code,d.health_checked_at,d.health_error,d.created_at,d.updated_at,
      (SELECT COUNT(*) FROM visits v WHERE v.domain_id=d.id) AS visits
      FROM domains d ORDER BY d.created_at DESC`).all();
    return json({domains:rows.results || []});
  }
  if (pathname === "/api/domains" && request.method === "POST") {
    let b; try { b=await request.json(); } catch { return json({error:"请求格式错误"},400); }
    const domain=normalizeDomain(b.domain),remark=validateRemark(b.remark),groupName=validateGroup(b.group_name),target=String(b.target_url||"").trim(),type=Number(b.redirect_type),enabled=Number(b.enabled),message=String(b.paused_message||DEFAULT_PAUSED).trim().slice(0,500)||DEFAULT_PAUSED;
    if (remark===null) return json({error:"备注不能超过 100 个字符"},400); if (groupName===null) return json({error:"分组不能超过 50 个字符"},400); if(!domain)return json({error:"域名格式不正确，请填写 example.com 或 go.example.com"},400);if(!validateTarget(target))return json({error:"目标网址必须是有效的 http:// 或 https:// 地址"},400);if(![301,302].includes(type))return json({error:"跳转类型只能是 301 或 302"},400);if(![0,1].includes(enabled))return json({error:"状态不合法"},400);
    try{const result=await env.DB.prepare("INSERT INTO domains (domain,remark,group_name,target_url,enabled,redirect_type,paused_message) VALUES (?,?,?,?,?,?,?)").bind(domain,remark,groupName,target,enabled,type,message).run();const id=result.meta?.last_row_id||null;await audit(env,actor,"domain.create",`新增入口 ${domain}，备注：${remark||'—'}`,id)}catch{return json({error:"该域名已存在，或数据库写入失败"},409)}return json({ok:true});
  }
  const match=pathname.match(/^\/api\/domains\/(\d+)$/);
  if (match && request.method === "PUT") {
    let b;try{b=await request.json()}catch{return json({error:"请求格式错误"},400)};
    const id=Number(match[1]),old=await env.DB.prepare("SELECT * FROM domains WHERE id=?").bind(id).first();if(!old)return json({error:"域名记录不存在"},404);const domain=old.domain,remark=validateRemark(b.remark),groupName=validateGroup(b.group_name),target=String(b.target_url||"").trim(),type=Number(b.redirect_type),enabled=Number(b.enabled),message=String(b.paused_message||DEFAULT_PAUSED).trim().slice(0,500)||DEFAULT_PAUSED;if(remark===null)return json({error:"备注不能超过 100 个字符"},400);if(groupName===null)return json({error:"分组不能超过 50 个字符"},400);if(!validateTarget(target))return json({error:"目标网址必须是有效的 http:// 或 https:// 地址"},400);if(![301,302].includes(type))return json({error:"跳转类型只能是 301 或 302"},400);if(![0,1].includes(enabled))return json({error:"状态不合法"},400);
    await env.DB.prepare("UPDATE domains SET domain=?,remark=?,group_name=?,target_url=?,enabled=?,redirect_type=?,paused_message=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(domain,remark,groupName,target,enabled,type,message,id).run();
    if(old.target_url!==target){await env.DB.prepare("INSERT INTO target_history (domain_id,old_target,new_target,changed_by) VALUES (?,?,?,?)").bind(id,old.target_url,target,actor).run();await audit(env,actor,"domain.target_change",`修改 ${domain} 目标网址：${old.target_url} → ${target}`,id)}else await audit(env,actor,"domain.update",`修改入口 ${domain}`,id);return json({ok:true});
  }
  if (match && request.method === "DELETE") { const id=Number(match[1]);const d=await env.DB.prepare("SELECT domain FROM domains WHERE id=?").bind(id).first();if(!d)return json({error:"域名记录不存在"},404);await env.DB.prepare("DELETE FROM visits WHERE domain_id=?").bind(id).run();const result=await env.DB.prepare("DELETE FROM domains WHERE id=?").bind(id).run();if(!result.meta?.changes)return json({error:"域名记录不存在"},404);await audit(env,actor,"domain.delete",`删除入口 ${d.domain}`,id);return json({ok:true}); }
  if (pathname === "/api/domains/bulk" && request.method === "POST") {
let b;try{b=await request.json()}catch{return json({error:"请求格式错误"},400)};const ids=Array.from(new Set((Array.isArray(b.ids)?b.ids:[]).map(Number).filter(Number.isInteger)));const action=String(b.action||"");if(!ids.length||ids.length>200)return json({error:"请选择 1-200 个域名"},400);if(!["enable","disable","301","302","delete"].includes(action))return json({error:"批量操作不支持"},400);const placeholders=ids.map(()=>"?").join(",");if(action==='delete'){await env.DB.prepare(`DELETE FROM visits WHERE domain_id IN (${placeholders})`).bind(...ids).run();await env.DB.prepare(`DELETE FROM domains WHERE id IN (${placeholders})`).bind(...ids).run()}else{const enabled=action==='enable'?1:action==='disable'?0:null;if(enabled!==null)await env.DB.prepare(`UPDATE domains SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id IN (${placeholders})`).bind(enabled,...ids).run();else await env.DB.prepare(`UPDATE domains SET redirect_type=?,updated_at=CURRENT_TIMESTAMP WHERE id IN (${placeholders})`).bind(Number(action),...ids).run()}await audit(env,actor,'domain.bulk',`批量操作 ${action}，数量 ${ids.length}`);return json({ok:true})}
  const healthMatch=pathname.match(/^\/api\/domains\/(\d+)\/health$/);
  if(healthMatch&&request.method==='POST'){const id=Number(healthMatch[1]);const d=await env.DB.prepare("SELECT domain,target_url FROM domains WHERE id=?").bind(id).first();if(!d)return json({error:"域名记录不存在"},404);const r=await updateDomainHealth(env,id,d.target_url);await audit(env,actor,'domain.health_check',`手动检查 ${d.domain}：${r.status}${r.code?' / '+r.code:''}`,id);return json({ok:true,result:r})}
  const detailMatch=pathname.match(/^\/api\/domains\/(\d+)\/detail$/);if(detailMatch&&request.method==='GET'){const id=Number(detailMatch[1]);const d=await env.DB.prepare("SELECT id,domain,remark,group_name,target_url,enabled,redirect_type,paused_message,health_status,health_code,health_checked_at,health_error,created_at,updated_at FROM domains WHERE id=?").bind(id).first();if(!d)return json({error:"域名记录不存在"},404);const [today,week,total,recent,history]=await Promise.all([env.DB.prepare("SELECT COUNT(*) n FROM visits WHERE domain_id=? AND date(visited_at)=date('now')").bind(id).first(),env.DB.prepare("SELECT COUNT(*) n FROM visits WHERE domain_id=? AND visited_at>=datetime('now','-7 days')").bind(id).first(),env.DB.prepare("SELECT COUNT(*) n FROM visits WHERE domain_id=?").bind(id).first(),env.DB.prepare("SELECT visited_at,source,referer,user_agent FROM visits WHERE domain_id=? ORDER BY id DESC LIMIT 30").bind(id).all(),env.DB.prepare("SELECT old_target,new_target,changed_by,changed_at FROM target_history WHERE domain_id=? ORDER BY id DESC LIMIT 30").bind(id).all()]);return json({domain:d,stats:{today:today?.n||0,week:week?.n||0,total:total?.n||0},recent:recent.results||[],history:history.results||[]})}
  if (pathname === "/api/stats" && request.method === "GET") {const [today,week,total,recent]=await Promise.all([env.DB.prepare("SELECT COUNT(*) n FROM visits WHERE date(visited_at)=date('now')").first(),env.DB.prepare("SELECT COUNT(*) n FROM visits WHERE visited_at>=datetime('now','-7 days')").first(),env.DB.prepare("SELECT COUNT(*) n FROM visits").first(),env.DB.prepare(`SELECT v.visited_at,d.domain,d.remark,v.source,v.referer FROM visits v LEFT JOIN domains d ON d.id=v.domain_id ORDER BY v.id DESC LIMIT 120`).all()]);return json({today:today?.n||0,week:week?.n||0,total:total?.n||0,recent:recent.results||[],retention:parseRetention(env)})}
  if (pathname === "/api/audit-logs" && request.method === "GET") {const rows=await env.DB.prepare("SELECT id,actor,action,summary,domain_id,created_at FROM audit_logs ORDER BY id DESC LIMIT 100").all();return json({logs:rows.results||[]})}
  if (pathname === "/api/cleanup" && request.method === "POST") {const deleted=await cleanupOldVisits(env);const audits=await cleanupOldAudits(env);await audit(env,actor,'system.cleanup',`立即清理访问记录 ${deleted} 条，操作日志 ${audits} 条`);return json({ok:true,deleted,audits})}

  return json({error:"接口不存在"},404);
}

export default {
  async fetch(request, env, ctx) {
    const url=new URL(request.url),host=normalizeHost(url.hostname),path=url.pathname;
    if(path.startsWith('/api/')){try{return await apiHandler(request,env,path,ctx)}catch(e){console.error(e);return json({error:'服务器内部错误'},500)}}
    const adminHost=normalizeHost(env.ADMIN_HOST||'');
    if(adminHost&&host===adminHost){try{if(path==='/'||path==='/admin'){if(await authenticated(request,env))return adminPage();return loginPage()}const dm=path.match(/^\/admin\/domain\/(\d+)$/);if(dm){if(await authenticated(request,env))return domainDetailPage(Number(dm[1]));return loginPage()}return html('Not Found',404)}catch(e){console.error('admin page error',e);return html('系统暂时无法打开，请稍后刷新。',500)}}
    const domain=await getDomain(env,host);if(!domain)return html('This domain is not configured.',404);ctx.waitUntil(recordVisit(env,request,domain.id).catch(()=>{}));if(!domain.enabled)return pausedPage(domain.paused_message);const target=new URL(domain.target_url);target.pathname='/';target.search='';target.hash='';return Response.redirect(target.toString(),Number(domain.redirect_type)===301?301:302);
  },
  async scheduled(controller, env, ctx) {
    try {
      if(controller.cron==='*/15 * * * *'){
        const rows=await env.DB.prepare("SELECT id,target_url,domain FROM domains WHERE enabled=1 ORDER BY CASE WHEN health_checked_at IS NULL THEN 0 ELSE 1 END, health_checked_at ASC LIMIT ?").bind(DEFAULT_HEALTH_LIMIT).all();
        const jobs=(rows.results||[]).map(async d=>{const r=await updateDomainHealth(env,d.id,d.target_url);return {domain:d.domain,result:r}});await Promise.all(jobs);console.log('health checks completed',rows.results?.length||0);
      } else if(controller.cron==='10 3 * * *') {
        const deleted=await cleanupOldVisits(env);const audits=await cleanupOldAudits(env);console.log('cleanup completed',{deleted,audits,retention:parseRetention(env)});
      }
    } catch(e){console.error('scheduled task failed',e)}
  }
};
