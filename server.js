'use strict';
// ══════════════════════════════════════════════════════════
//  焕墟幻境 · 后端服务  — 纯 Node.js 内置模块，无需 npm
// ══════════════════════════════════════════════════════════
const http   = require('http');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { parse: parseUrl } = require('url');

const PORT   = process.env.PORT || 3000;
const SECRET = 'huanxu_2024_secret_key';
const DATA   = path.join(__dirname, 'data');
const PUBLIC = path.join(__dirname, 'public');

if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });

// ── 持久化存储（JSON 文件 + 内存缓存）──────────────────────
const load  = n => { try { return JSON.parse(fs.readFileSync(path.join(DATA, n+'.json'), 'utf8')); } catch { return []; } };
const flush = (n, d) => fs.writeFileSync(path.join(DATA, n+'.json'), JSON.stringify(d, null, 2));

const DB = {
  users:     load('users'),
  sessions:  load('sessions'),
  answers:   load('answers'),
  marks:     load('marks'),
  shares:    load('shares'),
  contracts: load('contracts')
};
const save = n => flush(n, DB[n]);
const uid  = arr => (arr.length ? Math.max(...arr.map(x => x.id || 0)) : 0) + 1;

// ── 密码哈希（PBKDF2，纯内置）──────────────────────────────
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h    = crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha256').toString('hex');
  return `${salt}:${h}`;
}
function checkPw(pw, stored) {
  const [salt, h] = stored.split(':');
  return crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha256').toString('hex') === h;
}

// ── Token（HMAC-SHA256，纯内置）────────────────────────────
function mkToken(data) {
  const p = Buffer.from(JSON.stringify({ ...data, exp: Date.now() + 7 * 86400000 })).toString('base64url');
  const s = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  return `${p}.${s}`;
}
function parseToken(tok) {
  if (!tok) throw new Error('no token');
  const [p, s] = (tok || '').split('.');
  if (!p || !s) throw new Error('malformed');
  if (crypto.createHmac('sha256', SECRET).update(p).digest('base64url') !== s) throw new Error('invalid');
  const d = JSON.parse(Buffer.from(p, 'base64url').toString());
  if (d.exp < Date.now()) throw new Error('expired');
  return d;
}

// ── SSE 实时推送 ────────────────────────────────────────────
const SSE = {}; // { sessionId: { parent: res, child: res } }

function notify(sid, msg, skip = null) {
  const c = SSE[sid];
  if (!c) return;
  const d = `data: ${JSON.stringify(msg)}\n\n`;
  for (const role of ['parent', 'child']) {
    if (role !== skip && c[role]) { try { c[role].write(d); } catch {} }
  }
}

// ── 静态文件 ────────────────────────────────────────────────
const MIME = { '.html': 'text/html;charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.ico': 'image/x-icon' };
function serveFile(res, fp) {
  fs.readFile(fp, (e, d) => {
    if (e) { res.writeHead(404); res.end('404'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'text/plain' });
    res.end(d);
  });
}

// ── Body 解析 ───────────────────────────────────────────────
function readBody(req) {
  return new Promise(done => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => { try { done(JSON.parse(b)); } catch { done({}); } });
    req.on('error', () => done({}));
  });
}

// ══════════════════════════════════════════════════════════
//  HTTP 路由
// ══════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const u = parseUrl(req.url, true);
  const M = req.method;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (M === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── 静态文件 ──────────────────────────────────────────
  if (!u.pathname.startsWith('/api/')) {
    const fp = path.join(PUBLIC, u.pathname === '/' ? 'index.html' : u.pathname);
    if (!fp.startsWith(PUBLIC)) { res.writeHead(400); res.end(); return; }
    return serveFile(res, fp);
  }

  // ── SSE 连接 ───────────────────────────────────────────
  if (u.pathname === '/api/events') {
    let user;
    try { user = parseToken(u.query.token); } catch { res.writeHead(401); res.end(); return; }
    const sid  = +u.query.sessionId;
    const sess = DB.sessions.find(s => s.id === sid);
    if (!sess) { res.writeHead(404); res.end(); return; }
    if (user.role === 'child'  && sess.childId  !== user.id) { res.writeHead(403); res.end(); return; }
    if (user.role === 'parent' && sess.parentId !== user.id) { res.writeHead(403); res.end(); return; }

    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
    res.write('data: {"type":"connected"}\n\n');

    if (!SSE[sid]) SSE[sid] = {};
    SSE[sid][user.role] = res;
    req.on('close', () => { if (SSE[sid]) delete SSE[sid][user.role]; });
    return;
  }

  // ── JSON API ───────────────────────────────────────────
  res.setHeader('Content-Type', 'application/json');
  const b = M !== 'GET' ? await readBody(req) : {};
  let user = null;
  try { user = parseToken((req.headers.authorization || '').split(' ')[1]); } catch {}

  const ok   = d  => { res.writeHead(200); res.end(JSON.stringify(d)); };
  const fail = (c, e) => { res.writeHead(c); res.end(JSON.stringify({ error: e })); };
  const need = () => { if (!user) { fail(401, '请先登录'); return false; } return true; };

  // POST /api/register
  if (u.pathname === '/api/register' && M === 'POST') {
    const { email, password, role } = b;
    if (!email || !password || !['parent', 'child'].includes(role)) return fail(400, '请填写所有字段');
    const em = email.toLowerCase().trim();
    if (DB.users.find(u => u.email === em)) return fail(400, '该邮箱已注册');
    const nu = { id: uid(DB.users), email: em, passwordHash: hashPw(password), role };
    DB.users.push(nu); save('users');
    return ok({ token: mkToken({ id: nu.id, email: nu.email, role }), role: nu.role, email: nu.email });
  }

  // POST /api/login
  if (u.pathname === '/api/login' && M === 'POST') {
    const { email, password } = b;
    const u2 = DB.users.find(u => u.email === email?.toLowerCase().trim());
    if (!u2 || !checkPw(password, u2.passwordHash)) return fail(401, '邮箱或密码错误');
    return ok({ token: mkToken({ id: u2.id, email: u2.email, role: u2.role }), role: u2.role, email: u2.email });
  }

  // POST /api/sessions/create  (孩子创建，复用现有等待中的)
  if (u.pathname === '/api/sessions/create' && M === 'POST') {
    if (!need()) return;
    if (user.role !== 'child') return fail(403, '仅求道者可创建');
    const ex = DB.sessions.find(s => s.childId === user.id && !s.parentId && !s.complete);
    if (ex) return ok({ session: ex });
    let code;
    do { code = crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6); }
    while (DB.sessions.find(s => s.code === code));
    const s = { id: uid(DB.sessions), code, parentId: null, childId: user.id };
    DB.sessions.push(s); save('sessions');
    return ok({ session: s });
  }

  // POST /api/sessions/new  (孩子强制新建)
  if (u.pathname === '/api/sessions/new' && M === 'POST') {
    if (!need()) return;
    if (user.role !== 'child') return fail(403, '仅求道者可创建');
    let code;
    do { code = crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 6); }
    while (DB.sessions.find(s => s.code === code));
    const s = { id: uid(DB.sessions), code, parentId: null, childId: user.id };
    DB.sessions.push(s); save('sessions');
    return ok({ session: s });
  }

  // POST /api/sessions/join  (家长输入邀请码加入)
  if (u.pathname === '/api/sessions/join' && M === 'POST') {
    if (!need()) return;
    if (user.role !== 'parent') return fail(403, '仅护道者可加入');
    const ex = DB.sessions.find(s => s.parentId === user.id && !s.complete);
    if (ex) return ok({ session: ex });
    const s = DB.sessions.find(s => s.code === b.code?.toUpperCase().trim() && !s.parentId);
    if (!s) return fail(404, '邀请码无效或已被使用');
    s.parentId = user.id; save('sessions');
    notify(s.id, { type: 'parent_joined' });
    return ok({ session: s });
  }

  // GET /api/sessions/mine
  if (u.pathname === '/api/sessions/mine' && M === 'GET') {
    if (!need()) return;
    const list = DB.sessions.filter(s => user.role === 'child' ? s.childId === user.id : s.parentId === user.id);
    return ok({ session: list.sort((a, b) => b.id - a.id)[0] || null });
  }

  // POST /api/answers
  if (u.pathname === '/api/answers' && M === 'POST') {
    if (!need()) return;
    const { sessionId, q1, q2, q3 } = b;
    const idx = DB.answers.findIndex(a => a.sessionId === sessionId && a.role === user.role);
    const ans = { sessionId, role: user.role, q1: q1 || '', q2: q2 || '', q3: q3 || '' };
    if (idx >= 0) DB.answers[idx] = ans; else DB.answers.push(ans);
    save('answers');
    notify(sessionId, { type: 'partner_submitted', role: user.role }, user.role);
    const n = DB.answers.filter(a => a.sessionId === sessionId).length;
    if (n >= 2) notify(sessionId, { type: 'both_submitted' });
    return ok({ ok: true });
  }

  // GET /api/answers/:sid
  if (u.pathname.match(/^\/api\/answers\/\d+$/) && M === 'GET') {
    if (!need()) return;
    const sid = +u.pathname.split('/')[3];
    return ok({ answers: DB.answers.filter(a => a.sessionId === sid) });
  }

  // POST /api/marks
  if (u.pathname === '/api/marks' && M === 'POST') {
    if (!need()) return;
    const { sessionId, target, qnum, mtype } = b;
    const marker = user.role;
    const idx = DB.marks.findIndex(m => m.sessionId === sessionId && m.marker === marker && m.target === target && m.qnum === qnum);
    if (mtype) {
      if (idx >= 0) DB.marks[idx].mtype = mtype; else DB.marks.push({ sessionId, marker, target, qnum, mtype });
    } else {
      if (idx >= 0) DB.marks.splice(idx, 1);
    }
    save('marks');
    notify(sessionId, { type: 'mark_update', marker, target, qnum, mtype }, marker);
    if (mtype === 'gold') {
      const n = DB.marks.filter(m => m.sessionId === sessionId && m.qnum === qnum && m.mtype === 'gold').length;
      if (n >= 2) notify(sessionId, { type: 'resonance', qnum });
    }
    return ok({ ok: true });
  }

  // GET /api/marks/:sid
  if (u.pathname.match(/^\/api\/marks\/\d+$/) && M === 'GET') {
    if (!need()) return;
    const sid = +u.pathname.split('/')[3];
    return ok({ marks: DB.marks.filter(m => m.sessionId === sid) });
  }

  // POST /api/shares
  if (u.pathname === '/api/shares' && M === 'POST') {
    if (!need()) return;
    const { sessionId, text } = b;
    const field = user.role === 'parent' ? 'parentText' : 'childText';
    let share = DB.shares.find(s => s.sessionId === sessionId);
    if (!share) { share = { sessionId, parentText: '', childText: '' }; DB.shares.push(share); }
    share[field] = text || '';
    save('shares');
    notify(sessionId, { type: 'share_update', role: user.role, text: text || '' }, user.role);
    return ok({ ok: true });
  }

  // GET /api/shares/:sid
  if (u.pathname.match(/^\/api\/shares\/\d+$/) && M === 'GET') {
    if (!need()) return;
    const sid = +u.pathname.split('/')[3];
    return ok({ share: DB.shares.find(s => s.sessionId === sid) || null });
  }

  // POST /api/contracts/sign
  if (u.pathname === '/api/contracts/sign' && M === 'POST') {
    if (!need()) return;
    const { sessionId } = b;
    let c = DB.contracts.find(c => c.sessionId === sessionId);
    if (!c) { c = { sessionId, parentSigned: 0, childSigned: 0 }; DB.contracts.push(c); }
    if (user.role === 'parent') c.parentSigned = 1; else c.childSigned = 1;
    save('contracts');
    notify(sessionId, { type: 'partner_signed', role: user.role });
    if (c.parentSigned && c.childSigned) {
      const sess = DB.sessions.find(s => s.id === sessionId);
      if (sess) { sess.complete = true; save('sessions'); }
      notify(sessionId, { type: 'complete' });
    }
    return ok({ ok: true, contract: c });
  }

  // GET /api/contracts/:sid
  if (u.pathname.match(/^\/api\/contracts\/\d+$/) && M === 'GET') {
    if (!need()) return;
    const sid = +u.pathname.split('/')[3];
    return ok({ contract: DB.contracts.find(c => c.sessionId === sid) || null });
  }

  fail(404, 'Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  焕墟幻境 · 服务器已启动`);
  console.log(`  地址：http://localhost:${PORT}`);
  console.log(`  数据：${DATA}\n`);
});
