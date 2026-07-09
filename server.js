// server.js — MATSU MVP REST API (Express + SQLite + JWT)
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { db, initSchema, now, rid } from './db.js';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 4000;

initSchema();
const app = express();
app.use(cors());              // 운영 시 origin 화이트리스트로 제한하세요
app.use(express.json({ limit: '2mb' }));

// ── 인증 유틸 ──
function sign(user) { return jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' }); }
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'no_token' });
  try {
    req.uid = jwt.verify(t, JWT_SECRET).id;
    const u = db.prepare('SELECT suspended FROM users WHERE id=?').get(req.uid);
    if (u && u.suspended) return res.status(403).json({ error: 'suspended' });
    next();
  } catch { return res.status(401).json({ error: 'bad_token' }); }
}
// 토큰이 있으면 uid, 없거나 무효면 null (공개 엔드포인트에서 joined 여부 판단용)
function tryUid(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return null;
  try { return jwt.verify(t, JWT_SECRET).id; } catch { return null; }
}
const getUser = (id) => db.prepare('SELECT * FROM users WHERE id=?').get(id);

// 영구 익명 닉네임 생성
const ADJ = ['깜찍한','신난','용감한','날쌘','엉뚱한','포근한','새침한','든든한','수줍은','호기심많은','씩씩한','상냥한'];
const ANI = ['비단뱀','고슴도치','물개','수달','너구리','다람쥐','고양이','판다','여우','두더지','알파카','펭귄'];
function anonNick(seed) {
  let h = 0; for (const c of String(seed)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return ADJ[h % ADJ.length] + ANI[Math.floor(h / 7) % ANI.length];
}

// ── AUTH ──
// 데모/개발용 로그인. 실서비스는 카카오/애플 OAuth 토큰을 서버에서 검증 후 발급하세요.
app.post('/auth/dev-login', (req, res) => {
  const { name = '게스트', provider = 'kakao', gender = '남성', region = '경기 용인', sport = 'tennis' } = req.body || {};
  const pid = 'dev-' + Buffer.from(name).toString('hex').slice(0, 12);
  let u = db.prepare('SELECT * FROM users WHERE provider_id=?').get(pid);
  if (!u) {
    const nick = anonNick(pid);
    const r = db.prepare(`INSERT INTO users (provider,provider_id,name,gender,region,sport,anon_nick,created_at)
      VALUES (?,?,?,?,?,?,?,?)`).run(provider, pid, name, gender, region, sport, nick, now());
    u = getUser(rid(r));
  }
  res.json({ token: sign(u), user: u });
});

// ── 카카오 로그인 (실연동) ──
// 준비: https://developers.kakao.com → 앱 생성 → JavaScript 키 발급 → 플랫폼에 도메인 등록
async function kakaoIssue(access_token, res) {
  const kr = await fetch('https://kapi.kakao.com/v2/user/me', { headers: { Authorization: 'Bearer ' + access_token } });
  if (!kr.ok) return res.status(401).json({ error: 'kakao_verify_failed' });
  const k = await kr.json();                         // { id, kakao_account, properties }
  const pid = 'kakao-' + k.id;
  const name = (k.properties && k.properties.nickname) || ('카카오' + String(k.id).slice(-4));
  let u = db.prepare('SELECT * FROM users WHERE provider_id=?').get(pid);
  if (!u) {
    const r = db.prepare(`INSERT INTO users (provider,provider_id,name,anon_nick,created_at) VALUES ('kakao',?,?,?,?)`)
      .run(pid, name, anonNick(pid), now());
    u = getUser(rid(r));
  }
  res.json({ token: sign(u), user: u });
}
// 클라이언트가 Kakao SDK로 받은 access_token을 보내는 방식 (SPA 권장)
app.post('/auth/kakao', async (req, res) => {
  const { access_token } = req.body || {};
  if (!access_token) return res.status(400).json({ error: 'no_access_token' });
  try { await kakaoIssue(access_token, res); } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});
// (대안) 인가코드 방식: 서버가 code→token 교환. env: KAKAO_REST_KEY, KAKAO_REDIRECT_URI (, KAKAO_CLIENT_SECRET)
app.post('/auth/kakao/code', async (req, res) => {
  const { code } = req.body || {};
  const key = process.env.KAKAO_REST_KEY, redirect = process.env.KAKAO_REDIRECT_URI;
  if (!code || !key || !redirect) return res.status(400).json({ error: 'missing_code_or_env' });
  try {
    const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: key, redirect_uri: redirect, code });
    if (process.env.KAKAO_CLIENT_SECRET) body.set('client_secret', process.env.KAKAO_CLIENT_SECRET);
    const tk = await fetch('https://kauth.kakao.com/oauth/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body
    }).then(r => r.json());
    if (!tk.access_token) return res.status(401).json({ error: 'token_exchange_failed', detail: tk });
    await kakaoIssue(tk.access_token, res);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// 데모 매칭용 사용자 목록
app.get('/users', (req, res) => {
  const q = '%' + (req.query.q || '') + '%';
  res.json(db.prepare('SELECT id,name,region,sport,rating FROM users WHERE name LIKE ? ORDER BY id DESC LIMIT 30').all(q));
});

// ── 애플 로그인 (Sign in with Apple, 실연동) ──
// 클라이언트(Apple JS SDK/네이티브)가 받은 identity token(id_token, RS256 JWT)을 보내면,
// 서버가 Apple 공개키(JWKS)로 서명·발급자·대상(aud)을 검증한 뒤 우리 JWT 발급.
// env: APPLE_CLIENT_ID (Services ID 또는 앱 번들ID)
let _appleKeys = { keys: [], ts: 0 };
async function appleKeys() {
  if (_appleKeys.keys.length && Date.now() - _appleKeys.ts < 3600e3) return _appleKeys.keys;
  const r = await fetch('https://appleid.apple.com/auth/keys').then(x => x.json());
  _appleKeys = { keys: r.keys, ts: Date.now() };
  return r.keys;
}
app.post('/auth/apple', async (req, res) => {
  const { id_token, name } = req.body || {};
  if (!id_token) return res.status(400).json({ error: 'no_id_token' });
  try {
    const hdr = JSON.parse(Buffer.from(id_token.split('.')[0], 'base64url').toString());
    const jwk = (await appleKeys()).find(k => k.kid === hdr.kid);
    if (!jwk) return res.status(401).json({ error: 'apple_key_not_found' });
    const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const claims = jwt.verify(id_token, pub, {
      algorithms: ['RS256'],
      issuer: 'https://appleid.apple.com',
      ...(process.env.APPLE_CLIENT_ID ? { audience: process.env.APPLE_CLIENT_ID } : {})
    });
    const pid = 'apple-' + claims.sub;
    const nm = name || ('애플' + String(claims.sub).slice(-4));
    let u = db.prepare('SELECT * FROM users WHERE provider_id=?').get(pid);
    if (!u) {
      const r = db.prepare(`INSERT INTO users (provider,provider_id,name,anon_nick,created_at) VALUES ('apple',?,?,?,?)`)
        .run(pid, nm, anonNick(pid), now());
      u = getUser(rid(r));
    }
    res.json({ token: sign(u), user: u });
  } catch (e) { res.status(401).json({ error: 'apple_verify_failed', detail: String(e.message || e) }); }
});

// ── 토스페이먼츠 결제 (M캐쉬 충전, 실연동) ──
// 흐름: (1) 서버가 주문 생성(orderId·금액·캐쉬 고정) → (2) 클라가 토스 위젯으로 결제
//       → (3) 성공 콜백의 {paymentKey,orderId,amount}로 서버가 토스에 최종 승인 → (4) 캐쉬 지급
// env: TOSS_SECRET_KEY (테스트키로 시작 가능)
const CASH_BY_WON = { 8900: 25, 13900: 45, 24900: 90, 49900: 200, 129000: 600, 229000: 1100 };
app.post('/pay/order', auth, (req, res) => {
  const amount = +req.body.amount;
  const cash = CASH_BY_WON[amount];
  if (!cash) return res.status(400).json({ error: 'invalid_amount', allowed: Object.keys(CASH_BY_WON) });
  const orderId = 'matsu_' + req.uid + '_' + Date.now();
  db.prepare('INSERT INTO orders (order_id,user_id,amount,cash,status,created_at) VALUES (?,?,?,?,?,?)')
    .run(orderId, req.uid, amount, cash, 'ready', now());
  res.json({ orderId, amount, cash, orderName: `M캐쉬 ${cash}` });
});
app.post('/pay/confirm', async (req, res) => {
  const { paymentKey, orderId, amount } = req.body || {};
  if (!paymentKey || !orderId || amount == null) return res.status(400).json({ error: 'missing_params' });
  const ord = db.prepare('SELECT * FROM orders WHERE order_id=?').get(orderId);
  if (!ord) return res.status(404).json({ error: 'order_not_found' });
  if (ord.status === 'paid') return res.json({ ok: true, already: true, cash: getUser(ord.user_id).cash });
  if (ord.amount !== +amount) return res.status(400).json({ error: 'amount_mismatch' }); // 위변조 방지
  const secret = process.env.TOSS_SECRET_KEY;
  if (!secret) return res.status(500).json({ error: 'toss_secret_not_set' });
  try {
    const r = await fetch('https://api.tosspayments.com/v1/payments/confirm', {
      method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(secret + ':').toString('base64'), 'Content-Type': 'application/json' },
      body: JSON.stringify({ paymentKey, orderId, amount: ord.amount })
    });
    const pay = await r.json();
    if (!r.ok) return res.status(402).json({ error: 'toss_confirm_failed', detail: pay });
    const u = getUser(ord.user_id); const bal = u.cash + ord.cash;
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
    db.prepare("UPDATE orders SET status='paid', payment_key=? WHERE order_id=?").run(paymentKey, orderId);
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
      .run(u.id, ord.cash, 'toss_purchase', bal, now());
    sendPush(u.id, { title: '충전 완료', body: `M캐쉬 ${ord.cash} 충전됐어요` });
    res.json({ ok: true, cash: bal, credited: ord.cash });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// 토스 웹훅: 결제 상태를 비동기로 통지받아 이중 확인(멱등 처리). 토스 콘솔에 이 URL 등록.
app.post('/pay/webhook', (req, res) => {
  try {
    const ev = req.body || {};
    const data = ev.data || ev;
    const orderId = data.orderId; const status = data.status || ev.eventType;
    if (orderId && (status === 'DONE' || status === 'PAYMENT_STATUS_CHANGED')) {
      const ord = db.prepare('SELECT * FROM orders WHERE order_id=?').get(orderId);
      if (ord && ord.status !== 'paid') {
        const u = getUser(ord.user_id); const bal = u.cash + ord.cash;
        db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
        db.prepare("UPDATE orders SET status='paid' WHERE order_id=?").run(orderId);
        db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
          .run(u.id, ord.cash, 'toss_webhook', bal, now());
        sendPush(u.id, { title: '충전 완료', body: `M캐쉬 ${ord.cash} 충전됐어요` });
      }
    }
    res.json({ ok: true });               // 웹훅은 항상 200으로 응답
  } catch { res.json({ ok: true }); }
});

// 환불: 토스 결제 취소 API 호출 후 캐쉬 회수
app.post('/pay/refund', auth, async (req, res) => {
  const { orderId, reason } = req.body || {};
  const secret = process.env.TOSS_SECRET_KEY;
  const ord = db.prepare('SELECT * FROM orders WHERE order_id=? AND user_id=?').get(orderId, req.uid);
  if (!ord) return res.status(404).json({ error: 'order_not_found' });
  if (ord.status !== 'paid') return res.status(400).json({ error: 'not_paid' });
  if (!secret) return res.status(500).json({ error: 'toss_secret_not_set' });
  try {
    const r = await fetch(`https://api.tosspayments.com/v1/payments/${ord.payment_key}/cancel`, {
      method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(secret + ':').toString('base64'), 'Content-Type': 'application/json' },
      body: JSON.stringify({ cancelReason: reason || '고객 요청' })
    });
    const j = await r.json();
    if (!r.ok) return res.status(402).json({ error: 'toss_cancel_failed', detail: j });
    const u = getUser(ord.user_id); const bal = Math.max(0, u.cash - ord.cash);
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
    db.prepare("UPDATE orders SET status='refunded' WHERE order_id=?").run(orderId);
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
      .run(u.id, -ord.cash, 'refund', bal, now());
    res.json({ ok: true, cash: bal, refunded: ord.cash });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/me', auth, (req, res) => res.json(getUser(req.uid)));
app.patch('/me', auth, (req, res) => {
  const allow = ['gender','region','sport','exp','photos','phone_verified','real_verified','skill_verified'];
  const sets = [], vals = [];
  for (const k of allow) if (k in req.body) { sets.push(`${k}=?`); vals.push(typeof req.body[k]==='object'?JSON.stringify(req.body[k]):req.body[k]); }
  if (sets.length) { db.prepare(`UPDATE users SET ${sets.join(',')} WHERE id=?`).run(...vals, req.uid); }
  res.json(getUser(req.uid));
});

// ── CLUBS ──
app.get('/clubs', (req, res) => {
  const { sport, region, q } = req.query;
  let sql = 'SELECT * FROM clubs WHERE 1=1', p = [];
  if (sport) { sql += ' AND sport=?'; p.push(sport); }
  if (region) { sql += ' AND region LIKE ?'; p.push('%' + region + '%'); }
  if (q) { sql += ' AND name LIKE ?'; p.push('%' + q + '%'); }
  res.json(db.prepare(sql + ' ORDER BY created_at DESC LIMIT 100').all(...p));
});
app.post('/clubs', auth, (req, res) => {
  const { name, sport, region } = req.body;
  if (!name || !sport) return res.status(400).json({ error: 'name_sport_required' });
  const r = db.prepare(`INSERT INTO clubs (name,sport,region,owner_id,created_at) VALUES (?,?,?,?,?)`)
    .run(name, sport, region || '', req.uid, now());
  db.prepare(`INSERT INTO club_members (club_id,user_id,role,is_captain) VALUES (?,?,?,1)`)
    .run(rid(r), req.uid, 'owner');
  res.json(db.prepare('SELECT * FROM clubs WHERE id=?').get(rid(r)));
});
app.post('/clubs/:id/join', auth, (req, res) => {
  const cid = +req.params.id;
  const club = db.prepare('SELECT name,owner_id FROM clubs WHERE id=?').get(cid);
  if (!club) return res.status(404).json({ error: 'no_club' });
  const ex = db.prepare('SELECT status FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (ex) return res.json({ ok: true, status: ex.status });          // 이미 신청/가입됨
  db.prepare(`INSERT INTO club_members (club_id,user_id,role,status) VALUES (?,?, 'member','pending')`).run(cid, req.uid);
  const me = getUser(req.uid);
  // 클럽장·임원에게 알림
  db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND role IN ('owner','officer')").all(cid)
    .forEach(r => sendPush(r.user_id, { icon: '👤', title: '가입 신청', body: `${me.name} 님이 ${club.name} 가입을 신청했어요` }));
  res.json({ ok: true, status: 'pending' });
});
app.get('/clubs/:id/members', (req, res) => {
  res.json(db.prepare(`SELECT cm.id, cm.club_id, cm.user_id, cm.role, cm.jersey_no, cm.is_captain, cm.status, cm.grade,
    u.name, u.gender, u.rating FROM club_members cm
    JOIN users u ON u.id=cm.user_id WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
    ORDER BY (cm.role='owner') DESC, (cm.role='officer') DESC, u.name`).all(+req.params.id));
});

// 회원 등급 일괄 설정 (임원진) — { grades: { "12": "A", "34": "B" } }  키는 user_id
app.patch('/clubs/:id/grades', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const g = (req.body && req.body.grades) || {};
  const st = db.prepare('UPDATE club_members SET grade=? WHERE club_id=? AND user_id=?');
  Object.entries(g).forEach(([uid, v]) => {
    const gv = ['A', 'B', 'C'].includes(String(v)) ? String(v) : null;
    st.run(gv, cid, intOrNull(uid));
  });
  res.json({ ok: true, n: Object.keys(g).length });
});

// 역할 변경 (owner 만) — member ↔ officer
app.patch('/clubs/:id/members/:uid/role', auth, (req, res) => {
  const cid = +req.params.id;
  const owner = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, req.uid);
  if (!owner) return res.status(403).json({ error: 'owner_only' });
  const uid = intOrNull(req.params.uid);
  const target = db.prepare('SELECT role,status FROM club_members WHERE club_id=? AND user_id=?').get(cid, uid);
  if (!target) return res.status(404).json({ error: 'not_member' });
  if (target.role === 'owner') return res.status(400).json({ error: 'cannot_change_owner' });   // 클럽장은 강등 불가
  if (target.status && target.status !== 'active') return res.status(400).json({ error: 'not_active' }); // 승인 대기중은 불가
  const role = ['member', 'officer'].includes(req.body && req.body.role) ? req.body.role : 'member';
  db.prepare('UPDATE club_members SET role=? WHERE club_id=? AND user_id=?').run(role, cid, uid);
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  sendPush(uid, role === 'officer'
    ? { icon: '👑', title: '임원으로 임명됐어요', body: `${club.name} 대진 편성·모임 개설을 할 수 있어요` }
    : { icon: '🔔', title: '임원 권한이 해제됐어요', body: `${club.name} 일반 회원으로 변경됐어요` });
  res.json({ ok: true, role });
});

// 이번 모임 참석자 (대진 편성 대상). 일정이 있으면 그 참석자, 없으면 활성 회원 전원.
app.get('/clubs/:id/roster', (req, res) => {
  const cid = +req.params.id;
  const ev = db.prepare('SELECT id FROM club_events WHERE club_id=? ORDER BY id DESC LIMIT 1').get(cid);
  let rows;
  let guests = [];
  if (ev) {
    rows = db.prepare(`SELECT u.id user_id, u.name, u.gender, cm.grade, cm.is_captain
      FROM event_attendees ea JOIN users u ON u.id=ea.user_id
      LEFT JOIN club_members cm ON cm.club_id=? AND cm.user_id=u.id
      WHERE ea.event_id=? AND (ea.status IS NULL OR ea.status='going') ORDER BY u.name`).all(cid, ev.id);
    guests = db.prepare('SELECT id,name,gender,grade FROM event_guests WHERE event_id=? ORDER BY id').all(ev.id)
      .map(g => ({ user_id: null, name: g.name, gender: g.gender, grade: g.grade, is_guest: 1, guest_id: g.id }));
  }
  if (!rows || !rows.length) {
    rows = db.prepare(`SELECT u.id user_id, u.name, u.gender, cm.grade, cm.is_captain
      FROM club_members cm JOIN users u ON u.id=cm.user_id
      WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active') ORDER BY u.name`).all(cid);
  }
  res.json({ event_id: ev ? ev.id : null, members: [...rows, ...guests] });
});
// 가입 신청 목록 (임원진)
app.get('/clubs/:id/join-requests', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  res.json(db.prepare(`SELECT u.id user_id, u.name, u.gender, u.region, u.rating
    FROM club_members cm JOIN users u ON u.id=cm.user_id
    WHERE cm.club_id=? AND cm.status='pending' ORDER BY cm.id`).all(cid));
});
// 승인 / 거절 (임원진)
app.post('/clubs/:id/members/:uid/approve', auth, (req, res) => {
  const cid = +req.params.id, uid = intOrNull(req.params.uid);
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const ok = req.body && req.body.approve === false ? false : true;
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  if (ok) {
    db.prepare("UPDATE club_members SET status='active' WHERE club_id=? AND user_id=? AND status='pending'").run(cid, uid);
    sendPush(uid, { icon: '🎉', title: '가입 승인', body: `${club.name} 정회원이 됐어요` });
  } else {
    db.prepare("DELETE FROM club_members WHERE club_id=? AND user_id=? AND status='pending'").run(cid, uid);
    sendPush(uid, { icon: '🔔', title: '가입 신청 결과', body: `${club.name} 가입이 승인되지 않았어요` });
  }
  res.json({ ok: true, approved: ok });
});
// 클럽장 양도 (현 클럽장만). 넘겨주면 본인은 임원이 된다.
app.post('/clubs/:id/transfer-owner', auth, (req, res) => {
  const cid = +req.params.id, uid = intOrNull(req.body && req.body.user_id);
  const mine = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, req.uid);
  if (!mine) return res.status(403).json({ error: 'owner_only' });
  if (!uid || uid === req.uid) return res.status(400).json({ error: 'bad_target' });
  const t = db.prepare('SELECT status FROM club_members WHERE club_id=? AND user_id=?').get(cid, uid);
  if (!t) return res.status(404).json({ error: 'not_member' });
  if (t.status && t.status !== 'active') return res.status(400).json({ error: 'not_active' });
  db.prepare("UPDATE club_members SET role='owner' WHERE club_id=? AND user_id=?").run(cid, uid);
  db.prepare("UPDATE club_members SET role='officer' WHERE club_id=? AND user_id=?").run(cid, req.uid);
  db.prepare('UPDATE clubs SET owner_id=? WHERE id=?').run(uid, cid);
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  sendPush(uid, { icon: '👑', title: '클럽장이 됐어요', body: `${club.name} 클럽장 권한을 넘겨받았어요` });
  res.json({ ok: true });
});

// 내가 속한 클럽 목록 (역할·상태 포함)
app.get('/me/clubs', auth, (req, res) => {
  res.json(db.prepare(`SELECT c.*, cm.role, cm.status,
      (SELECT COUNT(*) FROM club_members x WHERE x.club_id=c.id AND (x.status IS NULL OR x.status='active')) member_count
    FROM club_members cm JOIN clubs c ON c.id=cm.club_id
    WHERE cm.user_id=? ORDER BY (cm.role='owner') DESC, c.id`).all(req.uid));
});

// 내 가입 상태
app.get('/clubs/:id/my-status', auth, (req, res) => {
  const m = db.prepare('SELECT role,status FROM club_members WHERE club_id=? AND user_id=?').get(+req.params.id, req.uid);
  res.json(m || { role: null, status: null });
});

// ── 클럽 일정(모임) ──
app.get('/clubs/:id/events', (req, res) => {
  const cid = +req.params.id; const uid = tryUid(req);
  const evs = db.prepare('SELECT * FROM club_events WHERE club_id=? ORDER BY id DESC LIMIT 20').all(cid);
  const byStatus = (eid, st) => db.prepare(`SELECT u.name FROM event_attendees ea JOIN users u ON u.id=ea.user_id
    WHERE ea.event_id=? AND ${st === 'going' ? "(ea.status IS NULL OR ea.status='going')" : 'ea.status=?'} ORDER BY u.name`)
    .all(...(st === 'going' ? [eid] : [eid, st])).map(r => r.name);
  res.json(evs.map(e => {
    const my = uid ? db.prepare('SELECT status FROM event_attendees WHERE event_id=? AND user_id=?').get(e.id, uid) : null;
    return {
      ...e,
      count: goingCount(e.id),
      attendees: byStatus(e.id, 'going'),
      absent: byStatus(e.id, 'absent'),
      undecided: byStatus(e.id, 'undecided'),
      guests: db.prepare('SELECT id,name,gender,grade FROM event_guests WHERE event_id=? ORDER BY id').all(e.id),
      my_status: my ? (my.status || 'going') : null,
      joined: !!(my && (my.status === null || my.status === 'going')),
    };
  }));
});
app.post('/clubs/:id/events', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const { title, date, tag } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title_required' });
  const r = db.prepare('INSERT INTO club_events (club_id,title,date,tag,created_by,created_at) VALUES (?,?,?,?,?,?)')
    .run(cid, String(title), String(date || ''), String(tag || '정기'), req.uid, now());
  notifyClub(cid, req.uid, '📅', '새 모임이 열렸어요', `${title}${date ? ' · ' + date : ''}`);
  res.json({ ok: true, id: rid(r) });
});
function eventGuard(eid, uid) {
  const ev = db.prepare('SELECT club_id FROM club_events WHERE id=?').get(eid);
  if (!ev) return { err: 404, msg: 'no_event' };
  const m = db.prepare('SELECT status FROM club_members WHERE club_id=? AND user_id=?').get(ev.club_id, uid);
  if (!m || (m.status && m.status !== 'active')) return { err: 403, msg: 'member_only' };
  return { ev };
}
const goingCount = (eid) => db.prepare("SELECT COUNT(*) n FROM event_attendees WHERE event_id=? AND (status IS NULL OR status='going')").get(eid).n;

// 참석 응답 — going | absent | undecided
app.post('/events/:id/rsvp', auth, (req, res) => {
  const eid = +req.params.id;
  const g = eventGuard(eid, req.uid);
  if (g.err) return res.status(g.err).json({ error: g.msg });
  const st = ['going', 'absent', 'undecided'].includes(req.body && req.body.status) ? req.body.status : 'going';
  const has = db.prepare('SELECT id FROM event_attendees WHERE event_id=? AND user_id=?').get(eid, req.uid);
  if (has) db.prepare('UPDATE event_attendees SET status=? WHERE id=?').run(st, has.id);
  else db.prepare('INSERT INTO event_attendees (event_id,user_id,status) VALUES (?,?,?)').run(eid, req.uid, st);
  res.json({ ok: true, status: st, count: goingCount(eid) });
});
// (구버전 호환) 토글 → going ↔ absent
app.post('/events/:id/attend', auth, (req, res) => {
  const eid = +req.params.id;
  const g = eventGuard(eid, req.uid);
  if (g.err) return res.status(g.err).json({ error: g.msg });
  const has = db.prepare('SELECT id,status FROM event_attendees WHERE event_id=? AND user_id=?').get(eid, req.uid);
  const going = !(has && (has.status === null || has.status === 'going'));
  const st = going ? 'going' : 'absent';
  if (has) db.prepare('UPDATE event_attendees SET status=? WHERE id=?').run(st, has.id);
  else db.prepare('INSERT INTO event_attendees (event_id,user_id,status) VALUES (?,?,?)').run(eid, req.uid, st);
  res.json({ ok: true, joined: going, count: goingCount(eid) });
});

// ── 게스트 (비회원) ──
app.get('/events/:id/guests', (req, res) => {
  res.json(db.prepare('SELECT id,name,gender,grade FROM event_guests WHERE event_id=? ORDER BY id').all(+req.params.id));
});
app.post('/events/:id/guests', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = db.prepare('SELECT club_id FROM club_events WHERE id=?').get(eid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  if (!isOfficer(ev.club_id, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const name = String((req.body && req.body.name) || '').trim().slice(0, 12);
  if (!name) return res.status(400).json({ error: 'name_required' });
  const gender = ['M', 'F'].includes(req.body.gender) ? req.body.gender : null;
  const grade = ['A', 'B', 'C'].includes(req.body.grade) ? req.body.grade : null;
  const dup = db.prepare('SELECT 1 FROM event_guests WHERE event_id=? AND name=?').get(eid, name);
  if (dup) return res.status(409).json({ error: 'duplicate_name' });
  const r = db.prepare('INSERT INTO event_guests (event_id,name,gender,grade,added_by,created_at) VALUES (?,?,?,?,?,?)')
    .run(eid, name, gender, grade, req.uid, now());
  res.json({ ok: true, id: rid(r) });
});
app.delete('/events/:id/guests/:gid', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = db.prepare('SELECT club_id FROM club_events WHERE id=?').get(eid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  if (!isOfficer(ev.club_id, req.uid)) return res.status(403).json({ error: 'officer_only' });
  db.prepare('DELETE FROM event_guests WHERE id=? AND event_id=?').run(intOrNull(req.params.gid), eid);
  res.json({ ok: true });
});
// ── 오픈 예정 경기(모집) ──
app.get('/open-matches', (req, res) => {
  const uid = tryUid(req);
  const rows = db.prepare('SELECT * FROM open_matches ORDER BY id ASC LIMIT 30').all();
  res.json(rows.map(m => ({
    ...m,
    cur: db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(m.id).n,
    joined: uid ? !!db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(m.id, uid) : false,
  })));
});
app.post('/open-matches', auth, (req, res) => {
  const { sport, dt, loc, fmt, gd, price, cap, min_cnt } = req.body || {};
  const r = db.prepare('INSERT INTO open_matches (sport,dt,loc,fmt,gd,price,cap,min_cnt,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(sport || 'tennis', dt || '', loc || '', fmt || '단식', gd || '남자부', +price || 0, +cap || 8, +min_cnt || 6, now());
  res.json({ ok: true, id: rid(r) });
});
app.post('/open-matches/:id/join', auth, (req, res) => {
  const mid = +req.params.id;
  db.prepare('INSERT OR IGNORE INTO open_match_joins (match_id,user_id) VALUES (?,?)').run(mid, req.uid);
  res.json({ ok: true, cur: db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n });
});
// 회비/게스트비 수정 (클럽장/임원만)
app.patch('/clubs/:id/fees', auth, (req, res) => {
  const c = db.prepare('SELECT * FROM clubs WHERE id=?').get(+req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(c.id, req.uid);
  if (!m || !['owner','officer'].includes(m.role)) return res.status(403).json({ error: 'officer_only' });
  const { entry_fee, season_fee, guest_fee, guest_cap } = req.body;
  db.prepare(`UPDATE clubs SET entry_fee=COALESCE(?,entry_fee), season_fee=COALESCE(?,season_fee),
    guest_fee=COALESCE(?,guest_fee), guest_cap=COALESCE(?,guest_cap) WHERE id=?`)
    .run(entry_fee, season_fee, guest_fee, guest_cap, c.id);
  res.json(db.prepare('SELECT * FROM clubs WHERE id=?').get(c.id));
});
// 등번호/주장
app.patch('/clubs/:id/roster', auth, (req, res) => {
  const { user_id, jersey_no, is_captain } = req.body;
  if (is_captain) db.prepare('UPDATE club_members SET is_captain=0 WHERE club_id=?').run(+req.params.id);
  db.prepare('UPDATE club_members SET jersey_no=COALESCE(?,jersey_no), is_captain=COALESCE(?,is_captain) WHERE club_id=? AND user_id=?')
    .run(jersey_no, is_captain ? 1 : null, +req.params.id, user_id);
  res.json({ ok: true });
});

// ── MATCHES (개인 1:1 · 팀 대전) ──
app.post('/matches', auth, (req, res) => {
  const { sport, kind, home_club_id, away_club_id, home_user_id, away_user_id, venue, scheduled_at } = req.body;
  const deadline = scheduled_at ? scheduled_at + 3 * 864e5 : null; // 스코어 입력 3일 마감
  const r = db.prepare(`INSERT INTO matches (sport,kind,home_club_id,away_club_id,home_user_id,away_user_id,venue,scheduled_at,score_deadline,status,created_by,created_at)
    VALUES (?,?,?,?,?,?,?,?,?, 'requested',?,?)`)
    .run(sport, kind, home_club_id, away_club_id, home_user_id || req.uid, away_user_id, venue, scheduled_at, deadline, req.uid, now());
  res.json(db.prepare('SELECT * FROM matches WHERE id=?').get(rid(r)));
});
app.post('/matches/:id/accept', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM matches WHERE id=?').get(+req.params.id);
  db.prepare("UPDATE matches SET status='scheduled' WHERE id=?").run(+req.params.id);
  if (m && m.created_by) sendPush(m.created_by, { icon: '✅', title: '대전 성사', body: '상대가 대전을 수락했어요' });
  res.json({ ok: true });
});
app.post('/matches/:id/decline', auth, (req, res) => {
  db.prepare("UPDATE matches SET status='declined' WHERE id=?").run(+req.params.id);
  res.json({ ok: true });
});
// 결과 입력 + 상호 확정
app.post('/matches/:id/result', auth, (req, res) => {
  const { home_score, away_score, side } = req.body; // side: 'home' | 'away'
  const m = db.prepare('SELECT * FROM matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const col = side === 'away' ? 'away_confirmed' : 'home_confirmed';
  db.prepare(`UPDATE matches SET home_score=?, away_score=?, ${col}=1, status='played' WHERE id=?`)
    .run(home_score, away_score, m.id);
  const m2 = db.prepare('SELECT * FROM matches WHERE id=?').get(m.id);
  if (m2.home_confirmed && m2.away_confirmed) {
    db.prepare("UPDATE matches SET status='confirmed' WHERE id=?").run(m.id);
    applyRating(m2); // 확정 시 레이팅 반영
  }
  res.json(db.prepare('SELECT * FROM matches WHERE id=?').get(m.id));
});
// 선수 기록(골/어시/홈런 등)
app.post('/matches/:id/stats', auth, (req, res) => {
  const items = req.body.stats || []; // [{user_id, stat, value}]
  const ins = db.prepare('INSERT INTO match_stats (match_id,user_id,stat,value) VALUES (?,?,?,?)');
  items.forEach(s => ins.run(+req.params.id, s.user_id, s.stat, s.value));
  res.json({ ok: true, saved: items.length });
});
// 간단 Elo
function applyRating(m) {
  if (!m.home_user_id || !m.away_user_id) return;
  const a = getUser(m.home_user_id), b = getUser(m.away_user_id);
  if (!a || !b) return;
  const ea = 1 / (1 + 10 ** ((b.rating - a.rating) / 400));
  const sa = m.home_score > m.away_score ? 1 : 0, K = 28;
  const da = Math.round(K * (sa - ea));
  db.prepare('UPDATE users SET rating=rating+? WHERE id=?').run(da, a.id);
  db.prepare('UPDATE users SET rating=rating-? WHERE id=?').run(da, b.id);
}

// ── RECORDS (수영/러닝) ──
app.post('/records', auth, (req, res) => {
  const { sport, event, value } = req.body;
  const r = db.prepare('INSERT INTO records (user_id,sport,event,value,recorded_at) VALUES (?,?,?,?,?)')
    .run(req.uid, sport, event, value, now());
  res.json(db.prepare('SELECT * FROM records WHERE id=?').get(rid(r)));
});
app.get('/records/leaderboard', (req, res) => {
  const { sport, event } = req.query;
  res.json(db.prepare(`SELECT r.user_id, u.name, MIN(r.value) best FROM records r JOIN users u ON u.id=r.user_id
    WHERE r.sport=? AND (?='' OR r.event=?) GROUP BY r.user_id ORDER BY best ASC LIMIT 100`)
    .all(sport, event || '', event || ''));
});

// ── LOUNGE (익명 커뮤니티) + 모더레이션 ──
app.get('/posts', (req, res) => {
  const { category, sport, q } = req.query;
  let sql = 'SELECT *, (SELECT COUNT(*) FROM comments WHERE post_id=posts.id AND hidden=0) AS comments FROM posts WHERE hidden=0', p = [];
  if (category && category !== '전체') { sql += ' AND category=?'; p.push(category); }
  if (sport) { sql += ' AND sport=?'; p.push(sport); }
  if (q) { sql += ' AND (title LIKE ? OR body LIKE ?)'; p.push('%'+q+'%','%'+q+'%'); }
  res.json(db.prepare(sql + ' ORDER BY created_at DESC LIMIT 100').all(...p));
});
// 댓글
app.get('/posts/:id/comments', (req, res) => {
  res.json(db.prepare(`SELECT c.id, c.body, c.created_at, COALESCE(c.anon_nick,u.anon_nick) AS anon_nick, u.gender
    FROM comments c LEFT JOIN users u ON u.id=c.user_id
    WHERE c.post_id=? AND c.hidden=0 ORDER BY c.id`).all(+req.params.id));
});
app.post('/posts/:id/comments', auth, (req, res) => {
  const body = (req.body && req.body.body || '').trim();
  if (!body) return res.status(400).json({ error: 'empty' });
  const u = getUser(req.uid);
  const r = db.prepare('INSERT INTO comments (post_id,user_id,anon_nick,body,created_at) VALUES (?,?,?,?,?)')
    .run(+req.params.id, req.uid, u.anon_nick, body, now());
  res.json({ ok: true, id: rid(r) });
});
app.post('/posts', auth, (req, res) => {
  const u = getUser(req.uid);
  const { title, body, category = '자유', sport } = req.body;
  if (!title) return res.status(400).json({ error: 'title_required' });
  const r = db.prepare(`INSERT INTO posts (user_id,sport,category,title,body,anon_nick,gender,region,created_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(req.uid, sport || u.sport, category, title, body || '', u.anon_nick, u.gender, u.region, now());
  res.json(db.prepare('SELECT * FROM posts WHERE id=?').get(rid(r)));
});
app.post('/posts/:id/like', auth, (req, res) => {
  db.prepare('UPDATE posts SET likes=likes+1 WHERE id=?').run(+req.params.id);
  res.json({ ok: true });
});
app.post('/report', auth, (req, res) => {
  const { target_type, target_id, reason } = req.body;
  db.prepare('INSERT INTO reports (reporter_id,target_type,target_id,reason,created_at) VALUES (?,?,?,?,?)')
    .run(req.uid, target_type, target_id, reason, now());
  // 자동 임시 숨김(누적 신고 3회) 예시
  if (target_type === 'post') {
    const cnt = db.prepare("SELECT COUNT(*) n FROM reports WHERE target_type='post' AND target_id=?").get(target_id).n;
    if (cnt >= 3) db.prepare('UPDATE posts SET hidden=1 WHERE id=?').run(target_id);
  }
  res.json({ ok: true });
});
app.post('/block', auth, (req, res) => {
  db.prepare('INSERT OR IGNORE INTO blocks (user_id,blocked_user_id) VALUES (?,?)').run(req.uid, req.body.user_id);
  res.json({ ok: true });
});

// ── M캐쉬 지갑 ──
app.post('/cash/spend', auth, (req, res) => {
  const { amount, reason } = req.body;
  const u = getUser(req.uid);
  if (u.cash < amount) return res.status(402).json({ error: 'insufficient', cash: u.cash });
  const bal = u.cash - amount;
  db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
  db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
    .run(u.id, -amount, reason, bal, now());
  res.json({ cash: bal });
});
// 실제 충전은 PG 결제 성공 콜백(웹훅)에서만 호출하세요. 아래는 데모용.
app.post('/cash/purchase', auth, (req, res) => {
  const { amount } = req.body; const u = getUser(req.uid); const bal = u.cash + amount;
  db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
  db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
    .run(u.id, amount, 'purchase', bal, now());
  res.json({ cash: bal });
});

// ── 통합 검색 ──
app.get('/search', (req, res) => {
  const q = '%' + (req.query.q || '') + '%';
  res.json({
    clubs: db.prepare('SELECT id,name,sport,region FROM clubs WHERE name LIKE ? LIMIT 20').all(q),
    users: db.prepare('SELECT id,name,region,sport FROM users WHERE name LIKE ? LIMIT 20').all(q),
    posts: db.prepare('SELECT id,title,category,sport FROM posts WHERE hidden=0 AND (title LIKE ? OR body LIKE ?) LIMIT 20').all(q, q),
  });
});

// ── 푸시 알림 (FCM) ──
// 디바이스 토큰 저장 + 전송 헬퍼. env FCM_SERVER_KEY 있으면 실제 전송, 없으면 로그만.
// (실서비스는 FCM HTTP v1 + 서비스계정 권장. 여기선 스타터로 legacy 방식.)
app.post('/push/register', auth, (req, res) => {
  const { token, platform } = req.body || {};
  if (!token) return res.status(400).json({ error: 'no_token' });
  db.prepare('INSERT OR IGNORE INTO devices (user_id,token,platform,created_at) VALUES (?,?,?,?)')
    .run(req.uid, token, platform || 'web', now());
  res.json({ ok: true });
});
async function sendPush(userId, msg) {
  const rows = db.prepare('SELECT token FROM devices WHERE user_id=?').all(userId);
  db.prepare('INSERT INTO notifications (user_id,icon,title,sub,created_at) VALUES (?,?,?,?,?)')
    .run(userId, msg.icon || '🔔', msg.title || '', msg.body || '', now());
  if (!rows.length) return;
  const key = process.env.FCM_SERVER_KEY;
  if (!key) { console.log('[push:mock]', userId, msg.title, '→', rows.length, 'devices'); return; }
  try {
    for (const { token } of rows) {
      await fetch('https://fcm.googleapis.com/fcm/send', {
        method: 'POST',
        headers: { Authorization: 'key=' + key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: token, notification: { title: msg.title, body: msg.body } })
      });
    }
  } catch (e) { console.error('push error', e.message); }
}
app.get('/notifications', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(req.uid));
});

// ── 라이브 스코어 (실시간, SSE) ──
const liveSubs = new Map(); // matchId -> Set(res)
app.get('/matches/:id/live', (req, res) => {
  const id = +req.params.id;
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders && res.flushHeaders();
  res.write(': connected\n\n');
  // 기존 이벤트 재생
  const past = db.prepare('SELECT * FROM match_events WHERE match_id=? ORDER BY id').all(id);
  past.forEach(e => res.write(`data: ${JSON.stringify(e)}\n\n`));
  if (!liveSubs.has(id)) liveSubs.set(id, new Set());
  liveSubs.get(id).add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(ping); liveSubs.get(id)?.delete(res); });
});
app.post('/matches/:id/event', auth, (req, res) => {
  const id = +req.params.id; const { minute, icon, text } = req.body || {};
  const r = db.prepare('INSERT INTO match_events (match_id,minute,icon,text,created_at) VALUES (?,?,?,?,?)')
    .run(id, minute || '', icon || '⚽', text || '', now());
  const ev = db.prepare('SELECT * FROM match_events WHERE id=?').get(rid(r));
  (liveSubs.get(id) || []).forEach(sub => sub.write(`data: ${JSON.stringify(ev)}\n\n`));
  res.json({ ok: true, event: ev });
});
// REST 조회(폴링용 — React Native 등 EventSource 미지원 클라이언트)
app.get('/matches/:id/events', (req, res) => {
  const since = +req.query.since || 0;
  res.json(db.prepare('SELECT * FROM match_events WHERE match_id=? AND id>? ORDER BY id').all(+req.params.id, since));
});
// 경기 목록 (대진 화면)
app.get('/matches', (req, res) => {
  res.json(db.prepare(`SELECT m.*, hu.name home_name, au.name away_name
    FROM matches m LEFT JOIN users hu ON hu.id=m.home_user_id LEFT JOIN users au ON au.id=m.away_user_id
    ORDER BY m.id DESC LIMIT 40`).all());
});
// 개인 레이팅 랭킹 (리그 화면)
app.get('/rankings', (req, res) => {
  const { sport } = req.query;
  let sql = 'SELECT id,name,region,sport,rating FROM users', p = [];
  if (sport) { sql += ' WHERE sport=?'; p.push(sport); }
  res.json(db.prepare(sql + ' ORDER BY rating DESC LIMIT 50').all(...p));
});
// 대진 결과 → 내 레이팅 Elo 반영 (봇 상대 포함)
app.post('/me/result', auth, (req, res) => {
  const { won, opp_rating } = req.body || {};
  const u = getUser(req.uid);
  const Ro = +opp_rating || u.rating;
  const ea = 1 / (1 + Math.pow(10, (Ro - u.rating) / 400));
  const delta = Math.round(28 * ((won ? 1 : 0) - ea));
  const nr = u.rating + delta;
  db.prepare('UPDATE users SET rating=?, mmr=mmr+? WHERE id=?').run(nr, won ? 12 : -8, u.id);
  sendPush(u.id, { icon: '🎾', title: won ? '경기 승리' : '경기 패배', body: `레이팅 ${delta >= 0 ? '+' : ''}${delta} → ${nr}` });
  res.json({ ok: true, rating: nr, delta });
});

// ── 토스 결제 웹뷰용 페이지 (RN WebView가 로드) ──
app.get('/pay/checkout', (req, res) => {
  const { clientKey, amount, orderId, orderName } = req.query;
  const base = `${req.protocol}://${req.get('host')}`;
  res.set('Content-Type', 'text/html; charset=utf-8').send(`<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://js.tosspayments.com/v1/payment"></script></head>
<body style="font-family:sans-serif;padding:24px;color:#333">
<p>결제창을 여는 중…</p>
<script>
  try {
    var toss = TossPayments(${JSON.stringify(clientKey || '')});
    toss.requestPayment('카드', {
      amount: ${Number(amount) || 0},
      orderId: ${JSON.stringify(orderId || '')},
      orderName: ${JSON.stringify(orderName || 'M캐쉬')},
      successUrl: ${JSON.stringify(base + '/pay/done')},
      failUrl: ${JSON.stringify(base + '/pay/done?fail=1')}
    }).catch(function(e){ document.body.innerHTML = '<p>결제 취소/실패: ' + (e && e.message) + '</p>'; });
  } catch(e){ document.body.innerHTML = '<p>clientKey를 확인하세요.</p>'; }
</script></body></html>`);
});
app.get('/pay/done', (_req, res) => {
  res.set('Content-Type', 'text/html; charset=utf-8')
    .send('<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;padding:24px"><b>결제 처리 완료</b><p>앱으로 돌아갑니다…</p></body>');
});

// ── 인앱결제(IAP) 영수증 검증 → M캐쉬 지급 ──
// 앱스토어/플레이스토어의 "디지털 재화"는 IAP로 팔아야 정책 위반이 없어요. (아래는 그 서버 검증부)
const IAP_CASH = { matsu_cash_25:25, matsu_cash_45:45, matsu_cash_90:90, matsu_cash_200:200, matsu_cash_600:600, matsu_cash_1100:1100 };
const PREMIUM_DAYS = { matsu_premium_monthly: 30, matsu_premium_yearly: 365 };
function grantPremium(userId, product) {
  const days = PREMIUM_DAYS[product] || 30;
  const until = now() + days * 864e5;
  db.prepare('UPDATE users SET premium=1, premium_until=? WHERE id=?').run(until, userId);
  return until;
}
// 애플: verifyReceipt (prod→sandbox 폴백). env APPLE_IAP_SHARED_SECRET
app.post('/iap/apple', auth, async (req, res) => {
  const { receipt } = req.body || {};
  if (!receipt) return res.status(400).json({ error: 'no_receipt' });
  const secret = process.env.APPLE_IAP_SHARED_SECRET;
  if (!secret) return res.status(500).json({ error: 'apple_iap_secret_not_set' });
  try {
    const body = JSON.stringify({ 'receipt-data': receipt, password: secret, 'exclude-old-transactions': true });
    let j = await fetch('https://buy.itunes.apple.com/verifyReceipt', { method: 'POST', body }).then(r => r.json());
    if (j.status === 21007) j = await fetch('https://sandbox.itunes.apple.com/verifyReceipt', { method: 'POST', body }).then(r => r.json());
    if (j.status !== 0) return res.status(402).json({ error: 'apple_verify_failed', status: j.status });
    const items = (j.receipt && j.receipt.in_app) || [];
    const last = items[items.length - 1] || {};
    const product = last.product_id;
    const txn = last.transaction_id || last.original_transaction_id;
    const dup = db.prepare('SELECT id FROM iap_receipts WHERE txn_id=?').get(txn);
    if (dup) return res.json({ ok: true, already: true, cash: getUser(req.uid).cash });
    // 프리미엄 구독 상품이면 프리미엄 활성화
    if (PREMIUM_DAYS[product]) {
      const until = grantPremium(req.uid, product);
      db.prepare('INSERT INTO iap_receipts (txn_id,user_id,store,product,cash,created_at) VALUES (?,?,?,?,?,?)').run(txn, req.uid, 'apple', product, 0, now());
      return res.json({ ok: true, premium: true, premium_until: until });
    }
    const cash = IAP_CASH[product];
    if (!cash) return res.status(400).json({ error: 'unknown_product', product });
    const u = getUser(req.uid); const bal = u.cash + cash;
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
    db.prepare('INSERT INTO iap_receipts (txn_id,user_id,store,product,cash,created_at) VALUES (?,?,?,?,?,?)').run(txn, u.id, 'apple', product, cash, now());
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)').run(u.id, cash, 'iap_apple', bal, now());
    res.json({ ok: true, cash: bal, credited: cash });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});
// 구글: 서비스계정 OAuth(JWT bearer) → Android Publisher API 로 구매 검증
async function googleAccessToken() {
  const email = process.env.GOOGLE_SA_EMAIL;
  const key = (process.env.GOOGLE_SA_KEY || '').replace(/\\n/g, '\n');
  const iat = Math.floor(Date.now() / 1000), exp = iat + 3600;
  const assertion = jwt.sign(
    { iss: email, scope: 'https://www.googleapis.com/auth/androidpublisher', aud: 'https://oauth2.googleapis.com/token', iat, exp },
    key, { algorithm: 'RS256' }
  );
  const j = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion })
  }).then(r => r.json());
  if (!j.access_token) throw new Error('google_token_failed');
  return j.access_token;
}
app.post('/iap/google', auth, async (req, res) => {
  const { productId, purchaseToken } = req.body || {};
  if (!productId || !purchaseToken) return res.status(400).json({ error: 'missing_params' });
  const pkg = process.env.ANDROID_PACKAGE, email = process.env.GOOGLE_SA_EMAIL;
  if (!pkg || !email) return res.status(501).json({ error: 'google_iap_not_configured' });
  try {
    const token = await googleAccessToken();
    const isSub = !!PREMIUM_DAYS[productId];
    const url = isSub
      ? `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${pkg}/purchases/subscriptions/${productId}/tokens/${purchaseToken}`
      : `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${pkg}/purchases/products/${productId}/tokens/${purchaseToken}`;
    const j = await fetch(url, { headers: { Authorization: 'Bearer ' + token } }).then(r => r.json());
    if (!isSub && j.purchaseState !== 0) return res.status(402).json({ error: 'not_purchased', detail: j });
    const dup = db.prepare('SELECT id FROM iap_receipts WHERE txn_id=?').get(purchaseToken);
    if (dup) return res.json({ ok: true, already: true, cash: getUser(req.uid).cash });
    if (isSub) {
      const until = grantPremium(req.uid, productId);
      db.prepare('INSERT INTO iap_receipts (txn_id,user_id,store,product,cash,created_at) VALUES (?,?,?,?,?,?)').run(purchaseToken, req.uid, 'google', productId, 0, now());
      return res.json({ ok: true, premium: true, premium_until: until });
    }
    const cash = IAP_CASH[productId];
    if (!cash) return res.status(400).json({ error: 'unknown_product', product: productId });
    const u = getUser(req.uid); const bal = u.cash + cash;
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
    db.prepare('INSERT INTO iap_receipts (txn_id,user_id,store,product,cash,created_at) VALUES (?,?,?,?,?,?)').run(purchaseToken, u.id, 'google', productId, cash, now());
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)').run(u.id, cash, 'iap_google', bal, now());
    // TODO: purchases.products.acknowledge 호출로 소비 확정
    res.json({ ok: true, cash: bal, credited: cash });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// ══════════════════════════════════════════════════════════════
//  대진(Bracket) — 클럽 모임 1회 = 대진 1개
//  · brackets      : 발행된 대진 (편성 결과 JSON + 설정)
//  · bracket_scores: 코트별 점수 (key = "라운드-코트" 또는 "h0-1")
//  · bracket_timers: 코트별 시작 시각 (라이브 운영)
//  db.js를 건드리지 않도록 여기서 자체 마이그레이션합니다.
// ══════════════════════════════════════════════════════════════
db.exec(`
CREATE TABLE IF NOT EXISTS brackets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id   INTEGER NOT NULL,
  event_id  INTEGER,
  sport     TEXT NOT NULL DEFAULT 'tennis',
  fmt       TEXT NOT NULL DEFAULT 'double',   -- double|single|level|hanul|monthly|bw
  date      TEXT,
  courts    INTEGER NOT NULL DEFAULT 3,
  data      TEXT NOT NULL,                    -- JSON: {attendees, rounds|groups, grades, genders, cfg}
  published INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_brackets_club ON brackets(club_id, id DESC);

CREATE TABLE IF NOT EXISTS bracket_scores (
  bracket_id INTEGER NOT NULL,
  court_key  TEXT NOT NULL,
  a INTEGER, b INTEGER,
  updated_by INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (bracket_id, court_key)
);

CREATE TABLE IF NOT EXISTS bracket_timers (
  bracket_id INTEGER NOT NULL,
  court_key  TEXT NOT NULL,
  started_at INTEGER,
  PRIMARY KEY (bracket_id, court_key)
);
`);

// event_attendees.status : going | absent | undecided  (기존 행은 going 으로 간주)
try { db.exec("ALTER TABLE event_attendees ADD COLUMN status TEXT DEFAULT 'going'"); } catch (e) {}
// 게스트(비회원) — 대진 편성에는 들어가되 회원 통계에는 안 잡히도록 분리
db.exec(`CREATE TABLE IF NOT EXISTS event_guests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL, name TEXT NOT NULL,
  gender TEXT, grade TEXT, added_by INTEGER, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_guests_event ON event_guests(event_id);`);

// club_members.grade (A/B/C) — 대진 편성용 실력 등급. db.js를 건드리지 않고 여기서 추가.
try { db.exec('ALTER TABLE club_members ADD COLUMN grade TEXT'); } catch (e) { /* 이미 있음 */ }

// node:sqlite는 boolean/undefined 바인딩을 거부한다 → 정수 또는 null 로 정규화
function intOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

// 클럽 임원 여부 (owner 또는 officer)
function isOfficer(clubId, uid) {
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(clubId, uid);
  return !!m && (m.role === 'owner' || m.role === 'officer');
}
function isMember(clubId, uid) {
  return !!db.prepare('SELECT 1 FROM club_members WHERE club_id=? AND user_id=?').get(clubId, uid);
}
function bracketPayload(b) {
  const scores = {};
  db.prepare('SELECT court_key,a,b FROM bracket_scores WHERE bracket_id=?').all(b.id)
    .forEach(r => { scores[r.court_key] = { a: r.a, b: r.b }; });
  const timers = {};
  db.prepare('SELECT court_key,started_at FROM bracket_timers WHERE bracket_id=?').all(b.id)
    .forEach(r => { if (r.started_at) timers[r.court_key] = r.started_at; });
  return { ...b, data: JSON.parse(b.data), scores, timers };
}

// 클럽의 최신 대진 (회원은 published=1 만)
app.get('/clubs/:id/brackets/latest', (req, res) => {
  const cid = +req.params.id, uid = tryUid(req);
  const officer = uid ? isOfficer(cid, uid) : false;
  const b = db.prepare(
    `SELECT * FROM brackets WHERE club_id=? ${officer ? '' : 'AND published=1'} ORDER BY id DESC LIMIT 1`
  ).get(cid);
  if (!b) return res.status(404).json({ error: 'no_bracket' });
  res.json({ ...bracketPayload(b), officer });
});

app.get('/brackets/:id', (req, res) => {
  const b = db.prepare('SELECT * FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  const uid = tryUid(req);
  if (!b.published && !(uid && isOfficer(b.club_id, uid))) return res.status(403).json({ error: 'not_published' });
  res.json(bracketPayload(b));
});

// 대진 편성 저장 (임원진). 같은 날짜면 덮어씀.
app.post('/clubs/:id/brackets', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const { sport = 'tennis', fmt = 'double', date = '', data } = req.body || {};
  if (!data || typeof data !== 'object') return res.status(400).json({ error: 'data_required' });
  const courts = intOrNull((req.body || {}).courts) || 3;
  const event_id = intOrNull((req.body || {}).event_id);
  const publish = (req.body || {}).publish ? 1 : 0;
  const t = now();
  const prev = date ? db.prepare('SELECT id FROM brackets WHERE club_id=? AND date=? AND fmt=?').get(cid, date, fmt) : null;
  let id;
  if (prev) {
    db.prepare('UPDATE brackets SET sport=?,courts=?,data=?,published=?,event_id=?,updated_at=? WHERE id=?')
      .run(String(sport), courts, JSON.stringify(data), publish, event_id, t, prev.id);
    id = prev.id;
    db.prepare('DELETE FROM bracket_scores WHERE bracket_id=?').run(id);   // 재편성 → 점수 초기화
    db.prepare('DELETE FROM bracket_timers WHERE bracket_id=?').run(id);
  } else {
    const r = db.prepare(`INSERT INTO brackets (club_id,event_id,sport,fmt,date,courts,data,published,created_by,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(cid, event_id, String(sport), String(fmt), String(date), courts, JSON.stringify(data), publish, req.uid, t, t);
    id = rid(r);
  }
  if (publish) notifyClub(cid, req.uid, '📢', '대진이 발행됐어요', `${date || '오늘'} · ${fmt} 대진을 확인하세요`);
  res.json({ ok: true, id, published: !!publish });
});

// 발행 / 발행 취소
app.post('/brackets/:id/publish', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (!isOfficer(b.club_id, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const on = req.body && req.body.published === false ? 0 : 1;
  db.prepare('UPDATE brackets SET published=?, updated_at=? WHERE id=?').run(on, now(), b.id);
  if (on) notifyClub(b.club_id, req.uid, '📢', '대진이 발행됐어요', `${b.date || '오늘'} · ${b.fmt} 대진을 확인하세요`);
  res.json({ ok: true, published: !!on });
});

// 점수 입력 (클럽 회원 누구나). null 을 보내면 지움.
app.put('/brackets/:id/scores/:key', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (!isMember(b.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  const key = String(req.params.key).slice(0, 24);
  const a = intOrNull((req.body || {}).a);
  const bb = intOrNull((req.body || {}).b);
  if (a === null && bb === null) db.prepare('DELETE FROM bracket_scores WHERE bracket_id=? AND court_key=?').run(b.id, key);
  else db.prepare(`INSERT INTO bracket_scores (bracket_id,court_key,a,b,updated_by,updated_at) VALUES (?,?,?,?,?,?)
    ON CONFLICT(bracket_id,court_key) DO UPDATE SET a=excluded.a,b=excluded.b,updated_by=excluded.updated_by,updated_at=excluded.updated_at`)
    .run(b.id, key, a, bb, req.uid, now());
  db.prepare('UPDATE brackets SET updated_at=? WHERE id=?').run(now(), b.id);
  res.json({ ok: true });
});

// 코트 타이머 시작/중단 (토글)
app.post('/brackets/:id/timer/:key', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (!isMember(b.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  const key = String(req.params.key).slice(0, 24);
  const cur = db.prepare('SELECT started_at FROM bracket_timers WHERE bracket_id=? AND court_key=?').get(b.id, key);
  if (cur && cur.started_at) db.prepare('DELETE FROM bracket_timers WHERE bracket_id=? AND court_key=?').run(b.id, key);
  else db.prepare(`INSERT INTO bracket_timers (bracket_id,court_key,started_at) VALUES (?,?,?)
    ON CONFLICT(bracket_id,court_key) DO UPDATE SET started_at=excluded.started_at`).run(b.id, key, now());
  // 폴링(/live)이 변경을 감지하도록 updated_at 갱신 — 없으면 타이머가 다른 기기에 전파되지 않음
  db.prepare('UPDATE brackets SET updated_at=? WHERE id=?').run(now(), b.id);
  res.json({ ok: true, started_at: cur && cur.started_at ? null : now() });
});

// 폴링용 — 점수·타이머만 가볍게
app.get('/brackets/:id/live', (req, res) => {
  const b = db.prepare('SELECT id,updated_at,published,club_id FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  const p = bracketPayload({ ...b, data: '{}' });
  res.json({ id: b.id, updated_at: b.updated_at, scores: p.scores, timers: p.timers });
});

function notifyClub(clubId, exceptUid, icon, title, body) {
  const rows = db.prepare('SELECT user_id FROM club_members WHERE club_id=?').all(clubId);
  rows.forEach(r => { if (r.user_id !== exceptUid) sendPush(r.user_id, { icon, title, body }); });
}

app.get('/health', (_, res) => res.json({ ok: true, ts: now() }));

// ── 이미지 업로드 (프로필·경기 사진) — 로컬 디스크. 운영은 S3/CDN 권장 ──
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
try { fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch {}
app.use('/uploads', express.static(UPLOAD_DIR));
app.post('/upload', auth, (req, res) => {
  const m = /^data:(image\/(png|jpe?g|webp));base64,(.+)$/.exec((req.body && req.body.dataUrl) || '');
  if (!m) return res.status(400).json({ error: 'bad_image' });
  const buf = Buffer.from(m[3], 'base64');
  if (buf.length > 3 * 1024 * 1024) return res.status(413).json({ error: 'too_large' });
  const ext = m[2] === 'jpeg' ? 'jpg' : m[2];
  const name = 'u' + req.uid + '_' + Date.now() + '.' + ext;
  fs.writeFileSync(UPLOAD_DIR + '/' + name, buf);
  res.json({ url: '/uploads/' + name });
});

// ── 운영자 대시보드 API ──
// 접근키: env ADMIN_KEY (미설정 시 데모용 'matsu-admin'). 헤더 x-admin-key 또는 ?key=
const ADMIN_KEY = process.env.ADMIN_KEY || 'matsu-admin';
function admin(req, res, next) {
  if ((req.headers['x-admin-key'] || req.query.key) !== ADMIN_KEY) return res.status(403).json({ error: 'admin_only' });
  next();
}
app.get('/admin/stats', admin, (_req, res) => {
  const one = (sql) => db.prepare(sql).get().n;
  res.json({
    users: one('SELECT COUNT(*) n FROM users'),
    clubs: one('SELECT COUNT(*) n FROM clubs'),
    posts: one('SELECT COUNT(*) n FROM posts WHERE hidden=0'),
    hidden: one('SELECT COUNT(*) n FROM posts WHERE hidden=1'),
    openReports: one("SELECT COUNT(*) n FROM reports WHERE status='open'"),
    matches: one('SELECT COUNT(*) n FROM matches'),
    paidOrders: one("SELECT COUNT(*) n FROM orders WHERE status='paid'"),
    revenueWon: db.prepare("SELECT COALESCE(SUM(amount),0) n FROM orders WHERE status='paid'").get().n,
    cashIssued: db.prepare("SELECT COALESCE(SUM(cash),0) n FROM orders WHERE status='paid'").get().n,
  });
});
app.get('/admin/users', admin, (_req, res) => {
  res.json(db.prepare('SELECT id,name,provider,region,sport,rating,cash,premium,created_at FROM users ORDER BY id DESC LIMIT 200').all());
});
app.get('/admin/reports', admin, (_req, res) => {
  const rows = db.prepare("SELECT * FROM reports WHERE status='open' ORDER BY id DESC LIMIT 200").all();
  // 신고 대상(글) 미리보기 붙이기
  res.json(rows.map(r => {
    let target = null;
    if (r.target_type === 'post') target = db.prepare('SELECT id,title,hidden FROM posts WHERE id=?').get(r.target_id) || null;
    return { ...r, target };
  }));
});
app.post('/admin/reports/:id/resolve', admin, (req, res) => {
  db.prepare("UPDATE reports SET status='reviewed' WHERE id=?").run(+req.params.id);
  res.json({ ok: true });
});
app.post('/admin/posts/:id/hide', admin, (req, res) => {
  db.prepare('UPDATE posts SET hidden=1 WHERE id=?').run(+req.params.id);
  db.prepare("UPDATE reports SET status='actioned' WHERE target_type='post' AND target_id=?").run(+req.params.id);
  res.json({ ok: true });
});
app.post('/admin/posts/:id/show', admin, (req, res) => {
  db.prepare('UPDATE posts SET hidden=0 WHERE id=?').run(+req.params.id);
  res.json({ ok: true });
});
app.get('/admin/orders', admin, (_req, res) => {
  res.json(db.prepare("SELECT o.*, u.name FROM orders o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200").all());
});
// 회원 정지/해제
app.post('/admin/users/:id/suspend', admin, (req, res) => {
  const cur = db.prepare('SELECT suspended FROM users WHERE id=?').get(+req.params.id);
  const v = cur && cur.suspended ? 0 : 1;
  db.prepare('UPDATE users SET suspended=? WHERE id=?').run(v, +req.params.id);
  res.json({ ok: true, suspended: v });
});
// 관리자 환불 (토스 취소 + 캐쉬 회수. 시크릿 없으면 데모로 상태만 변경)
app.post('/admin/orders/:orderId/refund', admin, async (req, res) => {
  const ord = db.prepare('SELECT * FROM orders WHERE order_id=?').get(req.params.orderId);
  if (!ord) return res.status(404).json({ error: 'order_not_found' });
  if (ord.status !== 'paid') return res.status(400).json({ error: 'not_paid' });
  const secret = process.env.TOSS_SECRET_KEY;
  try {
    if (secret && ord.payment_key) {
      const r = await fetch(`https://api.tosspayments.com/v1/payments/${ord.payment_key}/cancel`, {
        method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(secret + ':').toString('base64'), 'Content-Type': 'application/json' },
        body: JSON.stringify({ cancelReason: '운영자 환불' })
      });
      if (!r.ok) return res.status(402).json({ error: 'toss_cancel_failed', detail: await r.json() });
    }
    const u = getUser(ord.user_id); const bal = Math.max(0, u.cash - ord.cash);
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
    db.prepare("UPDATE orders SET status='refunded' WHERE order_id=?").run(ord.order_id);
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)').run(u.id, -ord.cash, 'admin_refund', bal, now());
    res.json({ ok: true, refunded: ord.cash });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// 연결된 웹 클라이언트 (public/) 서빙 — npm start 하면 http://localhost:PORT 에서 바로 동작
app.use(express.static(new URL('./public', import.meta.url).pathname));
// 에러는 JSON으로
app.use((err, req, res, _next) => { console.error(err); res.status(500).json({ error: String(err && err.message || err) }); });
app.listen(PORT, () => console.log(`MATSU API on http://localhost:${PORT}`));
