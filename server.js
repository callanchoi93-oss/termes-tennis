// server.js — MATSU MVP REST API (Express + SQLite + JWT)
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/* 웹 푸시. VAPID 키가 없으면 조용히 꺼진다.
   키 만들기:  npx web-push generate-vapid-keys  */
let webpush = null;
try {
  const { default: wp } = await import('web-push');
  if (process.env.VAPID_PUBLIC && process.env.VAPID_PRIVATE) {
    wp.setVapidDetails(
      process.env.VAPID_SUBJECT || 'mailto:admin@matsu.app',
      process.env.VAPID_PUBLIC, process.env.VAPID_PRIVATE);
    webpush = wp;
    console.log('[push] 웹 푸시 활성화');
  } else {
    console.log('[push] VAPID 키가 없어 푸시는 알림함에만 쌓입니다');
  }
} catch { console.log('[push] web-push 모듈 없음 · 알림함만 사용'); }
import { db, initSchema, now, rid } from './db.js';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 4000;

initSchema();
const app = express();
app.set('trust proxy', 1);   // Railway 프록시 뒤 — req.ip 가 실제 클라이언트 IP 가 되게
/* CORS — APP_ORIGIN 이 있으면 그 도메인과 네이티브 앱만 허용한다.
   같은 도메인 요청은 CORS 를 타지 않으므로 웹은 영향 없다. */
const ALLOWED = [
  process.env.APP_ORIGIN,                 // 예: https://matsu.up.railway.app
  'capacitor://localhost', 'ionic://localhost', 'https://localhost',
].filter(Boolean);
app.use(cors(process.env.APP_ORIGIN ? {
  origin: (o, cb) => cb(null, !o || ALLOWED.includes(o) || /^http:\/\/localhost(:\d+)?$/.test(o)),
} : {}));

/* 기본 보안 헤더. helmet 없이 필요한 것만 직접 단다. */
app.use((_req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');       // 업로드 파일을 스크립트로 실행하지 못하게
  res.set('X-Frame-Options', 'DENY');                 // 다른 사이트가 iframe 으로 감싸지 못하게
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});              // 운영 시 origin 화이트리스트로 제한하세요
app.use(express.json({ limit: '6mb' }));   // 3MB 사진의 base64(≈4MB) + 여유

// ── 인증 유틸 ──

// ══════════════════════════════════════════════════════════════
//  요청 제한 — 같은 IP 가 짧은 시간에 몰아치는 것을 막는다.
//  인스턴스가 여러 개가 되면 Redis 로 옮겨야 한다.
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS rate_buckets (
  id TEXT PRIMARY KEY, n INTEGER NOT NULL, reset BIGINT NOT NULL
);`);
setInterval(() => {                                   // 지난 창 청소
  try { db.prepare('DELETE FROM rate_buckets WHERE reset < ?').run(Date.now() - 60_000); } catch {}
}, 5 * 60 * 1000).unref?.();

function rateLimit({ windowMs, max }) {
  return (req, res, next) => {
    const who = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown';
    const id = who + ':' + (req.route?.path || req.path) + ':' + req.method;
    const t = Date.now();
    let over = false, wait = 0;
    try {
      tx(() => {
        const b = db.prepare('SELECT n, reset FROM rate_buckets WHERE id=?').get(id);
        if (!b || b.reset < t) {
          db.prepare('INSERT OR REPLACE INTO rate_buckets (id,n,reset) VALUES (?,1,?)').run(id, t + windowMs);
        } else {
          db.prepare('UPDATE rate_buckets SET n=n+1 WHERE id=?').run(id);
          if (b.n + 1 > max) { over = true; wait = Math.ceil((b.reset - t) / 1000); }
        }
      });
    } catch { return next(); }                        // 제한 장치 고장이 서비스를 막으면 안 된다
    if (over) {
      res.set('Retry-After', String(wait));
      return res.status(429).json({ error: 'too_many_requests', retry_after: wait });
    }
    next();
  };
}
const limitLogin  = rateLimit({ windowMs: 60_000, max: 10 });
const limitWrite  = rateLimit({ windowMs: 60_000, max: 30 });
const limitUpload = rateLimit({ windowMs: 60_000, max: 12 });


/* 동시 요청 경합 방지 — 검사와 쓰기를 한 덩어리로 묶는다.
   BEGIN IMMEDIATE 는 시작 즉시 쓰기 잠금을 잡아, 두 요청이 같은 검사를 통과하는 것을 막는다. */
function tx(fn, tries = 5) {
  for (let i = 0; ; i++) {
    try {
      db.exec('BEGIN IMMEDIATE');
    } catch (e) {                                       // 다른 요청이 잠금 중 → 잠깐 기다렸다 재시도
      if (i < tries && /busy|locked/i.test(e.message)) {
        const until = Date.now() + 15 + i * 25;
        while (Date.now() < until) {}                   // 수 ms 스핀 (요청량이 적을 때만 안전)
        continue;
      }
      throw e;
    }
    try { const r = fn(); db.exec('COMMIT'); return r; }
    catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; }
  }
}

function sign(user) {
  // tv(token version) 를 함께 서명한다. 사용자가 '모든 기기 로그아웃' 을 하면
  // users.token_version 이 올라가고, 옛 토큰은 전부 무효가 된다.
  const u = db.prepare('SELECT token_version FROM users WHERE id=?').get(user.id) || {};
  return jwt.sign({ id: user.id, tv: u.token_version || 0 }, JWT_SECRET, { expiresIn: '30d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'no_token' });
  try {
    const p = jwt.verify(t, JWT_SECRET);
    req.uid = p.id;
    const u = db.prepare('SELECT suspended, token_version FROM users WHERE id=?').get(req.uid);
    if (!u) return res.status(401).json({ error: 'bad_token' });
    if (u.suspended) return res.status(403).json({ error: 'suspended' });
    if ((p.tv || 0) !== (u.token_version || 0))          // 다른 기기에서 전체 로그아웃함
      return res.status(401).json({ error: 'token_revoked' });
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
const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.RAILWAY_SERVICE_NAME;

/* 운영 환경에서 기본 시크릿으로 뜨는 것을 막는다.
   JWT_SECRET 없이 뜨면 누구나 토큰을 위조해 아무 계정이나 될 수 있다. */
if (IS_PROD && JWT_SECRET === 'dev-secret-change-me') {
  console.error('[FATAL] 운영 환경인데 JWT_SECRET 이 설정되지 않았습니다. Railway Variables 에 추가하세요.');
  process.exit(1);
}
if (IS_PROD && !process.env.ADMIN_KEY) {
  console.error('[FATAL] 운영 환경인데 ADMIN_KEY 가 설정되지 않았습니다. 기본키(matsu-admin)로는 뜨지 않습니다.');
  process.exit(1);
}

/* 이름 정리 — 모든 표시 지점에 들어가는 문자열이라 여기서 한 번에 막는다.
   (HTML 특수문자·따옴표·제어문자 제거, 20자 제한) */
function cleanName(s, fallback) {
  const t = String(s == null ? '' : s).replace(/[<>"'`\\\u0000-\u001f\u007f]/g, '').replace(/\s+/g, ' ').trim().slice(0, 20);
  return t || fallback || '회원';
}

try { db.exec('ALTER TABLE users ADD COLUMN dev_pin TEXT'); } catch (e) { /* 이미 있음 */ }
const pinHash = (pid, pin) => crypto.createHash('sha256').update(pid + ':' + String(pin)).digest('hex');

const SRV_BUILD = 'sH-0714';
app.get('/version', (req, res) => res.json({ build: SRV_BUILD }));

app.post('/auth/dev-login', limitLogin, (req, res) => {
  // 이름 로그인 — 카카오 키가 준비될 때까지의 임시 입구.
  // 이름만으로는 남의 계정에 못 들어가게 4~6자리 간편 비밀번호(PIN)를 요구한다.
  if (IS_PROD && process.env.ALLOW_DEV_LOGIN !== '1')
    return res.status(403).json({ error: 'disabled_in_production' });
  const { name = '게스트', provider = 'kakao', gender = '남성', region = '경기 용인', sport = 'tennis' } = req.body || {};
  const pin = String((req.body || {}).pin || '').replace(/\D/g, '');   // 선택 사항 — 안 쓰면 이름만으로 로그인
  // 이름 전체를 해시한다. hex.slice(0,12) 는 한글 4자까지만 반영돼
  // '상대0' '상대1' 이 같은 계정이 되는 충돌이 있었다.
  const pid = 'dev-' + crypto.createHash('sha256').update(String(name)).digest('hex').slice(0, 16);
  let u = db.prepare('SELECT * FROM users WHERE provider_id=?').get(pid);
  if (!u) {
    const nick = anonNick(pid);
    const r = db.prepare(`INSERT INTO users (provider,provider_id,name,gender,region,sport,anon_nick,created_at,dev_pin)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(provider, pid, cleanName(name, '게스트'), gender, region, sport, nick, now(), pin ? pinHash(pid, pin) : null);
    u = getUser(rid(r));
    db.prepare('UPDATE users SET cash=0 WHERE id=?').run(u.id);  // 캐시는 0원부터
  } else if (u.dev_pin && pin && u.dev_pin !== pinHash(pid, pin)) {
    return res.status(403).json({ error: 'wrong_pin', message: '간편 비밀번호가 달라요' });
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
  const name = cleanName((k.properties && k.properties.nickname), '카카오' + String(k.id).slice(-4));
  let u = db.prepare('SELECT * FROM users WHERE provider_id=?').get(pid);
  if (!u) {
    const r = db.prepare(`INSERT INTO users (provider,provider_id,name,anon_nick,created_at) VALUES ('kakao',?,?,?,?)`)
      .run(pid, name, anonNick(pid), now());
    u = getUser(rid(r));
    db.prepare('UPDATE users SET cash=0 WHERE id=?').run(u.id);  // 캐시는 0원부터
  }
  res.json({ token: sign(u), user: u });
}
// 클라이언트가 Kakao SDK로 받은 access_token을 보내는 방식 (SPA 권장)
// ══════════════════════════════════════════════════════════════
//  클라이언트 설정 — 공개 키만 내려준다.
//  이렇게 하면 키를 index.html 에 적을 필요가 없다 (GitHub 이 Public 이므로 중요).
//  Railway Variables 에 넣으면 재배포 없이 바뀐다.
// ══════════════════════════════════════════════════════════════
app.get('/config', (_, res) => {
  res.set('Cache-Control', 'no-store');   // 브라우저가 옛 응답을 붙잡지 못하게
  res.json({
    google_client_id: process.env.GOOGLE_CLIENT_ID || '',
    kakao_js_key: process.env.KAKAO_JS_KEY || '',
    name_login: !IS_PROD || process.env.ALLOW_DEV_LOGIN === '1',   // 카카오 키 전까지의 임시 입구
    kakao_redirect_uri: process.env.KAKAO_REDIRECT_URI || '',
    kakao_ready: !!(process.env.KAKAO_JS_KEY && process.env.KAKAO_REST_KEY && process.env.KAKAO_REDIRECT_URI),
    naver_client_id: process.env.NAVER_CLIENT_ID || '',
    naver_redirect_uri: process.env.NAVER_REDIRECT_URI || '',
    apple_client_id: process.env.APPLE_CLIENT_ID || '',
    support_email: process.env.SUPPORT_EMAIL || '',
    active_sports: process.env.ACTIVE_SPORTS || 'tennis',
    toss_client_key: process.env.TOSS_CLIENT_KEY || '',
    toss_ready: !!(process.env.TOSS_SECRET_KEY && process.env.TOSS_CLIENT_KEY),
    vapid_public: process.env.VAPID_PUBLIC || '',
    phone_auth: !!process.env.SMS_PROVIDER,     // 문자 인증 업체가 붙어 있는가
  });
});

// ══════════════════════════════════════════════════════════════
//  네이버 로그인
//  브라우저 → 네이버 동의창 → code 받아옴 → 서버가 code 로 토큰 교환 → 프로필 조회
//  env: NAVER_CLIENT_ID, NAVER_CLIENT_SECRET, NAVER_REDIRECT_URI
// ══════════════════════════════════════════════════════════════
app.post('/auth/naver', async (req, res) => {
  const { code, state } = req.body || {};
  const id = process.env.NAVER_CLIENT_ID, secret = process.env.NAVER_CLIENT_SECRET;
  if (!code || !id || !secret) return res.status(400).json({ error: 'missing_code_or_env' });
  try {
    const q = new URLSearchParams({ grant_type: 'authorization_code', client_id: id, client_secret: secret, code, state: state || '' });
    const tk = await fetch('https://nid.naver.com/oauth2.0/token?' + q).then(r => r.json());
    if (!tk.access_token) return res.status(401).json({ error: 'token_exchange_failed', detail: tk });

    const me = await fetch('https://openapi.naver.com/v1/nid/me', {
      headers: { Authorization: 'Bearer ' + tk.access_token },
    }).then(r => r.json());
    if (me.resultcode !== '00' || !me.response || !me.response.id)
      return res.status(401).json({ error: 'profile_failed', detail: me });

    const p = me.response;
    const pid = 'naver-' + p.id;
    let u = db.prepare('SELECT * FROM users WHERE provider_id=?').get(pid);
    if (!u) {
      const name = cleanName(p.nickname || p.name, '네이버' + String(p.id).slice(-4));
      const r = db.prepare(`INSERT INTO users (provider,provider_id,name,anon_nick,created_at) VALUES ('naver',?,?,?,?)`)
        .run(pid, name, anonNick(pid), now());
      u = getUser(rid(r));
    db.prepare('UPDATE users SET cash=0 WHERE id=?').run(u.id);  // 캐시는 0원부터
    }
    res.json({ token: sign(u), user: u });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.post('/auth/kakao', limitLogin, async (req, res) => {
  const { access_token } = req.body || {};
  if (!access_token) return res.status(400).json({ error: 'no_access_token' });
  try { await kakaoIssue(access_token, res); } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});
// (대안) 인가코드 방식: 서버가 code→token 교환. env: KAKAO_REST_KEY, KAKAO_REDIRECT_URI (, KAKAO_CLIENT_SECRET)
app.post('/auth/kakao/code', limitLogin, async (req, res) => {
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

// ── 종목별 프로필 (포지션·주발·영법 …) ──
// 종목마다 항목이 달라서 컬럼으로 두지 않고 JSON 한 칸에 담는다.
try { db.exec("ALTER TABLE users ADD COLUMN sport_profile TEXT"); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN phone TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN sport_started TEXT'); } catch (e) {}   // 종목별 시작 시점 {"tennis":"2019-05"}
try { db.exec('ALTER TABLE users ADD COLUMN photos TEXT'); } catch (e) {}          // 프로필 사진 (JSON 배열)
try { db.exec('UPDATE users SET cash=0 WHERE cash BETWEEN 1 AND 6'); } catch (e) {} // 구 기본값(5원) 정리 — 캐시는 0원부터
try { db.exec('ALTER TABLE users ADD COLUMN exp TEXT'); } catch (e) {}             // 구력 표기
db.exec(`CREATE TABLE IF NOT EXISTS member_exits (
  id INTEGER PRIMARY KEY AUTOINCREMENT, club_id INTEGER, user_id INTEGER, name TEXT,
  reason TEXT, left_at INTEGER)`);
db.exec(`CREATE TABLE IF NOT EXISTS rest_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, club_id INTEGER, user_id INTEGER,
  rtype TEXT, start TEXT, end TEXT, reason TEXT, status TEXT DEFAULT 'pending', created_at INTEGER)`);                    // 연명부 연락처 (본인 입력)
try { db.exec('ALTER TABLE club_members ADD COLUMN resting INTEGER DEFAULT 0'); } catch (e) {}  // 휴회
try { db.exec('ALTER TABLE club_members ADD COLUMN joined_at INTEGER'); } catch (e) {}      // 가입(승인)일

app.get('/me/sport-profile', auth, (req, res) => {
  const u = db.prepare('SELECT sport_profile FROM users WHERE id=?').get(req.uid);
  let all = {};
  try { all = JSON.parse(u.sport_profile || '{}'); } catch (e) {}
  res.json(all);
});

app.put('/me/sport-profile/:sport', auth, (req, res) => {
  const sport = String(req.params.sport || '').slice(0, 20);
  const u = db.prepare('SELECT sport_profile FROM users WHERE id=?').get(req.uid);
  let all = {};
  try { all = JSON.parse(u.sport_profile || '{}'); } catch (e) {}
  const body = req.body || {};
  const clean = {};
  Object.keys(body).slice(0, 12).forEach(k => {
    const v = body[k];
    if (v === '' || v == null) return;
    clean[String(k).slice(0, 20)] = String(v).slice(0, 40);
  });
  all[sport] = clean;
  db.prepare('UPDATE users SET sport_profile=? WHERE id=?').run(JSON.stringify(all), req.uid);
  // 라켓 종목의 공통 항목은 users 컬럼에도 반영해 선수 비교에서 바로 쓴다
  for (const k of ['handed', 'backhand', 'style', 'birth_year']) {
    const v = k === 'birth_year' ? (parseInt(clean.birth, 10) || null) : clean[k];
    if (!v) continue;
    try { db.prepare(`UPDATE users SET ${k}=? WHERE id=?`).run(v, req.uid); }
    catch (e) { try { db.exec(`ALTER TABLE users ADD COLUMN ${k} ${k === 'birth_year' ? 'INTEGER' : 'TEXT'}`); db.prepare(`UPDATE users SET ${k}=? WHERE id=?`).run(v, req.uid); } catch (_) {} }
  }
  res.json({ ok: true, sport, profile: clean });
});

// 선수 비교용 공개 프로필 (민감정보 제외)
app.get('/users/:id/profile', (req, res) => {
  const u = db.prepare(`SELECT id,name,gender,region,sport,rating,mmr,peak_mmr,birth_year,handed,backhand,style,
    wins,losses,photos,skill_verified,real_verified FROM users WHERE id=?`).get(intOrNull(req.params.id));
  if (!u) return res.status(404).json({ error: 'not_found' });
  const rank = db.prepare('SELECT COUNT(*)+1 n FROM users WHERE sport=? AND rating>?').get(u.sport, u.rating).n;
  res.json({ ...u, rank });
});

// 데모 매칭용 사용자 목록
app.get('/users', (req, res) => {
  const q = '%' + (req.query.q || '') + '%';
  const sp = req.query.sport;
  if (sp) {
    // 종목 풀: 그 종목에서 실제 활동(클럽 가입·기록·대전)한 회원만 — 유령 회원이 추천 대진에 뜨는 것 방지
    return res.json(db.prepare(`SELECT id,name,region,sport,rating FROM users u WHERE name LIKE ? AND (
      EXISTS(SELECT 1 FROM club_members cm JOIN clubs c ON c.id=cm.club_id
             WHERE cm.user_id=u.id AND c.sport=? AND (cm.status IS NULL OR cm.status='active'))
      OR EXISTS(SELECT 1 FROM records r WHERE r.user_id=u.id AND r.sport=?)
      OR EXISTS(SELECT 1 FROM matches m WHERE m.sport=? AND (m.home_user_id=u.id OR m.away_user_id=u.id))
    ) ORDER BY id DESC LIMIT 30`).all(q, sp, sp, sp));
  }
  res.json(db.prepare('SELECT id,name,region,sport,rating FROM users WHERE name LIKE ? ORDER BY id DESC LIMIT 30').all(q));
});

// ── 구글 로그인 (Google Identity Services, 실연동) ──
// 클라이언트가 받은 credential(id_token, RS256 JWT)을 보내면
// 서버가 구글 공개키(JWKS)로 서명·발급자·대상(aud)을 검증한 뒤 우리 JWT 발급.
// 검증을 서버에서 하지 않으면 아무나 토큰을 위조해 남의 계정이 될 수 있다.
// env: GOOGLE_CLIENT_ID
let _googleKeys = { keys: [], ts: 0 };
async function googleKeys() {
  if (_googleKeys.keys.length && Date.now() - _googleKeys.ts < 3600e3) return _googleKeys.keys;
  const url = process.env.GOOGLE_JWKS_URL || 'https://www.googleapis.com/oauth2/v3/certs';  // 테스트용 주입
  const r = await fetch(url).then(x => x.json());
  _googleKeys = { keys: r.keys, ts: Date.now() };
  return r.keys;
}
app.post('/auth/google', limitLogin, async (req, res) => {
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: 'no_credential' });
  const aud = process.env.GOOGLE_CLIENT_ID;
  if (!aud) return res.status(400).json({ error: 'missing_env' });
  try {
    const hdr = JSON.parse(Buffer.from(credential.split('.')[0], 'base64url').toString());
    const jwk = (await googleKeys()).find(k => k.kid === hdr.kid);
    if (!jwk) return res.status(401).json({ error: 'google_key_not_found' });
    const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const claims = jwt.verify(credential, pub, {
      algorithms: ['RS256'],
      issuer: ['https://accounts.google.com', 'accounts.google.com'],
      audience: aud,
    });
    const pid = 'google-' + claims.sub;
    const nm = cleanName(claims.name || (claims.email ? claims.email.split('@')[0] : ''), '구글' + String(claims.sub).slice(-4));
    let u = db.prepare('SELECT * FROM users WHERE provider_id=?').get(pid);
    if (!u) {
      const r = db.prepare(`INSERT INTO users (provider,provider_id,name,anon_nick,created_at) VALUES ('google',?,?,?,?)`)
        .run(pid, nm, anonNick(pid), now());
      u = getUser(rid(r));
    }
    res.json({ token: sign(u), user: u });
  } catch (e) { res.status(401).json({ error: 'google_verify_failed', detail: String(e.message || e) }); }
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
    const nm = cleanName(name, '애플' + String(claims.sub).slice(-4));
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
  if (blockIosWebPurchase(req, res)) return;         // M캐쉬 충전 → 애플 IAP 필수
  if (requirePayments(req, res)) return;
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
  const allow = ['gender','region','sport','exp','photos','phone_verified','real_verified','skill_verified',
                 'birth_year','handed','backhand','style','phone','sport_started'];
  const nums = ['birth_year','phone_verified','real_verified','skill_verified'];
  const sets = [], vals = [];
  for (const k of allow) if (k in req.body) {
    sets.push(`${k}=?`);
    vals.push(nums.includes(k) ? intOrNull(req.body[k])
      : typeof req.body[k]==='object' ? JSON.stringify(req.body[k]) : req.body[k]);
  }
  if (sets.length) {
    try { db.prepare(`UPDATE users SET ${sets.join(',')} WHERE id=?`).run(...vals, req.uid); }
    catch (e) {                                            // 옛 DB에 컬럼이 없으면 보강 후 재시도 (자가 복구)
      allow.forEach(k => { try { db.exec(`ALTER TABLE users ADD COLUMN ${k} ${nums.includes(k) ? 'INTEGER' : 'TEXT'}`); } catch (_) {} });
      db.prepare(`UPDATE users SET ${sets.join(',')} WHERE id=?`).run(...vals, req.uid);
    }
  }
  res.json(getUser(req.uid));
});

// ── CLUBS ──
app.get('/clubs', (req, res) => {
  const { sport, region, q } = req.query;
  // 활동 지표(회원 수·최근 활동)로 정렬 — 유령 클럽이 검색을 오염시키지 않게
  let sql = `SELECT c.*,
      (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id AND (m.status IS NULL OR m.status='active')) members,
      COALESCE((SELECT MAX(e.created_at) FROM club_events e WHERE e.club_id=c.id),
               (SELECT MAX(ch.created_at) FROM club_chat ch WHERE ch.club_id=c.id), c.created_at) last_active
    FROM clubs c WHERE 1=1`, p = [];
  if (sport) { sql += ' AND c.sport=?'; p.push(sport); }
  if (region) { sql += ' AND c.region LIKE ?'; p.push('%' + region + '%'); }
  if (q) { sql += ' AND c.name LIKE ?'; p.push('%' + q + '%'); }
  res.json(db.prepare(sql + ' ORDER BY members DESC, last_active DESC LIMIT 100').all(...p));
});
app.post('/clubs', auth, (req, res) => {
  let { name, sport, region } = req.body;
  name = cleanName(name, '').slice(0, 24);
  if (!name || !sport) return res.status(400).json({ error: 'name_sport_required' });
  // 스팸 방지 최소 장치 — 승인제 대신 조용한 한도로 막는다
  const owned = db.prepare("SELECT COUNT(*) n FROM club_members WHERE user_id=? AND role='owner'").get(req.uid).n;
  if (owned >= 3) return res.status(400).json({ error: 'club_limit', message: '클럽은 1인당 3개까지 만들 수 있어요' });
  const dup = db.prepare('SELECT 1 FROM clubs WHERE name=? AND sport=?').get(name, sport);
  if (dup) return res.status(409).json({ error: 'name_taken', message: '이미 있는 클럽 이름이에요' });
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
  // 연락처는 임원에게만 — 토큰이 있으면 조용히 확인
  let uid = null;
  try { uid = jwt.verify((req.headers.authorization||'').replace('Bearer ',''), JWT_SECRET).uid; } catch (e) {}
  const officer = uid ? isOfficer(+req.params.id, uid) : false;
  const rows = db.prepare(`SELECT cm.id, cm.club_id, cm.user_id, cm.role, cm.jersey_no, cm.is_captain, cm.status, cm.grade,
    cm.resting, cm.joined_at, u.name, u.gender, u.rating, u.sport_started${officer ? ', u.phone' : ''} FROM club_members cm
    JOIN users u ON u.id=cm.user_id WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
    ORDER BY (cm.role='owner') DESC, (cm.role='officer') DESC, cm.resting, u.name`).all(+req.params.id);
  res.json(rows);
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

// 성별 설정 (임원진) — 회원 프로필은 건드리지 않고 클럽 내 오버라이드로 저장
app.patch('/clubs/:id/genders', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const g = (req.body && req.body.genders) || {};
  const st = db.prepare('UPDATE club_members SET gender_ov=? WHERE club_id=? AND user_id=?');
  Object.entries(g).forEach(([uid, v]) => {
    const gv = ['M', 'F'].includes(String(v)) ? String(v) : null;
    st.run(gv, cid, intOrNull(uid));
  });
  res.json({ ok: true, n: Object.keys(g).length });
});

// 휴회 토글 (임원)
// 휴회·복회 신청 (회원) — 임원 승인제
// 연명부 부속 기록 — 휴회·복회 이력 + 탈퇴 회원 (엑셀 시트용)
app.get('/clubs/:id/roster-logs', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const rests = db.prepare(`SELECT r.rtype, r.start, r.end, r.reason, r.created_at, r.status, u.name
    FROM rest_requests r JOIN users u ON u.id=r.user_id
    WHERE r.club_id=? AND r.status='approved' ORDER BY r.id DESC LIMIT 200`).all(cid);
  const exits = db.prepare('SELECT name, reason, left_at FROM member_exits WHERE club_id=? ORDER BY id DESC LIMIT 200').all(cid);
  res.json({ rests, exits });
});

app.post('/clubs/:id/rest-requests', auth, (req, res) => {
  const cid = +req.params.id;
  const mem = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND (status IS NULL OR status='active')").get(cid, req.uid);
  if (!mem) return res.status(403).json({ error: 'not_member' });
  const { rtype, start, end, reason } = req.body || {};
  if (!['rest', 'return'].includes(rtype)) return res.status(400).json({ error: 'bad_type' });
  const dup = db.prepare("SELECT 1 FROM rest_requests WHERE club_id=? AND user_id=? AND status='pending'").get(cid, req.uid);
  if (dup) return res.status(409).json({ error: 'already_pending' });
  db.prepare('INSERT INTO rest_requests (club_id,user_id,rtype,start,end,reason,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(cid, req.uid, rtype, start || '', end || '', (reason || '').slice(0, 40), now());
  const u = getUser(req.uid), club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND role IN ('owner','officer')").all(cid)
    .forEach(o => sendPush(o.user_id, { icon: '🛌', title: (rtype==='rest'?'휴회':'복회')+' 신청', body: `${u.name} · ${reason||''}` }));
  res.json({ ok: true });
});
app.get('/clubs/:id/rest-requests', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  res.json(db.prepare(`SELECT r.*, u.name FROM rest_requests r JOIN users u ON u.id=r.user_id
    WHERE r.club_id=? AND r.status='pending' ORDER BY r.id DESC`).all(cid));
});
app.post('/clubs/:id/rest-requests/:rid/decide', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const r = db.prepare('SELECT * FROM rest_requests WHERE id=? AND club_id=?').get(+req.params.rid, cid);
  if (!r || r.status !== 'pending') return res.status(404).json({ error: 'not_found' });
  const ok = !(req.body && req.body.approve === false);
  db.prepare('UPDATE rest_requests SET status=? WHERE id=?').run(ok ? 'approved' : 'rejected', r.id);
  if (ok) db.prepare('UPDATE club_members SET resting=? WHERE club_id=? AND user_id=?').run(r.rtype === 'rest' ? 1 : 0, cid, r.user_id);
  sendPush(r.user_id, { icon: ok ? '✅' : '🔔', title: (r.rtype==='rest'?'휴회':'복회') + (ok?' 승인':' 신청 결과'), body: ok ? '처리되었어요' : '승인되지 않았어요' });
  res.json({ ok: true });
});

app.patch('/clubs/:id/members/:uid/resting', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const v = req.body && req.body.resting ? 1 : 0;
  db.prepare('UPDATE club_members SET resting=? WHERE club_id=? AND user_id=?').run(v, cid, intOrNull(req.params.uid));
  res.json({ ok: true, resting: v });
});
// 역할 변경 — 임원: guest↔member / 클럽장: officer 포함
app.patch('/clubs/:id/members/:uid/role', auth, (req, res) => {
  const cid = +req.params.id;
  const owner = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, req.uid);
  const wanted = req.body && req.body.role;
  if (!owner) {
    // 임원은 게스트↔정회원 전환만
    if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
    if (!['guest', 'member'].includes(wanted)) return res.status(403).json({ error: 'owner_only_for_officer' });
    const t = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, intOrNull(req.params.uid));
    if (!t) return res.status(404).json({ error: 'not_member' });
    if (['owner', 'officer'].includes(t.role)) return res.status(400).json({ error: 'cannot_change' });
    if (wanted === 'member' && t.role === 'guest')
      db.prepare('UPDATE club_members SET role=?, joined_at=? WHERE club_id=? AND user_id=?').run(wanted, now(), cid, intOrNull(req.params.uid));
    else db.prepare('UPDATE club_members SET role=? WHERE club_id=? AND user_id=?').run(wanted, cid, intOrNull(req.params.uid));
    return res.json({ ok: true, role: wanted });
  }
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
/* ═══ 클럽 대진 v2 (테르메스 이식 v1) — JSON 블롭 + 권한 ═══
   data = { date, courts, rounds, games:[{r,c,label,teamA:[{id,name}],teamB:[...],sa,sb}], made_by } */
try { db.exec(`CREATE TABLE IF NOT EXISTS club_brackets (
  club_id INTEGER PRIMARY KEY, data TEXT, updated_at INTEGER)`); } catch (e) {}
function cbRole(cid, uid) {
  const m = db.prepare(`SELECT role FROM club_members WHERE club_id=? AND user_id=? AND (status IS NULL OR status='active')`).get(cid, uid);
  return m ? (m.role || 'member') : null;
}
app.get('/clubs/:id/bracket2', auth, (req, res) => {
  const cid = +req.params.id;
  if (!cbRole(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const row = db.prepare('SELECT data, updated_at FROM club_brackets WHERE club_id=?').get(cid);
  res.json(row ? { ...JSON.parse(row.data), updated_at: row.updated_at } : null);
});
app.put('/clubs/:id/bracket2', auth, (req, res) => {          // 발행/수정 — 임원만
  const cid = +req.params.id;
  const role = cbRole(cid, req.uid);
  if (role !== 'owner' && role !== 'officer') return res.status(403).json({ error: 'officer_only' });
  const data = req.body || {};
  db.prepare(`INSERT INTO club_brackets (club_id,data,updated_at) VALUES (?,?,?)
    ON CONFLICT(club_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`)
    .run(cid, JSON.stringify(data), now());
  res.json({ ok: true });
});
app.patch('/clubs/:id/bracket2/score', auth, (req, res) => {  // 스코어 — 당사자 또는 임원
  const cid = +req.params.id;
  const role = cbRole(cid, req.uid);
  if (!role) return res.status(403).json({ error: 'member_only' });
  const { gi, sa, sb } = req.body || {};
  const row = db.prepare('SELECT data FROM club_brackets WHERE club_id=?').get(cid);
  if (!row) return res.status(404).json({ error: 'no_bracket' });
  const data = JSON.parse(row.data);
  const g = (data.games || [])[gi];
  if (!g) return res.status(404).json({ error: 'no_game' });
  const officer = role === 'owner' || role === 'officer';
  const inGame = [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === req.uid);
  if (!officer && !inGame) return res.status(403).json({ error: 'player_only', message: '그 경기를 뛴 당사자나 임원만 입력할 수 있어요' });
  g.sa = Math.max(0, Math.min(9, +sa)); g.sb = Math.max(0, Math.min(9, +sb));
  g.by = req.uid; g.at = now();
  db.prepare('UPDATE club_brackets SET data=?, updated_at=? WHERE club_id=?').run(JSON.stringify(data), now(), cid);
  res.json({ ok: true, game: g });
});
app.get('/clubs/:id/roster', (req, res) => {
  const cid = +req.params.id;
  const ev = db.prepare('SELECT id FROM club_events WHERE club_id=? ORDER BY id DESC LIMIT 1').get(cid);
  let rows;
  let guests = [];
  if (ev) {
    rows = db.prepare(`SELECT u.id user_id, u.name, COALESCE(cm.gender_ov, u.gender) AS gender, u.photos, cm.grade, cm.is_captain
      FROM event_attendees ea JOIN users u ON u.id=ea.user_id
      LEFT JOIN club_members cm ON cm.club_id=? AND cm.user_id=u.id
      WHERE ea.event_id=? AND (ea.status IS NULL OR ea.status='going') ORDER BY u.name`).all(cid, ev.id);
    guests = db.prepare('SELECT id,name,gender,grade FROM event_guests WHERE event_id=? ORDER BY id').all(ev.id)
      .map(g => ({ user_id: null, name: g.name, gender: g.gender, grade: g.grade, is_guest: 1, guest_id: g.id }));
  }
  if (!rows || !rows.length) {
    rows = db.prepare(`SELECT u.id user_id, u.name, COALESCE(cm.gender_ov, u.gender) AS gender, u.photos, cm.grade, cm.is_captain
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
    if (!isPremium(cid) && activeMembers(cid) >= FREE_MAX_MEMBERS)
      return res.status(402).json({ error: 'member_limit', limit: FREE_MAX_MEMBERS, upgrade: 'club_premium' });
    const role = (req.body && req.body.role) === 'guest' ? 'guest' : 'member';
    db.prepare("UPDATE club_members SET status='active', role=?, joined_at=COALESCE(joined_at,?) WHERE club_id=? AND user_id=? AND status='pending'").run(role, now(), cid, uid);
    sendPush(uid, { icon: '🎉', title: '가입 승인', body: role==='guest' ? `${club.name} 게스트로 함께하게 됐어요` : `${club.name} 정회원이 됐어요` });
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
      guests: db.prepare('SELECT id,name,gender,grade,fee,paid FROM event_guests WHERE event_id=? ORDER BY id').all(e.id),
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

app.patch('/clubs/:id/events/:eid', auth, (req, res) => {
  const cid = +req.params.id, eid = +req.params.eid;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const ev = db.prepare('SELECT * FROM club_events WHERE id=? AND club_id=?').get(eid, cid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  const title = String((req.body || {}).title || ev.title);
  const date = String((req.body || {}).date != null ? (req.body || {}).date : ev.date);
  db.prepare('UPDATE club_events SET title=?, date=? WHERE id=?').run(title, date, eid);
  // 참석 응답한 회원들에게 변경 알림
  db.prepare('SELECT DISTINCT user_id FROM event_attendees WHERE event_id=?').all(eid)
    .forEach(a => { if (a.user_id !== req.uid) sendPush(a.user_id,
      { icon: '📅', title: '모임 일정이 바뀌었어요', body: `${title} · ${date}` }); });
  res.json({ ok: true });
});

app.delete('/clubs/:id/events/:eid', auth, (req, res) => {
  const cid = +req.params.id, eid = +req.params.eid;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const ev = db.prepare('SELECT * FROM club_events WHERE id=? AND club_id=?').get(eid, cid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  // 참석자에게 취소 알림 후 정리
  db.prepare('SELECT DISTINCT user_id FROM event_attendees WHERE event_id=?').all(eid)
    .forEach(a => { if (a.user_id !== req.uid) sendPush(a.user_id,
      { icon: '📅', title: '모임이 취소됐어요', body: `${ev.title}${ev.date ? ' · ' + ev.date : ''}` }); });
  db.prepare('DELETE FROM event_attendees WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM event_guests WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM club_events WHERE id=?').run(eid);
  res.json({ ok: true });
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
  if (st === 'going') settleReferral(req.uid);
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
// ══════════════════════════════════════════════════════════════
//  게스트 모집 링크 — 모임 단위 공개 링크로 외부인이 게스트 신청
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS guest_links (
  token TEXT PRIMARY KEY,
  club_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
  created_by INTEGER, created_at BIGINT
);`);
try { db.exec('ALTER TABLE event_guests ADD COLUMN phone TEXT'); } catch (e) { /* 신청자 연락처 */ }
try { db.exec("ALTER TABLE event_guests ADD COLUMN source TEXT DEFAULT 'manual'"); } catch (e) { /* link 신청 구분 */ }

app.post('/clubs/:id/events/:eid/guest-link', auth, (req, res) => {
  const cid = +req.params.id, eid = +req.params.eid;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const ev = db.prepare('SELECT id FROM club_events WHERE id=? AND club_id=?').get(eid, cid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  const exist = db.prepare('SELECT token FROM guest_links WHERE event_id=?').get(eid);
  if (exist) return res.json({ token: exist.token });
  const token = crypto.randomBytes(9).toString('base64url');
  db.prepare('INSERT INTO guest_links (token,club_id,event_id,created_by,created_at) VALUES (?,?,?,?,?)')
    .run(token, cid, eid, req.uid, now());
  res.json({ token });
});

// 공개: 링크 정보 (로그인 불필요)
app.get('/guest/:token', (req, res) => {
  const gl = db.prepare('SELECT * FROM guest_links WHERE token=?').get(String(req.params.token));
  if (!gl) return res.status(404).json({ error: 'no_link' });
  const club = db.prepare('SELECT id,name,region,sport,guest_fee FROM clubs WHERE id=?').get(gl.club_id);
  const ev = db.prepare('SELECT id,title,date FROM club_events WHERE id=?').get(gl.event_id);
  if (!club || !ev) return res.status(404).json({ error: 'no_event' });
  const nGuests = db.prepare('SELECT COUNT(*) n FROM event_guests WHERE event_id=?').get(ev.id).n;
  // 같은 클럽의 다른 모임들 (다음 매치 미리 신청용)
  const others = db.prepare('SELECT id,title,date FROM club_events WHERE club_id=? AND id!=? ORDER BY id DESC LIMIT 3')
    .all(gl.club_id, ev.id);
  res.json({ club: { name: club.name, region: club.region, sport: club.sport, guest_fee: club.guest_fee || 0 },
    event: { ...ev, guests: nGuests }, others });
});

// 게스트 신청 — 맞수 회원으로 신청한다 (가입이 곧 유입)
try { db.exec('ALTER TABLE event_guests ADD COLUMN user_id INTEGER'); } catch (e) { /* 이미 있음 */ }

app.post('/guest/:token/apply', auth, limitWrite, (req, res) => {
  const gl = db.prepare('SELECT * FROM guest_links WHERE token=?').get(String(req.params.token));
  if (!gl) return res.status(404).json({ error: 'no_link' });
  const me = getUser(req.uid);
  if (!me) return res.status(401).json({ error: 'unauthorized' });
  if (isMember(gl.club_id, req.uid)) return res.status(409).json({ error: 'already_member' });
  let eid = intOrNull((req.body || {}).event_id) || gl.event_id;
  // 신청 대상 모임은 반드시 같은 클럽 소속이어야 한다
  const ev = db.prepare('SELECT id,title FROM club_events WHERE id=? AND club_id=?').get(eid, gl.club_id);
  if (!ev) return res.status(400).json({ error: 'bad_request' });
  const dup = db.prepare('SELECT 1 FROM event_guests WHERE event_id=? AND (user_id=? OR name=?)')
    .get(eid, req.uid, me.name);
  if (dup) return res.status(409).json({ error: 'already_applied' });
  const club = db.prepare('SELECT guest_fee FROM clubs WHERE id=?').get(gl.club_id);
  db.prepare(`INSERT INTO event_guests (event_id,name,gender,added_by,created_at,fee,source,user_id)
    VALUES (?,?,?,?,?,?,'link',?)`)
    .run(eid, me.name, me.gender || null, null, now(), (club && club.guest_fee) || 0, req.uid);
  // 임원들에게 알림 — 신청자가 회원이라 앱에서 바로 채팅으로 연락 가능
  db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND role IN ('owner','officer')").all(gl.club_id)
    .forEach(o => sendPush(o.user_id, { icon: '🙌', title: '게스트 신청이 들어왔어요',
      body: `${me.name}님 · ${ev.title} — 채팅으로 안내해 주세요`, link: 'club' }));
  res.json({ ok: true });
});

app.get('/events/:id/guests', (req, res) => {
  res.json(db.prepare(`SELECT g.id,g.name,g.gender,g.grade,g.fee,g.paid,g.paid_at,g.added_by,u.name host_name
    FROM event_guests g LEFT JOIN users u ON u.id=g.added_by
    WHERE g.event_id=? ORDER BY g.id`).all(+req.params.id));
});

// 게스트비 수납 체크 (임원진)
app.patch('/events/:eid/guests/:gid', auth, (req, res) => {
  const eid = +req.params.eid;
  const ev = db.prepare('SELECT club_id FROM club_events WHERE id=?').get(eid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  if (!isOfficer(ev.club_id, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const g = db.prepare('SELECT id FROM event_guests WHERE id=? AND event_id=?').get(intOrNull(req.params.gid), eid);
  if (!g) return res.status(404).json({ error: 'not_found' });
  const b = req.body || {};
  if ('fee' in b) db.prepare('UPDATE event_guests SET fee=? WHERE id=?').run(intOrNull(b.fee) || 0, g.id);
  if ('paid' in b) {
    const paid = b.paid ? 1 : 0;
    db.prepare('UPDATE event_guests SET paid=?, paid_at=? WHERE id=?').run(paid, paid ? now() : null, g.id);
  }
  res.json({ ok: true });
});

// 이번 모임 게스트비 요약
app.get('/events/:id/guests/summary', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = db.prepare('SELECT club_id FROM club_events WHERE id=?').get(eid);
  if (!ev || !isMember(ev.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  const gs = db.prepare('SELECT fee,paid FROM event_guests WHERE event_id=?').all(eid);
  res.json({
    n: gs.length,
    total: gs.reduce((a, g) => a + (g.fee || 0), 0),
    collected: gs.filter(g => g.paid).reduce((a, g) => a + (g.fee || 0), 0),
    paid_n: gs.filter(g => g.paid).length,
  });
});
app.post('/events/:id/guests', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = db.prepare('SELECT club_id FROM club_events WHERE id=?').get(eid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  if (!isOfficer(ev.club_id, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const name = cleanName((req.body && req.body.name), '').slice(0, 12);
  if (!name) return res.status(400).json({ error: 'name_required' });
  const gender = ['M', 'F'].includes(req.body.gender) ? req.body.gender : null;
  const grade = ['A', 'B', 'C'].includes(req.body.grade) ? req.body.grade : null;
  const dup = db.prepare('SELECT 1 FROM event_guests WHERE event_id=? AND name=?').get(eid, name);
  if (dup) return res.status(409).json({ error: 'duplicate_name' });
  const club = db.prepare('SELECT guest_fee FROM clubs WHERE id=?').get(ev.club_id);
  const fee = intOrNull((req.body || {}).fee);
  const useFee = fee === null ? (club && club.guest_fee) || 0 : fee;
  const r = db.prepare('INSERT INTO event_guests (event_id,name,gender,grade,added_by,created_at,fee) VALUES (?,?,?,?,?,?,?)')
    .run(eid, name, gender, grade, req.uid, now(), useFee);
  res.json({ ok: true, id: rid(r), fee: useFee });
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
// 페어플레이 점수 — 기본 80, 최근 후기 30건 반영 (5점 +2 · 4점 +1 · 3점 0 · 2점 -2 · 1점 -4), 0~100
function fairplayOf(uid) {
  // 오픈매치 후기 + 클럽 회원 평가 합산, 최근 30건만 반영
  const rows = db.prepare(`SELECT stars, created_at t FROM om_reviews WHERE to_user=?
    UNION ALL SELECT stars, COALESCE(updated_at,0) t FROM club_peer_reviews WHERE to_user=?
    ORDER BY t DESC LIMIT 30`).all(uid, uid);
  const adj = { 5: 2, 4: 1, 3: 0, 2: -2, 1: -4 };
  let s = 80;
  rows.forEach(r => { s += adj[r.stars] || 0; });
  return { score: Math.max(0, Math.min(100, s)), reviews: rows.length };
}
app.get('/me/fairplay', auth, (req, res) => res.json(fairplayOf(req.uid)));
app.get('/open-matches', (req, res) => {
  const uid = tryUid(req);
  const { sport, sido, sigungu } = req.query;
  const where = ["(status IS NULL OR status!='cancelled')"];
  const args = [];
  if (sport)   { where.push('sport=?');   args.push(sport); }
  if (sido)    { where.push('sido=?');    args.push(sido); }
  if (sigungu) { where.push('sigungu=?'); args.push(sigungu); }
  const rows = db.prepare(`SELECT * FROM open_matches WHERE ${where.join(' AND ')}
    ORDER BY id DESC LIMIT 50`).all(...args);
  const fpCache = {};
  res.json(rows.map(m => {
    const v = omView(m, uid);
    if (m.host_id) {
      if (!fpCache[m.host_id]) fpCache[m.host_id] = fairplayOf(m.host_id);
      v.host_fp = fpCache[m.host_id].score;
      v.host_fp_n = fpCache[m.host_id].reviews;
    }
    return v;
  }));
});

// 주최자가 자기 매치를 삭제한다 (참가자 알림 후 완전 삭제)
app.delete('/open-matches/:id', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid) return res.status(403).json({ error: 'host_only' });
  db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(m.id)
    .forEach(p => { if (p.user_id !== req.uid) sendPush(p.user_id, { icon: '🗑️', title: '오픈매치가 삭제됐어요', body: `${m.dt} · ${m.loc}` }); });
  db.prepare('DELETE FROM open_match_joins WHERE match_id=?').run(m.id);
  db.prepare('DELETE FROM open_matches WHERE id=?').run(m.id);
  res.json({ ok: true });
});
try { db.exec('ALTER TABLE open_matches ADD COLUMN courts INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE open_matches ADD COLUMN court_cost INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE open_match_joins ADD COLUMN joined_at TEXT'); } catch (e) {}
/* 소셜 매치 요금 공식 — 구장 총액 1/n + 운영비(매니저·공·수수료) 9,000원, 500원 올림 */
const OM_SVC = 11000;                                     // 인당 서비스요금 (쉐어 기준가의 원천)
function omFee(courtCost, cap) {
  if (!cap) return 0;
  // 참가비 = 코트비 1/N + 서비스요금 11,000원
  // 쉐어 기준가 S = 11,000 × 정원 → 플랫폼 30% 이상 · 일반 매니저 15% · 파트너 45%(≈9만) · 볼값·PG 실비
  return Math.ceil((+courtCost || 0) / cap / 500) * 500 + OM_SVC;
}
app.post('/open-matches', auth, (req, res) => {
  const _b = req.body || {};
  let _courts = Math.min(3, Math.max(0, +_b.courts || 0));
  if (_courts) {                                          // 코트 기반 소셜 매치 규칙
    _courts = 3;                                          // 3코트 전용 (2h 12명 · 3h 18명)
    const _hours = (+_b.hours === 2) ? 2 : 3;             // 2·3시간만
    _b.courts = _courts;
    _b.cap = _courts * (_hours === 2 ? 4 : 6);            // 2시간 코트당 4명 · 3시간 코트당 6명 (로테이션 시간 기준)
    _b.min_cnt = _b.cap;                                  // 전원 모여야 확정
    _b.price = omFee(+_b.court_cost || 0, _b.cap);        // 가격은 서버가 산정 (신뢰 지점)
    if (_b.start_at) {                                    // 로컬 벽시계 그대로 +N시간 (서버 TZ 영향 제거)
      const mm = String(_b.start_at).match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
      if (mm) {
        const d0 = new Date(Date.UTC(+mm[1], +mm[2] - 1, +mm[3], +mm[4] + _hours, +mm[5]));
        _b.end_at = d0.toISOString().slice(0, 16);        // "YYYY-MM-DDTHH:mm" — start_at과 같은 나이브 포맷
      }
    }
    _b.account = null;                                    // 현장 계좌 입금 제거 — 앱 결제로 일원화
    req.body = _b;
    req._autoManager = true;                              // 개설자 = 매니저 (지원·지정 없음)
    // 일반 매니저 수고비 = 시간당 10,320원(최저시급 연동, 쉐어 기준가의 약 15.6%) · 파트너 40%는 다음 업데이트
    // 캔볼값은 클라이언트가 코트비에 합산해 보내므로 court_cost 환급에 포함된다
    // 매니저 = 이 매치의 개설자 1명뿐 · 다른 매치에 참가자로 들어가면 그 매치 정산과는 무관하다
    req._mgrPay = 10320 * _hours;
  }
  const { sport, dt, loc, fmt, gd, price, cap, min_cnt, note, start_at, end_at, sido, sigungu, dong, account } = req.body || {};
  if (!dt || !loc) return res.status(400).json({ error: 'dt_loc_required' });
  if (start_at && end_at && new Date(end_at) <= new Date(start_at))
    return res.status(400).json({ error: 'end_before_start' });
  const bad = findContact(`${loc} ${note || ''} ${dong || ''}`);   // 공개 모집글이므로 연락처 차단
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  const r = db.prepare(`INSERT INTO open_matches (sport,dt,loc,fmt,gd,price,cap,min_cnt,created_at,host_id,status,note,start_at,end_at,sido,sigungu,dong,account, courts, court_cost) VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,?, ?, ?)`)
    .run(sport || 'tennis', dt, loc, fmt || '단식', gd || '남자부', intOrNull(price) || 0,
         intOrNull(cap) || 8, intOrNull(min_cnt) || 6, now(), req.uid, note || '',
         start_at || null, end_at || null, sido || null, sigungu || null, dong || null,
         String(account || '').trim().slice(0, 60) || null, intOrNull(req.body.courts), intOrNull(req.body.court_cost));
  if (req._autoManager) {                                 // 매니저 정산액 = 구장·볼값 환급(당일) + 수고비(시간당 10,320원)
    db.prepare('UPDATE open_matches SET manager_id=?, manager_fee=? WHERE id=?')
      .run(req.uid, (intOrNull(req.body.court_cost) || 0) + (req._mgrPay || 20000), rid(r));
  }
  const mid = rid(r);
  // 매니저는 운영만 하고 경기에 참여하지 않는다 — 자동 참가 없음
  res.json(omView(db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid), req.uid));
});
app.post('/open-matches/:id/join', auth, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.status && m.status !== 'open') return res.status(400).json({ error: 'not_open' });
  const ns = noShowCount(req.uid);                       // 상습 노쇼는 참가를 막는다
  if (ns >= NOSHOW_LIMIT) return res.status(403).json({ error: 'noshow_blocked', count: ns, limit: NOSHOW_LIMIT });
  // 두 사람이 마지막 한 자리에 동시에 신청해도 정원을 넘기지 않도록 잠근다
  try {
    tx(() => {
      const cur = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n;
      const already = db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid);
      if (!already && cur >= (m.cap || 8)) throw new Error('full');
      db.prepare('INSERT OR IGNORE INTO open_match_joins (match_id,user_id,joined_at) VALUES (?,?,?)').run(mid, req.uid, now());
    });
  } catch (e) {
    if (e.message === 'full') return res.status(409).json({ error: 'full', cap: m.cap });
    throw e;
  }
  const isNewJoin = db.prepare('SELECT joined_at FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid).joined_at > now() - 3000;

  const after = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n;
  if (isNewJoin && m.host_id && m.host_id !== req.uid)
    sendPush(m.host_id, { icon: '🙋', title: '오픈매치 참가 신청', body: `${getUser(req.uid).name} 님 · ${after}/${m.cap}명` });
  // 최소 인원을 막 채웠으면 전원에게 성사 알림 (내 신청으로 정확히 채워진 경우)
  if (isNewJoin && after === (m.min_cnt || 0)) {
    db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(mid)
      .forEach(p => sendPush(p.user_id, { icon: '✅', title: '경기가 성사됐어요', body: `${m.dt} · ${m.loc} · ${after}명` }));
  }
  res.json(omView(db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid), req.uid));
});
// ══════════════════════════════════════════════════════════════
//  출석 · 노쇼
//  status: going(참석) / absent(불참) / undecided(미정)
//  showed: 1(왔음) / 0(노쇼) / null(아직 체크 안 함)
// ══════════════════════════════════════════════════════════════
try { db.exec("ALTER TABLE event_attendees ADD COLUMN showed INTEGER"); } catch (e) {}
try { db.exec("ALTER TABLE event_attendees ADD COLUMN checked_at BIGINT"); } catch (e) {}

// 모임의 참석 현황 (임원은 출석 체크 가능)
app.get('/events/:id/attendance', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = db.prepare('SELECT * FROM club_events WHERE id=?').get(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  if (!isMember(ev.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(ev.club_id, req.uid);
  const rows = db.prepare(`SELECT ea.user_id, u.name, ea.status, ea.showed
    FROM event_attendees ea JOIN users u ON u.id=ea.user_id
    WHERE ea.event_id=? ORDER BY u.name`).all(eid);
  res.json({
    event: { id: ev.id, title: ev.title, date: ev.date },
    is_officer: !!(m && ['owner', 'officer'].includes(m.role)),
    rows,
  });
});

// 출석 체크 (임원만). showed=1 왔음, 0 노쇼
app.patch('/events/:eid/attendance/:uid', auth, (req, res) => {
  const eid = +req.params.eid, target = +req.params.uid;
  const ev = db.prepare('SELECT * FROM club_events WHERE id=?').get(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(ev.club_id, req.uid);
  if (!m || !['owner', 'officer'].includes(m.role)) return res.status(403).json({ error: 'officer_only' });
  const v = (req.body || {}).showed;
  const showed = v === null ? null : (v ? 1 : 0);
  const has = db.prepare('SELECT id FROM event_attendees WHERE event_id=? AND user_id=?').get(eid, target);
  if (!has) db.prepare('INSERT INTO event_attendees (event_id,user_id,status) VALUES (?,?,?)').run(eid, target, 'going');
  db.prepare('UPDATE event_attendees SET showed=?, checked_at=? WHERE event_id=? AND user_id=?')
    .run(showed, now(), eid, target);
  if (showed === 0) {                                  // 노쇼 누적을 본인에게 알려 공정하게
    const n = noShowCount(target);
    if (n === NOSHOW_LIMIT - 1) sendPush(target, { icon: '⚠️', title: `노쇼가 ${n}회 기록됐어요`,
      body: `한 번 더 기록되면 오픈매치 참가가 90일간 제한돼요` });
    else if (n >= NOSHOW_LIMIT) sendPush(target, { icon: '🚫', title: '오픈매치 참가가 제한됐어요',
      body: `최근 90일 노쇼 ${n}회 · 기록이 지나면 자동으로 풀려요` });
  }
  res.json({ ok: true, user_id: target, showed });
});

// 회원별 누적 출석/노쇼 (클럽 랭킹·신뢰도에 쓴다)
app.get('/clubs/:id/attendance/summary', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT u.id user_id, u.name,
      SUM(CASE WHEN ea.showed=1 THEN 1 ELSE 0 END) attended,
      SUM(CASE WHEN ea.showed=0 THEN 1 ELSE 0 END) noshow,
      SUM(CASE WHEN ea.status='going' THEN 1 ELSE 0 END) signed_up
    FROM club_members cm JOIN users u ON u.id=cm.user_id
    LEFT JOIN event_attendees ea ON ea.user_id=u.id
      AND ea.event_id IN (SELECT id FROM club_events WHERE club_id=?)
    WHERE cm.club_id=? AND cm.role!='guest'
    GROUP BY u.id ORDER BY attended DESC, noshow ASC`).all(cid, cid);
  res.json(rows);
});


// ══════════════════════════════════════════════════════════════
//  계정 탈퇴 — 개인정보는 지우고, 클럽 기록(회비·전적)은 익명으로 남긴다
//  (장부 무결성을 위해 행 자체는 유지하되 누구인지 알 수 없게)
// ══════════════════════════════════════════════════════════════
// 내 신청 내역 — 프로필에서 확인 (게스트 신청 · 내가 연 오픈매치 · 참가한 오픈매치)
app.get('/me/applications', auth, (req, res) => {
  const me = getUser(req.uid);
  const guest = db.prepare(`SELECT g.id, g.created_at, e.title, e.date, c.name club
    FROM event_guests g JOIN club_events e ON e.id=g.event_id JOIN clubs c ON c.id=e.club_id
    WHERE g.user_id=? OR (g.user_id IS NULL AND g.name=?)
    ORDER BY g.id DESC LIMIT 20`).all(req.uid, me ? me.name : '');
  const hosted = db.prepare(`SELECT id, title, date, place, joined, cap, status
    FROM open_matches WHERE host_id=? ORDER BY id DESC LIMIT 20`).all(req.uid);
  let joined = [];
  try {
    joined = db.prepare(`SELECT m.id, m.title, m.date, m.place, m.status
      FROM open_match_joins j JOIN open_matches m ON m.id=j.match_id
      WHERE j.user_id=? ORDER BY j.id DESC LIMIT 20`).all(req.uid);
  } catch (e) { /* joins 테이블 없으면 생략 */ }
  res.json({ guest, hosted, joined });
});

app.delete('/me', auth, (req, res) => {
  try {
    const u = getUser(req.uid);
    db.prepare("SELECT club_id FROM club_members WHERE user_id=? AND (status IS NULL OR status='active')").all(req.uid)
      .forEach(r => db.prepare('INSERT INTO member_exits (club_id,user_id,name,reason,left_at) VALUES (?,?,?,?,?)')
        .run(r.club_id, req.uid, u ? u.name : '', '계정 탈퇴', now()));
  } catch (e) {}

  const uid = req.uid;
  // 클럽장은 넘기고 나가야 한다 — 클럽이 주인 없이 남으면 안 된다
  const owned = db.prepare("SELECT c.name FROM club_members m JOIN clubs c ON c.id=m.club_id WHERE m.user_id=? AND m.role='owner'").all(uid);
  if (owned.length) {
    const others = owned.filter(o => db.prepare(`SELECT COUNT(*) n FROM club_members m
      JOIN clubs c ON c.id=m.club_id WHERE c.name=? AND m.user_id<>?`).get(o.name, uid).n > 0);
    if (others.length) return res.status(400).json({ error: 'owner_must_transfer', clubs: others.map(o => o.name) });
  }
  tx(() => {
    // 회원 혼자인 클럽은 함께 정리
    db.prepare(`DELETE FROM clubs WHERE owner_id=? AND
      (SELECT COUNT(*) FROM club_members WHERE club_id=clubs.id AND user_id<>?)=0`).run(uid, uid);
    db.prepare('DELETE FROM club_members WHERE user_id=?').run(uid);
    db.prepare('DELETE FROM devices WHERE user_id=?').run(uid);          // 푸시 구독 파기
    db.prepare('DELETE FROM dms WHERE from_id=? OR to_id=?').run(uid, uid);   // 대화 파기
    db.prepare('DELETE FROM open_match_joins WHERE user_id=?').run(uid);
    db.prepare("UPDATE open_matches SET status='closed' WHERE host_id=? AND status='open'").run(uid);
    db.prepare('DELETE FROM notifications WHERE user_id=?').run(uid);
    // 사용자 행은 익명화 — 라운지 글·전적·회비 행이 참조 무결성을 잃지 않게
    db.prepare(`UPDATE users SET
        name='탈퇴한 회원', provider=NULL, provider_id=NULL, phone=NULL,
        gender=NULL, region=NULL, exp=NULL, anon_nick='탈퇴한 회원',
        cash=0, suspended=1, token_version=COALESCE(token_version,0)+1
      WHERE id=?`).run(uid);
  });
  res.json({ ok: true });
});

// ── 모든 기기에서 로그아웃 (폰 분실 대비) ──
try { db.exec('ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0'); } catch {}

app.post('/me/logout-all', auth, (req, res) => {
  db.prepare('UPDATE users SET token_version = COALESCE(token_version,0) + 1 WHERE id=?').run(req.uid);
  const u = getUser(req.uid);
  res.json({ ok: true, token: sign(u) });        // 지금 기기만 새 토큰으로 살려둔다
});


// ══════════════════════════════════════════════════════════════
//  클럽 탈퇴 · 강퇴 · 임원 임명
// ══════════════════════════════════════════════════════════════
app.delete('/clubs/:id/leave', auth, (req, res) => {
  const cid = +req.params.id;
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (!m) return res.status(404).json({ error: 'not_member' });
  if (m.role === 'owner') {
    const others = db.prepare("SELECT COUNT(*) n FROM club_members WHERE club_id=? AND user_id<>?").get(cid, req.uid).n;
    if (others > 0) return res.status(400).json({ error: 'owner_must_transfer' });   // 넘기고 나가야 한다
  }
  const unpaid = db.prepare("SELECT COUNT(*) n FROM dues WHERE club_id=? AND user_id=? AND status='unpaid'").get(cid, req.uid).n;
  db.prepare('DELETE FROM club_members WHERE club_id=? AND user_id=?').run(cid, req.uid);
  if (m.role === 'owner') db.prepare('DELETE FROM clubs WHERE id=?').run(cid);       // 마지막 사람이면 클럽도 정리
  res.json({ ok: true, unpaid_left: unpaid });
});

app.delete('/clubs/:id/members/:uid', auth, (req, res) => {
  const cid = +req.params.id, target = +req.params.uid;
  const me = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (!me || !['owner', 'officer'].includes(me.role)) return res.status(403).json({ error: 'officer_only' });
  const t = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, target);
  if (!t) return res.status(404).json({ error: 'not_member' });
  if (t.role === 'owner') return res.status(403).json({ error: 'cannot_kick_owner' });
  if (t.role === 'officer' && me.role !== 'owner') return res.status(403).json({ error: 'owner_only' });
  { const u = getUser(target);
    db.prepare('INSERT INTO member_exits (club_id,user_id,name,reason,left_at) VALUES (?,?,?,?,?)')
      .run(cid, target, u ? u.name : '', '탈퇴', now()); }
  db.prepare('DELETE FROM club_members WHERE club_id=? AND user_id=?').run(cid, target);
  const c = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  sendPush(target, { icon: '👋', title: '클럽에서 나가게 되었어요', body: `${c ? c.name : '클럽'} · 임원이 회원을 정리했어요` });
  res.json({ ok: true });
});

app.post('/clubs/:id/members/:uid/role', auth, (req, res) => {
  const cid = +req.params.id, target = +req.params.uid;
  const me = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (!me || me.role !== 'owner') return res.status(403).json({ error: 'owner_only' });
  const role = (req.body || {}).role;
  if (!['member', 'officer', 'owner'].includes(role)) return res.status(400).json({ error: 'bad_role' });
  if (role === 'owner') {                                     // 클럽장 넘기기
    db.prepare("UPDATE club_members SET role='member' WHERE club_id=? AND user_id=?").run(cid, req.uid);
    db.prepare('UPDATE clubs SET owner_id=? WHERE id=?').run(target, cid);
  }
  db.prepare('UPDATE club_members SET role=? WHERE club_id=? AND user_id=?').run(role, cid, target);
  sendPush(target, { icon: '⭐', title: role === 'owner' ? '클럽장이 되었어요' : role === 'officer' ? '임원이 되었어요' : '임원에서 내려왔어요', body: '' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  노쇼 제재 — 최근 90일간 3회 이상이면 오픈매치 참가를 막는다
// ══════════════════════════════════════════════════════════════
const NOSHOW_LIMIT = 3;
const NOSHOW_WINDOW = 90 * 24 * 3600 * 1000;
function noShowCount(uid) {
  const since = now() - NOSHOW_WINDOW;
  return db.prepare(`SELECT COUNT(*) n FROM event_attendees ea
    JOIN club_events e ON e.id=ea.event_id
    WHERE ea.user_id=? AND ea.showed=0 AND e.created_at > ?`).get(uid, since).n;
}
app.get('/me/noshow', auth, (req, res) => {
  const n = noShowCount(req.uid);
  res.json({ count: n, limit: NOSHOW_LIMIT, blocked: n >= NOSHOW_LIMIT });
});

// ══════════════════════════════════════════════════════════════
//  클럽 피드 (사진·글)
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS club_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  body TEXT,
  photo TEXT,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_club_posts ON club_posts(club_id, id DESC);`);

// 피드 확장 — 제목 · 앨범(여러 장) · 좋아요 · 댓글
try { db.exec('ALTER TABLE club_posts ADD COLUMN title TEXT'); } catch (e) { /* 이미 있음 */ }
try { db.exec('ALTER TABLE club_posts ADD COLUMN photos TEXT'); } catch (e) { /* 이미 있음 */ }
db.exec(`CREATE TABLE IF NOT EXISTS feed_likes (
  post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, UNIQUE(post_id, user_id)
);
CREATE TABLE IF NOT EXISTS feed_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  body TEXT NOT NULL, created_at BIGINT
);`);

app.get('/clubs/:id/feed', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT p.*, u.name author FROM club_posts p
    JOIN users u ON u.id=p.user_id WHERE p.club_id=? ORDER BY p.id DESC LIMIT 50`).all(cid);
  const nLikes = db.prepare('SELECT COUNT(*) n FROM feed_likes WHERE post_id=?');
  const myLike = db.prepare('SELECT 1 FROM feed_likes WHERE post_id=? AND user_id=?');
  const nCmts  = db.prepare('SELECT COUNT(*) n FROM feed_comments WHERE post_id=?');
  res.json(rows.map(p => ({ ...p,
    likes: nLikes.get(p.id).n, liked: !!myLike.get(p.id, req.uid),
    comments: nCmts.get(p.id).n, mine: p.user_id === req.uid })));
});

app.post('/clubs/:id/feed', auth, limitWrite, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const title = String((req.body || {}).title || '').trim().slice(0, 60);
  const body = String((req.body || {}).body || '').trim();
  let photos = (req.body || {}).photos;
  photos = Array.isArray(photos) ? photos.filter(u => typeof u === 'string').slice(0, 10) : [];
  const photo = photos[0] || String((req.body || {}).photo || '').trim() || null;
  if (!title && !body && !photo) return res.status(400).json({ error: 'empty' });
  const bad = findContact(title + ' ' + body);
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  const r = db.prepare('INSERT INTO club_posts (club_id,user_id,title,body,photo,photos,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(cid, req.uid, title || null, body, photo, JSON.stringify(photos), now());
  res.json({ ok: true, id: rid(r) });
});

app.post('/feed/:id/like', auth, (req, res) => {         // 좋아요 토글
  const pid = +req.params.id;
  const p = db.prepare('SELECT club_id FROM club_posts WHERE id=?').get(pid);
  if (!p || !isMember(p.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  const has = db.prepare('SELECT 1 FROM feed_likes WHERE post_id=? AND user_id=?').get(pid, req.uid);
  if (has) db.prepare('DELETE FROM feed_likes WHERE post_id=? AND user_id=?').run(pid, req.uid);
  else db.prepare('INSERT INTO feed_likes (post_id,user_id) VALUES (?,?)').run(pid, req.uid);
  res.json({ ok: true, liked: !has,
    likes: db.prepare('SELECT COUNT(*) n FROM feed_likes WHERE post_id=?').get(pid).n });
});

app.get('/feed/:id/comments', auth, (req, res) => {
  const pid = +req.params.id;
  const p = db.prepare('SELECT club_id FROM club_posts WHERE id=?').get(pid);
  if (!p || !isMember(p.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  res.json(db.prepare(`SELECT c.id, c.body, c.created_at, c.user_id, u.name FROM feed_comments c
    JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id`).all(pid)
    .map(c => ({ ...c, mine: c.user_id === req.uid })));
});

app.post('/feed/:id/comments', auth, limitWrite, (req, res) => {
  const pid = +req.params.id;
  const p = db.prepare('SELECT club_id, user_id FROM club_posts WHERE id=?').get(pid);
  if (!p || !isMember(p.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  const body = String((req.body || {}).body || '').trim().slice(0, 300);
  if (!body) return res.status(400).json({ error: 'empty' });
  const bad = findContact(body);
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  db.prepare('INSERT INTO feed_comments (post_id,user_id,body,created_at) VALUES (?,?,?,?)')
    .run(pid, req.uid, body, now());
  if (p.user_id !== req.uid) {                          // 글쓴이에게 알림
    const me = getUser(req.uid);
    sendPush(p.user_id, { icon: '💬', title: '내 소식에 댓글이 달렸어요', body: `${me.name}: ${body.slice(0, 40)}`, link: `feed:${pid}` });
  }
  res.json({ ok: true });
});

app.delete('/clubs/:cid/feed/:id', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM club_posts WHERE id=?').get(+req.params.id);
  if (!p) return res.status(404).json({ error: 'not_found' });
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(p.club_id, req.uid);
  const can = p.user_id === req.uid || (m && ['owner', 'officer'].includes(m.role));
  if (!can) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('DELETE FROM club_posts WHERE id=?').run(p.id);
  removePhoto(p.photo);                                  // 디스크에 남기지 않는다
  res.json({ ok: true });
});

/* 업로드 폴더 안의 파일만 지운다. 경로 조작(../)을 막는다. */
function removePhoto(url) {
  if (!url || !url.startsWith('/uploads/')) return;
  const name = path.basename(url);
  const p = path.join(UPLOAD_DIR, name);
  if (!p.startsWith(path.resolve(UPLOAD_DIR))) return;
  try { fs.unlinkSync(p); } catch {}
}

// ══════════════════════════════════════════════════════════════
//  내가 쓴 글
// ══════════════════════════════════════════════════════════════
app.get('/me/posts', auth, (req, res) => {
  res.json({
    lounge: db.prepare(`SELECT id,title,body,category,sport,likes,created_at,hidden,
        (SELECT COUNT(*) FROM comments WHERE post_id=posts.id AND hidden=0) comments
      FROM posts WHERE user_id=? ORDER BY id DESC LIMIT 50`).all(req.uid),
    comments: db.prepare(`SELECT c.id, c.body, c.created_at, p.id post_id, p.title post_title
      FROM comments c JOIN posts p ON p.id=c.post_id
      WHERE c.user_id=? AND c.hidden=0 ORDER BY c.id DESC LIMIT 50`).all(req.uid),
    club_feed: db.prepare(`SELECT cp.id, cp.body, cp.photo, cp.created_at, c.name club_name
      FROM club_posts cp JOIN clubs c ON c.id=cp.club_id
      WHERE cp.user_id=? ORDER BY cp.id DESC LIMIT 50`).all(req.uid),
  });
});

// ══════════════════════════════════════════════════════════════
//  클럽 리그 참가
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS club_league (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL,
  sport TEXT NOT NULL,
  division TEXT DEFAULT '3부',
  w INTEGER DEFAULT 0, l INTEGER DEFAULT 0, pt INTEGER DEFAULT 0,
  joined_at BIGINT NOT NULL,
  UNIQUE(club_id, sport)
);`);

app.get('/club-league', (req, res) => {
  const sport = req.query.sport || 'tennis';
  res.json(db.prepare(`SELECT cl.*, c.name, c.region FROM club_league cl
    JOIN clubs c ON c.id=cl.club_id WHERE cl.sport=?
    ORDER BY cl.pt DESC, cl.w DESC, c.name`).all(sport));
});

// 클럽장·임원만 참가 신청
app.post('/clubs/:id/league', auth, (req, res) => {
  const cid = +req.params.id;
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (!m || !['owner', 'officer'].includes(m.role)) return res.status(403).json({ error: 'officer_only' });
  const c = db.prepare('SELECT * FROM clubs WHERE id=?').get(cid);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const sport = (req.body || {}).sport || c.sport || 'tennis';
  const has = db.prepare('SELECT id FROM club_league WHERE club_id=? AND sport=?').get(cid, sport);
  if (has) return res.status(409).json({ error: 'already_joined' });
  db.prepare('INSERT INTO club_league (club_id,sport,joined_at) VALUES (?,?,?)').run(cid, sport, now());
  notifyClub(cid, req.uid, '🏆', '클럽 리그에 참가했어요', `${c.name} · ${sport}`);
  res.json({ ok: true });
});

app.delete('/clubs/:id/league', auth, (req, res) => {
  const cid = +req.params.id;
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (!m || !['owner', 'officer'].includes(m.role)) return res.status(403).json({ error: 'officer_only' });
  const sport = req.query.sport || 'tennis';
  db.prepare('DELETE FROM club_league WHERE club_id=? AND sport=?').run(cid, sport);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  클럽 공지사항
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS notices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  pinned INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_notices_club ON notices(club_id, id DESC);`);
try { db.exec('ALTER TABLE notices ADD COLUMN popup_days INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE notices ADD COLUMN poll TEXT'); } catch (e) {}
db.exec(`CREATE TABLE IF NOT EXISTS notice_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, notice_id INTEGER, user_id INTEGER,
  choice INTEGER, answer TEXT, created_at INTEGER, UNIQUE(notice_id, user_id))`);

app.get('/clubs/:id/notices', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT n.*, u.name author FROM notices n
    JOIN users u ON u.id=n.author_id WHERE n.club_id=?
    ORDER BY n.pinned DESC, n.id DESC LIMIT 50`).all(cid);
  {
    const cnt = db.prepare('SELECT choice, COUNT(*) n FROM notice_votes WHERE notice_id=? AND choice IS NOT NULL GROUP BY choice');
    const mineQ = db.prepare('SELECT choice, answer FROM notice_votes WHERE notice_id=? AND user_id=?');
    const answersQ = db.prepare(`SELECT v.answer, u.name FROM notice_votes v JOIN users u ON u.id=v.user_id
      WHERE v.notice_id=? AND v.answer IS NOT NULL ORDER BY v.id DESC LIMIT 50`);
    res.json(rows.map(n => {
      let poll = null;
      if (n.poll) {
        try { poll = JSON.parse(n.poll); } catch (e) {}
        if (poll) {
          const mine = mineQ.get(n.id, req.uid);
          if (poll.type === 'choice') {
            const counts = Array(poll.options.length).fill(0);
            cnt.all(n.id).forEach(r => { if (counts[r.choice] !== undefined) counts[r.choice] = r.n; });
            poll.counts = counts; poll.total = counts.reduce((a, b) => a + b, 0);
            poll.myChoice = mine ? mine.choice : null;
          } else {
            poll.answers = answersQ.all(n.id);
            poll.myAnswer = mine ? mine.answer : null;
            poll.total = poll.answers.length;
          }
        }
      }
      return { ...n, poll };
    }));
  }
});

app.post('/clubs/:id/notices', auth, (req, res) => {
  const cid = +req.params.id;
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (!m || !['owner', 'officer'].includes(m.role)) return res.status(403).json({ error: 'officer_only' });
  const body = String((req.body || {}).body || '').trim();
  if (!body) return res.status(400).json({ error: 'empty' });
  const bad = findContact(body);                       // 공지도 공개글이다
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  let poll = null;
  const pb = req.body.poll;
  if (pb && typeof pb === 'object' && ['choice', 'text'].includes(pb.type)) {
    if (pb.type === 'choice') {
      const opts = (Array.isArray(pb.options) ? pb.options : []).map(o => String(o).trim().slice(0, 40)).filter(Boolean).slice(0, 8);
      if (opts.length >= 2) poll = JSON.stringify({ q: String(pb.q || '').slice(0, 80), type: 'choice', options: opts });
    } else poll = JSON.stringify({ q: String(pb.q || '').slice(0, 80), type: 'text' });
  }
  const popupDays = Math.max(0, Math.min(14, intOrNull(req.body.popup_days) || 0));
  const r = db.prepare('INSERT INTO notices (club_id,author_id,body,pinned,created_at,popup_days,poll) VALUES (?,?,?,?,?,?,?)')
    .run(cid, req.uid, body, intOrNull(req.body.pinned) ? 1 : 0, now(), popupDays, poll);
  notifyClub(cid, req.uid, '📢', '새 공지가 올라왔어요', body.slice(0, 40));
  res.json({ ok: true, id: rid(r) });
});

// 공지 투표 (회원 · 1인 1표, 다시 누르면 변경)
app.post('/notices/:id/vote', auth, (req, res) => {
  const n = db.prepare('SELECT * FROM notices WHERE id=?').get(+req.params.id);
  if (!n || !n.poll) return res.status(404).json({ error: 'no_poll' });
  if (!isMember(n.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  let poll; try { poll = JSON.parse(n.poll); } catch (e) { return res.status(400).json({ error: 'bad_poll' }); }
  const b = req.body || {};
  let choice = null, answer = null;
  if (poll.type === 'choice') {
    choice = intOrNull(b.choice);
    if (choice == null || choice < 0 || choice >= poll.options.length) return res.status(400).json({ error: 'bad_choice' });
  } else {
    answer = String(b.answer || '').trim().slice(0, 120);
    if (!answer) return res.status(400).json({ error: 'empty' });
  }
  db.prepare(`INSERT INTO notice_votes (notice_id,user_id,choice,answer,created_at) VALUES (?,?,?,?,?)
    ON CONFLICT(notice_id,user_id) DO UPDATE SET choice=excluded.choice, answer=excluded.answer, created_at=excluded.created_at`)
    .run(n.id, req.uid, choice, answer, now());
  res.json({ ok: true });
});

app.delete('/notices/:id', auth, (req, res) => {
  const n = db.prepare('SELECT * FROM notices WHERE id=?').get(+req.params.id);
  if (!n) return res.status(404).json({ error: 'not_found' });
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(n.club_id, req.uid);
  const canDelete = n.author_id === req.uid || (m && ['owner', 'officer'].includes(m.role));
  if (!canDelete) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('DELETE FROM notices WHERE id=?').run(n.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  오픈매치 — 클럽 밖에서 사람을 모아 경기를 잡는다.
//  참가비는 앱이 받지 않는다(회비와 동일 원칙). 주최자가 현장에서 정산.
//  노쇼가 실제 문제가 되면 그때 예약금(PG)을 붙인다.
// ══════════════════════════════════════════════════════════════
['host_id INTEGER', 'status TEXT DEFAULT \'open\'', 'note TEXT',
 'start_at TEXT', 'end_at TEXT', 'sido TEXT', 'sigungu TEXT', 'dong TEXT',
 'account TEXT'].forEach(c => {
  try { db.exec(`ALTER TABLE open_matches ADD COLUMN ${c}`); } catch (e) {}
});
try { db.exec('ALTER TABLE open_match_joins ADD COLUMN joined_at BIGINT'); } catch (e) {}


// ── 오픈매치 좋아요 · 댓글 ──
db.exec(`CREATE TABLE IF NOT EXISTS om_likes (
  match_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  UNIQUE(match_id, user_id)
);
CREATE TABLE IF NOT EXISTS om_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  match_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  body TEXT NOT NULL, created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_omc ON om_comments(match_id, id);`);

app.post('/open-matches/:id/like', auth, (req, res) => {
  const mid = +req.params.id;
  if (!db.prepare('SELECT id FROM open_matches WHERE id=?').get(mid)) return res.status(404).json({ error: 'not_found' });
  const has = db.prepare('SELECT 1 FROM om_likes WHERE match_id=? AND user_id=?').get(mid, req.uid);
  if (has) db.prepare('DELETE FROM om_likes WHERE match_id=? AND user_id=?').run(mid, req.uid);
  else db.prepare('INSERT INTO om_likes (match_id,user_id) VALUES (?,?)').run(mid, req.uid);
  const n = db.prepare('SELECT COUNT(*) n FROM om_likes WHERE match_id=?').get(mid).n;
  res.json({ ok: true, liked: !has, likes: n });
});

app.get('/open-matches/:id/comments', (req, res) => {
  res.json(db.prepare(`SELECT c.id, c.user_id, c.body, c.created_at, u.name
    FROM om_comments c JOIN users u ON u.id=c.user_id
    WHERE c.match_id=? ORDER BY c.id LIMIT 100`).all(+req.params.id));
});

app.post('/open-matches/:id/comments', auth, limitWrite, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const body = String((req.body || {}).body || '').trim().slice(0, 300);
  if (!body) return res.status(400).json({ error: 'empty' });
  const bad = findContact(body);                        // 댓글도 공개글이다
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  const r = db.prepare('INSERT INTO om_comments (match_id,user_id,body,created_at) VALUES (?,?,?,?)')
    .run(mid, req.uid, body, now());
  if (m.host_id && m.host_id !== req.uid) {             // 주최자에게 알림
    const who = getUser(req.uid);
    sendPush(m.host_id, { icon: '💬', title: '오픈매치에 댓글이 달렸어요', body: `${who.name}: ${body.slice(0, 40)}` });
  }
  res.json({ ok: true, id: rid(r) });
});

app.delete('/om-comments/:id', auth, (req, res) => {
  const c = db.prepare('SELECT * FROM om_comments WHERE id=?').get(+req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const m = db.prepare('SELECT host_id FROM open_matches WHERE id=?').get(c.match_id);
  if (c.user_id !== req.uid && (!m || m.host_id !== req.uid)) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('DELETE FROM om_comments WHERE id=?').run(c.id);
  res.json({ ok: true });
});

function omView(m, uid) {
  const joins = db.prepare(`SELECT j.user_id, u.name, u.rating, u.gender FROM open_match_joins j
    JOIN users u ON u.id=j.user_id WHERE j.match_id=? ORDER BY j.id`).all(m.id);
  const host = m.host_id ? db.prepare('SELECT id,name FROM users WHERE id=?').get(m.host_id) : null;
  const likes = db.prepare('SELECT COUNT(*) n FROM om_likes WHERE match_id=?').get(m.id).n;
  const liked = uid ? !!db.prepare('SELECT 1 FROM om_likes WHERE match_id=? AND user_id=?').get(m.id, uid) : false;
  const comments = db.prepare('SELECT COUNT(*) n FROM om_comments WHERE match_id=?').get(m.id).n;
  const manager = m.manager_id ? db.prepare('SELECT id,name FROM users WHERE id=?').get(m.manager_id) : null;
  const mgr_applied = uid ? !!db.prepare('SELECT 1 FROM om_manager_apps WHERE match_id=? AND user_id=?').get(m.id, uid) : false;
  const mgr_apps = (uid && m.host_id === uid && !m.manager_id)
    ? db.prepare('SELECT a.user_id id, u.name FROM om_manager_apps a JOIN users u ON u.id=a.user_id WHERE a.match_id=? ORDER BY a.id').all(m.id) : [];
  const my_mreview = uid ? db.prepare('SELECT match_r,manager_r,venue_r,note FROM om_match_reviews WHERE match_id=? AND user_id=?').get(m.id, uid) : null;
  return {
    ...m,
    host, likes, liked, comments,
    manager, manager_fee: m.manager_fee || 0, settled: !!m.settled, mgr_applied, mgr_apps, my_mreview,
    bracket: (()=>{ try { return m.bracket ? JSON.parse(m.bracket) : null; } catch (e) { return null; } })(),
    photos: (()=>{ try { const p = m.photos ? JSON.parse(m.photos) : null; return Array.isArray(p) && p.length ? p : (m.photo ? [m.photo] : []); } catch (e) { return m.photo ? [m.photo] : []; } })(),
    cur: joins.length,
    players: joins.map(j => ({ id: j.user_id, name: j.name, rating: j.rating, gender: j.gender || '' })),
    joined: uid ? joins.some(j => j.user_id === uid) : false,
    is_host: uid ? m.host_id === uid : false,
    confirmed: joins.length >= (m.min_cnt || 0),
    full: joins.length >= (m.cap || 0),
  };
}

app.get('/open-matches/:id', (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  res.json(omView(m, tryUid(req)));
});

// 참가 취소
app.delete('/open-matches/:id/join', auth, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id === req.uid) return res.status(400).json({ error: 'host_cannot_leave' });
  const jr = db.prepare('SELECT joined_at FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid);
  if (!jr) return res.status(404).json({ error: 'not_joined' });

  /* ── 단계 환불 정책 (매치 시각은 KST 벽시계) ─────────────────
     2일 전 100% · 1일 전 80% · 당일~90분 전 20% · 90분 이내 불가
     + 신청 후 30분 이내는 하루 1회 무료 취소 (90분 이내 제외)     */
  try { db.exec(`CREATE TABLE IF NOT EXISTS cancel_logs (
    id INTEGER PRIMARY KEY, user_id INTEGER, match_id INTEGER, free INTEGER, refund INTEGER, created_at INTEGER)`); } catch (e) {}

  const price = m.price || 0;
  let pct = 100, freeGrace = 0;
  const startMs = Date.parse(String(m.start_at || '').slice(0, 16) + ':00+09:00');
  if (price > 0 && !isNaN(startMs)) {
    const minLeft = (startMs - Date.now()) / 60000;
    if (minLeft <= 90) return res.status(400).json({ error: 'too_late', message: '매치 시작 90분 이내에는 취소할 수 없어요' });
    const grace = jr.joined_at && (Date.now() - jr.joined_at) <= 30 * 60e3;
    const kstDay = ms => Math.floor((ms + 9 * 3600e3) / 86400e3);
    const dDiff = kstDay(startMs) - kstDay(Date.now());
    const usedFree = db.prepare('SELECT COUNT(*) n FROM cancel_logs WHERE user_id=? AND free=1 AND created_at>?')
      .get(req.uid, Date.now() - 86400e3).n;
    if (grace && usedFree < 1) { pct = 100; freeGrace = 1; }
    else if (dDiff >= 2) pct = 100;
    else if (dDiff === 1) pct = 80;
    else pct = 20;
  }
  const refund = Math.round(price * pct / 100);
  db.prepare('DELETE FROM open_match_joins WHERE match_id=? AND user_id=?').run(mid, req.uid);
  if (refund > 0) {                                       // 환불은 캐시로 (PG 연동 전)
    const u = getUser(req.uid);
    db.prepare('UPDATE users SET cash=? WHERE id=?').run((u.cash || 0) + refund, req.uid);
  }
  db.prepare('INSERT INTO cancel_logs (user_id,match_id,free,refund,created_at) VALUES (?,?,?,?,?)')
    .run(req.uid, mid, freeGrace, refund, Date.now());
  const me = getUser(req.uid);
  sendPush(m.host_id, { icon: '📣', title: '참가 취소', body: `${me.name} 님이 참가를 취소했어요 · ${m.dt || ''}` });
  res.json({ ok: true, refund, pct, cash: me.cash });
});
app.patch('/open-matches/:id', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid) return res.status(403).json({ error: 'host_only' });
  const st = ['open', 'closed', 'cancelled'].includes((req.body || {}).status) ? req.body.status : null;
  if (!st) return res.status(400).json({ error: 'bad_status' });
  db.prepare('UPDATE open_matches SET status=? WHERE id=?').run(st, m.id);
  const players = db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(m.id);
  const label = st === 'closed' ? '모집이 마감됐어요' : '모집이 취소됐어요';
  players.forEach(p => { if (p.user_id !== req.uid) sendPush(p.user_id, { icon: '📣', title: label, body: `${m.dt} · ${m.loc}` }); });
  res.json(omView(db.prepare('SELECT * FROM open_matches WHERE id=?').get(m.id), req.uid));
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
  if (!isOfficer(+req.params.id, req.uid)) return res.status(403).json({ error: 'officer_only' });
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
  // 상대가 지정된 도전이면 상대에게 알림
  if (away_user_id && +away_user_id !== req.uid) {
    const me = getUser(req.uid);
    sendPush(+away_user_id, { icon: '⚔️', title: '도전 신청이 왔어요',
      body: `${me.name} 님(레이팅 ${me.rating})이 대전을 신청했어요 · 매치 탭에서 수락하세요` });
  }
  // 클럽 대항전이면 상대 클럽장에게 알림
  if (away_club_id) {
    const myClub = home_club_id ? db.prepare('SELECT name FROM clubs WHERE id=?').get(home_club_id) : null;
    db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND role='owner'").all(+away_club_id)
      .forEach(o => sendPush(o.user_id, { icon: '🆚', title: '클럽 대항전 신청이 왔어요',
        body: `${myClub ? myClub.name : '다른 클럽'}에서 대전을 신청했어요 · 매치 탭에서 수락하세요` }));
  }
  res.json(db.prepare('SELECT * FROM matches WHERE id=?').get(rid(r)));
});
function matchParty(m, uid) {
  if (!m) return false;
  if ([m.home_user_id, m.away_user_id, m.created_by].includes(uid)) return true;
  // 클럽 대항전은 양쪽 클럽 임원이 당사자다
  if (m.home_club_id && isOfficer(m.home_club_id, uid)) return true;
  if (m.away_club_id && isOfficer(m.away_club_id, uid)) return true;
  return false;
}
app.post('/matches/:id/accept', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (!matchParty(m, req.uid)) return res.status(403).json({ error: 'party_only' });
  db.prepare("UPDATE matches SET status='scheduled' WHERE id=?").run(+req.params.id);
  if (m && m.created_by) sendPush(m.created_by, { icon: '✅', title: '대전 성사', body: '상대가 대전을 수락했어요' });
  res.json({ ok: true });
});
app.post('/matches/:id/decline', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (!matchParty(m, req.uid)) return res.status(403).json({ error: 'party_only' });
  db.prepare("UPDATE matches SET status='declined' WHERE id=?").run(+req.params.id);
  res.json({ ok: true });
});
// 결과 입력 + 상호 확정
app.post('/matches/:id/result', auth, (req, res) => {
  const { home_score, away_score, side } = req.body; // side: 'home' | 'away'
  const m = db.prepare('SELECT * FROM matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (!matchParty(m, req.uid)) return res.status(403).json({ error: 'party_only' });
  const col = side === 'away' ? 'away_confirmed' : 'home_confirmed';
  const other = col === 'away_confirmed' ? 'home_confirmed' : 'away_confirmed';
  // 이미 입력된 점수와 다른 점수를 제출하면 상대 확인을 되돌린다 — 불일치가 그대로 확정되는 것 방지
  const changed = m.home_score != null && (+m.home_score !== +home_score || +m.away_score !== +away_score);
  db.prepare(`UPDATE matches SET home_score=?, away_score=?, ${col}=1${changed ? `, ${other}=0` : ''}, status='played' WHERE id=?`)
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
  logRating(a.id, da, a.rating + da, '도전전');
  logRating(b.id, -da, b.rating - da, '도전전');
}

// ── RECORDS (수영/러닝) ──
// (구 records 라우트 제거 — sport_records 라우트가 처리)
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
  const bad = findContact(body);
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  const u = getUser(req.uid);
  const r = db.prepare('INSERT INTO comments (post_id,user_id,anon_nick,body,created_at) VALUES (?,?,?,?,?)')
    .run(+req.params.id, req.uid, u.anon_nick, body, now());
  res.json({ ok: true, id: rid(r) });
});
app.post('/posts', auth, limitWrite, (req, res) => {
  const u = getUser(req.uid);
  const { title, body, category = '자유', sport } = req.body;
  if (!title) return res.status(400).json({ error: 'title_required' });
  const bad = findContact(title + ' ' + (body || ''));
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  const r = db.prepare(`INSERT INTO posts (user_id,sport,category,title,body,anon_nick,gender,region,created_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(req.uid, sport || u.sport, category, title, body || '', u.anon_nick, u.gender, u.region, now());
  res.json(db.prepare('SELECT * FROM posts WHERE id=?').get(rid(r)));
});
db.exec(`CREATE TABLE IF NOT EXISTS post_likes (
  post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, UNIQUE(post_id, user_id)
);`);
app.post('/posts/:id/like', auth, (req, res) => {
  const pid = +req.params.id;
  const has = db.prepare('SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?').get(pid, req.uid);
  if (has) return res.json({ ok: true, already: true });
  db.prepare('INSERT INTO post_likes (post_id,user_id) VALUES (?,?)').run(pid, req.uid);
  db.prepare('UPDATE posts SET likes=likes+1 WHERE id=?').run(pid);
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
  if (IS_PROD) return res.status(403).json({ error: 'demo_only', message: '실 충전은 /pay/* 또는 /iap/* 를 사용하세요' });
  const amount = Math.max(0, intOrNull((req.body || {}).amount) || 0);
  const u = getUser(req.uid); const bal = u.cash + amount;
  db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
  db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
    .run(u.id, amount, 'purchase', bal, now());
  res.json({ cash: bal });
});

// ── 통합 검색 ──
app.get('/search', (req, res) => {
  const raw = String(req.query.q || '').trim();
  if ([...raw].length < 2) return res.json({ clubs: [], users: [], posts: [] });   // 2자 이상만
  // LIKE 의 % 와 _ 는 와일드카드다. 사용자가 친 글자는 문자 그대로 찾아야 한다.
  const q = '%' + raw.replace(/[\\%_]/g, (c) => '\\' + c) + '%';
  const sport = req.query.sport || null;
  const ex = " ESCAPE '\\' ";

  const clubs = db.prepare(`SELECT id, name, sport, region,
      (SELECT COUNT(*) FROM club_members WHERE club_id=clubs.id) members
    FROM clubs WHERE name LIKE ?${ex} ${sport ? 'AND sport=?' : ''}
    ORDER BY members DESC LIMIT 20`).all(...(sport ? [q, sport] : [q]));

  const users = db.prepare(`SELECT id, name, region, sport
    FROM users WHERE name LIKE ?${ex} AND suspended=0 ${sport ? 'AND sport=?' : ''}
    ORDER BY name LIMIT 20`).all(...(sport ? [q, sport] : [q]));

  const posts = db.prepare(`SELECT id, title, category, sport, likes, created_at
    FROM posts WHERE hidden=0 AND (title LIKE ?${ex} OR body LIKE ?${ex})
    ${sport ? 'AND sport=?' : ''} ORDER BY id DESC LIMIT 20`)
    .all(...(sport ? [q, q, sport] : [q, q]));

  res.json({ clubs, users, posts });
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

app.post('/push/unregister', auth, (req, res) => {
  const { token } = req.body || {};
  if (token) db.prepare('DELETE FROM devices WHERE user_id=? AND token=?').run(req.uid, token);
  else db.prepare('DELETE FROM devices WHERE user_id=?').run(req.uid);
  res.json({ ok: true });
});
try { db.exec('ALTER TABLE notifications ADD COLUMN link TEXT'); } catch (e) { /* 이미 있음 */ }

// 아이콘 → 이동 화면 기본 매핑. 개별 알림은 msg.link 로 덮어쓸 수 있다.
const ICON_LINKS = {
  '⚔️': 'match', '🆚': 'match', '🎾': 'club', '📅': 'club', '💰': 'club',
  '💬': 'chat', '✅': 'club', '👋': 'club', '🏆': 'bracket', '📋': 'bracket',
  '🔔': 'home', '⭐': 'league', '🥇': 'league', '📣': 'club', '🙌': 'club', '🏃': 'league', '🏊': 'league', '⚽': 'league', '🏀': 'league', '⚾': 'league', '🏸': 'bracket',
};

async function sendPush(userId, msg, opts) {
  // 알림함에는 기본으로 남긴다. 채팅처럼 잦은 알림은 skipInbox 로 푸시만 보낸다.
  const link = msg.link || ICON_LINKS[msg.icon] || null;
  if (!(opts && opts.skipInbox))
    db.prepare('INSERT INTO notifications (user_id,icon,title,sub,created_at,link) VALUES (?,?,?,?,?,?)')
      .run(userId, msg.icon || '🔔', msg.title || '', msg.body || '', now(), link);
  if (!webpush) return;
  const rows = db.prepare('SELECT token FROM devices WHERE user_id=?').all(userId);
  for (const { token } of rows) {
    let sub;
    try { sub = JSON.parse(token); } catch { continue; }        // 구독 객체가 아니면 건너뛴다
    if (!sub || !sub.endpoint) continue;
    webpush.sendNotification(sub, JSON.stringify({
      title: msg.title || 'MATSU', body: msg.body || '', url: msg.url || '/',
    })).catch(err => {
      if (err && (err.statusCode === 404 || err.statusCode === 410)) {   // 만료된 구독은 정리
        db.prepare('DELETE FROM devices WHERE token=?').run(token);
      } else {
        console.error('[push]', err && err.statusCode, err && err.body);
      }
    });
  }
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
  const uid = intOrNull(req.query.user);
  const where = uid ? 'WHERE m.home_user_id=? OR m.away_user_id=?' : '';
  const p = uid ? [uid, uid] : [];
  res.json(db.prepare(`SELECT m.*, hu.name home_name, au.name away_name, hc.name home_club, ac.name away_club
    FROM matches m LEFT JOIN users hu ON hu.id=m.home_user_id LEFT JOIN users au ON au.id=m.away_user_id
    LEFT JOIN clubs hc ON hc.id=m.home_club_id LEFT JOIN clubs ac ON ac.id=m.away_club_id
    ${where} ORDER BY m.id DESC LIMIT 40`).all(...p));
});
// 개인 레이팅 랭킹 (리그 화면)
app.get('/rankings', (req, res) => {
  const { sport } = req.query;
  let sql = "SELECT id,name,region,sport,rating,(wins+losses) AS games FROM users WHERE provider!='bot'", p = [];
  if (sport) { sql += ' AND sport=?'; p.push(sport); }
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
  logRating(u.id, delta, nr, '대진');
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
app.get('/pay/done', async (req, res) => {
  const { paymentKey, orderId, amount, fail } = req.query || {};
  let msg = '<b>결제 처리 완료</b><p>앱으로 돌아가면 잔액이 갱신돼요.</p>';
  if (fail) msg = '<b>결제가 취소되거나 실패했어요</b><p>앱으로 돌아가 다시 시도해 주세요.</p>';
  else if (paymentKey && orderId) {
    try {   // 토스가 successUrl 에 붙여준 파라미터로 서버가 직접 최종 승인 — 클라이언트 폴링 불필요
      const r = await fetch(`http://127.0.0.1:${PORT}/pay/confirm`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paymentKey, orderId, amount: +amount })
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) msg = `<b>승인에 실패했어요</b><p>${String((j && (j.error || '')) || '').slice(0, 80)} · 문제가 계속되면 문의해 주세요.</p>`;
    } catch (e) { msg = '<b>승인 확인 중 오류</b><p>잠시 후 앱에서 잔액을 확인해 주세요. 웹훅으로 자동 반영될 수 있어요.</p>'; }
  }
  res.set('Content-Type', 'text/html; charset=utf-8')
    .send(`<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;padding:24px">${msg}</body>`);
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
// ── PWA: 매니페스트 + 아이콘 (홈 화면 설치용) ──
const ICON_192 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAIAAADdvvtQAAABZElEQVR42u3SQREAMAjAsDFBCEM7IrDA8U4k9Bpd+eDqS4CBMBAGwkBgIAyEgTAQGAgDYSAMBAbCQBgIA4GBMBAGwkAYCAyEgTAQBgIDYSAMhIHAQBgIA2EgMBAGwkAYCAOBgTAQBsJAYCAMhIEwEBgIA2EgDAQGwkAYCAOBgTAQBsJAGAgMhIEwEAYCA2EgDISBwEAYCANhIDAQBsJAGAgDgYEwEAbCQGAgDISBMBAYCANhIAwEBsJAGAgDYSAwEAbCQBgIDISBMBAGAgNhIAyEgcBAGAgDYSAwEAbCQBgIA4GBMBAGwkBgIAyEgTAQGAgDYSAMBAbCQBgIA2EgMBAGwkAYCAyEgTAQBgIDYSAMhIHAQBgIA2EgDAQGwkAYCAOBgTAQBsJAYCAMhIEwEBgIA2EgDAQGwkAYCANhIDAQBsJAGAgMhIEwEAYCA2EgDISBwEAYCANhIAwEBsJAGAgDwdYAWwADBKKT2qQAAAAASUVORK5CYII=', 'base64');
const ICON_512 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAIAAAB7GkOtAAALVElEQVR42u3dPXJTTRCG0WuKFYiYkNReD1sw62ENrIeYkNTWGggoKDACpKuf293vOflXJY165rkjG393T4/3CwB5XlkCAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAABAAAAQBgvteWoIU3Hz+v+w+fPzxYPQweB909Pd5bhRlbzubE4CEA9p49icFDAOw9exKDhwDYfjakwTN4CIDtZ0MaPIOHANh+NqTBM3gCgB1oNxo8gycA2IF2o8EzeAKAHWg3GjyDJwDYgXajwTN4AoAdaDcaPIMnAHYgdqPBM3g9+WugNqE1scjWxA0A0+aJzOAZPDcAbEKrZEmtkhsAZssTmcEzeG4ANiHWzQJaNwEwTFg9S2f1uvMVkBlyKzd4Bk8AsAltRYN3Q7vd7tT/ZL/fGzwBsAk1wODNP+4vmASDJwA2oQYYvAmH/roYGDwBcPprgMGbdu4fXwKDJwBOfw0weDPP/WNKYPAEwOmvAQZv8rn/7xIYvJ/8OwCnvzW3COuP/han/4uXavAEwElk5b39iKP/4Mu25QXAGWT9vfGUo//Pt2DjC4DT36fgLQcd/S/ezrtPXwXAuYPPwpv9/3E58rMIb0DubwE5/QtK+PWMdoM39eh/4cv7t24ATn98Lt5g3OkfexVIvAE4/d0DDJ6j31VgWZbXjptAJ+3tdX9/kZwJmXcVyGlA3A0g8/H/gvv5Nj2YdwloNHjJp3/aPSArAFGn/w228VVjMKkBXQbP0Z+WgaAAhJz+m+zhK5VgRgOc/hpQln8JPOro32oPD/snQpnDYxEOmv3bQSk3AP+jpaYXgu6XgBaD5/SPvQdE3ACmnv5ln7sv+MJaf3ZOf/cAASB03zpZTJEGCICnsJQH/yu91KafYP2X7fTXgOEBGHb6d/8j7Dmfo9NfAwQAO9aJ47PQAAHwFGbHnvcuGn2axV+q018DfvK3gBz9G7wdf18I3AA8/oc+rK17Xy0+U4//LgECgL3qJLLmGiAAnsLs1cu9x+KfbOWX5/TXADcAp793CswNQPfH/7Qz8dT3W/bz9fjvEiAA2KjeteXVAAHwFGajXue9F/yU/Y+mEQCc/lbAqroECICnMLv0mutQ6rMuO3jmSgPcAAAQAI9pVsNK4hIwLwBNv/+xS1evSZFP3I9/cQPA6W9lLCDNLgECAOAG0FnHa7hntPPXZ/PPvebgGS2XADcAAATAM5pVsmi4BIwMQLvvf2zRC67Vhp++3//BDQAAAcDjvxWzVizL0uRbIAEAcAPoyfewbDIDBg8BwA3dulklDqv/LZAAALgB4AHN6oEAdOF7WDaZhIKDJ5A1Ff8WyA0AwA0AD2jWEAQAAAEA3I1Yr/KPAQQAwA0AD2hWEgSgBb8DyibzYPAQAAAEAAABAG7Mz0XqK/uLQAJgf1pPcAMAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEIDDnj88tHid+/3enN1gPW82D10GD9wAILSI1PHl/VsBAEAAABAAAARgLN/SWkkQAAAE4BL8Qh6bTEK1wXMxqqzsrwC5AQC4AeAZzRqCAAAgAA34MQCbzIAfA3CMyj8AcAOwRa0euAEAIAB4jLVuVonzFf/+Z0gA/Bgg2YafvsHDDQAAAcA93YpZK5Zl6fD9z5wAuIxn2vxzN3i4AeAxzVqBAOBcs0oWLV6L739GBcBlPE2RT9zg4QaAJzXrY+no9PgvAABuAL4T8KTWamVKfdYFB89oefx3A9AAawLEBKDjT+Scd6euRsFP2SWAdo//bgAAbgAuAR7WPP67BJD0+O8GYK9aAatK6Ok/NgBN/21O8l498r0X/2T9ozAEAA3wri2vx38B8Cxmu17u/bb4TGu+SA1w+rsBaIB3CmQEoPUXsgkn40nvsdGn6RLg8V8AsGOdR9bc6S8AnsXs2PPeV7vPsewL1gCnf9YNYEADJm3aFW+n6SfoV0IRADy4efz0KXj8FwDPYtn7dt3rb/3Z+SLI6S8AtuIl923Hrbv6ZQ/41DTA6S8AhGZg2A8w5g2SRUg+/bMCMOyHcvV375mvcMznVfmNaEDy6R93A5jXgJob+PwXNuyT0gCnf013T4/3aZ/lm4+fR76v3W434yiZ+guUlQdv8+Fx+rsB0PVC4Lv+AcNjEdJO/9AbwOBLwI2f6a5xasz+91PFB889IOr0zw1ASAOusbGv+qiY8K9n6w+eDCQc/ekBSGvA6h1+sy8Hcv52ggY4/QXAViTx9NcAp78A2Irknv6NBi8qA1FH/3d+C8hfbbT+3vhf5fx2UODp7wbgHuAQNHjpV4HMo98NwElkzS1C+lUg+fR3A3APcPAZvNCrQPjRLwAa4PQ3eIkZcPQLgAY4/Q1eXAYc/QKgAU5/gxeXAUf/QX4I7JyyqpboLPsfyr42p78bgHuAo83gpdwJfq2RwRMAGXD0G7z5JXhxCzF4AmArOv0N3uQY/O2rJ4MnALai09/gjUrCkT9pMHgCYDc6+g2eweNf/BaQ8bJKltQquQHgicwONHgGzw0AA2dNLLI1cQPAE5kdaPAMngBgN9qBBs/gCQB2ox1o8AyeABC3G+1Ag2fwBIC43WgHGjyDJwDE7UY70OAZPAEga0PafgbP4AkAWRvS9jN4Bk8AyNqQtp/BM3gCQNCetPcMnsETAIL2pL2HwUMA5m9OWw6DhwAA8Bt/DRRAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABABAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABABAACwBgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAACAAAWb4B7h5L1AWmSfMAAAAASUVORK5CYII=', 'base64');
app.get('/icon-192.png', (req, res) => { res.type('png').send(ICON_192); });
app.get('/icon-512.png', (req, res) => { res.type('png').send(ICON_512); });
app.get('/manifest.json', (req, res) => res.json({
  name: '맞수 MATSU', short_name: '맞수',
  description: '동호회 운영과 대진, 기록까지 — 맞수',
  start_url: '/', display: 'standalone',
  background_color: '#f6f1e7', theme_color: '#ec6a2e',
  icons: [
    { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png' }
  ]
}));

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
//  연락처 차단 — 공개 글·댓글에 전화번호/카톡ID/SNS 를 못 올리게 한다.
//  (1:1 쪽지에서는 허용. 그게 쪽지에 과금하는 이유다.)
// ══════════════════════════════════════════════════════════════
const _FULLW = { '０':'0','１':'1','２':'2','３':'3','４':'4','５':'5','６':'6','７':'7','８':'8','９':'9' };
// 한글 숫자는 "전화번호 판정용 문자열"에만 적용한다.
// 키워드 판정용 문자열에 적용하면 '아이디'→'아2디', '오픈채팅'→'5픈채팅' 처럼 단어가 깨진다.
const _HANGUL_NUM = { '영':'0','공':'0','일':'1','이':'2','삼':'3','사':'4','오':'5','육':'6','륙':'6','칠':'7','팔':'8','구':'9' };
const _SEP = /[\s\-\u00b7_/|,()\[\]{}<>+*~^$#!?"'`]/g;

function _keywordText(t) {                       // . 과 @ 는 남긴다 (이메일·도메인 판정)
  return String(t || '').toLowerCase().replace(/[０-９]/g, c => _FULLW[c]).replace(_SEP, '');
}
function _digitText(t) {                          // 숫자만 뽑아낸다 (구분자·한글숫자 우회 차단)
  let x = String(t || '').toLowerCase().replace(/[０-９]/g, c => _FULLW[c]);
  Object.entries(_HANGUL_NUM).forEach(([k, v]) => { x = x.split(k).join(v); });
  return x.replace(/[^0-9]/g, '');
}
const _KEYWORD_RULES = [
  { re: /openkakao|open\.kakao|kakao\.com|오픈채팅|오카방|톡방/,          reason: '오픈채팅 링크' },
  { re: /(카톡|카카오톡|kakaotalk|katalk)\s*(아이디|id|:|=|는|은)?/,      reason: '카카오톡 아이디' },
  { re: /(라인|line|텔레|telegram|텔레그램)(아이디|id|:|=)/,              reason: '메신저 아이디' },
  { re: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/,                        reason: '이메일 주소' },
  { re: /(인스타|instagram|insta)(아이디|id|:|=|@)?|@[a-z0-9._]{3,}/,     reason: 'SNS 아이디' },
];
const _PHONE_RE = [/01[016789]\d{7,8}/, /8210\d{7,8}/];

function findContact(text) {
  const k = _keywordText(text);
  for (const r of _KEYWORD_RULES) if (r.re.test(k)) return r.reason;
  const d = _digitText(text);
  for (const re of _PHONE_RE) if (re.test(d)) return '전화번호';
  return null;
}

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

// 선수 프로필 (선수 비교 화면용)
['birth_year INTEGER', 'handed TEXT', 'backhand TEXT', 'style TEXT', 'peak_mmr INTEGER', 'wins INTEGER DEFAULT 0', 'losses INTEGER DEFAULT 0']
  .forEach(col => { try { db.exec(`ALTER TABLE users ADD COLUMN ${col}`); } catch (e) {} });

// event_attendees.status : going | absent | undecided  (기존 행은 going 으로 간주)
try { db.exec("ALTER TABLE event_attendees ADD COLUMN status TEXT DEFAULT 'going'"); } catch (e) {}
// 게스트(비회원) — 대진 편성에는 들어가되 회원 통계에는 안 잡히도록 분리
db.exec(`CREATE TABLE IF NOT EXISTS event_guests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL, name TEXT NOT NULL,
  gender TEXT, grade TEXT, added_by INTEGER, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_guests_event ON event_guests(event_id);`);
// 게스트비: 데려온 회원(added_by)이 책임지고, 임원이 받으면 체크한다.
['fee INTEGER DEFAULT 0', 'paid INTEGER DEFAULT 0', 'paid_at BIGINT'].forEach(c => {
  try { db.exec(`ALTER TABLE event_guests ADD COLUMN ${c}`); } catch (e) {}
});

// club_members.grade (A/B/C) — 대진 편성용 실력 등급. db.js를 건드리지 않고 여기서 추가.
try { db.exec('ALTER TABLE club_members ADD COLUMN grade TEXT'); } catch (e) { /* 이미 있음 */ }
try { db.exec('ALTER TABLE club_members ADD COLUMN gender_ov TEXT'); } catch (e) { /* 이미 있음 */ }

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
// 과거 대진 전체 (시즌 리포트용). 발행된 것만 집계한다.
app.get('/clubs/:id/brackets/history', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const limit = Math.min(60, intOrNull(req.query.limit) || 30);
  const rows = db.prepare(`SELECT id, date, fmt, sport, data, created_at FROM brackets
    WHERE club_id=? AND published=1 ORDER BY id DESC LIMIT ?`).all(cid, limit);
  const out = rows.map(b => {
    const sc = db.prepare('SELECT court_key, a, b FROM bracket_scores WHERE bracket_id=?').all(b.id);
    const scores = {};
    sc.forEach(r => { if (r.a !== null && r.b !== null) scores[r.court_key] = { a: r.a, b: r.b }; });
    let data = {};
    try { data = JSON.parse(b.data); } catch (e) {}
    return { id: b.id, date: b.date, fmt: b.fmt, sport: b.sport, created_at: b.created_at,
             reg: data.reg || [], attendees: data.attendees || [], scores };
  });
  res.json(out.reverse());   // 오래된 것부터
});

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
  // 무료 클럽은 월 4개까지 (기존 대진 덮어쓰기·재편성은 개수에 안 들어간다)
  if (!prev && !isPremium(cid) && bracketsThisMonth(cid) >= FREE_MAX_BRACKETS_PER_MONTH)
    return res.status(402).json({ error: 'bracket_limit', limit: FREE_MAX_BRACKETS_PER_MONTH, upgrade: 'club_premium' });
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

// ══════════════════════════════════════════════════════════════
//  결제 게이트
//  아직 PG(토스·아임포트)도 애플 IAP도 붙어 있지 않다.
//  "돈을 받았다"고 확인할 방법이 없으면 팔지 않는다. 공짜로 주지도 않는다.
//  PAYMENTS_LIVE=1 을 켜야 유료 상품 경로가 열린다.
// ══════════════════════════════════════════════════════════════
const PAYMENTS_LIVE = process.env.PAYMENTS_LIVE === '1';
function requirePayments(req, res) {
  if (PAYMENTS_LIVE) return false;
  res.status(402).json({ error: 'payments_not_ready', message: '결제 준비 중입니다' });
  return true;
}

// ── 애플 3.1.1: iOS 앱에서 온 요청은 웹 결제를 받지 않는다 ──
// 클라이언트에서 버튼만 숨기면 우회가 가능하므로 서버에서도 막는다.
// iOS 앱은 X-Client-Platform: ios 헤더를 붙여 보낸다.
function blockIosWebPurchase(req, res) {
  const p = String(req.get('X-Client-Platform') || '').toLowerCase();
  if (p === 'ios') {
    res.status(403).json({ error: 'iap_required', message: 'iOS 앱에서는 인앱결제를 사용해야 합니다' });
    return true;
  }
  return false;
}

// ══════════════════════════════════════════════════════════════
//  클럽 프리미엄 — 월 9,900원 (클럽당). 클럽장이 결제.
//  무료: 정회원 15명, 대진 월 4회.  프리미엄: 무제한 + 회비 장부.
//  ※ 실결제는 /pay/* PG 웹훅에서 activatePremium() 을 호출하세요.
// ══════════════════════════════════════════════════════════════
const PREMIUM_WON = 9900;
const FREE_MAX_MEMBERS = 15;
const FREE_MAX_BRACKETS_PER_MONTH = 4;

try { db.exec('ALTER TABLE clubs ADD COLUMN premium_until BIGINT'); } catch (e) {}

function isPremium(clubId) {
  const c = db.prepare('SELECT premium, premium_until FROM clubs WHERE id=?').get(clubId);
  if (!c) return false;
  if (!c.premium) return false;
  return !c.premium_until || c.premium_until > now();
}
function activatePremium(clubId, months = 1) {
  const c = db.prepare('SELECT premium_until FROM clubs WHERE id=?').get(clubId);
  const base = c && c.premium_until && c.premium_until > now() ? c.premium_until : now();
  const until = base + months * 30 * 24 * 3600 * 1000;
  db.prepare('UPDATE clubs SET premium=1, premium_until=? WHERE id=?').run(until, clubId);
  return until;
}
const monthKey = (t) => new Date(t || Date.now()).toISOString().slice(0, 7);
function bracketsThisMonth(clubId) {
  const from = new Date(monthKey() + '-01T00:00:00Z').getTime();
  return db.prepare('SELECT COUNT(*) n FROM brackets WHERE club_id=? AND created_at>=?').get(clubId, from).n;
}
function activeMembers(clubId) {
  return db.prepare("SELECT COUNT(*) n FROM club_members WHERE club_id=? AND (status IS NULL OR status='active')").get(clubId).n;
}

app.get('/clubs/:id/premium', (req, res) => {
  const cid = +req.params.id;
  const c = db.prepare('SELECT premium, premium_until FROM clubs WHERE id=?').get(cid);
  if (!c) return res.status(404).json({ error: 'no_club' });
  res.json({
    premium: isPremium(cid), premium_until: c.premium_until || null, price: PREMIUM_WON,
    members: activeMembers(cid), member_limit: FREE_MAX_MEMBERS,
    brackets_this_month: bracketsThisMonth(cid), bracket_limit: FREE_MAX_BRACKETS_PER_MONTH,
  });
});

// 데모 결제. 실서비스에선 PG 웹훅에서만 activatePremium() 호출.
app.post('/clubs/:id/premium', auth, (req, res) => {
  if (blockIosWebPurchase(req, res)) return;          // 디지털 구독 → 애플 IAP 필수
  if (requirePayments(req, res)) return;              // 결제 검증 경로가 없으면 팔지 않는다
  const cid = +req.params.id;
  const owner = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, req.uid);
  if (!owner) return res.status(403).json({ error: 'owner_only' });
  const months = Math.min(12, Math.max(1, intOrNull(req.body && req.body.months) || 1));
  const until = activatePremium(cid, months);
  notifyClub(cid, req.uid, '👑', '클럽 프리미엄이 시작됐어요', '회비 장부 · 무제한 대진을 쓸 수 있어요');
  res.json({ ok: true, premium: true, premium_until: until, months });
});
app.delete('/clubs/:id/premium', auth, (req, res) => {
  const cid = +req.params.id;
  const owner = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, req.uid);
  if (!owner) return res.status(403).json({ error: 'owner_only' });
  db.prepare('UPDATE clubs SET premium=0, premium_until=NULL WHERE id=?').run(cid);
  res.json({ ok: true, premium: false });
});

// ══════════════════════════════════════════════════════════════
//  회비 장부 (클럽 프리미엄 전용)
//
//  ⚠️ 중요: 이 앱은 회비를 "보관하지 않는다".
//     회비는 클럽 명의의 실제 은행 계좌로 바로 들어가고,
//     앱은 (1) 누가 냈는지 기록하고 (2) 입금 내역과 대조만 한다.
//     앱이 돈을 들고 있으면 전자금융업(선불업/자금이체업) 등록 대상이 된다.
//     → 클럽장은 은행에서 언제든 직접 출금할 수 있다 (운용비 문제 해결).
//
//  입금 확인은 두 가지 중 하나로 붙인다:
//     A. 가상계좌(입금전용) — 회원마다 다른 계좌번호. 100% 정확. 건당 수수료
//     B. 오픈뱅킹 거래내역 조회 — 입금자명으로 매칭. 저렴. 동명이인 주의
//  아래 /deposits 는 그 웹훅/폴링이 호출할 자리다.
// ══════════════════════════════════════════════════════════════
db.exec(`
CREATE TABLE IF NOT EXISTS club_accounts (
  club_id INTEGER PRIMARY KEY, bank TEXT, number TEXT, holder TEXT, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS dues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL, period TEXT NOT NULL, user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'unpaid',
  paid_at INTEGER, deposit_id INTEGER, memo TEXT,
  UNIQUE(club_id, period, user_id)
);
CREATE TABLE IF NOT EXISTS deposits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL, depositor TEXT, amount INTEGER, occurred_at INTEGER,
  matched_user_id INTEGER, raw TEXT, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_dues_club ON dues(club_id, period);
CREATE INDEX IF NOT EXISTS ix_dep_club ON deposits(club_id, id DESC);`);

function premiumGate(cid, res) {
  if (!isPremium(cid)) { res.status(402).json({ error: 'premium_required', upgrade: 'club_premium', price: PREMIUM_WON }); return false; }
  return true;
}

// 클럽 계좌 등록 (클럽장). 실서비스는 계좌 실명확인(1원 인증) 필수.
app.post('/clubs/:id/bank', auth, (req, res) => {
  const cid = +req.params.id;
  const owner = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, req.uid);
  if (!owner) return res.status(403).json({ error: 'owner_only' });
  const { bank = '', number = '', holder = '' } = req.body || {};
  if (!bank || !number) return res.status(400).json({ error: 'bank_required' });
  db.prepare(`INSERT INTO club_accounts (club_id,bank,number,holder,updated_at) VALUES (?,?,?,?,?)
    ON CONFLICT(club_id) DO UPDATE SET bank=excluded.bank,number=excluded.number,holder=excluded.holder,updated_at=excluded.updated_at`)
    .run(cid, String(bank), String(number), String(holder), now());
  res.json({ ok: true });
});
app.get('/clubs/:id/bank', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  res.json(db.prepare('SELECT bank,number,holder FROM club_accounts WHERE club_id=?').get(cid) || {});
});

// 이번 달 회비 고지 생성 (임원진 · 프리미엄)
app.post('/clubs/:id/dues', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  if (!premiumGate(cid, res)) return;
  const period = String((req.body && req.body.period) || monthKey());
  const amount = intOrNull(req.body && req.body.amount);
  if (!amount || amount <= 0) return res.status(400).json({ error: 'amount_required' });
  const ms = db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND (status IS NULL OR status='active')").all(cid);
  const ins = db.prepare(`INSERT INTO dues (club_id,period,user_id,amount) VALUES (?,?,?,?)
    ON CONFLICT(club_id,period,user_id) DO UPDATE SET amount=excluded.amount`);
  ms.forEach(m => ins.run(cid, period, m.user_id, amount));
  ms.forEach(m => { if (m.user_id !== req.uid) sendPush(m.user_id, { icon: '💳', title: `${period} 회비 고지`, body: `${amount.toLocaleString()}원 · 클럽 계좌로 입금해 주세요` }); });
  res.json({ ok: true, period, amount, n: ms.length });
});

app.get('/clubs/:id/dues', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  if (!premiumGate(cid, res)) return;
  const period = String(req.query.period || monthKey());
  const officer = isOfficer(cid, req.uid);
  const rows = db.prepare(`SELECT d.*, u.name FROM dues d JOIN users u ON u.id=d.user_id
    WHERE d.club_id=? AND d.period=? ORDER BY (d.status='unpaid') DESC, u.name`).all(cid, period)
    .filter(r => officer || r.user_id === req.uid);   // 일반 회원은 자기 것만
  const all = db.prepare('SELECT status, amount FROM dues WHERE club_id=? AND period=?').all(cid, period);
  const paid = all.filter(r => r.status === 'paid');
  res.json({
    period, officer, rows,
    total: all.reduce((a, r) => a + r.amount, 0),
    collected: paid.reduce((a, r) => a + r.amount, 0),
    paid_n: paid.length, total_n: all.length,
  });
});

// 수동 납부 처리 (임원진) — 현금으로 받은 경우
app.patch('/dues/:id', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM dues WHERE id=?').get(intOrNull(req.params.id));
  if (!d) return res.status(404).json({ error: 'not_found' });
  if (!isOfficer(d.club_id, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const paid = !(req.body && req.body.status === 'unpaid');
  db.prepare('UPDATE dues SET status=?, paid_at=?, memo=? WHERE id=?')
    .run(paid ? 'paid' : 'unpaid', paid ? now() : null, String((req.body && req.body.memo) || ''), d.id);
  res.json({ ok: true, status: paid ? 'paid' : 'unpaid' });
});


// ── 은행 거래내역 붙여넣기 파서 ──
// 오픈뱅킹/펌뱅킹 연동 전까지 쓰는 현실적인 방법.
// 클럽장이 은행 앱에서 거래내역을 복사해 붙여넣으면 입금 건만 뽑아낸다.
function parseBankText(text) {
  const out = [];
  String(text || '').split(/\r?\n/).forEach(line => {
    const raw = line.trim();
    if (!raw) return;
    if (/출금|송금취소|수수료|이자|잔액조회/.test(raw)) return;      // 입금 건만

    // 날짜·시각을 먼저 지운다. 안 그러면 '2026' 이 금액으로 잡힌다.
    const body = raw
      .replace(/\d{4}[-.\/]\d{1,2}[-.\/]\d{1,2}/g, ' ')   // 2026.07.05
      .replace(/\d{1,2}[-.\/]\d{1,2}/g, ' ')              // 07/05
      .replace(/\d{1,2}:\d{2}(:\d{2})?/g, ' ');           // 14:22

    const amounts = (body.match(/\d{1,3}(?:,\d{3})+|\d{4,}/g) || [])
      .map(x => parseInt(x.replace(/,/g, ''), 10))
      .filter(n => n >= 1000);
    if (!amounts.length) return;

    const stop = /입금|출금|잔액|거래|내역|은행|이체|계좌|합계|원|기업|국민|신한|하나|우리|농협|카카오|토스/;
    const names = (body.match(/[가-힣]{2,5}/g) || []).filter(w => !stop.test(w));
    if (!names.length) return;

    // 금액이 여러 개면 첫 번째가 입금액, 마지막은 보통 잔액
    out.push({ name: names[names.length - 1], amount: amounts[0], raw });
  });
  return out;
}

// 붙여넣기 → 미리보기 (저장하지 않음)
app.post('/clubs/:id/deposits/parse', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const period = String((req.body && req.body.period) || monthKey());
  const parsed = parseBankText((req.body && req.body.text) || '');
  const preview = parsed.map(p => {
    const cands = db.prepare(`SELECT d.id FROM dues d JOIN users u ON u.id=d.user_id
      WHERE d.club_id=? AND d.period=? AND d.status='unpaid' AND u.name=? AND d.amount=?`).all(cid, period, p.name, p.amount);
    return { ...p, willMatch: cands.length === 1, reason: cands.length > 1 ? 'ambiguous' : cands.length ? '' : 'no_match' };
  });
  res.json({ period, parsed: preview, n: preview.length, matchable: preview.filter(p => p.willMatch).length });
}); 

// ── 회비 납부 요청 ──
// 임원진이 미납 회원에게 알림을 보낸다. 하루 1번으로 제한 (알림 도배 방지).
const REMIND_COOLDOWN_MS = 20 * 3600 * 1000;   // 20시간
try { db.exec('ALTER TABLE dues ADD COLUMN reminded_at BIGINT'); } catch (e) {}

app.post('/clubs/:id/dues/remind', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  if (!premiumGate(cid, res)) return;
  const period = String((req.body && req.body.period) || monthKey());
  const only = intOrNull(req.body && req.body.user_id);   // 특정 회원만 지정
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  const bank = db.prepare('SELECT bank,number FROM club_accounts WHERE club_id=?').get(cid);
  const t = now();

  let rows = db.prepare(`SELECT d.id, d.user_id, d.amount, d.reminded_at, u.name
    FROM dues d JOIN users u ON u.id=d.user_id
    WHERE d.club_id=? AND d.period=? AND d.status='unpaid'`).all(cid, period);
  if (only) rows = rows.filter(r => r.user_id === only);

  const sent = [], skipped = [];
  rows.forEach(r => {
    if (r.user_id === req.uid) return;                                        // 본인에겐 안 보냄
    if (r.reminded_at && t - r.reminded_at < REMIND_COOLDOWN_MS) { skipped.push(r.name); return; }
    db.prepare('UPDATE dues SET reminded_at=? WHERE id=?').run(t, r.id);
    sendPush(r.user_id, {
      icon: '💳', title: `${period} 회비 납부 요청`,
      body: `${club.name} · ${r.amount.toLocaleString()}원${bank && bank.bank ? ` · ${bank.bank} ${bank.number}` : ''}`,
    });
    sent.push(r.name);
  });
  res.json({ ok: true, sent: sent.length, skipped: skipped.length, sent_names: sent, skipped_names: skipped });
});

// 내 미납 회비 (앱 진입 시 팝업용) — 프리미엄 여부와 무관하게 본인 것은 항상 보인다
app.get('/me/dues/unpaid', auth, (req, res) => {
  const rows = db.prepare(`SELECT d.id, d.club_id, d.period, d.amount, d.reminded_at, c.name club_name,
      a.bank, a.number
    FROM dues d JOIN clubs c ON c.id=d.club_id
    LEFT JOIN club_accounts a ON a.club_id=d.club_id
    WHERE d.user_id=? AND d.status='unpaid' ORDER BY d.period DESC`).all(req.uid);
  res.json(rows);
});

// ── 입금 내역 수신 (가상계좌 웹훅 / 오픈뱅킹 폴링이 호출) ──
// 입금자명 + 금액으로 미납 회비를 자동 매칭한다.
app.post('/clubs/:id/deposits', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const list = Array.isArray(req.body && req.body.deposits) ? req.body.deposits : [];
  const period = String((req.body && req.body.period) || monthKey());
  const out = [];
  list.forEach(dep => {
    const name = String(dep.name || '').trim();
    const amount = intOrNull(dep.amount);
    const at = intOrNull(dep.at) || now();
    const r = db.prepare('INSERT INTO deposits (club_id,depositor,amount,occurred_at,raw,created_at) VALUES (?,?,?,?,?,?)')
      .run(cid, name, amount, at, JSON.stringify(dep), now());
    const did = rid(r);
    // 이름 + 금액이 정확히 일치하는 미납 건만 자동 처리 (동명이인은 수동)
    const cands = db.prepare(`SELECT d.id, d.user_id FROM dues d JOIN users u ON u.id=d.user_id
      WHERE d.club_id=? AND d.period=? AND d.status='unpaid' AND u.name=? AND d.amount=?`).all(cid, period, name, amount);
    if (cands.length === 1) {
      db.prepare("UPDATE dues SET status='paid', paid_at=?, deposit_id=? WHERE id=?").run(at, did, cands[0].id);
      db.prepare('UPDATE deposits SET matched_user_id=? WHERE id=?').run(cands[0].user_id, did);
      sendPush(cands[0].user_id, { icon: '✅', title: '회비 입금 확인', body: `${period} 회비 ${amount.toLocaleString()}원이 확인됐어요` });
      out.push({ name, amount, matched: true });
    } else {
      out.push({ name, amount, matched: false, reason: cands.length ? 'ambiguous' : 'no_match' });
    }
  });
  res.json({ ok: true, results: out });
});
app.get('/clubs/:id/deposits', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  res.json(db.prepare('SELECT * FROM deposits WHERE club_id=? ORDER BY id DESC LIMIT 50').all(cid));
});

// ══════════════════════════════════════════════════════════════
//  캐시 획득 — 친구 초대 · 광고 시청
//  (충전 외에 '벌 수 있는' 경로가 있어야 쪽지 5캐시가 부담스럽지 않다)
// ══════════════════════════════════════════════════════════════
const INVITE_REWARD = 10;     // 초대한 사람
const INVITEE_REWARD = 5;     // 가입한 사람
const AD_REWARD = 1;          // 광고 1회
const AD_DAILY_CAP = 1;       // 하루 1회. 리워드 광고 1회 수익은 3~8원이라 그 이상은 순손실

['referral_code TEXT', 'referred_by INTEGER', 'referral_rewarded INTEGER DEFAULT 0'].forEach(c => { try { db.exec(`ALTER TABLE users ADD COLUMN ${c}`); } catch (e) {} });
db.exec(`CREATE TABLE IF NOT EXISTS ad_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, day TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_adviews_user_day ON ad_views(user_id, day);`);

const dayKey = (t) => new Date(t || Date.now()).toISOString().slice(0, 10);
function grantCash(uid, amount, reason) {
  const u = getUser(uid);
  const bal = (u.cash || 0) + amount;
  db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, uid);
  db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
    .run(uid, amount, reason, bal, now());
  return bal;
}
function myReferralCode(uid) {
  let u = getUser(uid);
  if (u.referral_code) return u.referral_code;
  let code;
  do { code = crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 6); }
  while (db.prepare('SELECT 1 FROM users WHERE referral_code=?').get(code));
  db.prepare('UPDATE users SET referral_code=? WHERE id=?').run(code, uid);
  return code;
}

// 초대받은 사람이 첫 모임에 '참석'하면 그때 초대자에게 보상
function settleReferral(uid) {
  const u = getUser(uid);
  if (!u || !u.referred_by || u.referral_rewarded) return;
  db.prepare('UPDATE users SET referral_rewarded=1 WHERE id=?').run(uid);
  grantCash(u.referred_by, INVITE_REWARD, '친구 초대 확정 (첫 참석)');
  sendPush(u.referred_by, { icon: '🎁', title: '초대 보상이 지급됐어요', body: `${u.name} 님이 첫 모임에 참석했어요 · M캐쉬 ${INVITE_REWARD}개` });
}

app.get('/me/referral', auth, (req, res) => {
  const u = getUser(req.uid);
  const invited = db.prepare('SELECT COUNT(*) n FROM users WHERE referred_by=?').get(req.uid).n;
  const settled = db.prepare('SELECT COUNT(*) n FROM users WHERE referred_by=? AND referral_rewarded=1').get(req.uid).n;
  res.json({ code: myReferralCode(req.uid), invited, settled, pending: invited - settled,
             earned: settled * INVITE_REWARD, used: !!u.referred_by,
             invite_reward: INVITE_REWARD, invitee_reward: INVITEE_REWARD });
});

// 초대 코드 입력 (가입자가 1회만)
app.post('/me/referral/claim', auth, (req, res) => {
  const code = String((req.body && req.body.code) || '').trim().toUpperCase();
  const me = getUser(req.uid);
  if (me.referred_by) return res.status(400).json({ error: 'already_used' });
  const host = db.prepare('SELECT id FROM users WHERE referral_code=?').get(code);
  if (!host) return res.status(404).json({ error: 'bad_code' });
  if (host.id === req.uid) return res.status(400).json({ error: 'self_invite' });
  db.prepare('UPDATE users SET referred_by=? WHERE id=?').run(host.id, req.uid);
  const cash = grantCash(req.uid, INVITEE_REWARD, '친구 초대 코드 입력');
  // 초대한 사람 보상은 '초대받은 사람이 실제로 모임에 참석'할 때 지급한다.
  // 즉시 주면 부계정으로 자기 자신을 초대해 무한 캐시를 만들 수 있다.
  sendPush(host.id, { icon: '🎁', title: '친구가 가입했어요', body: `${me.name} 님이 첫 모임에 참석하면 M캐쉬 ${INVITE_REWARD}개를 받아요` });
  res.json({ ok: true, cash, reward: INVITEE_REWARD });
});

// 광고 시청 보상 (하루 5회)
app.get('/cash/ad-status', auth, (req, res) => {
  const used = db.prepare('SELECT COUNT(*) n FROM ad_views WHERE user_id=? AND day=?').get(req.uid, dayKey()).n;
  res.json({ used, cap: AD_DAILY_CAP, left: Math.max(0, AD_DAILY_CAP - used), reward: AD_REWARD, cash: getUser(req.uid).cash });
});
app.post('/cash/ad-reward', auth, (req, res) => {
  const day = dayKey();
  const used = db.prepare('SELECT COUNT(*) n FROM ad_views WHERE user_id=? AND day=?').get(req.uid, day).n;
  if (used >= AD_DAILY_CAP) return res.status(429).json({ error: 'daily_cap', cap: AD_DAILY_CAP });
  db.prepare('INSERT INTO ad_views (user_id,day,created_at) VALUES (?,?,?)').run(req.uid, day, now());
  const cash = grantCash(req.uid, AD_REWARD, '광고 시청 보상');
  res.json({ ok: true, cash, reward: AD_REWARD, left: AD_DAILY_CAP - used - 1 });
});

// ══════════════════════════════════════════════════════════════
//  1:1 쪽지 — 새 대화를 여는 첫 메시지에만 캐시 차감. 답장은 무료.
//  (스팸 비용을 보내는 쪽에 지우고, 받은 사람은 부담 없이 답장)
// ══════════════════════════════════════════════════════════════
const DM_COST = 0;   // M캐쉬 폐지 — 대화 무료
db.exec(`CREATE TABLE IF NOT EXISTS dms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL, to_id INTEGER NOT NULL,
  body TEXT NOT NULL, read INTEGER DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dms_pair ON dms(from_id, to_id, id DESC);`);

const threadKey = (a, b) => (a < b ? a + '_' + b : b + '_' + a);
function threadExists(a, b) {
  return !!db.prepare(`SELECT 1 FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) LIMIT 1`).get(a, b, b, a);
}

app.get('/dm/threads', auth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM dms WHERE from_id=? OR to_id=? ORDER BY id DESC LIMIT 200`).all(req.uid, req.uid);
  const seen = {}, out = [];
  rows.forEach(m => {
    const other = m.from_id === req.uid ? m.to_id : m.from_id;
    if (seen[other]) return;
    seen[other] = 1;
    const u = db.prepare('SELECT id,name,anon_nick,rating FROM users WHERE id=?').get(other);
    const unread = db.prepare('SELECT COUNT(*) n FROM dms WHERE from_id=? AND to_id=? AND read=0').get(other, req.uid).n;
    out.push({ user: u, last: m.body, last_at: m.created_at, mine: m.from_id === req.uid, unread });
  });
  res.json(out);
});

app.get('/dm/with/:uid', auth, (req, res) => {
  const other = intOrNull(req.params.uid);
  const rows = db.prepare(`SELECT id,from_id,to_id,body,created_at,read FROM dms
    WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) ORDER BY id`).all(req.uid, other, other, req.uid);
  db.prepare('UPDATE dms SET read=1 WHERE from_id=? AND to_id=? AND read=0').run(other, req.uid);
  res.json(rows.map(r => ({ ...r, mine: r.from_id === req.uid })));
});

db.exec(`CREATE TABLE IF NOT EXISTS dm_free_starts (
  user_id INTEGER NOT NULL, day TEXT NOT NULL, created_at BIGINT
);
CREATE INDEX IF NOT EXISTS ix_dm_free ON dm_free_starts(user_id, day);`);

app.post('/dm', auth, (req, res) => {
  const to = intOrNull(req.body && req.body.to);
  const body = String((req.body && req.body.body) || '').trim().slice(0, 500);
  if (!to || to === req.uid) return res.status(400).json({ error: 'bad_target' });
  if (!body) return res.status(400).json({ error: 'empty' });
  const target = getUser(to);
  if (!target) return res.status(404).json({ error: 'no_user' });
  if (db.prepare('SELECT 1 FROM blocks WHERE user_id=? AND blocked_user_id=?').get(to, req.uid))
    return res.status(403).json({ error: 'blocked' });

  const isNew = !threadExists(req.uid, to);
  // 성장 우선: 하루 3건까지는 새 대화도 무료, 그 이후부터 M캐쉬 차감
  const DM_FREE_PER_DAY = 3;
  let freeUsed = false;
  if (isNew) {
    const day = new Date().toISOString().slice(0, 10);
    const used = db.prepare("SELECT COUNT(*) n FROM dm_free_starts WHERE user_id=? AND day=?").get(req.uid, day).n;
    if (used < DM_FREE_PER_DAY) {
      db.prepare('INSERT INTO dm_free_starts (user_id,day,created_at) VALUES (?,?,?)').run(req.uid, day, now());
      freeUsed = true;
    }
  }
  if (isNew && !freeUsed) {                            // 무료 소진 후 새 대화만 유료 · 이중 차감 방지 잠금
    let after;
    try {
      after = tx(() => {
        const me = getUser(req.uid);
        if ((me.cash || 0) < DM_COST) throw new Error('insufficient_cash');
        const a = me.cash - DM_COST;
        db.prepare('UPDATE users SET cash=? WHERE id=?').run(a, req.uid);
        db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
          .run(req.uid, -DM_COST, '대화 · 새 대화 시작', a, now());
        return a;
      });
    } catch (e) {
      if (e.message === 'insufficient_cash') {
        const me = getUser(req.uid);
        return res.status(402).json({ error: 'insufficient_cash', need: DM_COST, cash: me.cash || 0 });
      }
      throw e;
    }
  }
  const r = db.prepare('INSERT INTO dms (from_id,to_id,body,created_at) VALUES (?,?,?,?)').run(req.uid, to, body, now());
  sendPush(to, { icon: '💬', title: '쪽지가 도착했어요', body: body.slice(0, 40) });
  res.json({ ok: true, id: rid(r), charged: (isNew && !freeUsed) ? DM_COST : 0, cash: getUser(req.uid).cash });
});

// ══════════════════════════════════════════════════════════════
//  클럽 단체 채팅 — 회원 전용. 폴링(GET ?since=) 방식.
//  연락처 차단은 하지 않는다 (회원끼리의 사적 공간 · DM 과 같은 원칙).
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS club_chat (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  body TEXT NOT NULL, created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_club_chat ON club_chat(club_id, id);
CREATE TABLE IF NOT EXISTS club_chat_reads (
  club_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  last_read_id INTEGER NOT NULL DEFAULT 0, updated_at BIGINT,
  PRIMARY KEY (club_id, user_id)
);`);

const setChatRead = db.prepare(`INSERT INTO club_chat_reads (club_id,user_id,last_read_id,updated_at) VALUES (?,?,?,?)
  ON CONFLICT(club_id,user_id) DO UPDATE SET
    last_read_id=MAX(last_read_id, excluded.last_read_id), updated_at=excluded.updated_at`);

app.get('/clubs/:id/chat', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const since = intOrNull(req.query.since) || 0;
  const rows = db.prepare(`SELECT c.id, c.user_id, c.body, c.created_at, u.name
    FROM club_chat c JOIN users u ON u.id=c.user_id
    WHERE c.club_id=? AND c.id>? ORDER BY c.id DESC LIMIT 100`).all(cid, since).reverse();
  // 메시지별 '안 읽은 사람 수' — 활성 회원 중 읽음 커서가 이 메시지에 못 미친 인원
  const total = activeMembers(cid);
  const readersUpTo = db.prepare('SELECT COUNT(*) n FROM club_chat_reads WHERE club_id=? AND last_read_id>=?');
  res.json(rows.map(r => ({ ...r, mine: r.user_id === req.uid,
    unread: Math.max(0, total - readersUpTo.get(cid, r.id).n) })));
});

app.post('/clubs/:id/chat', auth, limitWrite, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const body = String((req.body || {}).body || '').trim().slice(0, 500);
  if (!body) return res.status(400).json({ error: 'empty' });
  const prevMax = (db.prepare('SELECT MAX(id) m FROM club_chat WHERE club_id=?').get(cid).m) || 0;
  const r = db.prepare('INSERT INTO club_chat (club_id,user_id,body,created_at) VALUES (?,?,?,?)')
    .run(cid, req.uid, body, now());
  setChatRead.run(cid, req.uid, rid(r), now());          // 보낸 사람은 당연히 읽음
  // 새 메시지 푸시 — 밀린 메시지가 없던(=다 읽고 있던) 회원에게만 보내 도배를 막는다
  const me = getUser(req.uid);
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  db.prepare(`SELECT cm.user_id, COALESCE(cr.last_read_id,0) lr FROM club_members cm
    LEFT JOIN club_chat_reads cr ON cr.club_id=cm.club_id AND cr.user_id=cm.user_id
    WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active') AND cm.user_id<>?`).all(cid, req.uid)
    .forEach(m => { if (m.lr >= prevMax) sendPush(m.user_id,
      { icon: '💬', title: `${club ? club.name : '클럽'} 단체방`, body: `${me.name}: ${body.slice(0, 40)}` },
      { skipInbox: true }); });
  res.json({ ok: true, id: rid(r) });
});

// 읽음 커서 갱신
app.post('/clubs/:id/chat/read', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const lastId = intOrNull((req.body || {}).last_id) || 0;
  setChatRead.run(cid, req.uid, lastId, now());
  res.json({ ok: true });
});

// 안읽음 집계 — 헤더 배지용 (대화 아이콘)
app.get('/me/unread', auth, (req, res) => {
  const dm = db.prepare('SELECT COUNT(*) n FROM dms WHERE to_id=? AND read=0').get(req.uid).n;
  const clubs = {};
  db.prepare(`SELECT cm.club_id, COALESCE(cr.last_read_id,0) lr FROM club_members cm
    LEFT JOIN club_chat_reads cr ON cr.club_id=cm.club_id AND cr.user_id=cm.user_id
    WHERE cm.user_id=? AND (cm.status IS NULL OR cm.status='active')`).all(req.uid)
    .forEach(m => {
      const n = db.prepare('SELECT COUNT(*) n FROM club_chat WHERE club_id=? AND id>? AND user_id<>?')
        .get(m.club_id, m.lr, req.uid).n;
      if (n) clubs[m.club_id] = n;
    });
  const clubTotal = Object.values(clubs).reduce((a, b) => a + b, 0);
  res.json({ dm, clubs, total: dm + clubTotal });
});

// 클럽 회원 랭킹 — 레이팅 + 출석 (대진 결과 확정 시 레이팅이 갱신된다)
app.get('/clubs/:id/rankings', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT u.id user_id, u.name, u.rating, (u.wins+u.losses) AS games, cm.grade,
      (SELECT COUNT(*) FROM event_attendees ea JOIN club_events e ON e.id=ea.event_id
        WHERE ea.user_id=u.id AND e.club_id=cm.club_id AND ea.showed=1) attended
    FROM club_members cm JOIN users u ON u.id=cm.user_id
    WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
    ORDER BY u.rating DESC, attended DESC, u.name`).all(cid);
  res.json(rows);
});

// ══════════════════════════════════════════════════════════════
//  이용약관 · 개인정보처리방침 — 앱스토어 심사와 카카오 검수 요구사항
// ══════════════════════════════════════════════════════════════
const LEGAL_CSS = `<style>body{font-family:-apple-system,'Apple SD Gothic Neo',sans-serif;max-width:680px;margin:0 auto;padding:34px 22px 80px;color:#1b1813;background:#f5f2e9;line-height:1.75}
h1{font-size:22px;margin-bottom:4px}h2{font-size:15px;margin:26px 0 8px}p,li{font-size:13.5px;color:#4a4237}ul{padding-left:18px}
.sub{font-size:12px;color:#8a7f70}.box{background:#fffdf8;border:1px solid #e8e1d2;border-radius:14px;padding:14px 16px;font-size:12.5px;color:#8a7f70;margin-top:30px}</style>`;

app.get('/terms', (_req, res) => res.send(`<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>맞수 이용약관</title>${LEGAL_CSS}</head><body>
<h1>맞수(MATSU) 이용약관</h1><p class="sub">시행일: 2026-07-15</p>
<h2>제1조 (목적)</h2><p>이 약관은 맞수(이하 "서비스")가 제공하는 스포츠 동호회 운영·매칭 서비스의 이용 조건과 절차, 회원과 서비스의 권리·의무를 정합니다.</p>
<h2>제2조 (서비스 내용)</h2><p>서비스는 클럽 운영(모임·대진·회비·출석), 회원 간 매칭·대화, 커뮤니티 기능을 제공합니다. 일부 기능은 유료(M캐쉬·프리미엄)로 제공될 수 있으며, 요금과 조건은 앱 내에 표시합니다.</p>
<h2>제3조 (회원의 의무)</h2><ul><li>타인의 정보를 도용하거나 허위 정보를 등록하지 않습니다.</li><li>다른 회원을 비방·희롱하거나 연락처를 무단 수집하지 않습니다.</li><li>경기 결과·평점을 조작하지 않습니다. 위반 시 이용이 제한될 수 있습니다.</li></ul>
<h2>제4조 (결제와 환불)</h2><p>유료 결제는 결제 대행사를 통해 처리되며, 미사용 M캐쉬는 관련 법령과 앱 내 고지에 따라 환불됩니다. 참가비 등 회원 간 금전 거래는 당사자 간 책임입니다.</p>
<h2>제5조 (서비스 변경·중단)</h2><p>서비스는 운영상 필요에 따라 기능을 변경할 수 있으며, 중대한 변경은 사전에 공지합니다.</p>
<h2>제6조 (면책)</h2><p>서비스는 회원 간 경기·모임 중 발생한 사고, 회원 간 분쟁에 대해 고의·중과실이 없는 한 책임을 지지 않습니다.</p>
<h2>제7조 (탈퇴)</h2><p>회원은 언제든 앱 내에서 탈퇴할 수 있습니다. 탈퇴 시 개인정보는 지체 없이 파기되며, 클럽 장부·경기 기록은 무결성을 위해 익명 처리되어 보존됩니다.</p>
<div class="box">문의: 앱 내 신고·문의 기능 이용<br>사업자 정보: (등록 후 기재)</div></body></html>`));

app.get('/privacy', (_req, res) => res.send(`<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>맞수 개인정보처리방침</title>${LEGAL_CSS}</head><body>
<h1>개인정보처리방침</h1><p class="sub">시행일: 2026-07-15</p>
<h2>1. 수집하는 항목</h2><ul>
<li>필수: 이름(닉네임), 로그인 식별자(카카오·구글·애플 ID), 성별, 활동 지역, 종목</li>
<li>선택: 프로필 사진, 실력 정보, 기기 푸시 토큰</li>
<li>자동 수집: 서비스 이용 기록(경기 결과, 출석, 접속 일시)</li></ul>
<h2>2. 이용 목적</h2><p>회원 식별과 로그인, 클럽 운영 기능 제공(대진 편성·회비 장부·출석), 매칭·랭킹 산정, 알림 발송, 부정 이용 방지.</p>
<h2>3. 보관과 파기</h2><p>회원 탈퇴 시 개인정보는 지체 없이 파기합니다. 클럽 회비 장부와 경기 기록은 장부 무결성을 위해 <b>누구인지 알 수 없도록 익명화</b>하여 보존합니다. 법령이 보존을 요구하는 정보는 해당 기간 동안 보관합니다.</p>
<h2>4. 제3자 제공</h2><p>법령에 근거한 경우를 제외하고 개인정보를 제3자에게 제공하지 않습니다. 결제 처리를 위해 결제 대행사에 최소한의 정보가 전달될 수 있습니다.</p>
<h2>5. 처리 위탁</h2><p>서버 호스팅(Railway), 푸시 발송(웹 푸시/APNs)에 한하여 처리를 위탁하며, 수탁자가 개인정보를 다른 목적으로 이용하지 않도록 관리합니다.</p>
<h2>6. 이용자의 권리</h2><p>이용자는 언제든 자신의 정보를 열람·수정·삭제(탈퇴)할 수 있습니다. 앱 내 [내정보]에서 직접 처리하거나 문의 기능으로 요청할 수 있습니다.</p>
<h2>7. 안전성 확보 조치</h2><p>비밀 키 기반 인증 토큰, 전송 구간 암호화(HTTPS), 접근 통제, 일일 백업을 시행합니다.</p>
<div class="box">개인정보 보호책임자: (등록 후 기재)<br>문의: 앱 내 신고·문의 기능 이용</div></body></html>`));

const START_TS = Date.now();
app.get('/health', (_, res) => res.json({ ok: true, ts: now() }));

// ── 진단용 (값은 노출하지 않는다. 존재 여부·길이·앞 4글자만) ──
// 환경변수가 이 프로세스에 실제로 도달했는지 확인한다. 원인을 찾은 뒤 지워도 된다.
app.get('/diag', (_req, res) => {
  const seen = k => {
    const v = process.env[k];
    return v ? { set: true, length: v.length, head: v.slice(0, 4) + '…' } : { set: false };
  };
  res.set('Cache-Control', 'no-store');
  res.json({
    service: process.env.RAILWAY_SERVICE_NAME || null,
    environment: process.env.RAILWAY_ENVIRONMENT_NAME || null,
    deployment: (process.env.RAILWAY_DEPLOYMENT_ID || '').slice(0, 8) || null,
    started_at: new Date(START_TS).toISOString(),
    db_file_in_use: process.env.DB_PATH || 'matsu.db (기본값)',
    total_env_count: Object.keys(process.env).length,
    vars: {
      ADMIN_KEY: seen('ADMIN_KEY'),
      DB_PATH: seen('DB_PATH'),
      JWT_SECRET: seen('JWT_SECRET'),
      GOOGLE_CLIENT_ID: seen('GOOGLE_CLIENT_ID'),
      KAKAO_JS_KEY: seen('KAKAO_JS_KEY'),
    },
  });
});

// ── 이미지 업로드 (프로필·경기 사진) — 로컬 디스크. 운영은 S3/CDN 권장 ──
// 사진은 DB 와 같은 볼륨에 둔다. 컨테이너 임시 폴더에 두면 재배포마다 전부 사라진다.
const DB_DIR = path.dirname(process.env.DB_PATH || './matsu.db');

// ══════════════════════════════════════════════════════════════
//  일일 백업 — SQLite 파일이 데이터 전부라서 이게 보험이다.
//  DB와 같은 볼륨의 backups/ 에 두고 14개(2주) 보관.
//  Railway 볼륨이 마운트돼 있어야 재배포에도 살아남는다.
// ══════════════════════════════════════════════════════════════
const BK_DIR = path.join(DB_DIR, 'backups');
async function backupNow() {
  try {
    fs.mkdirSync(BK_DIR, { recursive: true });
    const stamp = new Date().toISOString().slice(0, 10);
    const dest = path.join(BK_DIR, `matsu-${stamp}.db`);
    await db.backup(dest);                              // WAL 안전 스냅샷
    const files = fs.readdirSync(BK_DIR).filter(f => f.startsWith('matsu-')).sort();
    while (files.length > 14) fs.unlinkSync(path.join(BK_DIR, files.shift()));
    console.log('[backup] 완료 →', dest);
  } catch (e) { console.error('[backup] 실패:', e.message); }
}
if (process.env.BACKUPS !== 'off') {
  setTimeout(backupNow, 60_000);                        // 부팅 1분 후 한 번
  setInterval(backupNow, 24 * 3600 * 1000).unref?.();   // 이후 24시간마다
}
app.post('/admin/backup', admin, async (_req, res) => { await backupNow(); res.json({ ok: true }); });
app.get('/admin/backup/latest', admin, (_req, res) => {
  try {
    const files = fs.readdirSync(BK_DIR).filter(f => f.startsWith('matsu-')).sort();
    if (!files.length) return res.status(404).json({ error: 'no_backup' });
    res.download(path.join(BK_DIR, files[files.length - 1]));
  } catch (e) { res.status(500).json({ error: 'backup_read_failed' }); }
});
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DB_DIR, 'uploads');
try { fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch {}
app.use('/uploads', express.static(UPLOAD_DIR));
app.post('/upload', auth, limitUpload, (req, res) => {
  const m = /^data:(image\/(png|jpe?g|webp));base64,(.+)$/.exec((req.body && req.body.dataUrl) || '');
  if (!m) return res.status(400).json({ error: 'bad_image' });
  const buf = Buffer.from(m[3], 'base64');
  if (buf.length > 3 * 1024 * 1024) return res.status(413).json({ error: 'too_large' });
  const ext = m[2] === 'jpeg' ? 'jpg' : m[2];
  const name = 'u' + req.uid + '_' + Date.now() + '.' + ext;
  fs.writeFileSync(UPLOAD_DIR + '/' + name, buf);
  res.json({ url: '/uploads/' + name });
});

/* ═══ 홈 배너 — 운영자가 이미지+랜딩 링크 등록, 홈 히어로 자리에 노출 ═══ */
db.exec(`CREATE TABLE IF NOT EXISTS banners (
  id INTEGER PRIMARY KEY AUTOINCREMENT, image TEXT, link TEXT, created_at TEXT)`);
app.get('/banners', (_req, res) => {
  res.json(db.prepare('SELECT id,image,link FROM banners ORDER BY id DESC LIMIT 5').all());
});
app.get('/admin/banners', admin, (_req, res) => {
  res.json(db.prepare('SELECT id,image,link,created_at FROM banners ORDER BY id DESC LIMIT 20').all());
});
app.post('/admin/banners', admin, (req, res) => {
  const b = req.body || {};
  let url = String(b.image || '');
  const m = /^data:(image\/(png|jpe?g|webp));base64,(.+)$/.exec(url);
  if (m) {
    const buf = Buffer.from(m[3], 'base64');
    if (buf.length > 3 * 1024 * 1024) return res.status(413).json({ error: 'too_large' });
    const name = 'bn_' + Date.now() + '.' + (m[2] === 'jpeg' ? 'jpg' : m[2]);
    fs.writeFileSync(UPLOAD_DIR + '/' + name, buf);
    url = '/uploads/' + name;
  } else if (!url.startsWith('/uploads/')) return res.status(400).json({ error: 'bad_image' });
  db.prepare('INSERT INTO banners (image,link,created_at) VALUES (?,?,?)')
    .run(url, String(b.link || '').slice(0, 300), now());
  res.json({ ok: true });
});
app.delete('/admin/banners/:id', admin, (req, res) => {
  db.prepare('DELETE FROM banners WHERE id=?').run(+req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  대진표 결과 확정 — 개인 전적·레이팅에 반영
//  대진표는 선수 배정을 클라이언트가 갖고 있어서, 끝난 뒤 한 번에 넘겨받는다.
// ══════════════════════════════════════════════════════════════
try { db.exec('ALTER TABLE brackets ADD COLUMN finalized INTEGER DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE brackets ADD COLUMN finalized_at BIGINT'); } catch {}

app.post('/brackets/:id/finalize', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (!isOfficer(b.club_id, req.uid)) return res.status(403).json({ error: 'officer_only' });
  if (b.finalized) return res.status(409).json({ error: 'already_finalized' });

  const games = Array.isArray((req.body || {}).games) ? req.body.games : [];
  let saved = 0;
  const ins = db.prepare(`INSERT INTO matches
      (sport, kind, home_club_id, away_club_id, home_user_id, away_user_id,
       home_score, away_score, status, home_confirmed, away_confirmed, created_by, created_at)
    VALUES (?, 'bracket', ?, ?, ?, ?, ?, ?, 'confirmed', 1, 1, ?, ?)`);

  const teamElo = ids => ids.reduce((t, id) => t + ((getUser(id) || {}).rating || 1000), 0) / ids.length;
  const bump = (id, d) => db.prepare('UPDATE users SET rating = COALESCE(rating,1000) + ? WHERE id=?').run(d, id);

  for (const g of games) {
    const hs = intOrNull(g.home_score), as = intOrNull(g.away_score);
    if (hs == null || as == null || hs === as) continue;              // 미입력·무승부는 건너뛴다
    const H = (Array.isArray(g.home) ? g.home : [g.home_user_id]).map(intOrNull).filter(Boolean);
    const A = (Array.isArray(g.away) ? g.away : [g.away_user_id]).map(intOrNull).filter(Boolean);
    if (!H.length || !A.length || H.some(x => A.includes(x))) continue;

    if (H.length === 1 && A.length === 1) {                           // 단식 — 정식 전적으로
      const r = ins.run(b.sport, b.club_id, b.club_id, H[0], A[0], hs, as, req.uid, now());
      applyRating(db.prepare('SELECT * FROM matches WHERE id=?').get(rid(r)));
    } else {                                                          // 복식 — 팀 평균 Elo 로 전원 반영
      const ea = 1 / (1 + 10 ** ((teamElo(A) - teamElo(H)) / 400));
      const sa = hs > as ? 1 : 0;
      const d = Math.round(24 * (sa - ea));                           // 복식은 K 를 낮춘다
      H.forEach(id => bump(id, d));
      A.forEach(id => bump(id, -d));
    }
    saved++;
  }
  db.prepare('UPDATE brackets SET finalized=1, finalized_at=? WHERE id=?').run(now(), b.id);
  notifyClub(b.club_id, req.uid, '🏅', '대진 결과가 반영됐어요', `${saved}경기 · 레이팅이 갱신됐어요`);
  res.json({ ok: true, saved });
});

// ══════════════════════════════════════════════════════════════
//  회비 요약 · 클럽 지출 장부                                (8·9)
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS club_expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL, title TEXT NOT NULL, amount INTEGER NOT NULL,
  spent_at TEXT, memo TEXT, created_by INTEGER, created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_expenses ON club_expenses(club_id, id DESC);`);

app.get('/clubs/:id/dues/summary', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const period = String(req.query.period || monthKey());
  const cur = db.prepare(`SELECT
      COUNT(*) n, COALESCE(SUM(amount),0) total,
      COALESCE(SUM(CASE WHEN status='paid' THEN amount END),0) paid_amount,
      COALESCE(SUM(CASE WHEN status='paid' THEN 1 ELSE 0 END),0) paid_n
    FROM dues WHERE club_id=? AND period=?`).get(cid, period);
  const income = db.prepare(`SELECT COALESCE(SUM(amount),0) v FROM dues WHERE club_id=? AND status='paid'`).get(cid).v;
  const spent = db.prepare('SELECT COALESCE(SUM(amount),0) v FROM club_expenses WHERE club_id=?').get(cid).v;
  res.json({
    period, members: cur.n, total: cur.total,
    paid_amount: cur.paid_amount, paid_n: cur.paid_n,
    unpaid_amount: cur.total - cur.paid_amount, unpaid_n: cur.n - cur.paid_n,
    balance: income - spent,                      // 누적 수입 − 누적 지출
  });
});

app.get('/clubs/:id/expenses', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  res.json(db.prepare(`SELECT e.*, u.name spender FROM club_expenses e
    LEFT JOIN users u ON u.id=e.created_by
    WHERE e.club_id=? ORDER BY e.id DESC LIMIT 100`).all(cid));
});

app.post('/clubs/:id/expenses', auth, limitWrite, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const title = String((req.body || {}).title || '').trim().slice(0, 60);
  const amount = intOrNull((req.body || {}).amount);
  if (!title || !amount || amount <= 0) return res.status(400).json({ error: 'bad_input' });
  const r = db.prepare(`INSERT INTO club_expenses (club_id,title,amount,spent_at,memo,created_by,created_at)
    VALUES (?,?,?,?,?,?,?)`)
    .run(cid, title, amount, String((req.body || {}).spent_at || '').slice(0, 10) || null,
         String((req.body || {}).memo || '').slice(0, 200) || null, req.uid, now());
  res.json({ ok: true, id: rid(r) });
});

app.delete('/clubs/:cid/expenses/:id', auth, (req, res) => {
  const cid = +req.params.cid;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  db.prepare('DELETE FROM club_expenses WHERE id=? AND club_id=?').run(+req.params.id, cid);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  초대 링크                                                (13)
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS club_invites (
  token TEXT PRIMARY KEY, club_id INTEGER NOT NULL,
  created_by INTEGER, expires_at BIGINT NOT NULL, uses INTEGER DEFAULT 0
);`);

app.post('/clubs/:id/invite', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const token = crypto.randomBytes(9).toString('base64url');       // 12자
  db.prepare('INSERT INTO club_invites (token,club_id,created_by,expires_at) VALUES (?,?,?,?)')
    .run(token, cid, req.uid, now() + 7 * 24 * 3600 * 1000);       // 7일 유효
  res.json({ token, url: `/?invite=${token}`, expires_days: 7 });
});

app.get('/invites/:token', (req, res) => {                          // 로그인 전에도 클럽 정보는 보여준다
  const inv = db.prepare('SELECT * FROM club_invites WHERE token=?').get(String(req.params.token));
  if (!inv || inv.expires_at < now()) return res.status(404).json({ error: 'invalid_or_expired' });
  const c = db.prepare(`SELECT id, name, region, sport, entry_fee, season_fee,
      (SELECT COUNT(*) FROM club_members WHERE club_id=clubs.id) members
    FROM clubs WHERE id=?`).get(inv.club_id);
  if (!c) return res.status(404).json({ error: 'invalid_or_expired' });
  res.json({ club: c });
});

app.post('/invites/:token/accept', auth, (req, res) => {
  const inv = db.prepare('SELECT * FROM club_invites WHERE token=?').get(String(req.params.token));
  if (!inv || inv.expires_at < now()) return res.status(404).json({ error: 'invalid_or_expired' });
  const cid = inv.club_id;
  const has = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (has) return res.json({ ok: true, already: true, club_id: cid });
  db.prepare("INSERT INTO club_members (club_id,user_id,role,status) VALUES (?,?,'member','active')")
    .run(cid, req.uid);
  db.prepare('UPDATE club_invites SET uses=uses+1 WHERE token=?').run(inv.token);
  const who = getUser(req.uid);
  const c = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  notifyClub(cid, req.uid, '🎉', '새 회원이 들어왔어요', `${who.name} 님이 초대 링크로 가입했어요`);
  res.json({ ok: true, club_id: cid, club_name: c ? c.name : '' });
});

// ══════════════════════════════════════════════════════════════
//  오픈매치 후기 (매너 점수)                                  (14)
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS om_reviews (
  match_id INTEGER NOT NULL, from_user INTEGER NOT NULL, to_user INTEGER NOT NULL,
  stars INTEGER NOT NULL, tag TEXT, created_at BIGINT NOT NULL,
  UNIQUE(match_id, from_user, to_user)
);`);

/* ═══ 플랩식 매니저 시스템 — 지원 → 호스트 지정 → 매치 종료 후 정산 ═══ */
try { db.exec('ALTER TABLE open_matches ADD COLUMN manager_id INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE open_matches ADD COLUMN manager_fee INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE open_matches ADD COLUMN settled INTEGER DEFAULT 0'); } catch (e) {}
db.exec(`CREATE TABLE IF NOT EXISTS om_manager_apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER, user_id INTEGER, created_at TEXT)`);
db.exec(`CREATE TABLE IF NOT EXISTS om_match_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER, user_id INTEGER,
  match_r TEXT, manager_r TEXT, venue_r TEXT, note TEXT, created_at TEXT)`);

try { db.exec('ALTER TABLE users ADD COLUMN bank_account TEXT'); } catch (e) {}
db.exec(`CREATE TABLE IF NOT EXISTS om_payouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER, user_id INTEGER,
  amount INTEGER, bank TEXT, status TEXT DEFAULT 'requested', created_at TEXT, paid_at TEXT)`);
app.post('/me/bank', auth, (req, res) => {
  const bank = String((req.body && req.body.bank) || '').trim().slice(0, 80);
  db.prepare('UPDATE users SET bank_account=? WHERE id=?').run(bank, req.uid);
  res.json(db.prepare('SELECT * FROM users WHERE id=?').get(req.uid));
});
app.get('/admin/payouts', admin, (_req, res) => {
  res.json(db.prepare(`SELECT p.*, u.name FROM om_payouts p JOIN users u ON u.id=p.user_id
    WHERE p.status='requested' ORDER BY p.id DESC LIMIT 100`).all()
    .map(p => ({ ...p, bank: p.bank || (db.prepare('SELECT bank_account FROM users WHERE id=?').get(p.user_id) || {}).bank_account || '' })));
});
app.post('/admin/payouts/:id/paid', admin, (req, res) => {
  const p = db.prepare('SELECT * FROM om_payouts WHERE id=?').get(+req.params.id);
  if (!p || p.status !== 'requested') return res.status(400).json({ error: 'bad_state' });
  db.prepare("UPDATE om_payouts SET status='paid', paid_at=? WHERE id=?").run(now(), p.id);
  sendPush(p.user_id, { icon: '✅', title: '정산 이체가 완료됐어요', body: `운영 정산 ${(p.amount || 0).toLocaleString()}원이 입금됐어요` });
  res.json({ ok: true });
});
app.post('/open-matches/:id/manager-apply', auth, limitWrite, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id === req.uid) return res.status(400).json({ error: 'host_cannot_apply' });
  if (m.manager_id) return res.status(400).json({ error: 'manager_set' });
  if (db.prepare('SELECT 1 FROM om_manager_apps WHERE match_id=? AND user_id=?').get(m.id, req.uid))
    return res.status(400).json({ error: 'already_applied' });
  db.prepare('INSERT INTO om_manager_apps (match_id,user_id,created_at) VALUES (?,?,?)').run(m.id, req.uid, now());
  const me = getUser(req.uid);
  if (m.host_id) sendPush(m.host_id, { icon: '🎽', title: '매니저 지원이 왔어요', body: `${me ? me.name : '회원'} 님이 ${m.dt || ''} 매치 운영을 맡고 싶어해요` });
  res.json({ ok: true });
});
app.post('/open-matches/:id/manager', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid) return res.status(403).json({ error: 'host_only' });
  const uid = intOrNull(req.body && req.body.user_id), fee = Math.max(0, +(req.body && req.body.fee) || 0);
  if (!uid || !getUser(uid)) return res.status(400).json({ error: 'no_user' });
  db.prepare('UPDATE open_matches SET manager_id=?, manager_fee=? WHERE id=?').run(uid, fee, m.id);
  sendPush(uid, { icon: '🎽', title: '매니저로 지정됐어요', body: `${m.dt || ''} 매치 운영을 맡게 됐어요${fee ? ` · 정산 ${fee}캐쉬` : ''}` });
  res.json({ ok: true, manager_id: uid, manager_fee: fee });
});
app.post('/open-matches/:id/settle', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid) return res.status(403).json({ error: 'host_only' });
  if (m.settled) return res.status(400).json({ error: 'already_settled' });
  if (!m.manager_id || !m.manager_fee) return res.status(400).json({ error: 'no_manager_fee' });
  // 원화 정산: 캐쉬가 아니라 실제 계좌 이체 대상 — 요청을 만들고 운영자가 이체 후 완료 처리한다
  const mu = getUser(m.manager_id);
  tx(() => {
    db.prepare('INSERT INTO om_payouts (match_id,user_id,amount,bank,status,created_at) VALUES (?,?,?,?,?,?)')
      .run(m.id, m.manager_id, m.manager_fee, (mu && mu.bank_account) || '', 'requested', now());
    db.prepare('UPDATE open_matches SET settled=1 WHERE id=?').run(m.id);
  });
  sendPush(m.manager_id, { icon: '💰', title: '운영 정산이 요청됐어요', body: `${m.dt || ''} 매치 · ${m.manager_fee.toLocaleString()}원 · ${(mu && mu.bank_account) ? '등록 계좌로 이체 예정이에요' : '내정보에서 정산 계좌를 등록해 주세요'}` });
  res.json({ ok: true, payout: true });
});
/* 등급 추이 — 레이팅이 움직이는 모든 지점을 기록한다 (10경기부터 추이 노출) */
db.exec(`CREATE TABLE IF NOT EXISTS rating_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, delta INTEGER, rating INTEGER, reason TEXT, created_at TEXT)`);
function logRating(uid, delta, rating, reason) {
  try { db.prepare('INSERT INTO rating_log (user_id,delta,rating,reason,created_at) VALUES (?,?,?,?,?)').run(uid, delta|0, rating|0, reason, now()); } catch (e) {}
}
app.get('/me/rating-log', auth, (req, res) => {
  res.json(db.prepare('SELECT delta,rating,reason,created_at FROM rating_log WHERE user_id=? ORDER BY id DESC LIMIT 40').all(req.uid).reverse());
});
/* 매니저 배치·경기력 평가 — 소셜 매치의 레벨 산정 주체는 매니저(또는 호스트).
   미배치 선수는 평가 레벨로 즉시 배치, 기배치 선수는 평가 쪽으로 1/3 가중 보정.
   개인 도전전 MMR(상호확인 레이팅)은 기존대로 병행된다. */
db.exec(`CREATE TABLE IF NOT EXISTS om_assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER, manager_id INTEGER,
  user_id INTEGER, level TEXT, created_at TEXT)`);
const ASSESS_MID = { '퓨처스1':840,'퓨처스2':915,'퓨처스3':975,'챌린저1':1025,'챌린저2':1075,'챌린저3':1125,'챌린저4':1175,'챌린저5':1225,'투어1':1285,'투어2':1355,'투어3':1425,'그랜드슬램':1500 };
try { db.exec('ALTER TABLE open_matches ADD COLUMN bracket TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE open_matches ADD COLUMN photo TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE open_matches ADD COLUMN photos TEXT'); } catch (e) {}
app.post('/open-matches/:id/photos', auth, limitWrite, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid && m.manager_id !== req.uid) return res.status(403).json({ error: 'host_only' });
  const urls = (Array.isArray(req.body && req.body.urls) ? req.body.urls : [])
    .map(u => String(u || '').slice(0, 300)).filter(u => u.startsWith('/uploads/')).slice(0, 6);
  db.prepare('UPDATE open_matches SET photos=?, photo=? WHERE id=?').run(JSON.stringify(urls), urls[0] || '', m.id);
  res.json({ ok: true, photos: urls });
});
app.post('/open-matches/:id/photo', auth, limitWrite, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid && m.manager_id !== req.uid) return res.status(403).json({ error: 'host_only' });
  const url = String((req.body && req.body.url) || '').slice(0, 300);
  if (url && !url.startsWith('/uploads/')) return res.status(400).json({ error: 'bad_url' });
  db.prepare('UPDATE open_matches SET photo=? WHERE id=?').run(url, m.id);
  res.json({ ok: true, photo: url });
});
app.post('/open-matches/:id/bracket', auth, limitWrite, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.manager_id !== req.uid && m.host_id !== req.uid) return res.status(403).json({ error: 'manager_only' });
  const br = JSON.stringify(req.body && req.body.bracket || null).slice(0, 8000);
  db.prepare('UPDATE open_matches SET bracket=? WHERE id=?').run(br, m.id);
  res.json({ ok: true });
});
app.post('/open-matches/:id/assess', auth, limitWrite, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.manager_id !== req.uid && m.host_id !== req.uid) return res.status(403).json({ error: 'manager_only' });
  const started = m.start_at && Date.parse(m.start_at) < Date.now();
  if (!(started || (m.status && m.status !== 'open'))) return res.status(400).json({ error: 'not_finished' });
  let applied = 0;
  for (const p of (req.body && req.body.players) || []) {
    const uid = intOrNull(p.user_id), mid = ASSESS_MID[p.level];
    if (!uid || !mid || uid === req.uid) continue;                       // 본인 평가는 제외
    if (!db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(m.id, uid)) continue;
    const u = getUser(uid); if (!u) continue;
    const prior = db.prepare('SELECT COUNT(*) n FROM om_assessments WHERE user_id=?').get(uid).n;
    const played = db.prepare("SELECT COUNT(*) n FROM matches WHERE status='confirmed' AND (home_user_id=? OR away_user_id=?)").get(uid, uid).n;
    const placed = prior > 0 || played > 0;
    const nr = placed ? Math.round(((u.rating || 1000) + mid * 2) / 3) : mid;   // 배치 or 보정
    tx(() => {
      db.prepare('INSERT INTO om_assessments (match_id,manager_id,user_id,level,created_at) VALUES (?,?,?,?,?)')
        .run(m.id, req.uid, uid, p.level, now());
      db.prepare('UPDATE users SET rating=? WHERE id=?').run(nr, uid);
    });
    logRating(uid, nr - (u.rating || 1000), nr, placed ? '매니저 평가' : '매니저 배치');
    sendPush(uid, { icon: '📊', title: placed ? '경기력 평가가 반영됐어요' : '레벨이 배치됐어요', body: `매니저 평가: ${p.level} · ${m.dt || ''} 매치` });
    applied++;
  }
  res.json({ ok: true, applied });
});
/* 플랩식 매치 평가 — 매치·매니저·구장 3축 + 한줄 소감 (1인 1회, 수정 가능) */
app.post('/open-matches/:id/match-review', auth, limitWrite, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const joined = !!db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(m.id, req.uid);
  if (!joined && m.host_id !== req.uid) return res.status(403).json({ error: 'participants_only' });
  const started = m.start_at && Date.parse(m.start_at) < Date.now();
  if (!(started || (m.status && m.status !== 'open'))) return res.status(400).json({ error: 'not_finished' });
  const ok = v => ['good', 'bad', 'praise'].includes(v) ? v : null;
  const b = req.body || {};
  const prev = db.prepare('SELECT id FROM om_match_reviews WHERE match_id=? AND user_id=?').get(m.id, req.uid);
  if (prev) db.prepare('UPDATE om_match_reviews SET match_r=?, manager_r=?, venue_r=?, note=?, created_at=? WHERE id=?')
    .run(ok(b.match_r), ok(b.manager_r), ok(b.venue_r), String(b.note || '').slice(0, 300), now(), prev.id);
  else db.prepare('INSERT INTO om_match_reviews (match_id,user_id,match_r,manager_r,venue_r,note,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(m.id, req.uid, ok(b.match_r), ok(b.manager_r), ok(b.venue_r), String(b.note || '').slice(0, 300), now());
  if (ok(b.manager_r) === 'praise' && m.manager_id && m.manager_id !== req.uid)
    sendPush(m.manager_id, { icon: '👏', title: '매니저 칭찬을 받았어요', body: '오늘 매치 운영이 좋았대요!' });
  res.json({ ok: true });
});
app.post('/open-matches/:id/reviews', auth, limitWrite, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  // 평가 창: 경기 시작 이후 ~ 종료(없으면 시작) + 24시간
  const startT = m.start_at ? Date.parse(m.start_at) : null;
  const endT = (m.end_at ? Date.parse(m.end_at) : startT);
  if (startT && Date.now() < startT) return res.status(400).json({ error: 'not_started' });
  if (endT && Date.now() > endT + 24 * 3600e3) return res.status(400).json({ error: 'review_closed' });
  const started = m.start_at ? Date.parse(m.start_at) < Date.now() : false;
  if (!(started || (m.status && m.status !== 'open'))) return res.status(400).json({ error: 'not_finished' });
  const me = db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid);
  const isHost = m.host_id === req.uid;
  if (!me && !isHost) return res.status(403).json({ error: 'participants_only' });
  const to = intOrNull((req.body || {}).to_user);
  const stars = Math.max(1, Math.min(5, intOrNull((req.body || {}).stars) || 0));
  if (!to || to === req.uid || !stars) return res.status(400).json({ error: 'bad_input' });
  const target = db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, to) || m.host_id === to;
  if (!target) return res.status(400).json({ error: 'not_participant' });
  try {
    db.prepare('INSERT INTO om_reviews (match_id,from_user,to_user,stars,tag,created_at) VALUES (?,?,?,?,?,?)')
      .run(mid, req.uid, to, stars, String((req.body || {}).tag || '').slice(0, 20) || null, now());
  } catch { return res.status(409).json({ error: 'already_reviewed' }); }
  res.json({ ok: true });
});

// 클럽 회원 평점 — 별점 1~5, 익명 집계, 평가자별 1표(수정 가능)
db.exec(`CREATE TABLE IF NOT EXISTS club_peer_reviews (
  club_id INTEGER NOT NULL, from_user INTEGER NOT NULL, to_user INTEGER NOT NULL,
  stars INTEGER NOT NULL, updated_at BIGINT,
  PRIMARY KEY (club_id, from_user, to_user)
);`);

app.get('/clubs/:id/peer-reviews', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT u.id user_id, u.name,
      (SELECT ROUND(AVG(stars),1) FROM club_peer_reviews r WHERE r.club_id=cm.club_id AND r.to_user=u.id) avg,
      (SELECT COUNT(*) FROM club_peer_reviews r WHERE r.club_id=cm.club_id AND r.to_user=u.id) n,
      (SELECT stars FROM club_peer_reviews r WHERE r.club_id=cm.club_id AND r.to_user=u.id AND r.from_user=?) my
    FROM club_members cm JOIN users u ON u.id=cm.user_id
    WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active') AND u.id<>?
    ORDER BY u.name`).all(req.uid, cid, req.uid);
  res.json(rows);
});

app.post('/clubs/:id/peer-reviews', auth, limitWrite, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const to = intOrNull((req.body || {}).to);
  const stars = Math.min(5, Math.max(1, intOrNull((req.body || {}).stars) || 0));
  if (!to || !stars) return res.status(400).json({ error: 'bad_request' });
  if (to === req.uid) return res.status(400).json({ error: 'self_review' });
  if (!isMember(cid, to)) return res.status(400).json({ error: 'not_member' });
  db.prepare(`INSERT INTO club_peer_reviews (club_id,from_user,to_user,stars,updated_at) VALUES (?,?,?,?,?)
    ON CONFLICT(club_id,from_user,to_user) DO UPDATE SET stars=excluded.stars, updated_at=excluded.updated_at`)
    .run(cid, req.uid, to, stars, now());
  res.json({ ok: true });
});

// ══════════ 코트 예약 현황 — 임원이 슬롯 상태를 관리, 회원은 열람 ══════════
db.exec(`CREATE TABLE IF NOT EXISTS club_court_slots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL, label TEXT NOT NULL, detail TEXT,
  status TEXT NOT NULL DEFAULT 'open', updated_by INTEGER, updated_at BIGINT
);`);

app.get('/clubs/:id/courts', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  res.json(db.prepare('SELECT id,label,detail,status FROM club_court_slots WHERE club_id=? ORDER BY id').all(cid));
});

app.post('/clubs/:id/courts', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const label = String((req.body || {}).label || '').trim().slice(0, 40);
  const detail = String((req.body || {}).detail || '').trim().slice(0, 40);
  if (!label) return res.status(400).json({ error: 'label_required' });
  const r = db.prepare('INSERT INTO club_court_slots (club_id,label,detail,status,updated_by,updated_at) VALUES (?,?,?,?,?,?)')
    .run(cid, label, detail, 'open', req.uid, now());
  res.json({ ok: true, id: rid(r) });
});

app.patch('/clubs/:id/courts/:sid', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const st = String((req.body || {}).status || '');
  if (!['open', 'requested', 'booked'].includes(st)) return res.status(400).json({ error: 'bad_status' });
  db.prepare('UPDATE club_court_slots SET status=?, updated_by=?, updated_at=? WHERE id=? AND club_id=?')
    .run(st, req.uid, now(), +req.params.sid, cid);
  res.json({ ok: true });
});

app.delete('/clubs/:id/courts/:sid', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  db.prepare('DELETE FROM club_court_slots WHERE id=? AND club_id=?').run(+req.params.sid, cid);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  기록 종목 (러닝·수영) — 개인 기록장 + 클럽 월간 보드
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS sport_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL, sport TEXT NOT NULL,
  ymd TEXT NOT NULL, dist_m INTEGER NOT NULL, secs INTEGER,
  note TEXT, created_at BIGINT
);
CREATE INDEX IF NOT EXISTS ix_records_user ON sport_records(user_id, sport, ymd);`);
try { db.exec("ALTER TABLE sport_records ADD COLUMN rtype TEXT DEFAULT 'train'"); } catch (e) { /* 이미 있음 */ }
try { db.exec('ALTER TABLE sport_records ADD COLUMN stroke TEXT'); } catch (e) { /* 수영 영법 */ }
try { db.exec('ALTER TABLE sport_records ADD COLUMN photo TEXT'); } catch (e) { /* 다이어리 사진 */ }
try { db.exec('ALTER TABLE sport_records ADD COLUMN detail TEXT'); } catch (e) { /* 종목별 상세(JSON) */ }

app.get('/records', auth, (req, res) => {
  const sport = String(req.query.sport || '');
  res.json(db.prepare(`SELECT * FROM sport_records WHERE user_id=? ${sport ? 'AND sport=?' : ''}
    ORDER BY ymd DESC, id DESC LIMIT 40`).all(...(sport ? [req.uid, sport] : [req.uid])));
});

app.post('/records', auth, limitWrite, (req, res) => {
  const b = req.body || {};
  const sport = String(b.sport || '').slice(0, 20);
  const ymd = String(b.ymd || '').slice(0, 10);
  const dist_m = Math.max(1, Math.min(300000, intOrNull(b.dist_m) || 0));
  const secs = Math.max(0, Math.min(86400, intOrNull(b.secs) || 0)) || null;
  const note = String(b.note || '').trim().slice(0, 120) || null;
  const rtype = ['race', 'club', 'lesson'].includes(b.rtype) ? b.rtype : 'train';
  const stroke = ['자유형','배영','평영','접영','혼영'].includes(b.stroke) ? b.stroke : null;
  let photo = null;
  if (typeof b.photo === 'string' && b.photo.startsWith('data:image') && b.photo.length < 400000) photo = b.photo;
  else if (Array.isArray(b.photos)) {
    const arr = b.photos.filter(p => typeof p === 'string' && p.startsWith('data:image')).slice(0, 3);
    const s = JSON.stringify(arr);
    if (arr.length && s.length < 900000) photo = s;   // 여러 장은 JSON 배열로
  }
  let detail = null;
  if (b.detail && typeof b.detail === 'object') { const s = JSON.stringify(b.detail); if (s.length <= 600) detail = s; }
  if (!sport || !/^\d{4}-\d{2}-\d{2}$/.test(ymd) || !dist_m)
    return res.status(400).json({ error: 'bad_request' });
  const r = db.prepare('INSERT INTO sport_records (user_id,sport,ymd,dist_m,secs,note,created_at,rtype,stroke,photo,detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .run(req.uid, sport, ymd, dist_m, secs, note, now(), rtype, stroke, photo, detail);
  res.json(db.prepare('SELECT * FROM sport_records WHERE id=?').get(rid(r)));   // 저장된 행 전체 반환
});

// 기록 수정 (본인 것만)
app.patch('/records/:id', auth, (req, res) => {
  const r = db.prepare('SELECT * FROM sport_records WHERE id=? AND user_id=?').get(+req.params.id, req.uid);
  if (!r) return res.status(404).json({ error: 'not_found' });
  const b = req.body || {};
  const ymd = /^\d{4}-\d{2}-\d{2}$/.test(b.ymd || '') ? b.ymd : r.ymd;
  const dist_m = Math.min(1000000, Math.max(1, intOrNull(b.dist_m) ?? r.dist_m));
  const secs = b.secs === null ? null : (intOrNull(b.secs) ?? r.secs);
  const note = b.note !== undefined ? (String(b.note || '').trim().slice(0, 120) || null) : r.note;
  const rtype = ['race', 'club', 'train', 'lesson'].includes(b.rtype) ? b.rtype : r.rtype;
  const stroke = ['자유형','배영','평영','접영','혼영'].includes(b.stroke) ? b.stroke : r.stroke;
  let photo = r.photo;
  if (b.photo === null || (Array.isArray(b.photos) && b.photos.length === 0)) photo = null;
  else if (typeof b.photo === 'string' && b.photo.startsWith('data:image') && b.photo.length < 400000) photo = b.photo;
  else if (Array.isArray(b.photos)) {
    const arr = b.photos.filter(p => typeof p === 'string' && p.startsWith('data:image')).slice(0, 3);
    const s = JSON.stringify(arr);
    if (s.length < 900000) photo = arr.length ? s : null;
  }
  let detail = r.detail;
  if (b.detail && typeof b.detail === 'object') { const s = JSON.stringify(b.detail); if (s.length <= 600) detail = s; }
  db.prepare('UPDATE sport_records SET ymd=?, dist_m=?, secs=?, note=?, rtype=?, stroke=?, photo=?, detail=? WHERE id=?')
    .run(ymd, dist_m, secs, note, rtype, stroke, photo, detail, r.id);
  res.json(db.prepare('SELECT * FROM sport_records WHERE id=?').get(r.id));
});
app.delete('/records/:id', auth, (req, res) => {
  db.prepare('DELETE FROM sport_records WHERE id=? AND user_id=?').run(+req.params.id, req.uid);
  res.json({ ok: true });
});

// 클럽 월간 보드 — 이번 달 누적 거리·횟수 랭킹
app.get('/clubs/:id/records/board', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const sport = String(req.query.sport || '');
  const month = String(req.query.month || new Date().toISOString().slice(0, 7));
  const rows = db.prepare(`SELECT u.id user_id, u.name,
      COALESCE(SUM(r.dist_m),0) total_m, COUNT(r.id) sessions,
      MIN(CASE WHEN r.secs>0 THEN r.secs*1000.0/r.dist_m END) best_pace_per_km_x1000
    FROM club_members cm JOIN users u ON u.id=cm.user_id
    LEFT JOIN sport_records r ON r.user_id=u.id AND r.sport=? AND r.ymd LIKE ?
    WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
    GROUP BY u.id ORDER BY total_m DESC, u.name`).all(sport, month + '%', cid);
  res.json({ month, rows });
});

// ══════════════════════════════════════════════════════════════
//  팀 종목 (축구·농구·야구) — 클럽 경기 결과 장부
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS club_team_matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  club_id INTEGER NOT NULL, ymd TEXT NOT NULL,
  opponent TEXT NOT NULL, our_score INTEGER NOT NULL, their_score INTEGER NOT NULL,
  note TEXT, created_by INTEGER, created_at BIGINT
);`);
// 자체전(팀 내부 경기) 지원 — 조끼팀 vs 맨팀 같은 내부 게임을 아카이빙한다
try { db.exec("ALTER TABLE club_team_matches ADD COLUMN kind TEXT DEFAULT 'external'"); } catch (e) { /* 이미 있음 */ }
try { db.exec('ALTER TABLE club_team_matches ADD COLUMN team_a TEXT'); } catch (e) { /* */ }
try { db.exec('ALTER TABLE club_team_matches ADD COLUMN team_b TEXT'); } catch (e) { /* */ }
try { db.exec('ALTER TABLE club_team_matches ADD COLUMN players_a TEXT'); } catch (e) { /* */ }
try { db.exec('ALTER TABLE club_team_matches ADD COLUMN players_b TEXT'); } catch (e) { /* */ }
try { db.exec('ALTER TABLE club_team_matches ADD COLUMN stats TEXT'); } catch (e) { /* 경기별 개인 스탯 JSON */ }

app.get('/clubs/:id/team-matches', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare('SELECT * FROM club_team_matches WHERE club_id=? ORDER BY ymd DESC, id DESC LIMIT 100').all(cid);
  const sum = { w: 0, d: 0, l: 0 };                     // 대외전 승/무/패만
  rows.filter(m => (m.kind || 'external') !== 'intra')
    .forEach(m => { if (m.our_score > m.their_score) sum.w++; else if (m.our_score < m.their_score) sum.l++; else sum.d++; });
  res.json({ rows, summary: sum });
});

app.post('/clubs/:id/team-matches', auth, limitWrite, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const b = req.body || {};
  const ymd = String(b.ymd || '').slice(0, 10);
  const kind = b.kind === 'intra' ? 'intra' : 'external';
  const our = intOrNull(b.our_score), their = intOrNull(b.their_score);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(ymd) || our == null || their == null)
    return res.status(400).json({ error: 'bad_request' });
  const clip = (arr) => Array.isArray(arr) ? JSON.stringify(arr.map(x => String(x).slice(0, 12)).slice(0, 20)) : null;
  let opponent = cleanName(b.opponent, '').slice(0, 24);
  let team_a = null, team_b = null, players_a = null, players_b = null;
  // 개인 스탯: {"이름":{"goal":2,"assist":1}} — 이름·키·값 전부 위생 처리
  let stats = null;
  if (b.stats && typeof b.stats === 'object') {
    const out = {};
    Object.entries(b.stats).slice(0, 20).forEach(([nm, cats]) => {
      if (!cats || typeof cats !== 'object') return;
      const c = {};
      Object.entries(cats).slice(0, 6).forEach(([k, v]) => {
        const n = Math.max(0, Math.min(99, intOrNull(v) || 0));
        if (n > 0) c[String(k).slice(0, 10)] = n;
      });
      if (Object.keys(c).length) out[String(nm).slice(0, 12)] = c;
    });
    if (Object.keys(out).length) stats = JSON.stringify(out);
  }
  if (kind === 'intra') {
    team_a = cleanName(b.team_a, '팀 A').slice(0, 12) || '팀 A';
    team_b = cleanName(b.team_b, '팀 B').slice(0, 12) || '팀 B';
    players_a = clip(b.players_a); players_b = clip(b.players_b);
    opponent = team_b;                                   // 목록 호환용
  } else if (!opponent) return res.status(400).json({ error: 'bad_request' });
  const r = db.prepare(`INSERT INTO club_team_matches
      (club_id,ymd,opponent,our_score,their_score,note,created_by,created_at,kind,team_a,team_b,players_a,players_b,stats)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(cid, ymd, opponent, Math.max(0, our), Math.max(0, their),
      String(b.note || '').slice(0, 60) || null, req.uid, now(), kind, team_a, team_b, players_a, players_b, stats);
  if (kind === 'intra')
    notifyClub(cid, req.uid, '🏆', '자체전 결과가 올라왔어요', `${team_a} ${our} : ${their} ${team_b}`);
  else {
    const rslt = our > their ? '승리' : our < their ? '패배' : '무승부';
    notifyClub(cid, req.uid, '🏆', `경기 결과 · ${rslt}`, `vs ${opponent} ${our}:${their}`);
  }
  res.json({ ok: true, id: rid(r) });
});

app.delete('/clubs/:id/team-matches/:mid', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  db.prepare('DELETE FROM club_team_matches WHERE id=? AND club_id=?').run(+req.params.mid, cid);
  res.json({ ok: true });
});

app.get('/users/:id/manner', (req, res) => {
  const r = db.prepare('SELECT ROUND(AVG(stars),1) avg, COUNT(*) n FROM om_reviews WHERE to_user=?').get(+req.params.id);
  res.json({ avg: r.avg || null, n: r.n });
});

// ══════════════════════════════════════════════════════════════
//  클럽 통계 — 월별 참석률 · 회비 수납률                       (15)
// ══════════════════════════════════════════════════════════════
app.get('/clubs/:id/stats', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const months = [];
  const d = new Date();
  for (let i = 5; i >= 0; i--) {
    const m = new Date(d.getFullYear(), d.getMonth() - i, 1);
    months.push(`${m.getFullYear()}-${String(m.getMonth() + 1).padStart(2, '0')}`);
  }
  const attendance = months.map(mo => {
    const r = db.prepare(`SELECT
        COALESCE(SUM(CASE WHEN ea.showed=1 THEN 1 ELSE 0 END),0) came,
        COUNT(ea.id) total
      FROM event_attendees ea JOIN club_events e ON e.id=ea.event_id
      WHERE e.club_id=? AND substr(e.date,1,7)=? AND ea.showed IS NOT NULL`).get(cid, mo);
    return { month: mo, came: r.came, total: r.total,
             rate: r.total ? Math.round(r.came / r.total * 100) : null };
  });
  const dues = months.map(mo => {
    const r = db.prepare(`SELECT COUNT(*) n,
        COALESCE(SUM(CASE WHEN status='paid' THEN 1 ELSE 0 END),0) paid
      FROM dues WHERE club_id=? AND period=?`).get(cid, mo);
    return { month: mo, paid: r.paid, total: r.n,
             rate: r.n ? Math.round(r.paid / r.n * 100) : null };
  });
  res.json({ attendance, dues });
});

// ══════════════════════════════════════════════════════════════
//  자동 알림 — 미납 회비 독촉 · 오픈매치 마감 임박
//  서버가 살아 있는 동안만 돈다. 인스턴스가 여러 개면 하나만 돌려야 한다.
// ══════════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS sent_reminders (
  kind TEXT NOT NULL, ref TEXT NOT NULL, sent_at BIGINT NOT NULL,
  UNIQUE(kind, ref)
);`);
function onceOnly(kind, ref) {                     // 같은 알림을 두 번 보내지 않는다
  try { db.prepare('INSERT INTO sent_reminders (kind,ref,sent_at) VALUES (?,?,?)').run(kind, ref, now()); return true; }
  catch { return false; }
}

function remindUnpaidDues() {
  const rows = db.prepare(`SELECT d.id, d.user_id, d.period, d.amount, c.name club
    FROM dues d JOIN clubs c ON c.id=d.club_id
    WHERE d.status='unpaid'`).all();
  for (const r of rows) {
    if (!onceOnly('dues', `${r.id}:${new Date().toISOString().slice(0, 7)}`)) continue;   // 월 1회
    sendPush(r.user_id, {
      icon: '💰', title: '회비가 아직 납부되지 않았어요',
      body: `${r.club} · ${r.period} · ${Number(r.amount).toLocaleString()}원`,
    });
  }
}

function remindClosingMatches() {
  const soon = Date.now() + 24 * 3600 * 1000;
  const rows = db.prepare("SELECT * FROM open_matches WHERE status='open'").all();
  for (const m of rows) {
    const t = m.start_at ? Date.parse(m.start_at) : NaN;
    if (!t || t > soon || t < Date.now()) continue;                   // 24시간 안에 시작하는 것만
    const cur = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(m.id).n;
    if (cur >= m.min_cnt) continue;                                   // 이미 성사됨
    if (!onceOnly('om_soon', String(m.id))) continue;
    const need = m.min_cnt - cur;
    if (m.host_id) sendPush(m.host_id, {
      icon: '⏰', title: '오픈매치 성사까지 얼마 안 남았어요',
      body: `${m.loc} · ${need}명 더 필요해요`,
    });
    db.prepare('SELECT user_id FROM om_likes WHERE match_id=?').all(m.id).forEach(l => {   // 관심 누른 사람
      sendPush(l.user_id, { icon: '⏰', title: '관심 있는 오픈매치가 곧 시작해요', body: `${m.loc} · ${need}명 더 필요해요` });
    });
  }
}

function remindTomorrowEvents() {
  // 내일 모임에 '참석' 응답한 회원에게 전날 알림 — 노쇼는 제재보다 예방이 먼저다
  const d = new Date(Date.now() + 24 * 3600 * 1000);
  const tomorrow = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const evs = db.prepare(`SELECT e.id, e.title, e.date, c.name club FROM club_events e
    JOIN clubs c ON c.id=e.club_id WHERE substr(e.date,1,10)=?`).all(tomorrow);
  for (const ev of evs) {
    if (!onceOnly('ev_soon', String(ev.id))) continue;
    const going = db.prepare("SELECT user_id FROM event_attendees WHERE event_id=? AND status='going'").all(ev.id);
    going.forEach(g => sendPush(g.user_id, {
      icon: '📅', title: '내일 모임이 있어요',
      body: `${ev.club} · ${ev.title}${ev.date.length > 10 ? ' · ' + ev.date.slice(11, 16) : ''}`,
    }));
  }
}

// 이번 주 모임 참석 넛지 — 3일 안에 모임이 있는데 아직 응답 안 한 회원에게 1회
function remindRsvpNudge() {
  const today = new Date();
  const evs = db.prepare('SELECT e.*, c.name club FROM club_events e JOIN clubs c ON c.id=e.club_id ORDER BY e.id DESC LIMIT 60').all();
  for (const ev of evs) {
    const mm = String(ev.date || '').match(/(\d{1,2})\/(\d{1,2})/);
    if (!mm) continue;
    const evDate = new Date(today.getFullYear(), +mm[1] - 1, +mm[2]);
    const diff = Math.round((evDate - new Date(today.getFullYear(), today.getMonth(), today.getDate())) / 864e5);
    if (diff < 0 || diff > 3) continue;                 // 지났거나 3일 넘게 남음
    const members = db.prepare(`SELECT cm.user_id FROM club_members cm
      WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
        AND cm.user_id NOT IN (SELECT user_id FROM event_attendees WHERE event_id=?)`).all(ev.club_id, ev.id);
    members.forEach(m => {
      if (!onceOnly('rsvp_nudge', `${ev.id}:${m.user_id}`)) return;
      sendPush(m.user_id, { icon: '🎾', title: `${diff === 0 ? '오늘' : diff === 1 ? '내일' : `${diff}일 뒤`} 모임 · 참석 체크하세요`,
        body: `${ev.club} · ${ev.title} ${ev.date} — 참석을 누르면 대진에 자동 포함돼요` });
    });
  }
}

// 모임 다음 날 넛지 — 전 종목. 종목마다 '다음 날 할 일'이 다르다:
//   기록(러닝·수영): 참석자에게 기록 입력 / 라켓: 참석자에게 결과 확정 / 팀: 임원에게 기록실 입력
const SPORT_NUDGE = {
  running:    { icon: '🏃', who: 'attendees', title: '어제 기록을 남겨보세요', link: 'league',
    body: (ev) => `${ev.club} · ${ev.title} — 거리와 시간을 올리면 이번 달 랭킹과 개인 기록에 반영돼요` },
  swimming:   { icon: '🏊', who: 'attendees', title: '어제 기록을 남겨보세요', link: 'league',
    body: (ev) => `${ev.club} · ${ev.title} — 거리와 시간을 올리면 이번 달 랭킹과 개인 기록에 반영돼요` },
  tennis:     { icon: '🎾', who: 'attendees', title: '어제 경기 결과를 확정하세요', link: 'bracket',
    body: (ev) => `${ev.club} · ${ev.title} — 점수를 확정하면 레이팅과 랭킹에 반영돼요` },
  badminton:  { icon: '🏸', who: 'attendees', title: '어제 경기 결과를 확정하세요', link: 'bracket',
    body: (ev) => `${ev.club} · ${ev.title} — 점수를 확정하면 레이팅과 랭킹에 반영돼요` },
  soccer:     { icon: '⚽', who: 'officers', title: '어제 경기를 기록실에 남겨보세요', link: 'league',
    body: (ev) => `${ev.club} · ${ev.title} — 자체전 결과와 골·도움을 기록하면 회원 스탯에 쌓여요` },
  basketball: { icon: '🏀', who: 'officers', title: '어제 경기를 기록실에 남겨보세요', link: 'league',
    body: (ev) => `${ev.club} · ${ev.title} — 자체전 결과와 개인 스탯을 기록하면 아카이브에 쌓여요` },
  baseball:   { icon: '⚾', who: 'officers', title: '어제 경기를 기록실에 남겨보세요', link: 'league',
    body: (ev) => `${ev.club} · ${ev.title} — 경기 결과와 개인 기록을 남기면 아카이브에 쌓여요` },
};

function remindRecordAfterEvent() {
  const today = new Date();
  const yst = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  const evs = db.prepare(`SELECT e.*, c.name club, c.sport FROM club_events e
    JOIN clubs c ON c.id=e.club_id ORDER BY e.id DESC LIMIT 60`).all();
  for (const ev of evs) {
    const cfg = SPORT_NUDGE[ev.sport] || SPORT_NUDGE.tennis;
    const mm = String(ev.date || '').match(/(\d{1,2})\/(\d{1,2})/);
    if (!mm) continue;
    const evDate = new Date(today.getFullYear(), +mm[1] - 1, +mm[2]);
    if (evDate.getTime() !== yst.getTime()) continue;   // 정확히 어제 모임만
    const targets = cfg.who === 'officers'
      ? db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND role IN ('owner','officer')").all(ev.club_id)
      : db.prepare("SELECT DISTINCT user_id FROM event_attendees WHERE event_id=? AND (status IS NULL OR status='going')").all(ev.id);
    targets.forEach(a => {
      if (!onceOnly('rec_nudge', `${ev.id}:${a.user_id}`)) return;
      sendPush(a.user_id, { icon: cfg.icon, title: cfg.title, body: cfg.body(ev), link: cfg.link });
    });
  }
}

function runReminders() {
  try { remindRecordAfterEvent(); } catch (e) { console.error('record nudge', e.message); }
  try { remindUnpaidDues(); } catch (e) { console.error('dues reminder', e.message); }
  try { remindRsvpNudge(); } catch (e) { console.error('rsvp nudge', e.message); }
  try { remindClosingMatches(); } catch (e) { console.error('match reminder', e.message); }
  try { remindTomorrowEvents(); } catch (e) { console.error('event reminder', e.message); }
}
if (process.env.REMINDERS !== 'off') {
  setTimeout(runReminders, 30_000);                    // 부팅 직후 한 번
  setInterval(runReminders, 6 * 3600 * 1000).unref?.();  // 6시간마다
}
app.post('/admin/run-reminders', admin, (_req, res) => { runReminders(); res.json({ ok: true }); });

// ── 운영자 대시보드 API ──
// 접근키: env ADMIN_KEY (미설정 시 데모용 'matsu-admin'). 헤더 x-admin-key 또는 ?key=
const ADMIN_KEY = process.env.ADMIN_KEY || 'matsu-admin';
function admin(req, res, next) {
  // 키는 반드시 헤더로. URL 쿼리는 브라우저 히스토리·서버 로그에 그대로 남는다.
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'admin_only' });
  next();
}
// 관리자가 특정 클럽에 프리미엄을 직접 부여 (초기 파트너 클럽 · 환불 · 테스트)
// 결제와 무관하게 열어주는 유일한 경로. ADMIN_KEY 를 아는 사람만.
// 운영자용 클럽 목록 — 클럽장·회원까지 함께 (클럽장 변경 UI 용)
app.get('/admin/clubs', admin, (_req, res) => {
  const clubs = db.prepare(`SELECT c.id, c.name, c.sport, c.region,
      (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id AND (m.status IS NULL OR m.status='active')) members
    FROM clubs c ORDER BY c.id DESC LIMIT 200`).all();
  res.json(clubs.map(c => ({
    ...c,
    owner: db.prepare(`SELECT u.id, u.name FROM club_members cm JOIN users u ON u.id=cm.user_id
      WHERE cm.club_id=? AND cm.role='owner' LIMIT 1`).get(c.id) || null,
    roster: db.prepare(`SELECT u.id, u.name, cm.role FROM club_members cm JOIN users u ON u.id=cm.user_id
      WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active') ORDER BY cm.role='owner' DESC, u.name LIMIT 50`).all(c.id),
  })));
});
// 운영자가 클럽장을 강제 변경 — 분쟁·연락 두절 클럽장 처리용. 기존 양도와 같은 규칙으로 정리한다.
app.post('/admin/clubs/:id/owner', admin, (req, res) => {
  const cid = +req.params.id, uid = intOrNull(req.body && req.body.user_id);
  const club = db.prepare('SELECT id,name FROM clubs WHERE id=?').get(cid);
  if (!club) return res.status(404).json({ error: 'not_found' });
  const t = db.prepare('SELECT status FROM club_members WHERE club_id=? AND user_id=?').get(cid, uid);
  if (!uid || !t) return res.status(400).json({ error: 'not_member' });
  if (t.status && t.status !== 'active') return res.status(400).json({ error: 'not_active' });
  const prev = db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND role='owner'").get(cid);
  tx(() => {
    if (prev) db.prepare("UPDATE club_members SET role='officer' WHERE club_id=? AND user_id=?").run(cid, prev.user_id);
    db.prepare("UPDATE club_members SET role='owner' WHERE club_id=? AND user_id=?").run(cid, uid);
    db.prepare('UPDATE clubs SET owner_id=? WHERE id=?').run(uid, cid);
  });
  sendPush(uid, { icon: '👑', title: '클럽장이 됐어요', body: `${club.name} 클럽장 권한을 받았어요 (운영자 지정)` });
  if (prev && prev.user_id !== uid) sendPush(prev.user_id, { icon: '🔧', title: '클럽장 변경 안내', body: `${club.name} 클럽장이 운영자에 의해 변경됐어요 · 임원으로 남아요` });
  res.json({ ok: true, club_id: cid, new_owner: uid });
});
app.post('/admin/clubs/:id/premium', admin, (req, res) => {
  const cid = +req.params.id;
  const c = db.prepare('SELECT id FROM clubs WHERE id=?').get(cid);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const months = Math.min(24, Math.max(1, intOrNull(req.body && req.body.months) || 1));
  const until = activatePremium(cid, months);
  res.json({ ok: true, club_id: cid, premium_until: until, granted_by: 'admin' });
});

// 클럽 영구 삭제 — 연관 데이터까지 전부 (복구 불가)
app.delete('/admin/clubs/:id', admin, (req, res) => {
  const cid = +req.params.id;
  const c = db.prepare('SELECT id,name FROM clubs WHERE id=?').get(cid);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const tables = db.prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all().map(t => t.name);
  let wiped = [];
  tx(() => {
    tables.forEach(t => {
      const cols = db.prepare(`PRAGMA table_info(${t})`).all().map(x => x.name);
      if (cols.includes('club_id') && t !== 'clubs') {
        const n = db.prepare(`DELETE FROM ${t} WHERE club_id=?`).run(cid).changes;
        if (n) wiped.push(`${t}:${n}`);
      }
    });
    db.prepare('DELETE FROM clubs WHERE id=?').run(cid);
  });
  res.json({ ok: true, deleted: c.name, wiped });
});

// 사용자 영구 삭제 — 탈퇴(익명) 계정 정리용 (복구 불가)
app.delete('/admin/users/:id', admin, (req, res) => {
  const uid = +req.params.id;
  const u = db.prepare('SELECT id,name,suspended FROM users WHERE id=?').get(uid);
  if (!u) return res.status(404).json({ error: 'not_found' });
  if (!u.suspended && req.query.force !== '1')
    return res.status(400).json({ error: 'active_user', message: '활성 계정이에요 · ?force=1 로만 삭제 가능' });
  const tables = db.prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all().map(t => t.name);
  let wiped = [];
  tx(() => {
    tables.forEach(t => {
      const cols = db.prepare(`PRAGMA table_info(${t})`).all().map(x => x.name);
      if (t === 'users') return;
      ['user_id', 'from_user', 'to_user', 'from_id', 'to_id', 'author_id', 'host_id'].forEach(col => {
        if (cols.includes(col)) {
          const n = db.prepare(`DELETE FROM ${t} WHERE ${col}=?`).run(uid).changes;
          if (n) wiped.push(`${t}.${col}:${n}`);
        }
      });
    });
    db.prepare('DELETE FROM users WHERE id=?').run(uid);
  });
  res.json({ ok: true, deleted: u.name, wiped });
});

// 정리 대상 조회 — 탈퇴 계정·클럽 목록
app.get('/admin/purge-list', admin, (_req, res) => {
  res.json({
    suspended_users: db.prepare('SELECT id,name,created_at FROM users WHERE suspended=1').all(),
    clubs: db.prepare(`SELECT c.id, c.name, c.sport,
      (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id) members FROM clubs c ORDER BY c.id`).all(),
  });
});

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
// ── 오픈매치 봇 (admin.html 오픈매치·봇 탭) ──────────────────────
// 목록 + 참가자
app.get('/admin/open-matches', admin, (_req, res) => {
  const ms = db.prepare(`SELECT id,loc,dt,price,cap,status,sport FROM open_matches
    ORDER BY id DESC LIMIT 100`).all();
  res.json(ms.map(m => ({ ...m,
    players: db.prepare(`SELECT u.id, u.name, u.provider
      FROM open_match_joins j JOIN users u ON u.id = j.user_id
      WHERE j.match_id = ? ORDER BY j.joined_at`).all(m.id) })));
});
// 봇 참가자 추가 — 이름만으로 provider='bot' 유저를 만들어 참가시킨다
app.post('/admin/open-matches/:id/bots', admin, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const body = req.body || {};
  const bots = (body.bots || (body.names || []).map(n => ({ name: n })))
    .map(b => ({ name: String(b.name || '').trim(),
                 gender: b.gender === '여성' ? '여성' : '남성',
                 rating: Math.max(600, Math.min(1700, +b.rating || 1000)) }))
    .filter(b => b.name).slice(0, 20);
  let added = 0;
  for (const b of bots) {
    const cur = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n;
    if (cur >= (m.cap || 8)) break;                                   // 정원 초과 방지
    const pid = 'bot:' + b.name;
    let u = db.prepare("SELECT id FROM users WHERE provider='bot' AND provider_id=?").get(pid);
    if (!u) {
      const r = db.prepare(`INSERT INTO users (provider,provider_id,name,gender,rating,sport,anon_nick,created_at)
        VALUES ('bot',?,?,?,?,?,?,?)`).run(pid, b.name, b.gender, b.rating, m.sport || 'tennis', b.name, now());
      u = { id: r.lastInsertRowid };
      db.prepare('UPDATE users SET cash=0 WHERE id=?').run(u.id);
    } else {
      db.prepare('UPDATE users SET gender=?, rating=? WHERE id=?').run(b.gender, b.rating, u.id);
    }
    const r2 = db.prepare(`INSERT OR IGNORE INTO open_match_joins (match_id,user_id,joined_at)
      VALUES (?,?,?)`).run(mid, u.id, now());
    if (r2.changes) added++;
  }
  res.json({ ok: true, added });
});
// 봇(또는 참가자) 제거
app.delete('/admin/open-matches/:id/bots/:uid', admin, (req, res) => {
  db.prepare('DELETE FROM open_match_joins WHERE match_id=? AND user_id=?')
    .run(+req.params.id, +req.params.uid);
  res.json({ ok: true });
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
  const rep = db.prepare('SELECT * FROM reports WHERE id=?').get(+req.params.id);
  const action = (req.body || {}).action || 'reviewed';        // reviewed | removed | rejected
  db.prepare("UPDATE reports SET status='reviewed' WHERE id=?").run(+req.params.id);
  if (rep && rep.reporter_id) {                                // 신고자에게 결과를 알린다
    const msg = action === 'removed' ? '신고하신 글을 삭제했어요'
      : action === 'rejected' ? '신고를 검토했지만 조치하지 않았어요'
      : '신고를 검토했어요';
    sendPush(rep.reporter_id, { icon: '🛡️', title: '신고 처리 결과', body: msg });
  }
  res.json({ ok: true });
});
// ── 운영자 삭제 권한 ──
// 이용약관 위반 게시물을 운영자가 직접 지운다.
// x-admin-key 헤더 또는 ?key= 로 인증. ADMIN_KEY 는 Railway Variables 에 있다.
app.delete('/admin/posts/:id', admin, (req, res) => {
  const id = +req.params.id;
  db.prepare('DELETE FROM comments WHERE post_id=?').run(id);
  const r = db.prepare('DELETE FROM posts WHERE id=?').run(id);
  res.json({ ok: true, deleted: !!(r.changes) });
});
app.delete('/admin/comments/:id', admin, (req, res) => {
  const r = db.prepare('DELETE FROM comments WHERE id=?').run(+req.params.id);
  res.json({ ok: true, deleted: !!(r.changes) });
});
app.delete('/admin/notices/:id', admin, (req, res) => {
  const r = db.prepare('DELETE FROM notices WHERE id=?').run(+req.params.id);
  res.json({ ok: true, deleted: !!(r.changes) });
});
app.delete('/admin/open-matches/:id', admin, (req, res) => {
  const id = +req.params.id;
  db.prepare('DELETE FROM open_match_joins WHERE match_id=?').run(id);
  const r = db.prepare('DELETE FROM open_matches WHERE id=?').run(id);
  res.json({ ok: true, deleted: !!(r.changes) });
});
// 최근 게시물 훑어보기 (신고가 없어도 확인할 수 있게)
app.get('/admin/feed', admin, (_req, res) => {
  res.json({
    posts: db.prepare(`SELECT p.id, p.title, p.body, p.hidden, p.created_at, u.name author
      FROM posts p LEFT JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 50`).all(),
    open_matches: db.prepare(`SELECT m.id, m.dt, m.loc, m.note, u.name host
      FROM open_matches m LEFT JOIN users u ON u.id=m.host_id ORDER BY m.id DESC LIMIT 50`).all(),
  });
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
