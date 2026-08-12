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

// ── 부팅 진단: 스키마 초기화 실패를 조용히 죽지 않게 (Railway 로그에 원인 남김) ──
try {
  initSchema();
  console.log('[boot] initSchema OK');
} catch (e) {
  console.error('[boot] initSchema FAILED:', e && e.message);
  console.error(e && e.stack);
  throw e;                                   // 원인을 로그에 남기고 종료
}
process.on('uncaughtException', (e) => {
  console.error('[fatal] uncaughtException:', e && e.message);
  console.error(e && e.stack);
});
process.on('unhandledRejection', (e) => {
  console.error('[fatal] unhandledRejection:', (e && e.message) || e);
  console.error((e && e.stack) || '');
});
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
const limitUpload = rateLimit({ windowMs: 60_000, max: 80 });   // 소식에 사진 여러 장을 한 번에 올린다


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
const MIN_AGE = 14;   // 만 14세 미만 가입 제한
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

const SRV_BUILD = 'sH-0812e';
/* public/index.html 의 BUILD 와 같은 값을 적는다 — 앱 업데이트 안내 기준 */
const WEB_BUILD = process.env.WEB_BUILD || 'v1.0.7-0812r';
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
    kakao_native_redirect_uri: process.env.KAKAO_NATIVE_REDIRECT_URI || '',   // iOS 앱: 딥링크 복귀용
    /* 앱에서 카카오톡을 직접 여는 데 쓰는 네이티브 앱 키.
       JS 키로는 kakaokompassauth:// 스킴이 열리지 않는다. */
    kakao_native_key: process.env.KAKAO_NATIVE_KEY || '',
    kakao_ready: !!(process.env.KAKAO_JS_KEY && process.env.KAKAO_REST_KEY && process.env.KAKAO_REDIRECT_URI),
    naver_client_id: process.env.NAVER_CLIENT_ID || '',
    naver_redirect_uri: process.env.NAVER_REDIRECT_URI || '',
    // APPLE_CLIENT_ID 는 "웹ServicesID,iOS번들ID" 형태 — 웹에는 첫 값만 내려준다
    apple_client_id: (process.env.APPLE_CLIENT_ID || '').split(',')[0].trim(),
    support_email: process.env.SUPPORT_EMAIL || '',
    /* 앱은 index.html 을 통째로 품고 있어서 서버만 올려도 화면이 안 바뀐다.
       서버가 아는 최신 화면 버전을 내려주고, 앱이 자기 것과 다르면 업데이트를 안내한다. */
    web_build: WEB_BUILD,
    ios_app_url: process.env.IOS_APP_URL || 'https://apps.apple.com/kr/app/id6793127517',   // 맞수 App Store
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
  const { code, redirect_uri } = req.body || {};
  const key = process.env.KAKAO_REST_KEY;
  // 교환 시 redirect_uri 는 인가 때 쓴 값과 정확히 같아야 한다.
  // 클라이언트가 보낸 값은 화이트리스트(웹/네이티브)에 있을 때만 인정한다.
  const allowed = [process.env.KAKAO_REDIRECT_URI, process.env.KAKAO_NATIVE_REDIRECT_URI].filter(Boolean);
  const redirect = (redirect_uri && allowed.includes(redirect_uri)) ? redirect_uri : process.env.KAKAO_REDIRECT_URI;
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

/* ── iOS 앱 복귀용 딥링크 ──
   외부 브라우저에서 카카오/네이버 인가가 끝나면 ?code=... 를 달고 여기로 온다.
   커스텀 스킴(matsu://)으로 302 시켜 iOS 가 앱을 다시 열게 한다.
   code 는 일회용·수 분 내 만료라 URL 노출 위험이 작다. */
app.get('/oauth/app-return', (req, res) => {
  const provider = /^[a-z]+$/.test(String(req.query.provider || '')) ? req.query.provider : 'kakao';
  const q = new URLSearchParams({
    provider,
    code: String(req.query.code || ''),
    state: String(req.query.state || ''),
  });
  const target = 'matsu://oauth?' + q.toString();
  // 일부 브라우저는 302 로 커스텀 스킴 이동을 막는다 — HTML 폴백을 함께 준다
  res.set('Cache-Control', 'no-store');
  res.send(`<!doctype html><meta charset="utf-8">
<title>MATSU</title>
<body style="font-family:-apple-system,sans-serif;display:flex;min-height:90vh;align-items:center;justify-content:center;flex-direction:column;gap:14px;background:#f7f5f0">
<div style="font-size:15px;color:#555">앱으로 돌아가는 중이에요…</div>
<a href="${target}" style="padding:12px 22px;background:#111;color:#fff;border-radius:12px;text-decoration:none;font-weight:600">앱 열기</a>
<script>location.href=${JSON.stringify(target)};<\/script>`);
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
  // 만 14세 미만은 법정대리인 동의 없이 가입할 수 없다 (정보통신망법)
  if (clean.birth) {
    const by = parseInt(clean.birth, 10);
    if (by && (new Date().getFullYear() - by) < MIN_AGE)
      return res.status(403).json({ error: 'under_age', min_age: MIN_AGE });
  }
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
  const rd = db.prepare('SELECT COALESCE(rating_doubles,1000) r FROM users WHERE id=?').get(u.id).r;
  const rankD = db.prepare('SELECT COUNT(*)+1 n FROM users WHERE sport=? AND COALESCE(rating_doubles,1000)>?').get(u.sport, rd).n;
  res.json({ ...u, rank, rating_doubles: rd, rank_doubles: rankD });
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
      // 웹(Services ID)과 iOS 앱(번들 ID)의 aud 가 달라 콤마로 여러 개 허용한다
      ...(process.env.APPLE_CLIENT_ID ? { audience: process.env.APPLE_CLIENT_ID.split(',').map(s => s.trim()).filter(Boolean) } : {})
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
/* ── 결제·캐시 장부 ──
   orders: 충전 주문 · cash_ledger: 캐시 증감 내역 · cash_withdrawals: 출금 신청
   (예전 배포에서 만들어진 테이블에 의존하고 있었다. 새 DB에서도 뜨도록 여기서 보장한다) */
db.exec(`
CREATE TABLE IF NOT EXISTS orders (
  order_id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,          -- 결제 금액(원)
  cash INTEGER NOT NULL,            -- 지급 캐시 (1:1)
  status TEXT NOT NULL DEFAULT 'ready',   -- ready|paid|refunded|partial
  payment_key TEXT,
  refunded INTEGER NOT NULL DEFAULT 0,    -- 이미 취소한 금액(부분취소 누적)
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_orders_user ON orders(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS cash_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  delta INTEGER NOT NULL,
  reason TEXT,                      -- toss_purchase|match_refund|om_payout|withdraw|...
  balance_after INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ledger_user ON cash_ledger(user_id, id DESC);
CREATE TABLE IF NOT EXISTS cash_withdrawals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,          -- 신청 총액(캐시)
  card_part INTEGER NOT NULL DEFAULT 0,   -- 카드 취소로 나간 금액
  bank_part INTEGER NOT NULL DEFAULT 0,   -- 계좌이체로 나갈 금액(세전)
  tax INTEGER NOT NULL DEFAULT 0,         -- 원천징수 3.3%
  payout INTEGER NOT NULL DEFAULT 0,      -- 실제 입금액(세후)
  bank TEXT,
  status TEXT NOT NULL DEFAULT 'requested', -- requested|paid|failed
  due_at INTEGER,                    -- 입금 예정일
  created_at INTEGER NOT NULL,
  paid_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_withdraw_user ON cash_withdrawals(user_id, id DESC);
`);
try { db.exec('ALTER TABLE orders ADD COLUMN refunded INTEGER NOT NULL DEFAULT 0'); } catch (e) {}

/* 캐시는 원 단위 1:1 — 1,000원 넣으면 1,000캐시.
   참가비가 4,000원·25,000원처럼 원 단위라 패키지(코인) 방식은 계산이 안 맞는다.
   iOS도 토스로 직접 결제한다(실물 서비스 결제). */
const CASH_MIN = 1000, CASH_MAX = 300000, CASH_STEP = 1000;

/* ── 매치별 참가비 수납 원장 ─────────────────────────────────
   정산은 "실제로 걷힌 돈" 안에서만 나간다. 이 표가 그 근거다.
   status: paid(수납) · refunded(취소 환불)                      */
db.exec(`CREATE TABLE IF NOT EXISTS om_payments (
  id INTEGER PRIMARY KEY,
  match_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  order_id TEXT,
  payment_key TEXT,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'paid',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ompay_match ON om_payments(match_id);
CREATE INDEX IF NOT EXISTS ix_ompay_user ON om_payments(user_id, match_id);`);

/* 이 매치로 실제 들어온 순수납액 (환불 제외) */
function omCollected(matchId) {
  const r = db.prepare(`SELECT COALESCE(SUM(CASE WHEN status='paid' THEN amount ELSE 0 END),0) s
    FROM om_payments WHERE match_id=?`).get(matchId);
  return (r && r.s) || 0;
}
/* 이 사람이 이 매치에 낸 돈 (환불 계산 기준) */
function omPaidBy(matchId, uid) {
  const r = db.prepare(`SELECT COALESCE(SUM(CASE WHEN status='paid' THEN amount ELSE 0 END),0) s
    FROM om_payments WHERE match_id=? AND user_id=?`).get(matchId, uid);
  return (r && r.s) || 0;
}
const OM_MAX_COURT_COST = 600000;   // 코트·캔볼 실비 상한 (건당) — 과다 입력으로 인한 부정 정산 방지

function cashAmountError(amount) {
  if (!Number.isInteger(amount)) return 'not_integer';
  if (amount < CASH_MIN || amount > CASH_MAX) return 'out_of_range';
  if (amount % CASH_STEP !== 0) return 'bad_step';
  return null;
}
app.post('/pay/order', auth, (req, res) => {
  if (requirePayments(req, res)) return;
  const amount = Math.trunc(+req.body.amount);
  const bad = cashAmountError(amount);
  if (bad) return res.status(400).json({ error: 'invalid_amount', reason: bad,
    min: CASH_MIN, max: CASH_MAX, step: CASH_STEP });
  const orderId = 'matsu_' + req.uid + '_' + Date.now();
  db.prepare('INSERT INTO orders (order_id,user_id,amount,cash,status,created_at) VALUES (?,?,?,?,?,?)')
    .run(orderId, req.uid, amount, amount, 'ready', now());          // cash = amount (1:1)
  res.json({ orderId, amount, cash: amount, orderName: `맞수 캐시 ${amount.toLocaleString()}원` });
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
    sendPush(u.id, { title: '충전 완료', body: `캐시 ${ord.cash.toLocaleString()}원이 충전됐어요` });
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

/* ══ 캐시 출금 ══
   캐시는 출처가 두 가지다.
     · 환불 캐시 — 매치 취소로 돌려받은 돈. 원결제 카드로 되돌리는 게 가장 빠르고 세금도 없다.
     · 정산 캐시 — 매니저 수고비·코트비 환급. 소득이라 3.3% 원천징수 후 계좌이체.
   출금은 정산 캐시부터 소진한다. 환불 캐시를 먼저 쓰면 나중에 취소할 원결제가 사라진다. */
const WITHHOLD_RATE = 0.033;
function cashSources(uid) {
  const rows = db.prepare('SELECT delta, reason FROM cash_ledger WHERE user_id=?').all(uid);
  let refundIn = 0, payoutIn = 0, expenseIn = 0, out = 0;
  rows.forEach(r => {
    if (r.delta > 0) {
      if (r.reason === 'om_payout' || r.reason === 'settle') payoutIn += r.delta;   // 수고비 = 소득(과세)
      else if (r.reason === 'om_expense') expenseIn += r.delta;                     // 코트·캔볼 실비 환급(비과세)
      else refundIn += r.delta;                                                     // 충전·매치환불 = 원결제가 있는 돈
    } else out += -r.delta;
  });
  const u = getUser(uid);
  const bal = Math.max(0, u.cash || 0);
  // 이미 쓴 금액은 실비 → 수고비 순으로 차감된 것으로 본다 (환불 캐시는 마지막까지 남긴다)
  let left = out;
  const expUsed = Math.min(left, expenseIn); left -= expUsed;
  const payUsed = Math.min(left, payoutIn);
  const expense = Math.max(0, expenseIn - expUsed);
  const payout = Math.max(0, payoutIn - payUsed);
  const refund = Math.max(0, bal - expense - payout);
  return { balance: bal, payout: Math.min(payout, bal), expense: Math.min(expense, bal), refund };
}
function nextBusinessDay(from, days) {              // 영업일 n일 뒤 (주말 건너뜀)
  const d = new Date(from); let left = days;
  while (left > 0) { d.setDate(d.getDate() + 1); const w = d.getDay(); if (w !== 0 && w !== 6) left--; }
  return d.getTime();
}
app.get('/me/cash', auth, (req, res) => {
  const src = cashSources(req.uid);
  const u = getUser(req.uid);
  const rows = db.prepare(`SELECT delta, reason, balance_after, created_at FROM cash_ledger
    WHERE user_id=? ORDER BY id DESC LIMIT 30`).all(req.uid);
  res.json({ ...src, bank: u.bank_account || '', history: rows,
             withholdRate: WITHHOLD_RATE, dueAt: nextBusinessDay(Date.now(), 3) });
});
/* 출금 미리보기 — 얼마가 카드로, 얼마가 계좌로, 세금은 얼마인지
   · 실비(코트·캔볼 환급)  → 계좌이체 · 세금 없음
   · 수고비                → 계좌이체 · 3.3% 원천징수
   · 환불/충전 캐시        → 원결제 카드 취소로만 (계좌로 현금화 불가) */
function withdrawPlan(uid, amount) {
  const src = cashSources(uid);
  const amt = Math.max(0, Math.min(Math.trunc(amount || 0), src.balance));
  const expensePart = Math.min(amt, src.expense);                    // 비과세 실비부터
  const feePart = Math.min(amt - expensePart, src.payout);           // 그다음 수고비(과세)
  const bankPart = expensePart + feePart;
  const cardPart = amt - bankPart;                                   // 남은 건 환불·충전분 → 카드 취소
  const tax = Math.round(feePart * WITHHOLD_RATE);                   // 세금은 수고비에만
  return { amount: amt, cardPart, bankPart, expensePart, feePart, tax,
           payout: cardPart + bankPart - tax, dueAt: nextBusinessDay(Date.now(), 3) };
}
app.post('/me/cash/withdraw/preview', auth, (req, res) => {
  res.json(withdrawPlan(req.uid, +(req.body || {}).amount));
});
app.post('/me/cash/withdraw', auth, limitWrite, async (req, res) => {
  const u = getUser(req.uid);
  const plan = withdrawPlan(req.uid, +(req.body || {}).amount);
  if (plan.amount <= 0) return res.status(400).json({ error: 'invalid_amount' });
  if (plan.bankPart > 0 && !u.bank_account)
    return res.status(400).json({ error: 'no_bank', message: '정산 계좌를 먼저 등록해 주세요' });

  // ① 환불 캐시는 원결제 카드로 부분취소 — 최근 결제부터 거슬러 올라간다
  let cardDone = 0;
  if (plan.cardPart > 0) {
    const secret = process.env.TOSS_SECRET_KEY;
    const paid = db.prepare(`SELECT * FROM orders WHERE user_id=? AND status IN ('paid','partial')
      AND payment_key IS NOT NULL ORDER BY created_at DESC`).all(req.uid);
    for (const ord of paid) {
      if (cardDone >= plan.cardPart) break;
      const left = ord.amount - (ord.refunded || 0);
      if (left <= 0) continue;
      const want = Math.min(left, plan.cardPart - cardDone);
      if (!secret) break;
      try {
        const r = await fetch(`https://api.tosspayments.com/v1/payments/${ord.payment_key}/cancel`, {
          method: 'POST',
          headers: { Authorization: 'Basic ' + Buffer.from(secret + ':').toString('base64'), 'Content-Type': 'application/json' },
          body: JSON.stringify({ cancelReason: '캐시 출금', cancelAmount: want })
        });
        if (!r.ok) continue;                            // 이 건은 건너뛰고 다음 결제로
        const nowRef = (ord.refunded || 0) + want;
        db.prepare("UPDATE orders SET refunded=?, status=? WHERE order_id=?")
          .run(nowRef, nowRef >= ord.amount ? 'refunded' : 'partial', ord.order_id);
        cardDone += want;
      } catch (e) { /* 다음 결제 건으로 */ }
    }
  }
  // 카드로 못 돌려준 몫은 계좌로 내보내지 않는다 — 충전·환불 캐시의 현금화(카드깡) 차단
  const failed = plan.cardPart - cardDone;
  const bankPart = plan.bankPart;                          // 실비 + 수고비만 계좌이체
  const tax = Math.round(plan.feePart * WITHHOLD_RATE);    // 세금은 수고비분에만
  const payout = cardDone + bankPart - tax;
  const spent = cardDone + bankPart;                       // 실제로 빠져나간 캐시만 차감

  const bal = Math.max(0, (u.cash || 0) - spent);
  db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, req.uid);
  db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
    .run(req.uid, -spent, 'withdraw', bal, now());
  const due = nextBusinessDay(Date.now(), 3);
  const r = db.prepare(`INSERT INTO cash_withdrawals
      (user_id,amount,card_part,bank_part,tax,payout,bank,status,due_at,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(req.uid, spent, cardDone, bankPart, tax, payout,
         u.bank_account || '', bankPart > 0 ? 'requested' : 'paid', due, now());
  sendPush(req.uid, { title: '출금 신청 완료',
    body: bankPart > 0 ? `${payout.toLocaleString()}원 · 영업일 3일 내 입금돼요` : `${cardDone.toLocaleString()}원 카드 취소를 요청했어요` });
  res.json({ ok: true, id: rid(r), cardPart: cardDone, bankPart, tax, payout, dueAt: due, cash: bal,
             failed, message: failed > 0 ? '일부 금액은 원결제 취소 기한이 지나 출금되지 않았어요. 고객센터로 문의해 주세요.' : undefined });
});
app.get('/me/cash/withdrawals', auth, (req, res) => {
  res.json(db.prepare(`SELECT id,amount,card_part,bank_part,tax,payout,status,due_at,created_at,paid_at
    FROM cash_withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 20`).all(req.uid));
});
/* 관리자 — 계좌이체를 실제로 보낸 뒤 완료 처리 */
app.get('/admin/withdrawals', admin, (_req, res) => {
  res.json(db.prepare(`SELECT w.*, u.name FROM cash_withdrawals w JOIN users u ON u.id=w.user_id
    WHERE w.status='requested' ORDER BY w.id ASC LIMIT 100`).all());
});
app.post('/admin/withdrawals/:id/paid', admin, (req, res) => {
  const w = db.prepare('SELECT * FROM cash_withdrawals WHERE id=?').get(+req.params.id);
  if (!w) return res.status(404).json({ error: 'not_found' });
  db.prepare("UPDATE cash_withdrawals SET status='paid', paid_at=? WHERE id=?").run(now(), w.id);
  sendPush(w.user_id, { title: '출금 완료', body: `${w.payout.toLocaleString()}원을 보냈어요` });
  res.json({ ok: true });
});

app.get('/me', auth, (req, res) => {
  const u = getUser(req.uid);
  if (!u) return res.status(404).json({ error: 'not_found' });
  // 복식 배치 판정용 — rating_log 의 '복식' 기록 수를 센다
  let pd = 0;
  try { pd = db.prepare("SELECT COUNT(*) n FROM rating_log WHERE user_id=? AND reason='복식'").get(req.uid).n; } catch (e) {}
  res.json({ ...u, played_doubles: pd });
});
app.patch('/me', auth, (req, res) => {
  /* name 추가 — 카카오 닉네임이 영문이거나 별명이면 본인이 고칠 수 있어야 한다 */
  const allow = ['name','gender','region','sport','exp','photos','phone_verified','real_verified','skill_verified',
                 'birth_year','handed','backhand','style','phone','sport_started'];
  if ('name' in req.body) {
    const nm = String(req.body.name || '').trim().slice(0, 20);
    if (!nm) return res.status(400).json({ error: 'bad_name', message: '이름을 입력해 주세요' });
    req.body.name = nm;
  }
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
/* 평균 등급 — C1~SS3 15단계만 허용 (그 외 값은 무시) */
const GRADE_STEPS = ['C','B','A','S','SS'].flatMap(g => [1,2,3].map(n => g + n));
const cleanGrade = v => GRADE_STEPS.includes(String(v || '')) ? String(v) : null;
app.post('/clubs', auth, (req, res) => {
  let { name, sport, region } = req.body;
  name = cleanName(name, '').slice(0, 24);
  if (!name || !sport) return res.status(400).json({ error: 'name_sport_required' });
  /* 이름 품질 — 'dd', 'ㅇㅇ' 같은 테스트 이름이 공개 목록에 올라오는 걸 막는다 */
  if (name.length < 2)
    return res.status(400).json({ error: 'name_short', message: '클럽 이름은 2자 이상이어야 해요' });
  if (/^[ㄱ-ㅎㅏ-ㅣ]+$/.test(name))
    return res.status(400).json({ error: 'name_jamo', message: '자음·모음만으로는 만들 수 없어요' });
  if (/^(.)\1*$/.test(name))
    return res.status(400).json({ error: 'name_repeat', message: '같은 글자만 반복할 수 없어요' });
  if (!/[가-힣a-zA-Z0-9]/.test(name))
    return res.status(400).json({ error: 'name_invalid', message: '클럽 이름을 다시 확인해 주세요' });
  // 스팸 방지 최소 장치 — 승인제 대신 조용한 한도로 막는다
  const owned = db.prepare("SELECT COUNT(*) n FROM club_members WHERE user_id=? AND role='owner'").get(req.uid).n;
  if (owned >= 3) return res.status(400).json({ error: 'club_limit', message: '클럽은 1인당 3개까지 만들 수 있어요' });
  const dup = db.prepare('SELECT 1 FROM clubs WHERE name=? AND sport=?').get(name, sport);
  if (dup) return res.status(409).json({ error: 'name_taken', message: '이미 있는 클럽 이름이에요' });
  const txt = (v, n) => String(v || '').trim().slice(0, n) || null;
  const r = db.prepare(`INSERT INTO clubs
      (name,sport,region,owner_id,created_at,avg_grade,home_court,meet_days,
       intro,logo,logo_ic,logo_bg,meet_time,age_bands,gender_pref)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(name, sport, region || '', req.uid, now(),
         cleanGrade(req.body.avg_grade), txt(req.body.home_court, 40), txt(req.body.meet_days, 30),
         txt(req.body.intro, 40), txt(req.body.logo, 300), txt(req.body.logo_ic, 8),
         txt(req.body.logo_bg, 12), txt(req.body.meet_time, 30),
         txt(req.body.age_bands, 40), txt(req.body.gender_pref, 10));
  db.prepare(`INSERT INTO club_members (club_id,user_id,role,is_captain) VALUES (?,?,?,1)`)
    .run(rid(r), req.uid, 'owner');
  res.json(db.prepare('SELECT * FROM clubs WHERE id=?').get(rid(r)));
});
/* 종목별 구력(개월). sport_started 는 {"tennis":"2019-05"} 형태 */
function careerMonths(uid, sport) {
  const u = getUser(uid);
  if (!u || !u.sport_started) return null;
  let ym;
  try { ym = JSON.parse(u.sport_started)[sport || 'tennis']; } catch (e) { return null; }
  if (!ym) return null;
  const [y, m] = String(ym).split('-').map(Number);
  if (!y) return null;
  const d = new Date();
  return Math.max(0, (d.getFullYear() - y) * 12 + (d.getMonth() + 1 - (m || 1)));
}

app.post('/clubs/:id/join', auth, (req, res) => {
  const cid = +req.params.id;
  const club = db.prepare('SELECT name,owner_id,sport,min_career_months,max_career_months FROM clubs WHERE id=?').get(cid);
  if (!club) return res.status(404).json({ error: 'no_club' });
  // 구력 조건 검사 — 테린이 클럽은 max, 상급 클럽은 min 을 쓴다
  if (club.min_career_months != null || club.max_career_months != null) {
    const mo = careerMonths(req.uid, club.sport);
    if (mo == null) return res.status(400).json({ error: 'career_required' });
    if (club.min_career_months != null && mo < club.min_career_months)
      return res.status(403).json({ error: 'career_too_short', need: club.min_career_months, mine: mo });
    if (club.max_career_months != null && mo > club.max_career_months)
      return res.status(403).json({ error: 'career_too_long', limit: club.max_career_months, mine: mo });
  }
  const ex = db.prepare('SELECT status FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (ex) return res.json({ ok: true, status: ex.status });          // 이미 신청/가입됨
  /* 신청 시각을 남겨야 신청자 화면에서 '언제 신청했는지'를 보여줄 수 있다 */
  db.prepare(`INSERT INTO club_members (club_id,user_id,role,status,joined_at) VALUES (?,?, 'member','pending',?)`)
    .run(cid, req.uid, now());
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
    cm.resting, cm.joined_at, COALESCE(NULLIF(cm.alias,''), u.name) AS name, u.name AS real_name, cm.alias,
    u.gender, u.rating, u.sport_started, u.photos, u.created_at AS user_created${officer ? ', u.phone' : ''} FROM club_members cm
    JOIN users u ON u.id=cm.user_id WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
    ORDER BY (cm.role='owner') DESC, (cm.role='officer') DESC, cm.resting, name`).all(+req.params.id);
  res.json(rows);
});

/* 클럽에서 부르는 이름 — 카카오 닉네임이 'KANGTAEMIN' 처럼 영문이어도
   클럽 명단·대진에는 우리가 부르는 이름으로 보이게 한다. 본인 계정 이름은 그대로. */
try { db.exec('ALTER TABLE club_members ADD COLUMN alias TEXT'); } catch (e) {}
app.patch('/clubs/:id/members/:uid/alias', auth, (req, res) => {
  const cid = +req.params.id, target = +req.params.uid;
  if (!isOfficer(cid, req.uid) && req.uid !== target)
    return res.status(403).json({ error: 'officer_only', message: '임원이나 본인만 바꿀 수 있어요' });
  const nm = String(req.body && req.body.alias || '').trim().slice(0, 20);
  db.prepare('UPDATE club_members SET alias=? WHERE club_id=? AND user_id=?')
    .run(nm || null, cid, target);
  res.json({ ok: true, alias: nm || null });
});

// 회원 등급 일괄 설정 (임원진) — { grades: { "12": "A", "34": "B" } }  키는 user_id
/* 클럽 소개 — 임원만 수정. 가입 전 미리보기에서 가장 먼저 읽는 글이다. */
app.patch('/clubs/:id/intro', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only',
    message: '클럽 소개는 임원만 수정할 수 있어요' });
  const intro = String((req.body || {}).intro || '').slice(0, 1000);
  db.prepare('UPDATE clubs SET intro=? WHERE id=?').run(intro || null, cid);
  res.json({ ok: true, intro });
});

app.patch('/clubs/:id/grades', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const g = (req.body && req.body.grades) || {};
  const st = db.prepare('UPDATE club_members SET grade=? WHERE club_id=? AND user_id=?');
  Object.entries(g).forEach(([uid, v]) => {
    const gv = ['S', 'A', 'B', 'C'].includes(String(v)) ? String(v) : null;
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
// 모임(이벤트)별로 대진을 따로 보관한다 — 같은 날 여러 모임이 있을 수 있다
try { db.exec(`CREATE TABLE IF NOT EXISTS club_brackets_ev (
  id INTEGER PRIMARY KEY, club_id INTEGER, event_id INTEGER, data TEXT, updated_at INTEGER,
  UNIQUE(club_id, event_id))`); } catch (e) {}
const evOf = (req) => { const v = +(req.query.event || (req.body || {}).event_id || 0); return v > 0 ? v : 0; };
function cbRole(cid, uid) {
  const m = db.prepare(`SELECT role FROM club_members WHERE club_id=? AND user_id=? AND (status IS NULL OR status='active')`).get(cid, uid);
  return m ? (m.role || 'member') : null;
}
app.get('/clubs/:id/bracket2', auth, (req, res) => {
  const cid = +req.params.id;
  if (!cbRole(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const eid = evOf(req);
  const row = eid
    ? db.prepare('SELECT data, updated_at FROM club_brackets_ev WHERE club_id=? AND event_id=?').get(cid, eid)
    : db.prepare('SELECT data, updated_at FROM club_brackets WHERE club_id=?').get(cid);
  res.json(row ? { ...JSON.parse(row.data), updated_at: row.updated_at } : null);
});
// 발행된 대진 목록 — 모임별로 골라 들어갈 수 있게
// ── 월례대회 승강 기록 (1주일간 배지 노출) ──
try { db.exec(`CREATE TABLE IF NOT EXISTS grade_changes (
  id INTEGER PRIMARY KEY, club_id INTEGER, user_id INTEGER, name TEXT,
  from_grade TEXT, to_grade TEXT, dir TEXT, created_at INTEGER)`); } catch (e) {}
// ── MVP (오픈매치 1위) ──
try { db.exec(`CREATE TABLE IF NOT EXISTS mvps (
  id INTEGER PRIMARY KEY, match_id INTEGER, user_id INTEGER, name TEXT,
  score TEXT, created_at INTEGER, UNIQUE(match_id, user_id))`); } catch (e) {}
app.post('/open-matches/:id/mvp', auth, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid) return res.status(403).json({ error: 'host_only', message: '매니저만 확정할 수 있어요' });
  const { user_id, name, score } = req.body || {};
  if (!user_id) return res.status(400).json({ error: 'user_required' });
  db.prepare('DELETE FROM mvps WHERE match_id=?').run(mid);
  db.prepare('INSERT INTO mvps (match_id,user_id,name,score,created_at) VALUES (?,?,?,?,?)')
    .run(mid, +user_id, String(name || ''), String(score || ''), now());
  const n = db.prepare('SELECT COUNT(*) c FROM mvps WHERE user_id=?').get(+user_id).c;
  sendPush(+user_id, { icon: '🏆', title: '오늘의 MVP예요', body: `${m.loc || ''} · 통산 ${n}회` });
  res.json({ ok: true, count: n });
});
app.get('/me/mvp', auth, (req, res) => {
  const rows = db.prepare(`SELECT v.match_id, v.score, v.created_at, o.loc, o.dt
    FROM mvps v LEFT JOIN open_matches o ON o.id=v.match_id
    WHERE v.user_id=? ORDER BY v.id DESC LIMIT 30`).all(req.uid);
  res.json({ count: rows.length, list: rows });
});
// 매치 참가자 중 MVP 보유자 집계 (상세 화면용)
app.get('/open-matches/:id/mvp-guests', (req, res) => {
  const mid = +req.params.id;
  const min = Math.max(1, +(req.query.min || 3));
  const rows = db.prepare(`SELECT u.id, u.name, (SELECT COUNT(*) FROM mvps v WHERE v.user_id=u.id) c
    FROM open_match_joins j JOIN users u ON u.id=j.user_id WHERE j.match_id=?`).all(mid);
  const holders = rows.filter(r => r.c >= min).sort((a, b) => b.c - a.c);
  res.json({ min, total: holders.length, top: holders.slice(0, 3).map(h => ({ name: h.name, count: h.c })) });
});
app.post('/clubs/:id/promote', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const list = ((req.body || {}).changes || []).filter(c => c && c.user_id && c.to);
  const up = db.prepare('UPDATE club_members SET grade=? WHERE club_id=? AND user_id=?');
  const ins = db.prepare(`INSERT INTO grade_changes (club_id,user_id,name,from_grade,to_grade,dir,created_at)
    VALUES (?,?,?,?,?,?,?)`);
  const order = { S: 4, A: 3, B: 2, C: 1 };
  list.forEach(c => {
    up.run(String(c.to), cid, +c.user_id);
    const dir = (order[c.to] || 0) > (order[c.from] || 0) ? 'up' : 'down';
    ins.run(cid, +c.user_id, String(c.name || ''), String(c.from || ''), String(c.to), dir, now());
    sendPush(+c.user_id, { icon: dir === 'up' ? '🎉' : '📉',
      title: dir === 'up' ? `${c.to}조로 승격했어요` : `${c.to}조로 조정됐어요`,
      body: '월례대회 결과가 반영됐어요' });
  });
  res.json({ ok: true, n: list.length });
});
app.get('/clubs/:id/promotions', auth, (req, res) => {
  const cid = +req.params.id;
  if (!cbRole(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const since = now() - 7 * 86400e3;                    // 최근 7일치만
  res.json(db.prepare('SELECT user_id,name,from_grade,to_grade,dir,created_at FROM grade_changes WHERE club_id=? AND created_at>? ORDER BY id DESC').all(cid, since));
});
app.get('/clubs/:id/brackets', auth, (req, res) => {
  const cid = +req.params.id;
  if (!cbRole(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT b.event_id, b.data, b.updated_at, e.title, e.date, e.tag
    FROM club_brackets_ev b LEFT JOIN club_events e ON e.id=b.event_id
    WHERE b.club_id=? ORDER BY b.updated_at DESC LIMIT 300`).all(cid);
  // 모임이 이미 사라진 대진은 목록에 올리지 않는다 (지난 버전에서 남은 찌꺼기)
  const out = rows.filter(r => !r.event_id || r.title != null).map(r => { let d = {}; try { d = JSON.parse(r.data); } catch (e) {}
    const gs = d.games || [];
    const done = gs.filter(g => g.sa != null).length;
    return { event_id: r.event_id, title: r.title || '모임', date: r.date || d.date, tag: r.tag || '정기',
      mode: d.mode, courts: d.courts, games: gs.length,
      done, active: !(gs.length > 0 && done === gs.length), updated_at: r.updated_at }; });
  const legacy = db.prepare('SELECT data, updated_at FROM club_brackets WHERE club_id=?').get(cid);
  if (legacy) { let d = {}; try { d = JSON.parse(legacy.data); } catch (e) {}
    const gs = d.games || [];
    const dn = gs.filter(g => g.sa != null).length;
    out.push({ event_id: 0, title: '모임 미지정', date: d.date, tag: '정기', mode: d.mode,
      courts: d.courts, games: gs.length, done: dn, active: !(gs.length > 0 && dn === gs.length), updated_at: legacy.updated_at }); }
  // 진행 중인 대진을 먼저, 그 다음 최신순
  out.sort((a, b) => (b.active - a.active) || (b.updated_at - a.updated_at));
  res.json(out);
});
try { db.exec(`CREATE TABLE IF NOT EXISTS club_bracket_logs (
  id INTEGER PRIMARY KEY, club_id INTEGER, date TEXT, data TEXT, updated_at INTEGER,
  UNIQUE(club_id, date))`); } catch (e) {}
/* 번개 대진은 시즌 기록에서 빼야 한다. 로그에는 모임 종류가 없었으므로 열을 하나 더한다.
   예전 행은 tag 가 비는데, 그건 '정기'로 본다 — 이미 반영된 순위를 뒤늦게 흔들지 않는다. */
try { db.exec('ALTER TABLE club_bracket_logs ADD COLUMN tag TEXT'); } catch (e) {}
function cbLog(cid, data, tag) {                               // 같은 날짜는 최신으로 덮어써 시즌 기록에 쌓인다
  try { db.prepare(`INSERT INTO club_bracket_logs (club_id,date,data,updated_at,tag) VALUES (?,?,?,?,?)
    ON CONFLICT(club_id,date) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at, tag=excluded.tag`)
    .run(cid, String(data.date || '').slice(0, 10) || new Date().toISOString().slice(0, 10),
      JSON.stringify(data), now(), tag || '정기'); } catch (e) {}
}
app.put('/clubs/:id/bracket2', auth, (req, res) => {          // 발행/수정 — 임원만
  const cid = +req.params.id;
  const role = cbRole(cid, req.uid);
  if (role !== 'owner' && role !== 'officer') return res.status(403).json({ error: 'officer_only' });
  const data = req.body || {};
  const eid = evOf(req);
  if (eid) {
    db.prepare(`INSERT INTO club_brackets_ev (club_id,event_id,data,updated_at) VALUES (?,?,?,?)
      ON CONFLICT(club_id,event_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`)
      .run(cid, eid, JSON.stringify(data), now());
  } else {
    db.prepare(`INSERT INTO club_brackets (club_id,data,updated_at) VALUES (?,?,?)
      ON CONFLICT(club_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`)
      .run(cid, JSON.stringify(data), now());
  }
  /* 어느 모임의 대진인지 알면 그 모임의 종류(정기/번개)를 로그에 함께 남긴다 */
  let tag = '정기';
  if (eid) {
    const ev = db.prepare('SELECT tag FROM club_events WHERE id=?').get(eid);
    if (ev && ev.tag) tag = ev.tag;
  }
  cbLog(cid, data, tag);
  res.json({ ok: true });
});
app.get('/clubs/:id/bracket2/logs', auth, (req, res) => {     // 시즌 기록 — 클럽 멤버
  const cid = +req.params.id;
  if (!cbRole(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare('SELECT date, data, tag FROM club_bracket_logs WHERE club_id=? ORDER BY date DESC LIMIT 400').all(cid);
  res.json(rows.map(r => ({ date: r.date, tag: r.tag || '정기', data: JSON.parse(r.data) })));
});
app.patch('/clubs/:id/bracket2/score', auth, (req, res) => {  // 스코어 — 당사자 또는 임원
  const cid = +req.params.id;
  const role = cbRole(cid, req.uid);
  if (!role) return res.status(403).json({ error: 'member_only' });
  const { gi, sa, sb } = req.body || {};
  const eid = evOf(req);
  const row = eid
    ? db.prepare('SELECT data FROM club_brackets_ev WHERE club_id=? AND event_id=?').get(cid, eid)
    : db.prepare('SELECT data FROM club_brackets WHERE club_id=?').get(cid);
  if (!row) return res.status(404).json({ error: 'no_bracket' });
  const data = JSON.parse(row.data);
  const g = (data.games || [])[gi];
  if (!g) return res.status(404).json({ error: 'no_game' });
  const officer = role === 'owner' || role === 'officer';
  const inGame = [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === req.uid);
  if (!officer && !inGame) return res.status(403).json({ error: 'player_only', message: '그 경기를 뛴 당사자나 임원만 입력할 수 있어요' });
  g.sa = Math.max(0, Math.min(9, +sa)); g.sb = Math.max(0, Math.min(9, +sb));
  g.by = req.uid; g.at = now();
  if (eid) db.prepare('UPDATE club_brackets_ev SET data=?, updated_at=? WHERE club_id=? AND event_id=?').run(JSON.stringify(data), now(), cid, eid);
  else db.prepare('UPDATE club_brackets SET data=?, updated_at=? WHERE club_id=?').run(JSON.stringify(data), now(), cid);
  cbLog(cid, data);
  res.json({ ok: true, game: g });
});
/* '오늘 대진에 쓸 모임'을 고른다.
   예전에는 id 가 가장 큰 모임(= 마지막에 만든 모임)을 썼다. 다음 주 모임을 미리 만들어두면
   오늘 대진 명단이 그 모임 참석자로 잡히는 문제가 있었다.
   이제 오늘 것 > 가장 가까운 앞날 > 가장 최근 지난 모임 순으로 고른다. */
function pickTodayEvent(cid) {
  const rows = db.prepare('SELECT id, date FROM club_events WHERE club_id=?').all(cid);
  if (!rows.length) return null;
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const scored = rows.map(r => {
    const m = String(r.date || '').match(/(\d{1,2})\/(\d{1,2})/);
    if (!m) return { id: r.id, t: null };
    const d = new Date(now.getFullYear(), +m[1] - 1, +m[2]);
    const diff = (d - today) / 864e5;                 // 연말·연초 보정
    if (diff < -200) d.setFullYear(now.getFullYear() + 1);
    if (diff > 200) d.setFullYear(now.getFullYear() - 1);
    return { id: r.id, t: d.getTime() };
  });
  const dated = scored.filter(x => x.t != null);
  if (!dated.length) return rows[rows.length - 1];
  const todayEv = dated.filter(x => x.t === today).sort((a, b) => b.id - a.id)[0];
  if (todayEv) return todayEv;
  const future = dated.filter(x => x.t > today).sort((a, b) => a.t - b.t || a.id - b.id)[0];
  if (future) return future;
  return dated.sort((a, b) => b.t - a.t || b.id - a.id)[0];
}

app.get('/clubs/:id/roster', (req, res) => {
  const cid = +req.params.id;
  const eid = evOf(req);                              // 모임을 지정하면 그 모임을 본다
  const ev = eid ? db.prepare('SELECT id FROM club_events WHERE id=? AND club_id=?').get(eid, cid)
                 : pickTodayEvent(cid);
  let rows;
  let guests = [];
  if (ev) {
    rows = db.prepare(`SELECT u.id user_id, COALESCE(NULLIF(cm.alias,''), u.name) AS name, COALESCE(cm.gender_ov, u.gender) AS gender, u.photos, cm.grade, cm.is_captain, cm.role, u.sport_started, u.rating
      FROM event_attendees ea JOIN users u ON u.id=ea.user_id
      LEFT JOIN club_members cm ON cm.club_id=? AND cm.user_id=u.id
      WHERE ea.event_id=? AND (ea.status IS NULL OR ea.status='going') ORDER BY name`).all(cid, ev.id);
    guests = db.prepare('SELECT id,name,gender,grade FROM event_guests WHERE event_id=? ORDER BY id').all(ev.id)
      .map(g => ({ user_id: null, name: g.name, gender: g.gender, grade: g.grade, is_guest: 1, guest_id: g.id }));
  }
  if (!rows || !rows.length) {
    rows = db.prepare(`SELECT u.id user_id, COALESCE(NULLIF(cm.alias,''), u.name) AS name, COALESCE(cm.gender_ov, u.gender) AS gender, u.photos, cm.grade, cm.is_captain, cm.role, u.sport_started, u.rating
      FROM club_members cm JOIN users u ON u.id=cm.user_id
      WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active') ORDER BY name`).all(cid);
  }
  res.json({ event_id: ev ? ev.id : null, members: [...rows, ...guests] });
});
// 가입 신청 목록 (임원진)
/* 내가 낸 클럽 가입 신청 — 신청한 사람이 스스로 상태를 볼 수 있어야 한다.
   승인을 마냥 기다리다 잊히는 게 가장 흔한 이탈 지점이다. */
app.get('/me/club-applications', auth, (req, res) => {
  const rows = db.prepare(`SELECT cm.club_id, cm.status, cm.role, cm.joined_at,
      c.name, c.region, c.logo, c.logo_ic, c.logo_bg, c.home_court, c.meet_days
    FROM club_members cm JOIN clubs c ON c.id=cm.club_id
    WHERE cm.user_id=? AND cm.status='pending' ORDER BY cm.club_id DESC`).all(req.uid);
  res.json(rows.map(r => ({ ...r, applied_at: r.joined_at || null })));
});

/* 신청 취소 — 승인 전에만 */
app.delete('/clubs/:id/join', auth, (req, res) => {
  const cid = +req.params.id;
  const m = db.prepare('SELECT * FROM club_members WHERE club_id=? AND user_id=?').get(cid, req.uid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.status !== 'pending')
    return res.status(400).json({ error: 'already', message: '이미 처리된 신청이에요' });
  db.prepare('DELETE FROM club_members WHERE club_id=? AND user_id=?').run(cid, req.uid);
  res.json({ ok: true });
});

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
  const { title, date, tag, place } = req.body || {};
  const isFlash = String(tag || '정기') === '번개';
  // 정기 모임은 임원만 · 번개 모임은 클럽 회원 누구나
  if (isFlash) {
    const mem = db.prepare(`SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND (status IS NULL OR status='active')`).get(cid, req.uid);
    if (!mem) return res.status(403).json({ error: 'member_only', message: '클럽 회원만 번개를 열 수 있어요' });
  } else if (!isOfficer(cid, req.uid)) {
    return res.status(403).json({ error: 'officer_only', message: '정기 모임은 임원만 만들 수 있어요' });
  }
  if (!title) return res.status(400).json({ error: 'title_required' });
  const r = db.prepare(`INSERT INTO club_events (club_id,title,date,tag,place,created_by,created_at)
                        VALUES (?,?,?,?,?,?,?)`)
    .run(cid, String(title), String(date || ''), String(tag || '정기'),
         String(place || '').trim().slice(0, 60) || null, req.uid, now());
  notifyClub(cid, req.uid, '📅', '새 모임이 열렸어요', `${title}${date ? ' · ' + date : ''}`);
  res.json({ ok: true, id: rid(r) });
});

app.patch('/clubs/:id/events/:eid', auth, (req, res) => {
  const cid = +req.params.id, eid = +req.params.eid;
  const ev = db.prepare('SELECT * FROM club_events WHERE id=? AND club_id=?').get(eid, cid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  // 임원이거나, 내가 만든 번개면 수정 가능
  if (!isOfficer(cid, req.uid) && !(ev.tag === '번개' && ev.created_by === req.uid))
    return res.status(403).json({ error: 'officer_only' });
  const title = String((req.body || {}).title || ev.title);
  const date = String((req.body || {}).date != null ? (req.body || {}).date : ev.date);
  const place = (req.body || {}).place != null
    ? String((req.body || {}).place).trim().slice(0, 60) : (ev.place || null);
  db.prepare('UPDATE club_events SET title=?, date=?, place=? WHERE id=?').run(title, date, place || null, eid);
  // 참석 응답한 회원들에게 변경 알림
  db.prepare('SELECT DISTINCT user_id FROM event_attendees WHERE event_id=?').all(eid)
    .forEach(a => { if (a.user_id !== req.uid) sendPush(a.user_id,
      { icon: '📅', title: '모임 일정이 바뀌었어요', body: `${title} · ${date}` }); });
  res.json({ ok: true });
});

app.delete('/clubs/:id/events/:eid', auth, (req, res) => {
  const cid = +req.params.id, eid = +req.params.eid;
  const ev = db.prepare('SELECT * FROM club_events WHERE id=? AND club_id=?').get(eid, cid);
  if (!ev) return res.status(404).json({ error: 'no_event' });
  if (!isOfficer(cid, req.uid) && !(ev.tag === '번개' && ev.created_by === req.uid))
    return res.status(403).json({ error: 'officer_only' });
  // 참석자에게 취소 알림 후 정리
  db.prepare('SELECT DISTINCT user_id FROM event_attendees WHERE event_id=?').all(eid)
    .forEach(a => { if (a.user_id !== req.uid) sendPush(a.user_id,
      { icon: '📅', title: '모임이 취소됐어요', body: `${ev.title}${ev.date ? ' · ' + ev.date : ''}` }); });
  db.prepare('DELETE FROM event_attendees WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM event_guests WHERE event_id=?').run(eid);
  /* 모임에 딸린 것들도 같이 지운다 — 예전에는 대진이 남아
     '진행 중' 목록에 없는 모임의 대진이 계속 떠 있었다 */
  try {
    const br = db.prepare('SELECT data FROM club_brackets_ev WHERE club_id=? AND event_id=?').get(cid, eid);
    db.prepare('DELETE FROM club_brackets_ev WHERE club_id=? AND event_id=?').run(cid, eid);
    if (br) {
      let day = ''; try { day = String(JSON.parse(br.data || '{}').date || '').slice(0, 10); } catch (e) {}
      if (day && !dayStillHasBracket(cid, day))
        db.prepare('DELETE FROM club_bracket_logs WHERE club_id=? AND date=?').run(cid, day);
    }
  } catch (e) {}
  try { db.prepare('DELETE FROM event_comments WHERE event_id=?').run(eid); } catch (e) {}
  try { db.prepare('DELETE FROM event_reactions WHERE event_id=?').run(eid); } catch (e) {}
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
// 모임 댓글
try { db.exec(`CREATE TABLE IF NOT EXISTS event_comments (
  id INTEGER PRIMARY KEY, event_id INTEGER, user_id INTEGER, body TEXT, created_at INTEGER)`); } catch (e) {}
try { db.exec('ALTER TABLE event_comments ADD COLUMN parent_id INTEGER'); } catch (e) {}   // 대댓글
app.get('/events/:id/comments', auth, (req, res) => {
  const rows = db.prepare(`SELECT c.id, c.body, c.created_at, c.user_id, c.parent_id, u.name, u.photos
    FROM event_comments c JOIN users u ON u.id=c.user_id WHERE c.event_id=? ORDER BY c.id ASC LIMIT 200`).all(+req.params.id);
  res.json(rows);
});
app.post('/events/:id/comments', auth, limitWrite, (req, res) => {
  const body = String((req.body || {}).body || '').trim().slice(0, 300);
  if (!body) return res.status(400).json({ error: 'empty' });
  const parent = (req.body || {}).parent_id ? +req.body.parent_id : null;
  const r = db.prepare('INSERT INTO event_comments (event_id,user_id,body,created_at,parent_id) VALUES (?,?,?,?,?)')
    .run(+req.params.id, req.uid, body, now(), parent);
  res.json({ ok: true, id: rid(r) });
});
// 댓글 반응 (이모지 리액션)
try { db.exec(`CREATE TABLE IF NOT EXISTS comment_reactions (
  id INTEGER PRIMARY KEY, comment_id INTEGER, user_id INTEGER, emoji TEXT, created_at INTEGER,
  UNIQUE(comment_id, user_id, emoji))`); } catch (e) {}
app.get('/events/:id/reactions', auth, (req, res) => {
  const rows = db.prepare(`SELECT r.comment_id, r.emoji, r.user_id FROM comment_reactions r
    JOIN event_comments c ON c.id=r.comment_id WHERE c.event_id=?`).all(+req.params.id);
  res.json(rows);
});
app.post('/comments/:cid/react', auth, (req, res) => {
  const cid = +req.params.cid;
  const emoji = String((req.body || {}).emoji || '').slice(0, 8);
  if (!emoji) return res.status(400).json({ error: 'emoji_required' });
  const ex = db.prepare('SELECT id FROM comment_reactions WHERE comment_id=? AND user_id=? AND emoji=?').get(cid, req.uid, emoji);
  if (ex) { db.prepare('DELETE FROM comment_reactions WHERE id=?').run(ex.id); return res.json({ ok: true, on: false }); }
  db.prepare('INSERT INTO comment_reactions (comment_id,user_id,emoji,created_at) VALUES (?,?,?,?)').run(cid, req.uid, emoji, now());
  res.json({ ok: true, on: true });
});
app.delete('/events/:id/comments/:cid', auth, (req, res) => {
  const c = db.prepare('SELECT * FROM event_comments WHERE id=?').get(+req.params.cid);
  if (!c) return res.status(404).json({ error: 'not_found' });
  if (c.user_id !== req.uid) return res.status(403).json({ error: 'mine_only' });
  db.prepare('DELETE FROM event_comments WHERE id=?').run(c.id);
  res.json({ ok: true });
});
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
  releaseSlotOfMatch(m.id);                   // 잡아둔 구장 코트를 되돌린다
  res.json({ ok: true });
});

/* 매치가 사라지면 코트도 놓아준다.
   이게 없으면 취소된 경기의 코트 대금이 사장님께 그대로 나간다. */
function releaseSlotOfMatch(matchId) {
  const list = db.prepare('SELECT * FROM venue_slots WHERE match_id=?').all(matchId);
  if (!list.length) return;
  tx(() => list.forEach(s => {
    db.prepare("DELETE FROM venue_payouts WHERE slot_id=? AND status='pending'").run(s.id);
    db.prepare("UPDATE venue_slots SET status='open', held_by=NULL, held_at=NULL, match_id=NULL WHERE id=?").run(s.id);
  }));
  const s = list[0];
  const v = db.prepare('SELECT owner_id FROM venues WHERE id=?').get(s.venue_id);
  if (v && v.owner_id) sendPush(v.owner_id, { icon: '↩️', title: '코트 예약이 취소됐어요',
    body: `${s.date} ${s.start}-${s.end} · ${list.length}면 · 다시 판매 대기로 돌아갔어요` });
}
try { db.exec('ALTER TABLE open_matches ADD COLUMN courts INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE open_matches ADD COLUMN court_cost INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE open_match_joins ADD COLUMN joined_at TEXT'); } catch (e) {}
/* 소셜 매치 요금 공식 — 앱 영수증(index.html의 omQuote)과 동일한 계산.
   두 곳이 어긋나면 매니저가 본 견적과 참가자가 내는 금액이 달라지므로 반드시 함께 고칠 것. */
const OM_MARGIN = 0.375, OM_CAP_PP = 10000;
/* 파트너 매니저 제도.
   보너스는 맞수 몫의 20%. 회당 매니저 수입이 1.7배가 되는 대신 맞수 마진은 37%→30%.
   파트너가 일반보다 25%만 더 열면 본전이고, 실제로는 그보다 훨씬 많이 연다. */
const PARTNER_BONUS_RATE = +(process.env.PARTNER_BONUS_RATE || 0.2);
const PARTNER_QUOTA_M   = +(process.env.PARTNER_QUOTA_M   || 20);   // 월 의무 횟수
const PARTNER_WINDOW_M  = +(process.env.PARTNER_WINDOW_M  || 3);    // 누적 판정 기간(개월)
const PARTNER_LEAD_D    = +(process.env.PARTNER_LEAD_D    || 7);    // 파트너 우선 선점 일수               // 목표 마진 · 1인당 운영비 상한
/* 일반 매니저 수고비 — 시간당 정액(최저임금 1.2~1.5배).
   코트 단가에 연동하지 않는다: 연동하면 그만큼 참가비에 얹혀 참가자가 부담하게 된다.
   코트 단가는 파트너 매니저 보너스(맞수 몫의 20%)에만 반영된다. */
function omManagerFee(courts, hours) {
  return (courts <= 2 ? 12000 : 15000) * hours;
}
/* court·ball 은 '총액'이다 (코트비 = 시간당 × 코트수 × 시간, 캔볼 = 캔값 × 코트수).
   캔볼은 마진 계산에서 빼고 실비로 넘긴다 — 캔볼값에까지 운영비가 붙으면 참가자가 더 낸다. */
function omQuote(court, ball, courts, hours) {
  const cap = courts * (hours === 2 ? 4 : 6);
  const mgr = omManagerFee(courts, hours);
  const base = (+court || 0) + mgr;
  const raw = base / (1 - OM_MARGIN) - base;
  const matsu = Math.min(raw, OM_CAP_PP * cap);
  const cost = base + (+ball || 0);
  const per = Math.round((cost + matsu) / cap / 500) * 500;
  return { cap, per, mgr, payout: (+court || 0) + (+ball || 0) + mgr };
}
app.post('/open-matches', auth, (req, res) => {
  const _b = req.body || {};
  let _courts = Math.min(3, Math.max(0, +_b.courts || 0));
  if (_courts) {                                          // 코트 기반 소셜 매치 규칙
    _courts = (_courts <= 2) ? 2 : 3;                     // 2코트(2h 8명·3h 12명) · 3코트(2h 12명·3h 18명)
    const _hours = (+_b.hours === 2) ? 2 : 3;             // 2·3시간만
    /* 구버전 앱은 코트비에 캔볼값을 합산해 court_cost 하나로 보낸다.
       ball_cost가 오면 분리해 계산하고(캔볼은 마진 제외), 없으면 전부 코트비로 본다. */
    const _court = Math.min(Math.max(0, +_b.court_cost || 0), OM_MAX_COURT_COST);
    const _ball = Math.min(Math.max(0, +_b.ball_cost || 0), OM_MAX_COURT_COST);
    const _q = omQuote(_court, _ball, _courts, _hours);
    _b.courts = _courts;
    _b.cap = _q.cap;                                      // 2시간 코트당 4명 · 3시간 코트당 6명 (로테이션 시간 기준)
    _b.min_cnt = _b.cap;                                  // 전원 모여야 확정
    _b.price = _q.per;                                    // 가격은 서버가 산정 (신뢰 지점) — 앱 영수증과 같은 식
    _b.court_cost = _court + _ball;                       // 정산 환급 대상은 코트비+캔볼 실비 합
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
    // 매니저 정산 = 코트·캔볼 실비 환급 + 수고비(2코트 시간당 12,000 · 3코트 15,000)
    // 지급은 매치 종료 후 영업일 3일 내 — PG 정산이 들어온 뒤에 내보내야 자금이 꼬이지 않는다
    // 매니저 = 이 매치의 개설자 1명뿐 · 다른 매치에 참가자로 들어가면 그 매치 정산과는 무관하다
    req._mgrPay = _q.mgr;
  }
  const { sport, dt, loc, fmt, gd, price, cap, min_cnt, note, start_at, end_at, sido, sigungu, dong, account } = req.body || {};
  if (!dt || !loc) return res.status(400).json({ error: 'dt_loc_required' });
  if (start_at && end_at && new Date(end_at) <= new Date(start_at))
    return res.status(400).json({ error: 'end_before_start' });
  const bad = findContact(`${loc} ${note || ''} ${dong || ''}`);   // 공개 모집글이므로 연락처 차단
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });
  // 앱이 보내는 태그 중 허용 목록에 있는 것만 남긴다
  const OM_AMEN = ['초급 환영','여성 환영','주차 가능','야간 조명','샤워 가능','실내 코트'];
  const tags = String((req.body && req.body.tags) || '').split(',')
    .map(t => t.trim()).filter(t => OM_AMEN.includes(t)).join(',') || null;
  const r = db.prepare(`INSERT INTO open_matches (sport,dt,loc,fmt,gd,price,cap,min_cnt,created_at,host_id,status,note,start_at,end_at,sido,sigungu,dong,account, courts, court_cost, tags) VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,?, ?, ?, ?)`)
    .run(sport || 'tennis', dt, loc, fmt || '단식', gd || '남자부', intOrNull(price) || 0,
         intOrNull(cap) || 8, intOrNull(min_cnt) || 6, now(), req.uid, note || '',
         start_at || null, end_at || null, sido || null, sigungu || null, dong || null,
         String(account || '').trim().slice(0, 60) || null, intOrNull(req.body.courts), intOrNull(req.body.court_cost), tags);
  if (req._autoManager) {                                 // 매니저 정산액 = 코트·캔볼 환급 + 수고비 (영업일 3일 내 지급)
    db.prepare('UPDATE open_matches SET manager_id=?, manager_fee=? WHERE id=?')
      .run(req.uid, (intOrNull(req.body.court_cost) || 0) + (req._mgrPay || 0), rid(r));
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
    try { venueConfirm(null, mid); } catch (e) { console.error('venueConfirm', e); }  // 코트 확정 + 사장님 정산 예약
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
  const hosted = db.prepare(`SELECT id, dt AS date, loc AS place, cap, status,
      COALESCE(NULLIF(loc,''),'오픈매치') || ' · ' || COALESCE(fmt,'') AS title,
      (SELECT COUNT(*) FROM open_match_joins j WHERE j.match_id=open_matches.id) AS joined
    FROM open_matches WHERE host_id=? ORDER BY id DESC LIMIT 20`).all(req.uid);
  let joined = [];
  try {
    joined = db.prepare(`SELECT m.id, m.dt AS date, m.loc AS place, m.status,
        COALESCE(NULLIF(m.loc,''),'오픈매치') || ' · ' || COALESCE(m.fmt,'') AS title
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
  /* 나간 회원이 대회 조에 남아 있으면 조 인원이 실제와 어긋난다 */
  try {
    const r = db.prepare('SELECT data FROM club_tiers WHERE club_id=?').get(cid);
    if (r) { const d = JSON.parse(r.data || '{}');
      if (d.groups && d.groups[String(target)]) {
        delete d.groups[String(target)];
        db.prepare('UPDATE club_tiers SET data=?, updated_at=? WHERE club_id=?').run(JSON.stringify(d), now(), cid);
      } }
  } catch (e) {}
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
  // '홍길동 님 외 2명이 좋아해요' 를 만들려면 이름이 필요하다 — 최근 순 3명만
  const likers = db.prepare(`SELECT u.name FROM feed_likes fl JOIN users u ON u.id=fl.user_id
    WHERE fl.post_id=? ORDER BY fl.rowid DESC LIMIT 3`);
  res.json(rows.map(p => ({ ...p,
    likes: nLikes.get(p.id).n, liked: !!myLike.get(p.id, req.uid),
    likers: likers.all(p.id).map(x => x.name),
    comments: nCmts.get(p.id).n, mine: p.user_id === req.uid })));
});

app.post('/clubs/:id/feed', auth, limitWrite, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const title = String((req.body || {}).title || '').trim().slice(0, 60);
  const body = String((req.body || {}).body || '').trim();
  let photos = (req.body || {}).photos;
  photos = Array.isArray(photos) ? photos.filter(u => typeof u === 'string').slice(0, 20) : [];
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
    likes: db.prepare('SELECT COUNT(*) n FROM feed_likes WHERE post_id=?').get(pid).n,
    likers: db.prepare(`SELECT u.name FROM feed_likes fl JOIN users u ON u.id=fl.user_id
      WHERE fl.post_id=? ORDER BY fl.rowid DESC LIMIT 3`).all(pid).map(x => x.name) });
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
db.exec(`CREATE TABLE IF NOT EXISTS cancel_logs (
  id INTEGER PRIMARY KEY, user_id INTEGER, match_id INTEGER, free INTEGER, refund INTEGER, created_at INTEGER)`);


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

/* ═══ 늦어요 알림 ═══════════════════════════════════════════════
   오픈매치는 늦참을 대진에 미리 반영하지 않는다(모르는 사람끼리라 선언이
   안 지켜지고, 앞 라운드를 비워두면 정시에 온 사람이 손해다).
   대신 늦는 사람이 매니저에게 바로 알리고, 매니저가 현장에서 순서를 바꾼다. */
try { db.exec(`CREATE TABLE IF NOT EXISTS om_lates (
  match_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
  minutes INTEGER NOT NULL, eta INTEGER NOT NULL, created_at INTEGER,
  PRIMARY KEY (match_id, user_id))`); } catch (e) {}

const OM_LATE_MAX = 180;                       // 3시간 넘게 늦는 건 늦참이 아니라 노쇼다
function omLateRows(mid) {
  return db.prepare(`SELECT l.user_id, l.minutes, l.eta, l.created_at, u.name
    FROM om_lates l JOIN users u ON u.id=l.user_id
    WHERE l.match_id=? ORDER BY l.eta`).all(mid);
}
/* 매니저(없으면 주최자)에게 알린다 */
function omLateTarget(m) { return m.manager_id || m.host_id || null; }

app.post('/open-matches/:id/late', auth, limitWrite, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const joined = !!db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid);
  if (!joined && m.host_id !== req.uid) return res.status(403).json({ error: 'not_joined' });

  const minutes = Math.max(1, Math.min(OM_LATE_MAX, Math.round(+(req.body || {}).minutes || 0)));
  if (!minutes) return res.status(400).json({ error: 'bad_minutes' });
  /* 도착 예정 시각은 서버가 정한다 — 기기 시계를 믿으면 남은 시간이 어긋난다 */
  const eta = now() + minutes * 60e3;
  db.prepare(`INSERT INTO om_lates (match_id,user_id,minutes,eta,created_at) VALUES (?,?,?,?,?)
    ON CONFLICT(match_id,user_id) DO UPDATE SET minutes=excluded.minutes, eta=excluded.eta, created_at=excluded.created_at`)
    .run(mid, req.uid, minutes, eta, now());

  const to = omLateTarget(m);
  if (to && to !== req.uid) {
    const who = getUser(req.uid);
    const hhmm = new Date(eta + 9 * 3600e3).toISOString().slice(11, 16);   // KST 벽시계
    sendPush(to, { icon: '🏸', title: '늦는다는 연락이 왔어요',
      body: `${who.name} 님 · ${minutes}분 뒤 도착 예정 (${hhmm})`, link: 'match' });
  }
  res.json({ ok: true, minutes, eta, lates: omLateRows(mid) });
});

app.delete('/open-matches/:id/late', auth, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const had = db.prepare('SELECT 1 FROM om_lates WHERE match_id=? AND user_id=?').get(mid, req.uid);
  db.prepare('DELETE FROM om_lates WHERE match_id=? AND user_id=?').run(mid, req.uid);
  const to = omLateTarget(m);
  if (had && to && to !== req.uid) {
    const who = getUser(req.uid);
    sendPush(to, { icon: '🏸', title: '도착했어요', body: `${who.name} 님이 도착했어요`, link: 'match' });
  }
  res.json({ ok: true, lates: omLateRows(mid) });
});

/* 매니저가 대신 내려주기 — 도착했는데 본인이 안 누르는 경우가 많다 */
app.delete('/open-matches/:id/late/:uid', auth, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (omLateTarget(m) !== req.uid && m.host_id !== req.uid) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('DELETE FROM om_lates WHERE match_id=? AND user_id=?').run(mid, +req.params.uid);
  res.json({ ok: true, lates: omLateRows(mid) });
});

app.get('/open-matches/:id/lates', (req, res) => res.json(omLateRows(+req.params.id)));

app.delete('/om-comments/:id', auth, (req, res) => {
  const c = db.prepare('SELECT * FROM om_comments WHERE id=?').get(+req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const m = db.prepare('SELECT host_id FROM open_matches WHERE id=?').get(c.match_id);
  if (c.user_id !== req.uid && (!m || m.host_id !== req.uid)) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('DELETE FROM om_comments WHERE id=?').run(c.id);
  res.json({ ok: true });
});

function omView(m, uid) {
  /* sport_started(구력)를 함께 보낸다 — 앱은 이 값으로 등급을 계산한다.
     빠뜨리면 참가자 전원이 '구력 미입력'으로 집계에서 빠지고 대진도 못 짠다. */
  const joins = db.prepare(`SELECT j.user_id, u.name, u.rating, u.gender, u.sport_started FROM open_match_joins j
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
  /* 늦어요 알림 — 매치가 끝났으면 굳이 싣지 않는다 */
  const endMs = Date.parse(String(m.end_at || '').slice(0, 16) + ':00+09:00');
  const lates = (isNaN(endMs) || endMs > Date.now()) ? omLateRows(m.id) : [];
  const my_late = uid ? (lates.find(x => x.user_id === uid) || null) : null;
  return {
    ...m,
    host, likes, liked, comments,
    manager, manager_fee: m.manager_fee || 0, settled: !!m.settled, mgr_applied, mgr_apps, my_mreview,
    lates, my_late,
    bracket: (()=>{ try { return m.bracket ? JSON.parse(m.bracket) : null; } catch (e) { return null; } })(),
    photos: (()=>{ try { const p = m.photos ? JSON.parse(m.photos) : null; return Array.isArray(p) && p.length ? p : (m.photo ? [m.photo] : []); } catch (e) { return m.photo ? [m.photo] : []; } })(),
    cur: joins.length,
    players: joins.map(j => ({ id: j.user_id, name: j.name, rating: j.rating, gender: j.gender || '',
                               sport_started: j.sport_started || null })),
    joined: uid ? joins.some(j => j.user_id === uid) : false,
    is_host: uid ? m.host_id === uid : false,
    /* 최소 인원을 안 적은 매치는 min_cnt 가 비어 있다. 이때 0 으로 보면
       "0명 ≥ 0명" 이 참이 되어 아무도 없는 매치가 개최 확정으로 뜬다.
       기본값을 정원의 절반(최소 2명)으로 두고, 참가자가 0명이면 절대 확정하지 않는다. */
    min: omMin(m),
    min_cnt: omMin(m),
    confirmed: joins.length > 0 && joins.length >= omMin(m),
    full: joins.length >= (m.cap || 0),
  };
}
/* 개최 최소 인원 — 값이 없으면 정원의 절반으로 본다 */
function omMin(m) {
  const v = +m.min_cnt;
  if (Number.isFinite(v) && v > 0) return v;
  const cap = +m.cap || 0;
  return cap > 0 ? Math.max(2, Math.ceil(cap / 2)) : 2;
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
  try { db.prepare('DELETE FROM om_lates WHERE match_id=? AND user_id=?').run(mid, req.uid); } catch (e) {}

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
  const paid = omPaidBy(mid, req.uid);                    // 실제로 낸 돈이 없으면 환불도 없다
  const refund = Math.min(Math.round(price * pct / 100), paid);
  db.prepare('DELETE FROM open_match_joins WHERE match_id=? AND user_id=?').run(mid, req.uid);
  if (refund > 0) {                                       // 환불은 캐시로 — 출처를 남겨야 나중에 카드 취소로 돌려줄 수 있다
    const u = getUser(req.uid);
    const bal = (u.cash || 0) + refund;
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, req.uid);
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
      .run(req.uid, refund, 'match_refund', bal, now());
    db.prepare("UPDATE om_payments SET status='refunded' WHERE match_id=? AND user_id=? AND status='paid'")
      .run(mid, req.uid);
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
/* ═══ 월례대회 조 ═══════════════════════════════════════════
   예전에는 기기(localStorage)에만 있어서 브라우저를 지우거나 다른 기기로 열면
   조가 통째로 사라졌다. 클럽 전체가 함께 보는 정보이므로 서버에 둔다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS club_tiers (
    club_id INTEGER PRIMARY KEY, data TEXT, updated_at INTEGER)`);
} catch (e) {}

app.get('/clubs/:id/tiers', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const r = db.prepare('SELECT data FROM club_tiers WHERE club_id=?').get(cid);
  let d = null; try { d = r ? JSON.parse(r.data) : null; } catch (e) {}
  res.json(d || { groups: {}, promote: 2, relegate: 2, skipFirst: true, seeded: false });
});

app.put('/clubs/:id/tiers', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const b = req.body || {};
  const groups = {};
  Object.entries(b.groups || {}).slice(0, 400).forEach(([k, v]) => {
    if (/^\d+$/.test(String(k)) && ['A', 'B', 'C', 'D'].includes(v)) groups[String(k)] = v;
  });
  const clamp = (v, d) => { const n = parseInt(v, 10); return isNaN(n) ? d : Math.max(0, Math.min(10, n)); };
  const data = { groups, promote: clamp(b.promote, 2), relegate: clamp(b.relegate, 2),
    skipFirst: b.skipFirst !== false, seeded: !!b.seeded };
  db.prepare(`INSERT INTO club_tiers (club_id,data,updated_at) VALUES (?,?,?)
    ON CONFLICT(club_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`)
    .run(cid, JSON.stringify(data), now());
  res.json({ ok: true, ...data });
});

/* ═══ 클럽 로고 ═══════════════════════════════════════════════
   업로드 폴더(/uploads)에 파일로 두면 컨테이너가 재시작될 때 사라진다.
   로고는 작고(≤512px) 자주 안 바뀌므로 DB 안에 넣어 DB와 수명을 같이 하게 한다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS club_logos (
    club_id INTEGER PRIMARY KEY, mime TEXT, data BLOB, updated_at INTEGER)`);
} catch (e) {}

app.post('/clubs/:id/logo', auth, limitUpload, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const m = /^data:(image\/(png|jpe?g|webp));base64,(.+)$/.exec((req.body && req.body.dataUrl) || '');
  if (!m) return res.status(400).json({ error: 'bad_image' });
  const buf = Buffer.from(m[3], 'base64');
  if (buf.length > 800 * 1024) return res.status(413).json({ error: 'too_large' });
  db.prepare(`INSERT INTO club_logos (club_id,mime,data,updated_at) VALUES (?,?,?,?)
    ON CONFLICT(club_id) DO UPDATE SET mime=excluded.mime, data=excluded.data, updated_at=excluded.updated_at`)
    .run(cid, m[1], buf, now());
  // ?v= 를 붙여 브라우저가 옛 로고를 붙잡고 있지 않게 한다
  const url = `/clubs/${cid}/logo?v=${now()}`;
  db.prepare('UPDATE clubs SET logo=?, logo_ic=NULL WHERE id=?').run(url, cid);
  res.json({ ok: true, url });
});

app.get('/clubs/:id/logo', (req, res) => {
  const r = db.prepare('SELECT mime,data FROM club_logos WHERE club_id=?').get(+req.params.id);
  if (!r || !r.data) return res.status(404).end();
  res.set('Content-Type', r.mime || 'image/png');
  res.set('Cache-Control', 'public, max-age=604800');   // ?v= 가 바뀌면 새로 받는다
  res.send(Buffer.from(r.data));
});

app.delete('/clubs/:id/logo', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  db.prepare('DELETE FROM club_logos WHERE club_id=?').run(cid);
  db.prepare('UPDATE clubs SET logo=NULL WHERE id=?').run(cid);
  res.json({ ok: true });
});

/* 클럽 소개 정보 (클럽장/임원만) — 평균 등급 · 주 사용 코트 · 정기모임 요일 */
app.patch('/clubs/:id/profile', auth, (req, res) => {
  const c = db.prepare('SELECT * FROM clubs WHERE id=?').get(+req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const m = db.prepare('SELECT role FROM club_members WHERE club_id=? AND user_id=?').get(c.id, req.uid);
  if (!m || !['owner','officer'].includes(m.role)) return res.status(403).json({ error: 'officer_only' });
  const has = k => Object.prototype.hasOwnProperty.call(req.body || {}, k);
  const pick = (k, n) => has(k) ? (String(req.body[k] || '').trim().slice(0, n) || null) : c[k];
  db.prepare(`UPDATE clubs SET avg_grade=?, home_court=?, meet_days=?, intro=?,
      logo=?, logo_ic=?, logo_bg=?, meet_time=?, age_bands=?, gender_pref=? WHERE id=?`).run(
    has('avg_grade') ? cleanGrade(req.body.avg_grade) : c.avg_grade,
    pick('home_court', 40), pick('meet_days', 30), pick('intro', 40),
    pick('logo', 300), pick('logo_ic', 8), pick('logo_bg', 12),
    pick('meet_time', 30), pick('age_bands', 40), pick('gender_pref', 10),
    c.id);
  res.json(db.prepare('SELECT * FROM clubs WHERE id=?').get(c.id));
});
// 가입 구력 조건 (클럽장/임원만) · null 로 보내면 제한 해제
app.patch('/clubs/:id/career-policy', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const norm = v => (v === null || v === '' || v === undefined) ? null : Math.max(0, parseInt(v, 10) || 0);
  const mn = norm(req.body.min_career_months), mx = norm(req.body.max_career_months);
  if (mn != null && mx != null && mn > mx) return res.status(400).json({ error: 'range_invalid' });
  db.prepare('UPDATE clubs SET min_career_months=?, max_career_months=? WHERE id=?').run(mn, mx, cid);
  res.json({ ok: true, min_career_months: mn, max_career_months: mx });
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
  const me = tryUid(req);
  let sql = 'SELECT *, (SELECT COUNT(*) FROM comments WHERE post_id=posts.id AND hidden=0) AS comments FROM posts WHERE hidden=0', p = [];
  if (me) {                                          // 차단한 사람의 글은 안 보인다
    sql += ' AND (user_id IS NULL OR user_id NOT IN (SELECT blocked_user_id FROM blocks WHERE user_id=?))';
    p.push(me);
  }
  if (category && category !== '전체') { sql += ' AND category=?'; p.push(category); }
  if (sport) { sql += ' AND sport=?'; p.push(sport); }
  if (q) { sql += ' AND (title LIKE ? OR body LIKE ?)'; p.push('%'+q+'%','%'+q+'%'); }
  res.json(db.prepare(sql + ' ORDER BY created_at DESC LIMIT 100').all(...p));
});
// 댓글
app.get('/posts/:id/comments', (req, res) => {
  const me = tryUid(req);
  res.json(db.prepare(`SELECT c.id, c.body, c.created_at, COALESCE(c.anon_nick,u.anon_nick) AS anon_nick, u.gender
    FROM comments c LEFT JOIN users u ON u.id=c.user_id
    WHERE c.post_id=? AND c.hidden=0
      AND (? IS NULL OR c.user_id IS NULL
           OR c.user_id NOT IN (SELECT blocked_user_id FROM blocks WHERE user_id=?))
    ORDER BY c.id`).all(+req.params.id, me, me));
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
  const t = +(req.body && req.body.user_id);
  if (!t || t === req.uid) return res.status(400).json({ error: 'bad_target' });
  db.prepare('INSERT OR IGNORE INTO blocks (user_id,blocked_user_id) VALUES (?,?)').run(req.uid, t);
  res.json({ ok: true });
});
app.post('/unblock', auth, (req, res) => {
  db.prepare('DELETE FROM blocks WHERE user_id=? AND blocked_user_id=?').run(req.uid, +(req.body && req.body.user_id));
  res.json({ ok: true });
});
app.get('/blocks', auth, (req, res) => {
  res.json(db.prepare(`SELECT b.blocked_user_id AS user_id, u.name, u.anon_nick
    FROM blocks b LEFT JOIN users u ON u.id=b.blocked_user_id
    WHERE b.user_id=? ORDER BY b.id DESC`).all(req.uid));
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
/* 개인 리그 참가 — 신청한 사람만 랭킹에 노출된다.
   신청 없이 전원을 줄세우면 '배치 중'만 가득해 리그가 의미를 잃는다. */
app.get('/league/me', auth, (req, res) => {
  const sport = String(req.query.sport || 'tennis');
  const div = String(req.query.div || 'men');
  const r = db.prepare('SELECT joined_at FROM league_entries WHERE user_id=? AND sport=? AND div=?')
    .get(req.uid, sport, div);
  const n = db.prepare('SELECT COUNT(*) n FROM league_entries WHERE sport=? AND div=?').get(sport, div).n;
  res.json({ joined: !!r, joined_at: r ? r.joined_at : null, entries: n, sport, div });
});

app.post('/league/join', auth, (req, res) => {
  const b = req.body || {};
  const sport = String(b.sport || 'tennis'), div = String(b.div || 'men');
  db.prepare(`INSERT INTO league_entries (user_id,sport,div,joined_at) VALUES (?,?,?,?)
              ON CONFLICT(user_id,sport,div) DO NOTHING`).run(req.uid, sport, div, now());
  res.json({ ok: true, joined: true });
});

app.delete('/league/join', auth, (req, res) => {
  const sport = String(req.query.sport || 'tennis'), div = String(req.query.div || 'men');
  db.prepare('DELETE FROM league_entries WHERE user_id=? AND sport=? AND div=?').run(req.uid, sport, div);
  res.json({ ok: true, joined: false });
});

app.get('/rankings', (req, res) => {
  const { sport } = req.query;
  const dbl = String(req.query.type || 'singles') === 'doubles';
  const col = dbl ? 'COALESCE(u.rating_doubles,1000)' : 'u.rating';
  /* 경기를 한 번도 안 한 사람은 랭킹에 올리지 않는다.
     마지막 경기 시각도 함께 줘서 앱이 '최근 활동'으로 한 번 더 거를 수 있게 한다. */
  const div = String(req.query.div || 'men');
  /* 참가 신청한 사람만 줄세운다.
     오래 안 뛴 사람은 내린다 — 안 오는 사람이 상단을 차지하면 순위가 죽은 표가 된다.
     신청만 하고 아직 안 뛴 사람도 같은 기간 안에는 남겨둔다. */
  const DORMANT_D = 90;
  const cut = now() - DORMANT_D * 86400000;
  let sql = `SELECT u.id,u.name,u.region,u.sport,${col} AS rating,
      (u.wins+u.losses) AS games, le.joined_at,
      (SELECT MAX(created_at) FROM rating_log rl WHERE rl.user_id=u.id) AS last_played_at
    FROM league_entries le JOIN users u ON u.id=le.user_id
    WHERE le.div=? AND u.provider NOT IN ('bot','venue','manager')
      AND COALESCE((SELECT MAX(created_at) FROM rating_log rl WHERE rl.user_id=u.id), le.joined_at) >= ?`;
  const p = [div, cut];
  if (sport) { sql += ' AND le.sport=? AND u.sport=?'; p.push(sport, sport); }
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
  /* 결제위젯(SDK v2) — 카드·간편결제·계좌이체·가상계좌를 한 화면에서 고른다.
     주의: 여기 쓰는 clientKey 는 반드시 '결제위젯 연동 키'여야 한다.
     '결제창(API 개별 연동)' 키를 넣으면 UNAUTHORIZED_KEY 가 난다. */
  const { clientKey, amount, orderId, orderName } = req.query;
  const base = `${req.protocol}://${req.get('host')}`;
  const amt = Number(amount) || 0;
  res.set('Content-Type', 'text/html; charset=utf-8').send(`<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>맞수 결제</title>
<script src="https://js.tosspayments.com/v2/standard"></script>
<style>
  body{margin:0;background:#f7f5f0;font-family:'Pretendard Variable',Pretendard,-apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo',sans-serif;color:#1c1b18}
  .wrap{max-width:520px;margin:0 auto;padding:18px 14px 120px}
  .top{display:flex;align-items:baseline;gap:8px;padding:6px 4px 14px}
  .top b{font-size:17px;letter-spacing:-.02em}
  .top span{margin-left:auto;font-size:12px;color:#7d7870}
  .amt{background:#fff;border-radius:16px;padding:16px;margin-bottom:12px}
  .amt .k{font-size:12px;color:#7d7870}
  .amt .v{font-size:26px;font-weight:700;letter-spacing:-.03em;margin-top:3px}
  .box{background:#fff;border-radius:16px;overflow:hidden;margin-bottom:12px}
  .bar{position:fixed;left:0;right:0;bottom:0;padding:12px 14px calc(12px + env(safe-area-inset-bottom));background:#f7f5f0}
  .btn{display:block;width:100%;max-width:492px;margin:0 auto;border:0;border-radius:14px;padding:16px;
       background:#ec6a2e;color:#fff;font-size:15px;font-weight:600;font-family:inherit;cursor:pointer}
  .btn[disabled]{opacity:.5}
  .msg{padding:22px;text-align:center;font-size:14px;color:#7d7870;line-height:1.6}
</style></head>
<body><div class="wrap">
  <div class="top"><b>맞수 캐시 충전</b><span>토스페이먼츠</span></div>
  <div class="amt"><div class="k">결제 금액</div><div class="v">${amt.toLocaleString()}원</div></div>
  <div class="box" id="method"></div>
  <div class="box" id="agreement"></div>
</div>
<div class="bar"><button class="btn" id="pay" disabled>결제하기</button></div>
<script>
(async function(){
  var el=document.getElementById('pay');
  try{
    var toss = TossPayments(${JSON.stringify(clientKey || '')});
    var widgets = toss.widgets({ customerKey: TossPayments.ANONYMOUS });
    await widgets.setAmount({ currency: 'KRW', value: ${amt} });
    await Promise.all([
      widgets.renderPaymentMethods({ selector:'#method', variantKey:'DEFAULT' }),
      widgets.renderAgreement({ selector:'#agreement', variantKey:'AGREEMENT' })
    ]);
    el.disabled=false;
    el.addEventListener('click', async function(){
      el.disabled=true;
      try{
        await widgets.requestPayment({
          orderId: ${JSON.stringify(orderId || '')},
          orderName: ${JSON.stringify(orderName || '맞수 캐시')},
          successUrl: ${JSON.stringify(base + '/pay/done')},
          failUrl: ${JSON.stringify(base + '/pay/done?fail=1')}
        });
      }catch(e){ el.disabled=false; }
    });
  }catch(e){
    document.querySelector('.wrap').innerHTML =
      '<div class="msg">결제창을 열지 못했어요.<br>결제위젯 연동 키가 맞는지 확인해 주세요.<br><br>'+(e&&e.message||'')+'</div>';
  }
})();
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
try {
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
} catch (e) { console.error('[boot] brackets 마이그레이션 실패:', e && e.message); }

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
['fee INTEGER DEFAULT 0', 'paid INTEGER DEFAULT 0', 'paid_at BIGINT',
 'phone TEXT', "source TEXT DEFAULT 'manual'", 'user_id INTEGER'].forEach(c => {
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
/* 대진 삭제 — 잘못 편성했거나 취소된 모임의 대진을 지운다. 임원만. */
/* 그 클럽에 아직 그 날짜의 대진이 남아 있나 — 남아 있으면 기록은 지우지 않는다 */
function dayStillHasBracket(cid, day) {
  if (!day) return true;
  const rows = [...db.prepare('SELECT data FROM club_brackets_ev WHERE club_id=?').all(cid),
                ...db.prepare('SELECT data FROM club_brackets WHERE club_id=?').all(cid)];
  return rows.some(r => { try { return String(JSON.parse(r.data).date || '').slice(0, 10) === day; }
                         catch (e) { return false; } });
}
/* :bid 는 모임 id. 0 이면 모임에 안 붙은 옛 대진.
   예전에는 club_brackets(옛 표)만 지워서, 모임별 대진과 '지난 모임' 기록이 그대로 남았다. */
app.delete('/clubs/:id/brackets/:bid', auth, (req, res) => {
  const cid = +req.params.id, eid = +req.params.bid;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only',
    message: '임원만 대진을 지울 수 있어요' });
  const row = eid
    ? db.prepare('SELECT data FROM club_brackets_ev WHERE club_id=? AND event_id=?').get(cid, eid)
    : db.prepare('SELECT data FROM club_brackets WHERE club_id=?').get(cid);
  if (!row) return res.status(404).json({ error: 'not_found' });
  let day = '';
  try { day = String(JSON.parse(row.data || '{}').date || '').slice(0, 10); } catch (e) {}
  if (eid) db.prepare('DELETE FROM club_brackets_ev WHERE club_id=? AND event_id=?').run(cid, eid);
  else     db.prepare('DELETE FROM club_brackets WHERE club_id=?').run(cid);
  if (day && !dayStillHasBracket(cid, day))
    db.prepare('DELETE FROM club_bracket_logs WHERE club_id=? AND date=?').run(cid, day);
  res.json({ ok: true, date: day });
});

/* 지난 모임 기록 하나만 지우기 — 이미 쌓인 찌꺼기를 화면에서 치울 수단 */
app.delete('/clubs/:id/bracket2/logs/:date', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const day = String(req.params.date || '').slice(0, 10);
  db.prepare('DELETE FROM club_bracket_logs WHERE club_id=? AND date=?').run(cid, day);
  res.json({ ok: true });
});

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
// 가입 구력 조건 (개월). null = 제한 없음. 테린이 클럽은 max 로 상급자를 막는다.
// 복식 레이팅 — 기존 rating 은 단식 전용으로 남기고, 복식은 따로 쌓는다
try { db.exec('ALTER TABLE users ADD COLUMN rating_doubles INTEGER DEFAULT 1000'); } catch (e) {}
try { db.exec("UPDATE users SET rating_doubles=1000 WHERE rating_doubles IS NULL"); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN min_career_months INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN max_career_months INTEGER'); } catch (e) {}
/* 클럽 찾기 카드에 쓰이는 소개 정보 — 평균 등급(C1~SS3 15단계) · 주 사용 코트 · 정기모임 요일 */
try { db.exec('ALTER TABLE clubs ADD COLUMN avg_grade TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN home_court TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN meet_days TEXT'); } catch (e) {}
/* 클럽 만들기 4단계에서 받는 값들 */
try { db.exec('ALTER TABLE clubs ADD COLUMN intro TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN logo TEXT'); } catch (e) {}        // 업로드 이미지 URL
try { db.exec('ALTER TABLE clubs ADD COLUMN logo_ic TEXT'); } catch (e) {}     // 심볼 (이미지 없을 때)
try { db.exec('ALTER TABLE clubs ADD COLUMN logo_bg TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN meet_time TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN age_bands TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE clubs ADD COLUMN gender_pref TEXT'); } catch (e) {}

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
try {
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
} catch (e) { console.error('[boot] club_accounts 마이그레이션 실패:', e && e.message); }

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

// 법률 문서에 들어갈 운영자 정보. Railway Variables 에서 채운다.
const OP_NAME  = process.env.OP_NAME  || '';          // 예: 최민혁
const OP_EMAIL = process.env.OP_EMAIL || process.env.SUPPORT_EMAIL || '';
const OP_BIZ   = process.env.OP_BIZ   || '';          // 예: 상호 · 사업자등록번호 · 주소
const opBox = (label) => {
  const rows = [];
  if (OP_NAME)  rows.push(`${label}: ${OP_NAME}`);
  if (OP_EMAIL) rows.push(`문의: <a href="mailto:${OP_EMAIL}">${OP_EMAIL}</a> · 앱 내 신고 기능`);
  else          rows.push('문의: 앱 내 신고 기능');
  if (OP_BIZ)   rows.push(OP_BIZ);
  return `<div class="box">${rows.join('<br>')}</div>`;
};

app.get('/terms', (_req, res) => res.send(`<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>맞수 이용약관</title>${LEGAL_CSS}</head><body>
<h1>맞수(MATSU) 이용약관</h1><p class="sub">시행일: 2026-07-15</p>
<h2>제1조 (목적)</h2><p>이 약관은 맞수(이하 "서비스")가 제공하는 스포츠 동호회 운영·매칭 서비스의 이용 조건과 절차, 회원과 서비스의 권리·의무를 정합니다.</p>
<h2>제2조 (서비스 내용)</h2><p>서비스는 클럽 운영(모임·대진·회비·출석), 회원 간 매칭·대화, 커뮤니티 기능을 제공합니다. 현재 앱 내 기능은 무료로 제공됩니다. 유료 기능을 도입하는 경우 요금과 조건을 앱 내에 미리 표시합니다.</p>
<h2>제3조 (가입 자격)</h2><p>만 14세 이상만 가입할 수 있습니다. 만 14세 미만은 관련 법령에 따라 가입이 제한됩니다. 가입 시 입력한 출생 연도가 사실과 다른 경우 이용이 제한될 수 있습니다.</p>
<h2>제4조 (회원의 의무)</h2><ul><li>타인의 정보를 도용하거나 허위 정보를 등록하지 않습니다.</li><li>다른 회원을 비방·희롱하거나 연락처를 무단 수집하지 않습니다.</li><li>경기 결과·평점을 조작하지 않습니다. 위반 시 이용이 제한될 수 있습니다.</li></ul>
<h2>제5조 (결제와 환불)</h2><p>현재 서비스는 회원에게 이용료를 받지 않습니다. 회비·참가비 등 회원 간 금전 거래는 당사자 간 책임이며 서비스는 이를 대행하지 않습니다.</p>
<h2>제6조 (서비스 변경·중단)</h2><p>서비스는 운영상 필요에 따라 기능을 변경할 수 있으며, 중대한 변경은 사전에 공지합니다.</p>
<h2>제7조 (면책)</h2><p>서비스는 회원 간 경기·모임 중 발생한 사고, 회원 간 분쟁에 대해 고의·중과실이 없는 한 책임을 지지 않습니다.</p>
<h2>제8조 (게시물의 권리)</h2><ul><li>회원이 작성한 게시물의 저작권은 작성한 회원에게 있습니다.</li><li>회원은 서비스가 해당 게시물을 서비스 운영·노출에 필요한 범위에서 사용하는 것을 허락합니다.</li><li>서비스는 법령이나 이 약관을 위반한 게시물을 삭제하거나 노출을 제한할 수 있습니다.</li><li>회원은 다른 회원을 차단할 수 있으며, 차단한 회원의 게시물과 대화는 표시되지 않습니다.</li></ul>
<h2>제9조 (탈퇴)</h2><p>회원은 언제든 앱 내에서 탈퇴할 수 있습니다. 탈퇴 시 개인정보는 지체 없이 파기되며, 클럽 장부·경기 기록은 무결성을 위해 익명 처리되어 보존됩니다.</p>
${opBox('운영자')}</body></html>`));

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
<h2>6. 이용자의 권리</h2><p>이용자는 언제든 자신의 정보를 열람·수정·삭제(탈퇴)할 수 있습니다. 앱 내 [내정보]에서 직접 처리하거나 아래 이메일로 요청할 수 있습니다.</p>
<h2>7. 안전성 확보 조치</h2><p>비밀 키 기반 인증 토큰, 전송 구간 암호화(HTTPS), 접근 통제, 일일 백업을 시행합니다.</p>
${opBox('개인정보 보호책임자')}</body></html>`));

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
    // node:sqlite(DatabaseSync)에는 .backup()이 없다 → SQLite 표준 VACUUM INTO 로 스냅샷
    if (typeof db.backup === 'function') {
      await db.backup(dest);                            // better-sqlite3 경로
    } else {
      try { fs.unlinkSync(dest); } catch (e) {}         // VACUUM INTO 는 기존 파일이 있으면 실패
      db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);   // WAL 포함 일관된 스냅샷
    }
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
try { db.exec('ALTER TABLE banners ADD COLUMN sort INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec("ALTER TABLE banners ADD COLUMN slot TEXT DEFAULT 'home'"); } catch (e) {}   // home | bracket
app.get('/banners', (req, res) => {
  const slot = String(req.query.slot || 'home');
  res.json(db.prepare("SELECT id,image,link FROM banners WHERE COALESCE(slot,'home')=? ORDER BY sort ASC, id DESC LIMIT 5").all(slot));
});
app.get('/admin/banners', admin, (_req, res) => {
  res.json(db.prepare("SELECT id,image,link,sort,COALESCE(slot,'home') slot,created_at FROM banners ORDER BY sort ASC, id DESC LIMIT 40").all());
});
// 배너 순서 저장 — ids 배열 순서 = 노출 순서
app.patch('/admin/banners/order', admin, (req, res) => {
  const ids = ((req.body || {}).ids || []).map(Number).filter(Boolean);
  ids.forEach((id, i) => db.prepare('UPDATE banners SET sort=? WHERE id=?').run(i, id));
  res.json({ ok: true, count: ids.length });
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
  db.prepare('INSERT INTO banners (image,link,slot,created_at) VALUES (?,?,?,?)')
    .run(url, String(b.link || '').slice(0, 300), (b.slot === 'bracket' ? 'bracket' : 'home'), now());
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

  // 복식은 rating_doubles 로 — 단식(rating)과 섞이지 않는다
  const teamElo = ids => ids.reduce((t, id) => t + ((getUser(id) || {}).rating_doubles || 1000), 0) / ids.length;
  const bump = (id, d) => {
    const u = getUser(id); const cur = (u && u.rating_doubles) || 1000;
    db.prepare('UPDATE users SET rating_doubles=? WHERE id=?').run(cur + d, id);
    logRating(id, d, cur + d, '복식');
  };

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
  const uid = intOrNull(req.body && req.body.user_id);
  if (!uid || !getUser(uid)) return res.status(400).json({ error: 'no_user' });
  /* 정산액은 여기서 정하지 않는다 — 실제 금액은 정산 시점에 서버가 다시 계산한다.
     호스트가 임의 금액을 적어 넣던 경로를 막는다. */
  db.prepare('UPDATE open_matches SET manager_id=? WHERE id=?').run(uid, m.id);
  sendPush(uid, { icon: '🎽', title: '매니저로 지정됐어요', body: `${m.dt || ''} 매치 운영을 맡게 됐어요` });
  res.json({ ok: true, manager_id: uid });
});
app.post('/open-matches/:id/settle', auth, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.host_id !== req.uid) return res.status(403).json({ error: 'host_only' });
  if (m.settled) return res.status(400).json({ error: 'already_settled' });
  if (!m.manager_id) return res.status(400).json({ error: 'no_manager' });

  /* ── 정산 안전장치 ────────────────────────────────────────
     ① 매치가 끝난 뒤에만  ② 실제로 걷힌 돈 안에서만
     ③ 금액은 서버가 다시 계산한다 (호스트 입력값을 믿지 않는다)
     이 셋이 없으면 매치를 만들고 금액만 적어 현금을 빼갈 수 있다. */
  const endMs = Date.parse(String(m.end_at || m.start_at || '').slice(0, 16) + ':00+09:00');
  if (!isNaN(endMs) && Date.now() < endMs)
    return res.status(400).json({ error: 'not_finished', message: '매치가 끝난 뒤에 정산할 수 있어요' });

  const collected = omCollected(m.id);
  if (collected <= 0)
    return res.status(400).json({ error: 'no_payment', message: '참가비 수납 내역이 없어 정산할 수 없어요' });

  // 실비(코트·캔볼)와 수고비를 서버가 다시 계산한다
  const courts = Math.max(0, m.courts || 0);
  const hours = (() => {
    const s = Date.parse(String(m.start_at || '').slice(0, 16) + ':00+09:00');
    const e = Date.parse(String(m.end_at || '').slice(0, 16) + ':00+09:00');
    return (!isNaN(s) && !isNaN(e) && e > s) ? Math.round((e - s) / 3600e3) : 3;
  })();
  /* 실비 환급은 '매니저가 자기 돈으로 코트비를 냈을 때'만 준다.
     맞수 계약 구장에서 열린 매치는 코트비를 맞수가 사장님께 직접 보내므로,
     여기서 또 환급하면 코트비를 두 번 내는 셈이 된다. */
  const onPartnerCourt = !!db.prepare('SELECT 1 FROM venue_slots WHERE match_id=?').get(m.id);
  const expense = onPartnerCourt
    ? 0
    : Math.min(Math.max(0, m.court_cost || 0), OM_MAX_COURT_COST);   // 실비 상한
  const fee = courts ? omManagerFee(courts <= 2 ? 2 : 3, hours === 2 ? 2 : 3) : 0;

  /* 파트너 매니저 보너스 — 맞수가 남긴 몫의 20%.
     코트 단가에 연동되므로 비싼 코트를 굴릴수록 매니저도 더 가져간다.
     참가비에는 영향이 없다(이미 걷은 돈을 나누는 것이라). */
  const mgrUser = getUser(m.manager_id) || {};
  const isPartner = mgrUser.manager_tier === 'partner';
  const realCourt = Math.max(0, m.court_cost || 0);
  const matsuShare = Math.max(0, collected - realCourt - fee);
  const bonus = isPartner ? Math.round(matsuShare * PARTNER_BONUS_RATE / 100) * 100 : 0;

  let payExpense = expense, payFee = fee, payBonus = bonus;

  // 걷힌 돈을 넘지 않게: 실비 → 수고비 → 보너스 순으로 채운다
  let room = collected;
  payExpense = Math.min(payExpense, room); room -= payExpense;
  payFee = Math.min(payFee, room);         room -= payFee;
  payBonus = Math.min(payBonus, room);
  const total = payExpense + payFee + payBonus;
  if (total <= 0) return res.status(400).json({ error: 'nothing_to_settle' });

  const mu = getUser(m.manager_id);
  if (!mu) return res.status(400).json({ error: 'no_manager' });
  tx(() => {
    db.prepare(`INSERT INTO om_payouts (match_id,user_id,amount,bank,status,created_at)
                VALUES (?,?,?,?,?,?)`)
      .run(m.id, m.manager_id, total, (mu && mu.bank_account) || '', 'cash', now());
    let bal = mu.cash || 0;
    if (payExpense > 0) {                       // 실비 환급 — 비과세
      bal += payExpense;
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(m.manager_id, payExpense, 'om_expense', bal, now());
    }
    if (payFee > 0) {                           // 수고비 — 소득(출금 시 3.3% 원천징수)
      bal += payFee;
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(m.manager_id, payFee, 'om_payout', bal, now());
    }
    if (payBonus > 0) {                         // 파트너 보너스 — 수고비와 같은 소득 처리
      bal += payBonus;
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(m.manager_id, payBonus, 'om_partner_bonus', bal, now());
    }
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, m.manager_id);
    db.prepare('UPDATE open_matches SET settled=1, manager_fee=? WHERE id=?').run(total, m.id);
  });
  sendPush(m.manager_id, { icon: '💰', title: '정산이 들어왔어요',
    body: `${m.dt || ''} 매치 · 수고비 ${payFee.toLocaleString()}원${
      payBonus ? ` + 파트너 보너스 ${payBonus.toLocaleString()}원` : ''}${
      payExpense ? ` + 실비 ${payExpense.toLocaleString()}원` : ''}` });
  res.json({ ok: true, payout: true, expense: payExpense, fee: payFee,
             bonus: payBonus, partner: isPartner, total, collected });
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
/* 조건·편의 태그 — 정해진 값만 저장한다 (자유 입력이 아니라 나중에 필터로 쓸 값) */
try { db.exec('ALTER TABLE open_matches ADD COLUMN tags TEXT'); } catch (e) {}
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
/* 오픈매치 대진용 참가자 명단 — 클럽 대진과 같은 구력 등급 체계를 쓴다.
   매니저 평가(om_assessments)가 있으면 그 등급이 구력보다 우선. */
app.get('/open-matches/:id/roster', (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT id,sport,courts,cap FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const rows = db.prepare(`SELECT u.id user_id, u.name, u.gender, u.sport_started, u.rating, u.photos,
      (SELECT level FROM om_assessments a WHERE a.user_id=u.id ORDER BY a.id DESC LIMIT 1) AS assessed
    FROM open_match_joins j JOIN users u ON u.id=j.user_id
    WHERE j.match_id=? ORDER BY j.joined_at, u.name`).all(mid);
  res.json({ match_id: mid, sport: m.sport, courts: m.courts || 2, cap: m.cap || 0, members: rows });
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
    sendPush(uid, { icon: '📊', title: placed ? '경기력 평가가 반영됐어요' : '티어가 배치됐어요', body: `매니저 평가: ${p.level} · ${m.dt || ''} 매치` });
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
  /* 오픈매치 등급은 구력(sport_started)에서 나온다.
     구력을 안 넣으면 분포 차트에서 '미입력'으로 빠지고 대진 편성도 이 사람을 못 읽는다. */
  const startedFrom = years => {
    const d = new Date(); d.setMonth(d.getMonth() - Math.round((+years || 0) * 12));
    return d.toISOString().slice(0, 7);                              // "YYYY-MM"
  };
  const bots = (body.bots || (body.names || []).map(n => ({ name: n })))
    .map(b => ({ name: String(b.name || '').trim(),
                 gender: b.gender === '여성' ? '여성' : '남성',
                 years: Math.max(0, Math.min(60, +b.years || 0)),
                 rating: Math.max(600, Math.min(1700, +b.rating || 1000)) }))
    .filter(b => b.name).slice(0, 20);
  let added = 0;
  for (const b of bots) {
    const cur = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n;
    if (cur >= (m.cap || 8)) break;                                   // 정원 초과 방지
    const pid = 'bot:' + b.name;
    let u = db.prepare("SELECT id FROM users WHERE provider='bot' AND provider_id=?").get(pid);
    if (!u) {
      const r = db.prepare(`INSERT INTO users (provider,provider_id,name,gender,rating,sport,anon_nick,created_at,sport_started)
        VALUES ('bot',?,?,?,?,?,?,?,?)`).run(pid, b.name, b.gender, b.rating, m.sport || 'tennis', b.name, now(),
        JSON.stringify({ [m.sport || 'tennis']: startedFrom(b.years) }));
      u = { id: r.lastInsertRowid };
      db.prepare('UPDATE users SET cash=0 WHERE id=?').run(u.id);
    } else {
      db.prepare('UPDATE users SET gender=?, rating=?, sport_started=? WHERE id=?')
        .run(b.gender, b.rating, JSON.stringify({ [m.sport || 'tennis']: startedFrom(b.years) }), u.id);
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
  const m = db.prepare('SELECT id,loc,dt,settled FROM open_matches WHERE id=?').get(id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  /* 정산이 끝난 매치는 회계 기록이라 실수로 지우지 못하게 막는다.
     정말 지워야 하면 ?force=1 을 붙인다. */
  const force = String(req.query.force || '') === '1';
  if (m.settled && !force)
    return res.status(400).json({ error: 'settled', message: '정산이 끝난 매치예요. 강제로 지우려면 force=1' });
  const paid = omCollected(id);
  if (paid > 0 && !force)
    return res.status(400).json({ error: 'has_payment',
      message: `참가비 ${paid.toLocaleString()}원이 수납된 매치예요. 환불 후 삭제하거나 force=1` });

  tx(() => {                                   // 남는 찌꺼기 없이 함께 정리한다
    db.prepare('DELETE FROM open_match_joins WHERE match_id=?').run(id);
    ['om_likes', 'om_comments', 'om_manager_apps', 'om_match_reviews', 'om_payouts', 'om_payments']
      .forEach(t => { try { db.prepare(`DELETE FROM ${t} WHERE match_id=?`).run(id); } catch (e) {} });
    db.prepare('DELETE FROM open_matches WHERE id=?').run(id);
  });
  res.json({ ok: true, deleted: true, loc: m.loc || '', dt: m.dt || '' });
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

/* ── 사장님 로그인 (아이디 · 비밀번호) ───────────────
   사장님은 소셜 로그인을 쓰지 않는다. 맞수가 계정을 만들어 전달한다.
   users 테이블을 그대로 쓰되 provider='venue' 로 구분한다. */
try { db.exec('ALTER TABLE users ADD COLUMN pw_hash TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN pw_salt TEXT'); } catch (e) {}
const pwHash = (pw, salt) =>
  crypto.scryptSync(String(pw), String(salt), 32).toString('hex');

app.post('/venue/login', limitLogin, (req, res) => {
  const loginId = String((req.body && req.body.login_id) || '').trim().toLowerCase().slice(0, 40);
  const pw = String((req.body && req.body.password) || '');
  if (!loginId || !pw) return res.status(400).json({ error: 'missing' });
  const u = db.prepare("SELECT * FROM users WHERE provider='venue' AND provider_id=?").get(loginId);
  // 아이디가 없어도 같은 메시지를 준다 (계정 존재 여부를 흘리지 않는다)
  if (!u || !u.pw_hash || u.pw_hash !== pwHash(pw, u.pw_salt || ''))
    return res.status(401).json({ error: 'bad_login', message: '아이디 또는 비밀번호가 맞지 않아요' });
  const v = db.prepare('SELECT id,name FROM venues WHERE owner_id=? AND active=1').get(u.id);
  res.json({ token: sign(u), user: { id: u.id, name: u.name }, venue: v || null });
});

/* 비밀번호 변경 — 로그인한 사장님 본인 */
app.post('/venue/password', auth, (req, res) => {
  const u = getUser(req.uid);
  if (!u || u.provider !== 'venue') return res.status(403).json({ error: 'not_venue' });
  const cur = String((req.body && req.body.current) || '');
  const next = String((req.body && req.body.next) || '');
  if (next.length < 6) return res.status(400).json({ error: 'weak', message: '비밀번호는 6자 이상이어야 해요' });
  if (u.pw_hash !== pwHash(cur, u.pw_salt || ''))
    return res.status(401).json({ error: 'bad_current', message: '현재 비밀번호가 맞지 않아요' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET pw_salt=?, pw_hash=? WHERE id=?').run(salt, pwHash(next, salt), u.id);
  res.json({ ok: true });
});

/* 맞수가 사장님 계정을 만들어 준다 */
app.post('/admin/venue-accounts', admin, (req, res) => {
  const b = req.body || {};
  const loginId = String(b.login_id || '').trim().toLowerCase().slice(0, 40);
  const pw = String(b.password || '');
  const name = cleanName(b.name, '').slice(0, 20);
  if (!/^[a-z0-9._-]{4,}$/.test(loginId))
    return res.status(400).json({ error: 'bad_id', message: '아이디는 영문·숫자 4자 이상이어야 해요' });
  if (pw.length < 6) return res.status(400).json({ error: 'weak', message: '비밀번호는 6자 이상' });
  if (db.prepare("SELECT 1 FROM users WHERE provider='venue' AND provider_id=?").get(loginId))
    return res.status(409).json({ error: 'dup', message: '이미 있는 아이디예요' });
  const salt = crypto.randomBytes(16).toString('hex');
  const r = db.prepare(`INSERT INTO users (provider,provider_id,name,pw_salt,pw_hash,created_at)
                        VALUES ('venue',?,?,?,?,?)`)
    .run(loginId, name || loginId, salt, pwHash(pw, salt), now());
  const uid = rid(r);
  if (b.venue_id) db.prepare('UPDATE venues SET owner_id=? WHERE id=?').run(uid, +b.venue_id);
  res.json({ ok: true, user_id: uid, login_id: loginId });
});

/* 비밀번호 초기화 — 사장님이 잊었을 때 */
app.post('/admin/venue-accounts/:id/password', admin, (req, res) => {
  const pw = String((req.body && req.body.password) || '');
  if (pw.length < 6) return res.status(400).json({ error: 'weak' });
  const u = db.prepare("SELECT * FROM users WHERE id=? AND provider='venue'").get(+req.params.id);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET pw_salt=?, pw_hash=?, token_version=COALESCE(token_version,0)+1 WHERE id=?')
    .run(salt, pwHash(pw, salt), u.id);          // 기존 로그인은 전부 해제
  res.json({ ok: true });
});

/* ═══════════════════════════════════════════════════════════════
   구장 · 코트 · 열린 시간
   ─ 구장과 코트는 맞수가 등록한다 (품질 관리).
   ─ 사장님은 "시간 열기 / 닫기"만 한다.
   ─ 매니저가 열린 시간을 잡으면 hold → 모집 확정되면 booked.
     일반 대관이 잡히면 사장님이 그 시간을 닫으면 된다.
   ═══════════════════════════════════════════════════════════════ */
db.exec(`
CREATE TABLE IF NOT EXISTS venues (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  owner_id INTEGER,                      -- 사장님 계정 (users.id)
  sido TEXT, sigungu TEXT, addr TEXT,
  phone TEXT, memo TEXT,
  photos TEXT,                           -- JSON 배열
  bank TEXT,                             -- 정산 계좌
  active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS venue_courts (
  id INTEGER PRIMARY KEY,
  venue_id INTEGER NOT NULL,
  no INTEGER NOT NULL,                   -- 1번, 2번 …
  label TEXT,                            -- 비우면 "N번 코트"
  indoor INTEGER DEFAULT 0,
  surface TEXT,                          -- 하드 · 클레이 · 인조잔디
  price_hour INTEGER DEFAULT 0,          -- 1면 · 1시간
  photos TEXT,
  status TEXT DEFAULT 'active',          -- active · paused
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_vc_venue ON venue_courts(venue_id);

CREATE TABLE IF NOT EXISTS venue_slots (
  id INTEGER PRIMARY KEY,
  venue_id INTEGER NOT NULL,
  date TEXT NOT NULL,                    -- YYYY-MM-DD
  start TEXT NOT NULL, end TEXT NOT NULL,-- HH:MM
  court_ids TEXT NOT NULL,               -- JSON 배열
  price INTEGER NOT NULL,                -- 이 타임 총 코트비
  status TEXT DEFAULT 'open',            -- open · held · booked · closed
  match_id INTEGER,                      -- 잡은 오픈매치
  held_by INTEGER, held_at INTEGER,      -- 잡은 매니저
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_vs_venue ON venue_slots(venue_id, date);
CREATE INDEX IF NOT EXISTS ix_vs_open ON venue_slots(status, date);

CREATE TABLE IF NOT EXISTS venue_payouts (
  id INTEGER PRIMARY KEY,
  venue_id INTEGER NOT NULL,
  slot_id INTEGER NOT NULL,
  match_id INTEGER,
  amount INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',         -- pending · paid
  due_at INTEGER, paid_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_vp_venue ON venue_payouts(venue_id, status);
`);
/* 정산 계좌 — 기존 DB에도 추가된다 */
['bank_name TEXT', 'bank_no TEXT', 'bank_holder TEXT', 'biz_no TEXT', 'bank_at INTEGER']
  .forEach(c => { try { db.exec(`ALTER TABLE venues ADD COLUMN ${c}`); } catch (e) { /* 이미 있음 */ } });
try { db.exec('ALTER TABLE users ADD COLUMN suspended INTEGER DEFAULT 0'); } catch (e) { /* 이미 있음 */ }
try { db.exec('ALTER TABLE club_events ADD COLUMN place TEXT'); } catch (e) { /* 이미 있음 */ }
try { db.exec('ALTER TABLE clubs ADD COLUMN intro TEXT'); } catch (e) { /* 이미 있음 */ }

/* 개인 리그 참가 신청 — 참가한 사람만 리그 테이블에 오른다 */
db.exec(`CREATE TABLE IF NOT EXISTS league_entries (
  user_id INTEGER NOT NULL, sport TEXT NOT NULL, div TEXT NOT NULL DEFAULT 'men',
  joined_at INTEGER NOT NULL, PRIMARY KEY (user_id, sport, div))`);
/* 매니저 등급 — 'partner' 는 맞수 몫의 20% 를 보너스로 받고 인기 시간을 먼저 잡는다 */
['manager_tier TEXT', 'partner_since INTEGER', 'tier_warned_at INTEGER']
  .forEach(c => { try { db.exec(`ALTER TABLE users ADD COLUMN ${c}`); } catch (e) {} });

const jparse = (s, d) => { try { return JSON.parse(s) || d; } catch (e) { return d; } };
const courtName = c => c.label || `${c.no}번 코트`;

/* 내가 사장님인 구장 */
function myVenue(uid) {
  return db.prepare('SELECT * FROM venues WHERE owner_id=? AND active=1').get(uid);
}
function venueGuard(req, res, next) {
  const v = myVenue(req.uid);
  if (!v) return res.status(403).json({ error: 'not_owner', message: '등록된 구장이 없어요' });
  req.venue = v; next();
}
/* 슬롯 금액 = 선택한 코트들의 시간당 단가 합 × 시간 */
function slotPrice(courtIds, start, end) {
  const hrs = Math.max(0, (Number(String(end).slice(0, 2)) * 60 + Number(String(end).slice(3, 5))
                        - Number(String(start).slice(0, 2)) * 60 - Number(String(start).slice(3, 5))) / 60);
  if (!hrs || !courtIds.length) return 0;
  const q = db.prepare(`SELECT COALESCE(SUM(price_hour),0) s FROM venue_courts
    WHERE id IN (${courtIds.map(() => '?').join(',')})`).get(...courtIds);
  return Math.round(((q && q.s) || 0) * hrs);
}
function slotView(s) {
  const ids = jparse(s.court_ids, []);
  const courts = ids.length ? db.prepare(`SELECT id,no,label,indoor,surface FROM venue_courts
    WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY no`).all(...ids) : [];
  const v = db.prepare('SELECT id,name,sido,sigungu,addr,photos FROM venues WHERE id=?').get(s.venue_id) || {};
  return { ...s, court_ids: ids, courts: courts.map(c => ({ ...c, name: courtName(c) })),
           venue: { ...v, photos: jparse(v.photos, []) } };
}

/* ── 사장님 ─────────────────────────────────────── */
app.get('/venue/me', auth, (req, res) => {
  const v = myVenue(req.uid);
  if (!v) return res.json({ venue: null });
  const courts = db.prepare('SELECT * FROM venue_courts WHERE venue_id=? ORDER BY no').all(v.id);
  res.json({ venue: { ...v, photos: jparse(v.photos, []) },
             courts: courts.map(c => ({ ...c, name: courtName(c), photos: jparse(c.photos, []) })) });
});

app.get('/venue/slots', auth, venueGuard, (req, res) => {
  const from = String(req.query.from || '').slice(0, 10) || new Date().toISOString().slice(0, 10);
  const to = String(req.query.to || '').slice(0, 10) || '9999-12-31';
  const rows = db.prepare(`SELECT * FROM venue_slots WHERE venue_id=? AND date BETWEEN ? AND ?
    ORDER BY date, start`).all(req.venue.id, from, to);
  res.json(rows.map(r => ({ ...slotView(r), ...slotUse(r) })));
});

/* 이 시간을 누가 쓰는지 — 사장님이 현장 준비를 다르게 해야 하므로 구분해서 준다.
   오픈매치는 12명이 매니저와 함께 오고, 개인 예약은 두세 명이 자기들끼리 온다. */
function slotUse(s) {
  const bk = db.prepare("SELECT * FROM venue_bookings WHERE slot_id=? AND status='paid'").get(s.id);
  if (bk) {
    const u = getUser(bk.user_id) || {};
    return { use: 'booking', headcount: null,
             booker: { name: u.name || '회원', phone: u.phone || '' },
             manager: null, memo: bk.memo || '' };
  }
  if (s.match_id) {
    const m = db.prepare('SELECT id,cap,min_cnt,host_id FROM open_matches WHERE id=?').get(s.match_id);
    const n = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(s.match_id).n;
    const h = m && m.host_id ? getUser(m.host_id) : null;
    return { use: 'match', headcount: n, booker: null,
             manager: h ? { name: h.name || '매니저', phone: h.phone || '' } : null,
             need: m ? (m.min_cnt || m.cap || 0) : 0 };
  }
  return { use: null, headcount: null, booker: null, manager: null };
}

/* 시간 열기 — 하루 지정 또는 요일 반복(weeks 주만큼) */
app.post('/venue/slots', auth, venueGuard, (req, res) => {
  const b = req.body || {};
  const courtIds = (Array.isArray(b.court_ids) ? b.court_ids : []).map(Number).filter(Boolean);
  const start = String(b.start || '').slice(0, 5), end = String(b.end || '').slice(0, 5);
  if (!courtIds.length || !/^\d\d:\d\d$/.test(start) || !/^\d\d:\d\d$/.test(end))
    return res.status(400).json({ error: 'bad_input' });
  if (end <= start) return res.status(400).json({ error: 'bad_time', message: '종료가 시작보다 빨라요' });

  // 내 구장 코트인지 확인 (남의 코트를 열 수 없게)
  const mine = db.prepare(`SELECT COUNT(*) n FROM venue_courts
    WHERE venue_id=? AND status='active' AND id IN (${courtIds.map(() => '?').join(',')})`)
    .get(req.venue.id, ...courtIds).n;
  if (mine !== courtIds.length) return res.status(400).json({ error: 'bad_court' });

  /* 긴 시간을 소셜 매치가 열릴 수 있는 단위로 자른다.
     오픈매치는 2시간 또는 3시간만 열리므로, 09-17시(8시간)를 한 덩어리로 두면 아무도 못 잡는다.
     3시간을 우선으로 채우고 1시간이 남으면 3+1 대신 2+2로 바꾼다. */
  function splitHours(total) {
    if (total < 2) return null;                       // 1시간짜리는 매치를 열 수 없다
    const out = [];
    let left = total;
    while (left >= 3) { out.push(3); left -= 3; }
    if (left === 2) out.push(2);
    else if (left === 1) {
      if (!out.length) return null;
      out.pop(); out.push(2, 2);                      // 3+1 → 2+2
    }
    return out;
  }
  const toMin = t => +t.slice(0, 2) * 60 + +t.slice(3, 5);
  const toHHMM = m => String(Math.floor(m / 60)).padStart(2, '0') + ':' + String(m % 60).padStart(2, '0');
  const totalMin = toMin(end) - toMin(start);
  if (totalMin % 60 !== 0)
    return res.status(400).json({ error: 'bad_time', message: '시간 단위로 열어주세요 (예: 09:00–17:00)' });
  let skippedTail = 0;
  const unit = String(b.unit || 'mix');          // '2' | '3' | 'mix'
  let chunks;
  if (unit === '2' || unit === '3') {
    const u = +unit, hrs = totalMin / 60;
    chunks = [];
    let left = hrs;
    while (left >= u) { chunks.push(u); left -= u; }
    if (left > 0 && chunks.length) skippedTail = left;   // 남는 자투리는 열지 않는다
    if (!chunks.length) chunks = null;
  } else {
    chunks = splitHours(totalMin / 60);
  }
  if (!chunks) return res.status(400).json({ error: 'bad_time',
    message: unit === '3' ? '3시간 이상 열어주세요' : '최소 2시간 이상 열어주세요' });

  const spans = [];
  let cur = toMin(start);
  chunks.forEach(h => { spans.push([toHHMM(cur), toHHMM(cur + h * 60)]); cur += h * 60; });

  const price = slotPrice([courtIds[0]], spans[0][0], spans[0][1]);
  if (price <= 0) return res.status(400).json({ error: 'no_price', message: '코트 단가가 설정되지 않았어요' });

  // 날짜 목록 만들기
  const dates = [];
  if (Array.isArray(b.dates) && b.dates.length) {
    b.dates.forEach(d => { const s = String(d).slice(0, 10); if (/^\d{4}-\d\d-\d\d$/.test(s)) dates.push(s); });
  } else if (Array.isArray(b.weekdays) && b.weekdays.length) {
    const weeks = Math.min(Math.max(1, +b.weeks || 4), 12);      // 최대 12주
    const base = new Date(); base.setHours(12, 0, 0, 0);
    for (let i = 0; i < weeks * 7; i++) {
      const d = new Date(base.getTime() + i * 86400000);
      if (b.weekdays.includes(d.getDay())) dates.push(d.toISOString().slice(0, 10));
    }
  }
  if (!dates.length) return res.status(400).json({ error: 'no_date' });

  let made = 0, skipped = 0;
  tx(() => {
    dates.forEach(date => spans.forEach(([sStart, sEnd]) => {
      // 같은 날 같은 시간에 코트가 겹치면 건너뛴다
      const same = db.prepare(`SELECT court_ids FROM venue_slots
        WHERE venue_id=? AND date=? AND status!='closed' AND NOT(end<=? OR start>=?)`)
        .all(req.venue.id, date, sStart, sEnd);
      const busy = new Set(); same.forEach(r => jparse(r.court_ids, []).forEach(id => busy.add(id)));
      skipped += courtIds.filter(id => busy.has(id)).length;
      /* 코트를 묶지 않고 1면씩 따로 연다.
         단식 한 사람은 1면만, 오픈매치 매니저는 여러 면을 골라 가져갈 수 있어야 한다. */
      courtIds.forEach(cid => {
        if (busy.has(cid)) return;
        const p = slotPrice([cid], sStart, sEnd);
        if (p <= 0) return;
        db.prepare(`INSERT INTO venue_slots (venue_id,date,start,end,court_ids,price,status,created_at)
                    VALUES (?,?,?,?,?,?, 'open', ?)`)
          .run(req.venue.id, date, sStart, sEnd, JSON.stringify([cid]), p, now());
        made++;
      });
    }));
  });
  res.json({ ok: true, made, skipped, price, unit, tail_hours: skippedTail, per_day: spans.length,
             spans: spans.map(([a, b2]) => `${a}-${b2}`) });
});

/* 시간 닫기 — 일반 대관이 잡혔을 때 */
app.delete('/venue/slots/:id', auth, venueGuard, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=? AND venue_id=?').get(+req.params.id, req.venue.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status === 'booked')
    return res.status(400).json({ error: 'booked', message: '이미 확정된 매치가 있어요. 맞수로 문의해 주세요' });
  if (s.status === 'held')
    return res.status(400).json({ error: 'held', message: '매니저가 모집 중이에요. 확정 전까지 기다려 주세요' });
  db.prepare("UPDATE venue_slots SET status='closed' WHERE id=?").run(s.id);
  res.json({ ok: true, closed: true });
});

/* ── 정산 계좌 ─────────────────────────────────────
   사장님이 직접 등록·변경한다. 계좌가 없으면 입금을 보낼 수 없다. */
app.get('/venue/bank', auth, venueGuard, (req, res) => {
  const v = req.venue;
  res.json({ bank_name: v.bank_name || '', bank_no: v.bank_no || '',
             bank_holder: v.bank_holder || '', biz_no: v.biz_no || '',
             updated_at: v.bank_at || null });
});

app.post('/venue/bank', auth, venueGuard, (req, res) => {
  const b = req.body || {};
  const name   = String(b.bank_name || '').trim().slice(0, 20);
  const no     = String(b.bank_no || '').replace(/[^0-9-]/g, '').slice(0, 30);
  const holder = String(b.bank_holder || '').trim().slice(0, 30);
  const biz    = String(b.biz_no || '').replace(/[^0-9-]/g, '').slice(0, 15);
  if (!name || !holder) return res.status(400).json({ error: 'missing', message: '은행과 예금주를 입력해 주세요' });
  if (no.replace(/-/g, '').length < 8)
    return res.status(400).json({ error: 'bad_account', message: '계좌번호를 다시 확인해 주세요' });
  const bizDigits = biz.replace(/-/g, '');
  if (bizDigits && bizDigits.length !== 10)
    return res.status(400).json({ error: 'bad_biz', message: '사업자등록번호는 10자리예요' });

  db.prepare(`UPDATE venues SET bank_name=?, bank_no=?, bank_holder=?, biz_no=?, bank_at=?,
              bank=? WHERE id=?`)
    .run(name, no, holder, biz, now(), `${name} ${no}`, req.venue.id);
  res.json({ ok: true });
});

/* ── 월별 명세 ─────────────────────────────────────
   확정(booked)된 슬롯 기준. 세금계산서 발행에 쓰이므로 공급가액·부가세를 나눠서 준다.
   VENUE_PRICE_INCLUDES_VAT=0 으로 두면 "코트 단가 + 부가세 별도"로 계산한다. */
const VAT_INCLUDED = String(process.env.VENUE_PRICE_INCLUDES_VAT || '1') !== '0';
function splitVat(total) {
  if (VAT_INCLUDED) {
    const supply = Math.round(total / 1.1);
    return { supply, vat: total - supply, total };
  }
  const vat = Math.round(total * 0.1);
  return { supply: total, vat, total: total + vat };
}

/* 월 목록 — 최근 12개월 */
app.get('/venue/statements', auth, venueGuard, (req, res) => {
  const rows = db.prepare(`SELECT substr(s.date,1,7) ym, COUNT(*) times, COALESCE(SUM(p.amount),0) amount
    FROM venue_payouts p JOIN venue_slots s ON s.id=p.slot_id
    WHERE p.venue_id=? GROUP BY ym ORDER BY ym DESC LIMIT 12`).all(req.venue.id);
  res.json(rows.map(r => ({ ...r, ...splitVat(r.amount), vat_included: VAT_INCLUDED })));
});

/* 한 달 상세 */
app.get('/venue/statements/:ym', auth, venueGuard, (req, res) => {
  const ym = String(req.params.ym || '').slice(0, 7);
  if (!/^\d{4}-\d{2}$/.test(ym)) return res.status(400).json({ error: 'bad_month' });
  const rows = db.prepare(`SELECT p.id, p.amount, p.status, p.due_at, p.paid_at,
      s.date, s.start, s.end, s.court_ids
    FROM venue_payouts p JOIN venue_slots s ON s.id=p.slot_id
    WHERE p.venue_id=? AND substr(s.date,1,7)=? ORDER BY s.date DESC, s.start DESC`)
    .all(req.venue.id, ym);
  const total = rows.reduce((a, r) => a + r.amount, 0);
  const courtNames = ids => {
    if (!ids.length) return '';
    const cs = db.prepare(`SELECT no,label FROM venue_courts WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY no`).all(...ids);
    return cs.map(courtName).join(' · ');
  };
  res.json({
    ym, times: rows.length, ...splitVat(total), vat_included: VAT_INCLUDED,
    venue: { name: req.venue.name, bank: req.venue.bank || '', biz_no: req.venue.biz_no || '' },
    list: rows.map(r => { const ids = jparse(r.court_ids, []);
      return { ...r, court_ids: ids, courts: courtNames(ids) }; })
  });
});

/* CSV 내려받기 — 엑셀에서 바로 열린다 */
app.get('/venue/statements/:ym/csv', auth, venueGuard, (req, res) => {
  const ym = String(req.params.ym || '').slice(0, 7);
  if (!/^\d{4}-\d{2}$/.test(ym)) return res.status(400).json({ error: 'bad_month' });
  const rows = db.prepare(`SELECT p.amount, p.status, p.paid_at, s.date, s.start, s.end
    FROM venue_payouts p JOIN venue_slots s ON s.id=p.slot_id
    WHERE p.venue_id=? AND substr(s.date,1,7)=? ORDER BY s.date, s.start`).all(req.venue.id, ym);
  const total = rows.reduce((a, r) => a + r.amount, 0);
  const v = splitVat(total);
  const d = t => t ? new Date(t).toISOString().slice(0, 10) : '';
  const lines = [['날짜', '시작', '종료', '금액', '상태', '입금일'].join(',')];
  rows.forEach(r => lines.push([r.date, r.start, r.end, r.amount,
    r.status === 'paid' ? '입금완료' : '입금예정', d(r.paid_at)].join(',')));
  lines.push('', `공급가액,${v.supply}`, `부가세,${v.vat}`, `합계,${v.total}`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition',
    `attachment; filename="matsu-${ym}.csv"; filename*=UTF-8''${encodeURIComponent(`맞수정산-${ym}.csv`)}`);
  res.send('\uFEFF' + lines.join('\n'));       // BOM — 엑셀 한글 깨짐 방지
});

app.get('/venue/payouts', auth, venueGuard, (req, res) => {
  const rows = db.prepare(`SELECT p.*, s.date, s.start, s.end, s.court_ids
    FROM venue_payouts p LEFT JOIN venue_slots s ON s.id=p.slot_id
    WHERE p.venue_id=? ORDER BY p.id DESC LIMIT 60`).all(req.venue.id);
  const sum = st => rows.filter(r => r.status === st).reduce((a, r) => a + r.amount, 0);
  res.json({ pending: sum('pending'), paid: sum('paid'),
             list: rows.map(r => ({ ...r, court_ids: jparse(r.court_ids, []) })) });
});

/* ── 매니저 ─────────────────────────────────────── */
app.get('/venue-slots/open', auth, (req, res) => {
  const { sido, sigungu } = req.query;
  const today = new Date().toISOString().slice(0, 10);
  const w = ["s.status='open'", 's.date>=?']; const a = [today];
  if (sido) { w.push('v.sido=?'); a.push(sido); }
  if (sigungu) { w.push('v.sigungu=?'); a.push(sigungu); }
  const rows = db.prepare(`SELECT s.* FROM venue_slots s JOIN venues v ON v.id=s.venue_id
    WHERE ${w.join(' AND ')} AND v.active=1 ORDER BY s.date, s.start LIMIT 120`).all(...a);
  const me = req.uid ? (getUser(req.uid) || {}) : {};
  res.json(rows.map(r => ({ ...slotView(r), holdable: canHoldNow(me, r), lead_days: PARTNER_LEAD_D })));
});

/* ══════════════════════════════════════════════════════════════
   회원 코트 예약 — 충전한 캐시로 결제한다 (카드 결제창을 다시 띄우지 않는다)

   오픈매치와 같은 슬롯을 두고 다투므로 규칙을 둔다:
   · 매니저가 잡지 않은(open) 슬롯만 예약할 수 있다
   · 경기 시작이 RESERVE_WINDOW_H 시간 이내로 임박한 것만 연다
     — 여유 있는 시간은 12명이 오는 오픈매치로 채우는 편이 모두에게 낫다
   ══════════════════════════════════════════════════════════════ */
/* 0 = 상시 예약. 몇 달 뒤 코트를 미리 잡는 사람이 많아 기본은 제한을 두지 않는다.
   오픈매치와 자리를 다투게 되면 이 값을 시간 단위로 올려 개인 예약을 뒤로 미룰 수 있다. */
const RESERVE_WINDOW_H = +(process.env.VENUE_RESERVE_WINDOW_H || 0);

/* 기본은 선착순 — 먼저 잡는 사람이 임자다.
   코트는 시간이 지나면 사라지는 재고라, 비워두는 것보다 누구에게든 파는 게 낫다.
   나중에 오픈매치가 코트를 못 구하는 일이 잦아지면 여기에 시간을 넣어
   '경기 N시간 전까지는 매니저만' 으로 바꿀 수 있다. */
const MANAGER_PRIORITY_H = +(process.env.VENUE_MANAGER_PRIORITY_H || 0);
const RESERVE_FEE_RATE = +(process.env.VENUE_RESERVE_FEE_RATE || 0.1);  // 코트비 위에 붙는 맞수 수수료

db.exec(`CREATE TABLE IF NOT EXISTS venue_bookings (
  id INTEGER PRIMARY KEY,
  slot_id INTEGER NOT NULL,
  venue_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  court_cost INTEGER NOT NULL,        -- 사장님께 갈 코트 대금
  fee INTEGER NOT NULL,               -- 맞수 수수료
  amount INTEGER NOT NULL,            -- 회원이 낸 캐시 총액
  status TEXT NOT NULL DEFAULT 'paid',-- paid · canceled
  memo TEXT,
  created_at INTEGER NOT NULL,
  canceled_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_vb_user ON venue_bookings(user_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS ux_vb_slot ON venue_bookings(slot_id);`);

function reserveQuote(slot) {
  const fee = Math.round(slot.price * RESERVE_FEE_RATE / 100) * 100;   // 100원 단위
  return { court_cost: slot.price, fee, amount: slot.price + fee };
}
function reserveOpenAt(slot) {                      // 개인 예약이 열리는 시각
  const startMs = new Date(`${slot.date}T${slot.start}:00`).getTime();
  const byWindow = RESERVE_WINDOW_H ? startMs - RESERVE_WINDOW_H * 3600000 : 0;
  const byPriority = MANAGER_PRIORITY_H ? startMs - MANAGER_PRIORITY_H * 3600000 : 0;
  return Math.max(byWindow, byPriority);
}

/* 지금 회원이 예약할 수 있는 코트 */
app.get('/venue-slots/reservable', (req, res) => {
  const { sido, sigungu, date } = req.query;
  const today = new Date().toISOString().slice(0, 10);
  const w = ["s.status='open'", 's.date>=?']; const a = [today];
  if (sido) { w.push('v.sido=?'); a.push(sido); }
  if (sigungu) { w.push('v.sigungu=?'); a.push(sigungu); }
  if (date) { w.push('s.date=?'); a.push(String(date).slice(0, 10)); }
  const rows = db.prepare(`SELECT s.* FROM venue_slots s JOIN venues v ON v.id=s.venue_id
    WHERE ${w.join(' AND ')} AND v.active=1 ORDER BY s.date, s.start LIMIT 120`).all(...a);
  const nowMs = Date.now();
  res.json(rows.map(r => {
    const v = slotView(r), q = reserveQuote(r);
    const openAt = reserveOpenAt(r);
    const startMs = new Date(`${r.date}T${r.start}:00`).getTime();
    return { ...v, ...q, reservable: nowMs >= openAt && startMs > nowMs,
             opens_at: openAt || null, window_h: RESERVE_WINDOW_H,
             priority_h: MANAGER_PRIORITY_H,
             hours: Math.round((new Date(`${r.date}T${r.end}:00`) - new Date(`${r.date}T${r.start}:00`)) / 36e5) };
  }));
});

/* 예약하기 — 캐시에서 바로 차감한다 */
app.post('/venue-slots/:id/reserve', auth, (req, res) => {
  const u = getUser(req.uid);
  if (!u) return res.status(401).json({ error: 'no_user' });
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status !== 'open')
    return res.status(409).json({ error: 'taken', message: '방금 다른 분이 잡았어요' });

  const startMs = new Date(`${s.date}T${s.start}:00`).getTime();
  if (startMs <= Date.now())
    return res.status(400).json({ error: 'past', message: '이미 지난 시간이에요' });
  if (Date.now() < reserveOpenAt(s))
    return res.status(400).json({ error: 'too_early',
      message: `아직 매니저 모집 기간이에요 · 경기 ${MANAGER_PRIORITY_H}시간 전부터 예약할 수 있어요` });

  const q = reserveQuote(s);
  if ((u.cash || 0) < q.amount)
    return res.status(402).json({ error: 'no_cash', need: q.amount, cash: u.cash || 0,
      message: `캐시가 ${(q.amount - (u.cash || 0)).toLocaleString()}원 모자라요` });

  let bookingId = null;
  try {
    tx(() => {
      // 슬롯을 먼저 잠근다 — 동시에 두 명이 눌러도 한 명만 통과한다
      const lock = db.prepare("UPDATE venue_slots SET status='booked' WHERE id=? AND status='open'").run(s.id);
      if (!lock.changes) throw new Error('taken');
      const bal = (u.cash || 0) - q.amount;
      db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(u.id, -q.amount, 'venue_reserve', bal, now());
      const r = db.prepare(`INSERT INTO venue_bookings
        (slot_id,venue_id,user_id,court_cost,fee,amount,status,memo,created_at)
        VALUES (?,?,?,?,?,?, 'paid', ?, ?)`)
        .run(s.id, s.venue_id, u.id, q.court_cost, q.fee, q.amount,
             String((req.body && req.body.memo) || '').slice(0, 200), now());
      bookingId = rid(r);
      // 사장님 정산도 같이 잡는다 — 오픈매치로 팔린 것과 같은 대우
      db.prepare(`INSERT INTO venue_payouts (venue_id,slot_id,match_id,amount,status,due_at,created_at)
                  VALUES (?,?,NULL,?, 'pending', ?, ?)`)
        .run(s.venue_id, s.id, q.court_cost, nextBusinessDay(startMs, 3), now());
    });
  } catch (e) {
    if (String(e.message) === 'taken')
      return res.status(409).json({ error: 'taken', message: '방금 다른 분이 잡았어요' });
    return res.status(500).json({ error: String(e.message || e) });
  }

  const v = db.prepare('SELECT name, owner_id FROM venues WHERE id=?').get(s.venue_id);
  if (v && v.owner_id) sendPush(v.owner_id, { icon: '🎾', title: '코트가 예약됐어요',
    body: `${s.date} ${s.start}-${s.end} · ${v.name}` });
  res.json({ ok: true, id: bookingId, ...q, cash: (u.cash || 0) - q.amount });
});

/* 내 예약 */
app.get('/me/venue-bookings', auth, (req, res) => {
  const rows = db.prepare(`SELECT b.*, s.date, s.start, s.end, s.court_ids, v.name venue_name,
      v.addr, v.sigungu, v.photos FROM venue_bookings b
    JOIN venue_slots s ON s.id=b.slot_id LEFT JOIN venues v ON v.id=b.venue_id
    WHERE b.user_id=? ORDER BY s.date DESC, s.start DESC LIMIT 40`).all(req.uid);
  res.json(rows.map(r => ({ ...r, photos: jparse(r.photos, []), court_ids: jparse(r.court_ids, []) })));
});

/* 예약 취소 — 경기 24시간 전까지는 전액, 이후에는 불가 */
const RESERVE_FREE_CANCEL_H = +(process.env.VENUE_CANCEL_FREE_H || 24);
/* ═══ 예약 취소 · 환불 3단계 ═══
   "그 이후에는 연락 주세요"가 가장 위험했다. 기준이 없으면 매번 협상이 되고,
   사장님은 이미 코트를 비워둔 상태다. 시점에 따라 손실을 나눈다.

     48시간 전   회원 전액 (수수료까지)
     24~48시간   코트비 전액 · 맞수 수수료는 미환급
     24시간 이내  코트비 50% · 나머지 50%는 사장님께
     시작 이후    환불 없음 · 코트비 전액 사장님께
   우천 휴장은 이 표와 무관하게 전액 환불한다. */
const CANCEL_FULL_H = +(process.env.CANCEL_FULL_H || 48);
const CANCEL_HALF_H = +(process.env.CANCEL_HALF_H || 24);

function cancelQuote(b, startMs, opts) {
  const rain = !!(opts && opts.rain);
  const left = (startMs - Date.now()) / 3600000;
  if (rain) return { refund: b.amount, venue: 0, tier: 'rain', label: '우천 휴장 · 전액 환불' };
  if (left >= CANCEL_FULL_H)
    return { refund: b.amount, venue: 0, tier: 'full', label: `${CANCEL_FULL_H}시간 전 · 전액 환불` };
  if (left >= CANCEL_HALF_H)
    return { refund: b.court_cost, venue: 0, tier: 'nofee',
             label: `${CANCEL_HALF_H}시간 전 · 코트비만 환불 (수수료 제외)` };
  if (left > 0) {
    const half = Math.round(b.court_cost / 2);
    return { refund: half, venue: b.court_cost - half, tier: 'half',
             label: `${CANCEL_HALF_H}시간 이내 · 코트비 절반만 환불` };
  }
  return { refund: 0, venue: b.court_cost, tier: 'noshow', label: '시작 이후 · 환불 없음' };
}

/* 취소 전에 얼마가 돌아오는지 미리 보여준다 — 눌러보고 알게 하면 안 된다 */
app.get('/me/venue-bookings/:id/cancel-quote', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM venue_bookings WHERE id=? AND user_id=?').get(+req.params.id, req.uid);
  if (!b) return res.status(404).json({ error: 'not_found' });
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(b.slot_id);
  const startMs = s ? new Date(`${s.date}T${s.start}:00`).getTime() : 0;
  const q = cancelQuote(b, startMs);
  res.json({ ...q, paid: b.amount, court_cost: b.court_cost, fee: b.fee,
             hours_left: Math.max(0, Math.round((startMs - Date.now()) / 3600000)) });
});

function applyBookingCancel(b, startMs, opts) {
  const q = cancelQuote(b, startMs, opts);
  const u = getUser(b.user_id);
  tx(() => {
    db.prepare("UPDATE venue_bookings SET status='canceled', canceled_at=?, memo=COALESCE(memo,'')||? WHERE id=?")
      .run(now(), ` [취소:${q.tier}]`, b.id);
    /* 사장님 몫이 남으면 정산을 지우지 않고 금액만 줄인다 —
       예약이 조용히 사라지면 사장님은 무슨 일이 있었는지 알 수 없다. */
    if (q.venue > 0) {
      db.prepare("UPDATE venue_payouts SET amount=? WHERE slot_id=? AND status='pending'").run(q.venue, b.slot_id);
    } else {
      db.prepare("DELETE FROM venue_payouts WHERE slot_id=? AND status='pending'").run(b.slot_id);
    }
    db.prepare("UPDATE venue_slots SET status='open' WHERE id=? AND status='booked'").run(b.slot_id);
    if (q.refund > 0 && u) {
      const bal = (u.cash || 0) + q.refund;
      db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(u.id, q.refund, 'venue_reserve_refund', bal, now());
    }
  });
  return q;
}

app.post('/me/venue-bookings/:id/cancel', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM venue_bookings WHERE id=? AND user_id=?').get(+req.params.id, req.uid);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (b.status !== 'paid') return res.status(400).json({ error: 'already', message: '이미 취소된 예약이에요' });
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(b.slot_id);
  const startMs = s ? new Date(`${s.date}T${s.start}:00`).getTime() : 0;
  const q = applyBookingCancel(b, startMs);
  try {
    if (q.venue > 0) sendPush(b.user_id, { title: '예약을 취소했어요', body: q.label });
  } catch (e) {}
  res.json({ ok: true, refunded: q.refund, tier: q.tier, label: q.label });
});

/* ── 우천 휴장 — 사장님이 누르면 그 슬롯 예약이 전액 환불된다 ── */
app.post('/venue/slots/:id/rain', auth, (req, res) => {
  const u = getUser(req.uid);
  if (!u || u.provider !== 'venue') return res.status(403).json({ error: 'not_venue' });
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const v = db.prepare('SELECT id FROM venues WHERE id=? AND owner_id=?').get(s.venue_id, req.uid);
  if (!v) return res.status(403).json({ error: 'not_owner' });
  const startMs = new Date(`${s.date}T${s.start}:00`).getTime();
  const bs = db.prepare("SELECT * FROM venue_bookings WHERE slot_id=? AND status='paid'").all(s.id);
  let refunded = 0;
  bs.forEach(b => { const q = applyBookingCancel(b, startMs, { rain: true }); refunded += q.refund;
    try { sendPush(b.user_id, { title: '우천으로 휴장돼요', body: `${s.date} ${s.start} · 전액 환불했어요` }); } catch (e) {} });
  db.prepare("UPDATE venue_slots SET status='closed' WHERE id=?").run(s.id);
  res.json({ ok: true, canceled: bs.length, refunded });
});

/* 매니저가 잡기 — 아직 돈은 나가지 않는다 */
app.post('/venue-slots/:id/hold', auth, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status !== 'open') return res.status(400).json({ error: 'taken', message: '이미 지나간 자리예요' });
  const me = getUser(req.uid) || {};
  if (!canHoldNow(me, s)) return res.status(403).json({ error: 'partner_only',
    message: `파트너 매니저가 먼저 고르는 기간이에요 · 경기 ${PARTNER_LEAD_D}일 전부터 열려요` });
  db.prepare("UPDATE venue_slots SET status='held', held_by=?, held_at=? WHERE id=? AND status='open'")
    .run(req.uid, now(), s.id);
  const v = db.prepare('SELECT owner_id,name FROM venues WHERE id=?').get(s.venue_id);
  if (v && v.owner_id) sendPush(v.owner_id, { icon: '🎾', title: '매니저가 코트를 잡았어요',
    body: `${s.date} ${s.start}–${s.end} · 모집이 확정되면 알려드릴게요` });
  res.json({ ok: true, slot: slotView(db.prepare('SELECT * FROM venue_slots WHERE id=?').get(s.id)) });
});

/* 여러 면을 한 번에 잡는다 — 오픈매치는 코트 수로 정원이 정해지므로 묶어서 가져가야 한다.
   하나라도 이미 나갔으면 전부 되돌린다. 반쪽만 잡히면 매치를 열 수 없다. */
app.post('/venue-slots/hold-many', auth, (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids)
    ? [...new Set(req.body.ids.map(Number).filter(Boolean))] : [];
  if (!ids.length) return res.status(400).json({ error: 'no_ids' });
  /* 오픈매치는 2면부터. 1면(4~6명)은 매니저 없이 개인끼리 치는 자리라
     수고비를 얹으면 참가비만 비싸진다. 그런 시간은 구장예약으로 팔린다. */
  if (ids.length < 2) return res.status(400).json({ error: 'too_few',
    message: '오픈매치는 2면부터 열 수 있어요 · 1면은 개인 예약으로 나갑니다' });
  if (ids.length > 6) return res.status(400).json({ error: 'too_many', message: '한 번에 6면까지예요' });

  const rows = db.prepare(`SELECT * FROM venue_slots WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids);
  if (rows.length !== ids.length) return res.status(404).json({ error: 'not_found' });
  const me = getUser(req.uid) || {};
  if (rows.some(r => !canHoldNow(me, r))) return res.status(403).json({ error: 'partner_only',
    message: `파트너 매니저가 먼저 고르는 기간이에요 · 경기 ${PARTNER_LEAD_D}일 전부터 열려요` });
  const base = rows[0];
  const same = rows.every(r => r.venue_id === base.venue_id && r.date === base.date
                            && r.start === base.start && r.end === base.end);
  if (!same) return res.status(400).json({ error: 'mixed', message: '같은 구장·같은 시간의 코트만 함께 잡을 수 있어요' });

  let ok = 0;
  try {
    tx(() => {
      rows.forEach(r => {
        const c = db.prepare("UPDATE venue_slots SET status='held', held_by=?, held_at=? WHERE id=? AND status='open'")
          .run(req.uid, now(), r.id);
        if (!c.changes) throw new Error('taken');
        ok++;
      });
    });
  } catch (e) {
    if (String(e.message) === 'taken')
      return res.status(409).json({ error: 'taken', message: '방금 누군가 가져간 코트가 있어요. 새로고침해 주세요' });
    return res.status(500).json({ error: String(e.message || e) });
  }

  const v = db.prepare('SELECT owner_id,name FROM venues WHERE id=?').get(base.venue_id);
  if (v && v.owner_id) sendPush(v.owner_id, { icon: '🎾', title: '매니저가 코트를 잡았어요',
    body: `${base.date} ${base.start}–${base.end} · ${ok}면 · 확정되면 알려드릴게요` });
  res.json({ ok: true, held: ok,
    slots: db.prepare(`SELECT * FROM venue_slots WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids).map(slotView) });
});

/* 잡은 코트 전체를 한 번에 놓는다 */
app.post('/venue-slots/release-many', auth, (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids.map(Number).filter(Boolean) : [];
  if (!ids.length) return res.status(400).json({ error: 'no_ids' });
  const r = db.prepare(`UPDATE venue_slots SET status='open', held_by=NULL, held_at=NULL, match_id=NULL
    WHERE held_by=? AND status='held' AND id IN (${ids.map(() => '?').join(',')})`).run(req.uid, ...ids);
  res.json({ ok: true, released: r.changes });
});

/* 매니저가 포기 — 다시 열어둔다 */
app.post('/venue-slots/:id/release', auth, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status !== 'held' || s.held_by !== req.uid) return res.status(400).json({ error: 'not_holder' });
  db.prepare("UPDATE venue_slots SET status='open', held_by=NULL, held_at=NULL, match_id=NULL WHERE id=?").run(s.id);
  res.json({ ok: true });
});

/* 모집 확정 → 코트 확정 + 사장님 정산 예약 */
/* 한 매치가 여러 면을 쓸 수 있으므로 걸려 있는 코트를 모두 확정한다.
   정산도 코트별로 따로 잡아야 나중에 1면만 취소하는 일이 가능하다. */
function venueConfirm(slotId, matchId) {
  const list = slotId
    ? [db.prepare('SELECT * FROM venue_slots WHERE id=?').get(slotId)].filter(Boolean)
    : db.prepare("SELECT * FROM venue_slots WHERE match_id=? AND status='held'").all(matchId);
  const todo = list.filter(s => s && s.status !== 'booked');
  if (!todo.length) return null;
  tx(() => todo.forEach(s => {
    db.prepare("UPDATE venue_slots SET status='booked', match_id=? WHERE id=?").run(matchId || s.match_id || null, s.id);
    db.prepare(`INSERT INTO venue_payouts (venue_id,slot_id,match_id,amount,status,due_at,created_at)
                VALUES (?,?,?,?, 'pending', ?, ?)`)
      .run(s.venue_id, s.id, matchId || s.match_id || null, s.price, nextBusinessDay(Date.now(), 3), now());
  }));
  const first = todo[0];
  const total = todo.reduce((a, s) => a + s.price, 0);
  const v = db.prepare('SELECT owner_id FROM venues WHERE id=?').get(first.venue_id);
  if (v && v.owner_id) sendPush(v.owner_id, { icon: '✅', title: '코트 판매가 확정됐어요',
    body: `${first.date} ${first.start}–${first.end} · ${todo.length}면 · ${total.toLocaleString()}원` });
  return first;
}

/* ══════════════════════════════════════════════════════════════
   매니저센터 — 맞수가 발급한 아이디로 로그인한다 (provider='manager')
   매니저는 열린 코트를 잡고 → 오픈매치를 걸어 사람을 모은다.
   ══════════════════════════════════════════════════════════════ */
app.post('/manager/login', limitLogin, (req, res) => {
  const loginId = String((req.body && req.body.login_id) || '').trim().toLowerCase().slice(0, 40);
  const pw = String((req.body && req.body.password) || '');
  if (!loginId || !pw) return res.status(400).json({ error: 'missing' });
  const u = db.prepare("SELECT * FROM users WHERE provider='manager' AND provider_id=?").get(loginId);
  if (!u || !u.pw_hash || u.pw_hash !== pwHash(pw, u.pw_salt || ''))
    return res.status(401).json({ error: 'bad_login', message: '아이디 또는 비밀번호가 맞지 않아요' });
  if (u.suspended) return res.status(403).json({ error: 'suspended', message: '정지된 계정이에요. 맞수로 문의해 주세요' });
  res.json({ token: sign(u), user: { id: u.id, name: u.name } });
});

function mgrGuard(req, res, next) {
  const u = getUser(req.uid);
  if (!u || u.provider !== 'manager') return res.status(403).json({ error: 'not_manager', message: '매니저 계정이 아니에요' });
  if (u.suspended) return res.status(403).json({ error: 'suspended' });
  req.mgr = u; next();
}

app.get('/manager/me', auth, mgrGuard, (req, res) => {
  const held = db.prepare("SELECT COUNT(*) n FROM venue_slots WHERE held_by=? AND status='held'").get(req.uid).n;
  const booked = db.prepare("SELECT COUNT(*) n FROM venue_slots WHERE held_by=? AND status='booked'").get(req.uid).n;
  const pend = db.prepare("SELECT COALESCE(SUM(amount),0) s FROM om_payouts WHERE user_id=? AND status!='paid'").get(req.uid).s;
  const paid = db.prepare("SELECT COALESCE(SUM(amount),0) s FROM om_payouts WHERE user_id=? AND status='paid'").get(req.uid).s;
  res.json({ user: { id: req.mgr.id, name: req.mgr.name },
             held, booked, payout_pending: pend, payout_paid: paid,
             tier: mgrTierState(req.mgr) });
});

/* 내가 잡은 코트 — 모집 중 · 확정 */
app.get('/manager/slots', auth, mgrGuard, (req, res) => {
  const rows = db.prepare(`SELECT * FROM venue_slots WHERE held_by=? AND status IN ('held','booked')
    AND date>=? ORDER BY date, start`).all(req.uid, new Date().toISOString().slice(0, 10));
  res.json(rows.map(r => {
    const v = slotView(r);
    const m = r.match_id ? db.prepare('SELECT id,dt,loc,cap,min_cnt,price FROM open_matches WHERE id=?').get(r.match_id) : null;
    const joined = r.match_id ? db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(r.match_id).n : 0;
    return { ...v, match: m ? { ...m, joined } : null };
  }));
});

/* 잡은 코트에 오픈매치를 연결 — 이미 만든 매치를 이 코트에 붙인다 */
app.post('/venue-slots/:id/link-match', auth, mgrGuard, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status !== 'held' || s.held_by !== req.uid)
    return res.status(400).json({ error: 'not_holder', message: '내가 잡은 코트가 아니에요' });
  const mid = +((req.body && req.body.match_id) || 0);
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'no_match' });
  if (m.host_id !== req.uid) return res.status(403).json({ error: 'host_only', message: '내가 만든 매치만 연결할 수 있어요' });
  const dup = db.prepare('SELECT id FROM venue_slots WHERE match_id=? AND id!=?').get(mid, s.id);
  if (dup) return res.status(409).json({ error: 'linked', message: '이 매치는 다른 코트에 연결돼 있어요' });
  db.prepare('UPDATE venue_slots SET match_id=? WHERE id=?').run(mid, s.id);
  // 이미 정원을 채운 매치라면 바로 확정
  const cnt = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n;
  if (cnt >= (m.min_cnt || m.cap || 0)) venueConfirm(s.id, mid);
  res.json({ ok: true, joined: cnt, need: m.min_cnt || m.cap || 0 });
});

/* 잡은 코트에서 오픈매치를 바로 만든다 — 앱을 오가지 않아도 되는 길.
   날짜·시간·장소·코트비를 슬롯에서 그대로 가져오므로 매니저가 옮겨 적을 일이 없다.
   요금 계산은 /open-matches 와 같은 omQuote 를 쓴다 (두 곳이 어긋나면 안 된다). */
app.post('/venue-slots/:id/create-match', auth, mgrGuard, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status !== 'held' || s.held_by !== req.uid)
    return res.status(400).json({ error: 'not_holder', message: '내가 잡은 코트가 아니에요' });
  if (s.match_id) return res.status(409).json({ error: 'linked', message: '이미 매치가 연결돼 있어요' });

  const v = db.prepare('SELECT * FROM venues WHERE id=?').get(s.venue_id) || {};
  const ids = jparse(s.court_ids, []);
  const hours = Math.round((Number(s.end.slice(0, 2)) * 60 + Number(s.end.slice(3, 5))
                          - Number(s.start.slice(0, 2)) * 60 - Number(s.start.slice(3, 5))) / 60);
  if (hours !== 2 && hours !== 3)
    return res.status(400).json({ error: 'bad_hours', message: '소셜 매치는 2시간 또는 3시간만 열려요' });
  const held = db.prepare("SELECT COUNT(*) n FROM venue_slots WHERE held_by=? AND status='held' AND date=? AND start=? AND venue_id=?")
    .get(req.uid, s.date, s.start, s.venue_id).n;
  if (held < 2) return res.status(400).json({ error: 'too_few',
    message: '오픈매치는 2면부터 열 수 있어요' });
  const courts = held <= 2 ? 2 : 3;                 // 요금표는 2코트·3코트 두 가지
  const ball = Math.max(0, +((req.body && req.body.ball_cost) || 0));
  const q = omQuote(s.price, ball, courts, hours);

  const b = req.body || {};
  const dt = `${s.date} ${s.start}`;
  const loc = v.name || '';
  const startAt = `${s.date}T${s.start}`;
  const endAt = `${s.date}T${s.end}`;

  const r = db.prepare(`INSERT INTO open_matches
    (sport,dt,loc,fmt,gd,price,cap,min_cnt,created_at,host_id,status,note,start_at,end_at,
     sido,sigungu,dong,account,courts,court_cost,tags,manager_id,manager_fee)
    VALUES (?,?,?,?,?,?,?,?,?,?, 'open', ?,?,?,?,?,?,NULL,?,?,?,?,?)`)
    .run('tennis', dt, loc, String(b.fmt || '복식').slice(0, 10), String(b.gd || '남녀부').slice(0, 10),
         q.per, q.cap, q.cap, now(), req.uid, String(b.note || '').slice(0, 300),
         startAt, endAt, v.sido || null, v.sigungu || null, null,
         courts, s.price + ball, JSON.stringify([]), req.uid, s.price + ball + q.mgr);

  const mid = rid(r);
  db.prepare('UPDATE venue_slots SET match_id=? WHERE id=?').run(mid, s.id);
  res.json({ ok: true, match_id: mid, price: q.per, cap: q.cap, hours, courts,
             mgr_fee: q.mgr, payout: s.price + ball + q.mgr });
});

/* 만들기 전 미리보기 — 매니저가 "얼마 받고 몇 명 모으는지" 먼저 본다 */
app.get('/venue-slots/:id/quote', auth, mgrGuard, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  const ids = jparse(s.court_ids, []);
  const hours = Math.round((Number(s.end.slice(0, 2)) * 60 + Number(s.end.slice(3, 5))
                          - Number(s.start.slice(0, 2)) * 60 - Number(s.start.slice(3, 5))) / 60);
  if (hours !== 2 && hours !== 3)
    return res.json({ ok: false, message: '소셜 매치는 2시간 또는 3시간만 열 수 있어요' });
  const courts = ids.length <= 2 ? 2 : 3;
  const ball = Math.max(0, +(req.query.ball || 0));
  const q = omQuote(s.price, ball, courts, hours);
  res.json({ ok: true, hours, courts, cap: q.cap, price: q.per,
             mgr_fee: q.mgr, payout: s.price + ball + q.mgr, court_cost: s.price });
});

/* ══════════════════════════════════════════════════════════════
   정원 미달 매치 자동 파기

   매니저가 코트를 잡아두고 사람을 못 채우면, 그대로 두면 세 사람이 모두 손해다.
   · 참가자 — 경기 당일에야 취소를 알고 다른 일정을 못 잡는다
   · 사장님 — 팔 수 있었던 시간을 통째로 날린다
   · 맞수 — 인원 미달인 채로 경기를 강행하면 만족도가 떨어진다

   그래서 경기 AUTO_KILL_H 시간 전에 정원이 안 차면 자동으로 접는다.
   참가비는 전액 캐시로 돌려주고, 코트는 사장님께 판매 대기로 반환한다.
   ══════════════════════════════════════════════════════════════ */
const AUTO_KILL_H = +(process.env.OM_AUTO_KILL_H || 24);      // 0이면 자동 파기를 끈다
const AUTO_WARN_H = +(process.env.OM_AUTO_WARN_H || 48);      // 미리 알려주는 시점

function omStartMs(m) {
  if (m.start_at) { const t = Date.parse(m.start_at); if (!isNaN(t)) return t; }
  if (m.dt) { const t = Date.parse(String(m.dt).replace(' ', 'T')); if (!isNaN(t)) return t; }
  return 0;
}

/* 한 매치를 접고 전원에게 캐시로 환불한다 */
function killMatch(m, why) {
  const joins = db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(m.id);
  const refunded = [];
  tx(() => {
    joins.forEach(j => {
      const paid = omPaidBy(m.id, j.user_id);               // 실제로 낸 돈만 돌려준다
      if (paid > 0) {
        const u = getUser(j.user_id);
        if (u) {
          const bal = (u.cash || 0) + paid;
          db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
          db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
            .run(u.id, paid, 'match_auto_cancel_refund', bal, now());
        }
        db.prepare("UPDATE om_payments SET status='refunded' WHERE match_id=? AND user_id=? AND status='paid'")
          .run(m.id, j.user_id);
      }
      refunded.push({ user_id: j.user_id, amount: paid });
    });
    db.prepare('DELETE FROM open_match_joins WHERE match_id=?').run(m.id);
    db.prepare("UPDATE open_matches SET status='cancelled' WHERE id=?").run(m.id);
  });
  releaseSlotOfMatch(m.id);                                  // 코트를 사장님께 돌려준다

  refunded.forEach(r => sendPush(r.user_id, { icon: '😢', title: '경기가 취소됐어요',
    body: `${m.dt || ''} · 인원이 모이지 않았어요${r.amount > 0 ? ` · ${r.amount.toLocaleString()}원 캐시 환불` : ''}` }));
  if (m.host_id) sendPush(m.host_id, { icon: '⚠️', title: '매치가 자동 취소됐어요',
    body: `${m.dt || ''} · 정원 미달로 접었어요 · 참가자 ${refunded.length}명 환불` });
  console.log(`[auto-kill] match ${m.id} (${why}) refunded ${refunded.length}`);
  return refunded.length;
}

/* 매시간 훑는다 — 경고 한 번, 파기 한 번 */
function sweepUnderfilled() {
  if (!AUTO_KILL_H) return;
  const nowMs = Date.now();
  const rows = db.prepare(`SELECT * FROM open_matches
    WHERE (status IS NULL OR status='open') AND (start_at IS NOT NULL OR dt IS NOT NULL)`).all();
  rows.forEach(m => {
    const startMs = omStartMs(m);
    if (!startMs || startMs <= nowMs) return;
    const need = m.min_cnt || m.cap || 0;
    if (!need) return;
    const have = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(m.id).n;
    if (have >= need) return;                                 // 다 찼으면 볼 일 없다
    const hoursLeft = (startMs - nowMs) / 3600000;

    if (hoursLeft <= AUTO_KILL_H) { killMatch(m, `${have}/${need}`); return; }

    // 파기 전 경고 — 매니저가 마지막으로 채울 기회를 준다
    if (hoursLeft <= AUTO_WARN_H && !m.warned_at) {
      db.prepare('UPDATE open_matches SET warned_at=? WHERE id=?').run(now(), m.id);
      if (m.host_id) sendPush(m.host_id, { icon: '⏰', title: '인원이 부족해요',
        body: `${m.dt || ''} · ${have}/${need}명 · ${AUTO_KILL_H}시간 전까지 못 채우면 자동 취소돼요` });
    }
  });
}
try { db.exec('ALTER TABLE open_matches ADD COLUMN warned_at INTEGER'); } catch (e) { /* 이미 있음 */ }
setInterval(sweepUnderfilled, 30 * 60 * 1000);               // 30분마다
setTimeout(sweepUnderfilled, 20 * 1000);                     // 뜨자마자 한 번

/* 관리자 수동 실행·확인 */
app.get('/admin/underfilled', admin, (_req, res) => {
  const nowMs = Date.now();
  const rows = db.prepare(`SELECT * FROM open_matches
    WHERE (status IS NULL OR status='open')`).all();
  const out = [];
  rows.forEach(m => {
    const startMs = omStartMs(m);
    if (!startMs || startMs <= nowMs) return;
    const need = m.min_cnt || m.cap || 0; if (!need) return;
    const have = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(m.id).n;
    if (have >= need) return;
    const h = db.prepare('SELECT name FROM users WHERE id=?').get(m.host_id) || {};
    out.push({ id: m.id, dt: m.dt, loc: m.loc, have, need, host: h.name || '',
               hours_left: Math.round((startMs - nowMs) / 36e5), warned: !!m.warned_at,
               kill_at_h: AUTO_KILL_H });
  });
  res.json({ kill_h: AUTO_KILL_H, warn_h: AUTO_WARN_H, list: out.sort((a, b) => a.hours_left - b.hours_left) });
});

app.post('/admin/open-matches/:id/kill', admin, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.status === 'cancelled') return res.status(400).json({ error: 'already' });
  const n = killMatch(m, 'admin');
  res.json({ ok: true, refunded: n });
});

/* ══════════════════════════════════════════════════════════════
   파트너 매니저 — 자격·유지·우선 선점

   의무만 세우면 이탈이 오히려 는다. 미달 → 강등 → 포기로 이어지기 때문이다.
   그래서 (1) 판정을 3개월 누적으로 완충하고, (2) 미리 경고하고,
   (3) 돈이 아닌 혜택(인기 시간 우선 선점)을 얹는다.
   ══════════════════════════════════════════════════════════════ */
function ymOf(ms) { return new Date(ms).toISOString().slice(0, 7); }

/* 확정까지 간 매치만 실적으로 센다 — 열기만 하고 못 채운 건 실적이 아니다 */
function mgrMatchCount(uid, months) {
  const from = new Date(); from.setMonth(from.getMonth() - (months - 1)); from.setDate(1);
  const fromStr = from.toISOString().slice(0, 10);
  return db.prepare(`SELECT COUNT(DISTINCT m.id) n FROM open_matches m
    WHERE m.manager_id=? AND m.status!='cancelled'
      AND COALESCE(substr(m.start_at,1,10), substr(m.dt,1,10)) >= ?
      AND EXISTS (SELECT 1 FROM venue_slots s WHERE s.match_id=m.id AND s.status='booked')`)
    .get(uid, fromStr).n;
}
function mgrTierState(u) {
  const need = PARTNER_QUOTA_M * PARTNER_WINDOW_M;
  const done = mgrMatchCount(u.id, PARTNER_WINDOW_M);
  const thisMonth = mgrMatchCount(u.id, 1);
  return { tier: u.manager_tier || 'normal', quota: PARTNER_QUOTA_M,
           window_m: PARTNER_WINDOW_M, need, done, this_month: thisMonth,
           left: Math.max(0, need - done), ok: done >= need,
           bonus_rate: PARTNER_BONUS_RATE, lead_days: PARTNER_LEAD_D };
}

/* 매니저가 이 슬롯을 지금 잡을 수 있는지 — 파트너는 언제든, 일반은 PARTNER_LEAD_D 이후부터 */
function canHoldNow(u, slot) {
  if (!PARTNER_LEAD_D) return true;
  if ((u.manager_tier || 'normal') === 'partner') return true;
  const startMs = new Date(`${slot.date}T${slot.start}:00`).getTime();
  return startMs - Date.now() <= PARTNER_LEAD_D * 86400000;
}

app.get('/manager/tier', auth, mgrGuard, (req, res) => {
  res.json(mgrTierState(req.mgr));
});

/* 매달 1일에 판정 — 3개월 누적이 모자라면 강등, 그 전에 경고 */
function sweepPartnerTier() {
  const need = PARTNER_QUOTA_M * PARTNER_WINDOW_M;
  db.prepare("SELECT * FROM users WHERE provider='manager' AND manager_tier='partner'").all()
    .forEach(u => {
      const done = mgrMatchCount(u.id, PARTNER_WINDOW_M);
      if (done >= need) {
        if (u.tier_warned_at) db.prepare('UPDATE users SET tier_warned_at=NULL WHERE id=?').run(u.id);
        return;
      }
      const day = new Date().getDate();
      if (day >= 1 && day <= 3) {                       // 달이 바뀌면 강등 판정
        db.prepare("UPDATE users SET manager_tier='normal', tier_warned_at=NULL WHERE id=?").run(u.id);
        sendPush(u.id, { icon: '📉', title: '파트너 자격이 해제됐어요',
          body: `최근 ${PARTNER_WINDOW_M}개월 ${done}/${need}회 · 다시 채우면 바로 복구돼요` });
        return;
      }
      if (!u.tier_warned_at || ymOf(u.tier_warned_at) !== ymOf(Date.now())) {
        db.prepare('UPDATE users SET tier_warned_at=? WHERE id=?').run(now(), u.id);
        sendPush(u.id, { icon: '⚠️', title: '파트너 자격이 위험해요',
          body: `최근 ${PARTNER_WINDOW_M}개월 ${done}/${need}회 · ${need - done}회 더 필요해요` });
      }
    });
}
setInterval(sweepPartnerTier, 12 * 60 * 60 * 1000);
setTimeout(sweepPartnerTier, 40 * 1000);

/* ── 관리자 ── */
app.get('/admin/managers', admin, (_req, res) => {
  const rows = db.prepare("SELECT * FROM users WHERE provider='manager' ORDER BY id DESC").all();
  res.json({ quota: PARTNER_QUOTA_M, window_m: PARTNER_WINDOW_M,
    bonus_rate: PARTNER_BONUS_RATE, lead_days: PARTNER_LEAD_D,
    list: rows.map(u => ({ id: u.id, name: u.name, login_id: u.provider_id,
      phone: u.phone || '', suspended: !!u.suspended,
      partner_since: u.partner_since || null, ...mgrTierState(u) })) });
});

app.post('/admin/managers/:id/tier', admin, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=? AND provider='manager'").get(+req.params.id);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const t = (req.body && req.body.tier) === 'partner' ? 'partner' : 'normal';
  db.prepare('UPDATE users SET manager_tier=?, partner_since=?, tier_warned_at=NULL WHERE id=?')
    .run(t, t === 'partner' ? (u.partner_since || now()) : null, u.id);
  sendPush(u.id, t === 'partner'
    ? { icon: '🏅', title: '파트너 매니저가 되셨어요',
        body: `이제 맞수 몫의 ${Math.round(PARTNER_BONUS_RATE*100)}%를 보너스로 받고, 인기 시간을 먼저 잡을 수 있어요` }
    : { icon: '📉', title: '파트너 자격이 해제됐어요', body: '다시 채우면 복구돼요' });
  res.json({ ok: true, tier: t });
});

/* 매니저 정산 — 내 수고비·실비 환급 내역 */
app.get('/manager/payouts', auth, mgrGuard, (req, res) => {
  const rows = db.prepare(`SELECT p.*, m.dt, m.loc FROM om_payouts p
    LEFT JOIN open_matches m ON m.id=p.match_id
    WHERE p.user_id=? ORDER BY p.id DESC LIMIT 60`).all(req.uid);
  const sum = f => rows.filter(f).reduce((a, r) => a + (r.amount || 0), 0);
  res.json({ pending: sum(r => r.status !== 'paid'), paid: sum(r => r.status === 'paid'), list: rows });
});

/* ── 맞수 관리자 : 계정 발급 ─────────────────────── */
/* 매니저 계정 발급 */
app.post('/admin/manager-accounts', admin, (req, res) => {
  const b = req.body || {};
  const loginId = String(b.login_id || '').trim().toLowerCase().slice(0, 40);
  const pw = String(b.password || '');
  const name = cleanName(b.name, '').slice(0, 20);
  if (!/^[a-z0-9._-]{4,}$/.test(loginId))
    return res.status(400).json({ error: 'bad_id', message: '아이디는 영문·숫자 4자 이상이어야 해요' });
  if (pw.length < 6) return res.status(400).json({ error: 'weak', message: '비밀번호는 6자 이상' });
  if (db.prepare("SELECT 1 FROM users WHERE provider='manager' AND provider_id=?").get(loginId))
    return res.status(409).json({ error: 'dup', message: '이미 있는 아이디예요' });
  const salt = crypto.randomBytes(16).toString('hex');
  const r = db.prepare(`INSERT INTO users (provider,provider_id,name,phone,pw_salt,pw_hash,created_at)
                        VALUES ('manager',?,?,?,?,?,?)`)
    .run(loginId, name || loginId, String(b.phone || '').slice(0, 20), salt, pwHash(pw, salt), now());
  res.json({ ok: true, user_id: rid(r), login_id: loginId });
});

/* 발급한 계정 목록 — 사장님·매니저 한 번에 */
app.get('/admin/staff-accounts', admin, (req, res) => {
  const rows = db.prepare(`SELECT id, provider, provider_id, name, phone, suspended, created_at
    FROM users WHERE provider IN ('venue','manager') ORDER BY provider, id DESC`).all();
  res.json(rows.map(u => ({
    ...u, suspended: !!u.suspended,
    venue: u.provider === 'venue'
      ? db.prepare('SELECT id,name FROM venues WHERE owner_id=?').get(u.id) || null : null,
    held: u.provider === 'manager'
      ? db.prepare("SELECT COUNT(*) n FROM venue_slots WHERE held_by=? AND status IN ('held','booked')").get(u.id).n : 0,
  })));
});

/* 비밀번호 초기화 — 사장님·매니저 공통 */
app.post('/admin/staff-accounts/:id/password', admin, (req, res) => {
  const pw = String((req.body && req.body.password) || '');
  if (pw.length < 6) return res.status(400).json({ error: 'weak', message: '비밀번호는 6자 이상' });
  const u = db.prepare("SELECT * FROM users WHERE id=? AND provider IN ('venue','manager')").get(+req.params.id);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET pw_salt=?, pw_hash=?, token_version=COALESCE(token_version,0)+1 WHERE id=?')
    .run(salt, pwHash(pw, salt), u.id);
  res.json({ ok: true });
});

/* 계정 정지 · 해제 */
app.post('/admin/staff-accounts/:id/suspend', admin, (req, res) => {
  const on = !!(req.body && req.body.suspended);
  const u = db.prepare("SELECT * FROM users WHERE id=? AND provider IN ('venue','manager')").get(+req.params.id);
  if (!u) return res.status(404).json({ error: 'not_found' });
  db.prepare('UPDATE users SET suspended=?, token_version=COALESCE(token_version,0)+1 WHERE id=?')
    .run(on ? 1 : 0, u.id);                    // 정지하면 열린 세션도 끊는다
  res.json({ ok: true, suspended: on });
});

/* ── 맞수 관리자 : 구장·코트 등록 ───────────────── */
app.get('/admin/venues', admin, (_req, res) => {
  const list = db.prepare('SELECT * FROM venues ORDER BY id DESC').all().map(v => ({
    ...v, photos: jparse(v.photos, []),
    courts: db.prepare('SELECT * FROM venue_courts WHERE venue_id=? ORDER BY no').all(v.id)
             .map(c => ({ ...c, name: courtName(c), photos: jparse(c.photos, []) })),
    open_slots: db.prepare("SELECT COUNT(*) n FROM venue_slots WHERE venue_id=? AND status='open'").get(v.id).n,
  }));
  res.json(list);
});
app.post('/admin/venues', admin, (req, res) => {
  const b = req.body || {};
  const name = cleanName(b.name, '').slice(0, 40);
  if (!name) return res.status(400).json({ error: 'name_required' });
  let ownerId = intOrNull(b.owner_id);
  if (!ownerId && b.owner_phone) {                       // 전화번호로 사장님 계정 찾기
    const u = db.prepare('SELECT id FROM users WHERE phone=?').get(String(b.owner_phone).replace(/\D/g, ''));
    ownerId = u ? u.id : null;
  }
  const r = db.prepare(`INSERT INTO venues (name,owner_id,sido,sigungu,addr,phone,memo,photos,bank,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(name, ownerId, b.sido || '', b.sigungu || '', b.addr || '', b.phone || '', b.memo || '',
         JSON.stringify(Array.isArray(b.photos) ? b.photos.slice(0, 8) : []), b.bank || '', now());
  res.json({ ok: true, id: rid(r) });
});
app.patch('/admin/venues/:id', admin, (req, res) => {
  const v = db.prepare('SELECT * FROM venues WHERE id=?').get(+req.params.id);
  if (!v) return res.status(404).json({ error: 'not_found' });
  const b = req.body || {};
  const f = [], a = [];
  ['name', 'sido', 'sigungu', 'addr', 'phone', 'memo', 'bank'].forEach(k => {
    if (b[k] != null) { f.push(`${k}=?`); a.push(String(b[k])); }
  });
  if (b.owner_id != null) { f.push('owner_id=?'); a.push(intOrNull(b.owner_id)); }
  if (b.active != null) { f.push('active=?'); a.push(b.active ? 1 : 0); }
  if (Array.isArray(b.photos)) { f.push('photos=?'); a.push(JSON.stringify(b.photos.slice(0, 8))); }
  if (!f.length) return res.json({ ok: true });
  a.push(v.id);
  db.prepare(`UPDATE venues SET ${f.join(',')} WHERE id=?`).run(...a);
  res.json({ ok: true });
});
app.post('/admin/venues/:id/courts', admin, (req, res) => {
  const v = db.prepare('SELECT id FROM venues WHERE id=?').get(+req.params.id);
  if (!v) return res.status(404).json({ error: 'not_found' });
  const b = req.body || {};
  const no = Math.max(1, +b.no || 0);
  if (!no) return res.status(400).json({ error: 'no_required' });
  const dup = db.prepare('SELECT 1 FROM venue_courts WHERE venue_id=? AND no=?').get(v.id, no);
  if (dup) return res.status(409).json({ error: 'dup_no', message: '같은 번호의 코트가 있어요' });
  const r = db.prepare(`INSERT INTO venue_courts (venue_id,no,label,indoor,surface,price_hour,photos,created_at)
                        VALUES (?,?,?,?,?,?,?,?)`)
    .run(v.id, no, String(b.label || '').slice(0, 20), b.indoor ? 1 : 0, String(b.surface || '하드'),
         Math.max(0, +b.price_hour || 0), JSON.stringify(Array.isArray(b.photos) ? b.photos.slice(0, 5) : []), now());
  res.json({ ok: true, id: rid(r) });
});
app.patch('/admin/courts/:id', admin, (req, res) => {
  const c = db.prepare('SELECT * FROM venue_courts WHERE id=?').get(+req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const b = req.body || {}, f = [], a = [];
  if (b.label != null) { f.push('label=?'); a.push(String(b.label).slice(0, 20)); }
  if (b.surface != null) { f.push('surface=?'); a.push(String(b.surface)); }
  if (b.indoor != null) { f.push('indoor=?'); a.push(b.indoor ? 1 : 0); }
  if (b.price_hour != null) { f.push('price_hour=?'); a.push(Math.max(0, +b.price_hour || 0)); }
  if (b.status != null) { f.push('status=?'); a.push(b.status === 'paused' ? 'paused' : 'active'); }
  if (Array.isArray(b.photos)) { f.push('photos=?'); a.push(JSON.stringify(b.photos.slice(0, 5))); }
  if (!f.length) return res.json({ ok: true });
  a.push(c.id);
  db.prepare(`UPDATE venue_courts SET ${f.join(',')} WHERE id=?`).run(...a);
  res.json({ ok: true });
});
app.delete('/admin/courts/:id', admin, (req, res) => {
  const c = db.prepare('SELECT * FROM venue_courts WHERE id=?').get(+req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const used = db.prepare(`SELECT COUNT(*) n FROM venue_slots
    WHERE venue_id=? AND status IN ('held','booked')`).get(c.venue_id).n;
  if (used) return res.status(400).json({ error: 'in_use', message: '진행 중인 예약이 있어 지울 수 없어요' });
  db.prepare('DELETE FROM venue_courts WHERE id=?').run(c.id);
  res.json({ ok: true });
});
/* 구장 사진 — 관리자 키로 인증한다 (사장님 계정과 무관).
   기존 venues.photos(JSON 배열)를 그대로 쓴다. 첫 장이 대표 사진이다. */
app.post('/admin/venues/:id/photo', admin, (req, res) => {
  const v = db.prepare('SELECT id, photos FROM venues WHERE id=?').get(+req.params.id);
  if (!v) return res.status(404).json({ error: 'not_found' });
  const list = jparse(v.photos, []);
  const m = /^data:(image\/(png|jpe?g|webp));base64,(.+)$/.exec((req.body && req.body.dataUrl) || '');
  if (!m) return res.status(400).json({ error: 'bad_image', message: 'PNG·JPG·WEBP만 올릴 수 있어요' });
  const buf = Buffer.from(m[3], 'base64');
  if (buf.length > 3 * 1024 * 1024)
    return res.status(413).json({ error: 'too_large', message: '3MB 이하로 줄여주세요' });
  if (list.length >= 6) return res.status(400).json({ error: 'too_many', message: '사진은 6장까지예요' });
  const name = 'venue' + v.id + '_' + Date.now() + '.' + (m[2] === 'jpeg' ? 'jpg' : m[2]);
  fs.writeFileSync(UPLOAD_DIR + '/' + name, buf);
  list.push('/uploads/' + name);
  db.prepare('UPDATE venues SET photos=? WHERE id=?').run(JSON.stringify(list), v.id);
  res.json({ ok: true, photos: list });
});

/* 사진 삭제 · 대표 지정 */
app.delete('/admin/venues/:id/photo', admin, (req, res) => {
  const v = db.prepare('SELECT id, photos FROM venues WHERE id=?').get(+req.params.id);
  if (!v) return res.status(404).json({ error: 'not_found' });
  const list = jparse(v.photos, []);
  const i = Number(req.query.i);
  if (!(i >= 0 && i < list.length)) return res.status(400).json({ error: 'bad_index' });
  list.splice(i, 1);
  db.prepare('UPDATE venues SET photos=? WHERE id=?').run(JSON.stringify(list), v.id);
  res.json({ ok: true, photos: list });
});

app.post('/admin/venues/:id/photo/cover', admin, (req, res) => {
  const v = db.prepare('SELECT id, photos FROM venues WHERE id=?').get(+req.params.id);
  if (!v) return res.status(404).json({ error: 'not_found' });
  const list = jparse(v.photos, []);
  const i = Number((req.body && req.body.i));
  if (!(i > 0 && i < list.length)) return res.status(400).json({ error: 'bad_index' });
  list.unshift(list.splice(i, 1)[0]);                 // 앞으로 끌어올리면 대표가 된다
  db.prepare('UPDATE venues SET photos=? WHERE id=?').run(JSON.stringify(list), v.id);
  res.json({ ok: true, photos: list });
});

/* 코트 수정 · 삭제 — 재계약으로 단가가 바뀔 때 */
app.patch('/admin/venues/:vid/courts/:cid', admin, (req, res) => {
  const c = db.prepare('SELECT * FROM venue_courts WHERE id=? AND venue_id=?')
    .get(+req.params.cid, +req.params.vid);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const b = req.body || {};
  const set = [], val = [];
  if (b.label !== undefined)      { set.push('label=?');      val.push(String(b.label).slice(0, 20)); }
  if (b.surface !== undefined)    { set.push('surface=?');    val.push(String(b.surface).slice(0, 10)); }
  if (b.indoor !== undefined)     { set.push('indoor=?');     val.push(b.indoor ? 1 : 0); }
  if (b.price_hour !== undefined) { set.push('price_hour=?'); val.push(Math.max(0, +b.price_hour || 0)); }
  if (b.status !== undefined)     { set.push('status=?');     val.push(b.status === 'paused' ? 'paused' : 'active'); }
  if (!set.length) return res.status(400).json({ error: 'nothing' });
  db.prepare(`UPDATE venue_courts SET ${set.join(',')} WHERE id=?`).run(...val, c.id);
  res.json({ ok: true });
});

app.delete('/admin/venues/:vid/courts/:cid', admin, (req, res) => {
  const cid = +req.params.cid;
  const c = db.prepare('SELECT * FROM venue_courts WHERE id=? AND venue_id=?').get(cid, +req.params.vid);
  if (!c) return res.status(404).json({ error: 'not_found' });
  // 이 코트가 들어간 살아있는 슬롯이 있으면 막는다 (지우면 매치가 갈 곳을 잃는다)
  const used = db.prepare("SELECT court_ids FROM venue_slots WHERE venue_id=? AND status IN ('open','held','booked')")
    .all(c.venue_id).some(r => jparse(r.court_ids, []).includes(cid));
  if (used) return res.status(409).json({ error: 'in_use',
    message: '열려 있는 시간에 쓰이는 코트예요. 삭제 대신 "쉼"으로 바꿔 주세요' });
  db.prepare('DELETE FROM venue_courts WHERE id=?').run(cid);
  res.json({ ok: true });
});

/* 구장별로 묶은 정산 — 월요일에 이 화면만 보고 이체하면 된다 */
app.get('/admin/venue-payouts/by-venue', admin, (_req, res) => {
  const rows = db.prepare(`SELECT p.id, p.venue_id, p.amount, p.status, p.due_at, p.paid_at,
      s.date, s.start, s.end FROM venue_payouts p LEFT JOIN venue_slots s ON s.id=p.slot_id
    WHERE p.status='pending' ORDER BY p.venue_id, s.date`).all();
  const byId = new Map();
  rows.forEach(r => {
    if (!byId.has(r.venue_id)) {
      const v = db.prepare(`SELECT id,name,bank_name,bank_no,bank_holder,biz_no,bank
        FROM venues WHERE id=?`).get(r.venue_id) || { id: r.venue_id, name: '(삭제된 구장)' };
      byId.set(r.venue_id, { venue: v, total: 0, ids: [], list: [] });
    }
    const g = byId.get(r.venue_id);
    g.total += r.amount; g.ids.push(r.id); g.list.push(r);
  });
  const groups = [...byId.values()].sort((a, b) => b.total - a.total);
  res.json({ total: groups.reduce((a, g) => a + g.total, 0), groups });
});

/* 구장 한 곳을 한 번에 입금 완료 처리 */
app.post('/admin/venue-payouts/pay-venue/:vid', admin, (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids.map(Number).filter(Boolean) : null;
  let r;
  if (ids && ids.length) {
    r = db.prepare(`UPDATE venue_payouts SET status='paid', paid_at=?
      WHERE venue_id=? AND status='pending' AND id IN (${ids.map(() => '?').join(',')})`)
      .run(now(), +req.params.vid, ...ids);
  } else {
    r = db.prepare("UPDATE venue_payouts SET status='paid', paid_at=? WHERE venue_id=? AND status='pending'")
      .run(now(), +req.params.vid);
  }
  const v = db.prepare('SELECT owner_id FROM venues WHERE id=?').get(+req.params.vid);
  if (v && v.owner_id && r.changes) sendPush(v.owner_id, { icon: '💰', title: '코트 대금을 보냈어요',
    body: `${r.changes}건 입금 완료 · 통장을 확인해 주세요` });
  res.json({ ok: true, updated: r.changes });
});

/* 회원 코트 예약 관리 — 취소 요청·분쟁이 오면 여기서 처리한다 */
app.get('/admin/venue-bookings', admin, (req, res) => {
  const st = String(req.query.status || '').trim();
  const w = []; const a = [];
  if (st) { w.push('b.status=?'); a.push(st); }
  const rows = db.prepare(`SELECT b.*, s.date, s.start, s.end, s.court_ids, s.status slot_status,
      v.name venue_name, u.name user_name, u.phone user_phone
    FROM venue_bookings b JOIN venue_slots s ON s.id=b.slot_id
    LEFT JOIN venues v ON v.id=b.venue_id LEFT JOIN users u ON u.id=b.user_id
    ${w.length ? 'WHERE ' + w.join(' AND ') : ''}
    ORDER BY s.date DESC, s.start DESC LIMIT 100`).all(...a);
  const sum = f => rows.filter(f).reduce((x, r) => x + (r.amount || 0), 0);
  res.json({ paid: sum(r => r.status === 'paid'), canceled: sum(r => r.status === 'canceled'),
    list: rows.map(r => ({ ...r, court_ids: jparse(r.court_ids, []) })) });
});

/* 관리자 강제 취소 — 시간 제한 없이 전액 캐시로 돌려준다 */
app.post('/admin/venue-bookings/:id/cancel', admin, (req, res) => {
  const b = db.prepare('SELECT * FROM venue_bookings WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (b.status !== 'paid') return res.status(400).json({ error: 'already', message: '이미 취소된 예약이에요' });
  const u = getUser(b.user_id);
  tx(() => {
    db.prepare("UPDATE venue_bookings SET status='canceled', canceled_at=? WHERE id=?").run(now(), b.id);
    db.prepare("DELETE FROM venue_payouts WHERE slot_id=? AND status='pending'").run(b.slot_id);
    db.prepare("UPDATE venue_slots SET status='open' WHERE id=? AND status='booked'").run(b.slot_id);
    if (u) {
      const bal = (u.cash || 0) + b.amount;
      db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(u.id, b.amount, 'venue_reserve_admin_refund', bal, now());
    }
  });
  if (u) sendPush(u.id, { icon: '↩️', title: '코트 예약이 취소됐어요',
    body: `${b.amount.toLocaleString()}원을 캐시로 돌려드렸어요` });
  res.json({ ok: true, refunded: b.amount });
});

/* 전체 열린 시간 모니터링 — 오래 잡아만 둔 건을 찾는다 */
app.get('/admin/venue-slots', admin, (req, res) => {
  const st = String(req.query.status || '').trim();
  const w = ['s.date>=?']; const a = [new Date().toISOString().slice(0, 10)];
  if (st) { w.push('s.status=?'); a.push(st); }
  const rows = db.prepare(`SELECT s.*, v.name venue, u.name holder FROM venue_slots s
    LEFT JOIN venues v ON v.id=s.venue_id LEFT JOIN users u ON u.id=s.held_by
    WHERE ${w.join(' AND ')} ORDER BY s.date, s.start LIMIT 120`).all(...a);
  res.json(rows.map(r => {
    const joined = r.match_id ? db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(r.match_id).n : 0;
    const m = r.match_id ? db.prepare('SELECT cap,min_cnt FROM open_matches WHERE id=?').get(r.match_id) : null;
    return { ...r, court_ids: jparse(r.court_ids, []), joined, need: m ? (m.min_cnt || m.cap || 0) : 0,
             held_hours: r.held_at ? Math.floor((Date.now() - r.held_at) / 36e5) : 0 };
  }));
});

/* 관리자 강제 해제 — 사장님이 못 닫는 held·booked 건을 푼다 */
app.post('/admin/venue-slots/:id/release', admin, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });

  /* 개인 예약이 걸린 슬롯이면 예약도 함께 취소하고 캐시를 돌려준다.
     이 처리가 없으면 회원은 돈을 낸 채 코트만 사라진다. */
  const bk = db.prepare("SELECT * FROM venue_bookings WHERE slot_id=? AND status='paid'").get(s.id);
  let refunded = 0;
  tx(() => {
    if (bk) {
      const u = getUser(bk.user_id);
      db.prepare("UPDATE venue_bookings SET status='canceled', canceled_at=? WHERE id=?").run(now(), bk.id);
      if (u) {
        const bal = (u.cash || 0) + bk.amount;
        db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, u.id);
        db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
          .run(u.id, bk.amount, 'venue_reserve_admin_refund', bal, now());
        refunded = bk.amount;
      }
    }
    db.prepare("DELETE FROM venue_payouts WHERE slot_id=? AND status='pending'").run(s.id);
    db.prepare("UPDATE venue_slots SET status='open', held_by=NULL, held_at=NULL, match_id=NULL WHERE id=?").run(s.id);
  });
  if (bk && refunded) sendPush(bk.user_id, { icon: '↩️', title: '코트 예약이 취소됐어요',
    body: `${refunded.toLocaleString()}원을 캐시로 돌려드렸어요` });
  res.json({ ok: true, refunded, had_booking: !!bk });
});

app.get('/admin/venue-payouts', admin, (_req, res) => {
  res.json(db.prepare(`SELECT p.*, v.name venue, v.bank, s.date, s.start, s.end
    FROM venue_payouts p LEFT JOIN venues v ON v.id=p.venue_id LEFT JOIN venue_slots s ON s.id=p.slot_id
    ORDER BY p.status='paid', p.id DESC LIMIT 80`).all());
});
app.post('/admin/venue-payouts/:id/paid', admin, (req, res) => {
  const r = db.prepare("UPDATE venue_payouts SET status='paid', paid_at=? WHERE id=? AND status='pending'")
    .run(now(), +req.params.id);
  res.json({ ok: true, updated: r.changes });
});

/* ═══════════════════════════════════════════════════════════════
   1:1 랭크 (MMR) — 상대 찾기 · 경기 · 스코어 확정
   ───────────────────────────────────────────────────────────────
   설계 근거
   · 시작 MMR 은 구력 등급으로 준다. 전원 1000 에서 출발하면 초반 매칭이
     어긋나 30경기를 뛰어도 실력과 오차가 남는다.
   · K 는 32 고정, 30경기부터 24. 시작점이 좋으면 크게 흔들 이유가 없다.
   · 배치(5경기) 전에는 MMR 을 공개하지 않는다. 표본이 없는 숫자다.
   · 스코어는 '저장'과 '확정'을 나눈다. 잘못 넣으면 상대 MMR 까지 틀어진다.
   ═══════════════════════════════════════════════════════════════ */

try { db.exec('ALTER TABLE users ADD COLUMN mmr INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN mmr_games INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN duel_mixed INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN duel_open_at INTEGER'); } catch (e) {}

try {
  db.exec(`CREATE TABLE IF NOT EXISTS duels (
    id INTEGER PRIMARY KEY,
    a_id INTEGER, b_id INTEGER, sport TEXT,
    status TEXT,                 -- requested | accepted | scored | confirmed | declined | canceled
    place TEXT, at TEXT,
    sa INTEGER, sb INTEGER,
    score_by INTEGER,            -- 스코어를 마지막으로 만진 사람
    a_ok INTEGER DEFAULT 0, b_ok INTEGER DEFAULT 0,
    mmr_a INTEGER, mmr_b INTEGER, d_a INTEGER, d_b INTEGER,
    created_at INTEGER, scored_at INTEGER, confirmed_at INTEGER)`);
} catch (e) {}

const DUEL_PLACE = 5;                      // 배치 경기 수
const GRADE_MMR = { SS: 1300, S: 1200, A: 1100, B: 1000, C: 900 };

/* 등급(grade)은 users 가 아니라 club_members 에 있다.
   여러 클럽에 속해 있으면 가장 높은 등급을 쓴다 — 실력은 하나뿐이니까. */
const GRADE_ORDER = ['SS', 'S', 'A', 'B', 'C'];
function gradeOfUser(uid) {
  let rows = [];
  try { rows = db.prepare('SELECT grade FROM club_members WHERE user_id=? AND grade IS NOT NULL').all(uid); }
  catch (e) { return ''; }
  let best = '';
  rows.forEach(r => {
    const g = String(r.grade || '').replace(/[0-9]/g, '').toUpperCase();
    if (!GRADE_ORDER.includes(g)) return;
    if (!best || GRADE_ORDER.indexOf(g) < GRADE_ORDER.indexOf(best)) best = g;
  });
  return best;
}
/* 구력 등급으로 시작 MMR 을 정한다. 등급이 없으면 B(1000) */
function seedMMR(u) {
  const g = (u && u.grade) || gradeOfUser(u && u.id);
  return GRADE_MMR[g] || 1000;
}
function duelUser(uid) {
  const u = db.prepare('SELECT id,name,gender,region,mmr,mmr_games,duel_open_at FROM users WHERE id=?').get(uid);
  if (!u) return null;
  u.grade = gradeOfUser(uid);
  if (u.mmr == null) {
    u.mmr = seedMMR(u);
    try { db.prepare('UPDATE users SET mmr=? WHERE id=?').run(u.mmr, uid); } catch (e) {}
  }
  u.mmr_games = u.mmr_games || 0;
  return u;
}
function kFactor(games) { return games >= 30 ? 24 : 32; }
function expectedScore(a, b) { return 1 / (1 + Math.pow(10, (b - a) / 400)); }

/* 대기 시간이 길수록 조건을 푼다. 작은 지역에서 좁게만 걸면 상대가 영영 안 나온다. */
function duelWindow(openAt) {
  const h = openAt ? (now() - openAt) / 3600000 : 0;
  if (h < 24) return { band: 100, scope: 'city', label: '같은 시·군' };
  if (h < 72) return { band: 150, scope: 'near', label: '인접 시·군' };
  return { band: 200, scope: 'province', label: '같은 도' };
}
function cityOf(region) { return String(region || '').trim().split(/\s+/).slice(0, 2).join(' '); }
function provinceOf(region) { return String(region || '').trim().split(/\s+/)[0] || ''; }

/* ── 상대 찾기 열기 / 닫기 ── */
app.post('/duel/open', auth, (req, res) => {
  db.prepare('UPDATE users SET duel_open_at=? WHERE id=?').run(now(), req.uid);
  const u = duelUser(req.uid);
  res.json({ ok: true, mmr: u.mmr, games: u.mmr_games, placing: u.mmr_games < DUEL_PLACE });
});
app.post('/duel/close', auth, (req, res) => {
  db.prepare('UPDATE users SET duel_open_at=NULL WHERE id=?').run(req.uid);
  res.json({ ok: true });
});

/* ── 후보 목록 ── */
app.get('/duel/candidates', auth, (req, res) => {
  const me = duelUser(req.uid);
  if (!me) return res.status(404).json({ error: 'no_user' });
  const w = duelWindow(me.duel_open_at);
  const rows = db.prepare(`SELECT id,name,gender,region,mmr,mmr_games
    FROM users WHERE id<>? AND duel_open_at IS NOT NULL AND suspended IS NOT 1`).all(req.uid);
  rows.forEach(r => { r.grade = gradeOfUser(r.id); });
  const myCity = cityOf(me.region), myProv = provinceOf(me.region);
  const out = [];
  for (const r of rows) {
    if (r.mmr == null) r.mmr = seedMMR(r);
    r.mmr_games = r.mmr_games || 0;
    /* 개인리그가 남자부·여자부로 나뉘므로 1:1 도 같은 성별끼리만 붙인다 */
    if (r.gender !== me.gender) continue;
    if (Math.abs((r.mmr || 1000) - me.mmr) > w.band) continue;
    const rc = cityOf(r.region), rp = provinceOf(r.region);
    let scope = null;
    if (rc && rc === myCity) scope = 'city';
    else if (rp && rp === myProv) scope = 'near';
    if (w.scope === 'city' && scope !== 'city') continue;
    if (w.scope === 'near' && !scope) continue;
    if (w.scope === 'province' && rp !== myProv && myProv) continue;
    out.push({
      id: r.id, name: r.name, region: r.region, grade: r.grade,
      mmr: r.mmr_games >= DUEL_PLACE ? r.mmr : null,     // 배치 중이면 숨긴다
      games: r.mmr_games || 0, placing: (r.mmr_games || 0) < DUEL_PLACE,
      gap: Math.abs(r.mmr - me.mmr),
    });
  }
  out.sort((a, b) => a.gap - b.gap);
  res.json({
    me: { mmr: me.mmr_games >= DUEL_PLACE ? me.mmr : null, games: me.mmr_games,
          placing: me.mmr_games < DUEL_PLACE, place_n: DUEL_PLACE,
          open: !!me.duel_open_at },
    window: { band: w.band, label: w.label, low: me.mmr - w.band, high: me.mmr + w.band },
    list: out.slice(0, 40),
  });
});

/* ── 신청 · 수락 ── */
app.post('/duel/request', auth, (req, res) => {
  const opp = +(req.body && req.body.opponent_id || 0);
  if (!opp || opp === req.uid) return res.status(400).json({ error: 'bad_opponent' });
  const dup = db.prepare(`SELECT id FROM duels WHERE status IN ('requested','accepted','scored')
    AND ((a_id=? AND b_id=?) OR (a_id=? AND b_id=?))`).get(req.uid, opp, opp, req.uid);
  if (dup) return res.status(409).json({ error: 'already', id: dup.id });
  const r = db.prepare(`INSERT INTO duels (a_id,b_id,sport,status,created_at) VALUES (?,?,?,'requested',?)`)
    .run(req.uid, opp, String(req.body.sport || 'tennis'), now());
  res.json({ ok: true, id: r.lastInsertRowid });
});
app.post('/duel/:id/accept', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.b_id !== req.uid) return res.status(403).json({ error: 'not_yours' });
  if (d.status !== 'requested') return res.status(409).json({ error: 'bad_status' });
  db.prepare("UPDATE duels SET status='accepted' WHERE id=?").run(d.id);
  res.json({ ok: true });
});
app.post('/duel/:id/decline', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.a_id !== req.uid && d.b_id !== req.uid) return res.status(403).json({ error: 'not_yours' });
  if (d.status === 'confirmed') return res.status(409).json({ error: 'already_confirmed' });
  db.prepare("UPDATE duels SET status='declined' WHERE id=?").run(d.id);
  res.json({ ok: true });
});

/* ── 코트·일시 — 제휴 구장이 아니어도 직접 적을 수 있다 ── */
app.patch('/duel/:id/plan', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.a_id !== req.uid && d.b_id !== req.uid) return res.status(403).json({ error: 'not_yours' });
  if (d.status === 'confirmed') return res.status(409).json({ error: 'already_confirmed' });
  db.prepare('UPDATE duels SET place=?, at=? WHERE id=?')
    .run(String(req.body.place || '').slice(0, 60), String(req.body.at || '').slice(0, 20), d.id);
  res.json({ ok: true });
});

/* ── 스코어 저장 — 확정 전에는 양쪽 다 고칠 수 있다 ── */
app.patch('/duel/:id/score', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.a_id !== req.uid && d.b_id !== req.uid) return res.status(403).json({ error: 'not_yours' });
  if (d.status === 'confirmed') return res.status(409).json({ error: 'already_confirmed' });
  const sa = Math.max(0, Math.min(99, +req.body.sa | 0));
  const sb = Math.max(0, Math.min(99, +req.body.sb | 0));
  if (sa === sb) return res.status(400).json({ error: 'no_draw' });   // 1:1 은 무승부가 없다
  /* 스코어가 바뀌면 양쪽 확인을 모두 취소한다 — 예전 숫자를 보고 누른 확인이 남으면 안 된다 */
  db.prepare(`UPDATE duels SET sa=?, sb=?, score_by=?, status='scored',
    a_ok=?, b_ok=?, scored_at=? WHERE id=?`)
    .run(sa, sb, req.uid, req.uid === d.a_id ? 1 : 0, req.uid === d.b_id ? 1 : 0, now(), d.id);
  res.json({ ok: true });
});

/* ── 확정 — 양쪽이 누르면 MMR 반영 ── */
function applyDuel(d) {
  const A = duelUser(d.a_id), B = duelUser(d.b_id);
  if (!A || !B) return null;
  const ea = expectedScore(A.mmr, B.mmr);
  const sA = d.sa > d.sb ? 1 : 0;
  const dA = Math.round(kFactor(A.mmr_games) * (sA - ea));
  const dB = Math.round(kFactor(B.mmr_games) * ((1 - sA) - (1 - ea)));
  db.prepare('UPDATE users SET mmr=?, mmr_games=? WHERE id=?').run(A.mmr + dA, A.mmr_games + 1, A.id);
  db.prepare('UPDATE users SET mmr=?, mmr_games=? WHERE id=?').run(B.mmr + dB, B.mmr_games + 1, B.id);
  db.prepare(`UPDATE duels SET status='confirmed', confirmed_at=?,
    mmr_a=?, mmr_b=?, d_a=?, d_b=? WHERE id=?`)
    .run(now(), A.mmr, B.mmr, dA, dB, d.id);
  return { dA, dB, a: A.mmr + dA, b: B.mmr + dB };
}
app.post('/duel/:id/confirm', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.a_id !== req.uid && d.b_id !== req.uid) return res.status(403).json({ error: 'not_yours' });
  if (d.status === 'confirmed') return res.json({ ok: true, already: true });
  if (d.sa == null || d.sb == null) return res.status(400).json({ error: 'no_score' });
  const col = req.uid === d.a_id ? 'a_ok' : 'b_ok';
  db.prepare(`UPDATE duels SET ${col}=1 WHERE id=?`).run(d.id);
  const d2 = db.prepare('SELECT * FROM duels WHERE id=?').get(d.id);
  if (d2.a_ok && d2.b_ok) {
    const r = applyDuel(d2);
    return res.json({ ok: true, confirmed: true, result: r });
  }
  res.json({ ok: true, confirmed: false });
});

/* ── 7일이 지나면 자동 확정. 상대가 응답을 안 해 기록이 영영 안 남는 걸 막는다 ── */
function duelAutoConfirm() {
  const cut = now() - 7 * 86400000;
  const rows = db.prepare(`SELECT * FROM duels WHERE status='scored' AND scored_at IS NOT NULL AND scored_at < ?`).all(cut);
  rows.forEach(d => { try { applyDuel(d); } catch (e) {} });
  return rows.length;
}
setInterval(() => { try { duelAutoConfirm(); } catch (e) {} }, 6 * 3600000);

/* ── 내 경기 목록 ── */
app.get('/duel/mine', auth, (req, res) => {
  const rows = db.prepare(`SELECT d.*, ua.name AS a_name, ub.name AS b_name
    FROM duels d LEFT JOIN users ua ON ua.id=d.a_id LEFT JOIN users ub ON ub.id=d.b_id
    WHERE (d.a_id=? OR d.b_id=?) AND d.status<>'declined'
    ORDER BY d.id DESC LIMIT 60`).all(req.uid, req.uid);
  const me = duelUser(req.uid);
  res.json({
    me: { mmr: me.mmr_games >= DUEL_PLACE ? me.mmr : null, games: me.mmr_games,
          placing: me.mmr_games < DUEL_PLACE, place_n: DUEL_PLACE, raw_mmr: me.mmr },
    list: rows.map(d => {
      const iamA = d.a_id === req.uid;
      return {
        id: d.id, status: d.status, place: d.place, at: d.at,
        opponent: iamA ? d.b_name : d.a_name, opponent_id: iamA ? d.b_id : d.a_id,
        my_score: iamA ? d.sa : d.sb, opp_score: iamA ? d.sb : d.sa,
        my_ok: iamA ? !!d.a_ok : !!d.b_ok, opp_ok: iamA ? !!d.b_ok : !!d.a_ok,
        delta: d.status === 'confirmed' ? (iamA ? d.d_a : d.d_b) : null,
        mine: iamA,
      };
    }),
  });
});

/* ── 운영진 정정 — 확정 후에도 고칠 수 있게. MMR 변동을 되돌린 뒤 다시 계산한다 ── */
app.patch('/duel/:id/fix', admin, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d || d.status !== 'confirmed') return res.status(409).json({ error: 'not_confirmed' });
  const A = duelUser(d.a_id), B = duelUser(d.b_id);
  db.prepare('UPDATE users SET mmr=?, mmr_games=? WHERE id=?').run(A.mmr - (d.d_a || 0), Math.max(0, A.mmr_games - 1), A.id);
  db.prepare('UPDATE users SET mmr=?, mmr_games=? WHERE id=?').run(B.mmr - (d.d_b || 0), Math.max(0, B.mmr_games - 1), B.id);
  const sa = Math.max(0, Math.min(99, +req.body.sa | 0));
  const sb = Math.max(0, Math.min(99, +req.body.sb | 0));
  if (sa === sb) return res.status(400).json({ error: 'no_draw' });
  db.prepare('UPDATE duels SET sa=?, sb=? WHERE id=?').run(sa, sb, d.id);
  const r = applyDuel(db.prepare('SELECT * FROM duels WHERE id=?').get(d.id));
  res.json({ ok: true, result: r });
});

/* ═══ 1:1 랭크 — 비용 나누기 · 취소 ═══
   코트를 잡은 사람이 코트비와 캔볼값을 넣으면, 상대 몫을 캐시로 걷는다.
   토스 결제를 새로 붙이지 않고 기존 캐시를 쓴다 — 캐시는 이미 토스로 충전되고,
   출금·환불 경로가 다 뚫려 있어서 정산이 한 갈래로 유지된다. */

try { db.exec('ALTER TABLE duels ADD COLUMN court_fee INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE duels ADD COLUMN ball_fee INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE duels ADD COLUMN hours REAL'); } catch (e) {}
try { db.exec('ALTER TABLE duels ADD COLUMN payer INTEGER'); } catch (e) {}   // 코트를 잡은 사람
try { db.exec('ALTER TABLE duels ADD COLUMN settled INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE duels ADD COLUMN cancel_by INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE duels ADD COLUMN cancel_reason TEXT'); } catch (e) {}

const DUEL_CANCEL_REASONS = ['비가 와서', '코트 예약이 취소돼서', '몸이 안 좋아서',
  '일정이 안 맞아서', '상대와 연락이 안 돼서', '직접 입력'];

/* ── 비용 입력 — 코트를 잡은 사람만 ── */
app.patch('/duel/:id/cost', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.a_id !== req.uid && d.b_id !== req.uid) return res.status(403).json({ error: 'not_yours' });
  if (d.settled) return res.status(409).json({ error: 'already_settled' });
  const hours = Math.max(0, Math.min(12, +req.body.hours || 0));
  const perHour = Math.max(0, Math.min(500000, +req.body.per_hour | 0));
  const ball = Math.max(0, Math.min(200000, +req.body.ball_fee | 0));
  const court = Math.round(perHour * hours);
  db.prepare('UPDATE duels SET court_fee=?, ball_fee=?, hours=?, payer=? WHERE id=?')
    .run(court, ball, hours, req.uid, d.id);
  const total = court + ball, half = Math.round(total / 2);
  res.json({ ok: true, court_fee: court, ball_fee: ball, total, half });
});

/* ── 상대 몫 걷기 — 캐시에서 차감해 코트 잡은 사람에게 보낸다 ── */
app.post('/duel/:id/settle', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.settled) return res.json({ ok: true, already: true });
  if (!d.payer) return res.status(400).json({ error: 'no_cost', message: '먼저 코트비를 입력해 주세요' });
  const other = d.payer === d.a_id ? d.b_id : d.a_id;
  if (req.uid !== other) return res.status(403).json({ error: 'not_payer_side', message: '비용을 낼 사람만 보낼 수 있어요' });
  const total = (d.court_fee || 0) + (d.ball_fee || 0);
  const half = Math.round(total / 2);
  if (half <= 0) return res.status(400).json({ error: 'zero' });

  const me = getUser(req.uid);
  if (me.cash < half)
    return res.status(402).json({ error: 'not_enough_cash', need: half, cash: me.cash,
      message: `캐시가 ${(half - me.cash).toLocaleString()}원 모자라요` });

  const host = getUser(d.payer);
  tx(() => {
    const mb = me.cash - half, hb = host.cash + half;
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(mb, me.id);
    db.prepare('UPDATE users SET cash=? WHERE id=?').run(hb, host.id);
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
      .run(me.id, -half, 'duel_share', mb, now());
    db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
      .run(host.id, half, 'duel_share_in', hb, now());
    db.prepare('UPDATE duels SET settled=1 WHERE id=?').run(d.id);
  });
  try { sendPush(host.id, { title: '코트비 정산', body: `${me.name}님이 ${half.toLocaleString()}원을 보냈어요` }); } catch (e) {}
  res.json({ ok: true, paid: half });
});

/* ── 취소 — 사유를 남긴다. 이미 정산했으면 되돌려준다 ── */
app.get('/duel/cancel-reasons', (_req, res) => res.json(DUEL_CANCEL_REASONS));
app.post('/duel/:id/cancel', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM duels WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'no_duel' });
  if (d.a_id !== req.uid && d.b_id !== req.uid) return res.status(403).json({ error: 'not_yours' });
  if (d.status === 'confirmed') return res.status(409).json({ error: 'already_confirmed', message: '이미 확정된 경기는 취소할 수 없어요' });
  const reason = String(req.body && req.body.reason || '').trim().slice(0, 60);
  if (!reason) return res.status(400).json({ error: 'need_reason', message: '취소 사유를 알려주세요' });

  /* 정산이 끝났으면 낸 사람에게 그대로 돌려준다 */
  if (d.settled) {
    const total = (d.court_fee || 0) + (d.ball_fee || 0), half = Math.round(total / 2);
    const other = d.payer === d.a_id ? d.b_id : d.a_id;
    const host = getUser(d.payer), payer = getUser(other);
    if (host && payer && half > 0) tx(() => {
      const hb = Math.max(0, host.cash - half), pb = payer.cash + half;
      db.prepare('UPDATE users SET cash=? WHERE id=?').run(hb, host.id);
      db.prepare('UPDATE users SET cash=? WHERE id=?').run(pb, payer.id);
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(host.id, -half, 'duel_share_back', hb, now());
      db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
        .run(payer.id, half, 'duel_share_refund', pb, now());
      db.prepare('UPDATE duels SET settled=0 WHERE id=?').run(d.id);
    });
  }
  db.prepare("UPDATE duels SET status='canceled', cancel_by=?, cancel_reason=? WHERE id=?")
    .run(req.uid, reason, d.id);
  const other = d.a_id === req.uid ? d.b_id : d.a_id;
  try {
    const me = getUser(req.uid);
    sendPush(other, { title: '경기가 취소됐어요', body: `${me.name}님 · ${reason}` });
  } catch (e) {}
  res.json({ ok: true, refunded: !!d.settled });
});

/* ═══ 매니저 콘솔 — 비밀번호 변경 ═══
   매니저도 users(provider='manager')로 저장되므로 구장과 같은 방식을 쓴다.
   초기 비밀번호를 계속 쓰는 계정이 쌓이는 게 가장 위험하다. */
app.post('/manager/password', auth, (req, res) => {
  const u = getUser(req.uid);
  if (!u || u.provider !== 'manager') return res.status(403).json({ error: 'not_manager' });
  const cur = String((req.body && req.body.current) || '');
  const next = String((req.body && req.body.next) || '');
  if (next.length < 6) return res.status(400).json({ error: 'weak', message: '비밀번호는 6자 이상이어야 해요' });
  if (u.pw_hash !== pwHash(cur, u.pw_salt || ''))
    return res.status(401).json({ error: 'bad_current', message: '현재 비밀번호가 맞지 않아요' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET pw_salt=?, pw_hash=? WHERE id=?').run(salt, pwHash(next, salt), u.id);
  res.json({ ok: true });
});

/* ═══ 매니저 — 내가 진행한 매치 ═══
   지금은 코트를 잡고 매치를 만드는 것까지만 있고, 결과를 돌아볼 화면이 없었다. */
app.get('/manager/matches', auth, (req, res) => {
  const u = getUser(req.uid);
  if (!u || u.provider !== 'manager') return res.status(403).json({ error: 'not_manager' });
  const rows = db.prepare(`SELECT id, loc, dt, cap, price, status, settled
    FROM open_matches WHERE host_id=? ORDER BY id DESC LIMIT 60`).all(req.uid);
  res.json(rows.map(m => {
    const joined = db.prepare('SELECT COUNT(*) c FROM open_match_joins WHERE match_id=?').get(m.id);
    return { ...m, joined: (joined && joined.c) || 0 };
  }));
});

/* ═══ 구장 정산 — 주 1회, 이용일 기준 ═══
   월 정산은 소규모 구장의 현금 흐름을 막는다. 화요일에 지난주 이용분을 일괄 지급한다.
   화요일인 이유는 주말 경기가 월요일에 정리되기 때문이다.
   최소 지급액은 두지 않는다 — 3만원이라도 그 주에 보내는 편이 신뢰에 낫다. */

function weekRange(ref) {                      // 지난주 월 00:00 ~ 일 24:00
  const d = new Date(ref); d.setHours(0, 0, 0, 0);
  const dow = (d.getDay() + 6) % 7;            // 월=0
  const thisMon = new Date(d); thisMon.setDate(d.getDate() - dow);
  const lastMon = new Date(thisMon); lastMon.setDate(thisMon.getDate() - 7);
  return { from: lastMon.getTime(), to: thisMon.getTime() - 1,
           label: `${lastMon.toISOString().slice(0, 10)} ~ ${new Date(thisMon - 86400000).toISOString().slice(0, 10)}` };
}

/* 지난주에 '이용이 끝난' 예약만 지급 대상이다.
   예약일이 아니라 이용일 기준 — 3개월 뒤 코트를 미리 잡아도 돈은 이용 후에 나간다. */
function venuePayoutBatch(dry) {
  const w = weekRange(Date.now());
  const rows = db.prepare(`
    SELECT p.id, p.venue_id, p.amount, s.date, s.start
    FROM venue_payouts p JOIN venue_slots s ON s.id=p.slot_id
    WHERE p.status='pending'`).all();
  const due = rows.filter(r => {
    const used = new Date(`${r.date}T${r.start || '00:00'}:00`).getTime();
    return used >= w.from && used <= w.to;     // 지난주 이용분
  });
  const byVenue = {};
  due.forEach(r => { (byVenue[r.venue_id] = byVenue[r.venue_id] || []).push(r); });
  const out = Object.keys(byVenue).map(vid => ({
    venue_id: +vid,
    count: byVenue[vid].length,
    amount: byVenue[vid].reduce((a, r) => a + (r.amount || 0), 0),
    ids: byVenue[vid].map(r => r.id),
  }));
  if (!dry) {
    const ts = now();
    tx(() => { due.forEach(r => {
      db.prepare("UPDATE venue_payouts SET status='paid', paid_at=? WHERE id=? AND status='pending'").run(ts, r.id);
    }); });
    out.forEach(v => {
      const own = db.prepare('SELECT owner_id, name FROM venues WHERE id=?').get(v.venue_id);
      if (own && own.owner_id) try {
        sendPush(own.owner_id, { title: '정산이 완료됐어요',
          body: `${w.label} · ${v.count}건 · ${v.amount.toLocaleString()}원` });
      } catch (e) {}
    });
  }
  return { week: w.label, venues: out.length,
           total: out.reduce((a, v) => a + v.amount, 0), detail: out };
}

/* 화요일 오전에 한 번 돈다. 서버가 하루 종일 떠 있다는 보장이 없으므로
   '이번 주에 이미 돌았는지'를 파일이 아니라 payout 상태로 판단한다. */
let LAST_PAYOUT_WEEK = null;
setInterval(() => {
  try {
    const d = new Date();
    if (d.getDay() !== 2 || d.getHours() < 9) return;      // 화요일 09시 이후
    const w = weekRange(Date.now()).label;
    if (LAST_PAYOUT_WEEK === w) return;
    const r = venuePayoutBatch(false);
    LAST_PAYOUT_WEEK = w;
    if (r.total) console.log(`[payout] ${r.week} · ${r.venues}개 구장 · ${r.total}원`);
  } catch (e) { console.error('payout batch', e); }
}, 3600000);

app.get('/admin/venue-payout-preview', admin, (_req, res) => res.json(venuePayoutBatch(true)));
app.post('/admin/venue-payout-run', admin, (_req, res) => res.json(venuePayoutBatch(false)));

/* ═══ 부족분 충전 후 원래 자리로 ═══
   "충전하러 가기"로 앱을 나갔다 오면 예약 화면이 초기화됐다.
   주문에 돌아갈 곳을 실어두고, 결제가 끝나면 그대로 이어서 결제한다. */
try { db.exec('ALTER TABLE orders ADD COLUMN return_to TEXT'); } catch (e) {}

app.post('/pay/order-for', auth, (req, res) => {
  const need = Math.max(1000, Math.min(2000000, +req.body.need | 0));
  /* 1,000원 단위로 올려 받는다 — 잔돈이 남아 다음 결제가 또 막히지 않게 */
  const amount = Math.ceil(need / 1000) * 1000;
  const orderId = 'mc_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
  const ret = String(req.body.return_to || '').slice(0, 120);
  db.prepare(`INSERT INTO orders (order_id,user_id,amount,cash,status,created_at,return_to)
              VALUES (?,?,?,?, 'ready', ?, ?)`)
    .run(orderId, req.uid, amount, amount, now(), ret);
  res.json({ ok: true, orderId, amount, return_to: ret });
});
app.get('/pay/return-to/:orderId', auth, (req, res) => {
  const o = db.prepare('SELECT return_to, status, cash FROM orders WHERE order_id=? AND user_id=?')
    .get(req.params.orderId, req.uid);
  if (!o) return res.status(404).json({ error: 'not_found' });
  res.json({ return_to: o.return_to || '', status: o.status, cash: o.cash });
});

// 연결된 웹 클라이언트 (public/) 서빙 — npm start 하면 http://localhost:PORT 에서 바로 동작
app.use(express.static(new URL('./public', import.meta.url).pathname));
// 에러는 JSON으로
app.use((err, req, res, _next) => { console.error(err); res.status(500).json({ error: String(err && err.message || err) }); });
app.listen(PORT, () => console.log(`MATSU API on http://localhost:${PORT}`));
