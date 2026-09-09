// server.js — MATSU MVP REST API (Express + SQLite + JWT)
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import http2 from 'node:http2';        // iOS 알림(APNs) 전송에 쓴다
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
const SEEN = new Map();          // uid → 마지막으로 DB 에 쓴 시각
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
    /* 마지막 접속 — 모든 요청이 이 문을 지나므로 여기 한 곳이면 된다.
       매 요청마다 쓰면 DB 가 바쁘니 5분에 한 번만 갱신한다. */
    try {
      const t0 = now();
      if (!SEEN.has(req.uid) || t0 - SEEN.get(req.uid) > 300000) {
        SEEN.set(req.uid, t0);
        /* 어느 기기로 들어왔는지도 함께 — iOS 앱은 헤더를 보내고, 없으면 웹이다 */
        const plat = String(req.headers['x-client-platform'] || 'web').slice(0, 12);
        db.prepare('UPDATE users SET last_seen=?, last_plat=? WHERE id=?').run(t0, plat, req.uid);
        /* 어느 지역에서 들어왔는지 — 조회는 절대 요청을 막지 않는다(fire and forget).
           IP 자체는 저장하지 않고 지역 이름만 남긴다. */
        try { geoTouch(req.uid, clientIp(req)); } catch (e) {}
      }
    } catch (e) {}
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

const SRV_BUILD = 'sH-0907a';
/* public/index.html 의 BUILD 와 같은 값을 적는다 — 앱 업데이트 안내 기준 */
/* 앱 안에 든 화면 버전. 이 값과 앱의 BUILD 가 다르면 <새 버전이 나왔어요> 배너가 뜬다.
   기본값을 옛 버전으로 두면 환경변수를 안 넣었을 때 모두에게 배너가 계속 뜬다 —
   실제로 1.0.9 를 배포한 뒤에도 v1.0.7 기본값 때문에 업데이트하라는 안내가 사라지지 않았다.
   앱을 새로 낼 때마다 이 값을 함께 올린다(Railway 환경변수 WEB_BUILD 로 덮어쓸 수 있다). */
const WEB_BUILD = process.env.WEB_BUILD || 'v1.1.7';
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
/* 서버에 어떤 기능이 올라가 있나 — 앱이 옛 서버에 대고 새 기능을 부르면
   404 만 돌아와서 왜 안 되는지 알 길이 없었다. 실제 표를 확인해 알려준다. */
function serverCan() {
  const has = (t, c) => { try {
    return db.prepare(`PRAGMA table_info(${t})`).all().some(x => x.name === c);
  } catch (e) { return false; } };
  return {
    talk_photo: has('court_posts', 'photos'),
    talk_edit: has('court_posts', 'edited_at'),
    venue_info: has('venues', 'indoor_n'),
  };
}

app.get('/config', (_, res) => {
  res.set('Cache-Control', 'no-store');   // 브라우저가 옛 응답을 붙잡지 못하게
  res.json({
    can: serverCan(),
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
    /* 점검 중이면 앱이 띠를 띄운다. /config 는 앱이 이미 부르는 곳이라
       새 요청이 늘지 않는다. */
    maint: maintOn() ? { msg: MAINT.msg || '잠시 점검 중이에요', until: MAINT.until || 0 } : null,
    /* 스토어 주소 — 앱이 자기 플랫폼에 맞는 쪽을 골라 쓴다 */
    android_app_url: process.env.ANDROID_APP_URL || '',
    /* 지도는 볼 때 받아온다 — 앱에 넣지 않아 크기가 안 늘어난다 */
    kakao_js_key: process.env.KAKAO_JS_KEY || '',
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
/* 휴회는 켜고 끄는 것뿐이라 <언제 돌아오는지>를 아무도 몰랐다.
   잊히면 그대로 탈퇴가 된다 — 시작일과 복귀 예정일을 함께 받는다. */
try { db.exec('ALTER TABLE club_members ADD COLUMN rest_from TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE club_members ADD COLUMN rest_until TEXT'); } catch (e) {}
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
      db.prepare('UPDATE users SET cash=0 WHERE id=?').run(u.id);  // 캐시는 0원부터
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
      db.prepare('UPDATE users SET cash=0 WHERE id=?').run(u.id);  // 캐시는 0원부터
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
app.post('/pay/confirm', async (req, res) => {  // @external 결제창이 돌아오며 부름
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
app.post('/pay/webhook', (req, res) => {  // @external 토스가 부름
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
/* ── 관심 신청 ──
   아직 안 연 기능에 <열리면 알림>을 눌러둔 사람들. 어느 지역부터 열지 정하는 데 쓴다.
   같은 사람이 여러 번 눌러도 한 줄만 남는다. */
db.exec(`CREATE TABLE IF NOT EXISTS interests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER, kind TEXT, region TEXT, created_at BIGINT)`);
try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_interest ON interests(user_id, kind)'); } catch (e) {}

app.post('/me/interest', auth, (req, res) => {
  const kind = String((req.body || {}).kind || '').slice(0, 20);
  if (!kind) return res.status(400).json({ error: 'kind_required' });
  const region = String((req.body || {}).region || '').slice(0, 40);
  try {
    db.prepare(`INSERT INTO interests (user_id,kind,region,created_at) VALUES (?,?,?,?)
      ON CONFLICT(user_id,kind) DO UPDATE SET region=excluded.region`)
      .run(req.uid, kind, region, now());
  } catch (e) {}
  res.json({ ok: true });
});
/* 어느 지역에 몇 명이 기다리는가 — 여는 순서를 정할 때 본다 */
app.get('/admin/interests', admin, (_req, res) => {
  res.json(db.prepare(`SELECT kind, COALESCE(NULLIF(region,''),'(미상)') region, COUNT(*) n
    FROM interests GROUP BY kind, region ORDER BY n DESC`).all());
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
  /* name 이 빠져 있어서 <이름 바꾸기> 가 저장되지 않았다.
     화면은 서버가 돌려준 값을 그대로 믿으므로 잠깐 바뀐 것처럼 보였다가,
     다시 로그인해 /me 를 받으면 구글에서 들어온 영문 이름으로 되돌아갔다. */
  const allow = ['name','gender','region','sport','exp','photos','phone_verified','real_verified','skill_verified',
                 'birth_year','handed','backhand','style','phone','sport_started'];
  const nums = ['birth_year','phone_verified','real_verified','skill_verified'];
  const sets = [], vals = [];
  for (const k of allow) if (k in req.body) {
    /* 이름은 그대로 쓰지 않는다 — 태그 문자·줄바꿈을 걸러 20자로 줄인다.
       빈 이름이 저장되면 명단에서 사람이 사라진 것처럼 보인다. */
    if (k === 'name') {
      const nm = cleanName(req.body.name, '');
      if (!nm) return res.status(400).json({ error: 'bad_name', message: '이름을 입력해 주세요' });
      sets.push('name=?'); vals.push(nm);
      continue;
    }
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
  /* 성별 배지(여성 클럽·남성 클럽)는 <실제 명단>으로 판단한다.
     그런데 그 숫자를 안 내려주고 있어서, 클럽이 스스로 gender_pref 를 적어둔 곳만
     배지가 붙고 나머지는 아무것도 안 나왔다.
     게스트는 빼고, 클럽 안에서 고쳐 둔 성별(gender_ov)을 먼저 본다. */
  const GQ = `(SELECT COUNT(*) FROM club_members m JOIN users u ON u.id=m.user_id
      WHERE m.club_id=c.id AND (m.status IS NULL OR m.status='active')
        AND COALESCE(m.role,'') <> 'guest' AND `;
  let sql = `SELECT c.*,
      (SELECT COUNT(*) FROM club_members m JOIN users mu ON mu.id=m.user_id
        WHERE m.club_id=c.id AND (m.status IS NULL OR m.status='active')
          AND COALESCE(mu.is_test,0)=0) members,
      ${GQ} COALESCE(NULLIF(m.gender_ov,''), u.gender)='F') g_f,
      ${GQ} COALESCE(NULLIF(m.gender_ov,''), u.gender)='M') g_m,
      ${GQ} COALESCE(NULLIF(m.gender_ov,''), u.gender, '') NOT IN ('F','M')) g_unknown,
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
  const hc = splitCourt(req.body.home_court);
  const r = db.prepare(`INSERT INTO clubs
      (name,sport,region,owner_id,created_at,avg_grade,home_court,home_courts,meet_days,
       intro,logo,logo_ic,logo_bg,meet_time,age_bands,gender_pref,founded_year,recruiting)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(name, sport, region || '', req.uid, now(),
         cleanGrade(req.body.avg_grade), txt(hc.venue, 40), txt(hc.courts, 20),
         txt(req.body.meet_days, 30),
         txt(req.body.intro, 40), txt(req.body.logo, 300), txt(req.body.logo_ic, 8),
         txt(req.body.logo_bg, 12), txt(req.body.meet_time, 30),
         txt(req.body.age_bands, 40), txt(req.body.gender_pref, 10),
         /* 창단연도 — 안 적으면 만든 해로 둔다. 나중에 운영진 도구에서 고칠 수 있다 */
         (() => { const v = parseInt(req.body.founded_year, 10);
                  const y = new Date().getFullYear();
                  return (v >= 1900 && v <= y) ? v : y; })(),
         /* 새 클럽은 모집 중으로 시작한다 — 막 만든 클럽은 사람을 찾고 있다.
            끄는 건 운영진 도구에서 한 번이면 된다. */
         (req.body.recruiting === 0 || req.body.recruiting === false) ? 0 : 1);
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
  const club = db.prepare(`SELECT name,owner_id,sport,min_career_months,max_career_months,
    join_open,join_reopen FROM clubs WHERE id=?`).get(cid);
  if (!club) return res.status(404).json({ error: 'no_club' });
  /* 가입 신청을 닫아둔 클럽 — 앱에서도 버튼을 감추지만, 링크로 바로 들어오는 길이 있다 */
  if (club.join_open === 0)
    return res.status(403).json({ error: 'join_closed', reopen: club.join_reopen || '',
      message: '지금은 회원을 받지 않아요' });
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
  /* 이름으로 짠 대진에 있던 사람이면, 어떤 이름이었는지 함께 받아 둔다 —
     승인할 때 클럽장이 확인하고 그때 이어붙인다. */
  const claim = String((req.body && req.body.claim_name) || '').trim().slice(0, 20);
  const claimGid = String((req.body && req.body.claim_gid) || '').trim().slice(0, 24);
  db.prepare(`INSERT INTO club_members (club_id,user_id,role,status,joined_at,claim_name,claim_gid)
    VALUES (?,?, 'member','pending',?,?,?)`)
    .run(cid, req.uid, now(), claim || null, claimGid || null);
  const me = getUser(req.uid);
  // 클럽장·임원에게 알림
  db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND role IN ('owner','officer')").all(cid)
    /* 임원이 누르면 가입 신청 목록이 바로 열린다 */
    .forEach(r => sendPush(r.user_id, { icon: '👤', title: '가입 신청',
      body: `${me.name} 님이 ${club.name} 가입을 신청했어요`, link: 'club:join' }));
  res.json({ ok: true, status: 'pending' });
});
app.get('/clubs/:id/members', (req, res) => {
  // 연락처는 임원에게만 — 토큰이 있으면 조용히 확인
  let uid = null;
  try { uid = jwt.verify((req.headers.authorization||'').replace('Bearer ',''), JWT_SECRET).uid; } catch (e) {}
  const officer = uid ? isOfficer(+req.params.id, uid) : false;
  const rows = db.prepare(`SELECT cm.id, cm.club_id, cm.user_id, cm.role, cm.jersey_no, cm.is_captain, cm.status, cm.grade,
    cm.resting, cm.rest_from, cm.rest_until, cm.joined_at, COALESCE(NULLIF(cm.alias,''), u.name) AS name, u.gender, u.rating, u.sport_started, u.photos, u.created_at AS user_created${officer ? ', u.phone' : ''} FROM club_members cm
    JOIN users u ON u.id=cm.user_id WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
      AND COALESCE(u.is_test,0)=0
    ORDER BY (cm.role='owner') DESC, (cm.role='officer') DESC, cm.resting, u.name`).all(+req.params.id);

  /* 최근 4주 출석 — 명단에서 진짜 궁금한 건 등급이 아니라 <요즘 나오나>다.
     모임 날짜는 '8/28 (금) 19:00~23:00 · 용인' 꼴의 글이라 SQL 로는 못 세고,
     eventDayTs 로 날짜를 뽑아 자바스크립트에서 센다. */
  const att = {}, last = {};
  try {
    const cid = +req.params.id;
    const t0 = now(), t28 = t0 - 28 * 864e5;
    const ts = {};
    db.prepare('SELECT id, date, created_at FROM club_events WHERE club_id=?').all(cid)
      .forEach(e => { const t = eventDayTs(e.date, e.created_at); if (t) ts[e.id] = t; });
    const ids = Object.keys(ts);
    if (ids.length) {
      /* id 는 Object.keys 라 문자열이다 — INTEGER 칸에 문자열을 넣으면 못 맞춘다 */
      db.prepare(`SELECT event_id, user_id FROM event_attendees
        WHERE status='going' AND event_id IN (${ids.map(() => '?').join(',')})`)
        .all(...ids.map(Number))
        .forEach(a => {
          const t = ts[a.event_id];
          if (t > t0) return;                                  // 앞으로 열릴 모임은 출석이 아니다
          if (t >= t28) att[a.user_id] = (att[a.user_id] || 0) + 1;
          if (!last[a.user_id] || t > last[a.user_id]) last[a.user_id] = t;
        });
    }
  } catch (e) {}

  res.json(rows.map(r => ({ ...r,
    att4w: att[r.user_id] || 0,
    last_seen_at: last[r.user_id] || null })));
});

/* 모임 글에서 날짜만 뽑는다 — '8/28 (금) 19:00~23:00 · 용인' → 그날 0시.
   연말·연초에 해가 넘어가는 것은 만든 시각을 기준으로 보정한다. */
function eventDayTs(dateText, createdAt) {
  const m = String(dateText || '').match(/(\d{1,2})\/(\d{1,2})/);
  if (!m) return null;
  const base = new Date(createdAt || now());
  const d = new Date(base.getFullYear(), +m[1] - 1, +m[2]);
  const diff = (d - base) / 864e5;
  if (diff < -200) d.setFullYear(base.getFullYear() + 1);
  if (diff > 200) d.setFullYear(base.getFullYear() - 1);
  return d.getTime();
}

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

/* 클럽에서 부를 이름 (임원, 또는 본인) — 계정 이름은 건드리지 않는다.
   빈 값으로 보내면 지워지고 계정 이름으로 돌아간다. */
app.patch('/clubs/:id/members/:uid/alias', auth, (req, res) => {
  const cid = +req.params.id, uid = +req.params.uid;
  const mine = uid === req.uid;
  if (!mine && !isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const m = db.prepare('SELECT user_id FROM club_members WHERE club_id=? AND user_id=?').get(cid, uid);
  if (!m) return res.status(404).json({ error: 'not_member' });
  const raw = (req.body && req.body.alias) || '';
  /* cleanName 은 빈 값에 '회원' 을 채워 준다 — 여기서는 그 기본값이 오히려 방해가 된다.
     빈 값은 <부를 이름 지우기> 라는 뜻이므로 그대로 비워 계정 이름으로 돌려보낸다. */
  const alias = String(raw).trim() ? cleanName(raw, '') : '';
  try { db.prepare('UPDATE club_members SET alias=? WHERE club_id=? AND user_id=?').run(alias || null, cid, uid); }
  catch (e) {
    try { db.exec('ALTER TABLE club_members ADD COLUMN alias TEXT'); } catch (_) {}
    db.prepare('UPDATE club_members SET alias=? WHERE club_id=? AND user_id=?').run(alias || null, cid, uid);
  }
  res.json({ ok: true, alias: alias || null });
});

// 휴회 토글 (임원)
// 휴회·복회 신청 (회원) — 임원 승인제
// 연명부 부속 기록 — 휴회·복회 이력 + 탈퇴 회원 (엑셀 시트용)
/* ── 가입하지 않은 사람이 보는 클럽 페이지 ─────────────────────────────
   밖에서 클럽을 고르는 사람에게 필요한 것만 내려준다. 이름은 여기서 가린다 —
   앱에서 가리면 원본이 이미 브라우저까지 간 뒤라 가린 것이 아니다. */
/* 이름은 그대로 내보낸다 — /clubs/:id/members 로 명단이 이미 열려 있어서
   대진표만 가리면 가린 것이 아니라 <굴러가는 클럽인지> 알아보기만 어려워진다.
   가려야 할 때가 오면 이 함수 하나만 바꾸면 전부 따라온다. */
function maskName(n) { return String(n || '').trim(); }
/* ── 이름으로 짠 대진과 나중에 들어온 회원 잇기 ────────────────────────
   회원이 앱에 없어도 이름만 적어 대진을 짤 수 있다. 그렇게 남은 이름은
   임시 id(g…) 를 달고 기록에 남는데, 그 사람이 나중에 가입하면 남남이 된다.
   가입 신청 때 본인이 이름을 고르고, 클럽장이 승인하면 그때 이어붙인다.
   같은 이름이 두 사람일 수 있으니 자동으로 잇지 않는다. */
/* 이름이 아니라 그때 그 사람(게스트 id)으로 잇는다 —
   같은 클럽에 동명이인 게스트가 둘일 수 있어서, 이름으로 묶으면 남의 기록을 가져간다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS club_name_links (
    club_id INTEGER, gid TEXT, name TEXT, user_id INTEGER, created_at BIGINT,
    PRIMARY KEY (club_id, gid))`);
} catch (e) {}
try { db.exec('ALTER TABLE club_members ADD COLUMN claim_name TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE club_members ADD COLUMN claim_gid TEXT'); } catch (e) {}

/* 아직 주인이 없는 이름들 — 초대받은 사람에게 후보로 보여준다 */
app.get('/clubs/:id/unlinked-names', (req, res) => {
  const cid = +req.params.id;
  const taken = new Set(db.prepare('SELECT gid FROM club_name_links WHERE club_id=?')
    .all(cid).map(r => String(r.gid)));
  const logs = db.prepare(`SELECT date, data FROM club_bracket_logs
    WHERE club_id=? ORDER BY date DESC LIMIT 12`).all(cid);
  const map = {};
  logs.forEach(r => {
    let d = {}; try { d = JSON.parse(r.data); } catch (e) {}
    (d.games || []).forEach(g => {
      const done = g.sa != null && g.sb != null;
      const put = (p, win) => {
        /* 임시 id(g…) 로 남은 사람만 후보다 — 이미 회원인 사람은 이을 것이 없다 */
        if (!p || !p.name || !/^g/i.test(String(p.id || ''))) return;
        const gid = String(p.id);
        if (taken.has(gid)) return;
        const t = map[gid] || (map[gid] = { gid, name: p.name, games: 0, w: 0, l: 0,
          days: new Set(), months: (p.months != null ? p.months : null), grade: p.grade || '' });
        if (t.months == null && p.months != null) t.months = p.months;
        if (!t.grade && p.grade) t.grade = p.grade;
        t.days.add(r.date);
        if (done) { t.games++; if (win > 0) t.w++; else if (win < 0) t.l++; }
      };
      const diff = done ? g.sa - g.sb : 0;
      (g.teamA || []).forEach(p => put(p, diff));
      (g.teamB || []).forEach(p => put(p, -diff));
    });
  });
  const out = Object.values(map)
    .map(t => ({ gid: t.gid, name: t.name, games: t.games, w: t.w, l: t.l,
                 months: t.months, grade: t.grade,
                 days: t.days.size, last: [...t.days].sort().pop() || '' }))
    .sort((a, b) => b.games - a.games).slice(0, 30);
  /* 같은 이름이 둘 이상이면 앱이 알아서 고르면 안 된다 — 표시를 달아 보낸다 */
  const dupe = {}; out.forEach(t => { dupe[t.name] = (dupe[t.name] || 0) + 1; });
  res.json(out.map(t => ({ ...t, dupe: dupe[t.name] > 1 })));
});

/* 승인하면서 잇는다 — 지난 기록의 임시 id 를 그 회원 id 로 바꿔 준다.
   이렇게 해두면 순위·전당·개인 기록이 모두 저절로 따라온다. */
function linkClubName(cid, gid, uid) {
  if (!cid || !gid || !uid) return 0;
  const dup = db.prepare('SELECT user_id FROM club_name_links WHERE club_id=? AND gid=?').get(cid, String(gid));
  if (dup) return 0;                                  // 이미 다른 사람이 가져갔다
  let nm = '';
  db.prepare('SELECT data FROM club_bracket_logs WHERE club_id=?').all(cid).forEach(r => {
    if (nm) return;
    let d; try { d = JSON.parse(r.data); } catch (e) { return; }
    (d.games || []).forEach(g => [g.teamA, g.teamB].forEach(t => (t || []).forEach(p => {
      if (!nm && p && String(p.id) === String(gid)) nm = p.name || ''; })));
  });
  db.prepare('INSERT INTO club_name_links (club_id,gid,name,user_id,created_at) VALUES (?,?,?,?,?)')
    .run(cid, String(gid), nm, uid, now());
  let changed = 0;
  db.prepare('SELECT date, data FROM club_bracket_logs WHERE club_id=?').all(cid).forEach(r => {
    let d; try { d = JSON.parse(r.data); } catch (e) { return; }
    let hit = false;
    (d.games || []).forEach(g => {
      [g.teamA, g.teamB].forEach(t => (t || []).forEach(p => {
        if (p && String(p.id) === String(gid)) { p.id = uid; hit = true; }
      }));
    });
    if (hit) {
      db.prepare('UPDATE club_bracket_logs SET data=? WHERE club_id=? AND date=?')
        .run(JSON.stringify(d), cid, r.date);
      changed++;
    }
  });
  return changed;
}

app.get('/clubs/:id/public', (req, res) => {
  const cid = +req.params.id;
  const c = db.prepare('SELECT * FROM clubs WHERE id=?').get(cid);
  if (!c) return res.status(404).json({ error: 'not_found' });

  const mem = db.prepare(`SELECT cm.grade, u.gender, u.sport_started
    FROM club_members cm JOIN users u ON u.id=cm.user_id
    WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
      AND COALESCE(u.is_test,0)=0`).all(cid);

  /* 구력 — sport_started 는 종목별 <YYYY-MM> 이 담긴 JSON 이다 */
  const months = [];
  mem.forEach(m => {
    try {
      const st = JSON.parse(m.sport_started || '{}')[c.sport || 'tennis'];
      if (!st) return;
      const [y, mo] = String(st).split('-').map(Number);
      if (!y) return;
      const d = new Date();
      const v = (d.getFullYear() - y) * 12 + (d.getMonth() + 1 - (mo || 1));
      if (v >= 0 && v < 900) months.push(v);
    } catch (e) {}
  });
  const avgMonths = months.length ? Math.round(months.reduce((a, b) => a + b, 0) / months.length) : null;

  const grades = {};
  mem.forEach(m => { const g = String(m.grade || '').replace(/[0-9]/g, ''); if (g) grades[g] = (grades[g] || 0) + 1; });
  const gf = mem.filter(m => /여|f/i.test(String(m.gender || ''))).length;
  const gm = mem.filter(m => /남|m/i.test(String(m.gender || ''))).length;

  /* 지난 모임 — 로그에 날짜별로 한 벌씩 쌓여 있다 */
  const logs = db.prepare(`SELECT date, data FROM club_bracket_logs
    WHERE club_id=? ORDER BY date DESC LIMIT 12`).all(cid);
  /* 시즌 순위 — 앱과 같은 셈법을 쓴다. 총점으로 줄을 세우면 많이 나온 사람이
     이기는 게 당연해져서, 많이 나온 것 자체가 실력처럼 보인다.
     승 3 · 무 1 로 모은 점수를 참석 횟수로 나눈다. 게스트는 빼고 센다. */
  const pts = {};
  const dayCnt = {};
  const gameCnt = {};
  const days = logs.map(r => {
    let d = {}; try { d = JSON.parse(r.data); } catch (e) {}
    const gs = (d.games || []).filter(g => g.sa != null && g.sb != null);
    const dayPt = {};
    gs.forEach(g => {
      const a = g.teamA || [], b = g.teamB || [];
      const win = g.sa > g.sb ? 3 : (g.sa === g.sb ? 1 : 0);
      const lose = g.sb > g.sa ? 3 : (g.sa === g.sb ? 1 : 0);
      const put = (p, pt) => {
        if (!p || !p.name) return;
        dayPt[p.name] = (dayPt[p.name] || 0) + pt;
        if (/^g/i.test(String(p.id || ''))) return;   // 게스트는 클럽 기록에 넣지 않는다
        pts[p.name] = (pts[p.name] || 0) + pt;
        gameCnt[p.name] = (gameCnt[p.name] || 0) + 1;
        (dayCnt[p.name] = dayCnt[p.name] || new Set()).add(r.date);
      };
      a.forEach(p => put(p, win));
      b.forEach(p => put(p, lose));
    });
    const top = Object.entries(dayPt).sort((x, y) => y[1] - x[1])[0];
    const courts = new Set((d.games || []).map(g => g.playCourt || g.c).filter(Boolean));
    return { date: r.date, mode: d.mode || 'normal', courts: courts.size || (d.courts || 0),
             games: (d.games || []).length, done: gs.length, top: top ? maskName(top[0]) : '' };
  }).filter(x => x.done > 0);

  /* 모임이 두 번 이상 있었으면 두 번 이상 나온 사람만 줄에 세운다 —
     한 번 와서 네 판 이긴 사람이 1위가 되면 순위가 농담이 된다. */
  const dayTotal = new Set(logs.map(r => r.date)).size;
  const minDays = dayTotal >= 2 ? 2 : 1;
  const ranking = Object.keys(pts)
    .map(nm => {
      const dn = (dayCnt[nm] || new Set()).size || 1;
      return { name: maskName(nm), pts: pts[nm], days: dn,
               games: gameCnt[nm] || 0, avg: Math.round(pts[nm] / dn * 10) / 10 };
    })
    .filter(r => r.days >= minDays)
    .sort((a, b) => b.avg - a.avg || b.pts - a.pts || b.games - a.games)
    .slice(0, 5)
    .map((r, i) => ({ pos: i + 1, ...r }));

  /* 다가오는 모임 — 이름은 빼고 인원만 */
  let events = [];
  try {
    events = db.prepare(`SELECT id, title, date, tag FROM club_events
      WHERE club_id=? ORDER BY id DESC LIMIT 12`).all(cid)
      .map(e => ({ ...e, count: (db.prepare('SELECT COUNT(*) c FROM event_attendees WHERE event_id=? AND status=?')
                    .get(e.id, 'going') || {}).c || 0 }));
  } catch (e) {}

  res.json({
    id: c.id, name: c.name, region: c.region, sport: c.sport,
    members: mem.length, founded_year: c.founded_year || null,
    recruiting: c.recruiting || 0, guest_min_months: c.guest_min_months || null,
    guest_visits: c.guest_visits || null, guest_cap: c.guest_cap || null,
    join_open: c.join_open == null ? 1 : c.join_open, join_reopen: c.join_reopen || '',
    guest_fee: c.guest_fee || null, entry_fee: c.entry_fee || null, season_fee: c.season_fee || null,
    meet_days: c.meet_days || '', meet_time: c.meet_time || '',
    home_court: c.home_court || '', home_courts: c.home_courts || '',
    intro: c.intro || '', gender_pref: c.gender_pref || '', age_bands: c.age_bands || '',
    avg_months: avgMonths, grades, g_f: gf, g_m: gm,
    days, ranking, events,
  });
});

/* 그날 하나 — 표로 그릴 수 있게 회차·코트별로 정리해서 준다 */
app.get('/clubs/:id/public/day/:date', (req, res) => {
  const cid = +req.params.id;
  const row = db.prepare('SELECT date, data FROM club_bracket_logs WHERE club_id=? AND date=?')
    .get(cid, String(req.params.date).slice(0, 10));
  if (!row) return res.status(404).json({ error: 'not_found' });
  let d = {}; try { d = JSON.parse(row.data); } catch (e) {}
  const nm = t => (t || []).map(p => maskName(p && p.name)).filter(Boolean).join('·');
  const done = (d.games || []).filter(g => g.sa != null && g.sb != null);
  const games = done.map(g => ({
    r: g.r || 1, court: g.playCourt || g.c || 1,
    a: nm(g.teamA), b: nm(g.teamB), sa: g.sa, sb: g.sb,
  }));
  /* 그날 순위 — 시즌과 같은 셈법(승 3 · 무 1)에, 가른 게임 차를 더해 동점을 푼다 */
  const tally = {};
  const put = (p, pt, gf, ga) => {
    if (!p || !p.name) return;
    const t = tally[p.name] || (tally[p.name] = { name: maskName(p.name), pts: 0, w: 0, d: 0, l: 0, gf: 0, ga: 0 });
    t.pts += pt; t.gf += gf; t.ga += ga;
    if (pt === 3) t.w++; else if (pt === 1) t.d++; else t.l++;
  };
  done.forEach(g => {
    const pa = g.sa > g.sb ? 3 : (g.sa === g.sb ? 1 : 0);
    const pb = g.sb > g.sa ? 3 : (g.sa === g.sb ? 1 : 0);
    (g.teamA || []).forEach(p => put(p, pa, g.sa, g.sb));
    (g.teamB || []).forEach(p => put(p, pb, g.sb, g.sa));
  });
  const standings = Object.values(tally)
    .sort((a, b) => b.pts - a.pts || (b.gf - b.ga) - (a.gf - a.ga) || b.gf - a.gf)
    .map((t, i) => ({ pos: i + 1, ...t, diff: t.gf - t.ga }));
  res.json({ date: row.date, mode: d.mode || 'normal', games, standings });
});

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
  sendPush(r.user_id, { icon: ok ? '✅' : '🔔', title: (r.rtype==='rest'?'휴회':'복회') + (ok?' 승인':' 신청 결과'), body: ok ? '처리됐어요' : '승인되지 않았어요' });
  res.json({ ok: true });
});

app.patch('/clubs/:id/members/:uid/resting', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const b = req.body || {};
  const v = b.resting ? 1 : 0;
  const ymd = x => /^\d{4}-\d{2}-\d{2}$/.test(String(x || '')) ? String(x) : null;
  /* 휴회를 풀면 기간도 함께 지운다 — 남겨두면 다음에 다시 쉴 때 옛 날짜가 따라온다 */
  const from  = v ? (ymd(b.rest_from) || new Date().toISOString().slice(0, 10)) : null;
  const until = v ? ymd(b.rest_until) : null;
  db.prepare('UPDATE club_members SET resting=?, rest_from=?, rest_until=? WHERE club_id=? AND user_id=?')
    .run(v, from, until, cid, intOrNull(req.params.uid));
  res.json({ ok: true, resting: v, rest_from: from, rest_until: until });
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
/* 대진을 짤 수 있는가 — 임원, 그리고 <자기가 연 번개>의 주최자.
   번개는 회원 누구나 여는데 대진은 임원만 짤 수 있으면
   연 사람이 임원을 붙잡아야 모임이 굴러간다.
   웹(index.html cb2CanEdit)과 같은 규칙이라야 한다 —
   한쪽만 열어두면 화면에서는 버튼이 눌리고 저장만 조용히 튕긴다.
   모임에 붙지 않은 클럽 공용 대진은 그대로 임원만. */
function cbCanEdit(cid, uid, eid) {
  const role = cbRole(cid, uid);
  if (role === 'owner' || role === 'officer') return true;
  if (!role) return false;                       // 클럽 회원이 아니면 여기서 끝
  if (!eid) return false;                        // 공용 대진은 임원만
  const ev = db.prepare('SELECT tag, created_by FROM club_events WHERE id=? AND club_id=?')
    .get(eid, cid);
  return !!(ev && ev.tag === '번개' && String(ev.created_by) === String(uid));
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
/* ── 월례대회 성적 ──
   승강 결과(grade_changes)만 남기면 <몇 등이었나>가 사라진다.
   그건 그날 하루치 화면에만 있었고, 다음 달이면 아무 데도 안 남았다.
   확정할 때 조별 순위를 통째로 저장해 <내 기록>에서 되짚을 수 있게 한다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS monthly_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    club_id INTEGER, user_id INTEGER, name TEXT, held_on TEXT,
    tier TEXT, rank INTEGER, n INTEGER, w INTEGER, l INTEGER, gd INTEGER,
    dir TEXT, to_tier TEXT, created_at BIGINT)`);
  db.exec('CREATE INDEX IF NOT EXISTS ix_mr_user ON monthly_results(club_id, user_id)');
  /* 같은 대회를 두 번 확정해도 한 줄만 남는다 */
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_mr ON monthly_results(club_id, user_id, held_on)');
} catch (e) {}

/* 내 월례대회 이력 — 최근 것부터 */
app.get('/clubs/:id/monthly/me', auth, (req, res) => {
  const cid = +req.params.id;
  if (!cbRole(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  res.json(db.prepare(`SELECT held_on, tier, rank, n, w, l, gd, dir, to_tier, created_at
    FROM monthly_results WHERE club_id=? AND user_id=?
    ORDER BY created_at DESC LIMIT 24`).all(cid, req.uid));
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
  /* 순위표를 함께 받으면 성적으로 남긴다 — 승강한 사람만이 아니라 <그날 뛴 전원>이 남는다 */
  const st = (req.body || {}).standings || [];
  const held = String((req.body || {}).held_on || '').slice(0, 20) || ymdOf(now());
  if (Array.isArray(st) && st.length) {
    const ins = db.prepare(`INSERT INTO monthly_results
      (club_id,user_id,name,held_on,tier,rank,n,w,l,gd,dir,to_tier,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(club_id,user_id,held_on) DO UPDATE SET
        tier=excluded.tier, rank=excluded.rank, n=excluded.n,
        w=excluded.w, l=excluded.l, gd=excluded.gd,
        dir=excluded.dir, to_tier=excluded.to_tier`);
    const t = now();
    st.forEach(r => {
      if (!r || !r.user_id || !r.tier) return;
      const mv = list.find(c => +c.user_id === +r.user_id);
      try {
        ins.run(cid, +r.user_id, String(r.name || ''), held, String(r.tier),
          +r.rank || 0, +r.n || 0, +r.w || 0, +r.l || 0, +r.gd || 0,
          mv ? String(mv.dir) : null, mv ? String(mv.to) : null, t);
      } catch (e) {}
    });
  }
  res.json({ ok: true, n: list.length });
});
/* 날짜만 뽑는다 — 같은 날 두 번 확정해도 한 줄로 합쳐진다 */
function ymdOf(ts) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
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
app.put('/clubs/:id/bracket2', auth, (req, res) => {          // 발행/수정 — 임원 또는 번개 주최자
  const cid = +req.params.id;
  const eid = evOf(req);
  if (!cbCanEdit(cid, req.uid, eid))
    return res.status(403).json({ error: 'officer_only',
      message: '대진은 임원 또는 이 번개를 연 사람이 짤 수 있어요' });
  const data = req.body || {};
  if (eid) {
    db.prepare(`INSERT INTO club_brackets_ev (club_id,event_id,data,updated_at) VALUES (?,?,?,?)
      ON CONFLICT(club_id,event_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`)
      .run(cid, eid, JSON.stringify(data), now());
  } else {
    db.prepare(`INSERT INTO club_brackets (club_id,data,updated_at) VALUES (?,?,?)
      ON CONFLICT(club_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`)
      .run(cid, JSON.stringify(data), now());
  }
  /* 시작 버튼을 누르면 tb 가 생긴다 — 그때 잠금화면 카드를 세운다.
     이후로는 회차가 넘어갈 때만 밀면 되고, 초 단위는 앱이 스스로 센다. */
  try { if (data && data.tb && data.tb.startedAt) liveActivityBroadcast(data, tbPhaseOf(data)); }
  catch (e) {}
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
  /* 오늘 이 대진에 이름이 올라 있는 회원이면 <비어 있는 점수>는 대신 넣을 수 있다.
     총무 한 사람만 넣을 수 있으면 그 사람이 코트를 못 보는 동안 클럽이 멈춘다.
     실제로 점수가 265분 비어 있던 날이 있었고, 그 사이 다른 코트도 놀았다.
     넣은 사람 id 를 남기므로 장난은 되짚을 수 있다. */
  const inBracket = (data.games || []).some(x =>
    [...(x.teamA || []), ...(x.teamB || [])].some(p => p && p.id === req.uid));
  /* 한울·월례대회는 조가 코트에 고정이라 다른 코트 사람은 그 경기를 보지 못한다.
     못 본 경기의 점수를 넣게 두면 잘못된 값이 들어가고, 그걸 되짚기도 어렵다.
     그래서 이 두 방식에서는 <같은 코트에서 뛴 사람>만 대신 넣을 수 있게 한다. */
  const fixedMode = data.mode === 'hanul' || data.mode === 'monthly';
  /* 청백전·대회 준비는 팀(조)끼리 붙는 방식이라 남이 대신 넣을 자리가 아니다.
     승패가 팀 성적으로 바로 이어져서, 당사자 아닌 사람이 넣으면 시비가 생긴다.
     이 두 방식은 <당사자 또는 운영진>만 넣는다. */
  const soloMode = data.mode === 'cheongbaek' || data.mode === 'tourney';
  const at = x => x.playCourt || x.c;
  const sameCourt = (data.games || []).some(x => at(x) === at(g) &&
    [...(x.teamA || []), ...(x.teamB || [])].some(p => p && p.id === req.uid));
  const helper = soloMode ? false : (fixedMode ? sameCourt : inBracket);
  const empty = g.sa == null || g.sb == null;
  /* 이미 들어간 점수를 고치는 것은 넣는 것과 다른 문제다 — 시즌 랭킹이 조용히 바뀐다.
     예전에는 당사자가 언제든 고칠 수 있었는데, 진 사람이 나중에 바꿀 여지가 있었다.
     이제 <끝난 경기는 운영진만> 고친다.
     다만 대신 넣어준 사람은 10분 안에 되돌릴 수 있게 둔다 —
     남의 경기에 잘못 넣었을 때 곧바로 바로잡을 길이 없으면 그게 더 나쁘다. */
  const mineRecent = g.by === req.uid && g.atMs && (Date.now() - g.atMs) < 10 * 60 * 1000;
  const may = empty ? (officer || inGame || helper)      // 아직 빈 점수를 넣는 경우
                    : (officer || mineRecent);            // 이미 들어간 점수를 고치는 경우
  if (!may) {
    if (!empty) return res.status(403).json({ error: 'edit_locked', message: '들어간 점수는 운영진이 고칠 수 있어요' });
    return res.status(403).json(soloMode
      ? { error: 'player_only', message: '그 경기를 뛴 분이나 운영진이 넣을 수 있어요' }
      : fixedMode
        ? { error: 'court_only', message: `${at(g)}번 코트에서 뛴 분이나 운영진이 넣을 수 있어요` }
        : { error: 'bracket_only', message: '오늘 대진에 있는 회원만 대신 넣을 수 있어요' });
  }
  /* 0:0 은 결과가 아니라 <아직 안 함>이다 — 그대로 받으면 무승부로 기록돼
     시즌 랭킹이 조용히 바뀐다. 화면에서도 막지만 옛 버전 앱이 보낼 수 있어 여기서도 막는다. */
  if (+sa === 0 && +sb === 0) return res.status(400).json({ error: 'zero_score', message: '0 : 0 은 저장할 수 없어요' });
  g.sa = Math.max(0, Math.min(9, +sa)); g.sb = Math.max(0, Math.min(9, +sb));
  g.by = req.uid; g.at = now(); g.atMs = Date.now();
  /* 코트 밖에서 도운 것도 남긴다 — 승패에만 쌓이면 대신 넣어준 사람은 아무 데도 안 남는다 */
  if (!inGame) g.byHelp = 1;
  if (eid) db.prepare('UPDATE club_brackets_ev SET data=?, updated_at=? WHERE club_id=? AND event_id=?').run(JSON.stringify(data), now(), cid, eid);
  else db.prepare('UPDATE club_brackets SET data=?, updated_at=? WHERE club_id=?').run(JSON.stringify(data), now(), cid);
  cbLog(cid, data);
  try { notifyNextUp(cid, data, g); } catch (e) {}   // 알림이 실패해도 점수 저장은 끝난 일이다
  /* 점수가 들어왔으니 그 넷의 잠금화면 카드는 다시 시계로 돌린다 */
  try { liveActivityBroadcast(data, tbPhaseOf(data)); } catch (e) {}
  res.json({ ok: true, game: g });
});

/* 지금이 경기 중인지 전환 중인지 — 서버도 같은 셈을 한다 */
function tbPhaseOf(data) {
  const tb = data && data.tb; if (!tb || !tb.startedAt) return 'done';
  const unit = (data.tbUnit || 25), swap = (data.tbSwap || 5);
  const cyc = (unit + swap) * 60000;
  const el = Date.now() - tb.startedAt;
  const idx = Math.floor(el / cyc);
  if (tb.rounds && idx >= tb.rounds) return 'done';
  return (el - idx * cyc) < unit * 60000 ? 'play' : 'swap';
}
/* 회차가 넘어가는 순간을 잡아 카드를 밀어준다.
   폰이 꺼져 있어도 시계는 흐르므로, 보내는 건 <회차가 바뀌었다>는 사실뿐이다. */
const _tbSeen = {};
setInterval(() => {
  if (!apnsReady()) return;
  try {
    const rows = [
      ...db.prepare('SELECT club_id, event_id, data FROM club_brackets_ev').all(),
      ...db.prepare('SELECT club_id, NULL event_id, data FROM club_brackets').all(),
    ];
    rows.forEach(row => {
      let data; try { data = JSON.parse(row.data); } catch (e) { return; }
      const tb = data.tb; if (!tb || !tb.startedAt) return;
      if (Date.now() - tb.startedAt > 8 * 3600e3) return;   // 지난 대진은 건드리지 않는다
      const key = `${row.club_id}:${row.event_id || 0}`;
      const unit = (data.tbUnit || 25), swap = (data.tbSwap || 5);
      const cyc = (unit + swap) * 60000;
      const idx = Math.floor((Date.now() - tb.startedAt) / cyc);
      const phase = tbPhaseOf(data);
      const mark = `${idx}:${phase}`;
      if (_tbSeen[key] === mark) return;
      _tbSeen[key] = mark;
      liveActivityBroadcast(data, phase);
      /* 전환이 시작됐다는 건 방금 회차가 끝났다는 뜻 — 빈 점수를 채워달라고 한다 */
      if (phase === 'swap') (data.games || [])
        .filter(g => g.r === idx + 1 && (g.sa == null || g.sb == null))
        .forEach(g => liveActivityAskScore(data, g));
    });
  } catch (e) {}
}, 20000);

/* ══════════ 라이브 액티비티 (ActivityKit) ══════════
   잠금화면과 다이나믹 아일랜드에 회차 시계를 띄운다.

   중요한 점 하나 — 타이머는 서버가 매초 보내지 않는다.
   ActivityKit 의 Text(timerInterval:) 이 <끝나는 시각>만 받으면 스스로 흐른다.
   그래서 서버가 푸시를 보내는 때는 회차가 넘어갈 때뿐이다(5회차면 하루 다섯 번).

   ── 앱(Swift) 쪽 계약 ──
   ActivityAttributes.ContentState 는 아래 값을 그대로 받는다:
     phase   "play" | "swap" | "score" | "done"
     round   현재 회차          rounds  전체 회차
     court   내 코트 번호(없으면 null)
     endsAt  이 구간이 끝나는 시각(초 단위 epoch) → Text(timerInterval:)
     title   한 줄 문구         sub     보조 문구
   앱은 시작할 때 pushToken 을 받아 POST /me/live-activity 로 보낸다. */
db.exec(`CREATE TABLE IF NOT EXISTS live_activities (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, club_id INTEGER,
  created_at INTEGER, updated_at INTEGER);`);

app.post('/me/live-activity', auth, (req, res) => {
  const token = String((req.body || {}).token || '').trim();
  const club_id = intOrNull((req.body || {}).club_id);
  if (!token) return res.status(400).json({ error: 'token_required' });
  db.prepare(`INSERT INTO live_activities (token,user_id,club_id,created_at,updated_at)
    VALUES (?,?,?,?,?) ON CONFLICT(token) DO UPDATE SET
      user_id=excluded.user_id, club_id=excluded.club_id, updated_at=excluded.updated_at`)
    .run(token, req.uid, club_id, now(), now());
  res.json({ ok: true });
});
app.delete('/me/live-activity', auth, (req, res) => {
  const token = String((req.body || {}).token || req.query.token || '').trim();
  if (token) db.prepare('DELETE FROM live_activities WHERE token=?').run(token);
  else db.prepare('DELETE FROM live_activities WHERE user_id=?').run(req.uid);
  res.json({ ok: true });
});

/* ── APNs 전송 ──
   서버에는 이미 알림용 APNs 코드가 있다(apnsPem · APNS · apnsToken · apnsSend).
   그것을 그대로 쓰고, 라이브 액티비티만 <토픽과 푸시 타입이 다르다>.
   예전에 여기서 const APNS 를 한 번 더 선언해 서버가 아예 못 떴다. */
function apnsSendLive(token, payload, hostIdx) {
  return new Promise(resolve => {
    if (!apnsReady()) return resolve({ ok: false, why: 'not_configured' });
    const host = APNS.hosts[hostIdx || 0];
    let client;
    try { client = http2.connect(host); } catch { return resolve({ ok: false }); }
    const body = Buffer.from(JSON.stringify(payload));
    const req = client.request({
      ':method': 'POST', ':path': '/3/device/' + token,
      authorization: 'bearer ' + apnsToken(),
      'apns-topic': APNS.bundleId + '.push-type.liveactivity',
      'apns-push-type': 'liveactivity',
      'apns-priority': '10',
      'content-type': 'application/json',
      'content-length': body.length,
    });
    let status = 0, out = '';
    req.on('response', h => { status = +h[':status'] || 0; });
    req.setEncoding('utf8');
    req.on('data', d => { out += d; });
    req.on('error', () => { try { client.close(); } catch {} resolve({ ok: false }); });
    req.on('end', () => {
      try { client.close(); } catch {}
      if (status === 200) return resolve({ ok: true });
      let reason = ''; try { reason = (JSON.parse(out) || {}).reason || ''; } catch {}
      /* 알림 쪽과 같은 규칙 — 환경이 안 맞으면 반대쪽 서버로 한 번 더 */
      if (!hostIdx && (reason === 'BadDeviceToken' || reason === 'BadEnvironmentKeyInToken'))
        return resolve(apnsSendLive(token, payload, 1));
      /* 410 · Unregistered 는 <이 액티비티는 끝났다>는 뜻이다 — 토큰을 지운다 */
      if (status === 410 || reason === 'Unregistered' || reason === 'BadDeviceToken')
        try { db.prepare('DELETE FROM live_activities WHERE token=?').run(token); } catch {}
      resolve({ ok: false, status, reason });
    });
    req.end(body);
  });
}

/* 한 사람에게 지금 상태를 보낸다 */
function liveActivityPush(uid, state, { end = false } = {}) {
  if (!apnsReady()) return;
  const rows = db.prepare('SELECT token FROM live_activities WHERE user_id=?').all(uid);
  if (!rows.length) return;
  const payload = {
    aps: {
      timestamp: Math.floor(Date.now() / 1000),
      event: end ? 'end' : 'update',
      'content-state': state,
      ...(end ? { 'dismissal-date': Math.floor(Date.now() / 1000) + 300 } : {}),
      /* 잠금화면이 꺼져 있어도 한 줄 알리고 싶을 때만 넣는다 */
      ...(state.alert ? { alert: { title: state.title, body: state.sub || '' } } : {}),
    },
  };
  rows.forEach(r => { apnsSendLive(r.token, payload); });
}
/* 대진이 바뀌었을 때 그 대진에 있는 사람 모두에게 — 회차가 넘어갈 때 부른다 */
function liveActivityBroadcast(data, phase, extra) {
  if (!apnsReady() || !data) return;
  const tb = data.tb; if (!tb || !tb.startedAt) return;
  const unit = (data.tbUnit || 25), swap = (data.tbSwap || 5);
  const cyc = (unit + swap) * 60000;
  const idx = Math.floor((Date.now() - tb.startedAt) / cyc);
  const round = idx + 1, rounds = tb.rounds || 0;
  const playEnd = tb.startedAt + idx * cyc + unit * 60000;
  const swapEnd = tb.startedAt + (idx + 1) * cyc;
  const ids = new Set();
  (data.games || []).forEach(g => [...(g.teamA || []), ...(g.teamB || [])]
    .forEach(p => { if (p && p.id) ids.add(p.id); }));
  ids.forEach(uid => {
    const mine = (data.games || []).find(g => g.r === round &&
      [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === uid));
    const next = (data.games || []).find(g => g.r === round + 1 &&
      [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === uid));
    const court = mine ? (mine.playCourt || mine.c || null) : null;
    /* 카드 아래 칸에 쓸 값들 — 앱이 옵셔널로 받으므로 없으면 그냥 빠집니다 */
    const nm = t => (t || []).map(p => (p && p.id === uid) ? '나' : ((p && p.name) || ''))
      .filter(Boolean).join(' · ');
    const iAmA = mine && (mine.teamA || []).some(p => p && p.id === uid);
    const finAt = tb.startedAt + rounds * cyc - swap * 60000;
    liveActivityPush(uid, {
      phase, round, rounds, court,
      endsAt: Math.floor((phase === 'swap' ? swapEnd : playEnd) / 1000),
      title: phase === 'swap'
        ? (next ? `${next.playCourt || next.c}번 코트로` : `${round + 1}회차는 쉬어요`)
        : (court ? `${court}번 코트` : `${round}회차는 쉬어요`),
      sub: `${round}/${rounds}회차`,
      mine:   mine ? nm(iAmA ? mine.teamA : mine.teamB) : '',
      theirs: mine ? nm(iAmA ? mine.teamB : mine.teamA) : '',
      next:   next ? (next.playCourt || next.c || null) : null,
      endAll: rounds ? Math.floor(finAt / 1000) : 0,
      ...(extra || {}),
    });
  });
}
/* 점수를 넣어달라고 — 그 경기 넷에게만 */
function liveActivityAskScore(data, g) {
  if (!apnsReady() || !g) return;
  const court = g.playCourt || g.c || null;
  [...(g.teamA || []), ...(g.teamB || [])].forEach(p => {
    if (!p || !p.id) return;
    /* 카드에 <누구와 뛴 경기인지>가 있어야 여러 코트가 도는 날 헷갈리지 않는다 */
    const nm = t => (t || []).map(q => (q && q.id === p.id) ? '나' : ((q && q.name) || ''))
      .filter(Boolean).join(' · ');
    const iAmA = (g.teamA || []).some(q => q && q.id === p.id);
    liveActivityPush(p.id, {
      phase: 'score', round: g.r || 0, rounds: (data.tb && data.tb.rounds) || 0,
      court, endsAt: 0, alert: 1,
      title: court ? `${court}번 코트 점수를 넣어주세요` : '점수를 넣어주세요',
      sub: `${g.r || ''}회차`,
      mine:   nm(iAmA ? g.teamA : g.teamB),
      theirs: nm(iAmA ? g.teamB : g.teamA),
      next: null, endAll: 0,
    });
  });
}
/* 무엇이 비었는지 짚어 준다 — ready:false 만 보면 넷 중 어디가 문제인지 모른다 */
app.get('/admin/apns-status', admin, (_req, res) => {  // @external 내가 curl 로 부름
  const miss = [];
  if (!APNS.key) miss.push('APNS_KEY');
  if (!APNS.keyId) miss.push('APNS_KEY_ID');
  if (!APNS.teamId) miss.push('APNS_TEAM_ID');
  if (!APNS.bundleId) miss.push('APNS_BUNDLE_ID');
  let sign = null;
  if (apnsReady()) { try { apnsToken(); sign = 'ok'; }
    catch (e) { sign = '키를 읽지 못했어요 · ' + String(e.message || e).slice(0, 80); } }
  res.json({
    ready: apnsReady() && sign === 'ok',
    missing: miss,
    sign,
    hosts: APNS.hosts,
    bundle: APNS.bundleId,
    topic: APNS.bundleId ? APNS.bundleId + '.push-type.liveactivity' : null,
    live_tokens: db.prepare('SELECT COUNT(*) c FROM live_activities').get().c,
  });
});

/* ══════════ 애플워치 · 단축어 ══════════
   워치에는 브라우저가 없어 웹앱을 띄울 수 없다. 네이티브 워치 앱은 iOS 앱부터
   만들어야 해서 몇 달이 걸린다. 그동안 <애플 단축어>로 점수만 넣게 한다.
   단축어는 워치에서 돌고 HTTPS 요청을 보낼 수 있다.

   핵심은 <경기를 고르지 않아도 되게> 만드는 것이다.
   손목에서 코트와 회차를 고르게 하면 폰을 꺼내는 것보다 느리다.
   지금 회차에 내가 뛴 경기는 하나뿐이므로 서버가 찾는다. */
db.exec(`CREATE TABLE IF NOT EXISTS watch_tokens (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
  created_at INTEGER, last_used INTEGER);`);

app.get('/me/watch-token', auth, (req, res) => {
  const r = db.prepare('SELECT token, created_at, last_used FROM watch_tokens WHERE user_id=?')
    .get(req.uid);
  res.json(r || { token: null });
});
app.post('/me/watch-token', auth, (req, res) => {
  /* 한 사람에 하나 — 새로 만들면 옛 토큰은 못 쓰게 된다(워치를 잃어버렸을 때) */
  db.prepare('DELETE FROM watch_tokens WHERE user_id=?').run(req.uid);
  /* 예전에는 rid() 로 만들었는데, rid 는 <방금 INSERT 한 행의 id를 꺼내는> 함수라
     인자 없이 부르면 값이 나오지 않았다. 그래서 이 요청이 실패했고,
     앱은 실패를 조용히 삼켜 워치가 영영 <준비하고 있어요>에 머물렀다.
     열쇠는 남이 찍어 맞힐 수 없어야 하므로 난수로 만든다. */
  const token = crypto.randomBytes(24).toString('base64url');
  db.prepare('INSERT INTO watch_tokens (token,user_id,created_at) VALUES (?,?,?)')
    .run(token, req.uid, now());
  res.json({ token });
});
app.delete('/me/watch-token', auth, (req, res) => {
  db.prepare('DELETE FROM watch_tokens WHERE user_id=?').run(req.uid);
  res.json({ ok: true });
});

/* 지금 내가 점수를 넣어야 할 경기를 찾는다.
   ① 내가 속한 클럽들의 오늘 대진을 본다
   ② 시계가 돌고 있으면 <지금 회차 이하>에서, 아니면 아무 회차에서
   ③ 내가 뛰었고 점수가 빈 경기 중 가장 최근 회차 하나 */
function watchFindGame(uid) {
  const clubs = db.prepare(`SELECT club_id FROM club_members
    WHERE user_id=? AND (status IS NULL OR status='active')`).all(uid).map(r => r.club_id);
  for (const cid of clubs) {
    const rows = [
      ...db.prepare('SELECT data, event_id FROM club_brackets_ev WHERE club_id=? ORDER BY updated_at DESC LIMIT 3').all(cid),
      ...db.prepare('SELECT data, NULL event_id FROM club_brackets WHERE club_id=?').all(cid),
    ];
    for (const row of rows) {
      let data; try { data = JSON.parse(row.data); } catch (e) { continue; }
      const games = data.games || [];
      if (!games.length) continue;
      /* 시계가 돌고 있으면 지금 몇 회차인지 계산한다 */
      let curR = null;
      const tb = data.tb;
      if (tb && tb.startedAt) {
        const unit = (data.tbUnit || 25), swap = (data.tbSwap || 5);
        const cyc = (unit + swap) * 60000;
        const idx = Math.floor((Date.now() - tb.startedAt) / cyc);
        if (idx >= 0) curR = Math.min(idx + 1, tb.rounds || 99);
      }
      const mine = games
        .map((g, gi) => ({ g, gi }))
        .filter(({ g }) => (g.sa == null || g.sb == null)
          && [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === uid)
          && (curR == null || !g.r || g.r <= curR))
        .sort((a, b) => (b.g.r || 0) - (a.g.r || 0));
      if (mine.length) return { cid, event_id: row.event_id, data, ...mine[0], curR, count: mine.length };
    }
  }
  return null;
}
function watchAuth(req, res) {
  const t = String((req.body && req.body.token) || req.query.token || '').trim();
  if (!t) { res.status(401).json({ error: 'token_required', message: '토큰이 없어요' }); return null; }
  const row = db.prepare('SELECT user_id FROM watch_tokens WHERE token=?').get(t);
  if (!row) { res.status(401).json({ error: 'bad_token', message: '연결이 끊겼어요 · 앱에서 다시 연결해 주세요' }); return null; }
  db.prepare('UPDATE watch_tokens SET last_used=? WHERE token=?').run(now(), t);
  return row.user_id;
}
/* 지금 넣을 경기가 무엇인지 — 단축어가 먼저 물어보고 화면에 보여준다 */
app.get('/watch/now', (req, res) => {
  const uid = watchAuth(req, res); if (!uid) return;
  const f = watchFindGame(uid);
  if (!f) return res.json({ ok: false, message: '지금 넣을 점수가 없어요' });
  const nm = t => (t || []).map(p => p && p.name).filter(Boolean).join('·');
  const g = f.g;
  const me = [...(g.teamA || [])].some(p => p && p.id === uid);
  res.json({ ok: true, round: g.r || null, court: g.playCourt || g.c || null,
    us: nm(me ? g.teamA : g.teamB), them: nm(me ? g.teamB : g.teamA),
    more: f.count - 1 });
});
/* ══════════ 워치 앱 · 지금 상태 한 벌 ══════════
   컴플리케이션과 Smart Stack 위젯이 30초에 한 번 부르는 자리다.
   초 단위는 워치가 스스로 센다 — endsAt 만 주면 Text(timerInterval:) 이 흐른다.
   그래서 자주 불러도 값이 바뀌는 때는 회차가 넘어갈 때뿐이다. */
function watchFindRunning(uid) {
  const clubs = db.prepare(`SELECT club_id FROM club_members
    WHERE user_id=? AND (status IS NULL OR status='active')`).all(uid).map(r => r.club_id);
  for (const cid of clubs) {
    const rows = [
      ...db.prepare('SELECT data, event_id FROM club_brackets_ev WHERE club_id=? ORDER BY updated_at DESC LIMIT 3').all(cid),
      ...db.prepare('SELECT data, NULL event_id FROM club_brackets WHERE club_id=?').all(cid),
    ];
    for (const row of rows) {
      let data; try { data = JSON.parse(row.data); } catch (e) { continue; }
      const tb = data.tb; if (!tb || !tb.startedAt) continue;
      if (Date.now() - tb.startedAt > 8 * 3600e3) continue;   // 지난 대진은 건드리지 않는다
      const inIt = (data.games || []).some(g =>
        [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === uid));
      if (inIt) return { cid, data };
    }
  }
  return null;
}
app.get('/watch/state', (req, res) => {
  const uid = watchAuth(req, res); if (!uid) return;
  const out = { ok: true, on: false };

  const f = watchFindRunning(uid);
  if (f) {
    const { cid, data } = f, tb = data.tb;
    const unit = (data.tbUnit || 25), swap = (data.tbSwap || 5);
    const cyc = (unit + swap) * 60000;
    const rounds = tb.rounds || 0;
    const idx = Math.floor((Date.now() - tb.startedAt) / cyc);
    const round = idx + 1;
    const done = rounds > 0 && idx >= rounds;
    const into = (Date.now() - tb.startedAt) - idx * cyc;
    const playing = into < unit * 60000;
    const gs = data.games || [];
    const inG = g => [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === uid);
    const nm = t => (t || []).map(p => (p && p.id === uid) ? '나' : ((p && p.name) || ''))
      .filter(Boolean).join(' · ');
    const g = gs.find(x => x.r === round && inG(x));
    const gn = gs.find(x => x.r === round + 1 && inG(x));
    const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
    Object.assign(out, {
      on: !done,
      club: (club && club.name) || '',
      phase: done ? 'done' : (playing ? 'play' : 'swap'),
      round: Math.min(round, rounds || round), rounds,
      court: g ? (g.playCourt || g.c || null) : null,
      next:  gn ? (gn.playCourt || gn.c || null) : null,
      endsAt: Math.floor((tb.startedAt + idx * cyc + (playing ? unit * 60000 : cyc)) / 1000),
      endAll: rounds ? Math.floor((tb.startedAt + rounds * cyc - swap * 60000) / 1000) : 0,
      mine:   g ? nm((g.teamA || []).some(p => p && p.id === uid) ? g.teamA : g.teamB) : '',
      theirs: g ? nm((g.teamA || []).some(p => p && p.id === uid) ? g.teamB : g.teamA) : '',
      club_id: cid,
    });
  }

  /* 시즌 순위 — 대진이 없는 날에도 컴플리케이션에 띄울 것이 있어야 한다 */
  try {
    const cid = out.club_id || db.prepare(`SELECT club_id FROM club_members
      WHERE user_id=? AND (status IS NULL OR status='active') LIMIT 1`).get(uid)?.club_id;
    if (cid) {
      const rows = db.prepare(`SELECT u.id FROM club_members cm JOIN users u ON u.id=cm.user_id
        WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
        ORDER BY u.rating DESC, u.name`).all(cid);
      const pos = rows.findIndex(r => r.id === uid);
      if (pos >= 0) out.rank = { pos: pos + 1, of: rows.length };
      if (!out.club) {
        const c = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
        out.club = (c && c.name) || '';
      }
      /* 다음 모임 — 오늘 이후 가장 가까운 하나 */
      const ev = db.prepare(`SELECT id, title, date, time, tag FROM club_events
        WHERE club_id=? AND date >= ? ORDER BY date, time LIMIT 1`).get(cid, ymdOf(Date.now()));
      if (ev) {
        const cnt = db.prepare('SELECT COUNT(*) c FROM event_attendees WHERE event_id=?').get(ev.id);
        out.event = { date: ev.date, time: ev.time || '', tag: ev.tag || '',
                      title: ev.title || '', count: (cnt && cnt.c) || 0 };
      }
    }
  } catch (e) {}

  res.json(out);
});
/* 점수 넣기 — 단축어가 "6" 과 "3" 을 보낸다 */
app.post('/watch/score', (req, res) => {
  const uid = watchAuth(req, res); if (!uid) return;
  const us = Math.max(0, Math.min(9, parseInt((req.body || {}).us, 10) || 0));
  const them = Math.max(0, Math.min(9, parseInt((req.body || {}).them, 10) || 0));
  if (us === 0 && them === 0)
    return res.status(400).json({ ok: false, message: '0 : 0 은 저장할 수 없어요' });
  const f = watchFindGame(uid);
  if (!f) return res.status(404).json({ ok: false, message: '지금 넣을 점수가 없어요' });
  const { cid, event_id, data, g } = f;
  /* 나는 어느 편인가 — 워치는 <우리>와 <상대>로만 말한다 */
  const inA = (g.teamA || []).some(p => p && p.id === uid);
  g.sa = inA ? us : them;
  g.sb = inA ? them : us;
  g.by = uid; g.at = now(); g.atMs = Date.now(); g.byWatch = 1;
  if (event_id) db.prepare('UPDATE club_brackets_ev SET data=?, updated_at=? WHERE club_id=? AND event_id=?')
    .run(JSON.stringify(data), now(), cid, event_id);
  else db.prepare('UPDATE club_brackets SET data=?, updated_at=? WHERE club_id=?')
    .run(JSON.stringify(data), now(), cid);
  try { cbLog(cid, data); } catch (e) {}
  try { notifyNextUp(cid, data, g); } catch (e) {}
  /* 다음에 할 일을 함께 돌려준다 — 워치 화면에 그대로 뜬다 */
  const next = (data.games || []).filter(x => (x.sa == null || x.sb == null)
    && [...(x.teamA || []), ...(x.teamB || [])].some(p => p && p.id === uid))
    .sort((a, b) => (a.r || 0) - (b.r || 0))[0];
  res.json({ ok: true, score: `${us} : ${them}`,
    court: g.playCourt || g.c || null, round: g.r || null,
    next: next ? { round: next.r || null, court: next.playCourt || next.c || null } : null,
    message: `${us} : ${them} 기록했어요` });
});

/* 점수가 들어오면 그 코트의 <다음 차례> 네 명에게 알린다.
   코트에서 가장 자주 하는 말이 "다음 누구예요?" 인데, 지금은 앱을 열어야만 알 수 있다.
   알림함에는 안 남긴다(skipInbox) — 그날 지나면 의미 없는 이야기라 목록만 지저분해진다. */
function notifyNextUp(cid, data, doneGame) {
  const games = data.games || [];
  const at = x => x.playCourt || x.c;
  const court = at(doneGame);
  const done = x => x.sa != null && x.sb != null;
  /* 이 코트에서 아직 시작 안 한 경기 중 가장 앞 순서 */
  const next = games.filter(x => at(x) === court && !done(x) && !x.startedAt)
    .sort((a, b) => a.r - b.r)[0];
  if (!next) return;
  /* 그 넷이 지금 다른 코트에서 뛰고 있으면 아직 못 들어간다 — 그때는 알리지 않는다 */
  const busy = new Set(games.filter(x => x.startedAt && !done(x) && !x.endedAt && x !== next)
    .flatMap(x => [...(x.teamA || []), ...(x.teamB || [])].map(p => p && p.id)));
  const four = [...(next.teamA || []), ...(next.teamB || [])].filter(Boolean);
  if (four.some(p => busy.has(p.id))) return;
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  const names = four.map(p => p.name).join(' · ');
  four.forEach(p => {
    if (!p.id) return;                                  // 게스트는 계정이 없다
    sendPush(p.id, {
      icon: '🎾',
      title: `${court}번 코트로 가주세요`,
      body: `${next.r}번째 게임 · ${names}`,
      thread: 'bracket-' + cid,
      url: '/',
    }, { skipInbox: true });
  });
}
/* 경기 종료 — 점수는 나중에, 코트는 지금 열어준다.
   예전에는 점수가 들어와야 코트가 열려서, 점수 입력이 6분만 늦어도
   코트가 30분 넘게 놀았다(18명 3코트 시뮬 12분 → 32분).
   경기가 끝난 사람은 실제로 코트에서 나와 있으니, 끝났다는 사실만 먼저 받는다. */
app.patch('/clubs/:id/bracket2/end', auth, (req, res) => {
  const cid = +req.params.id;
  const role = cbRole(cid, req.uid);
  if (!role) return res.status(403).json({ error: 'member_only' });
  const { gi, undo } = req.body || {};
  const eid = evOf(req);
  const row = eid
    ? db.prepare('SELECT data FROM club_brackets_ev WHERE club_id=? AND event_id=?').get(cid, eid)
    : db.prepare('SELECT data FROM club_brackets WHERE club_id=?').get(cid);
  if (!row) return res.status(404).json({ error: 'no_bracket' });
  const data = JSON.parse(row.data);
  const g = (data.games || [])[gi];
  if (!g) return res.status(404).json({ error: 'no_game' });
  if (!g.startedAt) return res.status(400).json({ error: 'not_started', message: '아직 시작하지 않은 경기예요' });
  if (g.sa != null && g.sb != null) return res.status(400).json({ error: 'already_scored', message: '이미 점수가 들어왔어요' });
  const officer = role === 'owner' || role === 'officer';
  const inGame = [...(g.teamA || []), ...(g.teamB || [])].some(p => p && p.id === req.uid);
  if (!officer && !inGame) return res.status(403).json({ error: 'player_only', message: '그 경기를 뛴 분이나 운영진이 누를 수 있어요' });
  if (undo) { delete g.endedAt; delete g.endedBy; }
  else { g.endedAt = Date.now(); g.endedBy = req.uid; }
  if (eid) db.prepare('UPDATE club_brackets_ev SET data=?, updated_at=? WHERE club_id=? AND event_id=?').run(JSON.stringify(data), now(), cid, eid);
  else db.prepare('UPDATE club_brackets SET data=?, updated_at=? WHERE club_id=?').run(JSON.stringify(data), now(), cid);
  res.json({ ok: true, game: g });
});
/* 빈 코트로 경기 옮기기 — 회원도 할 수 있다.
   코트가 놀고 있는데 임원만 옮길 수 있으면, 그 사람이 코트를 못 보는 동안 코트가 계속 빈다.
   대신 조건을 좁게 잡는다:
     · 옮길 코트에 지금 도는 경기가 없어야 한다(정말 비어 있을 때만)
     · 아직 시작 안 한 경기만 옮긴다
     · 그 경기 넷이 모두 지금 다른 코트에서 뛰고 있지 않아야 한다
     · 옮기는 사람은 그 경기 선수 또는 임원
   같은 바퀴에 이미 경기가 있으면 코트를 맞바꾼다 — 표가 어긋나지 않게. */
app.patch('/clubs/:id/bracket2/court', auth, (req, res) => {
  const cid = +req.params.id;
  const role = cbRole(cid, req.uid);
  if (!role) return res.status(403).json({ error: 'member_only' });
  const { gi, court } = req.body || {};
  const eid = evOf(req);
  const row = eid
    ? db.prepare('SELECT data FROM club_brackets_ev WHERE club_id=? AND event_id=?').get(cid, eid)
    : db.prepare('SELECT data FROM club_brackets WHERE club_id=?').get(cid);
  if (!row) return res.status(404).json({ error: 'no_bracket' });
  const data = JSON.parse(row.data);
  const games = data.games || [];
  const g = games[gi];
  if (!g) return res.status(404).json({ error: 'no_game' });
  const c = +court;
  const done = x => x.sa != null && x.sb != null;
  const ids = x => [...(x.teamA || []), ...(x.teamB || [])].map(p => p && p.id).filter(Boolean);

  if (!(c >= 1 && c <= (data.courts || 0))) return res.status(400).json({ error: 'bad_court' });
  if ((data.offCourts || []).includes(c)) return res.status(400).json({ error: 'court_off', message: '사용 중지된 코트예요' });
  if ((g.playCourt || g.c) === c) return res.json({ ok: true, game: g });
  if (done(g) || g.startedAt) return res.status(400).json({ error: 'already_started', message: '이미 시작한 경기는 옮길 수 없어요' });

  const officer = role === 'owner' || role === 'officer';
  const mine = ids(g).includes(req.uid);
  if (!officer && !mine) return res.status(403).json({ error: 'player_only', message: '그 경기 선수나 운영진이 옮길 수 있어요' });

  /* 옮길 코트가 정말 비어 있나 — 그 코트에서 뛰는 중인 경기가 없어야 한다.
     playCourt 로 옮겨와 뛰는 경기까지 함께 본다. */
  const at = x => x.playCourt || x.c;
  if (games.some(x => at(x) === c && x.startedAt && !done(x) && !x.endedAt))
    return res.status(400).json({ error: 'court_busy', message: '그 코트는 지금 경기 중이에요' });
  /* 이 경기 넷이 다른 코트에서 뛰고 있으면 옮겨도 못 시작한다 */
  const busy = new Set(games.filter(x => x.startedAt && !done(x)).flatMap(ids));
  if (ids(g).some(i => busy.has(i)))
    return res.status(400).json({ error: 'player_busy', message: '이 경기 선수 중에 지금 뛰고 있는 분이 있어요' });

  /* 대진표의 칸은 <순서>, 코트는 <어디서 뛰는지> — 원래 다른 정보다.
     칸을 옮기면 이미 끝난 경기가 엉뚱한 코트로 밀려나 기록이 틀어지고,
     줄을 새로 만들면 표에 빈 칸이 생겨 종이 대진표와 어긋난다.
     그래서 칸(r·c)은 그대로 두고 <이번엔 어디서 뛰는지>만 따로 남긴다. */
  g.playCourt = c;
  g.movedBy = req.uid; g.movedAtMs = Date.now();
  if (g.playCourt === g.c) { delete g.playCourt; delete g.movedBy; delete g.movedAtMs; }

  if (eid) db.prepare('UPDATE club_brackets_ev SET data=?, updated_at=? WHERE club_id=? AND event_id=?').run(JSON.stringify(data), now(), cid, eid);
  else db.prepare('UPDATE club_brackets SET data=?, updated_at=? WHERE club_id=?').run(JSON.stringify(data), now(), cid);
  res.json({ ok: true, game: g, swapped: other ? other.r : null });
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
      WHERE ea.event_id=? AND (ea.status IS NULL OR ea.status='going') ORDER BY u.name`).all(cid, ev.id);
    guests = db.prepare('SELECT id,name,gender,grade FROM event_guests WHERE event_id=? ORDER BY id').all(ev.id)
      .map(g => ({ user_id: null, name: g.name, gender: g.gender, grade: g.grade, is_guest: 1, guest_id: g.id }));
  }
  /* 참석자가 아직 없으면 명단은 비는 게 맞다.
     예전에는 여기서 회원 전체를 채워 넣었는데, 모임을 복제하면 아직 아무도
     참석을 안 눌렀는데 29명이 통째로 딸려왔다.
     <이 모임 참석자로 짜기>가 거짓이 되므로, 모임을 지정한 경우에는 비워 보낸다.
     모임 없이 부른 경우(클럽 전체 명단이 필요한 화면)에만 예전대로 채운다. */
  if ((!rows || !rows.length) && !ev) {
    rows = db.prepare(`SELECT u.id user_id, COALESCE(NULLIF(cm.alias,''), u.name) AS name, COALESCE(cm.gender_ov, u.gender) AS gender, u.photos, cm.grade, cm.is_captain, cm.role, u.sport_started, u.rating
      FROM club_members cm JOIN users u ON u.id=cm.user_id
      WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active') ORDER BY u.name`).all(cid);
  }
  if (!rows) rows = [];
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
  /* claim_name — 이름으로 짠 대진에서 본인이 고른 이름. 승인 화면에서 보여준다 */
  const rows = db.prepare(`SELECT u.id user_id, u.name, u.gender, u.region, u.rating,
      cm.claim_name, cm.claim_gid, u.sport_started
    FROM club_members cm JOIN users u ON u.id=cm.user_id
    WHERE cm.club_id=? AND cm.status='pending' ORDER BY cm.id`).all(cid);
  /* 그 이름으로 남은 경기가 몇 판인지도 함께 — 클럽장이 맞는지 판단할 근거가 된다 */
  const logs = db.prepare('SELECT data FROM club_bracket_logs WHERE club_id=?').all(cid);
  const cnt = {};
  logs.forEach(r => { let d; try { d = JSON.parse(r.data); } catch (e) { return; }
    (d.games || []).forEach(g => [g.teamA, g.teamB].forEach(t => (t || []).forEach(p => {
      if (p && /^g/i.test(String(p.id || ''))) cnt[String(p.id)] = (cnt[String(p.id)] || 0) + 1; }))); });
  res.json(rows.map(r => ({ ...r, claim_games: r.claim_gid ? (cnt[String(r.claim_gid)] || 0) : 0 })));
});
// 승인 / 거절 (임원진)
app.post('/clubs/:id/members/:uid/approve', auth, (req, res) => {
  const cid = +req.params.id, uid = intOrNull(req.params.uid);
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const ok = req.body && req.body.approve === false ? false : true;
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  if (ok) {
    /* 프리미엄 기능을 접었으므로 인원 제한도 없앤다.
       제한이 남아 있으면 이미 26명인 클럽이 회원을 한 명도 더 못 받는다
       (실제로 정회원 승인이 member_limit 으로 계속 막혔다). */
    const role = (req.body && req.body.role) === 'guest' ? 'guest' : 'member';
    const pend = db.prepare('SELECT claim_name, claim_gid FROM club_members WHERE club_id=? AND user_id=?').get(cid, uid) || {};
    db.prepare("UPDATE club_members SET status='active', role=?, joined_at=COALESCE(joined_at,?) WHERE club_id=? AND user_id=? AND status='pending'").run(role, now(), cid, uid);
    /* 이름으로 짠 대진에 있던 사람이면 그때 기록을 이어붙인다.
       link=false 로 보내면 잇지 않는다 — 동명이인일 때 클럽장이 고를 수 있어야 한다. */
    let linked = 0;
    const wantLink = !(req.body && req.body.link === false);
    if (wantLink && pend.claim_gid) linked = linkClubName(cid, pend.claim_gid, uid);
    sendPush(uid, { icon: '🎉', title: '가입 승인', body: role==='guest' ? `${club.name} 게스트로 함께하게 됐어요` : `${club.name} 정회원이 됐어요` });
    if (linked) sendPush(uid, { icon: '📘', title: '지난 기록이 이어졌어요',
      body: `${pend.claim_name} 이름으로 남아 있던 경기가 내 기록이 됐어요` });
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

/* ── 클럽 이름 변경 · 클럽 삭제 (클럽장 전용) ──────────────────────────
   앱에는 두 화면이 다 있는데 서버에 길이 없어 404 가 났다.
   이름 규칙은 POST /clubs 와 같은 것을 쓴다 — 만들 때는 막고 바꿀 때는
   통과하면, 금지한 이름이 이름 변경으로 우회된다.                      */
function clubOwnerGuard(cid, uid) {
  return !!db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, uid);
}
app.patch('/clubs/:id/name', auth, (req, res) => {
  const cid = +req.params.id;
  const club = db.prepare('SELECT name,sport FROM clubs WHERE id=?').get(cid);
  if (!club) return res.status(404).json({ error: 'no_club' });
  if (!clubOwnerGuard(cid, req.uid)) return res.status(403).json({ error: 'owner_only' });

  const name = cleanName(req.body && req.body.name, '').slice(0, 24);
  if (!name) return res.status(400).json({ error: 'name_required', message: '클럽 이름을 입력해 주세요' });
  if (name.length < 2)
    return res.status(400).json({ error: 'name_short', message: '클럽 이름은 2자 이상이어야 해요' });
  if (/^[ㄱ-ㅎㅏ-ㅣ]+$/.test(name))
    return res.status(400).json({ error: 'name_jamo', message: '자음·모음만으로는 만들 수 없어요' });
  if (/^(.)\1*$/.test(name))
    return res.status(400).json({ error: 'name_repeat', message: '같은 글자만 반복할 수 없어요' });
  if (!/[가-힣a-zA-Z0-9]/.test(name))
    return res.status(400).json({ error: 'name_invalid', message: '클럽 이름을 다시 확인해 주세요' });
  const bad = findContact(name);
  if (bad) return res.status(400).json({ error: 'contact_blocked', reason: bad });

  if (name === club.name) return res.json({ ok: true, name });
  /* 같은 종목 안에서만 겹치면 안 된다 — 자기 자신은 검사에서 뺀다 */
  const dup = db.prepare('SELECT 1 FROM clubs WHERE name=? AND sport=? AND id<>?').get(name, club.sport, cid);
  if (dup) return res.status(409).json({ error: 'name_taken', message: '이미 있는 클럽 이름이에요' });

  db.prepare('UPDATE clubs SET name=? WHERE id=?').run(name, cid);
  /* 앱은 클럽을 이름으로 찾는 곳이 많다 — 회원들이 옛 이름을 계속 들고 있지
     않도록 알림을 보내 다시 받아 가게 한다 */
  db.prepare("SELECT user_id FROM club_members WHERE club_id=? AND COALESCE(status,'active')='active'")
    .all(cid)
    .forEach(m => { if (m.user_id !== req.uid) sendPush(m.user_id,
      { icon: '✏️', title: '클럽 이름이 바뀌었어요', body: `${club.name} → ${name}` }); });
  res.json({ ok: true, name });
});

app.delete('/clubs/:id', auth, (req, res) => {
  const cid = +req.params.id;
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  if (!club) return res.status(404).json({ error: 'no_club' });
  if (!clubOwnerGuard(cid, req.uid)) return res.status(403).json({ error: 'owner_only' });

  /* 나 말고 정회원이 남아 있으면 지우지 않는다 — 남의 기록까지 사라지기 때문이다.
     가입 신청(pending)만 남은 건 회원이 아니므로 막지 않고 같이 정리한다. */
  const others = db.prepare(`SELECT COUNT(*) n FROM club_members
      WHERE club_id=? AND user_id<>? AND COALESCE(status,'active')='active'`).get(cid, req.uid).n;
  if (others > 0)
    return res.status(409).json({ error: 'members_left', count: others,
      message: '아직 회원이 남아 있어요' });

  /* 딸린 자료를 손으로 지운다. 표가 없거나 열 이름이 다른 경우가 있어
     한 줄씩 감싼다 — 하나 실패했다고 삭제 전체가 멈추면 반쪽만 지워진다. */
  const wipe = (sql, ...args) => { try { db.prepare(sql).run(...args); } catch (e) {} };
  const ids = (sql, ...args) => { try { return db.prepare(sql).all(...args).map(r => r.id); } catch (e) { return []; } };

  const evIds   = ids('SELECT id FROM club_events WHERE club_id=?', cid);
  const postIds = ids('SELECT id FROM club_posts  WHERE club_id=?', cid);
  const noticeIds = ids('SELECT id FROM notices   WHERE club_id=?', cid);
  const brIds   = ids('SELECT id FROM brackets    WHERE club_id=?', cid);
  const each = (list, sql) => list.forEach(v => wipe(sql, v));

  each(evIds, 'DELETE FROM event_attendees WHERE event_id=?');
  each(evIds, 'DELETE FROM event_guests    WHERE event_id=?');
  each(evIds, 'DELETE FROM event_comments  WHERE event_id=?');
  each(evIds, 'DELETE FROM event_reactions WHERE event_id=?');
  each(evIds, 'DELETE FROM exchange_games  WHERE event_id=?');
  each(postIds, 'DELETE FROM feed_comments WHERE post_id=?');
  each(postIds, 'DELETE FROM feed_likes    WHERE post_id=?');
  each(postIds, 'DELETE FROM post_likes    WHERE post_id=?');
  each(noticeIds, 'DELETE FROM notice_votes WHERE notice_id=?');
  each(brIds, 'DELETE FROM bracket_scores  WHERE bracket_id=?');
  each(brIds, 'DELETE FROM bracket_timers  WHERE bracket_id=?');

  [ 'brackets', 'club_accounts', 'club_bracket_logs', 'club_brackets', 'club_brackets_ev',
    'club_chat', 'club_chat_reads', 'club_court_slots', 'club_events', 'club_expenses',
    'club_invites', 'club_league', 'club_logos', 'club_members', 'club_peer_reviews',
    'club_posts', 'club_team_matches', 'club_tiers', 'deposits', 'dues', 'exchange_entries',
    'grade_changes', 'guest_links', 'live_activities', 'member_exits', 'monthly_results',
    'notices', 'rest_requests',
  ].forEach(t => wipe(`DELETE FROM ${t} WHERE club_id=?`, cid));

  db.prepare('DELETE FROM clubs WHERE id=?').run(cid);
  console.log(`[clubs] 삭제 id=${cid} name=${club.name} by uid=${req.uid}`);
  res.json({ ok: true });
});
app.get('/me/clubs', auth, (req, res) => {
  /* 내 클럽 목록에서도 성별 배지가 나와야 해서 같은 숫자를 함께 내려준다 */
  const GQ = `(SELECT COUNT(*) FROM club_members m JOIN users u ON u.id=m.user_id
      WHERE m.club_id=c.id AND (m.status IS NULL OR m.status='active')
        AND COALESCE(m.role,'') <> 'guest' AND `;
  res.json(db.prepare(`SELECT c.*, cm.role, cm.status,
      (SELECT COUNT(*) FROM club_members x JOIN users xu ON xu.id=x.user_id
        WHERE x.club_id=c.id AND (x.status IS NULL OR x.status='active')
          AND COALESCE(xu.is_test,0)=0) member_count,
      ${GQ} COALESCE(NULLIF(m.gender_ov,''), u.gender)='F') g_f,
      ${GQ} COALESCE(NULLIF(m.gender_ov,''), u.gender)='M') g_m,
      ${GQ} COALESCE(NULLIF(m.gender_ov,''), u.gender, '') NOT IN ('F','M')) g_unknown
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
  /* 이름은 클럽 명단에 적힌 것(cm.alias)을 먼저 쓴다.
     계정 이름은 소셜 로그인 닉네임이라 "L군^^" 처럼 클럽에서 안 쓰는 이름이 들어간다. */
  const byStatus = (eid, st) => db.prepare(`SELECT COALESCE(NULLIF(cm.alias,''), u.name) AS name
    FROM event_attendees ea JOIN users u ON u.id=ea.user_id
    LEFT JOIN club_members cm ON cm.club_id=? AND cm.user_id=u.id
    WHERE ea.event_id=? AND ${st === 'going' ? "(ea.status IS NULL OR ea.status='going')" : 'ea.status=?'}
    ORDER BY name`)
    .all(...(st === 'going' ? [cid, eid] : [cid, eid, st])).map(r => r.name);
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
  /* 구장을 목록에서 골랐으면 그 번호를 함께 저장한다 —
     글자만으로는 <용인테니스파크> 와 <용인 테니스 파크> 가 다른 곳이 된다. */
  /* 구장을 목록에서 골랐으면 번호를, 못 골랐으면 이름으로 한 번 더 찾아본다.
     그래야 <용인테니스파크> 와 <용인 테니스 파크> 가 같은 곳이 된다. */
  let vid = req.body && req.body.venue_id ? +req.body.venue_id : null;
  if (!vid && place) {
    const nm = String(place).replace(/\s+/g, '');
    const hit = db.prepare(`SELECT id FROM venues WHERE active=1
      AND REPLACE(name,' ','')=? LIMIT 1`).get(nm);
    if (hit) vid = hit.id;
  }
  const r = db.prepare(`INSERT INTO club_events (club_id,title,date,tag,place,venue_id,created_by,created_at)
                        VALUES (?,?,?,?,?,?,?,?)`)
    .run(cid, String(title), String(date || ''), String(tag || '정기'),
         String(place || '').trim().slice(0, 60) || null, vid, req.uid, now());
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
  const vid2 = req.body && req.body.venue_id ? +req.body.venue_id : null;
  db.prepare('UPDATE club_events SET title=?, date=?, place=?, venue_id=COALESCE(?,venue_id) WHERE id=?')
    .run(title, date, place || null, vid2, eid);
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
  /* 누가 눌렀는지 이름까지 — 숫자만 있으면 <누가 봤나> 를 알 수 없다.
     클럽은 서로 아는 사이라 이름이 보이는 편이 자연스럽다. */
  const rows = db.prepare(`SELECT r.comment_id, r.emoji, r.user_id,
      COALESCE(NULLIF(m.alias,''), u.name) AS name
    FROM comment_reactions r
    JOIN event_comments c ON c.id=r.comment_id
    LEFT JOIN users u ON u.id=r.user_id
    LEFT JOIN club_events e ON e.id=c.event_id
    LEFT JOIN club_members m ON m.club_id=e.club_id AND m.user_id=r.user_id
    WHERE c.event_id=? ORDER BY r.id`).all(+req.params.id);
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
  const raw = req.body && req.body.status;
  /* 누른 버튼을 다시 누르면 응답을 지운다 — <아직 답하지 않은> 상태로 되돌린다.
     예전에는 세 값 중 하나로만 갈 수 있어서, 잘못 누르면 되돌릴 길이 없었다.
     불참으로 남겨두는 것과 <아직 안 정했다>는 명단상 뜻이 다르다. */
  if (raw === null || raw === 'none' || raw === '') {
    db.prepare('DELETE FROM event_attendees WHERE event_id=? AND user_id=?').run(eid, req.uid);
    return res.json({ ok: true, status: null, count: goingCount(eid) });
  }
  const st = ['going', 'absent', 'undecided'].includes(raw) ? raw : 'going';
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
/* ══════════════════════════════════════════════════════════════
   오픈매치 티어 — 개인리그를 접고 티어를 오픈매치로 옮긴다.

   티어는 <경기 결과>로만 정한다. 상호평가는 쓰지 않는다.
   오픈매치 로테이션이 모든 사람과 한 번씩 파트너를 시키므로
   파트너 운이 라운드를 도는 사이 저절로 평균화되고,
   남는 것은 그 사람 자신의 기여뿐이다.
   ══════════════════════════════════════════════════════════════ */

// 티어 경계 — 전국 단일 분포. 지역별로 나누면 동네마다 그랜드슬램이 나온다.
const TIER_CUT = [
  { k: 'gs',   n: '그랜드슬램', top: 0.01, subs: 0 },
  { k: 'tour', n: '마스터스',   top: 0.10, subs: 3 },
  { k: 'chal', n: '챌린저',     top: 0.55, subs: 3 },
  { k: 'fut',  n: '퓨처스',     top: 1.00, subs: 3 },
];
const TIER_MIN_GAMES = 2;                 // 이만큼 뛰어야 배치된다 (그 전에는 러브)
const TIER_ORDER = ['love', 'fut', 'chal', 'tour', 'gs'];

/* 복식 오픈매치가 주력이라 rating_doubles 를 본다.
   경기 수는 그 사람이 실제로 뛴 확정 경기만 센다. */
function tierGames(uid) {
  try {
    return db.prepare(`SELECT COUNT(*) n FROM matches
      WHERE status='confirmed' AND (home_user_id=? OR away_user_id=?)`).get(uid, uid).n;
  } catch (e) { return 0; }
}
/* 전국 백분위 — 나보다 레이팅이 높은 사람이 몇 %인가.
   배치된 사람만 모집단에 넣는다. 러브까지 섞으면 분포가 아래로 눌린다. */
function tierPercentile(rating) {
  const row = db.prepare(`SELECT
      (SELECT COUNT(*) FROM users WHERE suspended IS NOT 1 AND COALESCE(rating_doubles,1000) > ?) hi,
      (SELECT COUNT(*) FROM users WHERE suspended IS NOT 1) tot`).get(rating);
  if (!row || !row.tot) return 1;
  return row.hi / row.tot;                              // 0 = 최상위 · 1 = 최하위
}
/* 세부 단계 1·2·3 — 숫자가 작을수록 위.
   그 티어 구간 안에서 내가 어디쯤인지로 가른다. */
function tierSub(pct, loIdx) {
  const lo = loIdx === 0 ? 0 : TIER_CUT[loIdx - 1].top;
  const hi = TIER_CUT[loIdx].top;
  const span = hi - lo || 1;
  const rel = Math.min(0.999, Math.max(0, (pct - lo) / span));   // 0 = 그 구간의 위쪽
  return 1 + Math.floor(rel * 3);                                // 1 · 2 · 3
}
function tierOf(uid) {
  const u = getUser(uid);
  if (!u) return { key: 'love', name: '러브', sub: 0, label: '러브', games: 0, placed: false };
  const games = tierGames(uid);
  if (games < TIER_MIN_GAMES)
    return { key: 'love', name: '러브', sub: 0, label: '러브',
      games, placed: false, need: TIER_MIN_GAMES - games };
  const pct = tierPercentile(u.rating_doubles || 1000);
  const i = TIER_CUT.findIndex(t => pct <= t.top);
  const T = TIER_CUT[i < 0 ? TIER_CUT.length - 1 : i];
  const idx = i < 0 ? TIER_CUT.length - 1 : i;
  const sub = T.subs ? tierSub(pct, idx) : 0;
  return {
    key: T.k, name: T.n, sub, label: sub ? `${T.n} ${sub}` : T.n,
    games, placed: true, pct: Math.round(pct * 1000) / 10,
    /* 경기가 적으면 티어가 자주 바뀐다 — 화면에서 미리 알려주기 위한 값 */
    settled: games >= 10,
  };
}
const tierRank = k => Math.max(0, TIER_ORDER.indexOf(k));
/* 매치가 요구하는 티어 범위 안에 드는가. 러브는 어디든 들어갈 수 있다 —
   배치되려면 2경기를 뛰어야 하는데 못 들어가면 영영 배치되지 않는다. */
function tierFits(t, lo, hi) {
  if (!t.placed) return true;
  const r = tierRank(t.key);
  if (lo && r < tierRank(lo)) return false;
  if (hi && r > tierRank(hi)) return false;
  return true;
}
app.get('/me/tier', auth, (req, res) => res.json(tierOf(req.uid)));

/* ── 경기 결과 요약 ──
   왜 그 티어가 됐는지 근거를 함께 준다. 티어만 툭 바뀌면
   사람들은 시스템이 고장 난 줄 알거나, 아무 의미 없다고 여긴다. */
app.get('/open-matches/:id/result', auth, (req, res) => {
  const mid = +req.params.id;
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const join = db.prepare('SELECT * FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid);
  if (!join) return res.status(403).json({ error: 'not_joined' });

  /* 이 매치의 대진에서 내 성적을 센다 — 점수가 들어온 게임만 */
  let win = 0, lose = 0, margin = 0, played = 0;
  const meNm = (getUser(req.uid) || {}).name;
  let br = null; try { br = JSON.parse(m.bracket || 'null'); } catch (e) {}
  const games = [];
  if (br && Array.isArray(br.courts)) br.courts.forEach(c => (c.rounds || []).forEach(g => games.push(g)));
  games.forEach(g => {
    if (g.sa == null || g.sb == null) return;
    const inA = (g.a || []).includes(meNm), inB = (g.b || []).includes(meNm);
    if (!inA && !inB) return;
    played++;
    const my = inA ? g.sa : g.sb, op = inA ? g.sb : g.sa;
    if (my > op) win++; else if (my < op) lose++;
    margin += (my - op);
  });

  /* 이 매치 전후로 티어가 어떻게 움직였나 — rating_log 로 되짚는다 */
  const t = tierOf(req.uid);
  const startMs = Date.parse(String(m.start_at || '').slice(0, 16) + ':00+09:00');
  const logs = db.prepare(`SELECT delta, rating, created_at FROM rating_log
    WHERE user_id=? ORDER BY id DESC LIMIT 20`).all(req.uid);
  const after = logs.find(l => isNaN(startMs) || l.created_at >= startMs - 3600e3);
  const before = after ? logs[logs.indexOf(after) + 1] : null;
  const delta = after ? after.delta : 0;

  /* 함께 뛴 사람들의 티어 — 상대가 강했는지 보여주기 위해서 */
  const opponents = db.prepare(`SELECT user_id FROM open_match_joins WHERE match_id=? AND user_id!=?`)
    .all(mid, req.uid).map(r => tierOf(r.user_id).label);

  res.json({
    match: { id: m.id, loc: m.loc, dt: m.dt, start_at: m.start_at, mode: m.mode, disc: m.disc },
    played, win, lose, margin,
    tier: t, delta,
    /* 배치가 방금 일어났는가 — "러브 → 퓨처스 2" 를 보여줄지 판단한다 */
    just_placed: t.placed && t.games <= TIER_MIN_GAMES,
    prev_rating: before ? before.rating : null,
    opponents,
    /* 캐시 환급 — 확정 때 돌려준 차액 */
    refund: join.refund || 0,
    manner_done: !!db.prepare('SELECT 1 FROM om_manner WHERE match_id=? AND from_id=?').get(mid, req.uid),
  });
});

/* ── 마감 처리 ──
   마감 시각에 딱 한 번 계산한다. 중간에 5명 됐다가 4명으로 줄 수 있는데,
   그때마다 환급하면 이미 돌려준 돈을 다시 청구해야 하고 그건 불가능하다. */
function omSettle(mid) {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
  if (!m || m.confirmed_at || (m.status && m.status !== 'open')) return null;
  const joins = db.prepare('SELECT * FROM open_match_joins WHERE match_id=? ORDER BY id').all(mid);
  const need = omMinCount(m);

  /* 미달 — 예약이 확정된 적이 없으니 업체에도 과금되지 않는다 */
  if (joins.length < need) {
    db.prepare("UPDATE open_matches SET status='cancelled', refunded_at=? WHERE id=?").run(now(), mid);
    joins.forEach(j => {
      if (j.paid > 0) cashAdd(j.user_id, j.paid, 'om_cancel_refund');
      sendPush(j.user_id, { icon: '🔔', title: '매치가 취소됐어요',
        body: `${m.loc} · 인원이 모이지 않아 전액 환불했어요` });
    });
    return { ok: true, cancelled: true, refunded: joins.length };
  }

  /* 확정 — 인원이 정해졌으니 그 인원의 가격을 적용하고 차액을 캐시로 돌려준다.
     현금 부분취소가 아니라 캐시인 이유: PG 수수료를 잃지 않고, 돈이 앱 안에 남는다. */
  const finalPrice = omPriceFor(m, joins.length);
  let refunded = 0;
  tx(() => {
    db.prepare("UPDATE open_matches SET status='confirmed', confirmed_at=? WHERE id=?").run(now(), mid);
    joins.forEach(j => {
      const diff = (j.paid || 0) - finalPrice;
      if (diff > 0) {
        cashAdd(j.user_id, diff, 'om_price_refund');
        db.prepare('UPDATE open_match_joins SET refund=? WHERE id=?').run(diff, j.id);
        refunded += diff;
      }
      sendPush(j.user_id, { icon: '✅', title: '매치가 확정됐어요', link: `match:${m.id}`,
        body: diff > 0
          ? `${joins.length}명이 모여 ${finalPrice.toLocaleString()}원으로 내려갔어요 · ${diff.toLocaleString()}원 돌려드렸어요`
          : `${m.loc} · ${m.dt}` });
    });
  });
  return { ok: true, confirmed: true, people: joins.length, price: finalPrice, refunded };
}
/* 캐시 지급 한 곳으로 모은다 — 장부(cash_ledger)를 빠뜨리면 잔액이 안 맞는다 */
function cashAdd(uid, amount, reason) {
  if (!amount) return;
  const u = getUser(uid); if (!u) return;
  const bal = (u.cash || 0) + amount;
  db.prepare('UPDATE users SET cash=? WHERE id=?').run(bal, uid);
  db.prepare('INSERT INTO cash_ledger (user_id,delta,reason,balance_after,created_at) VALUES (?,?,?,?,?)')
    .run(uid, amount, reason, bal, now());
}
/* 마감 시각이 지난 매치를 훑는다 — 10분마다 */
function omSweep() {
  try {
    const due = db.prepare(`SELECT id FROM open_matches
      WHERE status='open' AND close_at IS NOT NULL AND close_at <= ?`).all(new Date().toISOString().slice(0, 16));
    due.forEach(r => { try { omSettle(r.id); } catch (e) { console.error('[om] 마감 실패', r.id, e.message); } });
    if (due.length) console.log('[om] 마감 처리', due.length, '건');
  } catch (e) { console.error('[om] sweep', e.message); }
}
setInterval(omSweep, 10 * 60 * 1000);
setTimeout(omSweep, 20 * 1000);
/* 운영자가 손으로 마감시킬 수 있다 — 시각을 기다리지 않고 확인할 때 */
app.post('/admin/open-matches/:id/settle', admin, (req, res) => {
  const r = omSettle(+req.params.id);
  res.json(r || { ok: false, reason: '이미 처리됐거나 없는 매치예요' });
});

/* 매너 확인 — 기본값은 "다들 괜찮았어요". 문제가 있을 때만 사람을 고른다. */
app.post('/open-matches/:id/manner', auth, (req, res) => {
  const mid = +req.params.id;
  const joined = db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid);
  if (!joined) return res.status(403).json({ error: 'not_joined' });
  const b = req.body || {};
  const ins = db.prepare(`INSERT OR REPLACE INTO om_manner
    (match_id,from_id,target_id,kind,created_at) VALUES (?,?,?,?,?)`);
  if (b.ok) { ins.run(mid, req.uid, null, 'ok', now()); }
  else {
    const targets = (Array.isArray(b.targets) ? b.targets : []).map(intOrNull).filter(Boolean);
    targets.forEach(t => { if (t !== req.uid) ins.run(mid, req.uid, t, 'bad', now()); });
  }
  if (intOrNull(b.mvp)) ins.run(mid, req.uid, intOrNull(b.mvp), 'mvp', now());
  res.json({ ok: true });
});

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
  /* 장소 이름으로 구장을 찾아 땅 딱지를 붙인다.
     오픈매치는 개인이 모이는 자리라 <땅에 반영하지는 않는다> —
     클럽 이름으로 나온 게 아니니까. 딱지는 보여주기만 한다. */
  const landTag = (() => {
    const names = [...new Set(rows.map(m => String(m.loc || '').replace(/\s+/g, '')).filter(Boolean))];
    if (!names.length) return () => null;
    const ph = names.map(() => '?').join(',');
    const vs = db.prepare(`SELECT id, name FROM venues WHERE active=1
      AND REPLACE(name,' ','') IN (${ph})`).all(...names);
    if (!vs.length) return () => null;
    const byName = {}; vs.forEach(v => { byName[v.name.replace(/\s+/g, '')] = v.id; });
    const ids = vs.map(v => v.id);
    const own = {};
    db.prepare(`SELECT l.venue_id, l.depth, c.id club_id, c.name club FROM land l
      JOIN clubs c ON c.id=l.club_id WHERE l.venue_id IN (${ids.map(() => '?').join(',')})
      ORDER BY l.depth DESC`).all(...ids)
      .forEach(l => { if (!own[l.venue_id]) own[l.venue_id] = l; });
    /* 내가 속한 클럽들 — <우리 땅> 인지 가리는 데 쓴다 */
    const myClubs = uid ? db.prepare(`SELECT club_id FROM club_members WHERE user_id=?`)
      .all(uid).map(r => r.club_id) : [];
    return loc => {
      const vid = byName[String(loc || '').replace(/\s+/g, '')];
      if (!vid) return null;
      const o = own[vid];
      if (!o) return { t: '빈 구장', k: 'empty' };
      if (myClubs.includes(o.club_id)) return { t: '우리 땅', k: 'mine' };
      return { t: `${o.club} 땅`, k: 'rival' };
    };
  })();
  res.json(rows.map(m => {
    const v = omView(m, uid);
    if (m.host_id) {
      if (!fpCache[m.host_id]) fpCache[m.host_id] = fairplayOf(m.host_id);
      v.host_fp = fpCache[m.host_id].score;
      v.host_fp_n = fpCache[m.host_id].reviews;
    }
    v.land = landTag(m.loc);
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
  /* 1코트 자율 매치는 아래 소셜매치 규칙을 타지 않는다.
     그 규칙은 1코트를 2코트로 올리고(매니저 전제) 정원·가격을 자기 공식으로 덮어써서,
     자율 매치를 열려고 하면 조건이 어긋나 열리지 않았다. */
  const _selfMode = (_b.mode === 'self') || (_courts === 1);
  if (_courts && !_selfMode) {                            // 코트 기반 소셜 매치 규칙
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
  /* ── 티어 개편 값 ──
     종목(남복·여복·혼복)과 티어 범위를 여기서 못 받으면 목록에서 거를 수가 없다.
     혼복은 남녀 칸을 나눠 잠근다 — 선착순으로 받으면 남자만 4명 찬 혼복이 생긴다. */
  {
    const b2 = req.body || {};
    const nCourts = intOrNull(b2.courts) || 1;
    const mode = (b2.mode === 'managed' || nCourts > 1) ? 'managed' : 'self';
    const disc = ['mixed', 'men', 'women'].includes(b2.disc) ? b2.disc : 'mixed';
    const TK = ['love', 'fut', 'chal', 'tour', 'gs'];
    const tmin = TK.includes(b2.tier_min) ? b2.tier_min : null;
    const tmax = TK.includes(b2.tier_max) ? b2.tier_max : null;
    const capN = intOrNull(b2.cap) || (mode === 'managed' ? 8 : 4);
    let cm = intOrNull(b2.cap_m), cf = intOrNull(b2.cap_f);
    if (disc === 'men')   { cm = capN; cf = 0; }
    if (disc === 'women') { cm = 0; cf = capN; }
    if (disc === 'mixed' && (cm == null || cf == null)) { cm = Math.ceil(capN / 2); cf = capN - cm; }
    /* 마감은 시작 24시간 전 — 취소되어도 주말 일정을 다시 짤 수 있다 */
    let closeAt = b2.close_at || null;
    if (!closeAt && b2.start_at) {
      const st = Date.parse(String(b2.start_at).slice(0, 16) + ':00+09:00');
      if (!isNaN(st)) closeAt = new Date(st - 24 * 3600e3 + 9 * 3600e3).toISOString().slice(0, 16);
    }
    db.prepare(`UPDATE open_matches SET mode=?, disc=?, cap_m=?, cap_f=?,
        tier_min=?, tier_max=?, close_at=?, fee_rate=?, base_price=? WHERE id=?`)
      .run(mode, disc, cm, cf, tmin, tmax, closeAt,
           (b2.fee_rate != null ? +b2.fee_rate : null), null, mid);
    const fresh = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
    db.prepare('UPDATE open_matches SET base_price=? WHERE id=?')
      .run(omPriceFor(fresh, omMinCount(fresh)), mid);
  }
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

  const me = getUser(req.uid);
  /* 성별이 없으면 남복·여복을 거를 수 없다 — 신청 전에 받아야 한다.
     관리자 화면에 성별 없는 회원이 이미 여럿 있다. */
  if (!me.gender && m.disc && m.disc !== 'any')
    return res.status(400).json({ error: 'gender_required', message: '성별을 먼저 입력해 주세요' });
  if (m.disc === 'men'   && me.gender !== 'M')
    return res.status(403).json({ error: 'men_only',   message: '남자복식 매치예요' });
  if (m.disc === 'women' && me.gender !== 'F')
    return res.status(403).json({ error: 'women_only', message: '여자복식 매치예요' });
  /* 티어로 막지 않는다 — 초기에는 4명을 모으는 일이 실력을 맞추는 일보다 급하다.
     제한을 걸면 정원이 안 차 취소되고, 취소가 반복되면 사람이 먼저 떠난다.
     티어는 카드에 <지금 누가 모였나>로 보여주고 판단은 본인에게 맡긴다.
     매치가 충분히 많아지면 tier_min/max 를 채워 넣는 것만으로 제한을 켤 수 있다. */

  // 두 사람이 마지막 한 자리에 동시에 신청해도 정원을 넘기지 않도록 잠근다
  try {
    tx(() => {
      const already = db.prepare('SELECT 1 FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid);
      if (!already) {
        const cur = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n;
        if (cur >= (m.cap || 8)) throw new Error('full');
        /* 혼복은 성별 칸을 따로 잠근다 — 남은 자리가 있어도 내 성별 칸이 찼으면 못 들어간다 */
        if (m.disc === 'mixed') {
          const caps = omCaps(m), fill = omFilled(mid);
          if (me.gender === 'M' && fill.m >= caps.m) throw new Error('men_full');
          if (me.gender === 'F' && fill.f >= caps.f) throw new Error('women_full');
        }
      }
      db.prepare('INSERT OR IGNORE INTO open_match_joins (match_id,user_id,joined_at,paid) VALUES (?,?,?,?)')
        .run(mid, req.uid, now(), omPriceFor(m, omMinCount(m)));
      /* 첫 신청자가 모임장이 된다 — 권한이 아니라 역할이다 */
      if (!m.leader_id) db.prepare('UPDATE open_matches SET leader_id=? WHERE id=?').run(req.uid, mid);
    });
  } catch (e) {
    if (e.message === 'full') return res.status(409).json({ error: 'full', cap: m.cap });
    if (e.message === 'men_full')   return res.status(409).json({ error: 'men_full',   message: '남성 자리가 찼어요' });
    if (e.message === 'women_full') return res.status(409).json({ error: 'women_full', message: '여성 자리가 찼어요' });
    throw e;
  }
  const isNewJoin = db.prepare('SELECT joined_at FROM open_match_joins WHERE match_id=? AND user_id=?').get(mid, req.uid).joined_at > now() - 3000;

  const after = db.prepare('SELECT COUNT(*) n FROM open_match_joins WHERE match_id=?').get(mid).n;
  if (isNewJoin && m.host_id && m.host_id !== req.uid)
    sendPush(m.host_id, { icon: '🙋', title: '오픈매치 참가 신청', body: `${getUser(req.uid).name} 님 · ${after}/${m.cap}명` });
  // 최소 인원을 막 채웠으면 전원에게 성사 알림 (내 신청으로 정확히 채워진 경우)
  if (isNewJoin && after === (m.min_cnt || 0)) {
    db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(mid)
      .forEach(p => sendPush(p.user_id, { icon: '✅', title: '경기가 성사됐어요',
        body: `${m.dt} · ${m.loc} · ${after}명`, link: `match:${mid}` }));
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
  const rows = db.prepare(`SELECT ea.user_id, COALESCE(NULLIF(cm.alias,''), u.name) AS name,
      ea.status, ea.showed
    FROM event_attendees ea JOIN users u ON u.id=ea.user_id
    LEFT JOIN club_members cm ON cm.club_id=? AND cm.user_id=u.id
    WHERE ea.event_id=? ORDER BY name`).all(ev.club_id, eid);
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

/* ── 접속 지역 ─────────────────────────────────────────────────────
   어느 동네에서 쓰는지 알아야 클럽을 어디에 먼저 붙일지 정할 수 있다.

   IP 는 저장하지 않는다. 지역 이름만 남기고 IP 는 조회 캐시의 열쇠로만 쓴다.
   조회는 외부 API 를 타므로 절대 요청 처리를 막지 않는다 — 던져 두고 잊는다.
   같은 IP 는 캐시에서 꺼내므로 하루에 몇 번 안 부른다. */
try { db.exec('ALTER TABLE users ADD COLUMN last_region TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN last_region_at INTEGER'); } catch (e) {}
try { db.exec(`CREATE TABLE IF NOT EXISTS ip_geo (
  ip TEXT PRIMARY KEY, region TEXT, country TEXT, at INTEGER)`); } catch (e) {}

function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.ip || '';
}
/* 사설·로컬 대역은 조회해봐야 답이 없다 */
function localIp(ip) {
  return !ip || ip === '::1' || ip.startsWith('127.') || ip.startsWith('10.')
    || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}
const GEO_MEM = new Map();          // ip -> region (프로세스 캐시)
let GEO_CALLS = 0, GEO_MIN = 0;     // 분당 호출 상한
async function geoLookup(ip) {
  if (GEO_MEM.has(ip)) return GEO_MEM.get(ip);
  const row = db.prepare('SELECT region FROM ip_geo WHERE ip=?').get(ip);
  if (row && row.region) { GEO_MEM.set(ip, row.region); return row.region; }
  const m = Math.floor(Date.now() / 60000);
  if (m !== GEO_MIN) { GEO_MIN = m; GEO_CALLS = 0; }
  if (GEO_CALLS >= 30) return null;               // 무료 API 는 분당 45 — 여유를 둔다
  GEO_CALLS++;
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 3000);
    const r = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}`
      + '?fields=status,country,regionName,city&lang=ko', { signal: ac.signal });
    clearTimeout(t);
    const j = await r.json();
    if (!j || j.status !== 'success') return null;
    /* 한국은 <시도 · 시군구>, 해외는 <나라 · 도시> 로 적는다 */
    const region = j.country === '대한민국' || j.country === 'South Korea'
      ? [j.regionName, j.city].filter(Boolean).join(' ')
      : [j.country, j.city].filter(Boolean).join(' ');
    if (!region) return null;
    db.prepare('INSERT OR REPLACE INTO ip_geo (ip,region,country,at) VALUES (?,?,?,?)')
      .run(ip, region, String(j.country || ''), now());
    GEO_MEM.set(ip, region);
    return region;
  } catch (e) { return null; }
}
function geoTouch(uid, ip) {
  if (!uid || localIp(ip)) return;
  geoLookup(ip).then(region => {
    if (!region) return;
    try { db.prepare('UPDATE users SET last_region=?, last_region_at=? WHERE id=?')
      .run(region, now(), uid); } catch (e) {}
  }).catch(() => {});
}

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
  sendPush(target, { icon: '👋', title: '클럽에서 나가게 됐어요', body: `${c ? c.name : '클럽'} · 임원이 회원을 정리했어요` });
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
/* 공지를 올린 사람이 가장 궁금한 것은 <봤을까> 다. 지금은 알 길이 없었다. */
db.exec(`CREATE TABLE IF NOT EXISTS notice_reads (
  notice_id INTEGER, user_id INTEGER, at INTEGER,
  PRIMARY KEY(notice_id, user_id))`);
db.exec(`CREATE TABLE IF NOT EXISTS notice_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, notice_id INTEGER, user_id INTEGER,
  choice INTEGER, answer TEXT, created_at INTEGER, UNIQUE(notice_id, user_id))`);

app.get('/clubs/:id/notices', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT n.*, u.name author,
      (SELECT COUNT(*) FROM notice_reads r WHERE r.notice_id=n.id) read_n
    FROM notices n
    JOIN users u ON u.id=n.author_id WHERE n.club_id=?
    ORDER BY n.pinned DESC, n.id DESC LIMIT 50`).all(cid);
  /* 몇 명 중 몇 명이 읽었나 — 분모가 없으면 <18명 읽음>은 뜻이 없다 */
  const memberN = db.prepare('SELECT COUNT(*) n FROM club_members WHERE club_id=?').get(cid).n;
  rows.forEach(r => { r.member_n = memberN; });
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

/* 읽음 표시 — 앱이 공지를 화면에 그린 뒤 한 번 부른다 */
app.post('/notices/:nid/read', auth, (req, res) => {  // @external 앱이 화면 그린 뒤 부름
  try {
    db.prepare('INSERT OR IGNORE INTO notice_reads (notice_id,user_id,at) VALUES (?,?,?)')
      .run(+req.params.nid, req.uid, now());
  } catch (e) {}
  res.json({ ok: true });
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
/* ── 오픈매치 티어 개편에 필요한 칸들 ──
   mode  self=자율(매니저 없음) · managed=운영(매니저 배정)
   disc  mixed=혼복 · men=남복 · women=여복
   혼복은 남녀 정원을 따로 잠근다 — 선착순으로 받으면 남자만 4명 찬 혼복이 생긴다. */
['mode TEXT DEFAULT \'self\'', 'disc TEXT DEFAULT \'mixed\'',
 'cap_m INTEGER', 'cap_f INTEGER', 'close_at TEXT',
 'tier_min TEXT', 'tier_max TEXT', 'leader_id INTEGER',
 'base_price INTEGER',                                   // 4인 기준가 — 결제는 늘 이 값으로
 'fee_rate REAL',                                        // 업체 수수료율 (한산 0.2 · 붐빔 0.1)
 'confirmed_at BIGINT', 'refunded_at BIGINT'
].forEach(c => { try { db.exec(`ALTER TABLE open_matches ADD COLUMN ${c}`); } catch (e) {} });
['paid INTEGER DEFAULT 0', 'refund INTEGER DEFAULT 0'
].forEach(c => { try { db.exec(`ALTER TABLE open_match_joins ADD COLUMN ${c}`); } catch (e) {} });

/* 매너 확인 — 티어와 완전히 분리한다. 점수가 아니라 신고에 가깝게 받는다.
   기본값이 "다들 괜찮았어요"라 평소에는 한 줄도 안 쌓인다. */
db.exec(`CREATE TABLE IF NOT EXISTS om_manner (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  match_id INTEGER NOT NULL, from_id INTEGER NOT NULL,
  target_id INTEGER, kind TEXT, created_at BIGINT,
  UNIQUE(match_id, from_id, target_id))`);

/* ── 1인 참가비는 표가 아니라 공식으로 ──
   코트 단가가 시간당 33,000원인 곳도 77,000원인 곳도 있다.
   고정 가격표를 만들면 싼 코트에서는 과금이 되고 비싼 코트에서는 적자가 난다. */
/* 티어 오픈매치 전용 마진 — 위쪽 OM_MARGIN(0.375)은 기존 소셜매치 공식이 쓰고 있다.
   자율 매치는 매니저가 없어 원가가 낮으므로 마진율을 따로 잡는다. */
const OMT_MARGIN = { self: 0.33, managed: 0.45 };
function omPriceFor(m, people) {
  const gross = intOrNull(m.court_cost) || 0;             // 코트 정가(대관 전체)
  if (!gross) return intOrNull(m.base_price) || intOrNull(m.price) || 0;
  const fee = (m.fee_rate != null ? m.fee_rate : 0.2);    // 업체 수수료율
  const cost = gross * (1 - fee) + (intOrNull(m.manager_fee) || 0);
  const margin = OMT_MARGIN[m.mode === 'managed' ? 'managed' : 'self'];
  const n = Math.max(1, people || omMinCount(m));
  return Math.ceil(cost / (1 - margin) / n / 100) * 100;  // 100원 단위 올림
}
const omMinCount = m => (m.mode === 'managed' ? (intOrNull(m.min_cnt) || 8) : 4);
function omCaps(m) {
  const cap = intOrNull(m.cap) || 4;
  if (m.disc === 'men')   return { m: cap, f: 0 };
  if (m.disc === 'women') return { m: 0, f: cap };
  return { m: intOrNull(m.cap_m) || Math.ceil(cap / 2),
           f: intOrNull(m.cap_f) || Math.floor(cap / 2) };
}
/* 지금 성별별로 몇 명이 찼나 */
function omFilled(mid) {
  const rows = db.prepare(`SELECT u.gender g FROM open_match_joins j
    JOIN users u ON u.id=j.user_id WHERE j.match_id=?`).all(mid);
  return { m: rows.filter(r => r.g === 'M').length,
           f: rows.filter(r => r.g === 'F').length,
           n: rows.length };
}
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
  const caps = omCaps(m), fill = omFilled(m.id);
  const need = omMinCount(m);
  /* 지금 모인 사람들의 티어 — 제한이 아니라 정보다.
     실력차가 부담스러운 사람은 스스로 거르고, 괜찮은 사람은 그냥 들어온다. */
  const tierMix = (() => {
    const ks = joins.map(j => tierOf(j.user_id).key);
    const order = ['love', 'fut', 'chal', 'tour', 'gs'];
    const seen = order.filter(k => ks.includes(k));
    if (!seen.length) return null;
    const KO = { love: '러브', fut: '퓨처스', chal: '챌린저', tour: '마스터스', gs: '그랜드슬램' };
    return { keys: seen, label: seen.length === 1 ? KO[seen[0]] : `${KO[seen[0]]}~${KO[seen[seen.length - 1]]}` };
  })();
  return {
    ...m,
    /* 화면이 바로 쓰도록 계산해서 내려준다 — 앱이 다시 세면 서버와 어긋난다 */
    mode: m.mode || 'self', disc: m.disc || 'mixed',
    caps, fill, need, tier_mix: tierMix,
    left_m: Math.max(0, caps.m - fill.m),
    left_f: Math.max(0, caps.f - fill.f),
    price_now: omPriceFor(m, Math.max(need, fill.n)),
    price_base: omPriceFor(m, need),
    leader: m.leader_id ? db.prepare('SELECT id,name FROM users WHERE id=?').get(m.leader_id) : null,
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
  /* 홈구장에 코트 번호까지 적어 넣는 분이 많다 — 저장할 때 갈라 둔다.
     그래야 모임 제목에서 코트 표기가 겹치지 않는다. */
  const _hc = has('home_court') ? splitCourt(req.body.home_court)
                                : { venue: c.home_court, courts: c.home_courts };
  /* 창단연도는 숫자다 — 빈 값이면 지운다. 미래나 1900년 이전은 오타로 본다. */
  const _yr = has('founded_year')
    ? (() => { const v = parseInt(req.body.founded_year, 10);
               if (!v) return null;
               const now = new Date().getFullYear();
               return (v >= 1900 && v <= now) ? v : c.founded_year; })()
    : c.founded_year;
  const _rec = has('recruiting') ? (req.body.recruiting ? 1 : 0) : (c.recruiting || 0);
  /* 게스트 구력 — 0 이나 빈 값은 <제한 없음>(null)으로 둔다 */
  const num = (k, cur) => { if (!has(k)) return cur;
    const v = parseInt(req.body[k], 10); return (v >= 0 && v <= 9999999) ? v : cur; };
  const _entry  = num('entry_fee',  c.entry_fee);
  const _season = num('season_fee', c.season_fee);
  const _gfee   = num('guest_fee',  c.guest_fee);
  const _gcap   = num('guest_cap',  c.guest_cap);
  const _gvis   = has('guest_visits')
    ? (() => { const v = parseInt(req.body.guest_visits, 10);
               return (v > 0 && v <= 50) ? v : null; })()
    : c.guest_visits;
  const _jopen  = has('join_open') ? (req.body.join_open ? 1 : 0)
                                   : (c.join_open == null ? 1 : c.join_open);
  const _jre    = has('join_reopen') ? String(req.body.join_reopen || '').slice(0, 30) : c.join_reopen;
  const _gm = has('guest_min_months')
    ? (() => { const v = parseInt(req.body.guest_min_months, 10);
               return (v > 0 && v <= 600) ? v : null; })()
    : c.guest_min_months;
  db.prepare(`UPDATE clubs SET avg_grade=?, home_court=?, home_courts=?, meet_days=?, intro=?,
      logo=?, logo_ic=?, logo_bg=?, meet_time=?, age_bands=?, gender_pref=?,
      founded_year=?, recruiting=?, guest_min_months=?, guest_visits=?,
      entry_fee=?, season_fee=?, guest_fee=?, guest_cap=?,
      join_open=?, join_reopen=? WHERE id=?`).run(
    has('avg_grade') ? cleanGrade(req.body.avg_grade) : c.avg_grade,
    (_hc.venue || '').slice(0, 40) || null, (_hc.courts || '').slice(0, 20) || null,
    pick('meet_days', 30), pick('intro', 40),
    pick('logo', 300), pick('logo_ic', 8), pick('logo_bg', 12),
    pick('meet_time', 30), pick('age_bands', 40), pick('gender_pref', 10),
    _yr, _rec, _gm, _gvis, _entry, _season, _gfee, _gcap, _jopen, _jre, c.id);
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
      (SELECT COUNT(*) FROM club_members m2 JOIN users u2 ON u2.id=m2.user_id
        WHERE m2.club_id=clubs.id AND COALESCE(u2.is_test,0)=0) members
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
/* 등록 시도를 기억한다 — 앱이 요청을 보냈는지조차 알 수 없어서
   <기기 0대>가 앱 문제인지 저장 문제인지 가릴 수 없었다.
   서버가 다시 뜨면 사라지는 값이라 표를 만들지 않는다(진단용). */
const PUSH_TRIES = [];
/* 앱이 보내는 진단 한 줄 — 폰에서 콘솔을 볼 수 없어 원인을 알 길이 없었다.
   인증을 요구하지 않는다(로그인 전 단계에서 막히는 경우도 봐야 한다). */
app.post('/push/diag', (req, res) => {
  const b = req.body || {};
  PUSH_TRIES.unshift({ at: now(), user_id: 0, platform: 'diag', token_len: 0,
    result: String(b.step || '').slice(0, 24),
    extra: [b.extra, b.build, b.native ? '네이티브' : '웹',
      b.server_ok ? '' : '서버X', b.logged_in ? '' : '로그인X']
      .filter(Boolean).join(' · ').slice(0, 80) });
  PUSH_TRIES.length = Math.min(PUSH_TRIES.length, 30);
  console.log('[push:diag]', b.step, '·', b.extra || '', '·', b.build || '',
    b.native ? '네이티브' : '웹', b.server_ok ? '' : '서버X', b.logged_in ? '' : '로그인X');
  res.json({ ok: true });
});
/* 인증(auth)보다 앞에서 기록한다 — 예전에는 auth 를 통과한 뒤에만 남겨서,
   로그인 토큰이 없거나 만료돼 401 로 막히면 <요청 자체가 오지 않았다>고 보였다.
   앱이 보냈는지와 인증에서 막혔는지는 완전히 다른 문제다. */
app.post('/push/register', (req, res, next) => {
  const b = req.body || {};
  const hasAuth = !!(req.headers.authorization || '').startsWith('Bearer ');
  PUSH_TRIES.unshift({ at: now(), user_id: 0, platform: b.platform || '?',
    token_len: b.token ? String(b.token).length : 0,
    result: '도착', extra: hasAuth ? '' : '로그인 토큰 없음' });
  PUSH_TRIES.length = Math.min(PUSH_TRIES.length, 30);
  console.log('[push] 요청 도착 · platform=' + (b.platform || '?'),
    '· 토큰', b.token ? String(b.token).length + '자' : '없음',
    '· 로그인', hasAuth ? '있음' : '없음');
  next();
});
app.post('/push/register', auth, (req, res) => {
  const { token, platform } = req.body || {};
  const mark = (result, extra) => {
    PUSH_TRIES.unshift({ at: now(), user_id: req.uid, platform: platform || 'web',
      token_len: token ? String(token).length : 0, result, extra: extra || '' });
    PUSH_TRIES.length = Math.min(PUSH_TRIES.length, 30);
    console.log('[push] 등록', result, '· user=' + req.uid, '· platform=' + (platform || 'web'),
      '· 토큰', token ? String(token).length + '자' : '없음', extra || '');
  };
  if (!token) { mark('실패', '토큰 없음'); return res.status(400).json({ error: 'no_token' }); }
  try {
    /* 같은 기기가 다시 켜지면 platform 이 바뀌었을 수 있으니 갱신까지 한다.
       예전에는 INSERT OR IGNORE 라 platform 이 'web' 으로 남은 토큰이 고쳐지지 않았다. */
    db.prepare('INSERT OR IGNORE INTO devices (user_id,token,platform,created_at) VALUES (?,?,?,?)')
      .run(req.uid, token, platform || 'web', now());
    db.prepare('UPDATE devices SET user_id=?, platform=? WHERE token=?')
      .run(req.uid, platform || 'web', token);
    mark('완료');
    res.json({ ok: true });
  } catch (e) {
    mark('실패', String(e.message).slice(0, 60));
    res.status(500).json({ error: 'save_failed' });
  }
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

/* ── iOS 알림 (APNs) ─────────────────────────────────────────
   지금까지 sendPush 는 웹 푸시(VAPID)만 보냈다. iOS 토큰은 {endpoint} 꼴이 아니라
   64자 문자열이라 JSON.parse 에서 조용히 걸러졌고, 그래서 폰에는 아무것도 안 떴다.
   (알림함에는 쌓이고 있었다 — 만들어지는 알림은 이미 70종이 넘는다.)

   새 패키지 없이 Node 기본 모듈로 보낸다.
     · 인증  : ES256 으로 서명한 JWT (crypto)
     · 전송  : HTTP/2 (http2)
   Railway 환경변수 네 개가 없으면 조용히 넘어간다 — 개발 중에 오류가 나지 않게. */
/* .p8 내용을 붙여넣는 방식이 사람마다 다르다 —
   헤더(-----BEGIN PRIVATE KEY-----)를 빼고 본문만 넣거나,
   줄바꿈이 \n 글자로 들어오거나, 한 줄로 뭉개져 들어온다.
   어느 쪽이든 Node 가 읽을 수 있는 PEM 으로 되돌린다.
   (본문만 넣으면 서명 단계에서 DECODER unsupported 로 조용히 실패한다) */
function apnsPem(raw) {
  let v = String(raw || '').trim().replace(/\\n/g, '\n');
  if (!v) return '';
  if (v.includes('BEGIN')) return v;                    // 이미 온전한 PEM
  const body = v.replace(/\s+/g, '');                    // 공백·줄바꿈 제거
  return '-----BEGIN PRIVATE KEY-----\n'
    + (body.match(/.{1,64}/g) || []).join('\n')
    + '\n-----END PRIVATE KEY-----\n';
}
const APNS = {
  key: apnsPem(process.env.APNS_KEY),
  keyId: process.env.APNS_KEY_ID || '',
  teamId: process.env.APNS_TEAM_ID || '',
  bundleId: process.env.APNS_BUNDLE_ID || '',
  /* 배포 빌드는 api.push, Xcode 개발 빌드는 api.sandbox.push 로 가야 한다.
     둘 다 되는 키를 만들었으므로 서버는 실패하면 반대쪽으로 한 번 더 시도한다. */
  hosts: ['https://api.push.apple.com', 'https://api.sandbox.push.apple.com'],
  _jwt: null, _jwtAt: 0,
};
const apnsReady = () => !!(APNS.key && APNS.keyId && APNS.teamId && APNS.bundleId);
/* 서버가 뜰 때 한 번 서명해 본다 — 키가 잘못 들어갔으면 알림이 나갈 때가 아니라
   지금 알아야 한다. 실제로 헤더를 빼고 넣어 하나도 안 나간 적이 있다. */
if (apnsReady()) {
  try {
    crypto.sign('sha256', Buffer.from('probe'), { key: APNS.key, dsaEncoding: 'ieee-p1363' });
    console.log('[apns] 준비됨 ·', APNS.bundleId);
  } catch (e) {
    console.error('[apns] 키를 읽지 못했어요 — APNS_KEY 에 .p8 내용 전체를 넣어주세요:',
      String(e.message).split('\n')[0]);
    APNS.key = '';                                      // 잘못된 키로 계속 시도하지 않는다
  }
} else if (process.env.APNS_KEY || process.env.APNS_KEY_ID) {
  console.log('[apns] 설정이 덜 됐어요 — KEY·KEY_ID·TEAM_ID·BUNDLE_ID 네 개가 모두 필요해요');
}
function apnsToken() {
  /* JWT 는 최대 1시간까지 쓸 수 있다. 매번 새로 만들면 APNs 가 429 로 막는다. */
  if (APNS._jwt && Date.now() - APNS._jwtAt < 40 * 60 * 1000) return APNS._jwt;
  const b64 = b => Buffer.from(b).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const h = b64(JSON.stringify({ alg: 'ES256', kid: APNS.keyId }));
  const p = b64(JSON.stringify({ iss: APNS.teamId, iat: Math.floor(Date.now() / 1000) }));
  const sig = crypto.sign('sha256', Buffer.from(h + '.' + p),
    { key: APNS.key, dsaEncoding: 'ieee-p1363' });          // APNs 는 raw(R||S) 서명
  APNS._jwt = `${h}.${p}.${b64(sig)}`; APNS._jwtAt = Date.now();
  return APNS._jwt;
}
function apnsSend(token, msg, hostIdx) {
  return new Promise(resolve => {
    const host = APNS.hosts[hostIdx || 0];
    let client;
    try { client = http2.connect(host); } catch { return resolve({ ok: false }); }
    const body = Buffer.from(JSON.stringify({
      aps: {
        alert: { title: msg.title || '맞수', body: msg.body || '' },
        sound: 'default', badge: msg.badge || undefined,
        'thread-id': msg.thread || undefined,        // 같은 클럽 알림끼리 묶인다
      },
      url: msg.url || '/',
    }));
    const req = client.request({
      ':method': 'POST', ':path': '/3/device/' + token,
      authorization: 'bearer ' + apnsToken(),
      'apns-topic': APNS.bundleId,
      'apns-push-type': 'alert',
      'apns-priority': '10',
      'content-type': 'application/json',
      'content-length': body.length,
    });
    let status = 0, out = '';
    req.on('response', h => { status = +h[':status'] || 0; });
    req.on('data', d => { out += d; });
    req.on('error', () => { try { client.close(); } catch {} resolve({ ok: false }); });
    req.on('end', () => {
      try { client.close(); } catch {}
      if (status === 200) return resolve({ ok: true });
      let reason = ''; try { reason = (JSON.parse(out) || {}).reason || ''; } catch {}
      /* 둘 다 <다른 환경의 토큰>이라는 뜻이다 — 반대쪽 서버로 한 번 더.
         BadDeviceToken(400) 은 문서에 있고,
         BadEnvironmentKeyInToken(403) 은 문서에 없지만 같은 상황에서 나온다
         (개발 빌드 토큰 + 프로덕션 키). 예전에는 400 만 봐서 여기서 그냥 끝났다. */
      if (!hostIdx && (reason === 'BadDeviceToken' || reason === 'BadEnvironmentKeyInToken')) {
        console.log('[apns] 환경이 안 맞아요 —', reason, '· 샌드박스로 다시 보냅니다');
        return resolve(apnsSend(token, msg, 1));
      }
      resolve({ ok: false, status, reason });
    });
    req.end(body);
  });
}
/* ── 안드로이드 알림 (FCM HTTP v1) ────────────────────────────────
   구글이 2024년에 legacy 서버 키를 없앴다. 이제는 서비스 계정으로 토큰을 받아 쓴다.

   Railway 환경변수 하나면 된다:
     FCM_SERVICE_ACCOUNT = Firebase 콘솔에서 받은 JSON 통째로

   없으면 조용히 쉰다 — iOS 만 쓰던 때와 똑같이 동작한다. */
let FCM_SA = null;
try {
  const raw = process.env.FCM_SERVICE_ACCOUNT || '';
  if (raw.trim()) {
    FCM_SA = JSON.parse(raw);
    if (FCM_SA.private_key) FCM_SA.private_key = FCM_SA.private_key.replace(/\\n/g, '\n');
  }
} catch (e) { console.error('[fcm] FCM_SERVICE_ACCOUNT 를 읽지 못했습니다:', e.message); }
function fcmReady() { return !!(FCM_SA && FCM_SA.project_id && FCM_SA.client_email && FCM_SA.private_key); }

let FCM_TOKEN = null, FCM_TOKEN_EXP = 0;
async function fcmAccessToken() {
  if (FCM_TOKEN && Date.now() < FCM_TOKEN_EXP - 60000) return FCM_TOKEN;
  const iat = Math.floor(Date.now() / 1000);
  const assertion = jwt.sign({
    iss: FCM_SA.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat, exp: iat + 3600,
  }, FCM_SA.private_key, { algorithm: 'RS256' });
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('fcm_token: ' + JSON.stringify(j).slice(0, 200));
  FCM_TOKEN = j.access_token;
  FCM_TOKEN_EXP = Date.now() + (j.expires_in || 3600) * 1000;
  return FCM_TOKEN;
}
async function fcmSend(token, msg) {
  const at = await fcmAccessToken();
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${FCM_SA.project_id}/messages:send`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: {
      token,
      notification: { title: msg.title || '', body: msg.body || '' },
      /* 눌렀을 때 갈 곳. 앱이 data 로 읽는다 — iOS 의 url 과 같은 값을 쓴다. */
      data: { url: String(msg.url || 'home') },
      android: { priority: 'high', notification: { sound: 'default' } },
    } }),
  });
  if (r.ok) return { ok: true };
  let j = null; try { j = await r.json(); } catch (e) {}
  const status = j && j.error && j.error.status;
  return { ok: false, status: r.status, reason: status || '' };
}

async function sendPush(userId, msg, opts) {
  // 알림함에는 기본으로 남긴다. 채팅처럼 잦은 알림은 skipInbox 로 푸시만 보낸다.
  const link = msg.link || ICON_LINKS[msg.icon] || null;
  if (!(opts && opts.skipInbox))
    db.prepare('INSERT INTO notifications (user_id,icon,title,sub,created_at,link) VALUES (?,?,?,?,?,?)')
      .run(userId, msg.icon || '🔔', msg.title || '', msg.body || '', now(), link);
  /* 알림함에만 넣던 link 를 폰 알림에도 함께 보낸다.
     예전에는 apnsSend 가 msg.url 을 찾는데 그 값을 채우는 곳이 없어 항상 '/' 였다.
     그래서 무엇을 눌러도 앱이 홈으로 갔다. */
  const out = Object.assign({}, msg, { url: msg.url || link || 'home' });

  const rows = db.prepare('SELECT token, platform FROM devices WHERE user_id=?').all(userId);

  /* iOS 는 APNs 로 — 예전에는 이 갈래가 없어 폰 알림이 하나도 안 갔다 */
  if (apnsReady()) {
    rows.filter(r => r.platform === 'ios').forEach(({ token }) => {
      apnsSend(token, out).then(r => {
        /* Unregistered = 앱을 지웠거나 토큰이 만료됐다 — 표에서 지운다.
           BadDeviceToken 으로는 더 이상 지우지 않는다: 위에서 양쪽 서버를 다 시도하므로
           여기 도달했다면 <정말 죽은 토큰>과 <아직 설정이 덜 된 상태>를 구분할 수 없다.
           개발 중에 방금 등록한 기기가 조용히 사라지는 편이 훨씬 나쁘다. */
        if (!r.ok && r.reason === 'Unregistered')
          db.prepare('DELETE FROM devices WHERE token=?').run(token);
        else if (!r.ok) console.error('[apns]', r.status, r.reason);
      }).catch(() => {});
    });
  }

  /* 안드로이드는 FCM 으로 — 예전에는 이 갈래가 없어 토큰이 그냥 버려졌다.
     아래 웹푸시 고리는 토큰을 JSON 으로 파싱하는데, FCM 토큰은 그냥 문자열이라
     조용히 건너뛰어졌다(오류도 안 났다). */
  if (fcmReady()) {
    rows.filter(r => r.platform === 'android').forEach(({ token }) => {
      fcmSend(token, out).then(r => {
        /* 앱을 지웠거나 토큰이 만료된 경우만 지운다 — 설정이 덜 된 상태와 구분한다 */
        if (!r.ok && (r.reason === 'NOT_FOUND' || r.reason === 'UNREGISTERED'))
          db.prepare('DELETE FROM devices WHERE token=?').run(token);
        else if (!r.ok) console.error('[fcm]', r.status, r.reason);
      }).catch(e => console.error('[fcm]', e.message));
    });
  }

  if (!webpush) return;
  for (const { token } of rows) {
    /* 안드로이드 토큰은 위에서 처리했다 — 여기서 JSON.parse 하면 매번 실패한다 */
    if (rows.find(r => r.token === token && r.platform === 'android')) continue;
    let sub;
    try { sub = JSON.parse(token); } catch { continue; }        // 구독 객체가 아니면 건너뛴다
    if (!sub || !sub.endpoint) continue;
    webpush.sendNotification(sub, JSON.stringify({
      title: out.title || 'MATSU', body: out.body || '', url: out.url,
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
  .top b{font-size:18px;letter-spacing:-.02em}
  .top span{margin-left:auto;font-size:12px;color:#7d7870}
  .amt{background:#fff;border-radius:16px;padding:16px;margin-bottom:12px}
  .amt .k{font-size:12px;color:#7d7870}
  .amt .v{font-size:23px;font-weight:700;letter-spacing:-.03em;margin-top:3px}
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
app.get('/pay/done', async (req, res) => {  // @external 결제 뒤 브라우저가 돌아옴
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
app.get('/icon-192.png', (req, res) => { res.type('png').send(ICON_192); });  // @external 브라우저가 직접 요청
app.get('/icon-512.png', (req, res) => { res.type('png').send(ICON_512); });  // @external 브라우저가 직접 요청
app.get('/manifest.json', (req, res) => res.json({  // @external 브라우저가 직접 요청
  name: '맞수 MATSU', short_name: '맞수',
  description: '동호회 운영과 대진, 기록까지 — 맞수',
  start_url: '/', display: 'standalone',
  background_color: '#f6f1e7', theme_color: '#ec6a2e',
  icons: [
    { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png' }
  ]
}));

app.post('/iap/apple', auth, async (req, res) => {  // @external 애플 인앱결제 콜백
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
app.post('/iap/google', auth, async (req, res) => {  // @external 구글 인앱결제 콜백
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
/* 클럽에서 부를 이름 — 계정 이름은 그대로 두고 이 클럽에서만 다르게 부른다.
   구글로 가입해 <Ian Suh> 로 들어온 회원을 명단·대진에서 <서기훈> 으로 보이게 하는 용도다.
   화면과 저장 요청은 있었는데 서버에 받는 곳이 없어 늘 실패하고 있었다. */
try { db.exec('ALTER TABLE club_members ADD COLUMN alias TEXT'); } catch (e) { /* 이미 있음 */ }

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

/* ── 홈에 쓰는 내 클럽 한 줄 요약 ──
   시즌 순위·내 전적·클럽 평균 대비는 지금까지 클럽 탭에 들어가야 계산됐다.
   홈에서 대진 기록을 통째로 받아오면 무거우니, 서버가 세어 세 숫자만 보낸다.
   셈법은 클럽 <시즌 랭킹>과 같다 — 승 3점·무 1점을 참석 횟수로 나눈다. */
app.get('/clubs/:id/my-summary', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const out = { rank: null, total: 0, w: 0, l: 0, d: 0, wr: null, clubWr: null,
                days: 0, weekMeets: 0 };
  try {
    /* 이 클럽에서 내가 불리는 이름 — 별명이 있으면 별명으로 대진에 적힌다 */
    const meRow = db.prepare(`SELECT COALESCE(NULLIF(cm.alias,''), u.name) name
      FROM club_members cm JOIN users u ON u.id=cm.user_id
      WHERE cm.club_id=? AND cm.user_id=?`).get(cid, req.uid);
    const myName = meRow && meRow.name;

    const brs = db.prepare(`SELECT id, date, data FROM brackets
      WHERE club_id=? AND published=1 ORDER BY id DESC LIMIT 60`).all(cid);
    const st = {};                       // 이름 → 성적
    const pick = n => (st[n] = st[n] || { g:0, w:0, d:0, gf:0, ga:0, days:new Set() });
    brs.forEach(b => {
      let data = {}; try { data = JSON.parse(b.data); } catch (e) { return; }
      const sc = {};
      db.prepare('SELECT court_key, a, b FROM bracket_scores WHERE bracket_id=?').all(b.id)
        .forEach(r => { if (r.a !== null && r.b !== null) sc[r.court_key] = r; });
      (data.reg || []).forEach(r => {
        const s2 = sc[r.key];
        if (!s2 || !Array.isArray(r.names) || r.names.length < 2) return;
        const half = Math.floor(r.names.length / 2);
        const A = r.names.slice(0, half), B = r.names.slice(half);
        const draw = s2.a === s2.b;
        [[A, s2.a, s2.b], [B, s2.b, s2.a]].forEach(([side, mine, opp]) => {
          side.forEach(n => { if (!n) return;
            const t = pick(n);
            t.g++; t.gf += mine; t.ga += opp;
            if (draw) t.d++; else if (mine > opp) t.w++;
            t.days.add(b.date || String(b.id));
          });
        });
      });
    });

    const list = Object.entries(st).map(([n, t]) => {
      const dayN = t.days.size || 1;
      return { n, ...t, dayN, avg: (t.w * 3 + t.d) / dayN,
               gdAvg: (t.gf - t.ga) / dayN,
               wr: t.g ? Math.round(t.w / t.g * 100) : 0 };
    });
    /* 랭킹과 같은 기준 — 모임이 두 번 이상 있었으면 2회부터 순위에 넣는다 */
    const allDays = new Set(); brs.forEach(b => allDays.add(b.date || String(b.id)));
    const MIN = allDays.size >= 2 ? 2 : 1;
    const rank = list.filter(r => r.dayN >= MIN)
      .sort((a, b) => b.avg - a.avg || b.gdAvg - a.gdAvg || b.g - a.g);
    const i = rank.findIndex(r => r.n === myName);
    const me = i >= 0 ? rank[i] : list.find(r => r.n === myName);
    if (me) { out.w = me.w; out.l = me.g - me.w - me.d; out.d = me.d;
              out.wr = me.wr; out.days = me.dayN; }
    if (i >= 0) { out.rank = i + 1; out.total = rank.length; }
    if (rank.length) out.clubWr = Math.round(
      rank.reduce((a, r) => a + r.wr, 0) / rank.length);

    /* 이번 주 모임 수 — 월요일부터 오늘까지 */
    const t0 = new Date(); t0.setHours(0, 0, 0, 0);
    const mon = new Date(t0); mon.setDate(t0.getDate() - ((t0.getDay() + 6) % 7));
    const sun = new Date(mon); sun.setDate(mon.getDate() + 7);
    db.prepare('SELECT date, created_at FROM club_events WHERE club_id=?').all(cid)
      .forEach(e => { const t = eventDayTs(e.date, e.created_at);
        if (t && t >= mon.getTime() && t < sun.getTime()) out.weekMeets++; });
  } catch (e) {}
  res.json(out);
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
  /* 대진 월 발행 제한도 없앤다 — 주 2회 모이는 클럽은 월 4개로는 한 달을 못 넘긴다.
     프리미엄이 없어진 이상 막을 이유가 없다. */
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
/* ══════════════════════════════════════════════════════════════
   MATSU CUP — 초청 클럽대항전

   초청하는 7개 클럽은 앱을 쓰지 않는다. 그래서 두 가지를 지킨다.
   하나, 대표자 한 명만 링크로 들어온다. 로그인을 요구하지 않는다.
   둘, 나머지 9명은 이름·성별·NTRP 만 적는다. 가입을 시키면 신청을 포기한다.

   그래서 cup_roster 는 user_id 와 guest_name 을 둘 다 갖는다.
   ══════════════════════════════════════════════════════════════ */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS cup_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bracket_id INTEGER NOT NULL,
    club_id INTEGER,                    -- 앱 미사용 클럽은 NULL
    club_name TEXT NOT NULL,
    contact_name TEXT, contact_phone TEXT,
    status TEXT DEFAULT 'invited',      -- invited|applied|paid|confirmed|cancelled
    fee_paid INTEGER DEFAULT 0,
    deposit_state TEXT DEFAULT 'none',  -- none|held|returned|forfeited
    group_label TEXT, seat INTEGER,
    invite_token TEXT,
    applied_at INTEGER, created_at INTEGER)`);
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_cup_tok ON cup_entries(invite_token)');
  db.exec('CREATE INDEX IF NOT EXISTS ix_cup_br ON cup_entries(bracket_id)');
  db.exec(`CREATE TABLE IF NOT EXISTS cup_roster (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,
    user_id INTEGER,                    -- 앱 회원이면 채움
    guest_name TEXT,                    -- 비회원이면 이름만
    gender TEXT NOT NULL,               -- 'M' | 'F'
    ntrp REAL NOT NULL,
    birth_year INTEGER,
    slot INTEGER,
    guardian_consent INTEGER DEFAULT 0,
    health_declared INTEGER DEFAULT 0)`);
  db.exec('CREATE INDEX IF NOT EXISTS ix_cup_ros ON cup_roster(entry_id)');
  db.exec(`CREATE TABLE IF NOT EXISTS cup_lineups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bracket_id INTEGER NOT NULL,
    tie_id TEXT NOT NULL,
    entry_id INTEGER NOT NULL,
    match_no INTEGER NOT NULL,
    p1 INTEGER, p2 INTEGER,
    submitted_at INTEGER,
    UNIQUE(bracket_id, tie_id, entry_id, match_no))`);
} catch (e) { console.error('[schema cup]', e.message); }

/* MATSU CUP 대진 생성기 — 순수 함수.
   서버도 브라우저도 아닌 데서 그대로 돌려볼 수 있어야 한다.
   대회 당일 이 함수가 틀리면 되돌릴 방법이 없다. */

/* 4팀 조 리그의 고정 로테이션.
   랜덤이 아니다 — 추첨은 <어느 클럽이 어느 자리에 앉는가>만 정하고,
   자리끼리 붙는 순서는 늘 같다. 그래야 추첨 결과를 그 자리에서 보여줄 수 있다.

     R1: 1-2, 3-4
     R3: 1-3, 2-4
     R5: 1-4, 2-3

   세 판을 돌면 네 자리가 서로 정확히 한 번씩 만난다. */
const SEAT_ROUNDS = [
  [[1, 2], [3, 4]],
  [[1, 3], [2, 4]],
  [[1, 4], [2, 3]],
];
/* 3팀 조 — 6팀으로 열릴 때 쓴다.
   한 라운드에 한 타이뿐이라 두 조를 동시에 돌린다(4면을 다 쓴다).
   3팀이면 조별 2타이 + 결승/3위전 1타이 = 3타이로 <팀당 9매치>가 그대로 지켜진다. */
const SEAT_ROUNDS3 = [ [[1, 2]], [[1, 3]], [[2, 3]] ];

/* 몇 팀이 오느냐에 따라 조를 나눈다.
   6팀을 4+2 로 쪼개면 B조에 부전승이 다섯 번 생긴다 — 손익분기가 6팀인데
   그 경우가 안 굴러가면 대회를 못 연다. */
function cupGroupSizes(n) {
  if (n >= 8) return [4, 4];
  if (n === 7) return [4, 3];
  if (n === 6) return [3, 3];
  if (n === 5) return [3, 2];
  return [n, 0];
}

/* 한 타이는 두 슬롯에 걸친다.
   슬롯 1에서 1복식과 혼복을 두 코트에 동시에 놓고,
   슬롯 2에서 3복식을 한 코트에서 친다. 남는 한 면은 늦어진 매치의 예비 코트다.

   2:0으로 갈려도 3복식은 반드시 친다 — 게임 득실과 출전 인원 규칙 때문이다. */
/* 코트와 슬롯은 배치기가 나중에 넣는다 — 여기서는 자리만 만든다 */
function tieMatches(tieId, opt) {
  const fin = !!(opt && opt.final);
  const fmt = fin ? (opt.fmt || 'timed') : 'timed';
  return [
    { no: 1, kind: 'free',  court: 0, slot: 0, key: `${tieId}m1`, fmt },
    { no: 2, kind: 'mixed', court: 0, slot: 0, key: `${tieId}m2`, fmt },
    /* 본선에서 2:0 이면 안 친다 — 화면이 <칠 수도 있음>으로 보여준다 */
    { no: 3, kind: 'free',  court: 0, slot: 0, key: `${tieId}m3`, fmt,
      skippable: (fin && opt.skip) ? 1 : 0 },
  ];
}

const pad2 = n => String(n).padStart(2, '0');
function addMin(hhmm, min) {
  const [h, m] = String(hhmm).split(':').map(Number);
  const t = h * 60 + m + min;
  return `${pad2(Math.floor(t / 60) % 24)}:${pad2(t % 60)}`;
}

const CUP_DEFAULT = {
  /* 20분 단타임. 25분이면 4면에서 6시간이 걸린다.
     20분이면 5~6게임이 나와 승부를 가리기에 충분하다. */
  match_sec: 1200,
  /* 전환 5분 — 앞 팀이 나가고 다음 팀이 들어와 자리 잡는 시간. 워밍업 포함.
     3분은 지연됐을 때 당기는 카드로 남겨둔다(명세 2.6). */
  turn_sec: 300,
  courts: 4,
  /* 본선(준결승·결승·3위전) 포맷.
     'timed' — 조별과 같은 25분 단타임
     'pro6'  — 6게임 프로세트 노애드. 승부는 확실하지만 평균 35분이라 더 길다 */
  final_fmt: 'timed',
  /* 본선에서 2:0 이 되면 3복식을 생략한다.
     조별은 게임 득실과 출전 인원을 세야 해서 반드시 쳐야 하지만,
     본선은 이긴 팀만 올라가면 되므로 칠 이유가 없다. 라운드마다 25분이 빈다. */
  skip_dead: true,
  cap: { 1: null, 2: 20, 3: 16 },        // 구력 합산 상한(년)
  lunch_after: 4,           // 4라운드 뒤 점심
  lunch_min: 40,
};

/* teams: [{entry_id, name, group:'A'|'B', seat:1~4}]

   ── 슬롯 배치 ──────────────────────────────────────────
   전에는 <라운드>로 짰다. 한 라운드에 타이 두 개를 놓고, 슬롯1 에 1복식·혼복,
   슬롯2 에 3복식 하나만 놓았다. 슬롯2 마다 코트 한 면이 예비로 놀았다.
   그래서 8팀이 8시간 걸렸다.

   이제 슬롯 단위로 채운다. 한 타이는 슬롯 S 에 두 면(1복식·혼복),
   슬롯 S+1 에 한 면(3복식)을 쓴다. 남는 면에 다음 타이를 밀어 넣는다.

   지켜야 할 것
     · 한 팀이 같은 슬롯에 두 타이를 뛰지 않는다
     · 한 팀의 다음 타이는 앞 타이가 끝나고 한 슬롯 쉰 뒤에 시작한다
     · 조별이 다 끝나야 준결승, 준결승이 끝나야 결승 */
function packTies(list, courts, startSlot, busy) {
  const perSlot = Math.max(2, courts);
  const used = {};            // 슬롯 → 쓴 코트 수
  const free = s => perSlot - (used[s] || 0);
  const out = [];
  list.forEach(t => {
    let s = startSlot;
    for (;; s++) {
      if (free(s) < 2 || free(s + 1) < 1) continue;
      /* 한 팀이 같은 슬롯에 두 타이를 뛸 수는 없다.
         쉬는 시간은 팀이 아니라 사람 기준이다(명세 2.3) — 팀은 10명이라
         다음 타이에 다른 사람을 내면 된다. 팀 단위로 한 슬롯을 통째로
         비우게 하면 조별이 9슬롯이면 될 것을 12슬롯 쓰게 된다.

         준결승·결승은 팀이 아직 안 정해져 home 이 null 이다.
         null 을 팀 번호로 세면 두 타이가 서로 겹친다고 보고 흩어진다. */
      const ok = [t.home, t.away].filter(id => id != null).every(id => {
        const b = busy[id] || [];
        return !b.some(x => x === s || x === s + 1);
      });
      if (ok) break;
    }
    used[s] = (used[s] || 0) + 2;
    used[s + 1] = (used[s + 1] || 0) + 1;
    [t.home, t.away].forEach(id => {
      if (id == null) return;
      busy[id] = (busy[id] || []).concat([s, s + 1]);
    });
    out.push({ tie: t, slot: s });
  });
  const last = out.length ? Math.max(...out.map(x => x.slot + 1)) : startSlot - 1;
  return { placed: out, nextSlot: last + 1, used, perSlot };
}

/* 슬롯에 실제 코트 번호를 준다 — 같은 슬롯에 같은 면이 겹치면 안 된다.

   낮은 번호부터 채우면 1·2번만 계속 쓰이고 3·4번이 논다.
   실제로는 네 면이 다 열려 있는데 두 면만 쓰는 것처럼 보여서
   운영자가 <저 코트는 왜 비었나> 하고 헷갈린다. 골고루 돌린다. */
function assignCourts(placed, courts, state) {
  const st = state || { taken: {}, next: 1 };
  const taken = st.taken;
  const take = (s, n) => {
    const got = [];
    for (let k = 0; k < courts && got.length < n; k++) {
      const c = ((st.next - 1 + k) % courts) + 1;
      if (!taken[`${s}:${c}`]) { taken[`${s}:${c}`] = 1; got.push(c); }
    }
    /* 다음 타이는 그다음 면부터 — 한 면에 몰리지 않게 */
    if (got.length) st.next = (got[got.length - 1] % courts) + 1;
    return got;
  };
  placed.forEach(({ tie, slot }) => {
    const a = take(slot, 2), b = take(slot + 1, 1);
    tie.matches[0].court = a[0]; tie.matches[0].slot = slot;
    tie.matches[1].court = a[1]; tie.matches[1].slot = slot;
    tie.matches[2].court = b[0]; tie.matches[2].slot = slot + 1;
    tie.slot = slot;
  });
  return st;
}

function buildCupBracket(opt) {
  const teams = (opt && opt.teams) || [];
  const startTime = (opt && opt.startTime) || '09:00';
  const cfg = Object.assign({}, CUP_DEFAULT, (opt && opt.cfg) || {});
  const courts = (opt && opt.courts) || cfg.courts || 4;

  const byGroup = { A: [], B: [] };
  teams.forEach(t => { if (byGroup[t.group]) byGroup[t.group].push(t); });
  ['A', 'B'].forEach(g => byGroup[g].sort((a, b) => a.seat - b.seat));
  const seatTeam = (g, seat) => (byGroup[g].find(t => t.seat === seat) || null);

  const pat = n => (n >= 4 ? SEAT_ROUNDS : n === 3 ? SEAT_ROUNDS3 : []);
  const mk = (id, g, p, kind) => {
    const home = seatTeam(g, p[0]), away = seatTeam(g, p[1]);
    if (!home || !away) return null;
    return { id, group: g, kind: kind || null,
      home: home.entry_id, away: away.entry_id,
      home_name: home.name, away_name: away.name,
      matches: tieMatches(id, { final: kind ? 1 : 0, fmt: cfg.final_fmt, skip: cfg.skip_dead }) };
  };

  /* 조별 타이를 만든다 — 두 조를 번갈아 늘어놓아 한 조가 몰리지 않게 */
  const gt = [];
  const maxR = Math.max(pat(byGroup.A.length).length, pat(byGroup.B.length).length);
  for (let i = 0; i < maxR; i++) {
    ['A', 'B'].forEach(g => {
      const rows = pat(byGroup[g].length)[i] || [];
      rows.forEach((p, k) => {
        const t = mk(`g${i + 1}${g}${k + 1}`, g, p);
        if (t) gt.push(t);
      });
    });
  }

  const busy = {};
  const g = packTies(gt, courts, 0, busy);
  const cst = assignCourts(g.placed, courts);

  /* 준결승은 조별이 다 끝나야 상대가 정해진다 — 그 뒤 슬롯부터 */
  const semi = [
    { id: 'sf1', group: 'F', kind: 'semi', home: null, away: null,
      home_name: 'A조 1위', away_name: 'B조 2위',
      matches: tieMatches('sf1', { final: 1, fmt: cfg.final_fmt, skip: cfg.skip_dead }) },
    { id: 'sf2', group: 'F', kind: 'semi', home: null, away: null,
      home_name: 'B조 1위', away_name: 'A조 2위',
      matches: tieMatches('sf2', { final: 1, fmt: cfg.final_fmt, skip: cfg.skip_dead }) },
  ];
  const s2 = packTies(semi, courts, g.nextSlot, {});
  assignCourts(s2.placed, courts, cst);

  const fin = [
    { id: 'fn1', group: 'F', kind: 'final', home: null, away: null,
      home_name: '준결승 1 승자', away_name: '준결승 2 승자',
      matches: tieMatches('fn1', { final: 1, fmt: cfg.final_fmt, skip: cfg.skip_dead }) },
    { id: 'fn2', group: 'F', kind: 'third', home: null, away: null,
      home_name: '준결승 1 패자', away_name: '준결승 2 패자',
      matches: tieMatches('fn2', { final: 1, fmt: cfg.final_fmt, skip: cfg.skip_dead }) },
  ];
  const f2 = packTies(fin, courts, s2.nextSlot, {});
  assignCourts(f2.placed, courts, cst);

  /* 슬롯마다 시각을 매긴다. 점심은 조별 한가운데 */
  const slotMin = Math.round((cfg.match_sec + cfg.turn_sec) / 60);
  const lunchAt = Math.floor(g.nextSlot / 2);
  const slots = [];
  let at = startTime;
  const lastSlot = f2.nextSlot - 1;
  for (let sIdx = 0; sIdx <= lastSlot; sIdx++) {
    slots.push({ s: sIdx, start: at });
    at = addMin(at, slotMin);
    if (sIdx === lunchAt && cfg.lunch_min) at = addMin(at, cfg.lunch_min);
  }
  const slotStart = n => (slots[n] || {}).start || '';

  /* 화면은 아직 <라운드> 단위로 그린다 — 슬롯을 그대로 내보내면
     한 타이가 두 줄로 쪼개져 보인다. 타이를 시작 슬롯으로 묶는다. */
  const all = [].concat(
    g.placed.map(x => ({ ...x, phase: 'group' })),
    s2.placed.map(x => ({ ...x, phase: 'semi' })),
    f2.placed.map(x => ({ ...x, phase: 'final' })));
  const bySlot = {};
  all.forEach(x => { (bySlot[x.slot] = bySlot[x.slot] || []).push(x); });
  const rounds = Object.keys(bySlot).map(Number).sort((a, b) => a - b).map((sIdx, i) => {
    const items = bySlot[sIdx];
    const ties = items.map(x => {
      x.tie.lane = null;
      return x.tie;
    });
    const ph = items[0].phase;
    return { r: i + 1, slot: sIdx, start: slotStart(sIdx),
      group: ph === 'group' ? [...new Set(ties.map(t => t.group))].join('') : 'F',
      final: ph === 'group' ? 0 : 1,
      kind: ph === 'group' ? null : (ph === 'semi' ? 'semi' : 'final'),
      ties };
  });

  return { mode: 'cup', cfg, courts, teams, rounds,
    slots, slot_min: slotMin, end: addMin(slotStart(lastSlot), slotMin) };
}

/* 조 순위 — 승점 → 매치 득실 → 게임 득실 → 승자승.
   scores: { 'r1t1m1': {a, b}, ... }  a=home 게임수, b=away 게임수 */
function cupStandings(data, scores) {
  scores = scores || {};
  const rows = {};
  const put = id => rows[id] || (rows[id] = { entry_id: id, w: 0, l: 0, pts: 0,
    mw: 0, ml: 0, gw: 0, gl: 0, beat: {} });

  (data.rounds || []).forEach(rd => {
    if (rd.final) return;                       // 결승은 순위에 안 넣는다
    (rd.ties || []).forEach(t => {
      if (!t.home || !t.away) return;
      const H = put(t.home), A = put(t.away);
      let hm = 0, am = 0, done = 0;
      t.matches.forEach(m => {
        const s = scores[m.key];
        if (!s || (s.a == null && s.b == null)) return;
        done++;
        const a = +s.a || 0, b = +s.b || 0;
        H.gw += a; H.gl += b; A.gw += b; A.gl += a;
        if (a > b) hm++; else if (b > a) am++;
      });
      if (done < 3) return;                     // 세 매치를 다 쳐야 타이가 끝난다
      H.mw += hm; H.ml += am; A.mw += am; A.ml += hm;
      if (hm > am) { H.w++; H.pts += 3; A.l++; H.beat[t.away] = 1; }
      else if (am > hm) { A.w++; A.pts += 3; H.l++; A.beat[t.home] = 1; }
    });
  });

  const byG = { A: [], B: [] };
  (data.teams || []).forEach(t => {
    const r = put(t.entry_id);
    r.name = t.name; r.group = t.group; r.seat = t.seat;
    if (byG[t.group]) byG[t.group].push(r);
  });
  ['A', 'B'].forEach(g => byG[g].sort((x, y) =>
    y.pts - x.pts ||
    (y.mw - y.ml) - (x.mw - x.ml) ||
    (y.gw - y.gl) - (x.gw - x.gl) ||
    (x.beat[y.entry_id] ? 1 : y.beat[x.entry_id] ? -1 : 0)));
  return byG;
}

/* 한 타이의 승자·패자 — 세 매치를 다 쳐야 정해진다 */
function tieWinner(t, scores) {
  let h = 0, a = 0, done = 0;
  (t.matches || []).forEach(m => {
    const s = scores[m.key];
    if (!s || (s.a == null && s.b == null)) return;
    done++;
    if ((+s.a || 0) > (+s.b || 0)) h++; else if ((+s.b || 0) > (+s.a || 0)) a++;
  });
  /* 3복식을 생략할 수 있는 타이(본선)는 2:0 이면 두 매치로 끝난다.
     조별은 세 매치를 다 쳐야 한다 — 게임 득실과 출전 인원을 세야 하기 때문이다. */
  const canSkip = (t.matches || []).some(m => m.skippable);
  const enough = done >= 3 || (canSkip && (h >= 2 || a >= 2));
  if (!enough || h === a) return null;
  return h > a
    ? { win: t.home, win_name: t.home_name, lose: t.away, lose_name: t.away_name }
    : { win: t.away, win_name: t.away_name, lose: t.home, lose_name: t.home_name };
}

/* 조별이 끝나면 준결승을, 준결승이 끝나면 결승·3위전을 채운다 */
function cupFillFinal(data, scores) {
  scores = scores || {};
  const st = cupStandings(data, scores);
  const rs = data.rounds || [];
  const semi = rs.find(r => r.kind === 'semi');
  const fin = rs.find(r => r.kind === 'final');
  const set = (t, h, w) => {
    if (h) { t.home = h.entry_id || h.win || h.lose; t.home_name = h.name || h.win_name || h.lose_name; }
    if (w) { t.away = w.entry_id || w.win || w.lose; t.away_name = w.name || w.win_name || w.lose_name; }
  };
  const a = st.A, b = st.B;
  if (semi) {
    /* 조를 엇갈려 붙인다 — 같은 조끼리 다시 만나지 않게 */
    set(semi.ties[0], a[0], b[1]);
    set(semi.ties[1], b[0], a[1]);
  }
  if (semi && fin) {
    const w1 = tieWinner(semi.ties[0], scores), w2 = tieWinner(semi.ties[1], scores);
    if (w1 && w2) {
      fin.ties[0].home = w1.win; fin.ties[0].home_name = w1.win_name;
      fin.ties[0].away = w2.win; fin.ties[0].away_name = w2.win_name;
      fin.ties[1].home = w1.lose; fin.ties[1].home_name = w1.lose_name;
      fin.ties[1].away = w2.lose; fin.ties[1].away_name = w2.lose_name;
    }
  }
  return data;
}

/* 추첨 — 자리만 섞는다. 주최 클럽을 특정 조에 고정하지 않는다(공정성 시비).

   xorshift 는 씨앗이 작으면 첫 몇 개가 쏠린다. 1~400 을 넣어 400번 돌려보니
   첫 클럽이 A조에 한 번도 안 갔다. 씨앗을 먼저 흩고 앞의 몇 개를 버린다.
   추첨을 참가 클럽 앞에서 돌리는데 여기가 치우쳐 있으면 대회가 시작도 못 한다. */
function cupDraw(entries, seed) {
  let x = (seed == null ? Date.now() : seed) >>> 0;
  /* 씨앗 흩기 — 작은 수도 32비트에 고르게 퍼뜨린다 */
  x = (x ^ 0x9e3779b9) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x85ebca6b) >>> 0;
  x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35) >>> 0;
  x = (x ^ (x >>> 16)) >>> 0 || 1;
  const rnd = () => { x ^= x << 13; x >>>= 0; x ^= x >> 17; x ^= x << 5; x >>>= 0; return x / 4294967296; };
  for (let i = 0; i < 8; i++) rnd();            // 앞의 몇 개는 버린다

  const list = entries.slice();
  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [list[i], list[j]] = [list[j], list[i]];
  }
  const [sa] = cupGroupSizes(list.length);
  return list.map((e, i) => ({
    entry_id: e.id || e.entry_id, name: e.club_name || e.name,
    group: i < sa ? 'A' : 'B', seat: (i < sa ? i : i - sa) + 1,
  }));
}

/* 기본값 — 대회마다 바꿀 수 있다.
   상수로 두면 두 번째 대회에서 참가비나 팀 수를 못 고친다. */
const CUP_FEE = 450000, CUP_DEPOSIT = 100000, CUP_MIN_TEAMS = 6, CUP_MAX_TEAMS = 8;

/* 이 대회의 설정 — data 에 없으면 기본값 */
function cupCfg(b) {
  let d = {};
  try { d = typeof b === 'string' ? JSON.parse(b || '{}') : (b || {}); } catch (e) {}
  return {
    title: d.title || 'MATSU CUP',
    start: d.start || '09:00',
    place: d.place || '',
    pay: d.pay || null,
    fee: d.fee != null ? +d.fee : CUP_FEE,
    deposit: d.deposit != null ? +d.deposit : CUP_DEPOSIT,
    min_teams: d.min_teams ? +d.min_teams : CUP_MIN_TEAMS,
    max_teams: d.max_teams ? +d.max_teams : CUP_MAX_TEAMS,
    prize_pct: d.prize_pct != null ? +d.prize_pct : 85,
    /* 비용은 항목으로 갖는다 — 합계 한 칸만 두면 견적이 바뀌었을 때
       그 안에 뭐가 들었는지 몰라 통째로 다시 계산해야 한다. */
    fixed_items: Array.isArray(d.fixed_items) && d.fixed_items.length ? d.fixed_items : [
      { n: '코트 대관', h: '4면 × 8시간', v: 480000 },
      { n: '운영 인력', h: '2명 × 18만', v: 360000 },
      { n: '단체 상해보험', h: '80명', v: 200000 },
      { n: '트로피·메달', h: '', v: 180000 },
      { n: '현수막·비품·구급함', h: '', v: 180000 },
    ],
    var_items: Array.isArray(d.var_items) && d.var_items.length ? d.var_items : [
      { n: '공', h: '타이당 1통', v: 22000 },
      { n: '음료·간식', h: '', v: 18000 },
    ],
  };
}

/* 정산 — 여기가 틀리면 대회가 끝나고 돈이 모자란다.

   보증금은 수입이 아니다. 완주하면 돌려줄 돈이라 처음부터 빼고 세야 한다.
   상금을 <참가비 총액의 25%>로 잡으면 8팀에 70만이 나오는데,
   실제로 쓸 수 있는 돈은 200만이고 비용이 158만이라 42만밖에 안 남는다.
   그대로 주면 28만 적자다.

   그래서 상금은 <비용을 빼고 남은 돈의 몇 %>로 센다.
   팀이 적게 오면 남는 돈이 줄고 상금도 같이 줄어 적자가 날 수 없다. */
const sumItems = a => (a || []).reduce((x, i) => x + (+i.v || 0), 0);

function cupMoney(C, teams) {
  C = Object.assign({}, C, {
    fixed_cost: sumItems(C.fixed_items),
    var_cost: sumItems(C.var_items),
  });
  const gross = teams * C.fee;                 // 걷은 돈
  const deposits = teams * C.deposit;          // 돌려줄 돈
  const net = gross - deposits;                // 실제로 쓸 수 있는 돈
  const cost = C.fixed_cost + teams * C.var_cost;
  const left = net - cost;                     // 상금 주기 전 잔액
  const prize = Math.max(0, Math.round(left * C.prize_pct / 100));
  return { gross, deposits, net, cost, left, prize,
    rest: left - prize,                        // 대회 끝나고 남는 돈
    first: Math.round(prize * 0.5 / 10000) * 10000,
    second: Math.round(prize * 0.3 / 10000) * 10000,
    third: Math.round(prize * 0.2 / 10000) * 10000 };
}
/* 구력 합산 상한 — 1복식은 제한 없음, 혼복 20년, 3복식 16년.
   NTRP 로 잡았다가 구력으로 바꿨다. 앱에 NTRP 칸이 없어 등급을 환산해야 했는데,
   그 환산이 정확하지 않아 대표가 손볼 여지를 열어야 했고, 그러면 상한이 무의미해진다.
   구력은 sport_started 로 이미 서버가 갖고 있는 값이라 손댈 수 없다.

   강팀도 저변이 없으면 못 이기게 만드는 장치다. 규모가 작다고 빼면 안 된다. */
const CUP_CAP = { 1: null, 2: 20, 3: 16 };      // 년 단위
const CUP_ROSTER_N = 10, CUP_ROSTER_F = 2;

function cupBracket(id) {
  return db.prepare("SELECT * FROM brackets WHERE id=? AND fmt='cup'").get(+id);
}
function cupHost(b, uid) { return b && isOfficer(b.club_id, uid); }
function cupEntryByToken(tok) {
  return db.prepare('SELECT * FROM cup_entries WHERE invite_token=?').get(String(tok || ''));
}

/* ── 주최 ─────────────────────────────────────────────── */

/* 초청 명단에 클럽 한 곳을 올린다. 링크는 이때 만들어진다. */
app.post('/cup/:bid/entries', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  if (!cupHost(b, req.uid)) return res.status(403).json({ error: 'host_only', message: '주최 클럽 운영진만 할 수 있어요' });
  const name = String((req.body || {}).club_name || '').trim().slice(0, 40);
  if (!name) return res.status(400).json({ error: 'empty', message: '클럽 이름을 적어주세요' });
  const C0 = cupCfg(b.data);
  const n = db.prepare("SELECT COUNT(*) n FROM cup_entries WHERE bracket_id=? AND status!='cancelled'").get(b.id).n;
  if (n >= C0.max_teams)
    return res.status(400).json({ error: 'full', message: `${C0.max_teams}팀이 다 찼어요` });
  const tok = crypto.randomBytes(9).toString('base64url');
  const r = db.prepare(`INSERT INTO cup_entries
    (bracket_id,club_id,club_name,contact_name,contact_phone,invite_token,created_at)
    VALUES (?,?,?,?,?,?,?)`).run(b.id, +(req.body || {}).club_id || null, name,
    String((req.body || {}).contact_name || '').slice(0, 20) || null,
    String((req.body || {}).contact_phone || '').replace(/\D/g, '').slice(0, 11) || null,
    tok, now());
  res.json({ ok: true, id: rid(r), token: tok });
});

app.get('/cup/:bid/entries', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  if (!cupHost(b, req.uid)) return res.status(403).json({ error: 'host_only' });
  const rows = db.prepare('SELECT * FROM cup_entries WHERE bracket_id=? ORDER BY id').all(b.id);
  rows.forEach(r => {
    r.roster_n = db.prepare('SELECT COUNT(*) n FROM cup_roster WHERE entry_id=?').get(r.id).n;
    r.female_n = db.prepare("SELECT COUNT(*) n FROM cup_roster WHERE entry_id=? AND gender='F'").get(r.id).n;
  });
  const live = rows.filter(r => r.status !== 'cancelled');
  const paid = live.filter(r => r.fee_paid);
  /* 상금은 참가비 총액의 25% — 금액을 못 박지 않는다.
     팀이 적게 오면 상금도 줄어서 적자가 날 수 없다. */
  const C = cupCfg(b.data);
  res.json({
    entries: rows, teams: live.length, paid: paid.length,
    title: C.title, date: b.date, place: C.place, pay: C.pay,
    min_teams: C.min_teams, max_teams: C.max_teams,
    fee: C.fee, deposit: C.deposit,
    income: paid.length * C.fee,
    money: cupMoney(C, paid.length),
    ok_to_run: live.length >= C.min_teams,
  });
});

app.patch('/cup/entries/:id', auth, (req, res) => {
  const e = db.prepare('SELECT * FROM cup_entries WHERE id=?').get(+req.params.id);
  if (!e) return res.status(404).json({ error: 'no_entry' });
  const b = cupBracket(e.bracket_id);
  if (!cupHost(b, req.uid)) return res.status(403).json({ error: 'host_only' });
  const bd = req.body || {};
  const st = ['invited', 'applied', 'paid', 'confirmed', 'cancelled'].includes(bd.status) ? bd.status : null;
  const dep = ['none', 'held', 'returned', 'forfeited'].includes(bd.deposit_state) ? bd.deposit_state : null;
  db.prepare(`UPDATE cup_entries SET status=COALESCE(?,status),
      fee_paid=COALESCE(?,fee_paid), deposit_state=COALESCE(?,deposit_state) WHERE id=?`)
    .run(st, bd.fee_paid == null ? null : (bd.fee_paid ? 1 : 0), dep, e.id);
  res.json({ ok: true });
});





/* 입금 계좌·장소 고치기 — 대회를 만든 뒤에도 바뀐다 */
app.patch('/cup/:bid', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  if (!cupHost(b, req.uid)) return res.status(403).json({ error: 'host_only' });
  const q = req.body || {};
  let data = {}; try { data = JSON.parse(b.data || '{}'); } catch (e) {}
  data.pay = data.pay || {};
  if (q.bank != null) data.pay.bank = String(q.bank).trim().slice(0, 20);
  if (q.account != null) data.pay.no = String(q.account).replace(/[^0-9-]/g, '').slice(0, 30);
  if (q.holder != null) data.pay.holder = String(q.holder).trim().slice(0, 20);
  if (q.place != null) data.place = String(q.place).trim().slice(0, 40);
  if (q.title != null) data.title = String(q.title).trim().slice(0, 60);
  db.prepare('UPDATE brackets SET data=?, updated_at=? WHERE id=?')
    .run(JSON.stringify(data), now(), b.id);
  res.json({ ok: true, pay: data.pay, place: data.place || '' });
});

/* 추첨 — 자리를 섞고 대진을 만든다. 참가 클럽 앞에서 돌린다. */
app.post('/cup/:bid/draw', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  if (!cupHost(b, req.uid)) return res.status(403).json({ error: 'host_only' });
  const rows = db.prepare(`SELECT id, club_name FROM cup_entries
    WHERE bracket_id=? AND status!='cancelled' ORDER BY id`).all(b.id);
  if (rows.length < cupCfg(data).min_teams)
    return res.status(400).json({ error: 'too_few',
      message: `${cupCfg(data).min_teams}팀이 모여야 열 수 있어요 (지금 ${rows.length}팀)` });

  let data = {}; try { data = JSON.parse(b.data || '{}'); } catch (e) {}
  const seed = +(req.body || {}).seed || (Date.now() & 0x7fffffff);
  const teams = cupDraw(rows, seed);
  const built = buildCupBracket({ teams, startTime: data.start || '09:00', cfg: data.cfg });
  const out = Object.assign({}, data, built, { drawn_at: now(), seed });

  db.transaction(() => {
    db.prepare('UPDATE brackets SET data=?, updated_at=? WHERE id=?')
      .run(JSON.stringify(out), now(), b.id);
    const up = db.prepare('UPDATE cup_entries SET group_label=?, seat=? WHERE id=?');
    teams.forEach(t => up.run(t.group, t.seat, t.entry_id));
  })();
  res.json({ ok: true, teams, rounds: out.rounds.length, seed });
});

/* 조 순위 — 관전 화면과 운영 화면이 같은 값을 본다.
   앱마다 따로 세면 화면끼리 숫자가 어긋난다. */
app.get('/cup/:bid/standings', (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  let data = {}; try { data = JSON.parse(b.data || '{}'); } catch (e) {}
  const sc = {};
  db.prepare('SELECT court_key,a,b FROM bracket_scores WHERE bracket_id=?').all(b.id)
    .forEach(r => { sc[r.court_key] = { a: r.a, b: r.b }; });
  const st = cupStandings(data, sc);
  /* 조별이 다 끝났으면 결승 자리를 채워 돌려준다 */
  const doneAll = (data.rounds || []).filter(r => !r.final)
    .every(r => r.ties.every(t => t.matches.every(m => sc[m.key] && sc[m.key].a != null)));
  if (doneAll) cupFillFinal(data, sc);
  res.json({ standings: st, rounds: data.rounds || [], teams: data.teams || [],
    cfg: data.cfg || CUP_DEFAULT, title: data.title || '', done: doneAll,
    server_now: Date.now() });
});

/* ── 관리자 ───────────────────────────────────────────────
   MATSU CUP 은 플랫폼이 여는 대회다. 클럽마다 <제1회>를 열 수 있으면
   같은 이름의 대회가 여덟 개 생긴다. 그래서 여는 자리는 관리자에만 둔다. */
app.get('/admin/cups', admin, (_req, res) => {
  const rows = db.prepare(`SELECT id,club_id,date,published,data,updated_at FROM brackets
    WHERE fmt='cup' ORDER BY id DESC LIMIT 30`).all();
  res.json(rows.map(r => {
    let d = {}; try { d = JSON.parse(r.data || '{}'); } catch (e) {}
    const live = db.prepare("SELECT COUNT(*) n FROM cup_entries WHERE bracket_id=? AND status!='cancelled'").get(r.id).n;
    const paid = db.prepare("SELECT COUNT(*) n FROM cup_entries WHERE bracket_id=? AND status='confirmed'").get(r.id).n;
    return { id: r.id, date: r.date, open: !!r.published,
      title: d.title || 'MATSU CUP', place: d.place || '', pay: d.pay || null,
      host: (db.prepare('SELECT name FROM clubs WHERE id=?').get(r.club_id) || {}).name || '',
      host_id: r.club_id, teams: live, paid, drawn: !!d.drawn_at,
      income: paid * cupCfg(d).fee, money: cupMoney(cupCfg(d), paid),
      min_teams: cupCfg(d).min_teams, max_teams: cupCfg(d).max_teams, fee: cupCfg(d).fee };
  }));
});

app.post('/admin/cups', admin, (req, res) => {
  const b = req.body || {};
  const cid = +b.host_club_id;
  if (!cid || !db.prepare('SELECT 1 FROM clubs WHERE id=?').get(cid))
    return res.status(400).json({ error: 'no_club', message: '주최 클럽을 골라주세요' });
  const date = String(b.date || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date))
    return res.status(400).json({ error: 'bad_date', message: '날짜를 골라주세요' });
  const data = { mode: 'cup', cfg: Object.assign({}, CUP_DEFAULT),
    title: String(b.title || '제1회 MATSU CUP 초청 클럽대항전').slice(0, 60),
    start: String(b.start || '09:00').slice(0, 5),
    place: String(b.place || '').trim().slice(0, 40),
    pay: { bank: String(b.bank || '').trim().slice(0, 20),
      no: String(b.account || '').replace(/[^0-9-]/g, '').slice(0, 30),
      holder: String(b.holder || '').trim().slice(0, 20) },
    teams: [], rounds: [] };
  const r = db.prepare(`INSERT INTO brackets
    (club_id,sport,fmt,date,courts,data,published,created_by,created_at,updated_at)
    VALUES (?,'tennis','cup',?,4,?,0,?,?,?)`)
    .run(cid, date, JSON.stringify(data), req.uid || 0, now(), now());
  res.json({ ok: true, id: rid(r) });
});

app.get('/admin/cups/:bid', admin, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  let d = {}; try { d = JSON.parse(b.data || '{}'); } catch (e) {}
  const rows = db.prepare('SELECT * FROM cup_entries WHERE bracket_id=? ORDER BY id').all(b.id);
  rows.forEach(r => {
    r.roster_n = db.prepare('SELECT COUNT(*) n FROM cup_roster WHERE entry_id=?').get(r.id).n;
    r.female_n = db.prepare("SELECT COUNT(*) n FROM cup_roster WHERE entry_id=? AND gender='F'").get(r.id).n;
  });
  res.json({ id: b.id, date: b.date, open: !!b.published, title: d.title || '',
    place: d.place || '', pay: d.pay || null, start: d.start || '09:00',
    drawn: !!d.drawn_at, rounds: d.rounds || [], teams: d.teams || [],
    entries: rows, courts: b.courts,
    fee: cupCfg(d).fee, deposit: cupCfg(d).deposit, prize_pct: cupCfg(d).prize_pct,
    fixed_items: cupCfg(d).fixed_items, var_items: cupCfg(d).var_items,
    fixed_cost: sumItems(cupCfg(d).fixed_items), var_cost: sumItems(cupCfg(d).var_items),
    cfg: Object.assign({}, CUP_DEFAULT, d.cfg || {}),
    min_teams: cupCfg(d).min_teams, max_teams: cupCfg(d).max_teams,
    money: cupMoney(cupCfg(d),
      rows.filter(r => r.status === 'confirmed').length) });
});

/* 관리자는 주최 클럽 운영진이 아니어도 손댈 수 있어야 한다 */
app.post('/admin/cups/:bid/act', admin, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  const q = req.body || {}, act = String(q.act || '');
  let d = {}; try { d = JSON.parse(b.data || '{}'); } catch (e) {}

  if (act === 'open') {
    db.prepare('UPDATE brackets SET published=?, updated_at=? WHERE id=?')
      .run(q.on ? 1 : 0, now(), b.id);
    return res.json({ ok: true });
  }
  /* 설정 — 제목·날짜·장소·정원·참가비를 한 번에 받는다.
     따로따로 고치게 하면 <참가비만 바꾸려다 날짜가 지워지는> 일이 생긴다. */
  if (act === 'setup') {
    if (q.title != null) d.title = String(q.title).trim().slice(0, 60);
    if (q.start != null) d.start = String(q.start).slice(0, 5);
    if (q.place != null) d.place = String(q.place).trim().slice(0, 40);
    if (q.bank != null || q.account != null || q.holder != null) {
      d.pay = { bank: String(q.bank || '').trim().slice(0, 20),
        no: String(q.account || '').replace(/[^0-9-]/g, '').slice(0, 30),
        holder: String(q.holder || '').trim().slice(0, 20) };
    }
    const num = (v, lo, hi) => { const n = Math.round(+v); return (n >= lo && n <= hi) ? n : null; };
    const fee = num(q.fee, 0, 5000000);         if (fee != null) d.fee = fee;
    const dep = num(q.deposit, 0, 5000000);     if (dep != null) d.deposit = dep;
    const mx = num(q.max_teams, 2, 32);         if (mx != null) d.max_teams = mx;
    const mn = num(q.min_teams, 2, 32);         if (mn != null) d.min_teams = mn;
    const pc = num(q.prize_pct, 0, 100);        if (pc != null) d.prize_pct = pc;
    const items = (arr, cap) => (Array.isArray(arr) ? arr : []).slice(0, 12)
      .map(x => ({ n: String(x.n || '').slice(0, 24),
        h: String(x.h || '').slice(0, 24),
        v: Math.max(0, Math.min(cap, Math.round(+x.v || 0))) }))
      .filter(x => x.n);
    if (Array.isArray(q.fixed_items)) d.fixed_items = items(q.fixed_items, 50000000);
    if (Array.isArray(q.var_items)) d.var_items = items(q.var_items, 5000000);
    /* 본선 포맷 — 대진이 이미 짜였으면 다시 추첨해야 반영된다 */
    d.cfg = d.cfg || {};
    if (q.final_fmt === 'timed' || q.final_fmt === 'pro6') d.cfg.final_fmt = q.final_fmt;
    if (q.skip_dead != null) d.cfg.skip_dead = q.skip_dead ? true : false;
    const ms = num(q.match_min, 10, 60);   if (ms != null) d.cfg.match_sec = ms * 60;
    const ts = num(q.turn_min, 0, 20);     if (ts != null) d.cfg.turn_sec = ts * 60;
    /* 손익분기가 정원보다 크면 영영 못 연다 */
    if (d.min_teams && d.max_teams && d.min_teams > d.max_teams)
      return res.status(400).json({ error: 'bad',
        message: `손익분기(${d.min_teams}팀)가 정원(${d.max_teams}팀)보다 클 수 없어요` });

    const date = String(q.date || '').slice(0, 10);
    const courts = num(q.courts, 1, 12);
    db.prepare(`UPDATE brackets SET data=?, date=COALESCE(NULLIF(?,''),date),
        courts=COALESCE(?,courts), updated_at=? WHERE id=?`)
      .run(JSON.stringify(d), /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : '', courts, now(), b.id);
    return res.json({ ok: true });
  }
  if (act === 'invite') {
    const name = String(q.club_name || '').trim().slice(0, 40);
    if (!name) return res.status(400).json({ error: 'empty', message: '클럽 이름을 적어주세요' });
    const n = db.prepare("SELECT COUNT(*) n FROM cup_entries WHERE bracket_id=? AND status!='cancelled'").get(b.id).n;
    if (n >= cupCfg(d).max_teams) return res.status(400).json({ error: 'full', message: '자리가 다 찼어요' });
    const tok = crypto.randomBytes(9).toString('base64url');
    const r = db.prepare(`INSERT INTO cup_entries
      (bracket_id,club_name,contact_name,contact_phone,invite_token,created_at)
      VALUES (?,?,?,?,?,?)`).run(b.id, name,
      String(q.contact_name || '').slice(0, 20) || null,
      String(q.contact_phone || '').replace(/\D/g, '').slice(0, 11) || null, tok, now());
    return res.json({ ok: true, id: rid(r), token: tok });
  }
  if (act === 'entry') {
    const e = db.prepare('SELECT * FROM cup_entries WHERE id=? AND bracket_id=?').get(+q.entry_id, b.id);
    if (!e) return res.status(404).json({ error: 'no_entry' });

    /* 입금이 들어온 걸 확인하면 그 자리에서 확정한다.
       <입금 확인>과 <확정>을 따로 누르게 하면 하나만 눌러놓고 잊는다.
       보증금도 같이 <잡아둠>으로 옮긴다 — 완주하면 돌려주고 기권하면 몰수한다. */
    if (q.confirm != null) {
      if (q.confirm) {
        const n = db.prepare("SELECT COUNT(*) n FROM cup_entries WHERE bracket_id=? AND status='confirmed'").get(b.id).n;
        if (n >= cupCfg(d).max_teams)
          return res.status(400).json({ error: 'full',
            message: `확정된 팀이 이미 ${cupCfg(d).max_teams}곳이에요` });
        const ros = db.prepare('SELECT COUNT(*) n FROM cup_roster WHERE entry_id=?').get(e.id).n;
        db.prepare(`UPDATE cup_entries SET fee_paid=1, status='confirmed',
          deposit_state='held' WHERE id=?`).run(e.id);
        /* 엔트리를 아직 안 낸 팀도 확정할 수 있다 — 돈이 먼저 들어오는 게 보통이다.
           다만 대진을 짜기 전에는 채워야 하니 알려준다. */
        return res.json({ ok: true, warn: ros >= 10 ? null : '엔트리 10명은 아직 안 냈어요' });
      }
      db.prepare(`UPDATE cup_entries SET fee_paid=0, status='applied',
        deposit_state='none' WHERE id=?`).run(e.id);
      return res.json({ ok: true });
    }

    const st = ['invited', 'applied', 'paid', 'confirmed', 'cancelled'].includes(q.status) ? q.status : null;
    const dep = ['none', 'held', 'returned', 'forfeited'].includes(q.deposit_state) ? q.deposit_state : null;
    db.prepare(`UPDATE cup_entries SET status=COALESCE(?,status),
        fee_paid=COALESCE(?,fee_paid), deposit_state=COALESCE(?,deposit_state) WHERE id=?`)
      .run(st, q.fee_paid == null ? null : (q.fee_paid ? 1 : 0), dep, e.id);
    return res.json({ ok: true });
  }
  if (act === 'draw') {
    /* 확정된 팀만 대진에 넣는다 — 입금 안 한 팀을 넣으면 당일에 자리가 빈다.
       부전승이 아마추어 단체전을 죽인다. */
    const rows = db.prepare(`SELECT id, club_name FROM cup_entries
      WHERE bracket_id=? AND status='confirmed' ORDER BY id`).all(b.id);
    if (rows.length < cupCfg(d).min_teams)
      return res.status(400).json({ error: 'too_few',
        message: `확정된 팀이 ${cupCfg(d).min_teams}곳은 되어야 해요 (지금 ${rows.length}곳)` });
    const noRoster = rows.filter(r =>
      db.prepare('SELECT COUNT(*) n FROM cup_roster WHERE entry_id=?').get(r.id).n < 10);
    if (noRoster.length)
      return res.status(400).json({ error: 'no_roster',
        message: `엔트리를 안 낸 팀이 있어요 · ${noRoster.map(r => r.club_name).join(' · ')}` });
    const seed = +q.seed || (Date.now() & 0x7fffffff);
    const teams = cupDraw(rows, seed);
    const built = buildCupBracket({ teams, startTime: d.start || '09:00', cfg: d.cfg });
    const out = Object.assign({}, d, built, { drawn_at: now(), seed });
    db.transaction(() => {
      db.prepare('UPDATE brackets SET data=?, updated_at=? WHERE id=?')
        .run(JSON.stringify(out), now(), b.id);
      const up = db.prepare('UPDATE cup_entries SET group_label=?, seat=? WHERE id=?');
      teams.forEach(t => up.run(t.group, t.seat, t.entry_id));
    })();
    return res.json({ ok: true, teams, seed });
  }
  res.status(400).json({ error: 'bad_act' });
});

/* ── 앱 쓰는 클럽 ────────────────────────────────────────
   초청 링크와 달리 로그인해서 들어온다. 회원 명단이 이미 있으니
   이름·성별·NTRP 를 다시 치게 하지 않는다. 골라서 채운다. */

/* 클럽 탭에 띄울 모집 카드 — 공개된 대회가 있으면 그 한 건 */
app.get('/clubs/:id/cup-open', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const b = db.prepare(`SELECT id,date,data,club_id FROM brackets
    WHERE fmt='cup' AND published=1 ORDER BY id DESC LIMIT 1`).get();
  if (!b) return res.json({ cup: null });
  let d = {}; try { d = JSON.parse(b.data || '{}'); } catch (e) {}
  const C = cupCfg(d);
  const live = db.prepare("SELECT COUNT(*) n FROM cup_entries WHERE bracket_id=? AND status!='cancelled'").get(b.id).n;
  const mine = db.prepare("SELECT * FROM cup_entries WHERE bracket_id=? AND club_id=? AND status!='cancelled'").get(b.id, cid);
  const roster = mine
    ? db.prepare('SELECT COUNT(*) n FROM cup_roster WHERE entry_id=?').get(mine.id).n : 0;
  /* 마감까지 며칠 — 입금은 대회 21일 전이다 */
  let dday = null;
  if (b.date) {
    const due = new Date(b.date + 'T00:00:00').getTime() - 21 * 864e5;
    dday = Math.ceil((due - Date.now()) / 864e5);
  }
  res.json({ cup: {
    id: b.id, date: b.date, title: d.title || 'MATSU CUP', place: d.place || '',
    pay: C.pay, fee: C.fee, deposit: C.deposit,
    teams: live, max_teams: C.max_teams, min_teams: C.min_teams,
    left: Math.max(0, C.max_teams - live), dday,
    host: (db.prepare('SELECT name FROM clubs WHERE id=?').get(b.club_id) || {}).name || '',
    is_host: b.club_id === cid,
  }, entry: mine ? { id: mine.id, status: mine.status, fee_paid: mine.fee_paid,
    group_label: mine.group_label, seat: mine.seat, roster_n: roster } : null });
});

/* 신청 — 우리 클럽 이름으로 자리를 잡는다 */
app.post('/cup/:bid/apply', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  const cid = +(req.body || {}).club_id;
  if (!cid || !isOfficer(cid, req.uid))
    return res.status(403).json({ error: 'officer_only', message: '클럽 운영진만 신청할 수 있어요' });
  const had = db.prepare("SELECT * FROM cup_entries WHERE bracket_id=? AND club_id=? AND status!='cancelled'").get(b.id, cid);
  if (had) return res.json({ ok: true, id: had.id, already: true });
  const n = db.prepare("SELECT COUNT(*) n FROM cup_entries WHERE bracket_id=? AND status!='cancelled'").get(b.id).n;
  if (n >= cupCfg(b.data).max_teams)
    return res.status(400).json({ error: 'full', message: '자리가 다 찼어요' });
  const c = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid) || {};
  const u = db.prepare('SELECT name, phone FROM users WHERE id=?').get(req.uid) || {};
  const r = db.prepare(`INSERT INTO cup_entries
    (bracket_id,club_id,club_name,contact_name,contact_phone,status,invite_token,applied_at,created_at)
    VALUES (?,?,?,?,?,'applied',?,?,?)`)
    .run(b.id, cid, c.name || '클럽', u.name || null, u.phone || null,
      crypto.randomBytes(9).toString('base64url'), now(), now());
  res.json({ ok: true, id: rid(r) });
});

/* 구력(년) — sport_started 에서 계산한다. 앱이 보낸 값을 안 받는다.
   등급 환산은 부정확해서 손볼 여지를 열어야 했고, 그러면 상한이 무의미해졌다.
   구력은 가입할 때 적은 값이라 대회 때문에 고칠 수 없다. */
function careerYears(uid) {
  const m = careerMonths(uid, 'tennis');
  return m == null ? null : Math.floor(m / 12);
}

/* 엔트리 — 회원 id 로 낸다. 이름·성별·구력을 서버가 회원 표에서 가져온다.
   앱이 보낸 값을 믿으면 성별이나 구력을 바꿔 적어 규칙을 피할 수 있다. */
app.post('/cup/:bid/roster', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  const cid = +(req.body || {}).club_id;
  if (!cid || !isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const e = db.prepare("SELECT * FROM cup_entries WHERE bracket_id=? AND club_id=? AND status!='cancelled'").get(b.id, cid);
  if (!e) return res.status(400).json({ error: 'not_applied', message: '먼저 참가 신청을 해주세요' });

  const ids = Array.isArray((req.body || {}).user_ids) ? (req.body || {}).user_ids.map(Number) : [];
  const rows = ids.map(uid => {
    const m = db.prepare(`SELECT m.user_id, m.gender_ov, m.grade, m.alias,
        u.name, u.gender, u.birth_year FROM club_members m JOIN users u ON u.id=m.user_id
      WHERE m.club_id=? AND m.user_id=?`).get(cid, uid);
    if (!m) return null;
    const y = careerYears(m.user_id);
    if (y == null) return { err: `${m.alias || m.name}님은 구력이 없어요` };
    return { user_id: m.user_id, guest_name: m.alias || m.name,
      gender: (m.gender_ov || m.gender || 'M') === 'F' ? 'F' : 'M',
      ntrp: y, birth_year: m.birth_year || null };
  });
  const bad = rows.find(r => r && r.err);
  if (bad) return res.status(400).json({ error: 'no_career',
    message: bad.err + ' · 내정보에서 테니스 시작 시기를 적어야 나올 수 있어요' });
  if (rows.some(r => !r))
    return res.status(400).json({ error: 'not_member', message: '우리 클럽 회원만 넣을 수 있어요' });
  const why = cupCheckRoster(rows.map(r => Object.assign({}, r, {
    guardian_consent: 1, health_declared: 1 })));
  if (why) return res.status(400).json({ error: 'bad_roster', message: why });

  db.transaction(() => {
    db.prepare('DELETE FROM cup_roster WHERE entry_id=?').run(e.id);
    const ins = db.prepare(`INSERT INTO cup_roster
      (entry_id,user_id,guest_name,gender,ntrp,birth_year,slot,guardian_consent,health_declared)
      VALUES (?,?,?,?,?,?,?,1,1)`);
    rows.forEach((r, i) => ins.run(e.id, r.user_id, r.guest_name, r.gender, r.ntrp, r.birth_year, i + 1));
  })();
  res.json({ ok: true, n: rows.length });
});

/* 엔트리에 넣을 수 있는 회원 명단 — 이름·성별·등급을 붙여 준다.
   앱이 회원 목록을 따로 부르면 성별과 등급이 화면마다 다르게 나온다. */
app.get('/cup/:bid/pool', auth, (req, res) => {
  const cid = +req.query.club_id;
  if (!cid || !isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT m.user_id, m.grade, m.gender_ov, m.alias, m.resting,
      u.name, u.gender, u.birth_year FROM club_members m JOIN users u ON u.id=m.user_id
    WHERE m.club_id=? ORDER BY u.name`).all(cid);
  res.json(rows.map(m => ({
    user_id: m.user_id, name: m.alias || m.name,
    gender: (m.gender_ov || m.gender || 'M') === 'F' ? 'F' : 'M',
    grade: m.grade || '', years: careerYears(m.user_id),
    birth_year: m.birth_year || null, resting: m.resting ? 1 : 0,
  })));
});

/* 우리 클럽이 낸 엔트리 — 신청 화면을 다시 열 때 그대로 보여준다 */
app.get('/cup/:bid/my', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  const cid = +req.query.club_id;
  if (!cid || !isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const e = db.prepare("SELECT * FROM cup_entries WHERE bracket_id=? AND club_id=? AND status!='cancelled'").get(b.id, cid);
  if (!e) return res.json({ entry: null, roster: [] });
  res.json({ entry: { id: e.id, status: e.status, fee_paid: e.fee_paid,
      group_label: e.group_label, seat: e.seat },
    roster: db.prepare('SELECT * FROM cup_roster WHERE entry_id=? ORDER BY slot').all(e.id) });
});

/* 모집 열기·닫기 — published 로 클럽 탭 카드를 켠다 */
app.post('/cup/:bid/open', auth, (req, res) => {
  const b = cupBracket(req.params.bid);
  if (!b) return res.status(404).json({ error: 'no_cup' });
  if (!cupHost(b, req.uid)) return res.status(403).json({ error: 'host_only' });
  const on = (req.body || {}).open ? 1 : 0;
  db.prepare('UPDATE brackets SET published=?, updated_at=? WHERE id=?').run(on, now(), b.id);
  res.json({ ok: true, open: !!on });
});

/* ── 초청받은 클럽 (로그인 없음) ───────────────────────────
   토큰만으로 들어온다. 이 링크를 아는 사람이 그 클럽 대표자다. */

app.get('/cup/invite/:token', (req, res) => {
  const e = cupEntryByToken(req.params.token);
  if (!e) return res.status(404).json({ error: 'no_invite', message: '초청장을 찾을 수 없어요' });
  const b = db.prepare('SELECT id,date,courts,data,club_id FROM brackets WHERE id=?').get(e.bracket_id);
  let cfg = {}; try { cfg = JSON.parse(b.data || '{}').cfg || {}; } catch (x) {}
  const host = db.prepare('SELECT name FROM clubs WHERE id=?').get(b ? b.club_id : 0);
  const roster = db.prepare(`SELECT id,user_id,guest_name,gender,ntrp,birth_year,slot,
      guardian_consent,health_declared FROM cup_roster WHERE entry_id=? ORDER BY slot,id`).all(e.id);
  res.json({
    entry: { id: e.id, club_name: e.club_name, status: e.status,
      contact_name: e.contact_name, fee_paid: e.fee_paid },
    cup: { date: b ? b.date : null, courts: b ? b.courts : 0,
      host: host ? host.name : '',
      fee: cupCfg(b.data).fee, deposit: cupCfg(b.data).deposit,
      min_teams: cupCfg(b.data).min_teams, max_teams: cupCfg(b.data).max_teams, cfg,
      place: (() => { try { return JSON.parse(b.data || '{}').place || ''; } catch (x) { return ''; } })(),
      pay: (() => { try { return JSON.parse(b.data || '{}').pay || null; } catch (x) { return null; } })() },
    roster, need: { n: CUP_ROSTER_N, female: CUP_ROSTER_F },
  });
});

app.post('/cup/invite/:token/apply', (req, res) => {
  const e = cupEntryByToken(req.params.token);
  if (!e) return res.status(404).json({ error: 'no_invite' });
  if (e.status === 'cancelled') return res.status(400).json({ error: 'cancelled', message: '취소된 신청이에요' });
  const b = req.body || {};
  const nm = String(b.contact_name || '').trim().slice(0, 20);
  const ph = String(b.contact_phone || '').replace(/\D/g, '').slice(0, 11);
  if (!nm || ph.length < 9)
    return res.status(400).json({ error: 'bad', message: '대표자 이름과 연락처를 적어주세요' });
  db.prepare(`UPDATE cup_entries SET contact_name=?, contact_phone=?,
      club_name=COALESCE(NULLIF(?,''), club_name),
      status=CASE WHEN status='invited' THEN 'applied' ELSE status END,
      applied_at=COALESCE(applied_at,?) WHERE id=?`)
    .run(nm, ph, String(b.club_name || '').trim().slice(0, 40), now(), e.id);
  res.json({ ok: true });
});

/* 엔트리 10명 — 한 번에 통째로 받는다.
   한 명씩 받으면 <9명만 넣고 나간 클럽>이 생기고, 그 상태를 화면마다 다뤄야 한다. */
app.post('/cup/invite/:token/roster', (req, res) => {
  const e = cupEntryByToken(req.params.token);
  if (!e) return res.status(404).json({ error: 'no_invite' });
  const list = Array.isArray((req.body || {}).roster) ? (req.body || {}).roster : [];
  const why = cupCheckRoster(list);
  if (why) return res.status(400).json({ error: 'bad_roster', message: why });

  const yr = new Date().getFullYear();
  db.transaction(() => {
    db.prepare('DELETE FROM cup_roster WHERE entry_id=?').run(e.id);
    const ins = db.prepare(`INSERT INTO cup_roster
      (entry_id,user_id,guest_name,gender,ntrp,birth_year,slot,guardian_consent,health_declared)
      VALUES (?,?,?,?,?,?,?,?,?)`);
    list.forEach((p, i) => {
      const by = +p.birth_year || null;
      const age = by ? yr - by : null;
      ins.run(e.id, +p.user_id || null, String(p.guest_name || '').trim().slice(0, 20) || null,
        p.gender === 'F' ? 'F' : 'M', +p.ntrp,
        by, i + 1,
        (age != null && age < 18) ? 1 : 0,
        (age != null && age >= 65) ? 1 : 0);
    });
    db.prepare(`UPDATE cup_entries SET status=CASE WHEN status IN ('invited','applied')
      THEN 'applied' ELSE status END WHERE id=?`).run(e.id);
  })();
  res.json({ ok: true, n: list.length });
});

/* 엔트리 검사 — 서버에서 막는다. 화면에서만 막으면 링크를 아는 사람이 그냥 넘긴다. */
function cupCheckRoster(list) {
  if (!Array.isArray(list) || list.length !== CUP_ROSTER_N)
    return `정확히 ${CUP_ROSTER_N}명을 넣어주세요 (지금 ${(list || []).length}명)`;
  const yr = new Date().getFullYear();
  let f = 0;
  for (let i = 0; i < list.length; i++) {
    const p = list[i], no = i + 1;
    const nm = String(p.guest_name || '').trim();
    if (!p.user_id && !nm) return `${no}번 이름을 적어주세요`;
    if (p.gender !== 'M' && p.gender !== 'F') return `${no}번 성별을 골라주세요`;
    if (p.gender === 'F') f++;
    const n = +p.ntrp;                                 // 구력(년)
    if (!(n >= 0 && n <= 60)) return `${no}번 구력을 0~60년 사이로 적어주세요`;
    const by = +p.birth_year;
    if (by) {
      const age = yr - by;
      if (age < 16) return `${no}번은 만 16세 이상이어야 나올 수 있어요`;
      if (age < 18 && !p.guardian_consent) return `${no}번은 미성년자라 보호자 동의가 필요해요`;
      if (age >= 65 && !p.health_declared) return `${no}번은 건강 확인에 체크해주세요`;
    }
  }
  /* 혼복이 있으니 여성이 없으면 대회 자체가 안 굴러간다.
     여성 회원은 공고일 이후 가입도 인정한다 — 그 예외가 없으면
     여성이 없는 클럽은 출전을 포기한다. */
  if (f < CUP_ROSTER_F) return `여성 회원이 ${CUP_ROSTER_F}명 이상 있어야 해요 (혼합복식)`;
  return null;
}

/* ── 라인업 ────────────────────────────────────────────
   타이 시작 전에 세 매치의 짝을 낸다. 등급 상한과 인원 규칙을 여기서 막는다. */
app.post('/cup/invite/:token/lineup', (req, res) => {
  const e = cupEntryByToken(req.params.token);
  if (!e) return res.status(404).json({ error: 'no_invite' });
  const b = req.body || {};
  const tie = String(b.tie_id || '').slice(0, 24);
  const ms = Array.isArray(b.matches) ? b.matches : [];
  if (!tie) return res.status(400).json({ error: 'no_tie' });
  const ros = db.prepare('SELECT * FROM cup_roster WHERE entry_id=?').all(e.id);
  const why = cupCheckLineup(ms, ros);
  if (why) return res.status(400).json({ error: 'bad_lineup', message: why });
  db.transaction(() => {
    db.prepare('DELETE FROM cup_lineups WHERE bracket_id=? AND tie_id=? AND entry_id=?')
      .run(e.bracket_id, tie, e.id);
    const ins = db.prepare(`INSERT INTO cup_lineups
      (bracket_id,tie_id,entry_id,match_no,p1,p2,submitted_at) VALUES (?,?,?,?,?,?,?)`);
    ms.forEach(m => ins.run(e.bracket_id, tie, e.id, +m.no, +m.p1, +m.p2, now()));
  })();
  res.json({ ok: true });
});

function cupCheckLineup(ms, ros) {
  if (ms.length !== 3) return '세 매치를 모두 채워주세요';
  const by = {}; ros.forEach(r => { by[r.id] = r; });
  const used = [];
  for (const m of ms) {
    const no = +m.no;
    const a = by[+m.p1], c = by[+m.p2];
    if (!a || !c) return `${no}복식 선수를 엔트리에서 골라주세요`;
    if (a.id === c.id) return `${no}복식에 같은 사람이 두 번 들어갔어요`;
    used.push(a.id, c.id);
    if (no === 2 && !((a.gender === 'M' && c.gender === 'F') || (a.gender === 'F' && c.gender === 'M')))
      return '혼합복식은 남녀 한 명씩이어야 해요';
    const cap = CUP_CAP[no];
    const sum = (a.ntrp || 0) + (c.ntrp || 0);        // ntrp 칸에 구력(년)이 담긴다
    if (cap != null && sum > cap)
      return `${no}복식 구력 합이 ${cap}년을 넘어요 (지금 ${sum}년)`;
  }
  /* 6자리를 5명 이상이 채운다 — 중복 출전은 한 명까지.
     이게 없으면 에이스 둘이 세 매치를 다 돌고, 클럽 대항이 아니게 된다. */
  const uniq = new Set(used);
  if (uniq.size < 5) return `6자리를 5명 이상이 채워야 해요 (지금 ${uniq.size}명)`;
  const cnt = {}; used.forEach(id => { cnt[id] = (cnt[id] || 0) + 1; });
  if (Object.values(cnt).some(v => v > 2)) return '한 사람이 세 매치에 다 나올 수는 없어요';
  return null;
}

/* ── 라운드 일괄 타이머 ───────────────────────────────────
   코트마다 따로 켜면 25분 단타임이 코트별로 달라진다.
   운영자가 버튼 하나로 네 면을 동시에 시작한다. */
app.post('/brackets/:id/round/:r/start', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (!isMember(b.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  let data = {}; try { data = JSON.parse(b.data || '{}'); } catch (e) {}
  const rd = (data.rounds || []).find(x => +x.r === +req.params.r);
  if (!rd) return res.status(404).json({ error: 'no_round' });
  const slot = +req.query.slot || 1;
  const t = now();
  const ins = db.prepare(`INSERT INTO bracket_timers (bracket_id,court_key,started_at) VALUES (?,?,?)
    ON CONFLICT(bracket_id,court_key) DO UPDATE SET started_at=excluded.started_at`);
  let n = 0;
  db.transaction(() => {
    rd.ties.forEach(t2 => t2.matches.forEach(m => {
      if (+m.slot !== slot) return;
      ins.run(b.id, String(m.key).slice(0, 24), t); n++;
    }));
    db.prepare('UPDATE brackets SET updated_at=? WHERE id=?').run(t, b.id);
  })();
  res.json({ ok: true, started_at: t, courts: n });
});

app.post('/brackets/:id/round/:r/reset', auth, (req, res) => {
  const b = db.prepare('SELECT * FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  if (!isMember(b.club_id, req.uid)) return res.status(403).json({ error: 'member_only' });
  let data = {}; try { data = JSON.parse(b.data || '{}'); } catch (e) {}
  const rd = (data.rounds || []).find(x => +x.r === +req.params.r);
  if (!rd) return res.status(404).json({ error: 'no_round' });
  const del = db.prepare('DELETE FROM bracket_timers WHERE bracket_id=? AND court_key=?');
  db.transaction(() => {
    rd.ties.forEach(t => t.matches.forEach(m => del.run(b.id, String(m.key).slice(0, 24))));
    db.prepare('UPDATE brackets SET updated_at=? WHERE id=?').run(now(), b.id);
  })();
  res.json({ ok: true });
});

app.get('/brackets/:id/live', (req, res) => {
  const b = db.prepare('SELECT id,updated_at,published,club_id,fmt,data FROM brackets WHERE id=?').get(+req.params.id);
  if (!b) return res.status(404).json({ error: 'not_found' });
  const p = bracketPayload({ ...b, data: '{}' });
  /* 남은 시간을 기기 시계로 세면 코트마다 다르게 보인다.
     서버 시각을 같이 내려서 started_at + match_sec - server_now 로 세게 한다. */
  let cfg = null;
  if (b.fmt === 'cup') { try { cfg = (JSON.parse(b.data || '{}').cfg) || null; } catch (e) {} }
  res.json({ id: b.id, updated_at: b.updated_at, scores: p.scores, timers: p.timers,
    server_now: Date.now(), cfg });
});

function notifyClub(clubId, exceptUid, icon, title, body) {
  const rows = db.prepare('SELECT user_id FROM club_members WHERE club_id=?').all(clubId);
  rows.forEach(r => { if (r.user_id !== exceptUid) sendPush(r.user_id, { icon, title, body }); });
}
/* 임원에게만 — 도전장처럼 <답을 해야 하는> 일은 회원 전체에게 보낼 필요가 없다 */
function notifyClubOfficers(clubId, icon, title, body) {
  db.prepare(`SELECT user_id FROM club_members WHERE club_id=? AND role IN ('owner','officer')`)
    .all(clubId).forEach(r => sendPush(r.user_id, { icon, title, body }));
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
/* 프리미엄을 접으면서 두 제한을 풀었다(0 = 무제한).
   /clubs/:id/premium 응답에서 아직 참조하므로 값 자체는 남겨 둔다. */
const FREE_MAX_MEMBERS = 0;
const FREE_MAX_BRACKETS_PER_MONTH = 0;

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
/* 홈구장 이름에 코트 번호가 섞여 저장된 클럽이 있다 — <용인 테니스파크 1-3번코트>.
   코트 번호는 모임마다 달라지는 값이라 구장 이름에 박혀 있으면
   모임 제목에서 <1-3번코트번 코트> 처럼 계속 겹친다. 둘을 갈라 둔다. */
try { db.exec('ALTER TABLE clubs ADD COLUMN home_courts TEXT'); } catch (e) {}

/* 창단연도 — 클럽 페이지에서 <2024년부터>로 보인다. 밖에서 클럽을 고르는 사람에게
   <얼마나 오래된 모임인가>는 회원 수만큼 중요한 정보다. */
try { db.exec('ALTER TABLE clubs ADD COLUMN founded_year INTEGER'); } catch (e) {}
/* 회원 모집 중 — 클럽장이 켜고 끈다. 목록에서 이것만 모아 볼 수 있어야 하므로
   문구가 아니라 값으로 둔다(0/1). */
try { db.exec('ALTER TABLE clubs ADD COLUMN recruiting INTEGER DEFAULT 0'); } catch (e) {}
/* 게스트 조건 — <받아요>만으로는 알 수 없다. 구력 몇 년부터 받는지가 실제 문턱이다.
   null 이면 제한 없음. 가입 조건(min_career_months)과는 별개다 —
   게스트로는 받되 정회원은 더 높게 두는 클럽이 있다. */
try { db.exec('ALTER TABLE clubs ADD COLUMN guest_min_months INTEGER'); } catch (e) {}
/* 가입 전 게스트로 몇 번 나와야 하는지 — 구력과는 다른 문턱이다.
   <구력 2년 이상 · 게스트 참여 4회>처럼 둘을 함께 건다. */
try { db.exec('ALTER TABLE clubs ADD COLUMN guest_visits INTEGER'); } catch (e) {}
/* 가입 신청 받기 — 회원이 차면 잠시 닫는다. 기본은 열려 있다.
   <모집 중>과는 다르다: 모집 중은 목록에서 눈에 띄게, 이건 실제로 받을지. */
try { db.exec('ALTER TABLE clubs ADD COLUMN join_open INTEGER DEFAULT 1'); } catch (e) {}
try { db.exec("UPDATE clubs SET join_open=1 WHERE join_open IS NULL"); } catch (e) {}
/* 다시 받는 시점 — 닫아둘 때만 쓴다. <3월에>처럼 짧은 글 */
try { db.exec('ALTER TABLE clubs ADD COLUMN join_reopen TEXT'); } catch (e) {}

/* 구장 이름과 코트 번호를 가른다.
   반환: { venue, courts } — 코트 표기가 없으면 courts 는 빈 문자열. */
function splitCourt(raw) {
  const t = String(raw || '')
    .replace(/번\s*코트/g, '번 코트')
    .replace(/(번 코트)(\s*번 코트)+/g, '$1')
    .replace(/\s{2,}/g, ' ').trim();
  /* 끝에 붙은 <1-3번 코트> · <1·2·3번 코트> · <3면> 같은 꼬리를 떼어낸다 */
  const m = t.match(/^(.*?)[\s,·]*([0-9][0-9\s,.·~\-]*)\s*번\s*코트\s*$/);
  if (m && m[1].trim()) return { venue: m[1].trim(), courts: m[2].replace(/\s+/g, '') };
  return { venue: t, courts: '' };
}

/* 한 번만 도는 정리 — 이미 저장된 홈구장에서 코트 번호를 떼어 home_courts 로 옮긴다.
   지우지 않고 옮기기만 하므로 되돌릴 수 있다. */
(function normalizeHomeCourts() {
  let rows = [];
  try { rows = db.prepare('SELECT id, home_court, home_courts FROM clubs').all(); } catch (e) { return; }
  const up = db.prepare('UPDATE clubs SET home_court=?, home_courts=? WHERE id=?');
  let n = 0;
  rows.forEach(c => {
    if (c.home_courts != null) return;                 // 이미 정리된 클럽
    const { venue, courts } = splitCourt(c.home_court);
    if (venue === (c.home_court || '') && !courts) return;
    up.run(venue, courts, c.id);
    n++;
  });
  if (n) console.log(`[migrate] 홈구장에서 코트 번호를 분리했어요 · ${n}개 클럽`);
})();

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
h1{font-size:23px;margin-bottom:4px}h2{font-size:15px;margin:26px 0 8px}p,li{font-size:14px;color:#4a4237}ul{padding-left:18px}
.sub{font-size:12px;color:#8a7f70}.box{background:#fffdf8;border:1px solid #e8e1d2;border-radius:14px;padding:14px 16px;font-size:13px;color:#8a7f70;margin-top:30px}</style>`;

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
app.post('/admin/backup', admin, async (_req, res) => { await backupNow(); res.json({ ok: true }); });  // @external 내가 curl 로 부름
app.get('/admin/backup/latest', admin, (_req, res) => {  // @external 내가 curl 로 부름
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
      (SELECT COUNT(*) FROM club_members m2 JOIN users u2 ON u2.id=m2.user_id
        WHERE m2.club_id=clubs.id AND COALESCE(u2.is_test,0)=0) members
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
const ASSESS_MID = { '퓨처스1':840,'퓨처스2':915,'퓨처스3':975,'챌린저1':1025,'챌린저2':1075,'챌린저3':1125,'챌린저4':1175,'챌린저5':1225,'투어1':1285,'투어2':1355,'투어3':1425,
  '마스터스1':1285,'마스터스2':1355,'마스터스3':1425,'그랜드슬램':1500 };
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
  const had = !!m.bracket;
  db.prepare('UPDATE open_matches SET bracket=? WHERE id=?').run(br, m.id);
  /* 모든 게임에 점수가 들어왔으면 결과를 보라고 알린다 —
     티어가 조용히 바뀌면 아무도 눈치채지 못한다. */
  try{
    const b2 = (req.body && req.body.bracket) || {};
    const gs = [];
    (b2.courts || []).forEach(c => (c.rounds || []).forEach(g => gs.push(g)));
    const allDone = gs.length && gs.every(g => g.sa != null && g.sb != null);
    const wasDone = (() => { try { const o = JSON.parse(m.bracket || 'null'); const a = [];
      (o && o.courts || []).forEach(c => (c.rounds || []).forEach(g => a.push(g)));
      return a.length && a.every(g => g.sa != null && g.sb != null); } catch (e) { return false; } })();
    if (allDone && !wasDone) {
      db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(m.id)
        .forEach(p => sendPush(p.user_id, { icon: '🏆', title: '오늘 경기가 끝났어요',
          body: '결과와 티어 변동을 확인해 보세요', link: 'match' }));
    }
  }catch(e){}
  /* 대진이 처음 나오면 참가자 전원에게 알린다 — 매니저 없는 매치에서는
     이 알림이 "이제 시작해도 된다"는 신호 역할을 한다. */
  if (!had) {
    const b = (req.body && req.body.bracket) || {};
    const rounds = b.rounds || 0, gpp = b.gpp || 0;
    db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(m.id)
      .forEach(p => sendPush(p.user_id, { icon: '📋', title: '대진표가 나왔어요',
        body: `${m.loc || ''}${rounds ? ` · ${rounds}라운드` : ''}${gpp ? ` · 1인 ${gpp}게임` : ''}`,
        link: `match:${m.id}` }));
  }
  res.json({ ok: true });
});

/* ── 라운드 진행 알림 ──
   매니저가 하는 일은 셋뿐이다: 지금 몇 라운드인지 알리고, 다음 대진을 읽어주고,
   점수를 받아 적는 것. 앞의 둘은 알림으로 대신할 수 있다.
   타이머로 경기를 끊지는 않는다 — 앱이 틀린 순간부터 아무도 안 본다. */
app.post('/open-matches/:id/round-notice', auth, limitWrite, (req, res) => {
  const m = db.prepare('SELECT * FROM open_matches WHERE id=?').get(+req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  const isLeader = m.leader_id === req.uid || m.manager_id === req.uid || m.host_id === req.uid;
  if (!isLeader) return res.status(403).json({ error: 'leader_only' });
  const b = req.body || {};
  const r = intOrNull(b.round) || 1;
  const rows = db.prepare('SELECT user_id FROM open_match_joins WHERE match_id=?').all(m.id);
  rows.forEach(p => sendPush(p.user_id, {
    icon: '🎾', title: `${r}라운드 시작`,
    body: String(b.pairs || '').slice(0, 80) || `${m.loc || ''} · 게임당 25분`,
    link: 'match' }));
  res.json({ ok: true, sent: rows.length });
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
    sendPush(m.manager_id, { icon: '👏', title: '매니저 칭찬을 받았어요', body: '오늘 매치 운영이 좋았대요' });
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
app.post('/admin/run-reminders', admin, (_req, res) => { runReminders(); res.json({ ok: true }); });  // @external 내가 curl 로 부름

// ── 운영자 대시보드 API ──
// 접근키: env ADMIN_KEY (미설정 시 데모용 'matsu-admin'). 헤더 x-admin-key 또는 ?key=
const ADMIN_KEY = process.env.ADMIN_KEY || 'matsu-admin';
function admin(req, res, next) {
  // 키는 반드시 헤더로. URL 쿼리는 브라우저 히스토리·서버 로그에 그대로 남는다.
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'admin_only' });
  next();
}

/* 아래 두 화면은 admin 미들웨어와 ADMIN_KEY 가 만들어진 <뒤에> 있어야 한다.
   앞쪽(1300줄대)에 두었더니 ADMIN_KEY 가 아직 초기화되기 전이라
   키가 맞는데도 403 이 났다. */
/* 알림이 어디서 끊겼는지 한 화면에서 본다 —
   로그를 뒤지지 않고 <키·토큰·발송> 셋 중 어디가 문제인지 바로 알 수 있게. */
/* 회원 명단 내려받기 (CSV) — 나중에 제대로 된 DB 로 옮기거나
   엑셀에서 훑어볼 수 있게 한 줄에 한 사람, 열은 고정 순서로 낸다.
   화면 목록은 200명까지만 보이지만 여기서는 전부 낸다. */
app.get('/admin/users.csv', admin, (_req, res) => {
  const OV = `(SELECT NULLIF(m.gender_ov,'') FROM club_members m
      WHERE m.user_id=u.id AND NULLIF(m.gender_ov,'') IS NOT NULL
        AND (m.status IS NULL OR m.status='active') LIMIT 1)`;
  const rows = db.prepare(`SELECT u.id, u.name, u.provider, u.region, u.sport,
      u.rating, u.mmr, u.cash, u.premium, u.suspended, u.created_at, u.sport_started,
      u.phone_verified, u.real_verified,
      COALESCE(NULLIF(u.gender,''), ${OV}) AS gender,
      CASE WHEN NULLIF(u.gender,'') IS NOT NULL THEN '본인'
           WHEN ${OV} IS NOT NULL THEN '클럽' ELSE '' END AS gender_src,
      (SELECT COUNT(*) FROM club_members m WHERE m.user_id=u.id
        AND (m.status IS NULL OR m.status='active')) AS clubs,
      (SELECT GROUP_CONCAT(c.name, ' / ') FROM club_members m JOIN clubs c ON c.id=m.club_id
        WHERE m.user_id=u.id AND (m.status IS NULL OR m.status='active')) AS club_names,
      (SELECT COUNT(*) FROM devices d WHERE d.user_id=u.id AND d.platform='ios') AS ios_devices
    FROM users u ORDER BY u.id`).all();

  const PROV = { kakao: '카카오', google: '구글', apple: '애플', dev: '개발' };
  const G = { M: '남성', F: '여성', '남성': '남성', '여성': '여성' };
  const dt = t => { if (!t) return ''; const d = new Date(+t || t);
    return isNaN(d) ? '' : d.toISOString().slice(0, 10); };
  const career = v => { try { const ym = JSON.parse(v || '{}').tennis || '';
    return String(ym).slice(0, 7); } catch { return ''; } };

  const head = ['회원번호','이름','가입경로','성별','성별출처','구력시작','지역','종목',
    '레이팅','MMR','캐시','소속클럽수','소속클럽','아이폰알림','휴대폰인증','실명인증',
    '프리미엄','정지','가입일'];
  const line = r => [
    r.id, r.name, PROV[r.provider] || r.provider || '', G[r.gender] || '',
    r.gender_src || '', career(r.sport_started), r.region || '', r.sport || '',
    r.rating, r.mmr, r.cash, r.clubs, r.club_names || '',
    r.ios_devices ? 'Y' : '', r.phone_verified ? 'Y' : '', r.real_verified ? 'Y' : '',
    r.premium ? 'Y' : '', r.suspended ? 'Y' : '', dt(r.created_at),
  ];
  /* 엑셀은 쉼표·따옴표·줄바꿈이 든 값을 큰따옴표로 감싸야 한 칸으로 읽는다.
     맨 앞 BOM 이 없으면 한글이 깨진다(엑셀이 CP949 로 읽어버린다). */
  const cell = v => {
    const t = v == null ? '' : String(v);
    return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t;
  };
  const csv = '\ufeff' + [head, ...rows.map(line)].map(r => r.map(cell).join(',')).join('\r\n');
  const today = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="matsu-users-${today}.csv"`);
  res.send(csv);
});

app.get('/admin/push-status', admin, (req, res) => {
  const devs = db.prepare(`SELECT d.platform, COUNT(*) n FROM devices d GROUP BY d.platform`).all();
  const recent = db.prepare(`SELECT u.id, u.name, d.platform, d.created_at
    FROM devices d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC LIMIT 20`).all();
  res.json({
    tries: PUSH_TRIES.slice(0, 8),          // 앱이 등록을 시도했는지
    apns: {
      ready: apnsReady(),
      bundle_id: APNS.bundleId || null,
      key_id: APNS.keyId ? APNS.keyId.slice(0, 4) + '···' : null,
      team_id: APNS.teamId ? APNS.teamId.slice(0, 4) + '···' : null,
      key_loaded: !!APNS.key,
    },
    devices: devs,
    /* 잠금화면 시계 토큰은 알림 토큰과 다른 것이라 따로 센다 */
    live_tokens: (() => { try {
      return db.prepare('SELECT COUNT(*) c FROM live_activities').get().c;
    } catch (e) { return 0; } })(),
    recent: recent.map(r => ({ user_id: r.id, name: r.name, platform: r.platform, at: r.created_at })),
  });
});

/* 내 폰으로 시험 알림을 보낸다 — 실제로 도착하는지 확인하는 가장 빠른 길.
   ?user=12 로 특정 회원에게 보낼 수 있다(기본은 관리자 본인 기기 전부). */
app.post('/admin/push-test', admin, async (req, res) => {
  const uid = +((req.query && req.query.user) || (req.body && req.body.user) || 0);
  if (!uid) return res.status(400).json({ error: 'no_user', message: '?user=회원번호 를 붙여주세요' });
  const rows = db.prepare('SELECT token, platform FROM devices WHERE user_id=?').all(uid);
  if (!rows.length) return res.json({ ok: false, reason: '그 회원의 기기가 등록돼 있지 않아요' });
  const out = [];
  for (const r of rows.filter(x => x.platform === 'ios')) {
    const rr = await apnsSend(r.token, { title: '시험 알림', body: '이 알림이 보이면 잘 되고 있어요' });
    out.push({ platform: 'ios', ...rr });
  }
  res.json({ ok: true, sent: out, note: out.length ? '' : 'iOS 기기가 없어요' });
});


// 관리자가 특정 클럽에 프리미엄을 직접 부여 (초기 파트너 클럽 · 환불 · 테스트)
// 결제와 무관하게 열어주는 유일한 경로. ADMIN_KEY 를 아는 사람만.
// 운영자용 클럽 목록 — 클럽장·회원까지 함께 (클럽장 변경 UI 용)
app.get('/admin/clubs', admin, (_req, res) => {
  const clubs = db.prepare(`SELECT c.id, c.name, c.sport, c.region,
      (SELECT COUNT(*) FROM club_members m JOIN users mu ON mu.id=m.user_id
        WHERE m.club_id=c.id AND (m.status IS NULL OR m.status='active')
          AND COALESCE(mu.is_test,0)=0) members
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
  /* 되돌릴 수 없는 일일수록 <누가 언제> 가 남아야 한다 */
  alog(req, '회원 삭제', 'user', uid, { name: u.name, tables: wiped.length }, null);
  res.json({ ok: true, deleted: u.name, wiped });
});

// 정리 대상 조회 — 탈퇴 계정·클럽 목록
app.get('/admin/purge-list', admin, (_req, res) => {  // @external 내가 curl 로 부름
  res.json({
    suspended_users: db.prepare('SELECT id,name,created_at FROM users WHERE suspended=1').all(),
    clubs: db.prepare(`SELECT c.id, c.name, c.sport,
      (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id) members FROM clubs c ORDER BY c.id`).all(),
  });
});

/* ── 오류 알림 ────────────────────────────────────────────────────
   관리자 화면은 열어야만 보인다. 그런데 정작 급한 일은 안 열고 있을 때 생긴다.
   여러 사람에게 나는 오류가 새로 생기면 관리자에게 먼저 알린다.

   같은 오류로 계속 울리면 알림을 끄게 되므로, 한 종류당 하루 한 번만 보낸다. */
try { db.exec(`CREATE TABLE IF NOT EXISTS err_alerted (sig TEXT PRIMARY KEY, at INTEGER)`); } catch (e) {}
const ERR_ALERT_MIN = 3;          // 몇 명에게 나면 알릴 것인가
async function errWatch() {
  try {
    const rows = db.prepare(`SELECT sig, MAX(path) path, MAX(msg) msg,
        COUNT(DISTINCT COALESCE(user_id,-1)) people
      FROM client_errors WHERE at > ? AND kind NOT IN ('net','timeout')
      GROUP BY sig`).all(Date.now() - 3 * 864e5);
    const hot = rows.filter(r => r.people >= ERR_ALERT_MIN);
    if (!hot.length) return;
    const ids = (process.env.ADMIN_UIDS || '').split(',')
      .map(x => +String(x).trim()).filter(Boolean);
    if (!ids.length) return;      // 받을 사람이 정해져 있지 않으면 조용히 넘어간다
    const seen = db.prepare('SELECT at FROM err_alerted WHERE sig=?');
    const mark = db.prepare('INSERT OR REPLACE INTO err_alerted (sig,at) VALUES (?,?)');
    for (const h of hot) {
      const s0 = seen.get(h.sig);
      if (s0 && Date.now() - s0.at < 864e5) continue;    // 하루 한 번
      mark.run(h.sig, now());
      for (const uid of ids) {
        try { await sendPush(uid, { icon: '🚨',
          title: `오류가 ${h.people}명에게 나고 있어요`,
          body: `${h.path || ''} · ${String(h.msg || '').slice(0, 60)}`,
          link: '/admin.html' }); } catch (e) {}
      }
      console.log(`[errWatch] ${h.people}명 · ${h.sig.slice(0, 60)}`);
    }
  } catch (e) {}
}
setInterval(errWatch, 15 * 60000);          // 15분마다 — 더 자주 볼 일은 아니다
setTimeout(errWatch, 60000);

/* ── 내려받기 ─────────────────────────────────────────────────────
   세무·정산 정리는 결국 표로 한다. 화면에서 눈으로 옮겨 적게 두지 않는다. */
function toCsv(rows, cols) {
  const esc = v => {
    const t = v == null ? '' : String(v);
    return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t;
  };
  return '\uFEFF' + [cols.map(c => c[1]).join(',')]        // BOM — 엑셀이 한글을 안 깨게
    .concat(rows.map(r => cols.map(c => esc(r[c[0]])).join(','))).join('\n');
}
app.get('/admin/export/:what', admin, (req, res) => {
  const what = req.params.what;
  const ymd = t => t ? new Date(t).toISOString().slice(0, 10) : '';
  let rows, cols, name;
  if (what === 'users') {
    rows = db.prepare(`SELECT u.id, u.name, u.email, u.gender, u.provider,
        u.created_at, u.last_seen, u.last_plat, u.last_region,
        (SELECT GROUP_CONCAT(c.name, ' / ') FROM club_members m
          LEFT JOIN clubs c ON c.id=m.club_id WHERE m.user_id=u.id) clubs
      FROM users u ORDER BY u.id`).all()
      .map(r => ({ ...r, created_at: ymd(r.created_at), last_seen: ymd(r.last_seen),
        gender: r.gender === 'F' ? '여성' : r.gender === 'M' ? '남성' : '' }));
    cols = [['id','번호'],['name','이름'],['email','이메일'],['gender','성별'],
      ['provider','가입경로'],['clubs','클럽'],['created_at','가입일'],
      ['last_seen','마지막접속'],['last_plat','기기'],['last_region','지역']];
    name = 'members';
  } else if (what === 'payouts') {
    rows = db.prepare('SELECT * FROM payouts ORDER BY id DESC LIMIT 5000').all();
    cols = Object.keys(rows[0] || { id: 1 }).map(k => [k, k]);
    name = 'payouts';
  } else if (what === 'clubs') {
    rows = db.prepare(`SELECT c.id, c.name, c.sport, c.sido, c.sigungu,
        (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id) members
      FROM clubs c ORDER BY members DESC`).all();
    cols = [['id','번호'],['name','이름'],['sport','종목'],['sido','시도'],
      ['sigungu','시군구'],['members','회원수']];
    name = 'clubs';
  } else return res.status(400).json({ error: 'unknown' });

  alog(req, '내려받음', what, null, { rows: rows.length }, null);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition',
    `attachment; filename="matsu-${name}-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(toCsv(rows, cols));
});

/* ── 점검 모드 ────────────────────────────────────────────────────
   배포하는 몇 초 사이에 들어온 사람은 깨진 화면을 본다.
   미리 켜 두면 앱이 <잠시 점검 중> 을 띄운다. 관리자 경로는 늘 열어 둔다 —
   점검 모드를 끄러 들어와야 하니까. */
let MAINT = { on: false, msg: '', until: 0 };
app.get('/admin/maint', admin, (_req, res) => res.json(MAINT));
app.post('/admin/maint', admin, (req, res) => {
  const b = req.body || {};
  MAINT = { on: !!b.on, msg: String(b.msg || '').slice(0, 120),
    until: b.minutes ? Date.now() + Math.min(180, +b.minutes) * 60000 : 0 };
  alog(req, MAINT.on ? '점검 켬' : '점검 끔', 'maint', null,
    { msg: MAINT.msg, minutes: b.minutes || 0 }, null);
  res.json(MAINT);
});
function maintOn() { return MAINT.on && (!MAINT.until || Date.now() < MAINT.until); }

/* ── 작업 기록과 되돌리기 ──────────────────────────────────────────
   계정 탭이 있다는 건 관리자가 여럿이라는 뜻이다. 여럿이 만지는 데이터에
   기록이 없으면 <누가 왜 바꿨는지> 를 아무도 모르고, 되돌릴 수도 없다.

   되돌리기는 <되돌릴 값을 미리 적어 두는> 방식으로 만든다.
   그래야 무엇을 되돌려야 하는지 나중에 추측하지 않아도 된다. */
try { db.exec(`CREATE TABLE IF NOT EXISTS admin_log (
  id INTEGER PRIMARY KEY, who TEXT, action TEXT, target TEXT, target_id INTEGER,
  detail TEXT, undo TEXT, undone INTEGER DEFAULT 0, at INTEGER)`); } catch (e) {}
try { db.exec('CREATE INDEX IF NOT EXISTS ix_alog_at ON admin_log(at)'); } catch (e) {}

function adminWho(req) {
  /* 관리자 열쇠는 하나뿐이라 사람을 가릴 수 없다. 화면이 보내주면 그걸 쓴다. */
  return String(req.headers['x-admin-who'] || '').slice(0, 24) || '관리자';
}
function alog(req, action, target, targetId, detail, undo) {
  try {
    db.prepare(`INSERT INTO admin_log (who,action,target,target_id,detail,undo,at)
      VALUES (?,?,?,?,?,?,?)`)
      .run(adminWho(req), action, target, targetId || null,
        detail ? JSON.stringify(detail) : null,
        undo ? JSON.stringify(undo) : null, now());
  } catch (e) {}
}
app.get('/admin/log', admin, (req, res) => {
  const days = Math.min(90, Math.max(1, +req.query.days || 14));
  const rows = db.prepare(`SELECT * FROM admin_log WHERE at > ? ORDER BY id DESC LIMIT 200`)
    .all(Date.now() - days * 864e5);
  res.json(rows.map(r => ({ ...r,
    detail: r.detail ? JSON.parse(r.detail) : null,
    canUndo: !!r.undo && !r.undone })));
});
app.post('/admin/log/:id/undo', admin, (req, res) => {
  const r = db.prepare('SELECT * FROM admin_log WHERE id=?').get(+req.params.id);
  if (!r) return res.status(404).json({ error: 'not_found' });
  if (r.undone) return res.status(400).json({ error: 'already_undone' });
  if (!r.undo) return res.status(400).json({ error: 'cannot_undo' });
  let u; try { u = JSON.parse(r.undo); } catch (e) { return res.status(400).json({ error: 'bad_undo' }); }
  try {
    /* 되돌리기는 <미리 적어 둔 한 줄>만 실행한다. 임의의 SQL 을 받지 않는다 —
       그건 되돌리기가 아니라 뒷문이다. */
    if (u.kind === 'gender')
      db.prepare('UPDATE users SET gender=? WHERE id=?').run(u.value || null, u.id);
    else if (u.kind === 'club_gender_ov')
      db.prepare('UPDATE club_members SET gender_ov=? WHERE club_id=? AND user_id=?')
        .run(u.value || null, u.club_id, u.id);
    else if (u.kind === 'grade')
      db.prepare('UPDATE club_members SET grade=? WHERE club_id=? AND user_id=?')
        .run(u.value, u.club_id, u.id);
    else return res.status(400).json({ error: 'unknown_kind' });
  } catch (e) { return res.status(500).json({ error: 'undo_failed' }); }
  db.prepare('UPDATE admin_log SET undone=1 WHERE id=?').run(r.id);
  alog(req, '되돌림', r.target, r.target_id, { of: r.action }, null);
  res.json({ ok: true });
});

/* ── 클럽 한 곳 들여다보기 ────────────────────────────────────────
   회원은 한 명씩 볼 수 있는데 클럽은 못 봤다. 그런데 이 앱은 클럽 단위로 굴러간다 —
   대진이 잘 짜이는지, 사람이 붙는지, 죽어가는지가 전부 클럽에서 갈린다. */
app.get('/admin/clubs/:id/detail', admin, (req, res) => {
  const cid = +req.params.id;
  const c = db.prepare('SELECT * FROM clubs WHERE id=?').get(cid);
  if (!c) return res.status(404).json({ error: 'not_found' });

  const members = db.prepare(`SELECT m.user_id id, m.grade, m.role, u.name, u.gender,
      u.last_seen FROM club_members m LEFT JOIN users u ON u.id=m.user_id
    WHERE m.club_id=? ORDER BY (u.last_seen IS NULL), u.last_seen DESC`).all(cid);
  const F = v => v === 'F' || String(v || '').startsWith('여');
  const women = members.filter(m => F(m.gender)).length;
  const noGender = members.filter(m => !m.gender).length;
  const active = members.filter(m => m.last_seen && Date.now() - m.last_seen < 30 * 864e5).length;

  /* 최근 대진이 어떻게 짜였나 — 품질 탭과 같은 셈을 이 클럽만 놓고 다시 한다 */
  const logs = db.prepare(`SELECT date, data FROM club_bracket_logs
    WHERE club_id=? ORDER BY date DESC LIMIT 12`).all(cid);
  const lv = {}; members.forEach(m => { lv[m.id] = ladderLv(m.grade); });
  const brackets = [];
  let allN = 0, allBad = 0;
  logs.forEach(L => {
    let d; try { d = JSON.parse(L.data); } catch (e) { return; }
    let n = 0, bad = 0, scored = 0;
    (d.games || []).forEach(g => {
      const A = (g.teamA || []).filter(Boolean), B = (g.teamB || []).filter(Boolean);
      if (A.length < 2 || B.length < 2) return;
      const gp = Math.abs(((lv[A[0].id] || 2) + (lv[A[1].id] || 2)) / 2
                        - ((lv[B[0].id] || 2) + (lv[B[1].id] || 2)) / 2);
      n++; if (gp >= 1) bad++;
      if (g.sa != null && g.sb != null) scored++;
    });
    if (n) { brackets.push({ date: L.date, games: n, bad, scored }); allN += n; allBad += bad; }
  });

  const moves = db.prepare(`SELECT COUNT(*) n FROM grade_changes WHERE club_id=? AND created_at > ?`)
    .get(cid, Date.now() - 30 * 864e5).n;

  res.json({ id: cid, name: c.name, sido: c.sido, sigungu: c.sigungu,
    members: members.length, women, men: members.length - women, noGender, active,
    brackets, gapPct: allN ? Math.round(allBad / allN * 1000) / 10 : null,
    moves30: moves,
    top: members.slice(0, 8).map(m => ({ id: m.id, name: m.name, grade: m.grade,
      role: m.role, last_seen: m.last_seen })) });
});

/* ── 죽은 코드 찾기 ──────────────────────────────────────────────
   지금까지 세 번, 서버는 되는데 화면이 안 이어진 것을 뒤늦게 찾았다
   (공지 · 반응 이름 · 회원 삭제). 사람이 기억으로 잡을 일이 아니다.

   서버 라우트를 세고, 앱·관리자 파일에서 그 주소를 찾는다.
   웹훅처럼 바깥에서 부르는 것은 라우트 옆에 // @external 을 달아 뺀다 —
   자동으로 알아맞히려 하면 반드시 틀린다. */
app.get('/admin/dead-code', admin, (_req, res) => {
  const read = p => { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return ''; } };
  const here = new URL('.', import.meta.url).pathname;
  const src  = read(path.join(here, 'server.js'));
  /* public 안의 html·js 를 전부 읽는다 — 구장(venue)·매니저 화면이 따로 있어서
     index/admin 만 보면 그쪽 라우트가 통째로 <안 쓰임>으로 잡힌다. */
  let uses = '';
  try {
    const dir = path.join(here, 'public');
    fs.readdirSync(dir).forEach(f => {
      if (/\.(html|js)$/i.test(f)) uses += '\n' + read(path.join(dir, f));
    });
  } catch (e) {}
  if (!src) return res.json({ error: 'server.js 를 읽지 못했어요', routes: 0, dead: [] });

  const rx = /app\.(get|post|put|patch|delete)\(\s*'([^']+)'([^\n]*)/g;
  const routes = [];
  let m;
  while ((m = rx.exec(src))) {
    routes.push({ method: m[1].toUpperCase(), path: m[2],
      external: /@external/.test(m[3]),
      note: (m[3].match(/@external\s*([^*\n]*)/) || [, ''])[1].trim(),
      line: src.slice(0, m.index).split('\n').length });
  }
  /* 주소에 :id 같은 자리가 있으면 앱은 `${...}` 로 만든다.
     그래서 <고정된 앞부분>이 나오는지로 본다 — 놓치는 쪽이 잘못 지우는 것보다 낫다. */
  const seen = p => {
    const head = p.split('/:')[0];
    if (head.length < 4) return true;              // 너무 짧으면 판단하지 않는다
    return uses.includes(head);
  };
  const dead = routes.filter(r => !r.external && !seen(r.path));
  const ext  = routes.filter(r => r.external);
  res.json({
    routes: routes.length,
    dead: dead.slice(0, 80),
    external: ext.length,
    checked: !!uses,
  });
});

/* ══════════ 땅따먹기 ══════════════════════════════════════════
   교류전에서 <남의 홈에 원정 가서 이기면> 그 구장 둘레를 차지한다.
   · 홈  = 최근 1년 정기모임의 25% 이상인 구장 (최대 2곳) — 등록받지 않는다
   · 중립 구장 = 지도를 건드리지 않음 (승패 기록으로만 남음)
   · 원정 패 = 아무 일도 없음 — 져서 얻는 것은 없다
   · 옅어짐 = 뺏은 땅만 1년. 내 홈은 안 옅어진다(매주 거기서 치니까)
              실외 구장은 겨울 3개월을 그 계산에서 뺀다 */
try { db.exec('ALTER TABLE venues ADD COLUMN lat REAL'); } catch (e) {}
try { db.exec('ALTER TABLE venues ADD COLUMN lng REAL'); } catch (e) {}
try { db.exec('ALTER TABLE venues ADD COLUMN indoor INTEGER DEFAULT 0'); } catch (e) {}
/* 사설 코트는 카카오 장소에서 온다 — 같은 곳을 두 번 앉히지 않게 장소 번호를 들고 있는다.
   source: public(공공데이터) · kakao(장소검색) · owner(사장님이 직접 낸 곳) */
try { db.exec('ALTER TABLE venues ADD COLUMN kakao_id TEXT'); } catch (e) {}
try { db.exec("ALTER TABLE venues ADD COLUMN source TEXT DEFAULT 'public'"); } catch (e) {}
try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_venues_kakao ON venues(kakao_id) WHERE kakao_id IS NOT NULL'); } catch (e) {}

/* 코트의 성격 — source 와는 다른 값이다.
   source 는 <어디서 주워 왔나>이고 kind 는 <가서 칠 수 있는 곳인가>다.
   카카오 장소검색은 시립 코트도 같이 주기 때문에, source='kakao' 를 사설로 쓰면
   <용인시립골드테니스장 · 사설> 이 된다. 실제로 그렇게 나오고 있었다.

   공공/사설 둘로만 가르지 않는다. 학교와 아파트 코트는 남이 가서 칠 수 없는데
   사설로 묶어두면 <예약해볼까> 하고 헛걸음하게 된다. */
try { db.exec("ALTER TABLE venues ADD COLUMN kind TEXT") } catch (e) {}

const KIND_SCHOOL = /학교|대학|캠퍼스|교육청|유치원/;
const KIND_APT = /아파트|아파트단지|APT|힐스테이트|자이|푸르지오|e편한세상|이편한세상|래미안|더샵|아이파크|롯데캐슬|스카이뷰|리버파크|한신|주공|빌리지|타운/;
const KIND_PUBLIC = /시립|구립|군립|도립|국민체육|생활체육|공설|시민|체육공원|근린공원|체육센터|올림픽|월드컵|스포츠타운|문화체육|종합운동장|공단|주민센터|복지관|청소년/;

function venueKind(name, addr) {
  const t = `${name || ''} ${addr || ''}`;
  if (KIND_SCHOOL.test(t)) return 'school';
  if (KIND_APT.test(t)) return 'apt';
  if (KIND_PUBLIC.test(t)) return 'public';
  return 'private';
}
/* 한 번 훑어 채운다 — 공공데이터로 들어온 줄은 목록 자체가 공공체육시설이라
   이름이 무엇이든 공공으로 둔다. 나머지는 이름으로 가린다. */
try {
  const rows = db.prepare('SELECT id,name,addr,source FROM venues WHERE kind IS NULL').all();
  if (rows.length) {
    const up = db.prepare('UPDATE venues SET kind=? WHERE id=?');
    db.transaction(list => list.forEach(v => {
      const k = (v.source === 'public') ? 'public' : venueKind(v.name, v.addr);
      up.run(k, v.id);
    }))(rows);
    console.log(`[venue kind] ${rows.length}곳 분류`);
  }
} catch (e) { console.error('[venue kind]', e.message); }
/* 모임이 어느 구장인지 — 지금은 글자로만 적혀 있어 같은 곳인지 알 수 없다 */
try { db.exec('ALTER TABLE club_events ADD COLUMN venue_id INTEGER'); } catch (e) {}

db.exec(`CREATE TABLE IF NOT EXISTS land (
  venue_id INTEGER, club_id INTEGER,
  depth INTEGER DEFAULT 1,        -- 겹 수 (1겹=7칸, 2겹=19칸, 최대 4)
  is_home INTEGER DEFAULT 0,      -- 내 홈이면 안 옅어진다
  last_at INTEGER,                -- 마지막으로 지킨 때
  PRIMARY KEY(venue_id, club_id))`);

const LAND_MAXDEPTH = 4;

/* 겹 수는 클럽 규모로 정하고, 이웃 코트가 가까우면 줄인다.
   앱이 따로 계산하게 두었더니 <7칸> 이라고 적어놓고 19칸을 그렸다.
   숫자와 그림이 어긋나면 둘 다 못 믿는다. 여기서 한 번만 정하고 앱은 그대로 그린다. */
function depthOfSize(size) {
  const n = +size || 0;
  if (n < 8) return 1;
  return Math.max(1, Math.min(LAND_MAXDEPTH, Math.round(Math.sqrt(n) / 2.2)));
}
/* 가장 가까운 다른 구장까지 거리(km) — 경계는 그 절반에서 만난다 */
function nearestVenueKm(venueId) {
  const v = db.prepare('SELECT lat,lng FROM venues WHERE id=?').get(venueId);
  if (!v || v.lat == null) return 6;
  const d = 0.12;                                   // 대략 13km 상자만 훑는다
  const rows = db.prepare(`SELECT lat,lng FROM venues
    WHERE active=1 AND id!=? AND lat BETWEEN ? AND ? AND lng BETWEEN ? AND ?`)
    .all(venueId, v.lat - d, v.lat + d, v.lng - d * 1.3, v.lng + d * 1.3);
  let best = Infinity;
  const R = 6371, t = Math.PI / 180;
  rows.forEach(o => {
    const dLat = (o.lat - v.lat) * t, dLng = (o.lng - v.lng) * t;
    const s = Math.sin(dLat / 2) ** 2 + Math.cos(v.lat * t) * Math.cos(o.lat * t) * Math.sin(dLng / 2) ** 2;
    const km = 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
    if (km > 0.05 && km < best) best = km;
  });
  return isFinite(best) ? best : 6;
}
/* 실제로 그려질 겹 수 — 규모로 정한 뒤 이웃 거리로 깎는다 */
function effDepth(venueId, size) {
  const want = depthOfSize(size);
  const reach = nearestVenueKm(venueId) / 2;
  const room = Math.floor(reach / (Math.sqrt(3) * 0.2));   // 칸이 200m 밑이면 겹을 줄인다
  return Math.max(1, Math.min(want, room || 1));
}
/* 클럽 활동 인원 — 순위표는 클럽 수십 개를 훑으니 한 번 부른 값은 들고 있는다 */
const _sizeCache = new Map();
function sizeOfClub(clubId) {
  const hit = _sizeCache.get(clubId);
  if (hit && Date.now() - hit.t < 60e3) return hit.n;
  const n = shareActiveMembers(clubId, Date.now() - SHARE_ACT_DAYS * 864e5);
  _sizeCache.set(clubId, { n, t: Date.now() });
  return n;
}
const cellsOf = d => 3 * d * (d + 1) + 1;      // 겹 수 → 칸 수 (옛 방식, 남겨둠)

/* 지도에 그릴 원의 반경(m).
   벌집을 없앴다 — 육각형은 지형과 아무 상관이 없어서 지도 위에 격자를 덮어쓴 것처럼
   보였고, 이웃을 피하려 칸을 줄이다 보니 잘게 쪼개진 덩어리가 됐다.
   원은 가장자리를 흐리게 둘 수 있어 겹쳐도 지저분해지지 않는다.

   규모로 크기를 정하고, 이웃 코트까지 거리의 절반 안으로 묶는 규칙은 그대로다. */
function radiusOf(venueId, size) {
  const n = +size || 0;
  const want = 400 + Math.min(1400, Math.round(Math.sqrt(n) * 240));   // 8명 ≈ 1.1km, 60명 ≈ 1.8km
  const half = nearestVenueKm(venueId) / 2 * 1000;
  return Math.max(250, Math.round(Math.min(want, half)));
}

/* 한 구장에 클럽이 하나만 있는 게 아니다 — 같은 코트를 대여섯 클럽이 나눠 쓴다.
   운영진이 <여기가 우리 홈> 이라고 걸면 그 구장의 지분 다툼에 들어간다.
   지분이 가장 큰 클럽이 그 구장의 <대표 클럽> 으로 지도에 오른다. */
/* 스키마 생성은 반드시 감싼다 — 여기서 던지면 라우트가 하나도 안 붙어
   앱 전체가 안 뜬다. 기능 하나가 죽는 편이 서버가 죽는 것보다 낫다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS venue_clubs (
    venue_id INTEGER, club_id INTEGER,
    set_by INTEGER,               -- 건 사람 (운영진)
    set_at INTEGER,
    PRIMARY KEY(venue_id, club_id))`);
  db.exec('CREATE INDEX IF NOT EXISTS ix_vc_club ON venue_clubs(club_id)');
} catch (e) { console.error('[schema venue_clubs]', e.message); }

const HOME_MAX = 2;               // 한 클럽이 걸 수 있는 홈 구장 수

/* 클럽의 홈 구장 — 운영진이 걸어 둔 곳을 먼저 본다.
   안 걸었으면 최근 1년 정기모임을 세어 예전처럼 자동으로 잡는다.
   (기존 클럽이 갑자기 홈을 잃지 않게 하려고 자동 판정을 남겨 둔다) */
function homeVenues(clubId) {
  const set = db.prepare('SELECT venue_id FROM venue_clubs WHERE club_id=? ORDER BY set_at')
    .all(clubId).map(r => r.venue_id);
  if (set.length) return set.slice(0, HOME_MAX);
  const since = Date.now() - 365 * 864e5;
  const rows = db.prepare(`SELECT venue_id, COUNT(*) n FROM club_events
    WHERE club_id=? AND venue_id IS NOT NULL AND tag!='교류전'
      AND created_at > ? GROUP BY venue_id ORDER BY n DESC`).all(clubId, since);
  const tot = rows.reduce((a, r) => a + r.n, 0);
  if (tot < 10) return [];                      // 기록이 적으면 홈을 정하지 않는다
  return rows.slice(0, 2).filter(r => r.n / tot >= 0.25).map(r => r.venue_id);
}

/* 구장 지분 —
     홈으로 걸어둠              10점
     규모  √(최근 3개월 활동 인원) × 4
     모임  최근 6개월 모임 1회     1점
     교류전 최근 1년 홈 교류전 승  12점

   규모에 √를 씌우는 이유 — 인원을 그대로 곱하면 60명 클럽이 12명 클럽의 5배가 되어
   모임도 교류전도 의미가 없어진다. √를 씌우면 5배 규모가 2.2배 지분이 된다.
   크기가 반영은 되되 혼자 결정하지는 않는 자리다.

   활동 인원은 명부가 아니라 최근 3개월에 한 번이라도 나온 사람으로 센다.
   명부를 쓰면 몇 년 전에 나가고 이름만 남은 회원이 그대로 지분이 된다. */
const SHARE_BASE = 10, SHARE_SIZE = 4, SHARE_EVENT = 1, SHARE_WIN = 12;
const SHARE_EV_DAYS = 182, SHARE_WIN_DAYS = 365, SHARE_ACT_DAYS = 90;

/* 지분에 쓰는 <활동 인원> — 최근 3개월에 모임에 한 번이라도 나온 사람 수.
   위쪽 activeMembers() 는 명부 인원(요금제 한도용)이라 뜻이 다르다. 이름을 갈라 둔다. */
function shareActiveMembers(clubId, since) {
  try {
    return db.prepare(`SELECT COUNT(DISTINCT ea.user_id) n
      FROM event_attendees ea JOIN club_events e ON e.id=ea.event_id
      WHERE e.club_id=? AND e.created_at > ?
        AND (ea.status IS NULL OR ea.status='going')`).get(clubId, since).n;
  } catch (e) { return 0; }
}

/* 이 구장에서 열린 교류전을 클럽별 승수로 센다.
   land.depth 를 쓰면 안 된다 — 그 값은 원정 승리만 올리고 4에서 막힌다.
   내 홈에서 지켜낸 승리가 지분에서는 가장 무거운데 depth 에는 안 담긴다. */
function venueWins(venueId, since) {
  const evs = db.prepare(`SELECT id FROM club_events
    WHERE venue_id=? AND tag='교류전' AND created_at > ?`).all(venueId, since);
  const out = {};
  for (const e of evs) {
    /* 교류전 한 판의 승자 — 게임 단위가 아니라 판 단위로 센다.
       게임으로 세면 코트를 많이 빌린 큰 판 하나가 전부를 삼킨다. */
    const win = {};
    db.prepare(`SELECT home_club, away_club, sa, sb FROM exchange_games WHERE event_id=?`)
      .all(e.id).forEach(g => {
        if (g.sa == null || g.sb == null) return;
        const w = g.sa > g.sb ? g.home_club : g.sa < g.sb ? g.away_club : null;
        if (w) win[w] = (win[w] || 0) + 1;
      });
    const sorted = Object.entries(win).sort((a, b) => b[1] - a[1]);
    if (!sorted.length) continue;
    /* 동점이면 아무도 이긴 게 아니다 */
    if (sorted.length > 1 && sorted[0][1] === sorted[1][1]) continue;
    const w = +sorted[0][0];
    out[w] = (out[w] || 0) + 1;
  }
  return out;
}

function venueShares(venueId) {
  const rows = db.prepare(`SELECT vc.club_id, vc.set_at, c.name, c.region
    FROM venue_clubs vc JOIN clubs c ON c.id=vc.club_id
    WHERE vc.venue_id=? ORDER BY vc.set_at`).all(venueId);
  if (!rows.length) return { clubs: [], top: null, total: 0 };
  const t = Date.now();
  /* 모임은 <실제로 친 자리>만 센다 — 참석 확정 4명 미만은 빼는데,
     행 하나 만들면 점수가 오르는 구조라면 빈 모임을 찍어내는 클럽이 반드시 나온다.
     4명은 코트 한 면을 채우는 최소 인원이다. */
  const evs = db.prepare(`SELECT e.club_id, COUNT(*) n FROM club_events e
    WHERE e.venue_id=? AND e.created_at > ?
      AND (SELECT COUNT(*) FROM event_attendees a
           WHERE a.event_id=e.id AND (a.status IS NULL OR a.status='going')) >= 4
    GROUP BY e.club_id`).all(venueId, t - SHARE_EV_DAYS * 864e5);
  const evMap = {}; evs.forEach(e => { evMap[e.club_id] = e.n; });
  const winMap = venueWins(venueId, t - SHARE_WIN_DAYS * 864e5);
  rows.forEach(r => {
    r.events = evMap[r.club_id] || 0;
    r.wins = winMap[r.club_id] || 0;
    r.size = shareActiveMembers(r.club_id, t - SHARE_ACT_DAYS * 864e5);
    r.score = SHARE_BASE + SHARE_SIZE * Math.sqrt(r.size)
      + SHARE_EVENT * r.events + SHARE_WIN * r.wins;
  });
  const total = rows.reduce((a, r) => a + r.score, 0);
  rows.forEach(r => {
    r.pct = total ? Math.round(r.score / total * 1000) / 10 : 0;
    r.score = Math.round(r.score);
  });
  /* 점수순 — 같으면 먼저 건 쪽이 앞 */
  rows.sort((a, b) => b.score - a.score || a.set_at - b.set_at);
  return { clubs: rows, top: rows[0] || null, total: Math.round(total) };
}

/* 교류전이 끝나면 부른다 — 이긴 클럽이 남의 홈에서 이겼을 때만 땅이 움직인다 */
function landAfterExchange(eventId) {
  try {
    const ev = db.prepare('SELECT venue_id, club_id FROM club_events WHERE id=?').get(eventId);
    if (!ev || !ev.venue_id) return;            // 구장을 못 고른 모임은 셈에서 뺀다
    const entries = db.prepare('SELECT club_id FROM exchange_entries WHERE event_id=?').all(eventId);
    if (entries.length < 2) return;
    /* 클럽별 승수 — 이긴 쪽을 가린다 */
    const win = {};
    db.prepare(`SELECT home_club, away_club, sa, sb FROM exchange_games WHERE event_id=?`)
      .all(eventId).forEach(g => {
        if (g.sa == null || g.sb == null) return;
        const w = g.sa > g.sb ? g.home_club : g.sa < g.sb ? g.away_club : null;
        if (w) win[w] = (win[w] || 0) + 1;
      });
    const sorted = Object.entries(win).sort((a, b) => b[1] - a[1]);
    if (!sorted.length) return;
    const winner = +sorted[0][0];
    const homesOfWinner = homeVenues(winner);
    /* 진 클럽들의 홈인가 — 원정 승리여야 땅이 넘어온다 */
    const awayWin = entries.some(e => e.club_id !== winner
      && homeVenues(e.club_id).includes(ev.venue_id));
    const isMyHome = homesOfWinner.includes(ev.venue_id);
    if (!awayWin && !isMyHome) return;           // 중립 구장 — 지도는 그대로
    const now = Date.now();
    const cur = db.prepare('SELECT depth FROM land WHERE venue_id=? AND club_id=?')
      .get(ev.venue_id, winner);
    const depth = isMyHome
      ? Math.max(1, cur ? cur.depth : 1)         // 홈은 지킨 것 — 겹이 늘지 않는다
      : Math.min(LAND_MAXDEPTH, (cur ? cur.depth : 0) + 1);
    db.prepare(`INSERT INTO land (venue_id,club_id,depth,is_home,last_at) VALUES (?,?,?,?,?)
      ON CONFLICT(venue_id,club_id) DO UPDATE SET depth=?, is_home=?, last_at=?`)
      .run(ev.venue_id, winner, depth, isMyHome ? 1 : 0, now, depth, isMyHome ? 1 : 0, now);
  } catch (e) { console.error('[land]', e.message); }
}

/* 옅어짐 — 하루 한 번 훑는다. 뺏은 땅만 줄고, 홈은 그대로 둔다. */
function landDecay() {
  try {
    const now = Date.now();
    const m = new Date().getMonth();             // 0=1월
    const winter = (m <= 1 || m === 11);         // 12~2월
    db.prepare('SELECT rowid, venue_id, club_id, depth, is_home, last_at FROM land')
      .all().forEach(r => {
        if (r.is_home) return;                   // 내 홈은 안 옅어진다
        const v = db.prepare('SELECT indoor FROM venues WHERE id=?').get(r.venue_id) || {};
        let gap = now - (r.last_at || 0);
        /* 실외는 겨울에 못 친다 — 그 3개월을 벌점으로 세지 않는다 */
        if (winter && !v.indoor) gap -= 90 * 864e5;
        if (gap > 365 * 864e5) {
          if (r.depth > 1) db.prepare('UPDATE land SET depth=depth-1, last_at=? WHERE rowid=?')
            .run(now, r.rowid);
          else db.prepare('DELETE FROM land WHERE rowid=?').run(r.rowid);
        }
      });
  } catch (e) { console.error('[landDecay]', e.message); }
}
setInterval(landDecay, 24 * 3600e3);

/* 공공데이터포털 <전국 공공체육시설 현황> 을 한 번에 넣는다.
   CSV 를 그대로 붙여넣으면 테니스장만 골라 담는다 —
   구장이 비어 있으면 도전장에서 고를 게 없어 교류전이 안 열린다. */
app.post('/admin/venues/import', admin, (req, res) => {
  const raw = String((req.body || {}).csv || '');
  if (!raw.trim()) return res.status(400).json({ error: '표를 붙여넣어 주세요' });

  /* 공공데이터 표는 엑셀에서 복사한 <탭 구분> 이고, 칸 안에 줄바꿈이 들어 있다.
     ("클레이 4\n하드 2" 처럼) 그래서 큰따옴표를 세어가며 줄을 다시 잇는다. */
  const lines = [];
  let cur = '', q = false;
  for (const ch of raw) {
    if (ch === '"') { q = !q; cur += ch; }
    else if (ch === '\n' && !q) { lines.push(cur); cur = ''; }
    else if (ch !== '\r') cur += ch;
  }
  if (cur) lines.push(cur);

  const cut = l => {
    const out = []; let c = '', qq = false;
    for (const ch of l) {
      if (ch === '"') qq = !qq;
      else if ((ch === '\t' || (ch === ',' && !l.includes('\t'))) && !qq) { out.push(c); c = ''; }
      else c += ch;
    }
    out.push(c);
    return out.map(x => x.replace(/\s+/g, ' ').trim());
  };

  const ins = db.prepare(`INSERT INTO venues (name,sido,sigungu,addr,indoor,active,created_at)
    VALUES (?,?,?,?,?,1,?)`);
  const dup = db.prepare(`SELECT id FROM venues WHERE REPLACE(name,' ','')=? LIMIT 1`);
  const norm = x => String(x || '').replace(/\s/g, '');

  let added = 0, skipped = 0, sido = '';
  db.transaction(() => {
    for (const line of lines) {
      const c = cut(line);
      /* 시도 칸이 채워져 있으면 갈아탄다 — 아래 줄들은 비어 있고 위를 이어받는다 */
      if (c[0]) {
        const v = c[0].replace(/\s/g, '');
        if (v && !/개소|^계$|^소계$|^시도$/.test(v)) sido = c[0].trim();
      }
      const gu = c[1] || '', name = c[2] || '';
      /* 합계 줄(<계>, <소 계>, <856개소>)과 머리글은 건너뛴다 */
      if (!name || /개소|^계$|^소 ?계$|^시설명$/.test(norm(gu) + norm(name))) continue;
      if (!/테니스|정구/.test(name)) continue;
      if (dup.get(norm(name))) { skipped++; continue; }
      /* 코트 면수 칸(10번째)이 있으면 참고용으로 주소에 남긴다 */
      const addr = [sido, gu].filter(Boolean).join(' ');
      ins.run(name.slice(0, 60), sido || null, gu || null, addr || null,
        /실내|돔|인도어/.test(name) ? 1 : 0, now());
      added++;
    }
  })();
  res.json({ ok: true, added, skipped,
    total: db.prepare('SELECT COUNT(*) n FROM venues WHERE active=1').get().n });
});

/* 구장이 몇 곳이고 좌표가 몇 곳에 있는지 — 관리자 화면에 띄운다.
   비어 있으면 도전장에서 구장을 못 고르고, 그러면 교류전이 안 열린다. */
app.get('/admin/venues/stats', admin, (_req, res) => {
  const one = q => { try { return db.prepare(q).get().n; } catch (e) { return 0; } };
  res.json({
    total:   one(`SELECT COUNT(*) n FROM venues WHERE active=1`),
    geo:     one(`SELECT COUNT(*) n FROM venues WHERE active=1 AND lat IS NOT NULL`),
    addr:    one(`SELECT COUNT(*) n FROM venues WHERE active=1 AND addr IS NOT NULL AND addr!=''`),
    indoor:  one(`SELECT COUNT(*) n FROM venues WHERE active=1 AND indoor=1`),
    used:    one(`SELECT COUNT(DISTINCT venue_id) n FROM club_events WHERE venue_id IS NOT NULL`),
    sido:    (() => { try {
      return db.prepare(`SELECT sido, COUNT(*) n FROM venues WHERE active=1 AND sido IS NOT NULL
        GROUP BY sido ORDER BY n DESC LIMIT 8`).all();
    } catch (e) { return []; } })(),
    /* 교류전이 몇 번 있었나 — 땅따먹기를 켤 때가 됐는지 알려준다 */
    exchanges: one(`SELECT COUNT(*) n FROM club_events WHERE tag='교류전'`),
    challenges: one(`SELECT COUNT(*) n FROM challenges`),
  });
});

/* 카카오 장소 검색으로 구장을 찾는다.
   공공데이터(856곳)는 <공공체육시설> 뿐이라 사설 코트가 하나도 없다 —
   실내 코트는 대부분 사설이고, 실제로는 이쪽이 더 많다.
   키워드 검색은 상호·주소·좌표를 함께 주니 좌표를 따로 채울 필요도 없다. */
const KAKAO_SIDO = ['서울','부산','대구','인천','광주','대전','울산','세종',
  '경기','강원','충북','충남','전북','전남','경북','경남','제주'];

/* 테니스장이 맞나 — 검색어가 넓어 용품점·아카데미가 잔뜩 섞여 온다 */
const VENUE_BAD = /용품|샵|숍|스토어|아카데미|레슨|교습|학원|스트링|수리|중고|판매/;
function isCourtName(name) {
  const n = String(name || '');
  return /테니스|정구/.test(n) && !VENUE_BAD.test(n);
}
/* 같은 곳인가 — 이름만 보면 안 된다.
   <시민테니스장> 은 전국에 열 곳이 넘어서, 이름만 맞춰보면
   부산 것을 넣을 때 서울 것이 이미 있다고 건너뛰어 버린다.
   이름이 같고 300m 안이면 같은 곳으로 본다. */
function findVenueDup(name, lat, lng, kakaoId) {
  const norm = x => String(x || '').replace(/\s/g, '');
  if (kakaoId) {
    const k = db.prepare('SELECT id FROM venues WHERE kakao_id=? LIMIT 1').get(String(kakaoId));
    if (k) return k.id;
  }
  const rows = db.prepare(`SELECT id, lat, lng FROM venues
    WHERE REPLACE(name,' ','')=?`).all(norm(name));
  if (!rows.length) return null;
  if (!isFinite(lat) || !isFinite(lng)) return rows[0].id;
  for (const r of rows) {
    if (r.lat == null || r.lng == null) return r.id;   // 좌표가 없던 옛 줄 — 같은 곳으로 본다
    const dLat = (r.lat - lat) * 111, dLng = (r.lng - lng) * 88;
    if (Math.sqrt(dLat * dLat + dLng * dLng) < 0.3) return r.id;
  }
  return null;
}
/* 카카오 장소 하나를 구장 표에 앉힌다. 이미 있으면 그 id 를 돌려준다. */
function upsertKakaoVenue(d) {
  const name = String(d.place_name || d.name || '').slice(0, 60);
  const lat = +(d.y != null ? d.y : d.lat), lng = +(d.x != null ? d.x : d.lng);
  const kid = d.id != null ? String(d.id) : null;
  if (!name || !isFinite(lat) || !isFinite(lng)) return null;
  if (!isCourtName(name)) return null;
  const had = findVenueDup(name, lat, lng, kid);
  if (had) {
    /* 공공데이터로 들어와 좌표가 비어 있던 곳이면 여기서 채워준다 */
    try {
      db.prepare(`UPDATE venues SET lat=COALESCE(lat,?), lng=COALESCE(lng,?),
        kakao_id=COALESCE(kakao_id,?) WHERE id=?`).run(lat, lng, kid, had);
    } catch (e) {}
    return { id: had, added: false };
  }
  const addr = String(d.road_address_name || d.address_name || d.addr || '');
  const parts = addr.split(/\s+/);
  const r = db.prepare(`INSERT INTO venues
    (name,sido,sigungu,addr,lat,lng,indoor,phone,kakao_id,source,kind,active,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,'kakao',?,1,?)`)
    .run(name, parts[0] || null, parts[1] || null, addr.slice(0, 120), lat, lng,
      /실내|돔|인도어|아레나/.test(name) ? 1 : 0,
      String(d.phone || '').slice(0, 20) || null, kid, venueKind(name, addr), now());
  return { id: r.lastInsertRowid, added: true };
}

/* 지도에서 방금 찾은 사설 코트를 누를 때 — 우리 표에 없으면 그 자리에서 앉힌다.
   훑어 담기(admin)를 기다리지 않아도 오늘 문 연 코트에서 모임을 잡을 수 있다. */
app.post('/venues/from-kakao', auth, (req, res) => {
  const b = req.body || {};
  let out = null;
  try { out = upsertKakaoVenue(b); } catch (e) { return res.status(500).json({ error: e.message }); }
  if (!out) return res.status(400).json({ error: '테니스장으로 보이지 않아요' });
  const v = db.prepare('SELECT id,name,addr,lat,lng,indoor,phone,source,kind FROM venues WHERE id=?').get(out.id);
  res.json({ ok: true, venue: v, added: out.added });
});

/* 시도마다 대략의 네모 — 검색을 이 안에서 쪼갠다.
   [서쪽경도, 남쪽위도, 동쪽경도, 북쪽위도] */
const SIDO_BOX = {
  서울: [126.76, 37.42, 127.18, 37.70], 부산: [128.80, 34.99, 129.30, 35.39],
  대구: [128.35, 35.62, 128.76, 36.02], 인천: [126.37, 37.28, 126.79, 37.65],
  광주: [126.64, 35.05, 127.02, 35.26], 대전: [127.25, 36.18, 127.56, 36.50],
  울산: [129.05, 35.42, 129.47, 35.75], 세종: [127.14, 36.42, 127.40, 36.72],
  경기: [126.36, 36.88, 127.84, 38.30], 강원: [127.06, 37.03, 129.38, 38.62],
  충북: [127.24, 36.00, 128.66, 37.26], 충남: [125.98, 35.98, 127.60, 37.07],
  전북: [126.30, 35.28, 127.92, 36.15], 전남: [125.06, 34.10, 127.90, 35.50],
  경북: [127.80, 35.70, 129.60, 37.55], 경남: [127.55, 34.55, 129.25, 35.92],
  제주: [126.14, 33.10, 126.98, 33.60],
};

app.post('/admin/venues/search', admin, async (req, res) => {
  const key = process.env.KAKAO_REST_KEY;
  if (!key) return res.json({ error: 'KAKAO_REST_KEY 환경변수가 없어요' });
  const area = String((req.body || {}).area || '').trim();
  if (!area) return res.status(400).json({ error: '지역을 골라주세요' });

  let added = 0, skipped = 0, seen = 0, calls = 0;
  const words = ['테니스장', '테니스클럽', '테니스코트', '실내테니스'];
  const box = SIDO_BOX[area];

  /* 카카오는 한 검색어에 45곳(3쪽)까지만 준다.
     <경기 테니스장> 하나로 훑으면 45곳에서 잘려 사설 코트가 대부분 빠졌다 —
     지도를 네모로 쪼개 각 칸을 따로 물어보고, 45곳을 넘는 칸은 넷으로 또 쪼갠다.
     쪼개는 건 넘치는 칸만 하니 부르는 횟수는 크게 늘지 않는다. */
  const ask = async (word, rect, page) => {
    const q = new URLSearchParams({ query: word, size: '15', page: String(page) });
    if (rect) q.set('rect', rect.join(','));
    else q.set('query', area + ' ' + word);
    calls++;
    const r = await fetch('https://dapi.kakao.com/v2/local/search/keyword.json?' + q,
      { headers: { Authorization: 'KakaoAK ' + key } });
    if (!r.ok) return null;
    await new Promise(t => setTimeout(t, 60));   // 카카오 초당 제한
    return r.json();
  };
  const take = docs => {
    seen += docs.length;
    for (const d of docs) {
      if (!isCourtName(d.place_name)) continue;
      /* 네모가 시도 경계를 살짝 넘을 수 있다 — 주소로 한 번 더 거른다 */
      const addr = String(d.road_address_name || d.address_name || '');
      if (box && addr && !addr.startsWith(area)) continue;
      let out = null;
      try { out = upsertKakaoVenue(d); } catch (e) { continue; }
      if (!out) continue;
      if (out.added) added++; else skipped++;
    }
  };
  /* 한 칸을 훑는다. 45곳을 넘으면 넷으로 나눠 다시 — 깊이 3까지(한 칸 ≈ 5km). */
  const sweep = async (word, rect, depth) => {
    if (calls > 700) return;
    let over = false;
    for (let page = 1; page <= 3; page++) {
      const j = await ask(word, rect, page);
      if (!j) return;
      take(j.documents || []);
      const meta = j.meta || {};
      if (page === 1 && (meta.pageable_count || 0) >= 45) over = true;
      if (meta.is_end) break;
    }
    if (over && rect && depth < 3) {
      const [x1, y1, x2, y2] = rect, mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      for (const q of [[x1, y1, mx, my], [mx, y1, x2, my], [x1, my, mx, y2], [mx, my, x2, y2]])
        await sweep(word, q, depth + 1);
    }
  };

  try {
    for (const w of words) await sweep(w, box || null, 0);
  } catch (e) { return res.json({ error: e.message, added, skipped }); }
  res.json({ ok: true, area, added, skipped, seen, calls,
    boxed: !!box,
    kinds: db.prepare(`SELECT COALESCE(kind,'?') k, COUNT(*) n FROM venues
      WHERE active=1 GROUP BY k`).all(),
    total: db.prepare('SELECT COUNT(*) n FROM venues WHERE active=1').get().n });
});

/* 어느 지역이 아직 비었나 — 훑을 곳을 알려준다 */
app.get('/admin/venues/areas', admin, (_req, res) => {
  const rows = db.prepare(`SELECT sido, COUNT(*) n FROM venues
    WHERE active=1 AND sido IS NOT NULL GROUP BY sido`).all();
  const have = {};
  rows.forEach(r => { KAKAO_SIDO.forEach(s => { if (String(r.sido).startsWith(s)) have[s] = (have[s] || 0) + r.n; }); });
  res.json(KAKAO_SIDO.map(s => ({ area: s, n: have[s] || 0 })));
});

/* 코트가 얼마나·어떻게 들어와 있나 — 사설이 실제로 담겼는지 눈으로 볼 자리.
   공공데이터만 넣고 훑어 담기를 안 돌리면 사설이 0곳인데, 지도만 봐서는 모른다. */
app.get('/admin/venues/kinds', admin, (_req, res) => {
  const q = sql => { try { return db.prepare(sql).all(); } catch (e) { return []; } };
  res.json({
    total: db.prepare('SELECT COUNT(*) n FROM venues WHERE active=1').get().n,
    geocoded: db.prepare('SELECT COUNT(*) n FROM venues WHERE active=1 AND lat IS NOT NULL').get().n,
    by_kind: q(`SELECT COALESCE(kind,'?') k, COUNT(*) n FROM venues
      WHERE active=1 GROUP BY k ORDER BY n DESC`),
    by_source: q(`SELECT COALESCE(source,'?') s, COUNT(*) n FROM venues
      WHERE active=1 GROUP BY s ORDER BY n DESC`),
    /* 시도별 사설 수 — 훑어 담기를 안 돌린 지역이 여기서 0 으로 드러난다 */
    private_by_sido: q(`SELECT COALESCE(sido,'?') sido, COUNT(*) n FROM venues
      WHERE active=1 AND kind='private' GROUP BY sido ORDER BY n DESC LIMIT 20`),
  });
});

/* 좌표 채우기 — 주소를 카카오 지도로 바꿔 한 번 저장한다.
   공공데이터포털 체육시설 목록에 주소가 있으니 그걸 그대로 쓴다. */
app.post('/admin/venues/geocode', admin, async (_req, res) => {
  const key = process.env.KAKAO_REST_KEY;
  if (!key) return res.json({ error: 'KAKAO_REST_KEY 환경변수가 없어요' });
  const rows = db.prepare(`SELECT id, name, addr FROM venues
    WHERE active=1 AND lat IS NULL AND addr IS NOT NULL AND addr!='' LIMIT 200`).all();
  let ok = 0, fail = 0;
  for (const v of rows) {
    try {
      const r = await fetch('https://dapi.kakao.com/v2/local/search/address.json?query='
        + encodeURIComponent(v.addr), { headers: { Authorization: 'KakaoAK ' + key } });
      const j = await r.json();
      const d = (j.documents || [])[0];
      if (d) {
        db.prepare('UPDATE venues SET lat=?, lng=? WHERE id=?').run(+d.y, +d.x, v.id);
        ok++;
      } else fail++;
      await new Promise(r2 => setTimeout(r2, 60));   // 카카오 초당 제한을 넘지 않게
    } catch (e) { fail++; }
  }
  /* 이름에 드러나는 실내 구장을 표시해 둔다 — 겨울 규칙에 쓴다 */
  try {
    db.prepare(`UPDATE venues SET indoor=1 WHERE indoor=0
      AND (name LIKE '%실내%' OR name LIKE '%돔%' OR name LIKE '%인도어%')`).run();
  } catch (e) {}
  res.json({ ok, fail, left: db.prepare('SELECT COUNT(*) n FROM venues WHERE active=1 AND lat IS NULL').get().n });
});

/* 모임을 만들 때 고를 구장 목록.
   <자주 가는 곳> 을 맨 위에 둔다 — 대부분 늘 같은 곳에서 치니
   한 번에 고르고 끝나야 한다. 딱지로 <여기서 이기면 뺏어요> 까지 알려준다. */
app.get('/venues/pick', auth, (req, res) => {
  const q = String(req.query.q || '').trim();
  const cid = +req.query.club_id || 0;
  const lat = +req.query.lat, lng = +req.query.lng;
  const near = isFinite(lat) && isFinite(lng);
  const pick = r => ({ ...r, coords: r.lat != null });

  /* 1) 그 클럽이 최근 1년 쓴 구장 — 많이 간 순 */
  let recent = [];
  if (cid && !q) {
    recent = db.prepare(`SELECT v.id, v.name, v.sido, v.sigungu, v.addr, v.lat, v.lng, v.indoor,
        COUNT(*) used FROM club_events e JOIN venues v ON v.id=e.venue_id
      WHERE e.club_id=? AND e.created_at > ? GROUP BY v.id
      ORDER BY used DESC LIMIT 6`).all(cid, Date.now() - 365 * 864e5);
  }
  const seen = new Set(recent.map(r => r.id));

  /* 2) 검색 · 가까운 곳 */
  let rows;
  if (q) {
    rows = db.prepare(`SELECT id, name, sido, sigungu, addr, lat, lng, indoor, kind FROM venues
      WHERE active=1 AND (name LIKE ? OR addr LIKE ?) ORDER BY name LIMIT 40`)
      .all('%' + q + '%', '%' + q + '%');
  } else if (near) {
    rows = db.prepare(`SELECT id, name, sido, sigungu, addr, lat, lng, indoor, kind,
        ((lat-?)*(lat-?) + (lng-?)*(lng-?)) d FROM venues
      WHERE active=1 AND lat IS NOT NULL ORDER BY d LIMIT 40`).all(lat, lat, lng, lng);
  } else {
    rows = db.prepare(`SELECT id, name, sido, sigungu, addr, lat, lng, indoor, kind FROM venues
      WHERE active=1 ORDER BY id DESC LIMIT 40`).all();
  }
  rows = rows.filter(r => !seen.has(r.id));

  /* 3) 딱지 — 땅과 예약 타임을 봐서 붙인다 */
  const all = recent.concat(rows);
  const ids = all.map(v => v.id);
  const owner = {}, slots = {};
  if (ids.length) {
    const ph = ids.map(() => '?').join(',');
    db.prepare(`SELECT l.venue_id, l.club_id, l.depth, l.is_home, c.name club
      FROM land l JOIN clubs c ON c.id=l.club_id
      WHERE l.venue_id IN (${ph}) ORDER BY l.depth DESC`).all(...ids)
      .forEach(l => { if (!owner[l.venue_id]) owner[l.venue_id] = l; });
    db.prepare(`SELECT venue_id, COUNT(*) n FROM venue_slots
      WHERE venue_id IN (${ph}) AND status='open' AND date >= ?
      GROUP BY venue_id`).all(...ids, new Date().toISOString().slice(0, 10))
      .forEach(s => { slots[s.venue_id] = s.n; });
  }
  const homes = cid ? homeVenues(cid) : [];
  const tag = v => {
    if (homes.includes(v.id)) return { t: '우리 홈', k: 'home' };
    const o = owner[v.id];
    if (o && o.club_id === cid) return { t: '우리 땅', k: 'mine' };
    if (o) return { t: `${o.club} 땅`, k: 'rival' };
    if (slots[v.id]) return { t: '예약 가능', k: 'book' };
    return { t: '빈 구장', k: 'empty' };
  };
  const dist = v => (near && v.lat != null)
    ? Math.round(Math.hypot((v.lat - lat) * 111, (v.lng - lng) * 89) * 10) / 10 : null;
  /* 면수를 함께 준다 — 고르면 <쓰는 코트> 를 그만큼만 보여줄 수 있다 */
  const courtN = {};
  if (ids.length) {
    const ph2 = ids.map(() => '?').join(',');
    db.prepare(`SELECT venue_id, COUNT(*) n FROM venue_courts
      WHERE venue_id IN (${ph2}) AND status='active' GROUP BY venue_id`).all(...ids)
      .forEach(c => { courtN[c.venue_id] = c.n; });
  }
  const wrap = v => ({ ...pick(v), tag: tag(v), km: dist(v),
    slots: slots[v.id] || 0, courts: courtN[v.id] || 0 });
  res.json({ recent: recent.map(wrap), near: rows.map(wrap) });
});

/* 빈 구장을 눌렀을 때 — 그 구장에서 잡을 수 있는 타임 */
app.get('/venues/:id/open-slots', auth, (req, res) => {
  const rows = db.prepare(`SELECT id, date, start, end, price, court_ids FROM venue_slots
    WHERE venue_id=? AND status='open' AND date >= ? ORDER BY date, start LIMIT 8`)
    .all(+req.params.id, new Date().toISOString().slice(0, 10));
  rows.forEach(r => { try { r.courts = JSON.parse(r.court_ids || '[]').length; } catch (e) { r.courts = 0; } });
  const v = db.prepare('SELECT id, name, addr, indoor, lat, lng FROM venues WHERE id=?').get(+req.params.id);
  res.json({ venue: v || null, slots: rows });
});

/* ── 시즌 마감 ────────────────────────────────────────────────
   반기마다 시·도별 1위를 뽑아 남긴다.
   전국 1위는 몇 년을 해도 못 잡지만 <용인시 1위> 는 교류전 두 번이면 바뀐다 —
   가질 만한 자리라야 겨룰 마음이 생긴다. */
db.exec(`CREATE TABLE IF NOT EXISTS land_seasons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  season TEXT,                    -- 2026H1
  city TEXT,                      -- 경기도 용인시
  club_id INTEGER, cells INTEGER, venues INTEGER,
  created_at INTEGER)`);
try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_ls ON land_seasons(season, city)'); } catch (e) {}

function seasonKey(d = new Date()) {
  return `${d.getFullYear()}H${d.getMonth() < 6 ? 1 : 2}`;
}
/* 반기가 끝나면 그 시점 1위를 굳혀 둔다 */
function closeSeason(key) {
  const season = key || seasonKey(new Date(Date.now() - 864e5));
  try {
    /* 지역 자르기는 SQL 보다 여기서 하는 편이 읽기 쉽다 */
    const rows = db.prepare(`SELECT c.id club_id, c.region,
        SUM(3*l.depth*(l.depth+1)+1) cells, COUNT(DISTINCT l.venue_id) venues
      FROM land l JOIN clubs c ON c.id=l.club_id
      WHERE c.region IS NOT NULL AND c.region != ''
      GROUP BY c.id`).all();
    const best = {};
    rows.forEach(r => {
      const city = String(r.region || '').split(' ').filter(Boolean).slice(0, 2).join(' ');
      if (!city) return;
      if (!best[city] || r.cells > best[city].cells) best[city] = { ...r, city };
    });
    const ins = db.prepare(`INSERT INTO land_seasons (season,city,club_id,cells,venues,created_at)
      VALUES (?,?,?,?,?,?) ON CONFLICT(season,city) DO UPDATE
      SET club_id=excluded.club_id, cells=excluded.cells, venues=excluded.venues`);
    Object.values(best).forEach(b =>
      ins.run(season, b.city, b.club_id, b.cells, b.venues, Date.now()));
    return Object.keys(best).length;
  } catch (e) { console.error('[season]', e.message); return 0; }
}
/* 반기 첫날에 지난 반기를 굳힌다 */
setInterval(() => {
  const d = new Date();
  if (d.getDate() === 1 && (d.getMonth() === 0 || d.getMonth() === 6)) closeSeason();
}, 12 * 3600e3);
app.post('/admin/land/close-season', admin, (req, res) => {
  const n = closeSeason(req.body && req.body.season);
  res.json({ ok: true, cities: n });
});

/* 지난 시즌 1위들 — 클럽 화면의 명예의 전당에 쓴다 */
app.get('/clubs/:id/land-seasons', auth, (req, res) => {
  const cid = +req.params.id;
  const club = db.prepare('SELECT region FROM clubs WHERE id=?').get(cid) || {};
  const city = String(club.region || '').split(' ').slice(0, 2).join(' ');
  const mine = db.prepare(`SELECT s.*, c.name club FROM land_seasons s
    JOIN clubs c ON c.id=s.club_id WHERE s.club_id=? ORDER BY s.season DESC LIMIT 8`).all(cid);
  const here = city ? db.prepare(`SELECT s.*, c.name club FROM land_seasons s
    JOIN clubs c ON c.id=s.club_id WHERE s.city=? ORDER BY s.season DESC LIMIT 8`).all(city) : [];
  res.json({ mine, city: here, season: seasonKey() });
});

/* 지도에 뿌릴 것 — 구장 좌표와 클럽별 칸 */
app.get('/land/map', auth, (req, res) => {
  const lat = +req.query.lat, lng = +req.query.lng;
  const km = Math.min(60, +req.query.km || 12);
  const d = km / 111;
  const near = (isFinite(lat) && isFinite(lng))
    ? ' AND v.lat BETWEEN ? AND ? AND v.lng BETWEEN ? AND ? ' : '';
  const args = near ? [lat - d, lat + d, lng - d * 1.2, lng + d * 1.2] : [];
  const venues = db.prepare(`SELECT v.id, v.name, v.lat, v.lng, v.indoor, v.sigungu, v.source, v.kind
    FROM venues v WHERE v.active=1 AND v.lat IS NOT NULL ${near}
    ORDER BY v.id LIMIT 600`).all(...args);
  const ids = venues.map(v => v.id);
  let land = [];
  if (ids.length) {
    land = db.prepare(`SELECT l.venue_id, l.club_id, l.depth, l.is_home, l.last_at, c.name club
      FROM land l JOIN clubs c ON c.id=l.club_id
      WHERE l.venue_id IN (${ids.map(() => '?').join(',')})`).all(...ids);
  }
  /* 옅어짐이 임박한 곳을 앱이 흐리게 그릴 수 있게 남은 날을 함께 준다 */
  const now = Date.now();
  const sizeCache = {};
  const sizeOf = id => (sizeCache[id] != null ? sizeCache[id]
    : (sizeCache[id] = shareActiveMembers(id, now - SHARE_ACT_DAYS * 864e5)));
  land.forEach(l => {
    /* 앱은 이 depth 를 그대로 그린다 — 따로 계산하지 않는다 */
    l.depth = effDepth(l.venue_id, sizeOf(l.club_id));
    l.cells = cellsOf(l.depth);
    l.radius_m = radiusOf(l.venue_id, sizeOf(l.club_id));
    l.days_left = l.is_home ? null
      : Math.max(0, Math.round((365 * 864e5 - (now - (l.last_at || now))) / 864e5));
  });
  const mine = (req.query.club_id ? homeVenues(+req.query.club_id) : []);
  /* 구장마다 대표 클럽 — 지분 1등을 지도 딱지에 함께 띄운다 */
  const reps = {};
  if (ids.length) {
    db.prepare(`SELECT vc.venue_id, vc.club_id, c.name FROM venue_clubs vc
      JOIN clubs c ON c.id=vc.club_id
      WHERE vc.venue_id IN (${ids.map(() => '?').join(',')})`).all(...ids)
      .forEach(r => { (reps[r.venue_id] = reps[r.venue_id] || []).push(r); });
    Object.keys(reps).forEach(vid => {
      const s = venueShares(+vid);
      reps[vid] = s.top ? { club_id: s.top.club_id, name: s.top.name, pct: s.top.pct,
        wins: s.top.wins, size: s.top.size, n: s.clubs.length } : null;
    });
  }
  res.json({ venues, land, my_homes: mine, reps });
});

/* ── 구장 지분 · 홈 걸기 ──────────────────────────────────────── */

/* 이 구장에 어느 클럽이 있고 누가 대표인가 */
app.get('/venues/:id/clubs', auth, (req, res) => {
  const vid = +req.params.id;
  const v = db.prepare('SELECT id,name,addr,sigungu,indoor,source,kind FROM venues WHERE id=?').get(vid);
  if (!v) return res.status(404).json({ error: 'no_venue' });
  const s = venueShares(vid);
  /* 내 클럽이 여기 걸려 있나 · 내가 운영진인가 — 버튼을 뭘 보여줄지 정한다 */
  const cid = +req.query.club_id || 0;
  const mine = cid ? s.clubs.find(c => c.club_id === cid) : null;
  res.json({ venue: v, clubs: s.clubs, top: s.top, total: s.total,
    my_share: mine ? mine.pct : null,
    joined: !!mine,
    can_set: cid ? isOfficer(cid, req.uid) : false,
    home_left: cid ? HOME_MAX - db.prepare('SELECT COUNT(*) n FROM venue_clubs WHERE club_id=?')
      .get(cid).n : 0 });
});

/* 홈으로 걸기 — 운영진만. 걸면 그 구장 지분에 들어가고 구장톡이 열린다. */
app.post('/venues/:id/home', auth, (req, res) => {
  const vid = +req.params.id, cid = +(req.body || {}).club_id;
  if (!cid) return res.status(400).json({ error: 'no_club' });
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  if (!db.prepare('SELECT 1 FROM venues WHERE id=? AND active=1').get(vid))
    return res.status(404).json({ error: 'no_venue' });
  if (db.prepare('SELECT 1 FROM venue_clubs WHERE venue_id=? AND club_id=?').get(vid, cid))
    return res.json({ ok: true, already: true });
  const n = db.prepare('SELECT COUNT(*) n FROM venue_clubs WHERE club_id=?').get(cid).n;
  if (n >= HOME_MAX) return res.status(400).json({ error: 'home_full',
    message: `홈은 ${HOME_MAX}곳까지 걸 수 있어요. 한 곳을 내려놓고 다시 걸어주세요` });
  db.prepare('INSERT INTO venue_clubs (venue_id,club_id,set_by,set_at) VALUES (?,?,?,?)')
    .run(vid, cid, req.uid, now());
  /* 홈으로 걸었으니 지도에도 우리 색이 깔린다 — 옅어지지 않는 홈 칸 */
  try {
    db.prepare(`INSERT INTO land (venue_id,club_id,depth,is_home,last_at) VALUES (?,?,1,1,?)
      ON CONFLICT(venue_id,club_id) DO UPDATE SET is_home=1, last_at=?`)
      .run(vid, cid, now(), now());
  } catch (e) {}
  const s = venueShares(vid);
  res.json({ ok: true, clubs: s.clubs, top: s.top });
});

/* 홈 내려놓기 — 지분도 같이 빠진다 */
app.delete('/venues/:id/home', auth, (req, res) => {
  const vid = +req.params.id, cid = +req.query.club_id;
  if (!cid || !isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  db.prepare('DELETE FROM venue_clubs WHERE venue_id=? AND club_id=?').run(vid, cid);
  /* 뺏은 땅(원정 승리)은 남기고, 홈 표시만 뗀다 */
  try { db.prepare('UPDATE land SET is_home=0 WHERE venue_id=? AND club_id=?').run(vid, cid); } catch (e) {}
  res.json({ ok: true });
});

/* ── 구장톡 ────────────────────────────────────────────────────
   같은 코트를 쓰는 클럽끼리는 서로를 모른다.
   화요일 저녁마다 옆 코트에서 치는 사람들인데 말을 섞을 데가 없었다.
   구장톡은 그 구장에 홈을 건 클럽만 보이고, 전국톡은 모두 본다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS court_posts (
    id INTEGER PRIMARY KEY,
    venue_id INTEGER,             -- 전국톡이면 글쓴이의 홈 구장 (어디서 왔는지 딱지용)
    club_id INTEGER, user_id INTEGER,
    scope TEXT DEFAULT 'court',   -- court(그 구장 클럽만) · all(전국)
    title TEXT, body TEXT,
    created_at INTEGER)`);
  db.exec('CREATE INDEX IF NOT EXISTS ix_cp_venue ON court_posts(venue_id, scope, created_at)');
  db.exec('CREATE INDEX IF NOT EXISTS ix_cp_scope ON court_posts(scope, created_at)');
  db.exec(`CREATE TABLE IF NOT EXISTS court_comments (
    id INTEGER PRIMARY KEY, post_id INTEGER, user_id INTEGER, club_id INTEGER,
    body TEXT, created_at INTEGER)`);
  db.exec('CREATE INDEX IF NOT EXISTS ix_cc_post ON court_comments(post_id, created_at)');
} catch (e) { console.error('[schema court_talk]', e.message); }
/* ALTER 는 두 번째 실행부터 <이미 있다>고 던진다 — 하나로 묶으면 뒤엣것이 건너뛰어진다 */
try { db.exec('ALTER TABLE court_posts ADD COLUMN anon INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE court_comments ADD COLUMN anon INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE court_posts ADD COLUMN cat TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE court_posts ADD COLUMN views INTEGER DEFAULT 0'); } catch (e) {}
/* 조회수 — 같은 사람이 열 번 들어와도 한 번으로 센다.
   안 그러면 글쓴이가 자기 글을 새로고침하는 것만으로 <오늘의 픽>에 오른다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS court_views (
    post_id INTEGER, user_id INTEGER, at INTEGER,
    PRIMARY KEY(post_id, user_id))`);
} catch (e) { console.error('[schema court_views]', e.message); }

/* 말머리 — 두 톡의 목록이 다르다.
   구장톡은 한 코트를 같이 쓰는 사람들끼리라 <분실물>처럼 그 코트에서만 통하는 게 있고,
   전국톡은 모르는 사람들이 만나는 자리라 주제가 넓다. */
const CAT_COURT = [
  { k: 'state', n: '코트 상태' }, { k: 'seat', n: '빈자리·모집' },
  { k: 'match', n: '교류전 제안' }, { k: 'cost', n: '예약·비용' },
  { k: 'lost', n: '분실물' }, { k: 'chat', n: '잡담' },
];
const CAT_ALL = [
  { k: 'chat', n: '잡담' }, { k: 'gear', n: '장비' },
  { k: 'review', n: '코트 후기' }, { k: 'lesson', n: '레슨·강습' },
  { k: 'tour', n: '대회·리그' }, { k: 'used', n: '중고·나눔' },
  { k: 'injury', n: '부상·고민' }, { k: 'newbie', n: '초보 질문' },
];
const catName = (scope, k) => {
  const hit = (scope === 'all' ? CAT_ALL : CAT_COURT).find(c => c.k === k);
  return hit ? hit.n : '';
};

/* ── 익명 닉네임 ──────────────────────────────────────────────
   이름만 가리고 클럽은 남긴다. 클럽까지 가리면 무책임한 말이 늘고,
   옆 코트 클럽과 얘기하는 자리라는 성격도 사라진다.

   <익명1·익명2> 로는 대화가 안 된다. 사람마다 고정된 이름이 있어야
   댓글에서 누가 원글쓴이인지 알 수 있다.

   같은 코트에서는 늘 같은 이름, 다른 코트에서는 다른 이름이다.
   코트마다 같은 이름을 쓰면 여러 코트를 넘나들며 한 사람을 따라갈 수 있다.

   40 × 42 × 42 = 70,560 가지. 두 칸으로 이만큼 만들려면 각 목록이 265개씩
   필요한데, 그만큼 쓰면 억지스러운 말이 섞인다. 칸을 하나 늘렸다. */
const NICK_A = ['조용한','끈질긴','묵직한','느긋한','날쌘','깊은','침착한','화끈한','부지런한','담백한',
  '은근한','단단한','유연한','성실한','과감한','정확한','가벼운','낮은','빠른','꾸준한',
  '무던한','태연한','여유로운','재빠른','다부진','알뜰한','신중한','대범한','소탈한','살가운',
  '진득한','야무진','시원한','촘촘한','노련한','상냥한','무심한','우직한','반듯한','씩씩한'];
const NICK_B = ['새벽','아침','한낮','저녁','한밤','주말','평일','월요일','수요일','금요일',
  '봄날','여름밤','가을','겨울','장마','첫눈','바람','햇살','그늘','소나기',
  '안개','노을','실내','야외','클레이','하드코트','잔디','옆코트','뒷코트','센터코트',
  '베이스라인','네트앞','듀스코트','애드코트','왼손','오른손','양손','원핸드','투핸드','사이드',
  '코너','야간'];
const NICK_C = ['드롭샷','랠리','스매시','로브','발리','크로스','슬라이스','톱스핀','백핸드','포핸드',
  '리턴','에이스','서브','패싱샷','앵글샷','하프발리','오버헤드','문볼','듀스','타이브레이크',
  '풋워크','스텝','스윙','팔로스루','토스','그립','스트링','라켓','텐션','러닝샷',
  '다운더라인','드라이브','언더스핀','사이드스핀','백스윙','리시브','브레이크','러브게임','매치포인트','세트포인트',
  '네트플레이','킥서브'];
const NICK_TOTAL = NICK_A.length * NICK_B.length * NICK_C.length;

/* 한 번 정해진 이름은 바꾸지 않는다 — 겹쳐서 옆으로 밀린 이름도 그대로 남아야
   어제 대화하던 사람과 오늘 같은 사람인 걸 알 수 있다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS court_nicks (
    venue_id INTEGER, user_id INTEGER, nick TEXT,
    made_at INTEGER,
    PRIMARY KEY(venue_id, user_id))`);
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_cn_nick ON court_nicks(venue_id, nick)');
} catch (e) { console.error('[schema court_nicks]', e.message); }

function nickOf(index) {
  const c = index % NICK_C.length;
  const b = Math.floor(index / NICK_C.length) % NICK_B.length;
  const a = Math.floor(index / (NICK_C.length * NICK_B.length)) % NICK_A.length;
  return `${NICK_A[a]} ${NICK_B[b]} ${NICK_C[c]}`;
}
function courtNick(venueId, userId) {
  const had = db.prepare('SELECT nick FROM court_nicks WHERE venue_id=? AND user_id=?')
    .get(venueId, userId);
  if (had) return had.nick;
  /* 사람과 코트를 섞어 자리를 정한다 — 앱에는 완성된 이름만 나간다 */
  const h = crypto.createHash('sha256')
    .update(`${userId}:${venueId}:${process.env.JWT_SECRET || 'matsu'}`).digest();
  let idx = h.readUInt32BE(0) % NICK_TOTAL;
  /* 이미 쓰이는 조합이면 다음 자리로 — 한 코트에 7만 명이 올 일은 없으니 곧 빈자리가 나온다 */
  for (let i = 0; i < 50; i++) {
    const nick = nickOf((idx + i) % NICK_TOTAL);
    try {
      db.prepare('INSERT INTO court_nicks (venue_id,user_id,nick,made_at) VALUES (?,?,?,?)')
        .run(venueId, userId, nick, now());
      return nick;
    } catch (e) { /* 그 이름은 이미 쓰인다 */ }
  }
  return nickOf(idx) + ' ' + (userId % 100);
}
/* 글·댓글 한 줄을 화면에 나갈 모양으로 다듬는다 */
function talkWho(row, venueId, uid) {
  if (!row.venue_id && !venueId) venueId = 0;      // 클럽 없이 전국톡에 쓴 글
  /* 규칙을 바꾸기 전에 실명으로 쌓인 글도 같은 규칙을 따른다 —
     어제 글만 실명이면 그 사람만 드러난다. */
  row.who = courtNick(venueId || row.venue_id || 0, row.user_id);
  row.anon = 1;
  row.mine = (uid && row.user_id === uid) ? 1 : 0;   // 내 글이면 지울 수 있게
  delete row.user_id;
  return row;
}
/* 반응 — 아파트톡처럼 여러 종류. 코트 글은 <물 고였어요>처럼 알림성이 많아서
   좋아요 하나로는 부족하다. 한 사람이 한 글에 하나만 고른다. */
const REACTS = ['heart', 'smile', 'lol', 'clap', 'sad'];
try {
  db.exec(`CREATE TABLE IF NOT EXISTS court_reacts (
    post_id INTEGER, user_id INTEGER, kind TEXT, at INTEGER,
    PRIMARY KEY(post_id, user_id))`);
} catch (e) { console.error('[schema court_reacts]', e.message); }
try { db.exec('ALTER TABLE court_posts ADD COLUMN tags TEXT'); } catch (e) {}

/* 투표 — 글에 딸린다. 한 사람이 하나만 고르고, 고른 뒤에 숫자가 보인다.
   미리 보이면 앞선 쪽으로 쏠린다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS court_polls (
    post_id INTEGER PRIMARY KEY, opts TEXT, made_at INTEGER)`);
  db.exec(`CREATE TABLE IF NOT EXISTS court_votes (
    post_id INTEGER, user_id INTEGER, opt INTEGER, at INTEGER,
    PRIMARY KEY(post_id, user_id))`);
} catch (e) { console.error('[schema court_polls]', e.message); }

function reactsOf(pid, uid) {
  const rows = db.prepare('SELECT kind, COUNT(*) n FROM court_reacts WHERE post_id=? GROUP BY kind').all(pid);
  const map = {}; rows.forEach(r => { map[r.kind] = r.n; });
  const mine = db.prepare('SELECT kind FROM court_reacts WHERE post_id=? AND user_id=?').get(pid, uid);
  return { counts: map, mine: mine ? mine.kind : null,
    total: rows.reduce((a, r) => a + r.n, 0) };
}
function pollOf(pid, uid) {
  const p = db.prepare('SELECT opts FROM court_polls WHERE post_id=?').get(pid);
  if (!p) return null;
  let opts = []; try { opts = JSON.parse(p.opts) || []; } catch (e) {}
  const mine = db.prepare('SELECT opt FROM court_votes WHERE post_id=? AND user_id=?').get(pid, uid);
  const rows = db.prepare('SELECT opt, COUNT(*) n FROM court_votes WHERE post_id=? GROUP BY opt').all(pid);
  const cnt = {}; rows.forEach(r => { cnt[r.opt] = r.n; });
  const total = rows.reduce((a, r) => a + r.n, 0);
  /* 고르기 전에는 숫자를 숨긴다 — 미리 보이면 앞선 쪽으로 쏠린다 */
  const voted = mine != null;
  return { opts: opts.map((t, i) => ({ t, n: voted ? (cnt[i] || 0) : null })),
    mine: voted ? mine.opt : null, total };
}

app.post('/talk/:pid/react', auth, (req, res) => {
  const pid = +req.params.pid;
  const kind = String((req.body || {}).kind || '');
  const p = db.prepare('SELECT venue_id, scope FROM court_posts WHERE id=?').get(pid);
  if (!p) return res.status(404).json({ error: 'no_post' });
  if (p.scope === 'court' && !atCourt(req.uid, p.venue_id))
    return res.status(403).json({ error: 'not_at_court' });
  const had = db.prepare('SELECT kind FROM court_reacts WHERE post_id=? AND user_id=?').get(pid, req.uid);
  /* 같은 걸 다시 누르면 뗀다 — 실수로 눌렀을 때 되돌릴 길이 있어야 한다 */
  if (had && had.kind === kind) {
    db.prepare('DELETE FROM court_reacts WHERE post_id=? AND user_id=?').run(pid, req.uid);
  } else if (REACTS.includes(kind)) {
    db.prepare(`INSERT INTO court_reacts (post_id,user_id,kind,at) VALUES (?,?,?,?)
      ON CONFLICT(post_id,user_id) DO UPDATE SET kind=?, at=?`)
      .run(pid, req.uid, kind, now(), kind, now());
  }
  res.json({ ok: true, react: reactsOf(pid, req.uid) });
});

app.post('/talk/:pid/vote', auth, (req, res) => {
  const pid = +req.params.pid, opt = +(req.body || {}).opt;
  const p = db.prepare('SELECT venue_id, scope FROM court_posts WHERE id=?').get(pid);
  if (!p) return res.status(404).json({ error: 'no_post' });
  if (p.scope === 'court' && !atCourt(req.uid, p.venue_id))
    return res.status(403).json({ error: 'not_at_court' });
  const poll = db.prepare('SELECT opts FROM court_polls WHERE post_id=?').get(pid);
  if (!poll) return res.status(404).json({ error: 'no_poll' });
  let opts = []; try { opts = JSON.parse(poll.opts) || []; } catch (e) {}
  if (!(opt >= 0 && opt < opts.length)) return res.status(400).json({ error: 'bad_opt' });
  /* 한 번 고르면 못 바꾼다 — 바꿀 수 있으면 결과를 보고 옮겨 다니게 된다 */
  try {
    db.prepare('INSERT INTO court_votes (post_id,user_id,opt,at) VALUES (?,?,?,?)')
      .run(pid, req.uid, opt, now());
  } catch (e) { return res.status(400).json({ error: 'already' }); }
  res.json({ ok: true, poll: pollOf(pid, req.uid) });
});

/* ── 신고 · 차단 ────────────────────────────────────────────────
   전국톡이 열리면서 가입만 하면 누구나 전국에 글을 올릴 수 있게 됐다.
   광고와 도배가 들어올 자리다.

   익명이어도 서버는 누가 썼는지 안다. 그래서 신고도 차단도 동작한다. */
const REPORT_REASONS = [
  { k: 'ad', n: '광고·홍보' }, { k: 'abuse', n: '욕설·비방' },
  { k: 'porn', n: '음란물' }, { k: 'spam', n: '도배' },
  { k: 'privacy', n: '개인정보 노출' }, { k: 'etc', n: '그 밖에' },
];
/* 몇 명이 신고하면 자동으로 가릴까 —
   3명은 30명짜리 구장에서는 짜고 치면 넘길 수 있는 수다. 그래도 방치보다 낫다.
   가려질 뿐 지워지지 않고, 운영진이 풀 수 있다. */
const REPORT_HIDE_AT = 3;
try {
  db.exec(`CREATE TABLE IF NOT EXISTS court_reports (
    id INTEGER PRIMARY KEY,
    kind TEXT,                     -- post · comment
    target_id INTEGER,
    user_id INTEGER,               -- 신고한 사람
    author_id INTEGER,             -- 신고당한 글쓴이
    venue_id INTEGER, scope TEXT,
    reason TEXT, memo TEXT,
    state TEXT DEFAULT 'open',     -- open · kept(문제없음) · removed
    at INTEGER)`);
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_crp ON court_reports(kind, target_id, user_id)');
  db.exec('CREATE INDEX IF NOT EXISTS ix_crp_state ON court_reports(state, at)');
  db.exec(`CREATE TABLE IF NOT EXISTS court_blocks (
    user_id INTEGER, target_id INTEGER, at INTEGER,
    PRIMARY KEY(user_id, target_id))`);
} catch (e) { console.error('[schema court_reports]', e.message); }
try { db.exec('ALTER TABLE court_posts ADD COLUMN hidden INTEGER DEFAULT 0'); } catch (e) {}
/* 사진 — 클럽 소식과 같은 방식이다. /upload 로 올린 주소만 담는다(그림 자체는 파일로 간다) */
try { db.exec('ALTER TABLE court_posts ADD COLUMN photos TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE court_posts ADD COLUMN edited_at INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE court_comments ADD COLUMN hidden INTEGER DEFAULT 0'); } catch (e) {}

/* 내가 안 보기로 한 사람들 — 목록에서 통째로 뺀다 */
function blockedBy(uid) {
  try {
    return db.prepare('SELECT target_id FROM court_blocks WHERE user_id=?').all(uid)
      .map(r => r.target_id);
  } catch (e) { return []; }
}

app.get('/talk/report-reasons', auth, (_req, res) => res.json(REPORT_REASONS));

app.post('/talk/report', auth, (req, res) => {
  const b = req.body || {};
  const kind = b.kind === 'comment' ? 'comment' : 'post';
  const tid = +b.id;
  const reason = REPORT_REASONS.some(r => r.k === b.reason) ? b.reason : 'etc';
  const memo = String(b.memo || '').trim().slice(0, 300);

  const row = kind === 'post'
    ? db.prepare('SELECT user_id, venue_id, scope FROM court_posts WHERE id=?').get(tid)
    : db.prepare(`SELECT cc.user_id, p.venue_id, p.scope FROM court_comments cc
        JOIN court_posts p ON p.id=cc.post_id WHERE cc.id=?`).get(tid);
  if (!row) return res.status(404).json({ error: 'no_target' });
  /* 자기 글은 신고할 수 없다 — 지우면 된다 */
  if (row.user_id === req.uid) return res.status(400).json({ error: 'own' });

  try {
    db.prepare(`INSERT INTO court_reports
      (kind,target_id,user_id,author_id,venue_id,scope,reason,memo,at)
      VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(kind, tid, req.uid, row.user_id, row.venue_id, row.scope, reason, memo || null, now());
  } catch (e) { return res.json({ ok: true, already: true }); }

  /* 여러 사람이 신고하면 일단 가린다 — 지우지는 않는다. 운영진이 풀 수 있다. */
  const n = db.prepare('SELECT COUNT(*) n FROM court_reports WHERE kind=? AND target_id=?')
    .get(kind, tid).n;
  let hidden = false;
  if (n >= REPORT_HIDE_AT) {
    const t = kind === 'post' ? 'court_posts' : 'court_comments';
    try { db.prepare(`UPDATE ${t} SET hidden=1 WHERE id=?`).run(tid); hidden = true; } catch (e) {}
  }
  res.json({ ok: true, count: n, hidden });
});

/* 이 사람 글 안 보기 — 닉네임이 구장마다 고정이라 실제로 한 사람을 가린다 */
app.post('/talk/block', auth, (req, res) => {
  const b = req.body || {};
  const kind = b.kind === 'comment' ? 'comment' : 'post';
  const tid = +b.id;
  const row = kind === 'post'
    ? db.prepare('SELECT user_id FROM court_posts WHERE id=?').get(tid)
    : db.prepare('SELECT user_id FROM court_comments WHERE id=?').get(tid);
  if (!row) return res.status(404).json({ error: 'no_target' });
  if (row.user_id === req.uid) return res.status(400).json({ error: 'own' });
  try {
    db.prepare('INSERT INTO court_blocks (user_id,target_id,at) VALUES (?,?,?)')
      .run(req.uid, row.user_id, now());
  } catch (e) {}
  res.json({ ok: true });
});

app.get('/admin/talk/reports', admin, (req, res) => {
  const state = String(req.query.state || 'open');
  const rows = db.prepare(`SELECT r.*, v.name venue FROM court_reports r
    LEFT JOIN venues v ON v.id=r.venue_id
    WHERE r.state=? ORDER BY r.at DESC LIMIT 100`).all(state);
  rows.forEach(r => {
    r.reason_name = (REPORT_REASONS.find(x => x.k === r.reason) || {}).n || r.reason;
    const t = r.kind === 'post' ? 'court_posts' : 'court_comments';
    const row = db.prepare(`SELECT body, hidden FROM ${t} WHERE id=?`).get(r.target_id);
    r.body = row ? String(row.body || '').slice(0, 200) : '(지워짐)';
    r.hidden = row ? row.hidden : null;
    r.count = db.prepare('SELECT COUNT(*) n FROM court_reports WHERE kind=? AND target_id=?')
      .get(r.kind, r.target_id).n;
  });
  res.json(rows);
});

app.post('/admin/talk/reports/:id', admin, (req, res) => {
  const id = +req.params.id;
  const act = String((req.body || {}).act || '');
  const r = db.prepare('SELECT kind, target_id FROM court_reports WHERE id=?').get(id);
  if (!r) return res.status(404).json({ error: 'no_report' });
  const t = r.kind === 'post' ? 'court_posts' : 'court_comments';
  if (act === 'remove') {
    db.prepare(`UPDATE ${t} SET hidden=1 WHERE id=?`).run(r.target_id);
    db.prepare("UPDATE court_reports SET state='removed' WHERE kind=? AND target_id=?")
      .run(r.kind, r.target_id);
  } else if (act === 'keep') {
    /* 문제없음 — 가려둔 걸 도로 푼다 */
    db.prepare(`UPDATE ${t} SET hidden=0 WHERE id=?`).run(r.target_id);
    db.prepare("UPDATE court_reports SET state='kept' WHERE kind=? AND target_id=?")
      .run(r.kind, r.target_id);
  } else return res.status(400).json({ error: 'bad_act' });
  res.json({ ok: true });
});

/* 지도를 열 때 찾은 코트를 통째로 담는다 —
   눌러야만 담기게 두었더니 화면에는 보이는데 표는 비어 있었다.
   821곳이 전부 공공데이터인 이유가 이것이다. 사람들이 지도를 볼수록 표가 채워진다. */
app.post('/venues/from-kakao/bulk', auth, (req, res) => {
  const list = Array.isArray((req.body || {}).places) ? (req.body || {}).places.slice(0, 30) : [];
  let added = 0, had = 0;
  const ids = {};
  db.transaction(() => {
    for (const p of list) {
      let out = null;
      try { out = upsertKakaoVenue(p); } catch (e) { continue; }
      if (!out) continue;
      if (out.added) added++; else had++;
      if (p.id) ids[p.id] = out.id;             // 카카오 장소번호 → 우리 구장번호
    }
  })();
  res.json({ ok: true, added, had, ids });
});

/* 코트 정보 — 몇 면인지, 조명이 있는지, 주차가 되는지.
   남이 이 구장을 눌러 들어왔을 때 알고 싶은 것들이다.
   공공데이터에도 카카오에도 없어서 다니는 사람이 채워야 한다. */
try { db.exec('ALTER TABLE venues ADD COLUMN courts_n INTEGER'); } catch (e) {}
/* 실내·실외를 따로 센다 — 한 구장에 둘 다 있는 곳이 흔한데
   indoor 는 참·거짓 하나뿐이라 <실내 2면 실외 3면>을 담을 데가 없었다.
   그래서 사람들이 바닥 칸에 적어 넣고, 화면에는 <실외 5면 · 실내 2코트 실외 3코트>가 됐다. */
try { db.exec('ALTER TABLE venues ADD COLUMN indoor_n INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE venues ADD COLUMN outdoor_n INTEGER'); } catch (e) {}
try { db.exec('ALTER TABLE venues ADD COLUMN surface TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE venues ADD COLUMN lights TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE venues ADD COLUMN parking TEXT'); } catch (e) {}

app.post('/venues/:id/info', auth, (req, res) => {
  const vid = +req.params.id, b = req.body || {};
  const v = db.prepare('SELECT owner_id FROM venues WHERE id=?').get(vid);
  if (!v) return res.status(404).json({ error: 'no_venue' });
  /* 그 구장에 홈을 건 클럽의 운영진, 구장 주인만 고칠 수 있다 */
  const ok = (v.owner_id && v.owner_id === req.uid) ||
    !!db.prepare(`SELECT 1 FROM venue_clubs vc JOIN club_members m ON m.club_id=vc.club_id
      WHERE vc.venue_id=? AND m.user_id=? AND m.role IN ('owner','officer') LIMIT 1`)
      .get(vid, req.uid);
  if (!ok) return res.status(403).json({ error: 'not_allowed' });

  const num = x => (x === '' || x == null) ? null
    : Math.max(0, Math.min(60, parseInt(x, 10) || 0));
  const io = num(b.indoor_n), oo = num(b.outdoor_n);
  const total = (io == null && oo == null) ? num(b.courts_n) : (io || 0) + (oo || 0);
  const cut = (x, len) => { const t = String(x == null ? '' : x).trim().slice(0, len); return t || null; };
  /* 실내만 있으면 실내 구장, 아니면 실외로 둔다 — 목록 딱지에 쓰는 값이다 */
  const indoorFlag = (io != null || oo != null) ? ((io > 0 && !(oo > 0)) ? 1 : 0) : null;
  db.prepare(`UPDATE venues SET indoor_n=?, outdoor_n=?, courts_n=?, surface=?, lights=?, parking=?,
      indoor=COALESCE(?, indoor), kind=COALESCE(?, kind) WHERE id=?`)
    .run(io, oo, total, cut(b.surface, 20), cut(b.lights, 20), cut(b.parking, 20),
      indoorFlag,
      ['public', 'private', 'school', 'apt'].includes(b.kind) ? b.kind : null, vid);
  res.json({ ok: true });
});

/* 내가 이 구장 사람인가 — 내 클럽 중 하나라도 여기 홈을 걸었으면 그렇다 */
function atCourt(uid, venueId) {
  return !!db.prepare(`SELECT 1 FROM venue_clubs vc
    JOIN club_members m ON m.club_id=vc.club_id
    WHERE vc.venue_id=? AND m.user_id=? LIMIT 1`).get(venueId, uid);
}
function postRow(p) {
  return { ...p, comments: db.prepare('SELECT COUNT(*) n FROM court_comments WHERE post_id=?')
    .get(p.id).n };
}

/* 구장톡을 마지막으로 본 때 — <새 글> 점을 정직하게 찍으려고 남긴다.
   최근 3일 글 수로 대신하면 이미 읽은 글에도 점이 붙는다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS court_seen (
    user_id INTEGER, venue_id INTEGER, seen_at INTEGER,
    PRIMARY KEY(user_id, venue_id))`);
} catch (e) { console.error('[schema court_seen]', e.message); }

/* 클럽 탭 홈코트 카드 — 한 번에 한 장 분량을 준다.
   지분·순위·다음 한 수·안 읽은 글을 따로 부르면 탭 열 때마다 네 번을 왕복한다. */
app.get('/clubs/:id/homecourt', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const officer = isOfficer(cid, req.uid);
  const row = db.prepare(`SELECT vc.venue_id, v.name FROM venue_clubs vc
    JOIN venues v ON v.id=vc.venue_id WHERE vc.club_id=? ORDER BY vc.set_at LIMIT 1`).get(cid);
  if (!row) return res.json({ home: null, can_set: officer });

  const s = venueShares(row.venue_id);
  const mine = s.clubs.find(c => c.club_id === cid);
  const rank = s.clubs.findIndex(c => c.club_id === cid) + 1;
  const top = s.top;
  /* 1등이 아니면 몇 승이 모자란가 — 숫자만 보여주면 뭘 해야 할지 모른다 */
  let need = null;
  if (mine && top && top.club_id !== cid) need = Math.ceil((top.score - mine.score) / SHARE_WIN) + 1;

  const seen = db.prepare('SELECT seen_at FROM court_seen WHERE user_id=? AND venue_id=?')
    .get(req.uid, row.venue_id);
  const unread = db.prepare(`SELECT COUNT(*) n FROM court_posts
    WHERE venue_id=? AND scope='court' AND user_id!=? AND created_at > ?`)
    .get(row.venue_id, req.uid, (seen && seen.seen_at) || 0).n;

  res.json({
    home: { venue_id: row.venue_id, name: row.name },
    pct: mine ? mine.pct : 0, rank: rank || null, clubs: s.clubs.length,
    /* 혼자 쓰는 중일 때 <100%> 대신 무엇을 적을지 정하려면 우리 활동량이 필요하다 */
    events: mine ? mine.events : 0, wins: mine ? mine.wins : 0,
    top: top ? { name: top.name, pct: top.pct, mine: top.club_id === cid } : null,
    need, unread, can_set: officer,
    bars: s.clubs.map(c => ({ pct: c.pct, mine: c.club_id === cid, wins: c.wins })),
  });
});

app.post('/venues/:id/talk/seen', auth, (req, res) => {
  try {
    db.prepare(`INSERT INTO court_seen (user_id,venue_id,seen_at) VALUES (?,?,?)
      ON CONFLICT(user_id,venue_id) DO UPDATE SET seen_at=?`)
      .run(req.uid, +req.params.id, now(), now());
  } catch (e) {}
  res.json({ ok: true });
});

app.get('/venues/:id/talk', auth, (req, res) => {
  const vid = +req.params.id || 0;
  /* 구장을 안 고른 채로 오면(클럽이 없는 사람) 전국톡만 본다 —
     전국톡은 클럽에 안 든 사람도 낄 수 있는 자리다. */
  const scope = (!vid || req.query.scope === 'all') ? 'all' : 'court';
  const v = vid ? (db.prepare('SELECT name FROM venues WHERE id=?').get(vid) || {}) : {};
  /* 누가 이 코트를 쓰는지 — 글이 하나도 없어도 빈 방으로 느껴지지 않게 앞에 세운다 */
  const s = vid ? venueShares(vid) : { clubs: [] };
  const who = s.clubs.map(c => ({ club_id: c.club_id, name: c.name, wins: c.wins, size: c.size }));
  if (scope === 'court' && !atCourt(req.uid, vid))
    return res.json({ scope, locked: true, posts: [], venue: v.name || '', clubs: who,
      message: '이 구장을 홈으로 건 클럽만 보이는 공간이에요' });
  /* 말머리로 거른다 — 없으면 전체 */
  const cat = String(req.query.cat || '').trim();
  const catSql = cat ? ' AND p.cat=? ' : '';
  /* 가려진 글과 안 보기로 한 사람의 글은 뺀다.
     내 글은 가려져도 나에게는 보인다 — 왜 반응이 없는지 알 수 있어야 한다. */
  const bl = blockedBy(req.uid);
  const hideSql = ` AND (p.hidden IS NULL OR p.hidden=0 OR p.user_id=${+req.uid}) `
    + (bl.length ? ` AND p.user_id NOT IN (${bl.map(Number).join(',')}) ` : '');
  const rows = scope === 'court'
    ? db.prepare(`SELECT p.id,p.title,p.body,p.created_at,p.club_id,p.user_id,p.anon,p.venue_id,
        p.cat,p.views,p.tags,p.hidden,p.photos,p.edited_at, c.name club, u.name who FROM court_posts p
        LEFT JOIN clubs c ON c.id=p.club_id LEFT JOIN users u ON u.id=p.user_id
        WHERE p.venue_id=? AND p.scope='court' ${catSql} ${hideSql}
        ORDER BY p.created_at DESC LIMIT 50`).all(...(cat ? [vid, cat] : [vid]))
    : db.prepare(`SELECT p.id,p.title,p.body,p.created_at,p.club_id,p.user_id,p.anon,p.venue_id,
        p.cat,p.views,p.tags,p.hidden,p.photos,p.edited_at, c.name club, u.name who, v.name venue, v.sigungu FROM court_posts p
        LEFT JOIN clubs c ON c.id=p.club_id LEFT JOIN users u ON u.id=p.user_id
        LEFT JOIN venues v ON v.id=p.venue_id
        WHERE p.scope='all' ${catSql} ${hideSql} ORDER BY p.created_at DESC LIMIT 50`).all(...(cat ? [cat] : []));
  rows.forEach(r => {
    r.cat_name = catName(scope, r.cat);
    r.hidden = r.hidden ? 1 : 0;
    r.react_n = db.prepare('SELECT COUNT(*) n FROM court_reacts WHERE post_id=?').get(r.id).n;
    r.has_poll = !!db.prepare('SELECT 1 FROM court_polls WHERE post_id=?').get(r.id);
    r.poll_n = r.has_poll
      ? db.prepare('SELECT COUNT(*) n FROM court_votes WHERE post_id=?').get(r.id).n : 0;
    try { r.tags = r.tags ? JSON.parse(r.tags) : []; } catch (e) { r.tags = []; }
    try { r.photos = r.photos ? JSON.parse(r.photos) : []; } catch (e) { r.photos = []; }
  });
  /* 전국톡은 코트가 저마다 달라 글쓴이의 홈구장 기준으로 이름을 만든다 */
  const posts = rows.map(r => talkWho(postRow(r), r.venue_id || vid, req.uid));
  /* 내가 이 코트에서 어떤 이름으로 보이는지 — 글쓰기 화면에서 미리 보여준다 */
  const myNick = courtNick(vid || 0, req.uid);
  /* 오늘의 픽 — 사람이 고르는 자리를 만들어두면 매일 같은 글이 박혀 있게 된다.
     최근 이레 안에서 많이 읽힌 순으로 자동으로 뽑는다. 아무도 안 만져도 굴러간다. */
  let picks = [];
  if (scope === 'all') {
    picks = db.prepare(`SELECT p.id,p.title,p.body,p.created_at,p.views,p.cat,p.venue_id,p.user_id,
        v.name venue, v.sigungu FROM court_posts p LEFT JOIN venues v ON v.id=p.venue_id
      WHERE p.scope='all' AND p.created_at > ? AND p.views > 0
        AND (p.hidden IS NULL OR p.hidden=0)
      ORDER BY p.views DESC LIMIT 3`).all(Date.now() - 7 * 864e5);
    picks.forEach(p => { p.cat_name = catName('all', p.cat); talkWho(p, p.venue_id, req.uid); });
  }
  res.json({ scope, locked: false, posts, venue: v.name || '', clubs: who, my_nick: myNick,
    cats: scope === 'all' ? CAT_ALL : CAT_COURT, picks, total: rows.length });
});

app.post('/venues/:id/talk', auth, (req, res) => {
  const vid = +req.params.id || 0, b = req.body || {};
  const scope = (!vid || b.scope === 'all') ? 'all' : 'court';
  /* 앱이 club_id 를 못 보내는 경우가 있다(초대로 들어온 클럽은 이름-번호 짝이 비어 있다).
     그때는 서버가 내 클럽을 찾아 붙인다 — 안 그러면 글에 클럽 이름이 안 붙는다. */
  let cid = +b.club_id || null;
  if (!cid) {
    const m = db.prepare('SELECT club_id FROM club_members WHERE user_id=? ORDER BY club_id LIMIT 1')
      .get(req.uid);
    cid = m ? m.club_id : null;
  }
  if (scope === 'court' && !atCourt(req.uid, vid))
    return res.status(403).json({ error: 'not_at_court',
      message: '이 구장을 홈으로 건 클럽의 회원만 쓸 수 있어요' });
  if (cid && !isMember(cid, req.uid))
    return res.status(403).json({ error: 'member_only', message: '클럽 회원만 쓸 수 있어요' });
  const title = String(b.title || '').trim().slice(0, 60);
  const body = String(b.body || '').trim().slice(0, 2000);
  /* 사진만 올려도 된다 — 코트 상태는 글보다 사진이 빠르다 */
  if (!body && !(Array.isArray(b.photos) && b.photos.length))
    return res.status(400).json({ error: 'empty', message: '사진이나 글을 넣어주세요' });
  /* 구장톡은 통째로 익명이다 — 고르게 두면 스위치가 늘 켜진 채로 남아
     아무 뜻 없는 버튼이 된다. 클럽 이름은 그대로 보이니 책임은 남는다. */
  /* 말머리는 목록에 있는 값만 받는다 — 앱이 아무 문자열이나 보내도 표에 안 들어가게 */
  const list = scope === 'all' ? CAT_ALL : CAT_COURT;
  const cat = list.some(c => c.k === b.cat) ? b.cat : list[list.length - 1].k;
  /* 태그는 다섯 개까지, 한 개 12자까지 — 길고 많으면 목록이 태그로 덮인다 */
  const tags = (Array.isArray(b.tags) ? b.tags : [])
    .map(x => String(x || '').replace(/[#\s]/g, '').slice(0, 12))
    .filter(Boolean).slice(0, 5);
  const photos = (Array.isArray(b.photos) ? b.photos : [])
    .filter(u => typeof u === 'string' && u.length < 500).slice(0, 10);
  const r = db.prepare(`INSERT INTO court_posts (venue_id,club_id,user_id,scope,title,body,anon,cat,tags,photos,created_at)
    VALUES (?,?,?,?,?,?,1,?,?,?,?)`)
    .run(vid || null, cid, req.uid, scope, title || null, body, cat,
      JSON.stringify(tags), JSON.stringify(photos), now());
  const pid = rid(r);
  /* 투표는 두 개 이상 골라야 뜻이 있다 */
  const opts = (Array.isArray(b.poll) ? b.poll : [])
    .map(x => String(x || '').trim().slice(0, 40)).filter(Boolean).slice(0, 6);
  if (opts.length >= 2) {
    try {
      db.prepare('INSERT INTO court_polls (post_id,opts,made_at) VALUES (?,?,?)')
        .run(pid, JSON.stringify(opts), now());
    } catch (e) {}
  }
  res.json({ ok: true, id: pid });
});

app.get('/talk/:pid/comments', auth, (req, res) => {
  const pid = +req.params.pid;
  const p = db.prepare('SELECT venue_id, scope FROM court_posts WHERE id=?').get(pid);
  if (!p) return res.status(404).json({ error: 'no_post' });
  if (p.scope === 'court' && !atCourt(req.uid, p.venue_id))
    return res.status(403).json({ error: 'not_at_court' });
  const author = db.prepare('SELECT user_id FROM court_posts WHERE id=?').get(pid).user_id;
  /* 글을 열 때 조회로 센다 — 댓글을 부르는 시점이 곧 글을 여는 시점이다.
     같은 사람은 한 번만. 두 번째부터는 INSERT 가 막혀 조용히 지나간다. */
  try {
    db.prepare('INSERT INTO court_views (post_id,user_id,at) VALUES (?,?,?)').run(pid, req.uid, now());
    db.prepare('UPDATE court_posts SET views=COALESCE(views,0)+1 WHERE id=?').run(pid);
  } catch (e) { /* 이미 본 글 */ }
  const bl2 = blockedBy(req.uid);
  const rows = db.prepare(`SELECT cc.id,cc.body,cc.created_at,cc.user_id,cc.anon,cc.hidden,
    u.name who, c.name club FROM court_comments cc
    LEFT JOIN users u ON u.id=cc.user_id LEFT JOIN clubs c ON c.id=cc.club_id
    WHERE cc.post_id=?
      AND (cc.hidden IS NULL OR cc.hidden=0 OR cc.user_id=?)
      ${bl2.length ? `AND cc.user_id NOT IN (${bl2.map(Number).join(',')})` : ''}
    ORDER BY cc.created_at`).all(pid, req.uid);
  /* 글쓴이 표시 — 이름이 고정이라야 댓글에서 누가 원글쓴이인지 알 수 있다 */
  rows.forEach(r => { r.mine_post = (r.user_id === author) ? 1 : 0; });
  res.json({ comments: rows.map(r => talkWho(r, p.venue_id, req.uid)),
    react: reactsOf(pid, req.uid), poll: pollOf(pid, req.uid),
    tags: (() => { try { const t = db.prepare('SELECT tags FROM court_posts WHERE id=?').get(pid).tags;
      return t ? JSON.parse(t) : []; } catch (e) { return []; } })(),
    post: (() => {
      const row = db.prepare('SELECT title,body,photos,cat,edited_at FROM court_posts WHERE id=?').get(pid);
      if (!row) return null;
      try { row.photos = row.photos ? JSON.parse(row.photos) : []; } catch (e) { row.photos = []; }
      return row;
    })() });
});

app.post('/talk/:pid/comments', auth, (req, res) => {
  const pid = +req.params.pid, b = req.body || {};
  const p = db.prepare('SELECT venue_id, scope FROM court_posts WHERE id=?').get(pid);
  if (!p) return res.status(404).json({ error: 'no_post' });
  if (p.scope === 'court' && !atCourt(req.uid, p.venue_id))
    return res.status(403).json({ error: 'not_at_court' });
  const body = String(b.body || '').trim().slice(0, 1000);
  if (!body) return res.status(400).json({ error: 'empty', message: '내용을 적어주세요' });
  if (!b.club_id) {
    const m = db.prepare('SELECT club_id FROM club_members WHERE user_id=? ORDER BY club_id LIMIT 1')
      .get(req.uid);
    if (m) b.club_id = m.club_id;
  }
  const r = db.prepare(`INSERT INTO court_comments (post_id,user_id,club_id,body,anon,created_at)
    VALUES (?,?,?,?,1,?)`).run(pid, req.uid, +b.club_id || null, body, now());
  res.json({ ok: true, id: rid(r) });
});

/* 구장 한 페이지에 필요한 것을 한 번에 준다 —
   코트 정보·최근에 있었던 일·구장톡 미리보기를 따로 부르면 페이지 하나에 네 번 왕복한다. */
app.get('/venues/:id/detail', auth, (req, res) => {
  const vid = +req.params.id;
  const v = db.prepare(`SELECT id,name,addr,sido,sigungu,indoor,phone,source,kind,lat,lng,
    courts_n,indoor_n,outdoor_n,surface,lights,parking,owner_id FROM venues WHERE id=?`).get(vid);
  if (!v) return res.status(404).json({ error: 'no_venue' });

  /* 면 수와 표면 — 사장님이 등록한 곳에만 있다. 없으면 그 줄을 안 보여준다. */
  const courts = db.prepare(`SELECT COUNT(*) n,
      GROUP_CONCAT(DISTINCT surface) surfaces FROM venue_courts
    WHERE venue_id=? AND status!='paused'`).get(vid) || {};

  /* 이 코트에서 있었던 일 — 46% 라는 숫자보다 <10월 26일 라온이 이겼다>가 잘 읽힌다 */
  const evs = db.prepare(`SELECT e.id, e.title, e.date, e.tag, e.created_at, c.name club
    FROM club_events e LEFT JOIN clubs c ON c.id=e.club_id
    WHERE e.venue_id=? ORDER BY e.created_at DESC LIMIT 6`).all(vid);
  const winCache = {};
  evs.forEach(e => {
    e.people = db.prepare(`SELECT COUNT(*) n FROM event_attendees
      WHERE event_id=? AND (status IS NULL OR status='going')`).get(e.id).n;
    if (e.tag !== '교류전') return;
    /* 교류전이면 누가 이겼는지까지 — 목록에서 바로 읽히게 */
    const win = {};
    db.prepare('SELECT home_club, away_club, sa, sb FROM exchange_games WHERE event_id=?')
      .all(e.id).forEach(g => {
        if (g.sa == null || g.sb == null) return;
        const w = g.sa > g.sb ? g.home_club : g.sa < g.sb ? g.away_club : null;
        if (w) win[w] = (win[w] || 0) + 1;
      });
    const sorted = Object.entries(win).sort((a, b) => b[1] - a[1]);
    e.games = Object.values(win).reduce((a, b) => a + b, 0);
    if (sorted.length && !(sorted.length > 1 && sorted[0][1] === sorted[1][1])) {
      const c = db.prepare('SELECT name FROM clubs WHERE id=?').get(+sorted[0][0]);
      e.winner = c ? c.name : null;
    }
    const seats = db.prepare(`SELECT c.name FROM exchange_entries x
      JOIN clubs c ON c.id=x.club_id WHERE x.event_id=?`).all(e.id).map(r => r.name);
    e.clubs = seats;
  });

  /* 구장톡 미리보기 — 들어가 보지 않아도 무슨 얘기가 도는지 보이게 */
  let talk = [], talkLocked = true;
  if (atCourt(req.uid, vid)) {
    talkLocked = false;
    talk = db.prepare(`SELECT p.id,p.title,p.body,p.created_at,p.anon,p.user_id,p.cat,p.views,c.name club
      FROM court_posts p LEFT JOIN clubs c ON c.id=p.club_id
      WHERE p.venue_id=? AND p.scope='court'
      ORDER BY p.created_at DESC LIMIT 2`).all(vid);
    talk.forEach(p => {
      p.comments = db.prepare('SELECT COUNT(*) n FROM court_comments WHERE post_id=?').get(p.id).n;
      p.cat_name = catName('court', p.cat);
      talkWho(p, vid, req.uid);
    });
  }
  /* 이 구장을 고칠 수 있는 사람인가 — 화면에서 <고치기>를 보여줄지 정한다 */
  const canEdit = (v.owner_id && v.owner_id === req.uid) ||
    !!db.prepare(`SELECT 1 FROM venue_clubs vc JOIN club_members m ON m.club_id=vc.club_id
      WHERE vc.venue_id=? AND m.user_id=? AND m.role IN ('owner','officer') LIMIT 1`)
      .get(vid, req.uid);
  res.json({
    venue: v, can_edit: canEdit,
    courts: courts.n || v.courts_n || 0,
    surfaces: courts.surfaces ? String(courts.surfaces).split(',').filter(Boolean)
      : (v.surface ? [v.surface] : []),
    events: evs, talk, talk_locked: talkLocked,
  });
});

/* 잘못 잡힌 성격을 고친다 — 이름만으로는 가릴 수 없는 곳이 많다.
   용인테니스파크처럼 아무 단서가 없는 이름은 기계가 알 길이 없다. */
app.post('/venues/:id/kind', auth, (req, res) => {
  const vid = +req.params.id;
  const k = String((req.body || {}).kind || '');
  if (!['public', 'private', 'school', 'apt'].includes(k))
    return res.status(400).json({ error: 'bad_kind' });
  /* 그 구장에 홈을 건 클럽의 운영진이거나, 구장 주인이거나, 관리자 */
  const v = db.prepare('SELECT owner_id FROM venues WHERE id=?').get(vid);
  if (!v) return res.status(404).json({ error: 'no_venue' });
  const ok = (v.owner_id && v.owner_id === req.uid) ||
    !!db.prepare(`SELECT 1 FROM venue_clubs vc JOIN club_members m ON m.club_id=vc.club_id
      WHERE vc.venue_id=? AND m.user_id=? AND m.role IN ('owner','officer') LIMIT 1`)
      .get(vid, req.uid);
  if (!ok) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('UPDATE venues SET kind=? WHERE id=?').run(k, vid);
  res.json({ ok: true, kind: k });
});

/* 고치기 — 쓴 사람만. 운영진도 남의 글을 고칠 수는 없다(지우는 건 되지만).
   남의 말을 바꿔놓을 수 있으면 익명 게시판이 성립하지 않는다. */
app.patch('/talk/:pid', auth, (req, res) => {
  const pid = +req.params.pid, b = req.body || {};
  const p = db.prepare('SELECT user_id, scope FROM court_posts WHERE id=?').get(pid);
  if (!p) return res.status(404).json({ error: 'no_post', message: '지워졌거나 없는 글이에요' });
  if (p.user_id !== req.uid)
    return res.status(403).json({ error: 'own_only', message: '쓴 사람만 고칠 수 있어요' });
  const title = String(b.title || '').trim().slice(0, 60);
  const body = String(b.body || '').trim().slice(0, 2000);
  const photos = (Array.isArray(b.photos) ? b.photos : [])
    .filter(u => typeof u === 'string' && u.length < 500).slice(0, 10);
  if (!body && !photos.length)
    return res.status(400).json({ error: 'empty', message: '사진이나 글을 넣어주세요' });
  const list = p.scope === 'all' ? CAT_ALL : CAT_COURT;
  const cat = list.some(c => c.k === b.cat) ? b.cat : null;
  const tags = (Array.isArray(b.tags) ? b.tags : [])
    .map(x => String(x || '').replace(/[#\s]/g, '').slice(0, 12)).filter(Boolean).slice(0, 5);
  try {
    db.prepare(`UPDATE court_posts SET title=?, body=?, photos=?, tags=?,
        cat=COALESCE(?, cat), edited_at=? WHERE id=?`)
      .run(title || null, body, JSON.stringify(photos), JSON.stringify(tags), cat, now(), pid);
  } catch (e) {
    /* 칸이 없거나 값이 안 맞으면 여기서 걸린다 — 그냥 500 으로 흘리면 다음에도 못 잡는다 */
    console.error('[talk patch]', e.message);
    return res.status(500).json({ error: 'db', message: '고치지 못했어요 · ' + e.message });
  }
  res.json({ ok: true });
});

/* 지우기 — 쓴 사람과, 그 구장에 홈을 건 클럽의 운영진이 지울 수 있다.
   익명이라 화면에는 누군지 안 보이지만 서버는 알고 있다. */
app.delete('/talk/:pid', auth, (req, res) => {
  const pid = +req.params.pid;
  const p = db.prepare('SELECT user_id, venue_id FROM court_posts WHERE id=?').get(pid);
  if (!p) return res.status(404).json({ error: 'no_post' });
  const officer = !!db.prepare(`SELECT 1 FROM venue_clubs vc JOIN club_members m ON m.club_id=vc.club_id
    WHERE vc.venue_id=? AND m.user_id=? AND m.role IN ('owner','officer') LIMIT 1`)
    .get(p.venue_id, req.uid);
  if (p.user_id !== req.uid && !officer) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('DELETE FROM court_comments WHERE post_id=?').run(pid);
  db.prepare('DELETE FROM court_posts WHERE id=?').run(pid);
  res.json({ ok: true });
});

app.delete('/talk/comments/:cid', auth, (req, res) => {
  const cid = +req.params.cid;
  const c = db.prepare(`SELECT cc.user_id, p.venue_id FROM court_comments cc
    JOIN court_posts p ON p.id=cc.post_id WHERE cc.id=?`).get(cid);
  if (!c) return res.status(404).json({ error: 'no_comment' });
  const officer = !!db.prepare(`SELECT 1 FROM venue_clubs vc JOIN club_members m ON m.club_id=vc.club_id
    WHERE vc.venue_id=? AND m.user_id=? AND m.role IN ('owner','officer') LIMIT 1`)
    .get(c.venue_id, req.uid);
  if (c.user_id !== req.uid && !officer) return res.status(403).json({ error: 'not_allowed' });
  db.prepare('DELETE FROM court_comments WHERE id=?').run(cid);
  res.json({ ok: true });
});

/* 우리 클럽 땅 요약 */
app.get('/clubs/:id/land', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const rows = db.prepare(`SELECT l.*, v.name, v.sigungu, v.lat, v.lng, v.indoor
    FROM land l JOIN venues v ON v.id=l.venue_id WHERE l.club_id=?
    ORDER BY l.depth DESC, l.last_at DESC`).all(cid);
  /* <19칸>은 아무도 못 알아본다. 육각형을 없애면서 칸도 같이 내렸다.
     이제 세는 값은 <깃발 꽂은 코트가 몇 곳인가>다. 이건 설명이 필요 없다.
     지도에는 원으로 그리니 반경(m)만 내려준다. */
  const mySize = shareActiveMembers(cid, Date.now() - SHARE_ACT_DAYS * 864e5);
  rows.forEach(r => {
    r.radius_m = radiusOf(r.venue_id, mySize);
    r.size = mySize;
  });
  const total = rows.length;
  /* 같은 <시> 안에서만 줄을 세운다.
     전국 순위는 큰 클럽이 위를 차지해 작은 클럽이 겨룰 수가 없다 —
     47위라는 걸 알아봐야 할 수 있는 일이 없다.
     코트 3곳 대 2곳이면 다음 교류전 한 번으로 뒤집힌다. */
  const club = db.prepare('SELECT region FROM clubs WHERE id=?').get(cid) || {};
  const parts = String(club.region || '').split(' ').filter(Boolean);
  const city = parts.slice(0, 2).join(' ');        // 「경기도 용인시」
  const label = parts[1] || parts[0] || '';        // 화면에는 「용인시」
  /* 순위도 코트 수로 — 같으면 교류전 승수가 많은 쪽이 앞 */
  let rank = [];
  if (city) {
    const cs = db.prepare(`SELECT c.id, c.name, l.venue_id, l.depth FROM land l
      JOIN clubs c ON c.id=l.club_id WHERE c.region LIKE ?`).all(city + '%');
    const acc = {};
    cs.forEach(r => {
      const a = acc[r.id] || (acc[r.id] = { id: r.id, name: r.name, venues: 0, wins: 0 });
      a.venues++; a.wins += Math.max(0, (r.depth || 1) - 1);
    });
    rank = Object.values(acc).sort((a, b) => b.venues - a.venues || b.wins - a.wins).slice(0, 20);
  }
  const pos = rank.findIndex(r => r.id === cid) + 1;
  /* 전국은 순위가 아니라 <얼마나 다녔나> 로 본다 — 작은 클럽도 겨룰 만하다 */
  const flags = rows.length;
  const allVenues = db.prepare('SELECT COUNT(*) n FROM venues WHERE active=1 AND lat IS NOT NULL').get().n;
  res.json({ total, venues: rows, rank, my_rank: pos || null,
    region: label, city, flags, all_venues: allVenues });
});

/* ── 회원 실력 스냅샷 ────────────────────────────────────────────
   실력 차이는 앱이 계산한다(서버는 경기 기록만 준다).
   그런데 <이번 값>만 보이면 한 번 튄 숫자로 판단하게 된다.
   화면을 열 때 그날 값을 한 벌 남겨 두고, 다음에 <지난달과 견줘> 보여준다. */
try { db.exec(`CREATE TABLE IF NOT EXISTS skill_snaps (
  club_id INTEGER, user_id INTEGER, ymd TEXT, steps INTEGER, games INTEGER, edge INTEGER,
  PRIMARY KEY(club_id, user_id, ymd))`); } catch (e) {}

app.post('/clubs/:id/skill-snap', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const rows = Array.isArray((req.body || {}).rows) ? req.body.rows.slice(0, 200) : [];
  const d = new Date().toISOString().slice(0, 10);
  const ins = db.prepare(`INSERT INTO skill_snaps (club_id,user_id,ymd,steps,games,edge)
    VALUES (?,?,?,?,?,?) ON CONFLICT(club_id,user_id,ymd) DO UPDATE
    SET steps=excluded.steps, games=excluded.games, edge=excluded.edge`);
  try {
    db.transaction(list => list.forEach(r => {
      if (!r || !r.user_id) return;
      ins.run(cid, +r.user_id, d, +r.steps || 0, +r.games || 0, r.edge == null ? null : +r.edge);
    }))(rows);
  } catch (e) { console.error('[skill-snap]', e.message); }
  res.json({ ok: true, saved: rows.length, ymd: d });
});

/* 지난 값 — 3일보다 오래된 것 중 가장 최근 한 벌.
   오늘 것과 견주면 늘 같으므로 조금 떨어진 날을 고른다. */
app.get('/clubs/:id/skill-prev', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const cut = new Date(Date.now() - 3 * 864e5).toISOString().slice(0, 10);
  const day = db.prepare(`SELECT ymd FROM skill_snaps WHERE club_id=? AND ymd<=?
    ORDER BY ymd DESC LIMIT 1`).get(cid, cut);
  if (!day) return res.json({ ymd: null, rows: [] });
  const rows = db.prepare(`SELECT user_id, steps, games, edge FROM skill_snaps
    WHERE club_id=? AND ymd=?`).all(cid, day.ymd);
  res.json({ ymd: day.ymd, rows });
});

/* ── 전역 검색 ────────────────────────────────────────────────────
   문의가 오면 이름 하나만 들고 온다. 그런데 지금은 <어느 탭인지> 부터 정해야 했다.
   한 칸에 넣으면 회원·클럽·매치를 한꺼번에 찾아준다. */
app.get('/admin/search', admin, (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 1) return res.json({ users: [], clubs: [], matches: [] });
  const like = '%' + q + '%';
  const num = /^#?\d+$/.test(q) ? +q.replace('#', '') : null;

  const users = db.prepare(`SELECT id, name, email, gender, last_seen, last_plat, last_region
    FROM users WHERE name LIKE ? OR email LIKE ? ${num ? 'OR id=?' : ''}
    ORDER BY (last_seen IS NULL), last_seen DESC LIMIT 8`)
    .all(...(num ? [like, like, num] : [like, like]));

  const clubs = db.prepare(`SELECT c.id, c.name, c.sido, c.sigungu,
      (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id) members
    FROM clubs c WHERE c.name LIKE ? ${num ? 'OR c.id=?' : ''} LIMIT 6`)
    .all(...(num ? [like, num] : [like]));

  const matches = db.prepare(`SELECT id, dt, loc, status, fmt FROM open_matches
    WHERE loc LIKE ? ${num ? 'OR id=?' : ''} ORDER BY dt DESC LIMIT 6`)
    .all(...(num ? [like, num] : [like]));

  res.json({ users, clubs, matches });
});

/* ── 메뉴에 붙는 숫자 ──────────────────────────────────────────────
   화면을 열어야만 보이는 정보는 급할 때 소용이 없다.
   메뉴에 숫자를 붙여 <어디를 눌러야 하는지> 를 먼저 알린다. */
app.get('/admin/badges', admin, (_req, res) => {
  const out = {};
  try {
    /* 통신 실패는 신호가 약한 곳에서 나는 것이라 코드 문제가 아니다 —
       배지에 섞으면 <급한 일>이 아닌 것으로 알림이 울린다. */
    const r = db.prepare(`SELECT sig, COUNT(DISTINCT COALESCE(user_id,-1)) people
      FROM client_errors WHERE at > ? AND kind NOT IN ('net','timeout')
      GROUP BY sig`).all(Date.now() - 3 * 864e5);
    const many = r.filter(x => x.people >= 3).length;
    if (many) out.errors = many;
  } catch (e) {}
  try {
    const n = db.prepare("SELECT COUNT(*) n FROM reports WHERE status='open'").get().n;
    if (n) out.reports = n;
  } catch (e) {}
  res.json(out);
});

/* ── 회원 한 명 들여다보기 ────────────────────────────────────────
   문의가 오면 세 가지를 묻게 된다 — 언제 뭘 했나, 등급이 왜 움직였나,
   그리고 뭔가 깨졌던 건 아닌가. 지금은 그 셋이 서로 다른 화면에 흩어져 있어
   답 한 번 하려고 세 곳을 돌아다녀야 한다. 한 자리에 모은다. */
app.get('/admin/users/:id/detail', admin, (req, res) => {
  const uid = +req.params.id;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(uid);
  if (!u) return res.status(404).json({ error: 'not_found' });

  const clubs = db.prepare(`SELECT m.club_id, m.grade, m.role, c.name
    FROM club_members m LEFT JOIN clubs c ON c.id=m.club_id WHERE m.user_id=?`).all(uid);

  /* 등급이 어떻게 움직였나 — 문의의 절반은 여기서 답이 난다 */
  const grades = db.prepare(`SELECT g.*, c.name AS club FROM grade_changes g
    LEFT JOIN clubs c ON c.id=g.club_id WHERE g.user_id=?
    ORDER BY g.created_at DESC LIMIT 12`).all(uid);

  /* 최근 대진 — 이름이 아니라 아이디로 찾는다. 동명이인이 있어도 어긋나지 않는다 */
  const games = [];
  const logs = db.prepare(`SELECT l.club_id, l.date, l.data, c.name AS club
    FROM club_bracket_logs l LEFT JOIN clubs c ON c.id=l.club_id
    WHERE l.club_id IN (SELECT club_id FROM club_members WHERE user_id=?)
    ORDER BY l.date DESC LIMIT 20`).all(uid);
  for (const L of logs) {
    let d; try { d = JSON.parse(L.data); } catch (e) { continue; }
    let w = 0, n = 0, mates = new Set(), foes = new Set();
    (d.games || []).forEach(g => {
      const A = (g.teamA || []).filter(Boolean), B = (g.teamB || []).filter(Boolean);
      const inA = A.some(p => +p.id === uid), inB = B.some(p => +p.id === uid);
      if (!inA && !inB) return;
      n++;
      const mine = inA ? A : B, them = inA ? B : A;
      mine.forEach(p => { if (+p.id !== uid) mates.add(p.name); });
      them.forEach(p => foes.add(p.name));
      if (g.sa != null && g.sb != null) {
        const diff = inA ? g.sa - g.sb : g.sb - g.sa;
        if (diff > 0) w++;
      }
    });
    if (n) games.push({ date: L.date, club: L.club, n, w,
      mates: mates.size, foes: foes.size });
    if (games.length >= 8) break;
  }

  /* 이 사람이 겪은 오류 — <나만 이래요> 라는 문의에 바로 답할 수 있다 */
  const errors = db.prepare(`SELECT kind, msg, path, build, at FROM client_errors
    WHERE user_id=? ORDER BY at DESC LIMIT 10`).all(uid);

  res.json({
    id: uid, region: u.last_region || null, region_at: u.last_region_at || null,
    clubs, grades, games, errors,
    totals: { games: games.reduce((a, g) => a + g.n, 0),
              wins: games.reduce((a, g) => a + g.w, 0) }
  });
});

/* ── 앱 오류 모으기 ────────────────────────────────────────────────
   지금까지는 회원이 알려줘야 알았다. 어제 <클럽 가입했는데 안 한 것처럼 보임>도
   제보로 알았고, 그 사이 며칠을 그냥 흘려보냈다.
   앱이 실패를 겪으면 한 줄 보내게 하고 여기서 묶어 본다.

   묶어서 보는 것이 핵심이다. 한 명이면 그 사람 환경 문제고,
   여러 명이면 코드 문제다 — 이 구분이 가장 값지다. */
try { db.exec(`CREATE TABLE IF NOT EXISTS client_errors (
  id INTEGER PRIMARY KEY, user_id INTEGER, sig TEXT, kind TEXT, msg TEXT,
  path TEXT, build TEXT, plat TEXT, at INTEGER)`); } catch (e) {}
try { db.exec('CREATE INDEX IF NOT EXISTS ix_cerr_at ON client_errors(at)'); } catch (e) {}

const CERR_RATE = new Map();          // uid|ip -> {m, n}
app.post('/client-error', (req, res) => {  // @external 앱이 오류 때 부름(fetch 직접)
  /* 인증을 요구하지 않는다 — 로그인 자체가 깨졌을 때가 제일 알고 싶은 순간이다.
     대신 한 사람이 쏟아붓지 못하게 분당 상한을 둔다. */
  try {
    const uid = tryUid(req);
    const who = String(uid || clientIp(req) || '?');
    const m = Math.floor(Date.now() / 60000);
    const r = CERR_RATE.get(who);
    if (r && r.m === m) { if (r.n >= 20) return res.json({ ok: true, dropped: true }); r.n++; }
    else CERR_RATE.set(who, { m, n: 1 });

    const b = req.body || {};
    const cut = (v, n) => String(v == null ? '' : v).slice(0, n);
    const kind = cut(b.kind, 24) || 'api';
    const msg = cut(b.msg, 300);
    const path = cut(b.path, 160);
    if (!msg && !path) return res.json({ ok: true });
    /* 같은 오류인지 묶는 열쇠. 숫자(아이디·시각)는 빼야 같은 것끼리 모인다. */
    const sig = (kind + ' ' + path.replace(/\d+/g, '#') + ' ' + msg.replace(/\d+/g, '#')).slice(0, 200);
    db.prepare(`INSERT INTO client_errors (user_id,sig,kind,msg,path,build,plat,at)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(uid || null, sig, kind, msg, path, cut(b.build, 32), cut(b.plat, 12), now());
  } catch (e) {}
  res.json({ ok: true });
});

app.get('/admin/errors', admin, (req, res) => {
  const days = Math.min(30, Math.max(1, +req.query.days || 3));
  const since = Date.now() - days * 864e5;
  const groups = db.prepare(`SELECT sig, kind,
      COUNT(*) n, COUNT(DISTINCT COALESCE(user_id,-1)) people,
      MAX(at) last, MIN(at) first,
      MAX(msg) msg, MAX(path) path, MAX(build) build
    FROM client_errors WHERE at > ?
    GROUP BY sig ORDER BY people DESC, n DESC LIMIT 60`).all(since);
  const total = groups.reduce((a, g) => a + g.n, 0);
  /* 어느 빌드에서 나는지 — 옛 앱만의 문제인지 새 앱도인지 가른다 */
  const builds = db.prepare(`SELECT COALESCE(NULLIF(build,''),'모름') b, COUNT(*) n
    FROM client_errors WHERE at > ? GROUP BY b ORDER BY n DESC LIMIT 8`).all(since);
  res.json({ days, total, groups, builds });
});
app.delete('/admin/errors', admin, (req, res) => {
  const d = Math.max(0, +req.query.olderThanDays || 0);
  db.prepare('DELETE FROM client_errors WHERE at < ?').run(Date.now() - d * 864e5);
  res.json({ ok: true });
});

/* ── 공지 보내기 ──────────────────────────────────────────────────
   업데이트·점검을 알릴 곳이 없었다. push-test 는 나 한 명에게만 갔다.
   대상을 골라 보내고, 보내기 전에 몇 명인지 먼저 보여준다 —
   전체 발송은 되돌릴 수 없으므로 숫자를 보고 손이 멈출 수 있어야 한다. */
function noticeTargets(to, clubId) {
  if (to === 'club' && clubId)
    return db.prepare(`SELECT user_id id FROM club_members WHERE club_id=?`).all(+clubId).map(r => r.id);
  if (to === 'dormant')
    return db.prepare(`SELECT id FROM users WHERE last_seen IS NOT NULL AND last_seen < ?`)
      .all(Date.now() - 30 * 864e5).map(r => r.id);
  if (to === 'ghost')
    return db.prepare(`SELECT id FROM users WHERE last_seen IS NULL`).all().map(r => r.id);
  if (to === 'active')
    return db.prepare(`SELECT id FROM users WHERE last_seen > ?`)
      .all(Date.now() - 30 * 864e5).map(r => r.id);
  return db.prepare('SELECT id FROM users').all().map(r => r.id);
}
app.get('/admin/notify/count', admin, (req, res) => {
  const n = noticeTargets(String(req.query.to || 'all'), req.query.club).length;
  res.json({ n });
});
app.post('/admin/notify', admin, async (req, res) => {
  const b = req.body || {};
  const title = String(b.title || '').trim().slice(0, 60);
  const body = String(b.body || '').trim().slice(0, 200);
  if (!title) return res.status(400).json({ error: 'title_required' });
  const ids = noticeTargets(String(b.to || 'all'), b.club);
  if (!ids.length) return res.json({ sent: 0 });
  alog(req, '공지 보냄', 'notify', null, { to: b.to || 'all', n: ids.length, title }, null);
  res.json({ sent: ids.length });          // 먼저 답하고 뒤에서 보낸다 — 수백 명이면 오래 걸린다
  for (const id of ids) {
    try { await sendPush(id, { icon: b.icon || '📢', title, body, link: b.link || null }); }
    catch (e) {}
  }
  console.log(`[notify] ${ids.length}명 · ${title}`);
});

/* ── 서버 상태 ── Railway 는 디스크가 차면 조용히 죽는다 */
app.get('/admin/health', admin, (_req, res) => {
  const out = { uptime: Math.floor(process.uptime()), node: process.version,
    build: SRV_BUILD, web_build: WEB_BUILD, mem: Math.round(process.memoryUsage().rss / 1048576) };
  try {
    const p = db.prepare('PRAGMA page_count').get(), s = db.prepare('PRAGMA page_size').get();
    out.dbMB = Math.round((p.page_count * s.page_size) / 1048576 * 10) / 10;
  } catch (e) {}
  try {
    let n = 0, sz = 0;
    for (const f of fs.readdirSync(UPLOAD_DIR)) {
      try { sz += fs.statSync(path.join(UPLOAD_DIR, f)).size; n++; } catch (e) {}
    }
    out.uploads = n; out.uploadsMB = Math.round(sz / 1048576 * 10) / 10;
  } catch (e) {}
  try { out.errors24h = db.prepare('SELECT COUNT(*) n FROM client_errors WHERE at > ?')
    .get(Date.now() - 864e5).n; } catch (e) {}
  /* 오류 알림이 켜져 있는지 — 안 켜져 있으면 조용히 아무 일도 안 하므로
     화면에서 그 사실을 보여줘야 한다. */
  out.alertTo = (process.env.ADMIN_UIDS || '').split(',').map(x => x.trim()).filter(Boolean).length;
  /* 알림이 어느 플랫폼까지 나가나 — 안드로이드를 붙였는데 FCM 을 안 넣으면 조용히 안 간다 */
  out.apns = apnsReady();
  out.fcm  = fcmReady();
  try { const d = db.prepare(`SELECT platform, COUNT(*) n FROM devices GROUP BY platform`).all();
    out.devices = d; } catch (e) {}
  res.json(out);
});

/* ── 대진 품질 감시 ────────────────────────────────────────────────
   대진 로직을 크게 바꾸면 시뮬레이션 숫자와 실전이 다를 수 있다.
   실제로 발행된 대진을 다시 읽어 팀 격차·중복·성비를 세어 준다.
   여기 숫자가 시뮬레이션(3칸 0.45%)보다 크게 높으면 계수를 다시 봐야 한다. */
const GRADE_LADDER_S = ['C1','C2','C3','B1','B2','B3','A1','A2','A3','S1','S2','S3','SS1','SS2','SS3'];
function ladderLv(code) {
  const i = GRADE_LADDER_S.indexOf(String(code || '').toUpperCase());
  return i >= 0 ? 1 + i / 3 : 2;                       // 모르면 한가운데(B2 언저리)
}
app.get('/admin/bracket-quality', admin, (req, res) => {
  const days = Math.min(120, Math.max(7, +req.query.days || 30));
  const since = new Date(Date.now() - days * 864e5).toISOString().slice(0, 10);
  const logs = db.prepare(`SELECT l.club_id, l.date, l.data, c.name AS club
    FROM club_bracket_logs l LEFT JOIN clubs c ON c.id = l.club_id
    WHERE l.date >= ? ORDER BY l.date DESC LIMIT 300`).all(since);

  /* 등급·성별은 회원 명부에서 가져온다 — 대진 로그에는 이름만 들어 있다 */
  const lvOf = {}, sexOf = {};
  db.prepare(`SELECT m.club_id, m.user_id, m.grade, u.gender FROM club_members m
    LEFT JOIN users u ON u.id = m.user_id`).all().forEach(r => {
      lvOf[r.club_id + ':' + r.user_id] = ladderLv(r.grade);
      sexOf[r.club_id + ':' + r.user_id] = String(r.gender || '');
    });
  const isF = v => v === 'F' || String(v).startsWith('여');

  const out = [];
  const roll = { n: 0, g0: 0, g1: 0, g2: 0, g3: 0, g4: 0, dupP: 0, maxO: 0, locked: 0, courts: 0 };
  logs.forEach(L => {
    let d; try { d = JSON.parse(L.data); } catch (e) { return; }
    const games = (d && d.games) || []; if (!games.length) return;
    const key = (a, b) => String(a) < String(b) ? a + '|' + b : b + '|' + a;
    const lv = p => lvOf[L.club_id + ':' + p.id] != null ? lvOf[L.club_id + ':' + p.id] : 2;
    const pair = {}, meet = {}, byCourt = {};
    const H = [0, 0, 0, 0, 0];                          // 0~4칸
    games.forEach(g => {
      const A = (g.teamA || []).filter(Boolean), B = (g.teamB || []).filter(Boolean);
      if (A.length < 2 || B.length < 2) return;
      const gap = Math.abs((lv(A[0]) + lv(A[1])) / 2 - (lv(B[0]) + lv(B[1])) / 2);
      H[Math.min(4, Math.round(gap / (1 / 3)))]++;
      [A, B].forEach(t => { const k = key(t[0].id, t[1].id); pair[k] = (pair[k] || 0) + 1; });
      A.forEach(a => B.forEach(b => { const k = key(a.id, b.id); meet[k] = (meet[k] || 0) + 1; }));
      const c = g.c || 1; (byCourt[c] = byCourt[c] || new Set());
      [...A, ...B].forEach(p => byCourt[c].add(p.id));
    });
    const n = H.reduce((a, b) => a + b, 0); if (!n) return;
    const dupP = Object.values(pair).reduce((a, v) => a + Math.max(0, v - 1), 0);
    const maxO = Math.max(0, ...Object.values(meet));
    /* 성비 잠긴 코트 — 어느 성별이든 1~2명이면 그 사람들은 하루 종일 서로의 상대다 */
    let locked = 0, courts = 0;
    Object.entries(byCourt).forEach(([c, set]) => {
      courts++;
      let f = 0; set.forEach(id => { if (isF(sexOf[L.club_id + ':' + id])) f++; });
      const m = set.size - f;
      if ((f >= 1 && f <= 2) || (m >= 1 && m <= 2)) locked++;
    });
    out.push({ club: L.club || ('#' + L.club_id), club_id: L.club_id, date: L.date,
      games: n, gap3: H[3] + H[4], gap4: H[4], hist: H, dupP, maxO, locked, courts });
    roll.n += n; roll.g0 += H[0]; roll.g1 += H[1]; roll.g2 += H[2]; roll.g3 += H[3]; roll.g4 += H[4];
    roll.dupP += dupP; roll.maxO = Math.max(roll.maxO, maxO);
    roll.locked += locked; roll.courts += courts;
  });
  res.json({ days, brackets: out.length, roll, list: out.slice(0, 60) });
});

/* ── 등급 이동 감시 ────────────────────────────────────────────────
   기대 대비 실적으로 바꾸면 회원 등급이 한 번 크게 흔들린다.
   누가 몇 칸 움직였는지 여기서 바로 본다 — 문의가 오면 이 화면으로 답한다. */
app.get('/admin/grade-moves', admin, (req, res) => {
  const days = Math.min(180, Math.max(7, +req.query.days || 30));
  const rows = db.prepare(`SELECT g.*, c.name AS club FROM grade_changes g
    LEFT JOIN clubs c ON c.id = g.club_id
    WHERE g.created_at > ? ORDER BY g.created_at DESC LIMIT 400`)
    .all(Date.now() - days * 864e5);
  const step = r => {
    const a = GRADE_LADDER_S.indexOf(String(r.from_grade || '').toUpperCase());
    const b = GRADE_LADDER_S.indexOf(String(r.to_grade || '').toUpperCase());
    return (a < 0 || b < 0) ? null : b - a;             // 사다리 칸 수
  };
  const list = rows.map(r => ({ ...r, step: step(r) }));
  const up = list.filter(x => x.dir === 'up').length;
  const dn = list.filter(x => x.dir === 'down').length;
  const big = list.filter(x => x.step != null && Math.abs(x.step) >= 3);
  res.json({ days, total: list.length, up, down: dn, big: big.length, list: list.slice(0, 120) });
});

/* ── 접속 지역 ────────────────────────────────────────────────────
   어디에 사람이 모여 있는지 봐야 다음 클럽을 어디에 붙일지 정할 수 있다. */
app.get('/admin/regions', admin, (_req, res) => {
  const rows = db.prepare(`SELECT last_region AS region, COUNT(*) n,
      SUM(CASE WHEN last_seen > ? THEN 1 ELSE 0 END) active
    FROM users WHERE last_region IS NOT NULL AND last_region <> ''
    GROUP BY last_region ORDER BY n DESC LIMIT 40`).all(Date.now() - 30 * 864e5);
  const known = rows.reduce((a, r) => a + r.n, 0);
  const total = db.prepare('SELECT COUNT(*) n FROM users').get().n;
  res.json({ total, known, unknown: total - known, list: rows });
});

app.get('/admin/stats', admin, (_req, res) => {
  const one = (sql) => db.prepare(sql).get().n;
  res.json({
    users: one('SELECT COUNT(*) n FROM users WHERE COALESCE(is_test,0)=0'),
    testUsers: one('SELECT COUNT(*) n FROM users WHERE is_test=1'),
    clubs: one('SELECT COUNT(*) n FROM clubs'),
    posts: one('SELECT COUNT(*) n FROM posts WHERE hidden=0'),
    hidden: one('SELECT COUNT(*) n FROM posts WHERE hidden=1'),
    openReports: one("SELECT COUNT(*) n FROM reports WHERE status='open'"),
    matches: one('SELECT COUNT(*) n FROM matches'),
    paidOrders: one("SELECT COUNT(*) n FROM orders WHERE status='paid'"),
    revenueWon: db.prepare("SELECT COALESCE(SUM(amount),0) n FROM orders WHERE status='paid'").get().n,
    cashIssued: db.prepare("SELECT COALESCE(SUM(cash),0) n FROM orders WHERE status='paid'").get().n,

    /* ── 살아 있는 앱인지 보는 값들 ──
       총계만 보면 늘고 있는지 줄고 있는지 알 수 없다.
       가입자 수보다 <이번 주에 들어온 사람>이 더 중요하다. */
    dau: one(`SELECT COUNT(*) n FROM users WHERE last_seen > ${Date.now() - 864e5}`),
    wau: one(`SELECT COUNT(*) n FROM users WHERE last_seen > ${Date.now() - 7 * 864e5}`),
    mau: one(`SELECT COUNT(*) n FROM users WHERE last_seen > ${Date.now() - 30 * 864e5}`),
    /* 한 번도 안 들어온 사람 — 가입만 하고 이탈했다 */
    ghost: one(`SELECT COUNT(*) n FROM users WHERE last_seen IS NULL
                  AND created_at < ${Date.now() - 864e5}`),
    /* 30일 넘게 안 들어온 사람 */
    dormant: one(`SELECT COUNT(*) n FROM users
                    WHERE last_seen IS NOT NULL AND last_seen < ${Date.now() - 30 * 864e5}`),
    newWeek: one(`SELECT COUNT(*) n FROM users WHERE created_at > ${Date.now() - 7 * 864e5}`),
    newMonth: one(`SELECT COUNT(*) n FROM users WHERE created_at > ${Date.now() - 30 * 864e5}`),

    /* 클럽이 실제로 돌아가는가 — 만들어만 놓고 안 쓰는 클럽이 얼마나 되나 */
    clubsAlive: one(`SELECT COUNT(DISTINCT club_id) n FROM club_events
                       WHERE created_at > ${Date.now() - 30 * 864e5}`),
    bracketsMonth: one(`SELECT COUNT(*) n FROM club_bracket_logs
                          WHERE updated_at > ${Date.now() - 30 * 864e5}`),
    exchanges: one("SELECT COUNT(*) n FROM club_events WHERE kind='exchange'"),

    /* 어느 기기로 쓰나 — 아이폰 앱과 웹 중 어디가 주인가 */
    byPlat: db.prepare(`SELECT COALESCE(last_plat,'?') p, COUNT(*) n FROM users
      WHERE last_seen IS NOT NULL GROUP BY p ORDER BY n DESC`).all(),
    iosUsers: one(`SELECT COUNT(*) n FROM users WHERE last_plat='ios'`),

    /* 가입 경로 — 어디서 들어오는지 */
    byProvider: db.prepare(`SELECT COALESCE(provider,'?') p, COUNT(*) n
      FROM users GROUP BY provider ORDER BY n DESC`).all(),
    /* 최근 2주 일별 가입 — 늘고 있는지 한눈에 */
    signups: db.prepare(`SELECT COUNT(*) n,
        (created_at / 86400000) d FROM users
      WHERE created_at > ${Date.now() - 14 * 864e5} GROUP BY d ORDER BY d`).all(),
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
app.get('/admin/users', admin, (req, res) => {
  /* gender 를 빼먹고 있었다 — 관리자 화면이 <성별 없음>으로만 보였다.
     이름 검색(?q=)도 화면은 보내는데 서버가 무시하고 있었다.

     그리고 성별이 사는 곳이 둘이다.
       users.gender            — 본인이 프로필에서 정한 값
       club_members.gender_ov  — 운영진이 <운영진 도구 · 성별 설정>에서 고쳐 둔 값
     대진은 두 값을 합쳐 보는데(COALESCE) 관리자 화면은 users.gender 만 봐서,
     운영진이 다 채워둔 클럽도 여기서는 전부 <성별 없음>으로 보였다.
     그래서 <실제로 쓰이는 성별(gender)>과 <어디서 온 값인지(gender_src)>를 함께 내려준다. */
  const q = String((req.query && req.query.q) || '').trim();
  const OV = `(SELECT NULLIF(m.gender_ov,'') FROM club_members m
      WHERE m.user_id=u.id AND NULLIF(m.gender_ov,'') IS NOT NULL
        AND (m.status IS NULL OR m.status='active') LIMIT 1)`;
  /* suspended 를 함께 내려준다 — 탈퇴한 계정만 영구 삭제 버튼을 보여주기 위해서.
     이게 없으면 화면에서 <탈퇴한 회원>과 활성 회원을 구분할 방법이 없다. */
  const cols = `u.id, u.name, u.provider, u.region, u.sport, u.rating, u.cash, u.premium, u.created_at,
    u.last_seen, u.last_plat, u.last_region,
    COALESCE(u.rating_doubles,1000) AS rating_doubles,
    (SELECT COUNT(*) FROM matches WHERE status='confirmed'
      AND (home_user_id=u.id OR away_user_id=u.id)) AS tier_games,
    COALESCE(u.suspended,0) AS suspended,
    COALESCE(NULLIF(u.gender,''), ${OV}) AS gender,
    NULLIF(u.gender,'') AS gender_self,
    ${OV} AS gender_club,
    CASE WHEN NULLIF(u.gender,'') IS NOT NULL THEN 'self'
         WHEN ${OV} IS NOT NULL THEN 'club' ELSE '' END AS gender_src`;
  /* 테스트로 만든 가짜 회원은 감춘다 — 진짜 회원 사이에 섞이면 목록을 못 믿는다.
     ?test=1 로 부르면 그것만 본다(정리할 때 쓴다). */
  const only = String((req.query && req.query.test) || '');
  const where = only === '1' ? 'COALESCE(u.is_test,0)=1' : 'COALESCE(u.is_test,0)=0';
  const rows = q
    ? db.prepare(`SELECT ${cols} FROM users u WHERE ${where} AND u.name LIKE ?
        ORDER BY u.id DESC LIMIT 200`).all('%' + q + '%')
    : db.prepare(`SELECT ${cols} FROM users u WHERE ${where} ORDER BY u.id DESC LIMIT 200`).all();
  res.json(rows);
});

/* 관리자 화면에서 성별 고치기 — 엔드포인트가 아예 없어서 눌러도 저장되지 않았다.
   여기서는 users.gender(본인 값)에 쓴다. 클럽별 조정(gender_ov)은 그대로 둔다. */
app.post('/admin/users/:id/gender', admin, (req, res) => {
  const id = +req.params.id;
  const raw = String((req.body && req.body.gender) || '').trim();
  const g = /^(F|여)/i.test(raw) ? 'F' : /^(M|남)/i.test(raw) ? 'M' : null;
  const u = db.prepare('SELECT id, name, gender FROM users WHERE id=?').get(id);
  if (!u) return res.status(404).json({ error: 'no_user' });
  db.prepare('UPDATE users SET gender=? WHERE id=?').run(g, id);
  /* 바꾸기 전 값을 되돌릴 거리로 함께 적는다 — 나중에 추측하지 않아도 되게 */
  alog(req, '성별 바꿈', 'user', id,
    { name: u.name, from: u.gender || null, to: g },
    { kind: 'gender', id, value: u.gender || null });
  res.json({ ok: true, gender: g });
});

/* 클럽에서 정한 성별을 본인 값으로 한 번에 옮긴다 —
   운영진이 이미 채워둔 것을 관리자가 다시 47번 누르게 할 이유가 없다. */
app.post('/admin/users/fill-gender', admin, (_req, res) => {
  const rows = db.prepare(`SELECT u.id,
      (SELECT NULLIF(m.gender_ov,'') FROM club_members m
        WHERE m.user_id=u.id AND NULLIF(m.gender_ov,'') IS NOT NULL
          AND (m.status IS NULL OR m.status='active') LIMIT 1) ov
    FROM users u WHERE NULLIF(u.gender,'') IS NULL`).all();
  const st = db.prepare('UPDATE users SET gender=? WHERE id=?');
  let n = 0;
  const before = [];
  rows.forEach(r => { if (r.ov === 'M' || r.ov === 'F') { before.push(r.id); st.run(r.ov, r.id); n++; } });
  /* 한 번에 여럿을 바꾼 것은 되돌리기를 걸지 않는다 —
     되돌릴 값이 사람마다 달라, 한 줄로 담으면 반드시 어긋난다. 기록만 남긴다. */
  if (n) alog(req, '성별 일괄 채움', 'user', null, { count: n }, null);
  res.json({ ok: true, filled: n });
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
  const nm = (db.prepare('SELECT name FROM users WHERE id=?').get(+req.params.id) || {}).name;
  alog(req, v ? '계정 정지' : '정지 해제', 'user', +req.params.id, { name: nm }, null);
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

/* ── 열린 슬롯에서 오픈매치를 바로 연다 ──
   구장 사장님이 시간대를 열어두면(venue_slots.status='open')
   그 자리를 골라 매치를 만든다. 코트비·시간·코트 수가 슬롯에 이미 있으므로
   종목과 티어 범위만 더 받으면 된다. */
app.post('/venue-slots/:id/open-match', auth, (req, res) => {
  const s = db.prepare('SELECT * FROM venue_slots WHERE id=?').get(+req.params.id);
  if (!s) return res.status(404).json({ error: 'not_found' });
  if (s.status !== 'open') return res.status(400).json({ error: 'taken', message: '이미 나간 자리예요' });
  const v = db.prepare('SELECT * FROM venues WHERE id=?').get(s.venue_id) || {};
  const b = req.body || {};

  let courtN = 1;
  try { const a = JSON.parse(s.court_ids); if (Array.isArray(a) && a.length) courtN = a.length; } catch (e) {}
  const mode = (b.mode === 'managed' || courtN > 1) ? 'managed' : 'self';
  const disc = ['mixed', 'men', 'women'].includes(b.disc) ? b.disc : 'mixed';
  const TK = ['love', 'fut', 'chal', 'tour', 'gs'];
  const tmin = TK.includes(b.tier_min) ? b.tier_min : null;
  const tmax = TK.includes(b.tier_max) ? b.tier_max : null;
  const capN = Math.max(4, Math.min(18, intOrNull(b.cap) || (mode === 'managed' ? courtN * 5 : 4)));
  let cm = null, cf = null;
  if (disc === 'men')   { cm = capN; cf = 0; }
  else if (disc === 'women') { cm = 0; cf = capN; }
  else { cm = Math.ceil(capN / 2); cf = capN - cm; }

  const startAt = `${s.date}T${s.start}`, endAt = `${s.date}T${s.end}`;
  const stMs = Date.parse(startAt + ':00+09:00');
  const closeAt = isNaN(stMs) ? null
    : new Date(stMs - 24 * 3600e3 + 9 * 3600e3).toISOString().slice(0, 16);
  const hours = (!isNaN(stMs) && !isNaN(Date.parse(endAt + ':00+09:00')))
    ? (Date.parse(endAt + ':00+09:00') - stMs) / 36e5 : 2;
  const mgrFee = mode === 'managed' ? omManagerFee(courtN, hours >= 3 ? 3 : 2) : 0;

  let mid;
  try {
    tx(() => {
      const c = db.prepare("UPDATE venue_slots SET status='held', held_by=?, held_at=? WHERE id=? AND status='open'")
        .run(req.uid, now(), s.id).changes;
      if (!c) throw new Error('taken');
      const r = db.prepare(`INSERT INTO open_matches
        (sport,dt,loc,fmt,gd,price,cap,min_cnt,created_at,host_id,status,note,
         start_at,end_at,sido,sigungu,courts,court_cost,mode,disc,cap_m,cap_f,
         tier_min,tier_max,close_at,fee_rate,manager_fee)
        VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run('tennis', `${s.date} ${s.start}`, v.name || '구장', '복식',
             disc === 'women' ? '여자부' : disc === 'men' ? '남자부' : '혼성',
             0, capN, mode === 'managed' ? capN : 4, now(), req.uid,
             String(b.note || '').slice(0, 300),
             startAt, endAt, v.sido || null, v.sigungu || null,
             courtN, s.price || 0, mode, disc, cm, cf, tmin, tmax, closeAt,
             (b.fee_rate != null ? +b.fee_rate : 0.2), mgrFee);
      mid = rid(r);
      db.prepare("UPDATE venue_slots SET match_id=? WHERE id=?").run(mid, s.id);
      if (mode === 'managed') db.prepare('UPDATE open_matches SET manager_id=? WHERE id=?').run(req.uid, mid);
      const fresh = db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid);
      const p = omPriceFor(fresh, omMinCount(fresh));
      db.prepare('UPDATE open_matches SET base_price=?, price=? WHERE id=?').run(p, p, mid);
    });
  } catch (e) {
    if (e.message === 'taken') return res.status(409).json({ error: 'taken', message: '방금 다른 사람이 가져갔어요' });
    throw e;
  }
  if (v.owner_id) sendPush(v.owner_id, { icon: '🎾', title: '코트에 매치가 열렸어요',
    body: `${s.date} ${s.start}–${s.end} · 모집이 확정되면 알려드릴게요` });
  res.json(omView(db.prepare('SELECT * FROM open_matches WHERE id=?').get(mid), req.uid));
});

/* 매치를 열 수 있는 <비어 있는> 슬롯만 — 기존 /admin/venue-slots 와는 쓰임이 다르다.
   그쪽은 예약·정산까지 포함한 전체 목록이라 경로를 나눠 쓴다.
   (같은 경로로 두 번 등록하면 먼저 선언된 쪽이 가로채 기존 화면이 비어 보인다) */
app.get('/admin/open-slots', admin, (req, res) => {
  const from = String((req.query && req.query.from) || new Date().toISOString().slice(0, 10));
  const rows = db.prepare(`SELECT s.*, v.name venue_name, v.sido, v.sigungu
    FROM venue_slots s JOIN venues v ON v.id=s.venue_id
    WHERE s.status='open' AND s.date >= ? ORDER BY s.date, s.start LIMIT 100`).all(from);
  res.json(rows.map(r => {
    let n = 1; try { const a = JSON.parse(r.court_ids); if (Array.isArray(a) && a.length) n = a.length; } catch (e) {}
    return { ...r, courts: n };
  }));
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
  /* 사장님이 직접 낸 곳 — source 기본값이 'public' 이라 공립으로 잡히고 있었다.
     주인이 있는 코트는 사설이다. 이름이 <○○시민테니스장> 이어도 위탁 운영이면 사설이다. */
  const r = db.prepare(`INSERT INTO venues (name,owner_id,sido,sigungu,addr,phone,memo,photos,bank,source,kind,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,'owner',?,?)`)
    .run(name, ownerId, b.sido || '', b.sigungu || '', b.addr || '', b.phone || '', b.memo || '',
         JSON.stringify(Array.isArray(b.photos) ? b.photos.slice(0, 8) : []), b.bank || '',
         'private', now());
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

/* 정적 서빙·에러 핸들러·listen 은 <모든 라우트가 등록된 뒤>여야 한다.
   예전에는 이 줄들이 파일 중간에 있어서, 아래쪽에 정의된 32개 라우트가
   에러 핸들러의 보호를 못 받았다. 그 라우트에서 500 이 나면 Express 기본
   HTML 페이지가 나가서, 관리자 오류 목록에 <!DOCTYPE html> 덩어리만 찍혔다.
   실제 파일 맨 끝(bootServer 호출)으로 옮겼다. */

/* ── 교류전 모임 보기 ──
   교류전은 주최 클럽 소속 모임이라 상대 클럽 회원에게는 목록에 뜨지 않는다.
   양쪽이 같은 자리에서 인사를 주고받을 수 있어야 하므로,
   <그 교류전에 참가한 클럽의 회원>이면 모임과 댓글을 볼 수 있게 연다. */
function xcCanSee(eid, uid) {
  const ent = xcEntries(eid);
  if (!ent.length) return false;
  return ent.some(e => !!cbRole(e.club_id, uid));
}
app.get('/exchange/:id/event', auth, (req, res) => {
  const eid = +req.params.id;
  if (!xcCanSee(eid, req.uid))
    return res.status(403).json({ error: 'not_in_match', message: '이 교류전에 참가한 클럽만 볼 수 있어요' });
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const my = db.prepare('SELECT status FROM event_attendees WHERE event_id=? AND user_id=?').get(eid, req.uid);
  const byStatus = st => db.prepare(`SELECT COALESCE(NULLIF(cm.alias,''), u.name) name, u.photos, cm.club_id
      FROM event_attendees ea JOIN users u ON u.id=ea.user_id
      LEFT JOIN club_members cm ON cm.user_id=u.id AND cm.club_id IN (
        SELECT club_id FROM exchange_entries WHERE event_id=? AND status='joined')
      WHERE ea.event_id=? AND ${st === 'going' ? "(ea.status IS NULL OR ea.status='going')" : 'ea.status=?'}
      GROUP BY u.id ORDER BY name`).all(...(st === 'going' ? [eid, eid] : [eid, eid, st]));
  res.json({
    id: ev.id, title: ev.title, date: ev.date, place: ev.place, tag: ev.tag,
    attendees: byStatus('going'),
    my_status: my ? (my.status || 'going') : null,
    clubs: xcEntries(eid).map(e => ({ club_id: e.club_id, name: e.club_name })),
  });
});
/* 댓글도 같은 잣대로 — 참가 클럽 회원이면 읽고 쓸 수 있다 */
app.get('/exchange/:id/comments', auth, (req, res) => {
  const eid = +req.params.id;
  if (!xcCanSee(eid, req.uid)) return res.status(403).json({ error: 'not_in_match' });
  const rows = db.prepare(`SELECT c.id, c.body, c.created_at, c.user_id, c.parent_id, u.name, u.photos
    FROM event_comments c JOIN users u ON u.id=c.user_id
    WHERE c.event_id=? ORDER BY c.id ASC LIMIT 200`).all(eid);
  /* 어느 클럽 사람인지 함께 — 뱃지 색을 나누기 위해서다 */
  const ent = xcEntries(eid);
  const of = uid => { const e = ent.find(x => cbRole(x.club_id, uid)); return e ? e.club_id : 0; };
  res.json(rows.map(r => ({ ...r, club_id: of(r.user_id) })));
});
app.post('/exchange/:id/comments', auth, limitWrite, (req, res) => {
  const eid = +req.params.id;
  if (!xcCanSee(eid, req.uid))
    return res.status(403).json({ error: 'not_in_match', message: '이 교류전에 참가한 클럽만 쓸 수 있어요' });
  const ev = xcEvent(eid);
  /* 경기가 끝난 교류전은 읽기만 — 진 쪽이 생기는 자리라 뒤끝이 남지 않게 닫는다 */
  if (ev && ev.match_status === 'done')
    return res.status(400).json({ error: 'closed', message: '끝난 교류전에는 댓글을 쓸 수 없어요' });
  const body = String((req.body || {}).body || '').trim().slice(0, 300);
  if (!body) return res.status(400).json({ error: 'empty' });
  const r = db.prepare('INSERT INTO event_comments (event_id,user_id,body,created_at,parent_id) VALUES (?,?,?,?,?)')
    .run(eid, req.uid, body, now(), (req.body || {}).parent_id ? +req.body.parent_id : null);
  res.json({ ok: true, id: rid(r) });
});
/* 참석 체크도 상대 클럽 회원이 할 수 있어야 한다 */
app.post('/exchange/:id/rsvp', auth, (req, res) => {
  const eid = +req.params.id;
  if (!xcCanSee(eid, req.uid))
    return res.status(403).json({ error: 'not_in_match', message: '이 교류전에 참가한 클럽만 할 수 있어요' });
  const st = String((req.body || {}).status || 'going');
  const ok = ['going', 'absent', 'undecided'].includes(st) ? st : 'going';
  const had = db.prepare('SELECT id FROM event_attendees WHERE event_id=? AND user_id=?').get(eid, req.uid);
  if (had) db.prepare('UPDATE event_attendees SET status=? WHERE id=?').run(ok, had.id);
  else db.prepare('INSERT INTO event_attendees (event_id,user_id,status) VALUES (?,?,?)').run(eid, req.uid, ok);
  res.json({ ok: true, status: ok });
});

/* ── 사용 기록 ──
   어느 화면을 보고 어디서 멈추는지 알아야 고칠 곳이 보인다.
   외부 도구를 붙이면 회원 정보가 밖으로 나가므로 직접 쌓는다.
   이름과 몇 개의 값만 남기고, 개인을 특정할 내용은 담지 않는다. */
try {
  db.exec(`CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, props TEXT,
    platform TEXT, at INTEGER)`);
  db.exec('CREATE INDEX IF NOT EXISTS ix_ev_at ON events(at)');
  db.exec('CREATE INDEX IF NOT EXISTS ix_ev_name ON events(name, at)');
} catch (e) {}
/* 예전 버전이 platform 없이 만든 표가 남아 있으면 INSERT 준비 단계에서 터진다.
   CREATE TABLE IF NOT EXISTS 는 컬럼을 더해주지 않으므로 따로 붙인다.
   이미 있으면 예외가 나고 그냥 넘어간다. */
try { db.exec('ALTER TABLE events ADD COLUMN platform TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE events ADD COLUMN props TEXT'); } catch (e) {}

/* 앱은 모아서 한 번에 보낸다 — 화면을 옮길 때마다 요청하면 배터리를 먹는다 */
app.post('/track', auth, (req, res) => {
  /* 사용 기록은 <있으면 좋은> 것이지 <꼭 되어야 하는> 것이 아니다.
     예전에는 db.prepare 가 try 밖에 있어, 표가 조금만 어긋나도 500 이 났다.
     기록 하나 못 남긴 것 때문에 앱이 오류를 겪을 이유가 없다 — 통째로 감싼다. */
  try {
    const list = Array.isArray((req.body || {}).events) ? req.body.events.slice(0, 40) : [];
    const plat = String(req.headers['x-client-platform'] || 'web').slice(0, 12);
    const ins = db.prepare('INSERT INTO events (user_id,name,props,platform,at) VALUES (?,?,?,?,?)');
    const t = db.transaction(rows => rows.forEach(r => {
      const nm = String(r.n || '').slice(0, 40);
      if (!nm) return;
      let p = null;
      try { p = r.p ? JSON.stringify(r.p).slice(0, 400) : null; } catch (e) {}
      ins.run(req.uid, nm, p, plat, +r.t || now());
    }));
    t(list);
  } catch (e) { console.error('[track]', e.message); }
  res.json({ ok: true });
});

/* 관리자 — 무엇을 보고 무엇을 하는가 */
app.get('/admin/track', admin, (req, res) => {
  const days = Math.min(90, Math.max(1, +(req.query.days || 7)));
  const from = Date.now() - days * 864e5;
  const one = sql => db.prepare(sql).get(from);
  res.json({
    days,
    total: one('SELECT COUNT(*) n FROM events WHERE at > ?').n,
    users: one('SELECT COUNT(DISTINCT user_id) n FROM events WHERE at > ?').n,
    /* 화면별 조회 — 어디에 사람이 몰리나 */
    screens: db.prepare(`SELECT name, COUNT(*) n, COUNT(DISTINCT user_id) u
      FROM events WHERE at > ? AND name LIKE 'view:%'
      GROUP BY name ORDER BY n DESC LIMIT 20`).all(from),
    /* 행동별 — 무엇을 실제로 하나 */
    actions: db.prepare(`SELECT name, COUNT(*) n, COUNT(DISTINCT user_id) u
      FROM events WHERE at > ? AND name NOT LIKE 'view:%'
      GROUP BY name ORDER BY n DESC LIMIT 25`).all(from),
    /* 일별 추이 */
    daily: db.prepare(`SELECT (at/86400000) d, COUNT(*) n, COUNT(DISTINCT user_id) u
      FROM events WHERE at > ? GROUP BY d ORDER BY d`).all(from),
    /* 기기 */
    platforms: db.prepare(`SELECT COALESCE(platform,'?') p, COUNT(DISTINCT user_id) n
      FROM events WHERE at > ? GROUP BY p ORDER BY n DESC`).all(from),
  });
});
/* 깔때기 — 어디서 떨어지나. 단계 이름을 순서대로 받아 각 단계 인원을 센다 */
app.get('/admin/funnel', admin, (req, res) => {
  const steps = String(req.query.steps || '').split(',').map(x => x.trim()).filter(Boolean).slice(0, 8);
  const days = Math.min(90, Math.max(1, +(req.query.days || 30)));
  const from = Date.now() - days * 864e5;
  if (!steps.length) return res.json({ steps: [] });
  const out = [];
  let prev = null;
  steps.forEach(nm => {
    /* 앞 단계를 거친 사람 중에서만 센다 — 그래야 <떨어진 비율>이 뜻을 갖는다 */
    const rows = prev
      ? db.prepare(`SELECT DISTINCT user_id FROM events
          WHERE at > ? AND name=? AND user_id IN (${prev.map(() => '?').join(',') || '0'})`)
          .all(from, nm, ...prev)
      : db.prepare('SELECT DISTINCT user_id FROM events WHERE at > ? AND name=?').all(from, nm);
    const ids = rows.map(r => r.user_id);
    out.push({ name: nm, n: ids.length });
    prev = ids.length ? ids : ['0'];
  });
  res.json({ days, steps: out });
});

/* ── 교류전 테스트 도구 (관리자) ──
   24명을 실제로 모아야 대진을 볼 수 있는데, 그건 무리다.
   가짜 회원을 만들지 않고 <그 클럽의 실제 회원>을 골라 참석 처리한다 —
   데이터가 지저분해지지 않고, 대진도 진짜 등급·성별로 짜인다. */
app.post('/admin/exchange/:id/fill', admin, (req, res) => {
  const eid = +req.params.id;
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const ent = xcEntries(eid);
  if (!ent.length) return res.status(400).json({ error: 'no_club', message: '참가 클럽이 없어요' });

  const per = ev.per_club || 12;
  const mix = xcMix(ev.squad_mix || '');
  const out = [];
  ent.forEach(e => {
    /* 성비를 맞춰 뽑는다 — 아무나 채우면 혼복 조가 안 만들어진다 */
    const pick = (g, n) => db.prepare(`SELECT u.id FROM club_members cm
        JOIN users u ON u.id=cm.user_id
        WHERE cm.club_id=? AND cm.role IN ('member','officer','owner')
          AND (cm.status IS NULL OR cm.status='active')
          AND COALESCE(NULLIF(cm.gender_ov,''), u.gender) = ?
          AND COALESCE(u.is_test,0) = 0
        ORDER BY u.id LIMIT ?`).all(e.club_id, g, n).map(r => r.id);
    let men = pick('M', mix.men), women = pick('F', mix.women);
    /* 클럽에 사람이 모자라면 테스트 회원을 만들어 채운다.
       회원이 셋뿐인 클럽으로도 12명 대진을 돌려봐야 하기 때문이다.
       is_test 로 표시해 두고 회원 목록에서는 감춘다. */
    const MEN = ['김도윤','최우진','강태현','윤성호','백지훈','임현우','조성민','장우현',
                 '신동엽','정민재','이준혁','박도윤'];
    const WOMEN = ['박서연','한소민','서지우','이하늘','정혜정','문예린','오세라','김수빈',
                   '윤가은','최지아','임소영','배유진'];
    const mkTest = (g, want, used) => {
      const out = [];
      const pool = g === 'M' ? MEN : WOMEN;
      /* 클럽마다 다른 사람이어야 한다 — 같은 이름을 두 클럽에 넣으면
         양쪽 명단에 같은 사람이 나오고 대진도 자기 자신과 붙는다.
         클럽 번호를 이름 뒤에 붙여 갈라 둔다. */
      for (let i = 0; out.length < want && i < pool.length * 3; i++) {
        const base = pool[i % pool.length];
        const dup = Math.floor(i / pool.length);
        const nm = `${base}${dup ? dup + 1 : ''}`;
        const key = `${nm}#${e.club_id}`;
        let u = db.prepare('SELECT id FROM users WHERE test_key=?').get(key);
        if (!u) {
          /* 등급 계산에 쓰이는 값을 채워 둔다 — 대진이 실력을 보고 짝을 맞춘다.
             구력을 흩어 놓아야 A·B·C 가 섞인 실제 대진처럼 나온다. */
          const yrs = [1, 2, 3, 4, 5, 6, 8, 10][out.length % 8];
          /* sport_started 는 {"tennis":"2019-05"} 꼴이다 — 이 값으로 C·B·A·S 가 정해진다 */
          const d = new Date(now() - yrs * 365 * 864e5);
          const started = JSON.stringify({ tennis:
            `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}` });
          const rd = 1000 + (yrs - 4) * 45;
          const r = db.prepare(`INSERT INTO users (name,gender,provider,rating,rating_doubles,
              created_at,is_test,sport,sport_started,test_key)
            VALUES (?,?,'test',?,?,?,1,'tennis',?,?)`)
            .run(nm, g, rd, rd, now(), started, key);
          u = { id: rid(r) };
        }
        if (used.has(u.id)) continue;
        /* 그 클럽 회원으로 넣어 둔다 — 대진이 등급을 읽어야 한다 */
        const has = db.prepare('SELECT id FROM club_members WHERE club_id=? AND user_id=?')
          .get(e.club_id, u.id);
        if (!has) db.prepare(`INSERT INTO club_members (club_id,user_id,role,status,joined_at,gender_ov)
          VALUES (?,?,'member','active',?,?)`).run(e.club_id, u.id, now(), g);
        out.push(u.id); used.add(u.id);
      }
      return out;
    };
    const used = new Set([...men, ...women]);
    if (men.length < mix.men) men = men.concat(mkTest('M', mix.men - men.length, used));
    if (women.length < mix.women) women = women.concat(mkTest('F', mix.women - women.length, used));
    let ids = [...men, ...women];
    ids.forEach(uid => {
      const had = db.prepare('SELECT id FROM event_attendees WHERE event_id=? AND user_id=?').get(eid, uid);
      if (had) db.prepare("UPDATE event_attendees SET status='going' WHERE id=?").run(had.id);
      else db.prepare("INSERT INTO event_attendees (event_id,user_id,status) VALUES (?,?,'going')").run(eid, uid);
    });
    const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(e.club_id) || {};
    out.push({ club: club.name || e.club_id, filled: ids.length, need: per });
  });
  res.json({ ok: true, clubs: out });
});
/* 테스트 회원을 모두 지운다 — 교류전 테스트가 끝나면 흔적을 남기지 않는다.
   예전에는 users·club_members·event_attendees 세 곳만 지워서,
   이미 만들어진 대진·점수·기록에는 이름이 그대로 남았다. 딸린 것을 함께 지운다. */
app.post('/admin/test-users/purge', admin, (_req, res) => {
  const rows = db.prepare('SELECT id, name FROM users WHERE is_test=1').all();
  const ids = rows.map(r => r.id);
  if (!ids.length) return res.json({ ok: true, n: 0 });
  const ph = ids.map(() => '?').join(',');
  [`DELETE FROM event_attendees WHERE user_id IN (${ph})`,
   `DELETE FROM club_members WHERE user_id IN (${ph})`,
   `DELETE FROM monthly_results WHERE user_id IN (${ph})`,
   `DELETE FROM grade_changes WHERE user_id IN (${ph})`,
   `DELETE FROM interests WHERE user_id IN (${ph})`,
   `DELETE FROM users WHERE id IN (${ph})`].forEach(sql => {
    try { db.prepare(sql).run(...ids); } catch (e) {}
  });
  /* 테스트 회원이 낀 교류전 대진은 통째로 지운다 — 반쪽 대진은 아무 쓸모가 없다 */
  let games = 0;
  try {
    const set = new Set(ids.map(String));
    db.prepare('SELECT id, home_json, away_json FROM exchange_games').all().forEach(g => {
      const has = [g.home_json, g.away_json].some(j => {
        try { return (JSON.parse(j || '[]') || []).some(p => set.has(String(p.id))); }
        catch (e) { return false; }
      });
      if (has) { db.prepare('DELETE FROM exchange_games WHERE id=?').run(g.id); games++; }
    });
  } catch (e) {}
  res.json({ ok: true, n: ids.length, games, names: rows.map(r => r.name).slice(0, 40) });
});
/* 지우기 전에 <누가 지워지는지> 먼저 본다 */
app.get('/admin/test-users', admin, (_req, res) => {
  const rows = db.prepare(`SELECT u.id, u.name, u.gender,
      (SELECT GROUP_CONCAT(c.name, ', ') FROM club_members m JOIN clubs c ON c.id=m.club_id
       WHERE m.user_id=u.id) clubs
    FROM users u WHERE u.is_test=1 ORDER BY u.id`).all();
  res.json({ n: rows.length, rows });
});

/* 상대 클럽을 붙인다 — 테스트할 때 다른 클럽 계정으로 로그인해 신청하기가 번거롭다.
   실제 클럽 중 하나를 골라 참가시킨다. */
app.post('/admin/exchange/:id/opponent', admin, (req, res) => {
  const eid = +req.params.id;
  const cid = +((req.body || {}).club_id || 0);
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const ent = xcEntries(eid);
  if (ent.some(e => e.club_id === cid))
    return res.status(400).json({ error: 'already', message: '이미 참가한 클럽이에요' });
  if (ent.length >= (ev.club_slots || 2))
    return res.status(400).json({ error: 'full', message: '자리가 다 찼어요' });
  const club = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid);
  if (!club) return res.status(404).json({ error: 'no_club' });
  const seat = ent.length + 1;
  db.prepare(`INSERT INTO exchange_entries (event_id,club_id,seat_no,status,joined_at)
    VALUES (?,?,?,'joined',?)`).run(eid, cid, seat, now());
  res.json({ ok: true, club: club.name });
});
/* 고를 수 있는 클럽 — 이미 참가한 클럽은 뺀다 */
app.get('/admin/exchange/:id/clubs', admin, (req, res) => {
  const eid = +req.params.id;
  const inIt = xcEntries(eid).map(e => e.club_id);
  const rows = db.prepare(`SELECT c.id, c.name, c.region,
      (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id
        AND m.role IN ('member','officer','owner')) members
    FROM clubs c ORDER BY members DESC LIMIT 30`).all();
  res.json(rows.filter(c => !inIt.includes(c.id)));
});

/* 참석을 전부 지운다 — 다시 테스트하려면 비워야 한다 */
app.post('/admin/exchange/:id/clear', admin, (req, res) => {
  const eid = +req.params.id;
  db.prepare('DELETE FROM event_attendees WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM exchange_games WHERE event_id=?').run(eid);
  db.prepare("UPDATE club_events SET match_status='open' WHERE id=?").run(eid);
  res.json({ ok: true });
});
/* 점수를 무작위로 채운다 — 승점 계산과 순위표를 보려면 결과가 있어야 한다 */
app.post('/admin/exchange/:id/scores', admin, (req, res) => {
  const eid = +req.params.id;
  const gs = db.prepare('SELECT id FROM exchange_games WHERE event_id=?').all(eid);
  if (!gs.length) return res.status(400).json({ error: 'no_games', message: '대진을 먼저 만들어 주세요' });
  gs.forEach(g => {
    /* 6점제 — 6:0 부터 5:6 까지, 접전이 조금 더 자주 나오게 */
    const a = 6, b = [0, 1, 2, 3, 4, 4, 5, 5, 6][Math.floor(Math.random() * 9)];
    const flip = Math.random() < 0.5;
    db.prepare('UPDATE exchange_games SET sa=?, sb=? WHERE id=?')
      .run(flip ? b : a, flip ? a : b, g.id);
  });
  res.json({ ok: true, n: gs.length });
});
/* 관리자용 교류전 목록 */
app.get('/admin/exchange', admin, (_req, res) => {
  const rows = db.prepare(`SELECT e.id, e.title, e.date, e.per_club, e.courts, e.squad_mix,
      e.match_status FROM club_events e WHERE e.kind='exchange' ORDER BY e.id DESC LIMIT 40`).all();
  res.json(rows.map(ev => ({
    ...ev,
    clubs: xcEntries(ev.id).map(e => ({
      id: e.club_id, name: e.club_name,
      count: xcRoster(ev.id, e.club_id).length,
    })),
    games: db.prepare('SELECT COUNT(*) n FROM exchange_games WHERE event_id=?').get(ev.id).n,
    scored: db.prepare('SELECT COUNT(*) n FROM exchange_games WHERE event_id=? AND sa IS NOT NULL')
      .get(ev.id).n,
  })));
});

/* ── 삭제 · 취소 · 하차 ──
   상대가 없으면 흔적 없이 지운다. 상대가 있으면 지우면 안 된다 —
   그쪽은 이미 회원들에게 알리고 인원을 모으고 있다. 취소로 남기고 알린다. */
app.delete('/exchange/:id', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const ent = xcEntries(eid);
  const host = ent.find(e => e.seat_no === 1);
  if (!host || !isOfficer(host.club_id, req.uid))
    return res.status(403).json({ error: 'host_only', message: '연 클럽의 임원만 할 수 있어요' });

  const others = ent.filter(e => e.club_id !== host.club_id);
  if (!others.length) {
    /* 아무도 안 들어왔다 — 그냥 지운다 */
    db.prepare('DELETE FROM exchange_games WHERE event_id=?').run(eid);
    db.prepare('DELETE FROM exchange_entries WHERE event_id=?').run(eid);
    db.prepare('DELETE FROM club_events WHERE id=?').run(eid);
    return res.json({ ok: true, deleted: true });
  }
  /* 상대가 있다 — 양쪽에 알리고 모임을 지운다.
     상태만 바꾸면 클럽 일정에 계속 남는다. 열리지 않은 모임을 달력에 두면
     회원들이 그날 코트가 잡혀 있는 줄 안다. */
  const why = String((req.body || {}).reason || '').trim().slice(0, 60);
  ent.forEach(e => notifyClub(e.club_id, null, '🆚', '교류전이 취소됐어요',
    `${ev.title}${ev.date ? ' · ' + ev.date : ''}${why ? ' · ' + why : ''}`));
  db.prepare('DELETE FROM exchange_games WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM exchange_entries WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM event_attendees WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM event_comments WHERE event_id=?').run(eid);
  db.prepare('DELETE FROM club_events WHERE id=?').run(eid);
  res.json({ ok: true, cancelled: true });
});

/* 참가 클럽이 스스로 빠진다 — 마감까지 기다리는 것보다 미리 알리는 편이 낫다.
   주최 클럽이 다른 상대를 찾을 시간이 생긴다. */
app.post('/exchange/:id/leave', auth, (req, res) => {
  const eid = +req.params.id;
  const cid = +((req.body || {}).club_id || 0);
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  if (!isOfficer(cid, req.uid))
    return res.status(403).json({ error: 'officer_only', message: '임원만 할 수 있어요' });
  const ent = xcEntries(eid);
  const me = ent.find(e => e.club_id === cid);
  if (!me) return res.status(404).json({ error: 'not_joined' });
  if (me.seat_no === 1)
    return res.status(400).json({ error: 'host', message: '연 클럽은 하차 대신 취소를 해주세요' });

  db.prepare("UPDATE exchange_entries SET status='dropped' WHERE id=?").run(me.id);
  db.prepare("UPDATE club_events SET match_status='open' WHERE id=?").run(eid);
  db.prepare('DELETE FROM exchange_games WHERE event_id=?').run(eid);   // 대진이 있었다면 무효
  const host = ent.find(e => e.seat_no === 1);
  const name = (db.prepare('SELECT name FROM clubs WHERE id=?').get(cid) || {}).name || '';
  if (host) notifyClub(host.club_id, null, '🆚', '상대 클럽이 빠졌어요',
    `${name} 클럽이 하차했어요 · 자리가 다시 열렸어요`);
  notifyClub(cid, req.uid, '🆚', '교류전에서 빠졌어요', `${ev.title}`);
  res.json({ ok: true });
});

/* ── 대진표 ── 확정되면 누구나 본다. 감출 이유가 없다 */
/* 대진에 등급을 붙인다 — 처음 만나는 상대라 실력을 짐작할 수 없다.
   클럽 대진과 같은 잣대(구력)를 쓴다. */
function withGrade(players) {
  return (players || []).map(p => {
    if (!p || !p.id) return p;
    let g = null;
    try {
      const m = careerMonths(p.id, 'tennis');
      if (m != null) g = m < 24 ? 'C' : m < 60 ? 'B' : m < 120 ? 'A' : 'S';
    } catch (e) {}
    return { ...p, grade: p.grade || g };
  });
}
/* 팀 평균 — 글자 하나로는 두 사람의 무게가 안 보인다. C=1 · B=2 · A=3 · S=4 로 세어 평균을 낸다 */
function teamGrade(players) {
  const V = { C: 1, B: 2, A: 3, S: 4 };
  const xs = (players || []).map(p => V[(p.grade || '').toUpperCase()]).filter(Boolean);
  if (!xs.length) return null;
  const avg = xs.reduce((a, b) => a + b, 0) / xs.length;
  return ['C', 'B', 'A', 'S'][Math.max(0, Math.min(3, Math.round(avg) - 1))];
}

app.get('/exchange/:id/games', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const rows = db.prepare('SELECT * FROM exchange_games WHERE event_id=? ORDER BY round, court').all(eid);
  res.json({
    event: xcView(ev, req.uid),
    games: rows.map(g => ({
      id: g.id, round: g.round, court: g.court, kind: g.kind,
      home: { club_id: g.home_club, seat: g.home_seat,
        players: withGrade(JSON.parse(g.home_json || '[]')) },
      away: { club_id: g.away_club, seat: g.away_seat,
        players: withGrade(JSON.parse(g.away_json || '[]')) },
      sa: g.sa, sb: g.sb, by: g.scored_by, at: g.scored_at,
    })),
    result: xcResult(eid),
    started_at: ev.started_at || null,
    started_by: ev.started_by || null,
    started_name: ev.started_by
      ? (db.prepare('SELECT name FROM users WHERE id=?').get(ev.started_by) || {}).name || null
      : null,
  });
});

/* 시작 — 시간 대진처럼 아무나 누르면 모두의 화면에서 시계가 돈다.
   누가 눌렀는지 남겨 둔다. 코트에서 <시작했어요?> 를 묻지 않게. */
app.post('/exchange/:id/start', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  if (!xcCanSee(eid, req.uid))
    return res.status(403).json({ error: 'not_in_match', message: '이 교류전에 참가한 클럽만 할 수 있어요' });
  if (ev.started_at) return res.json({ ok: true, started_at: ev.started_at, already: true });
  const t = now();
  db.prepare('UPDATE club_events SET started_at=?, started_by=? WHERE id=?').run(t, req.uid, eid);
  const who = (db.prepare('SELECT name FROM users WHERE id=?').get(req.uid) || {}).name || '누군가';
  xcEntries(eid).forEach(e => notifyClub(e.club_id, null, '⏱', '교류전이 시작됐어요',
    `${who} 님이 시작을 눌렀어요 · 1회차부터 시계가 돌아요`));
  res.json({ ok: true, started_at: t, by: req.uid, name: who });
});

/* ── 점수 ── 한 코트에 한 명만 넣으면 된다. 나중에 고칠 수 있다 */
app.post('/exchange/:id/score', auth, (req, res) => {
  const eid = +req.params.id;
  const { game_id, sa, sb } = req.body || {};
  const g = db.prepare('SELECT * FROM exchange_games WHERE id=? AND event_id=?').get(+game_id, eid);
  if (!g) return res.status(404).json({ error: 'not_found' });
  if (!isMember(g.home_club, req.uid) && !isMember(g.away_club, req.uid))
    return res.status(403).json({ error: 'not_in_match', message: '참가한 클럽만 넣을 수 있어요' });
  db.prepare('UPDATE exchange_games SET sa=?, sb=?, scored_by=?, scored_at=? WHERE id=?')
    .run(sa == null ? null : +sa, sb == null ? null : +sb, req.uid, now(), g.id);
  /* 모든 경기 점수가 들어왔으면 땅을 갱신한다 — 중간에 하면 앞선 쪽이 계속 바뀐다 */
  try {
    const left = db.prepare('SELECT COUNT(*) n FROM exchange_games WHERE event_id=? AND (sa IS NULL OR sb IS NULL)')
      .get(eid).n;
    if (!left) landAfterExchange(eid);
  } catch (e) {}
  res.json({ ok: true, result: xcResult(eid) });
});

/* ── 승점 ── 1승 3점 · 무승부 1점. 합산이 큰 쪽이 이긴다.
   개인 등급에는 반영하지 않는다 — 친선이고, 클럽 기록으로만 남는다. */
function xcResult(eid) {
  const ev = xcEvent(eid);
  const ent = xcEntries(eid);
  if (!ev || ent.length < 2) return null;
  const A = ent[0].club_id, B = ent[1].club_id;
  const rows = db.prepare('SELECT * FROM exchange_games WHERE event_id=?').all(eid);
  const t = { [A]: { w: 0, d: 0, l: 0, pt: 0, gf: 0, ga: 0 }, [B]: { w: 0, d: 0, l: 0, pt: 0, gf: 0, ga: 0 } };
  let played = 0;
  rows.forEach(g => {
    if (g.sa == null || g.sb == null) return;
    played++;
    t[g.home_club].gf += g.sa; t[g.home_club].ga += g.sb;
    t[g.away_club].gf += g.sb; t[g.away_club].ga += g.sa;
    if (g.sa > g.sb) { t[g.home_club].w++; t[g.home_club].pt += 3; t[g.away_club].l++; }
    else if (g.sa < g.sb) { t[g.away_club].w++; t[g.away_club].pt += 3; t[g.home_club].l++; }
    else { t[A].d++; t[B].d++; t[A].pt += 1; t[B].pt += 1; }
  });
  const name = id => (db.prepare('SELECT name FROM clubs WHERE id=?').get(id) || {}).name || '';
  const side = id => ({ club_id: id, name: name(id), ...t[id] });
  const a = side(A), b = side(B);
  const done = played >= rows.length && rows.length > 0;
  return {
    played, total: rows.length, done,
    home: a, away: b,
    winner: !done ? null : a.pt > b.pt ? A : b.pt > a.pt ? B
      : (a.gf - a.ga) > (b.gf - b.ga) ? A : (b.gf - b.ga) > (a.gf - a.ga) ? B : null,
  };
}

/* ── 클럽 기록 ── 상대 클럽별 통산 */
app.get('/clubs/:id/exchange/record', auth, (req, res) => {
  const cid = +req.params.id;
  const evs = db.prepare(`SELECT e.id FROM club_events e
     JOIN exchange_entries x ON x.event_id=e.id AND x.club_id=? AND x.status<>'dropped'
     WHERE e.kind='exchange' AND e.match_status IN ('confirmed','done')`).all(cid);
  const vs = {};
  let w = 0, d = 0, l = 0;
  evs.forEach(({ id }) => {
    const r = xcResult(id);
    if (!r || !r.done) return;
    const me = r.home.club_id === cid ? r.home : r.away;
    const op = r.home.club_id === cid ? r.away : r.home;
    const k = op.club_id;
    vs[k] = vs[k] || { club_id: k, name: op.name, w: 0, d: 0, l: 0 };
    if (r.winner === cid) { w++; vs[k].w++; }
    else if (r.winner == null) { d++; vs[k].d++; }
    else { l++; vs[k].l++; }
  });
  res.json({ total: { w, d, l }, vs: Object.values(vs) });
});

/* ── 마감 처리 ── 인원을 못 채운 클럽은 하차, 자리가 안 차면 취소.
   하루 한 번 도는 것으로 충분하다 — 마감은 밤 12시다. */
function xcSweep() {
  const t = now();
  db.prepare(`SELECT * FROM club_events WHERE kind='exchange'
      AND match_status IN ('open','filled') AND close_at IS NOT NULL AND close_at < ?`).all(t)
    .forEach(ev => {
      const ent = xcEntries(ev.id);
      const short = ent.filter(e => xcRoster(ev.id, e.club_id).length < (ev.per_club || 0));
      short.forEach(e => {
        db.prepare("UPDATE exchange_entries SET status='dropped' WHERE id=?").run(e.id);
        notifyClub(e.club_id, null, '🆚', '교류전에서 빠졌어요',
          `${ev.title} · 마감까지 인원을 채우지 못했어요`);
      });
      const left = xcEntries(ev.id);
      if (left.length < (ev.club_slots || 2)) {
        /* 상태만 바꾸면 모임이 클럽 일정에 계속 남는다 —
           일정 탭은 club_events 를 그대로 읽기 때문이다.
           성사되지 않은 교류전은 흔적을 남길 이유가 없으므로 통째로 지운다. */
        left.forEach(e => notifyClub(e.club_id, null, '🆚', '교류전이 취소됐어요',
          `${ev.title} · 인원이 차지 않았어요 · 코트 취소는 직접 해주셔야 해요`));
        db.prepare('DELETE FROM exchange_games WHERE event_id=?').run(ev.id);
        db.prepare('DELETE FROM exchange_entries WHERE event_id=?').run(ev.id);
        db.prepare('DELETE FROM event_attendees WHERE event_id=?').run(ev.id);
        db.prepare('DELETE FROM event_comments WHERE event_id=?').run(ev.id);
        db.prepare('DELETE FROM club_events WHERE id=?').run(ev.id);
      }
    });
}
/* test_key 가 없는 예전 테스트 계정은 클럽이 갈리지 않아 양쪽에 같은 이름이 나온다 — 치운다 */
try {
  const old = db.prepare('SELECT id FROM users WHERE is_test=1 AND test_key IS NULL').all().map(r => r.id);
  if (old.length) {
    const ph = old.map(() => '?').join(',');
    [`DELETE FROM event_attendees WHERE user_id IN (${ph})`,
     `DELETE FROM club_members WHERE user_id IN (${ph})`,
     `DELETE FROM users WHERE id IN (${ph})`].forEach(sql => {
      try { db.prepare(sql).run(...old); } catch (e) {}
    });
    console.log('예전 테스트 계정 정리:', old.length, '명');
  }
} catch (e) {}
/* 예전에 상태만 바꿔둔 교류전이 일정에 남아 있다 — 한 번 치운다 */
try {
  const stale = db.prepare(`SELECT id, title FROM club_events
    WHERE kind='exchange' AND match_status='cancelled'`).all();
  stale.forEach(ev => {
    db.prepare('DELETE FROM exchange_games WHERE event_id=?').run(ev.id);
    db.prepare('DELETE FROM exchange_entries WHERE event_id=?').run(ev.id);
    db.prepare('DELETE FROM event_attendees WHERE event_id=?').run(ev.id);
    db.prepare('DELETE FROM event_comments WHERE event_id=?').run(ev.id);
    db.prepare('DELETE FROM club_events WHERE id=?').run(ev.id);
  });
  if (stale.length) console.log('취소된 교류전 정리:', stale.length, '건');
} catch (e) {}
setInterval(() => { try { xcSweep(); } catch (e) { console.error('xcSweep', e); } }, 30 * 60 * 1000);
/* 서버가 뜰 때 한 번 — 30분을 기다리면 그 사이 일정에 남아 있다 */
setTimeout(() => { try { xcSweep(); } catch (e) {} }, 5000);

// ── 오픈매치 대기 명단 ─────────────────────────────────────────
// 구장 계약 전이라 매치가 하나도 없다. om_likes 는 매치별 관심이라 쓸 수 없어
// 서비스 오픈을 기다리는 사람을 따로 모은다.
db.exec(`CREATE TABLE IF NOT EXISTS om_waitlist (
  user_id INTEGER PRIMARY KEY,
  region TEXT, sport TEXT, created_at BIGINT
);`);

const OM_GOAL = 50;   // 이만큼 모이면 첫 코트를 연다 (앱의 OM_GOAL 과 같은 값)

function omWaitPayload(uid) {
  const count = db.prepare('SELECT COUNT(*) c FROM om_waitlist').get().c;
  const mine  = !!db.prepare('SELECT 1 FROM om_waitlist WHERE user_id=?').get(uid);
  // 얼굴 몇 개 — 사진이 없으면 앱이 색 원으로 그린다
  /* 열 이름은 photos 다 — photo 로 물으면 SQL 이 통째로 실패해 500 이 난다 */
  const faces = db.prepare(`SELECT u.photos FROM om_waitlist w JOIN users u ON u.id=w.user_id
                            ORDER BY w.created_at DESC LIMIT 4`).all()
    .map(r => ({ photo: r.photos || null }));
  /* 이번 주에 새로 신청한 사람 — <멈춰 있지 않다>는 신호다 */
  const t0 = new Date(); t0.setHours(0, 0, 0, 0);
  const mon = new Date(t0); mon.setDate(t0.getDate() - ((t0.getDay() + 6) % 7));
  const week = db.prepare('SELECT COUNT(*) c FROM om_waitlist WHERE created_at>=?')
    .get(mon.getTime()).c;
  /* 구장 협의 현황 — 운영진이 admin 에서 적어 두는 값이다.
     없으면 앱이 <구장과 이야기하고 있어요>로만 말하고 숫자는 감춘다. */
  let venues = 0, first_regions = '';
  try {
    const v = db.prepare("SELECT value FROM app_config WHERE key='om_venues'").get();
    const f = db.prepare("SELECT value FROM app_config WHERE key='om_first_regions'").get();
    venues = v ? (+v.value || 0) : 0;
    first_regions = f ? String(f.value || '') : '';
  } catch (e) {}
  return { count, mine, goal: OM_GOAL, faces, week, venues, first_regions };
}
/* 운영진이 직접 적는 값 몇 개 — 지어낸 숫자를 화면에 띄우지 않기 위해서다 */
db.exec(`CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT);`);
app.get('/admin/config', admin, (_req, res) => {
  const rows = db.prepare('SELECT key, value FROM app_config').all();
  const out = {}; rows.forEach(r => { out[r.key] = r.value; });
  res.json(out);
});
app.post('/admin/config', admin, (req, res) => {
  const b = req.body || {};
  Object.keys(b).forEach(k => {
    db.prepare('INSERT INTO app_config (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
      .run(String(k), String(b[k] == null ? '' : b[k]));
  });
  res.json({ ok: true });
});

app.get('/om/waitlist', auth, (req, res) => res.json(omWaitPayload(req.uid)));

app.post('/om/waitlist', auth, (req, res) => {
  const { region, sport } = req.body || {};
  db.prepare(`INSERT INTO om_waitlist (user_id,region,sport,created_at) VALUES (?,?,?,?)
              ON CONFLICT(user_id) DO UPDATE SET region=excluded.region, sport=excluded.sport`)
    .run(req.uid, String(region || '전국'), String(sport || 'tennis'), now());
  res.json(omWaitPayload(req.uid));
});

/* 알림 끄기 — 화면 곁말은 <언제든 끌 수 있어요>라고 말하는데 끄는 길이 없었다.
   켤 수만 있고 못 끄는 알림은 다음에 켜기를 망설이게 만든다.
   자기 자신만 지운다. 다시 켜면 POST 가 그대로 새로 넣는다. */
app.delete('/om/waitlist', auth, (req, res) => {
  db.prepare('DELETE FROM om_waitlist WHERE user_id=?').run(req.uid);
  res.json(omWaitPayload(req.uid));
});

// ══════════════════════════════════════════════════════════════
//  교류전 — 두 클럽이 한 날 한 구장에서 붙는다
//  모임(club_events)을 그대로 쓰고 열 몇 개를 더한다. 새 표는 참가 클럽 하나뿐.
//  2클럽 전용이지만 club_slots·format 은 미리 둔다 — 3·4클럽을 켤 때
//  서버를 갈아엎지 않기 위해서다.
// ══════════════════════════════════════════════════════════════
try { db.exec("ALTER TABLE club_events ADD COLUMN kind TEXT"); } catch (e) {}           // 'exchange'
try { db.exec("ALTER TABLE club_events ADD COLUMN club_slots INTEGER"); } catch (e) {}  // 지금은 항상 2
try { db.exec("ALTER TABLE club_events ADD COLUMN per_club INTEGER"); } catch (e) {}    // 클럽당 인원
try { db.exec("ALTER TABLE club_events ADD COLUMN courts INTEGER"); } catch (e) {}
try { db.exec("ALTER TABLE club_events ADD COLUMN squad_mix TEXT"); } catch (e) {}      // 'md2,mx4'
try { db.exec("ALTER TABLE club_events ADD COLUMN format TEXT"); } catch (e) {}         // 'single'
try { db.exec("ALTER TABLE club_events ADD COLUMN match_status TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE club_events ADD COLUMN close_at BIGINT"); } catch (e) {}
try { db.exec("ALTER TABLE club_events ADD COLUMN court_fee INTEGER"); } catch (e) {}
try { db.exec("ALTER TABLE club_events ADD COLUMN mins INTEGER"); } catch (e) {}        // 대관 시간(분)
try { db.exec("ALTER TABLE club_events ADD COLUMN dinner_fee INTEGER"); } catch (e) {}  // 회식비(전체)
try { db.exec("ALTER TABLE users ADD COLUMN last_seen INTEGER"); } catch (e) {}        // 마지막 접속
try { db.exec("ALTER TABLE users ADD COLUMN last_plat TEXT"); } catch (e) {}          // 마지막에 쓴 기기
try { db.exec("ALTER TABLE users ADD COLUMN is_test INTEGER DEFAULT 0"); } catch (e) {}  // 테스트용 가짜 회원
try { db.exec("ALTER TABLE users ADD COLUMN test_key TEXT"); } catch (e) {}           // 이름#클럽 — 클럽마다 다른 사람
try { db.exec("ALTER TABLE club_events ADD COLUMN started_at INTEGER"); } catch (e) {}  // 교류전 시작 시각
try { db.exec("ALTER TABLE club_events ADD COLUMN started_by INTEGER"); } catch (e) {}  // 시작 버튼을 누른 사람

db.exec(`CREATE TABLE IF NOT EXISTS exchange_games (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER, round INTEGER, court INTEGER, kind TEXT,
  home_club INTEGER, away_club INTEGER, home_seat INTEGER, away_seat INTEGER,
  home_json TEXT, away_json TEXT,
  sa INTEGER, sb INTEGER, scored_by INTEGER, scored_at BIGINT
);`);
try { db.exec('CREATE INDEX IF NOT EXISTS ix_xg ON exchange_games(event_id)'); } catch (e) {}

db.exec(`CREATE TABLE IF NOT EXISTS exchange_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER, club_id INTEGER, seat_no INTEGER,
  status TEXT, squad_json TEXT, joined_at BIGINT
);`);
try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_xe ON exchange_entries(event_id, club_id)'); } catch (e) {}

/* 코트 수와 대관 시간으로 규모를 계산한다.
   회차 = 경기 25분 + 교체 5분 = 30분.  총원 × 1인경기 = 코트 × 회차 × 4 */
const XC_UNIT = 30;
function xcPlanFor(courts, mins) {
  const R = Math.floor((+mins || 0) / XC_UNIT);
  const c = +courts || 0;
  if (R < 2 || c < 2) return null;
  // 2클럽은 대전 하나가 전 코트를 계속 쓴다 → 클럽당 인원 = 코트 × 2
  const per = c * 2;
  const games = Math.floor(c * R * 4 / (per * 2));   // 1인 경기 수
  return { rounds: R, per_club: per, games, total: per * 2 };
}

/* 종목 구성 — 'md2,mx4' 를 {남복,혼복,여복} 과 필요 성비로 푼다 */
function xcMix(code) {
  const out = { md: 0, mx: 0, wd: 0 };
  String(code || 'md2,mx4').split(',').forEach(t => {
    const m = String(t).trim().match(/^(md|mx|wd)(\d+)$/);
    if (m) out[m[1]] = +m[2];
  });
  return { ...out, men: out.md * 2 + out.mx, women: out.wd * 2 + out.mx };
}

function xcEvent(eid) {
  return db.prepare("SELECT * FROM club_events WHERE id=? AND kind='exchange'").get(eid);
}
function xcEntries(eid) {
  return db.prepare(`SELECT e.*, c.name club_name, c.region
     FROM exchange_entries e JOIN clubs c ON c.id=e.club_id
     WHERE e.event_id=? AND e.status<>'dropped' ORDER BY e.seat_no`).all(eid);
}
/* 그 클럽이 이 교류전에 낼 수 있는 사람 — 참석을 누른 회원 중에서 센다.
   게스트는 명부에 guest 로 올라 있고, 어느 클럽에서도 정회원이 아닌 사람만. */
function xcRoster(eid, clubId) {
  /* club_members 에 같은 사람이 두 줄 있으면 참석자가 두 번 나온다 — user_id 로 묶는다 */
  /* LEFT JOIN 이라 그 클럽 사람이 아니어도 다 나왔다 — 양쪽 참석자가 섞여
     클럽마다 24명으로 보이고 명단이 똑같았다. 그 클럽 회원만 남긴다. */
  const rows = db.prepare(`SELECT u.id, COALESCE(NULLIF(cm.alias,''), u.name) name,
      COALESCE(cm.gender_ov, u.gender) gender, cm.role, u.sport_started, cm.grade, u.photos
    FROM event_attendees ea JOIN users u ON u.id=ea.user_id
    JOIN club_members cm ON cm.club_id=? AND cm.user_id=u.id
      AND (cm.status IS NULL OR cm.status='active')
    WHERE ea.event_id=? AND (ea.status IS NULL OR ea.status='going')
    GROUP BY u.id`).all(clubId, eid);
  const ok = rows.filter(r => {
    if (r.role !== 'guest') return true;
    const elsewhere = db.prepare(`SELECT 1 FROM club_members
      WHERE user_id=? AND role IN ('member','officer','owner')`).get(r.id);
    return !elsewhere;                       // 어디서든 정회원이면 게스트로는 못 나간다
  });
  /* 같은 사람이 계정 두 개(카카오·네이버)로 클럽에 들어와 있으면 user_id 가 달라
     GROUP BY 로는 안 걸린다 — 대진에 <최민혁 · 최민혁> 이 한 팀으로 나온 이유다.
     한 클럽 안에서 이름이 겹치면 먼저 들어온 계정만 남긴다.
     동명이인이 진짜로 있으면 클럽 명단에서 별명(alias)을 달아 갈라 놓는다. */
  const seen = new Set();
  return ok.filter(r => {
    const k = String(r.name || '').trim();
    if (!k) return true;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
function xcView(ev, uid) {
  const ent = xcEntries(ev.id);
  const mix = xcMix(ev.squad_mix);
  return {
    id: ev.id, kind: 'exchange', title: ev.title, date: ev.date, place: ev.place,
    courts: ev.courts, per_club: ev.per_club, club_slots: ev.club_slots || 2,
    squad_mix: ev.squad_mix, status: ev.match_status, close_at: ev.close_at,
    court_fee: ev.court_fee || 0, dinner_fee: ev.dinner_fee || 0, need: mix,
    /* 1인 참가비 = (코트비 ÷ 두 클럽 + 회식비 ÷ 두 클럽) ÷ 클럽당 인원.
       회원이 알아야 하는 건 총액이 아니라 자기가 내는 돈이다. */
    per_head: (ev.per_club ? Math.ceil(((ev.court_fee || 0) / 2 + (ev.dinner_fee || 0) / 2)
                / ev.per_club / 100) * 100 : 0),
    clubs: ent.map(e => {
      const r = xcRoster(ev.id, e.club_id);          // 참석을 누른 사람들
      return {
        club_id: e.club_id, name: e.club_name, seat_no: e.seat_no, host: e.seat_no === 1,
        count: r.length, ready: r.length >= (ev.per_club || 0),
        men: r.filter(p => p.gender === 'M').length,
        women: r.filter(p => p.gender === 'F').length,
        names: r.map(p => p.name),
        /* 성별·등급까지 보낸다 — 교류전은 <남 10 · 여 2> 로 자리가 정해져 있어서
           명단 화면이 <몇 명 왔나>가 아니라 <어느 자리가 비었나>를 답해야 한다. */
        /* 등급은 운영진이 손으로 적어둔 값(cm.grade)이 없는 회원이 많다 —
           그러면 구력으로 계산해 채운다. 명단에서 어떤 사람만 등급이 뜨면
           <저 사람은 왜 없지> 를 매번 묻게 된다. */
        people: withGrade(r).map(p => ({ name: p.name, photos: p.photos || null,
          gender: p.gender || null, grade: p.grade || null, guest: p.role === 'guest' ? 1 : 0 })),
        /* 이름 표기가 다른 같은 사람(카카오/네이버 계정) — 운영진에게만 귀띔한다.
           로마자 이름이 섞여 있으면 자동으로는 못 걸러낸다. */
        latin: r.filter(p => /^[A-Za-z][A-Za-z .'-]*$/.test(String(p.name || '').trim()))
          .map(p => p.name),
      };
    }),
    my_clubs: (db.prepare(`SELECT club_id FROM club_members WHERE user_id=?
      AND role IN ('member','officer','owner')`).all(uid) || []).map(r => r.club_id),
    /* 참석 버튼을 교류전 화면에서 바로 누를 수 있게 — 모임 정보로 한 번 더
       들어가게 하면 대부분 거기까지 가지 않는다 */
    my_status: (() => {
      const r = db.prepare('SELECT status FROM event_attendees WHERE event_id=? AND user_id=?')
        .get(ev.id, uid);
      return r ? (r.status || 'going') : null;
    })(),
    place: ev.place || '',
  };
}

/* ── 열기 ── 코트를 잡은 클럽의 임원만 */
/* ══════════ 도전장 ══════════════════════════════════════════
   교류전이 한 번도 안 열린 이유는 셋이다 —
   상대를 모르고, 연락이 번거롭고, 해서 뭐가 좋은지 모른다.
   땅따먹기는 셋째만 푼다. 앞의 둘은 이걸로 푼다:
   근처 클럽을 보여주고, 앱 안에서 한 번 눌러 청한다. */
db.exec(`CREATE TABLE IF NOT EXISTS challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_club INTEGER, to_club INTEGER,
  date TEXT, venue_id INTEGER, place TEXT,
  courts INTEGER DEFAULT 2, mins INTEGER DEFAULT 180,
  msg TEXT,
  status TEXT DEFAULT 'sent',      -- sent · accepted · declined · expired
  event_id INTEGER,                -- 수락하면 만들어진 교류전
  created_by INTEGER, created_at INTEGER, replied_at INTEGER)`);
try { db.exec('CREATE INDEX IF NOT EXISTS ix_ch ON challenges(to_club, status)'); } catch (e) {}

/* 근처 클럽 — 땅이 없어도 홈은 있으니 <옆 동네에 클럽이 셋 있네> 가 보인다.
   실력이 비슷한지도 함께 준다. 붙어도 되겠다는 판단이 서야 청한다. */
app.get('/clubs/:id/nearby', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const me = db.prepare('SELECT region, sport, avg_grade FROM clubs WHERE id=?').get(cid) || {};
  const sido = String(me.region || '').split(' ')[0] || '';
  const rows = db.prepare(`SELECT c.id, c.name, c.region, c.avg_grade,
      (SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id) members
    FROM clubs c WHERE c.id!=? AND c.sport=? AND c.region LIKE ?
    ORDER BY members DESC LIMIT 20`).all(cid, me.sport || 'tennis', sido + '%');
  /* 이미 보낸 도전장은 다시 못 보내게 표시 */
  const sent = {};
  db.prepare(`SELECT to_club, status FROM challenges
    WHERE from_club=? AND status='sent'`).all(cid).forEach(r => { sent[r.to_club] = 1; });
  /* 지난 교류전 전적 */
  const hist = {};
  db.prepare(`SELECT e.club_id a, e2.club_id b, ce.id eid FROM exchange_entries e
    JOIN exchange_entries e2 ON e2.event_id=e.event_id AND e2.club_id!=e.club_id
    JOIN club_events ce ON ce.id=e.event_id
    WHERE e.club_id=?`).all(cid).forEach(r => { hist[r.b] = (hist[r.b] || 0) + 1; });
  const myG = String(me.avg_grade || '');
  res.json(rows.map(c => ({
    ...c,
    sent: !!sent[c.id],
    played: hist[c.id] || 0,
    /* 등급 앞글자가 같으면 <우리와 비슷> — 붙을 만하다는 신호 */
    similar: !!(myG && c.avg_grade && myG[0] === String(c.avg_grade)[0]),
  })));
});

/* 도전장 보내기 — 연락처를 몰라도 앱 안에서 끝난다 */
app.post('/clubs/:id/challenge', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid))
    return res.status(403).json({ error: 'officer_only', message: '임원만 보낼 수 있어요' });
  const { to_club, date, venue_id, place, courts, mins, msg } = req.body || {};
  if (!to_club || !date) return res.status(400).json({ error: 'bad_req' });
  const dup = db.prepare(`SELECT id FROM challenges
    WHERE from_club=? AND to_club=? AND status='sent'`).get(cid, +to_club);
  if (dup) return res.status(409).json({ error: 'already', message: '이미 보낸 도전장이 있어요' });
  const r = db.prepare(`INSERT INTO challenges
    (from_club,to_club,date,venue_id,place,courts,mins,msg,created_by,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(cid, +to_club, String(date), venue_id ? +venue_id : null,
         String(place || '').slice(0, 60) || null, +courts || 2, +mins || 180,
         String(msg || '').slice(0, 200) || null, req.uid, now());
  const from = db.prepare('SELECT name FROM clubs WHERE id=?').get(cid) || {};
  notifyClubOfficers(+to_club, '🆚', '도전장이 왔어요',
    `${from.name || '어느 클럽'} · ${date}`);
  res.json({ ok: true, id: rid(r) });
});

/* 받은·보낸 도전장 */
app.get('/clubs/:id/challenges', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isMember(cid, req.uid)) return res.status(403).json({ error: 'member_only' });
  const q = `SELECT ch.*, cf.name from_name, ct.name to_name
    FROM challenges ch
    LEFT JOIN clubs cf ON cf.id=ch.from_club
    LEFT JOIN clubs ct ON ct.id=ch.to_club WHERE `;
  res.json({
    got: db.prepare(q + `ch.to_club=? AND ch.status='sent' ORDER BY ch.id DESC LIMIT 10`).all(cid),
    sent: db.prepare(q + `ch.from_club=? ORDER BY ch.id DESC LIMIT 10`).all(cid),
  });
});

/* 수락 — 양쪽에 교류전이 만들어지고 둘 다 자리에 앉는다 */
app.post('/challenges/:id/accept', auth, (req, res) => {
  const ch = db.prepare('SELECT * FROM challenges WHERE id=?').get(+req.params.id);
  if (!ch || ch.status !== 'sent') return res.status(404).json({ error: 'not_found' });
  if (!isOfficer(ch.to_club, req.uid)) return res.status(403).json({ error: 'officer_only' });
  const plan = xcPlanFor(ch.courts, ch.mins) || { per_club: 8 };
  const from = db.prepare('SELECT name FROM clubs WHERE id=?').get(ch.from_club) || {};
  const to = db.prepare('SELECT name FROM clubs WHERE id=?').get(ch.to_club) || {};
  const title = `${from.name || ''} vs ${to.name || ''}`.trim();
  /* 교류전은 도전한 쪽이 연다 — 구장도 그쪽이 골랐으니 */
  const r = db.prepare(`INSERT INTO club_events
      (club_id,title,date,tag,place,venue_id,created_by,created_at,
       kind,club_slots,per_club,courts,squad_mix,format,match_status)
      VALUES (?,?,?,'교류전',?,?,?,?, 'exchange',2,?,?, 'md2,mx4','single','open')`)
    .run(ch.from_club, title, ch.date, ch.place, ch.venue_id, req.uid, now(),
         plan.per_club, ch.courts);
  const eid = rid(r);
  db.prepare(`INSERT INTO exchange_entries (event_id,club_id,seat_no,status,joined_at)
    VALUES (?,?,1,'joined',?), (?,?,2,'joined',?)`)
    .run(eid, ch.from_club, now(), eid, ch.to_club, now());
  db.prepare(`UPDATE challenges SET status='accepted', event_id=?, replied_at=? WHERE id=?`)
    .run(eid, now(), ch.id);
  notifyClub(ch.from_club, req.uid, '🆚', '도전장을 받아줬어요',
    `${to.name || ''} · ${ch.date} · 참석을 눌러주세요`);
  notifyClub(ch.to_club, req.uid, '🆚', '교류전이 잡혔어요',
    `${from.name || ''} · ${ch.date} · 참석을 눌러주세요`);
  res.json({ ok: true, event_id: eid });
});

app.post('/challenges/:id/decline', auth, (req, res) => {
  const ch = db.prepare('SELECT * FROM challenges WHERE id=?').get(+req.params.id);
  if (!ch || ch.status !== 'sent') return res.status(404).json({ error: 'not_found' });
  if (!isOfficer(ch.to_club, req.uid)) return res.status(403).json({ error: 'officer_only' });
  db.prepare(`UPDATE challenges SET status='declined', replied_at=? WHERE id=?`).run(now(), ch.id);
  /* 거절은 조용히 — 벌도 없고 소문도 안 낸다 */
  const to = db.prepare('SELECT name FROM clubs WHERE id=?').get(ch.to_club) || {};
  notifyClubOfficers(ch.from_club, '🆚', '이번엔 어렵대요',
    `${to.name || ''} · 다른 날로 다시 보내볼 수 있어요`);
  res.json({ ok: true });
});

app.post('/clubs/:id/exchange', auth, (req, res) => {
  const cid = +req.params.id;
  if (!isOfficer(cid, req.uid))
    return res.status(403).json({ error: 'officer_only', message: '임원만 교류전을 열 수 있어요' });
  const { title, date, place, courts, mins, squad_mix, close_at, court_fee } = req.body || {};
  const plan = xcPlanFor(courts, mins);
  if (!plan) return res.status(400).json({ error: 'bad_size', message: '코트 수와 시간을 확인해 주세요' });
  const mix = xcMix(squad_mix);
  if (mix.men + mix.women !== plan.per_club)
    return res.status(400).json({ error: 'bad_mix',
      message: `${plan.per_club}명에 맞는 종목 구성을 골라주세요` });
  const r = db.prepare(`INSERT INTO club_events
      (club_id,title,date,tag,place,created_by,created_at,
       kind,club_slots,per_club,courts,squad_mix,format,match_status,close_at,court_fee,dinner_fee)
      VALUES (?,?,?,?,?,?,?, 'exchange',2,?,?,?, 'single','open',?,?,?)`)
    .run(cid, String(title || '교류전'), String(date || ''), '교류전',
         String(place || '').trim().slice(0, 60) || null, req.uid, now(),
         plan.per_club, +courts, String(squad_mix || 'md2,mx4'),
         +close_at || null, +court_fee || 0, +((req.body||{}).dinner_fee) || 0);
  const eid = rid(r);
  db.prepare(`INSERT INTO exchange_entries (event_id,club_id,seat_no,status,joined_at)
              VALUES (?,?,1,'joined',?)`).run(eid, cid, now());
  notifyClub(cid, req.uid, '🆚', '교류전이 열렸어요',
    `${title || '교류전'}${date ? ' · ' + date : ''} · 참석을 눌러주세요`);
  res.json({ ok: true, id: eid, plan });
});

/* ── 자리 신청 ── 상대 클럽 임원만. 승낙 없이 선착순 */
app.post('/exchange/:id/join', auth, (req, res) => {
  const eid = +req.params.id, cid = +((req.body || {}).club_id || 0);
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  if (ev.match_status !== 'open')
    return res.status(409).json({ error: 'closed', message: '이미 자리가 찼어요' });
  if (!isOfficer(cid, req.uid))
    return res.status(403).json({ error: 'officer_only', message: '임원만 신청할 수 있어요' });
  const ent = xcEntries(eid);
  if (ent.some(e => e.club_id === cid))
    return res.status(409).json({ error: 'already', message: '이미 신청한 클럽이에요' });
  if (ent.length >= (ev.club_slots || 2))
    return res.status(409).json({ error: 'full', message: '자리가 다 찼어요' });

  /* 성비를 못 맞추는 클럽은 여기서 막는다 — 당일에 알면 늦다 */
  const mix = xcMix(ev.squad_mix);
  const pool = db.prepare(`SELECT COALESCE(cm.gender_ov, u.gender) g, cm.role
      FROM club_members cm JOIN users u ON u.id=cm.user_id
      WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active')`).all(cid);
  const nM = pool.filter(p => p.g === 'M').length, nF = pool.filter(p => p.g === 'F').length;
  if (nM < mix.men || nF < mix.women)
    return res.status(400).json({ error: 'roster_short',
      message: (() => {
        const dM = Math.max(0, mix.men - nM), dF = Math.max(0, mix.women - nF);
        const p = [];
        if (dM) p.push(`남성 ${dM}명`);
        if (dF) p.push(`여성 ${dF}명`);
        return p.length ? `${p.join(' · ')}이 모자라요` : '성별 구성이 맞지 않아요';
      })() });

  const seat = ent.length + 1;
  db.prepare(`INSERT INTO exchange_entries (event_id,club_id,seat_no,status,joined_at)
              VALUES (?,?,?,'joined',?)`).run(eid, cid, seat, now());
  if (seat >= (ev.club_slots || 2))
    db.prepare("UPDATE club_events SET match_status='filled' WHERE id=?").run(eid);

  const host = ent[0];
  if (host) notifyClub(host.club_id, null, '🆚', '교류전 상대가 정해졌어요',
    `${db.prepare('SELECT name FROM clubs WHERE id=?').get(cid).name} 클럽이 참가해요`);
  notifyClub(cid, req.uid, '🆚', '교류전에 참가해요',
    `${ev.title}${ev.date ? ' · ' + ev.date : ''} · 참석을 눌러주세요`);
  res.json(xcView(xcEvent(eid), req.uid));
});

/* ── 회원이 임원에게 제안 ── */
app.post('/exchange/:id/suggest', auth, (req, res) => {
  const eid = +req.params.id, cid = +((req.body || {}).club_id || 0);
  if (!isMember(cid, req.uid))
    return res.status(403).json({ error: 'member_only' });
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const me = getUser(req.uid);
  db.prepare(`SELECT user_id FROM club_members WHERE club_id=? AND role IN ('owner','officer')`)
    .all(cid).forEach(r => sendPush(r.user_id, { icon: '🆚', title: '교류전 참가 제안',
      body: `${me.name} 님이 ${ev.title} 참가를 제안했어요`, link: `club:${cid}` }));
  res.json({ ok: true });
});

/* ── 조회 ── */
app.get('/exchange/:id', auth, (req, res) => {
  const ev = xcEvent(+req.params.id);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  res.json(xcView(ev, req.uid));
});
app.get('/clubs/:id/exchange', auth, (req, res) => {
  const cid = +req.params.id;
  const rows = db.prepare(`SELECT e.* FROM club_events e
     JOIN exchange_entries x ON x.event_id=e.id AND x.club_id=? AND x.status<>'dropped'
     WHERE e.kind='exchange' ORDER BY e.id DESC LIMIT 20`).all(cid);
  res.json(rows.map(ev => xcView(ev, req.uid)));
});

/* ── 대진 ── 양쪽 인원이 다 차면 짜서 바로 공개한다. 사람이 손대지 않는다 */
app.post('/exchange/:id/draw', auth, (req, res) => {
  const eid = +req.params.id;
  const ev = xcEvent(eid);
  if (!ev) return res.status(404).json({ error: 'not_found' });
  const ent = xcEntries(eid);
  if (ent.length < (ev.club_slots || 2))
    return res.status(409).json({ error: 'need_clubs', message: '상대 클럽이 아직 없어요' });

  /* 이미 점수가 들어간 대진을 말없이 지우면 안 된다 — 다시 짜려면 한 번 더 묻는다 */
  const scored = db.prepare(
    'SELECT COUNT(*) n FROM exchange_games WHERE event_id=? AND sa IS NOT NULL').get(eid).n;
  if (scored && !(req.body || {}).force)
    return res.status(409).json({ error: 'has_scores',
      message: `이미 ${scored}경기 점수가 들어가 있어요 · 다시 짜면 모두 지워집니다` });

  const mix = xcMix(ev.squad_mix);
  const squads = {}, rosters = {};
  for (const e of ent) {
    const roster = xcRoster(eid, e.club_id);
    if (roster.length < ev.per_club)
      return res.status(409).json({ error: 'need_players',
        message: `${e.club_name} 인원이 ${roster.length}/${ev.per_club}명이에요` });
    const sq = xcSquadAt(roster, mix, 0);            // 1회차 조 — 성비가 맞는지 여기서 걸러진다
    if (!sq) {
      /* 총 필요 인원을 말하면 <12명 다 모였는데 왜?> 가 된다.
         모자란 쪽과 그 수만 말한다. */
      const nM = roster.filter(r => r.gender === 'M').length;
      const nF = roster.filter(r => r.gender === 'F').length;
      const dM = Math.max(0, mix.men - nM), dF = Math.max(0, mix.women - nF);
      const parts = [];
      if (dM) parts.push(`남성 ${dM}명`);
      if (dF) parts.push(`여성 ${dF}명`);
      return res.status(409).json({ error: 'bad_gender',
        message: parts.length
          ? `${e.club_name}: ${parts.join(' · ')}이 모자라요`
          : `${e.club_name}: 성별 구성이 맞지 않아요 (남 ${nM} · 여 ${nF})` });
    }
    squads[e.club_id] = sq;
    rosters[e.club_id] = roster;
    db.prepare('UPDATE exchange_entries SET squad_json=? WHERE event_id=? AND club_id=?')
      .run(JSON.stringify(sq), eid, e.club_id);
  }
  /* 회차 수 = 총원 × 1인경기 ÷ (코트 × 4). 2클럽은 클럽당 인원 = 코트 × 2 이므로
     언제나 1인 6경기, 회차는 코트 수와 무관하게 6이 된다. */
  const rounds = Math.round((ev.per_club * 2 * 6) / (ev.courts * 4));
  const games = xcDraw(ent, rosters, mix, ev.courts, rounds);
  db.prepare('DELETE FROM exchange_games WHERE event_id=?').run(eid);
  const ins = db.prepare(`INSERT INTO exchange_games
    (event_id,round,court,kind,home_club,away_club,home_seat,away_seat,home_json,away_json)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);
  games.forEach(g => ins.run(eid, g.round, g.court, g.kind,
    g.home.club_id, g.away.club_id, g.home.seat, g.away.seat,
    JSON.stringify(g.home.players), JSON.stringify(g.away.players)));
  db.prepare("UPDATE club_events SET match_status='confirmed' WHERE id=?").run(eid);
  ent.forEach(e => notifyClub(e.club_id, null, '📋', '교류전 대진이 나왔어요',
    `${ev.title}${ev.date ? ' · ' + ev.date : ''}`));
  res.json({ ok: true, games, squads });
});

/* 구력(개월) — 조를 짤 때 쓰는 실력 잣대. 모르면 중간값 2년으로 본다. */
function xcLevel(p) {
  const m = String((p && p.sport_started) || '').match(/^(\d{4})-(\d{1,2})/);
  if (!m) return 24;
  return Math.max(0, (new Date().getFullYear() - +m[1]) * 12 +
                     (new Date().getMonth() + 1 - +m[2]));
}

/* 조 묶기 — 회차마다 다시 짠다.
   예전에는 조를 한 번 짜서 squad_json 에 굳혀 두고 여섯 회차를 그대로 돌렸다.
   그래서 파트너가 세 시간 내내 고정이었고, 남복은 상대 조가 넷뿐인데 6회차라
   5·6회차가 1·2회차의 재대결이 됐다(혼복은 상대가 둘이라 같은 팀을 세 번 만났다).

   두 가지를 회차 번호 r 로 민다.
     ① 혼복에 나갈 사람 — 늘 같은 두 명이 혼복만 뛰지 않게 순번을 민다
     ② 파트너 — 약한 쪽 줄을 두 회차마다 한 칸씩 민다
   강+약 짝짓기는 그대로다. 강한 사람끼리 묶으면 1조는 무적이고 마지막 조는 학살당한다.
   12명·6코트 기준으로 재어 보면 한 사람이 여섯 회차 동안 만나는
   서로 다른 파트너가 1명 → 4~6명, 같은 네 사람이 다시 붙는 판은 12번 → 1~3번이 된다. */
function xcSquadAt(roster, mix, r) {
  const men = (roster || []).filter(p => p.gender === 'M').sort((a, b) => xcLevel(b) - xcLevel(a));
  const women = (roster || []).filter(p => p.gender === 'F').sort((a, b) => xcLevel(b) - xcLevel(a));
  if (men.length < mix.men || women.length < mix.women) return null;
  const M = men.slice(0, mix.men), W = women.slice(0, mix.women);
  const R = Math.max(0, r | 0);
  const out = [];

  /* ① 혼복 당번 — 회차마다 mix.mx 칸씩 민다.
     한 바퀴 돌 때마다 한 칸을 더 밀어(+floor) 같은 조합으로 되돌아오지 않게 한다.
     그냥 mx 칸씩만 밀면 8명 중 4명을 뽑는 경우 두 회차 만에 처음으로 돌아온다. */
  const rot = (len, n) => {
    const base = R * n + Math.floor((R * n) / len);
    const set = new Set();
    for (let k = 0; k < n; k++) set.add(((base + k) % len + len) % len);
    return set;
  };
  const mxMi = mix.mx ? rot(M.length, mix.mx) : new Set();
  const mxWi = mix.mx ? rot(W.length, mix.mx) : new Set();
  const mxM = M.filter((_, i) => mxMi.has(i));
  const mxW = W.filter((_, i) => mxWi.has(i));
  const mdPool = M.filter((_, i) => !mxMi.has(i));       // 남은 남자가 남복
  const wdPool = W.filter((_, i) => !mxWi.has(i));       // 남은 여자가 여복

  /* ② 강+약 짝짓기 — 뒤 절반을 뒤집어(약한 순) 앞 절반에 붙인다.
     그대로 붙이면 어느 조나 두 사람의 무게 합이 같다. 여기서 약한 쪽 줄을
     회차마다 <0 · −1 · +1 · −2 · +2 …> 로 좌우 번갈아 민다.
     한 방향으로만 밀면 두 회차씩 같은 자리가 겹쳐(3·4회차가 똑같은 조가 됐다),
     번갈아 밀면 여섯 회차가 모두 다른 짝이 된다.
     조끼리 생기는 무게 차이는 아래 xcDraw 가 <무게 비슷한 조끼리> 붙여서 상쇄한다. */
  const pairUp = (pool, n, kind) => {
    if (!n) return;
    const S = pool.slice(0, n), Wk = pool.slice(n).reverse();
    const shift = (R % 2) ? -Math.ceil(R / 2) : Math.ceil(R / 2);
    for (let i = 0; i < n; i++) out.push({ kind, p: [S[i], Wk[((i + shift) % n + n) % n]] });
  };
  pairUp(mdPool, mix.md, '남복');
  for (let i = 0; i < mix.mx; i++)                        // 센 남자에 약한 여자
    out.push({ kind: '혼복', p: [mxM[i], mxW[(mix.mx - 1 - i + R) % mix.mx]] });
  pairUp(wdPool, mix.wd, '여복');

  /* 자기 자신과 짝이 되는 일은 없어야 한다 — 명단이 홀수로 잘리면
     가운데 사람이 앞뒤 양쪽에 걸린다. 그런 조는 만들지 않고 편성을 실패시켜,
     왜 안 되는지 화면에서 묻게 한다. */
  if (out.some(g => !g.p[0] || !g.p[1] || g.p[0].id === g.p[1].id)) return null;
  /* lv = 조의 무게(구력 합). 상대를 고를 때 쓴다 — 선수 정보에는 안 들어간다. */
  return out.map(g => ({ kind: g.kind, lv: xcLevel(g.p[0]) + xcLevel(g.p[1]),
    players: g.p.map(x => ({ id: x.id, name: x.name })) }));
}
/* 예전 이름 — 1회차 조를 뜻한다 */
function xcSquad(roster, mix) { return xcSquadAt(roster, mix, 0); }

/* 대진 — 회차마다 양쪽 클럽의 조를 새로 짜고, 같은 종목끼리 <무게가 비슷한 조>를 맞붙인다.

   예전에는 상대를 한 칸씩 미는 방식이었다(j+r). 조가 고정일 때는 모든 조의 무게가
   같아서 그래도 됐지만, 회차마다 조를 새로 짜면 조마다 무게가 달라져 한 칸씩 밀면
   센 조가 약한 조를 만나는 판이 생긴다. 그래서 양쪽을 무게 순으로 세워 같은 자리끼리 붙인다.
   무게가 같은 조가 여럿이면 그 안에서 회차마다 순번을 돌린다 —
   그래야 같은 네 사람이 두 번 만나는 일이 없다.

   코트 번호가 뜻하는 종목(1~4 남복 · 5~6 혼복 식)은 회차가 바뀌어도 그대로다. */
function xcDraw(ent, rosters, mix, courts, rounds) {
  const games = [];
  for (let r = 0; r < rounds; r++) {
    const A = xcSquadAt(rosters[ent[0].club_id], mix, r);
    const B = xcSquadAt(rosters[ent[1].club_id], mix, r);
    if (!A || !B) break;
    let court = 0;
    ['남복', '혼복', '여복'].forEach(kind => {
      const ia = A.map((g, i) => [g, i]).filter(([g]) => g.kind === kind);
      let ib = B.map((g, i) => [g, i]).filter(([g]) => g.kind === kind)
        .sort((x, y) => y[0].lv - x[0].lv);
      /* 무게가 <비슷한> 구간은 회차마다 돌린다.
         딱 같을 때만 돌리면 제일 센 사람은 여섯 회차 내내 상대 클럽 제일 센 사람만 만난다.
         구력 합 2년(=1인 1년) 안쪽은 같은 무게로 보고 섞는다. */
      const TOL = 24;                       // 개월
      const rot = [];
      for (let i = 0; i < ib.length;) {
        let j = i;
        while (j < ib.length && Math.abs(ib[i][0].lv - ib[j][0].lv) <= TOL) j++;
        const grp = ib.slice(i, j);
        for (let k = 0; k < grp.length; k++) rot.push(grp[(k + r) % grp.length]);
        i = j;
      }
      ib = rot;
      /* 우리 조도 무게 순으로 세워, 같은 자리끼리 붙인다 (코트 순서는 그대로 둔다) */
      const order = ia.map((x, i) => [x, i]).sort((x, y) => y[0][0].lv - x[0][0].lv);
      const pick = new Array(ia.length);
      order.forEach(([, i], k) => { pick[i] = ib[k]; });
      for (let j = 0; j < ia.length; j++) {
        const a = ia[j], b = pick[j];
        games.push({ round: r + 1, court: ++court, kind,
          home: { club_id: ent[0].club_id, seat: a[1] + 1, players: a[0].players },
          away: { club_id: ent[1].club_id, seat: b[1] + 1, players: b[0].players } });
      }
    });
  }
  return games;
}

/* ── 마지막: 정적 파일 · 에러 핸들러 · 서버 시작 ──────────────────── */
// 연결된 웹 클라이언트 (public/) 서빙 — npm start 하면 http://localhost:PORT 에서 바로 동작
app.use(express.static(new URL('./public', import.meta.url).pathname));
// 에러는 JSON으로 — 라우트가 터져도 화면이 원인을 읽을 수 있게
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: String((err && err.message) || err).slice(0, 300) });
});
app.listen(PORT, () => console.log(`MATSU API on http://localhost:${PORT}`));
