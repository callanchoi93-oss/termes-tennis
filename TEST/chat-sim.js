/* 대화 시뮬레이터 — 1:1(DM)과 클럽 단체방을 실제 SQLite 위에서 돌린다.

   권한 규칙은 chat-rules.js 를 **그대로 import** 한다. 베껴 오지 않는다 —
   예전엔 이 파일이 SQL 사본을 들고 있었고, 서버의 DM_COST 를 안 옮겨서
   있지도 않은 과금을 검증한 적이 있다.

   실행:  node test/chat-sim.js [시드]        (Node 22 이상 — node:sqlite) */
import { DatabaseSync } from 'node:sqlite';
import { makeChatRules } from '../chat-rules.js';

const db = new DatabaseSync(':memory:');
const now = () => Date.now();
const rid = (r) => Number(r.lastInsertRowid);

db.exec(`
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, cash INTEGER DEFAULT 0,
  suspended INTEGER DEFAULT 0, provider TEXT DEFAULT 'kakao');
CREATE TABLE clubs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);
CREATE TABLE club_members (club_id INTEGER, user_id INTEGER, role TEXT, status TEXT);
CREATE TABLE dms (id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER NOT NULL,
  to_id INTEGER NOT NULL, body TEXT NOT NULL, read INTEGER DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE blocks (user_id INTEGER, blocked_user_id INTEGER);
CREATE TABLE cash_ledger (user_id INTEGER, delta INTEGER, reason TEXT, balance_after INTEGER, created_at BIGINT);
CREATE TABLE duels (id INTEGER PRIMARY KEY AUTOINCREMENT, a_id INTEGER, b_id INTEGER, status TEXT);
CREATE TABLE open_matches (id INTEGER PRIMARY KEY AUTOINCREMENT, manager_id INTEGER);
CREATE TABLE open_match_joins (match_id INTEGER, user_id INTEGER);
`);

/* ── 규칙은 서버와 같은 모듈에서 ── */
const { threadExists, canStartDM } = makeChatRules(db);
const getUser = (id) => db.prepare('SELECT * FROM users WHERE id=?').get(id);

/* POST /dm 을 함수로 (응답 코드와 본문만 흉내) */
function postDM(uid, to, body) {
  body = String(body || '').trim().slice(0, 500);
  if (!to || to === uid) return { s: 400, e: 'bad_target' };
  if (!body) return { s: 400, e: 'empty' };
  const target = getUser(to);
  if (!target) return { s: 404, e: 'no_user' };
  if (db.prepare('SELECT 1 FROM blocks WHERE user_id=? AND blocked_user_id=?').get(to, uid))
    return { s: 403, e: 'blocked' };

  const isNew = !threadExists(uid, to);
  if (isNew && !canStartDM(uid, to)) return { s: 403, e: 'dm_not_allowed' };

  /* 대화는 무료다 — 차감도, 하루 상한도 없다 */
  const r = db.prepare('INSERT INTO dms (from_id,to_id,body,created_at) VALUES (?,?,?,?)')
    .run(uid, to, body, now());
  return { s: 200, id: rid(r), isNew };
}

/* GET /dm/with/:uid — 읽음 처리 */
function readDM(uid, other) {
  db.prepare('UPDATE dms SET read=1 WHERE from_id=? AND to_id=? AND read=0').run(other, uid);
  return db.prepare(`SELECT * FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)
    ORDER BY id`).all(uid, other, other, uid);
}

/* GET /me/unread — 1:1 만 센다 */
function meUnread(uid) {
  const dm = db.prepare('SELECT COUNT(*) n FROM dms WHERE to_id=? AND read=0').get(uid).n;
  return { dm, total: dm };
}

/* ── 세계 만들기 ─────────────────────────────────────────────── */
let seed = Number(process.argv[2] || 20260812);
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const pick = (a) => a[Math.floor(rnd() * a.length) % a.length];
const N_USERS = 60, N_CLUBS = 5;

const users = [];
for (let i = 0; i < N_USERS; i++) {
  const r = db.prepare('INSERT INTO users (name,cash,provider) VALUES (?,?,?)')
    .run('U' + i, Math.floor(rnd() * 500), i < 3 ? 'manager' : 'kakao');
  users.push(rid(r));
}
const clubList = [];
for (let i = 0; i < N_CLUBS; i++) clubList.push(rid(db.prepare('INSERT INTO clubs (name) VALUES (?)').run('C' + i)));

/* 회원 배치: 일부는 pending(가입 신청 중) */
const memberOf = {};   // club -> Set(active users)
clubList.forEach(c => { memberOf[c] = new Set(); });
users.forEach(u => {
  if (rnd() < 0.55) {
    const c = pick(clubList);
    const st = rnd() < 0.15 ? 'pending' : 'active';
    db.prepare('INSERT INTO club_members (club_id,user_id,role,status) VALUES (?,?,?,?)')
      .run(c, u, 'member', st);
    if (st === 'active') memberOf[c].add(u);
  }
});
/* 1:1 랭크 — 다양한 상태 */
const duelOK = new Set();   // "a_b" 정렬키, 성사된 쌍
for (let i = 0; i < 40; i++) {
  const a = pick(users), b = pick(users); if (a === b) continue;
  const st = pick(['requested', 'accepted', 'scored', 'confirmed', 'declined', 'canceled']);
  db.prepare('INSERT INTO duels (a_id,b_id,status) VALUES (?,?,?)').run(a, b, st);
  if (['accepted', 'scored', 'confirmed'].includes(st)) duelOK.add([a, b].sort((x, y) => x - y).join('_'));
}
/* 오픈매치 — 매니저 1명 + 참가자 여럿 */
const mgrPairs = new Set(), coParticipants = [];
for (let i = 0; i < 6; i++) {
  const mgr = users[Math.floor(rnd() * 3)];
  const mid = rid(db.prepare('INSERT INTO open_matches (manager_id) VALUES (?)').run(mgr));
  const ps = [];
  for (let k = 0; k < 8; k++) { const u = pick(users); if (u !== mgr && !ps.includes(u)) ps.push(u); }
  ps.forEach(u => {
    db.prepare('INSERT INTO open_match_joins (match_id,user_id) VALUES (?,?)').run(mid, u);
    mgrPairs.add([mgr, u].sort((x, y) => x - y).join('_'));
  });
  for (let x = 0; x < ps.length; x++) for (let y = x + 1; y < ps.length; y++) coParticipants.push([ps[x], ps[y]]);
}
/* 차단 */
for (let i = 0; i < 15; i++) {
  const a = pick(users), b = pick(users); if (a === b) continue;
  db.prepare('INSERT INTO blocks (user_id,blocked_user_id) VALUES (?,?)').run(a, b);
}

/* 기대값을 SQL 과 무관하게 따로 계산한다 (교차 검증) */
const activeClubsOf = {};
users.forEach(u => { activeClubsOf[u] = new Set(); });
clubList.forEach(c => memberOf[c].forEach(u => activeClubsOf[u].add(c)));
function expectCanStart(a, b) {
  for (const c of activeClubsOf[a]) if (activeClubsOf[b].has(c)) return true;
  const k = [a, b].sort((x, y) => x - y).join('_');
  return duelOK.has(k) || mgrPairs.has(k);
}
const isBlocked = (to, from) =>
  !!db.prepare('SELECT 1 FROM blocks WHERE user_id=? AND blocked_user_id=?').get(to, from);

/* 시작 시점 캐시 잔액 — 끝나고 그대로인지 본다 */
const startCash = {};
db.prepare('SELECT id,cash FROM users').all().forEach(u => { startCash[u.id] = u.cash; });

/* 허용되는 쌍 목록 — 무작위로만 뽑으면 성공 경로가 거의 안 돌아간다 */
const relatedPairs = [];
for (let i = 0; i < users.length; i++)
  for (let j = i + 1; j < users.length; j++)
    if (expectCanStart(users[i], users[j])) relatedPairs.push([users[i], users[j]]);

/* ── 시뮬레이션 ──────────────────────────────────────────────── */
const N = 10000;
const fail = [];
const stat = { dm_ok: 0, dm_new: 0, dm_blocked: 0, dm_denied: 0, reads: 0, unread_checks: 0 };
const threads = new Set();          // 열린 1:1 스레드 (정렬키)
const openMatchDmAttempts = { tried: 0, allowed: 0 };

function bad(msg, extra) { if (fail.length < 25) fail.push(msg + (extra ? ' · ' + JSON.stringify(extra) : '')); }

for (let step = 0; step < N; step++) {
  const roll = rnd();

  if (roll < 0.40) {
    /* ── 1:1 보내기 ── 절반은 대화가 가능한 쌍으로, 절반은 완전 무작위로 */
    let a, b;
    if (rnd() < 0.5 && relatedPairs.length) { const p = pick(relatedPairs); a = p[0]; b = p[1];
      if (rnd() < 0.5) { const t = a; a = b; b = t; } }
    else { a = pick(users); b = pick(users); }
    const key = [a, b].sort((x, y) => x - y).join('_');
    const wasNew = !threadExists(a, b);
    const before = getUser(a).cash;
    const r = postDM(a, b, 'msg' + step);

    if (a === b) { if (r.s !== 400) bad('자기 자신에게 보냈는데 통과', r); continue; }
    if (isBlocked(b, a)) { if (r.s !== 403 || r.e !== 'blocked') bad('차단인데 안 막힘', r); stat.dm_blocked++; continue; }

    const should = wasNew ? expectCanStart(a, b) : true;
    if (!should) {
      if (r.s !== 403 || r.e !== 'dm_not_allowed') bad('허용되면 안 되는 새 대화가 열림', { a, b, r });
      else stat.dm_denied++;
      continue;
    }
    if (r.s !== 200) { bad('보낼 수 있어야 하는데 실패', { a, b, r }); continue; }
    stat.dm_ok++;
    if (r.isNew) stat.dm_new++;
    // 대화는 무료 — 어떤 경우에도 캐시가 움직이면 안 된다
    if (getUser(a).cash !== before) bad('대화를 보냈는데 캐시가 변했다', { a, before, after: getUser(a).cash });
    threads.add(key);

  } else if (roll < 0.50) {
    /* ── 오픈매치 동석자끼리 시도 (핵심 규칙) ── */
    if (!coParticipants.length) continue;
    const [a, b] = pick(coParticipants);
    openMatchDmAttempts.tried++;
    const wasNew = !threadExists(a, b);
    const r = postDM(a, b, 'om' + step);
    if (wasNew && r.s === 200) {
      openMatchDmAttempts.allowed++;
      // 클럽·1:1·매니저 관계가 따로 있으면 허용이 맞다
      if (!expectCanStart(a, b)) bad('오픈매치 동석만으로 대화가 열렸다', { a, b });
    }

  } else if (roll < 0.60) {
    /* ── 1:1 읽기 ── */
    const a = pick(users), b = pick(users); if (a === b) continue;
    const rows = readDM(a, b);
    stat.reads++;
    const unreadFromB = db.prepare('SELECT COUNT(*) n FROM dms WHERE from_id=? AND to_id=? AND read=0').get(b, a).n;
    if (unreadFromB !== 0) bad('읽었는데 안읽음이 남았다', { a, b, unreadFromB });
    for (let i = 1; i < rows.length; i++) if (rows[i].id <= rows[i - 1].id) bad('1:1 메시지 순서가 뒤집혔다');

  } else {
    /* ── 안읽음 집계 검증 ── */
    const u = pick(users);
    const un = meUnread(u);
    stat.unread_checks++;
    if (un.dm < 0 || un.total < 0) bad('안읽음이 음수', un);
    const dmExpect = db.prepare('SELECT COUNT(*) n FROM dms WHERE to_id=? AND read=0').get(u).n;
    if (un.dm !== dmExpect) bad('DM 안읽음 수가 안 맞다', { u, got: un.dm, want: dmExpect });
    if (un.total !== un.dm) bad('total 이 DM 수와 다르다', un);
  }
}

/* ── 마무리 전수 검사 ────────────────────────────────────────── */
db.prepare('SELECT DISTINCT from_id a, to_id b FROM dms').all().forEach(({ a, b }) => {
  const first = db.prepare(`SELECT from_id f, to_id t FROM dms
    WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) ORDER BY id LIMIT 1`).get(a, b, b, a);
  if (!expectCanStart(first.f, first.t))
    bad('열려서는 안 되는 스레드가 존재한다', { from: first.f, to: first.t });
});
// 캐시는 음수가 될 수 없다
db.prepare('SELECT id,cash FROM users WHERE cash<0').all().forEach(u => bad('캐시가 음수', u));
// 유료 차감 건수 = 원장 건수
// 대화로는 원장에 한 줄도 남지 않아야 한다
const ledgerN = db.prepare('SELECT COUNT(*) n FROM cash_ledger').get().n;
if (ledgerN !== 0) bad('대화 때문에 캐시 원장이 생겼다', { ledgerN });
// 시작 시점 잔액이 그대로 남아 있어야 한다
db.prepare('SELECT id,cash FROM users').all().forEach(u => {
  if (u.cash !== startCash[u.id]) bad('사용자 캐시가 변했다', { u, want: startCash[u.id] });
});

/* ── 결과 ── */
console.log(`실행 ${N.toLocaleString()}회 · 사용자 ${N_USERS}명 · 클럽 ${N_CLUBS}곳 (1:1 대화 전용)\n`);
console.log('1:1');
console.log(`  전송 성공        ${stat.dm_ok}  (새 대화 ${stat.dm_new})`);
console.log(`  규칙 위반 거절   ${stat.dm_denied}`);
console.log(`  차단 거절        ${stat.dm_blocked}`);
console.log(`  과금             없음 — 대화 무료`);
console.log(`  읽음 처리        ${stat.reads}`);
console.log('\n오픈매치 동석자');
console.log(`  대화 시도        ${openMatchDmAttempts.tried}`);
console.log(`  그중 열린 건     ${openMatchDmAttempts.allowed}${
  openMatchDmAttempts.allowed ? ' (전부 클럽·1:1·매니저 관계가 따로 있는 쌍)' : ''}`);
console.log(`\n안읽음 집계 검증   ${stat.unread_checks}`);

console.log('\n' + '─'.repeat(52));
if (!fail.length) console.log('오류 없음 — 모든 불변식 통과');
else { console.log(`불변식 위반 ${fail.length}건:`); fail.forEach(f => console.log('  · ' + f)); }
process.exit(fail.length ? 1 : 0);
