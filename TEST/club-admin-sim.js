/* 이름 변경 · 클럽 이름 변경 · 클럽 삭제 규칙 테스트

   이름(users.name)은 본인이 고친다.
     카카오로 가입하면 닉네임이 그대로 이름이 되는데, 그 상태로 클럽에 들어가면
     임원이 일일이 별칭을 달아줘야 했다. 본인이 바꾸면 그 일이 사라진다.

   클럽 이름·삭제는 클럽장만.
     삭제는 '나 말고 아무도 없을 때'만 — 회원이 남아 있는데 지우면
     그 사람들의 기록·일정이 예고 없이 사라진다.

   실행:  node test/club-admin-sim.js
*/
import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(':memory:');
db.exec(`
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE clubs(id INTEGER PRIMARY KEY, name TEXT, sport TEXT);
CREATE TABLE club_members(club_id INTEGER, user_id INTEGER, role TEXT, status TEXT, alias TEXT);
INSERT INTO users VALUES (1,'회장'),(2,'kakao_nick_9231'),(3,'손님');
INSERT INTO clubs VALUES (1,'테스트클럽','tennis'),(2,'다른클럽','tennis'),(3,'같은이름','badminton');
INSERT INTO club_members VALUES (1,1,'owner','active',NULL),(1,2,'member','active',NULL),
  (2,1,'owner','active',NULL);   -- 같은 사람이 클럽 2 도 갖고 있다 (이름 중복 검사용)
`);

const setName = (uid, raw) => {
  const n = String(raw || '').trim().slice(0, 20);
  if (!n) return { error: 'bad_name' };
  db.prepare('UPDATE users SET name=? WHERE id=?').run(n, uid);
  return { name: n };
};
const clubName = (cid, uid) => {
  const m = db.prepare("SELECT 1 FROM club_members WHERE club_id=? AND user_id=? AND role='owner'").get(cid, uid);
  return !!m;
};
const rename = (cid, uid, raw) => {
  if (!clubName(cid, uid)) return { error: 'owner_only' };
  const n = String(raw || '').trim().slice(0, 20);
  if (!n) return { error: 'bad_name' };
  const c = db.prepare('SELECT * FROM clubs WHERE id=?').get(cid);
  const dup = db.prepare('SELECT 1 FROM clubs WHERE name=? AND sport IS ? AND id<>?').get(n, c.sport, cid);
  if (dup) return { error: 'name_taken' };
  db.prepare('UPDATE clubs SET name=? WHERE id=?').run(n, cid);
  return { name: n, before: c.name };
};
const remove = (cid, uid) => {
  if (!clubName(cid, uid)) return { error: 'owner_only' };
  const others = db.prepare('SELECT COUNT(*) n FROM club_members WHERE club_id=? AND user_id<>?').get(cid, uid).n;
  if (others > 0) return { error: 'members_left', left: others };
  db.prepare('DELETE FROM club_members WHERE club_id=?').run(cid);
  db.prepare('DELETE FROM clubs WHERE id=?').run(cid);
  return { ok: true };
};
/* 클럽 명단 이름 = 별칭 우선 (alias-sim 과 같은 규칙) */
const memberName = (cid, uid) => db.prepare(
  `SELECT COALESCE(NULLIF(cm.alias,''), u.name) AS name FROM club_members cm
   JOIN users u ON u.id=cm.user_id WHERE cm.club_id=? AND cm.user_id=?`).get(cid, uid).name;

let bad = 0; const ok = (c, m) => { if (!c) { bad++; console.log('FAIL', m); } else console.log('ok  ', m); };

console.log('■ 본인 이름 변경');
ok(setName(2, '최민혁').name === '최민혁', 'kakao_nick_9231 → 최민혁');
ok(setName(2, '   ').error === 'bad_name', '빈 이름은 거절');
ok(setName(2, 'x'.repeat(30)).name.length === 20, '20자에서 자른다');
setName(2, '최민혁');
ok(memberName(1, 2) === '최민혁', '클럽 명단에도 새 이름이 나온다 (별칭 없을 때)');
db.prepare("UPDATE club_members SET alias='서기훈' WHERE club_id=1 AND user_id=2").run();
ok(memberName(1, 2) === '서기훈', '별칭이 있으면 별칭이 이긴다');
setName(2, '최민혁2');
ok(memberName(1, 2) === '서기훈', '별칭이 있으면 본명을 바꿔도 클럽에선 그대로');

console.log('\n■ 클럽 이름 변경');
ok(rename(1, 2, '뺏기').error === 'owner_only', '회원은 못 바꾼다');
ok(rename(1, 1, '용인 테르메스').name === '용인 테르메스', '클럽장은 바꾼다');
ok(rename(2, 1, '용인 테르메스').error === 'name_taken', '같은 종목에 같은 이름은 거절');
ok(rename(2, 1, '같은이름').name === '같은이름', '다른 종목이면 같은 이름도 된다');
ok(rename(3, 1, '용인 테르메스').error === 'owner_only', '남의 클럽은 못 바꾼다');

console.log('\n■ 클럽 삭제');
ok(remove(1, 2).error === 'owner_only', '회원은 못 지운다');
const d1 = remove(1, 1);
ok(d1.error === 'members_left' && d1.left === 1, `회원이 남아 있으면 거절 (남은 ${d1.left}명)`);
db.prepare('DELETE FROM club_members WHERE club_id=1 AND user_id=2').run();
ok(remove(1, 1).ok === true, '나 혼자 남으면 지워진다');
ok(!db.prepare('SELECT 1 FROM clubs WHERE id=1').get(), '클럽이 사라졌다');
ok(!db.prepare('SELECT 1 FROM club_members WHERE club_id=1').get(), '회원 기록도 함께 정리됐다');

console.log(bad ? `\n${bad}건 실패` : '\n전부 통과');
process.exit(bad ? 1 : 0);
