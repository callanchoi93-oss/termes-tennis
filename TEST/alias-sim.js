/* 클럽 안에서 한 사람은 한 이름으로만 보여야 한다

   club_members.alias 는 '이 클럽에서 부르는 이름'이다.
   앱은 이름을 열쇠로 사람을 찾는다 — 멤버 카드 열기, 게스트 표시, 프로필 사진.
   그래서 어느 한 화면만 users.name 을 쓰면 그 열쇠가 맞지 않는다.

   실제로 그런 일이 있었다: 멤버 목록엔 '서기훈'(alias), 참석자엔 '기훈'(users.name).
   같은 사람인데 이름이 갈려서 게스트 표시도, 멤버 카드도 안 열렸다.

   실행:  node test/alias-sim.js        (Node 22 이상 — node:sqlite)
*/
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync(':memory:');
db.exec(`
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, photos TEXT);
CREATE TABLE clubs(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE club_members(club_id INTEGER, user_id INTEGER, role TEXT, status TEXT,
  alias TEXT, grade TEXT);
CREATE TABLE club_events(id INTEGER PRIMARY KEY, club_id INTEGER, date TEXT);
CREATE TABLE event_attendees(id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER, user_id INTEGER, status TEXT, showed INTEGER);
INSERT INTO users VALUES (1,'기훈',NULL),(2,'최민혁',NULL),(3,'이정욱',NULL);
INSERT INTO clubs VALUES (1,'테르메스');
INSERT INTO club_members VALUES
  (1,1,'guest','active','서기훈','B2'),        -- 별칭이 있는 게스트
  (1,2,'owner','active',NULL,'B1'),            -- 별칭 없음
  (1,3,'member','active','',   'B2');          -- 빈 별칭
INSERT INTO club_events VALUES (10,1,'8/21');
INSERT INTO event_attendees (event_id,user_id,status) VALUES (10,1,'going'),(10,2,'going'),(10,3,'going');
`);

/* 이름 규칙은 한 곳에만 적는다 — 두 벌이 되는 순간 어긋난다 */
const NAME = `COALESCE(NULLIF(cm.alias,''), u.name)`;

const members = db.prepare(`SELECT cm.user_id, ${NAME} AS name, cm.role
  FROM club_members cm JOIN users u ON u.id=cm.user_id
  WHERE cm.club_id=? AND (cm.status IS NULL OR cm.status='active') ORDER BY name`).all(1);

const attendees = db.prepare(`SELECT ${NAME} AS name FROM event_attendees ea
  JOIN users u ON u.id=ea.user_id
  JOIN club_members cm ON cm.user_id=ea.user_id AND cm.club_id=?
    AND (cm.status IS NULL OR cm.status='active')
  WHERE ea.event_id=? AND (ea.status IS NULL OR ea.status='going') ORDER BY name`)
  .all(1, 10).map(r => r.name);

let bad = 0;
const ok = (c, m) => { if (!c) { bad++; console.log('FAIL', m); } else console.log('ok  ', m); };

console.log('■ 이름 규칙');
ok(members.find(m => m.user_id === 1).name === '서기훈', '별칭이 있으면 별칭을 쓴다');
ok(members.find(m => m.user_id === 2).name === '최민혁', '별칭이 없으면 본명을 쓴다');
ok(members.find(m => m.user_id === 3).name === '이정욱', '별칭이 빈 문자열이면 본명을 쓴다');

console.log('\n■ 멤버 목록과 참석 명단이 같은 이름을 쓰는가');
const mNames = members.map(m => m.name).sort();
ok(JSON.stringify(attendees.slice().sort()) === JSON.stringify(mNames),
  `참석자 [${attendees.join(', ')}] = 멤버 [${mNames.join(', ')}]`);

console.log('\n■ 앱이 이름으로 찾는 것들');
const guestMap = {}; members.forEach(m => { if (m.role === 'guest') guestMap[m.name] = 1; });
const photoMap = {}; members.forEach(m => { photoMap[m.name] = null; });
ok(guestMap['서기훈'] === 1, '게스트 표시가 붙는다');
ok(attendees.every(n => n in photoMap), '참석자 전원이 멤버 조회에 잡힌다 (멤버 카드·사진)');
ok(attendees.filter(n => guestMap[n]).length === 1, '참석자 중 게스트는 정확히 1명');

console.log(bad ? `\n${bad}건 실패` : '\n전부 통과');
process.exit(bad ? 1 : 0);
