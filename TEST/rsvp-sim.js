/* 모임 참석 응답(RSVP) 규칙 테스트

   ① 같은 버튼을 한 번 더 누르면 응답이 해제된다 (참석/불참/미정 모두)
   ② 클럽을 떠나면 다가올 모임의 응답이 사라진다 — 출석 확인된 지난 기록은 남는다
   ③ 예전에 쌓인 유령 행이 있어도 명단 조회에서 걸러진다

   실행:  node test/rsvp-sim.js        (Node 22 이상 — node:sqlite) */
import { DatabaseSync } from 'node:sqlite';
const db=new DatabaseSync(':memory:');
db.exec(`
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE clubs(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE club_members(club_id INTEGER,user_id INTEGER,role TEXT,status TEXT);
CREATE TABLE club_events(id INTEGER PRIMARY KEY, club_id INTEGER, title TEXT, date TEXT);
CREATE TABLE event_attendees(id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER,
  user_id INTEGER, status TEXT, showed INTEGER);
`);
db.exec(`INSERT INTO users VALUES (1,'최민혁'),(2,'강태민'),(3,'이석용');
INSERT INTO clubs VALUES (1,'테르메스');
INSERT INTO club_members VALUES (1,1,'owner','active'),(1,2,'member','active'),(1,3,'member','active');
INSERT INTO club_events VALUES (10,1,'금요모임','8/21'),(11,1,'지난모임','7/10');`);

const goingCount=e=>db.prepare("SELECT COUNT(*) n FROM event_attendees WHERE event_id=? AND (status IS NULL OR status='going')").get(e).n;
function rsvp(eid,uid,st){
  const has=db.prepare('SELECT id,status FROM event_attendees WHERE event_id=? AND user_id=?').get(eid,uid);
  const cur=has?(has.status===null?'going':has.status):null;
  if(cur===st){ db.prepare('DELETE FROM event_attendees WHERE id=?').run(has.id);
    return {status:null,count:goingCount(eid)}; }
  if(has) db.prepare('UPDATE event_attendees SET status=? WHERE id=?').run(st,has.id);
  else db.prepare('INSERT INTO event_attendees (event_id,user_id,status) VALUES (?,?,?)').run(eid,uid,st);
  return {status:st,count:goingCount(eid)};
}
function purgeClubRsvp(cid,uid){
  return db.prepare(`DELETE FROM event_attendees WHERE user_id=? AND showed IS NULL
    AND event_id IN (SELECT id FROM club_events WHERE club_id=?)`).run(uid,cid).changes;
}
function listGoing(cid,eid){
  return db.prepare(`SELECT u.name FROM event_attendees ea JOIN users u ON u.id=ea.user_id
    JOIN club_members cm ON cm.user_id=ea.user_id AND cm.club_id=? AND (cm.status IS NULL OR cm.status='active')
    WHERE ea.event_id=? AND (ea.status IS NULL OR ea.status='going') ORDER BY u.name`).all(cid,eid).map(r=>r.name);
}
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 토글');
ok(rsvp(10,1,'going').status==='going','참석 누르면 참석');
ok(rsvp(10,1,'going').status===null,'참석 한 번 더 → 해제');
ok(goingCount(10)===0,'해제 후 참석 인원 0');
ok(rsvp(10,1,'absent').status==='absent','불참 누르면 불참');
ok(rsvp(10,1,'undecided').status==='undecided','불참 → 미정 (다른 버튼은 전환)');
ok(rsvp(10,1,'undecided').status===null,'미정 한 번 더 → 해제');
ok(db.prepare('SELECT COUNT(*) n FROM event_attendees WHERE event_id=10 AND user_id=1').get().n===0,'해제하면 행 자체가 사라짐');
// 옛 데이터: status NULL = going 으로 간주
db.prepare('INSERT INTO event_attendees (event_id,user_id,status) VALUES (10,3,NULL)').run();
ok(rsvp(10,3,'going').status===null,'옛 데이터(status NULL)도 참석 한 번 더 → 해제');

console.log('\n■ 탈퇴 정리');
rsvp(10,2,'going'); rsvp(11,2,'going');
db.prepare("UPDATE event_attendees SET showed=1 WHERE event_id=11 AND user_id=2").run();  // 지난 모임 출석 확인됨
ok(listGoing(1,10).includes('강태민'),'탈퇴 전 명단에 있음');
db.prepare('DELETE FROM club_members WHERE club_id=1 AND user_id=2').run();
const n=purgeClubRsvp(1,2);
ok(n===1,`다가올 모임 응답만 지움 (지운 행 ${n}건)`);
ok(!listGoing(1,10).includes('강태민'),'탈퇴 후 명단에서 사라짐');
ok(db.prepare('SELECT COUNT(*) n FROM event_attendees WHERE event_id=11 AND user_id=2').get().n===1,
   '출석 확인된 지난 기록은 남음 (출석률 통계 보존)');

console.log('\n■ 옛 데이터 방어 (purge 없이 탈퇴한 경우)');
db.prepare("INSERT INTO event_attendees (event_id,user_id,status) VALUES (10,99,'going')").run();
db.prepare("INSERT INTO users VALUES (99,'탈퇴한 회원')").run();
ok(!listGoing(1,10).includes('탈퇴한 회원'),'회원이 아니면 명단 조회에서 걸러짐');
ok(listGoing(1,10).length===0,`명단 인원 ${listGoing(1,10).length}명 — 유령 없음`);

console.log(bad? `\n${bad}건 실패` : '\n전부 통과');
process.exit(bad?1:0);
