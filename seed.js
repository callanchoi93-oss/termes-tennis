// seed.js — 데모 데이터 주입
import { db, initSchema, now, rid } from './db.js';
initSchema();

const t = now();
const users = [
  ['kakao','u1','곽주영','남성','경기 용인','tennis'],
  ['kakao','u2','이석용','남성','경기 용인','tennis'],
  ['naver','u3','정윤희','여성','경기 용인','tennis'],
  ['kakao','u4','김영민','남성','경기 성남','soccer'],
];
const insU = db.prepare(`INSERT OR IGNORE INTO users (provider,provider_id,name,gender,region,sport,anon_nick,created_at)
  VALUES (?,?,?,?,?,?,?,?)`);
users.forEach(u => insU.run(...u, u[2] + '봇', t));

const owner = db.prepare("SELECT id FROM users WHERE provider_id='u1'").get().id;
const c = db.prepare(`INSERT INTO clubs (name,sport,region,owner_id,created_at) VALUES (?,?,?,?,?)`)
  .run('용인 마츠 클럽','tennis','경기 용인',owner,t);
db.prepare(`INSERT INTO club_members (club_id,user_id,role,is_captain,jersey_no) VALUES (?,?, 'owner',1,10)`).run(rid(c), owner);

db.prepare(`INSERT INTO posts (user_id,sport,category,title,body,anon_nick,gender,region,views,likes,created_at)
  VALUES (?, 'tennis','자유','백핸드 슬라이스 팁','자꾸 떠요','씩씩한고슴도치','남성','경기 용인',14,3,?)`).run(owner, t);
db.prepare(`INSERT INTO posts (user_id,sport,category,title,body,anon_nick,gender,region,views,likes,created_at)
  VALUES (?, 'running','자랑','드디어 10km 50분 깼다','6개월 걸림 ㅠㅠ','호기심많은치타','여성','서울 강남',53,12,?)`).run(owner, t-300000);

// 오픈 예정 경기
const insOM = db.prepare('INSERT INTO open_matches (sport,dt,loc,fmt,gd,price,cap,min_cnt,created_at) VALUES (?,?,?,?,?,?,?,?,?)');
insOM.run('tennis','6/28 (토) 09:00','양재시민의숲 · 2번코트','단식','남자부',85000,8,6,t);
insOM.run('tennis','6/29 (일) 10:00','올림픽공원 · 4번코트','복식','남자부',65000,8,6,t);
insOM.run('tennis','7/05 (토) 14:00','반포 종합운동장','단식','여자부',75000,8,6,t);

// 클럽 일정
const insEV = db.prepare('INSERT INTO club_events (club_id,title,date,tag,created_by,created_at) VALUES (?,?,?,?,?,?)');
insEV.run(rid(c),'주말 정기전','6/28 (토) 09:00','정기',owner,t);
insEV.run(rid(c),'수요 번개','7/03 (수) 19:00','번개',owner,t);

console.log('✅ seed 완료: users/club/posts/open-matches/events 생성');
