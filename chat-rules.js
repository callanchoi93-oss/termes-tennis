/* chat-rules.js — 대화 권한 규칙 한 곳
   ───────────────────────────────────────────────────────────────
   server.js 와 test/chat-sim.js 가 **같은 함수**를 쓴다.
   예전엔 테스트가 이 SQL 을 베껴 갖고 있었는데, 서버만 고치고 테스트를
   안 고치면 시뮬은 통과하는데 실서비스는 틀린 상태가 됐다.
   (실제로 DM_COST 를 안 옮겨서 있지도 않은 과금을 검증한 적이 있다.)

   db 를 인자로 받는다 — 서버는 실 DB 를, 테스트는 메모리 DB 를 넘긴다.
   better-sqlite3 와 node:sqlite 는 prepare().get/.all/.run 이 같아 그대로 쓴다.
   ─────────────────────────────────────────────────────────────── */

/* 1:1 랭크가 '성사됐다'고 보는 상태.
   requested 는 한쪽이 누르기만 한 것이라 제외한다 — 이걸 인정하면
   아무에게나 신청을 걸어 대화를 여는 우회로가 된다. */
export const DUEL_LIVE = ['accepted', 'scored', 'confirmed'];

export function makeChatRules(db) {
  const q = (sql) => db.prepare(sql);

  /* ── 클럽 ── */
  /* 가입 신청 중(pending)도 참이다. '이미 신청했는가' 판정에는 이게 맞다. */
  function isMember(clubId, uid) {
    return !!q('SELECT 1 FROM club_members WHERE club_id=? AND user_id=?').get(clubId, uid);
  }
  /* 승인된 회원만. 단체방처럼 승인된 사람만 들어가야 하는 곳에 쓴다.
     안읽음 집계(/me/unread)가 active 만 세므로, pending 을 들여보내면
     글은 쓰는데 배지는 안 잡히는 어긋남이 생긴다. */
  function isActiveMember(clubId, uid) {
    return !!q(`SELECT 1 FROM club_members WHERE club_id=? AND user_id=?
      AND (status IS NULL OR status='active')`).get(clubId, uid);
  }
  function activeMembers(clubId) {
    return q(`SELECT COUNT(*) n FROM club_members WHERE club_id=?
      AND (status IS NULL OR status='active')`).get(clubId).n;
  }

  /* ── 1:1 ── */
  function threadExists(a, b) {
    return !!q(`SELECT 1 FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) LIMIT 1`)
      .get(a, b, b, a);
  }

  /* 새 대화를 걸 수 있는 사이인지 — 허용 목록으로 관리한다.

     열어두는 관계
     · 같은 클럽 회원 — 이미 서로 아는 사이다
     · 1:1 랭크가 성사된 상대 — 코트·일시를 정하려면 말이 통해야 한다
     · 매니저 ↔ 그 매치 참가자 — 매치 연락은 매니저를 거친다

     막는 관계
     · 오픈매치를 같이 뛴 것뿐인 사이. 무작위로 모인 자리라 참가자 명단이
       비공개고, 여기서 대화를 트게 두면 명단이 사실상 공개되는 셈이 된다.
     · 같은 개인리그에 참가했을 뿐인 사이. 리그는 수백 명이 함께 올라오는
       목록이라 이것만으로 열면 랭킹이 곧 연락처 명부가 된다. 붙고 나서 이야기한다. */
  function shareClub(a, b) {
    return !!q(`SELECT 1 FROM club_members m1 JOIN club_members m2 ON m1.club_id=m2.club_id
      WHERE m1.user_id=? AND m2.user_id=?
        AND (m1.status IS NULL OR m1.status='active')
        AND (m2.status IS NULL OR m2.status='active') LIMIT 1`).get(a, b);
  }
  function duelPair(a, b) {
    const marks = DUEL_LIVE.map(() => '?').join(',');
    try {
      return !!q(`SELECT 1 FROM duels WHERE status IN (${marks})
        AND ((a_id=? AND b_id=?) OR (a_id=? AND b_id=?)) LIMIT 1`)
        .get(...DUEL_LIVE, a, b, b, a);
    } catch (e) { return false; }
  }
  function mgrOfSameMatch(a, b) {
    try {
      return !!q(`SELECT 1 FROM open_matches m JOIN open_match_joins j ON j.match_id=m.id
        WHERE (m.manager_id=? AND j.user_id=?) OR (m.manager_id=? AND j.user_id=?) LIMIT 1`)
        .get(a, b, b, a);
    } catch (e) { return false; }
  }
  function canStartDM(a, b) {
    if (!a || !b || a === b) return false;
    return shareClub(a, b) || duelPair(a, b) || mgrOfSameMatch(a, b);
  }
  /* 왜 되는지/안 되는지 — 디버깅과 테스트 리포트용 */
  function whyCanStartDM(a, b) {
    if (!a || !b || a === b) return null;
    if (shareClub(a, b)) return 'club';
    if (duelPair(a, b)) return 'duel';
    if (mgrOfSameMatch(a, b)) return 'manager';
    return null;
  }

  return { isMember, isActiveMember, activeMembers,
           threadExists, shareClub, duelPair, mgrOfSameMatch, canStartDM, whyCanStartDM };
}
