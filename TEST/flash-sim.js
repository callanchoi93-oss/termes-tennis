/* 번개 모임과 대진 짜기 권한

   번개는 클럽 회원 누구나 열 수 있다. 그런데 대진은 임원만 짤 수 있으면
   번개를 연 사람이 임원을 붙잡아야 모임이 굴러간다.
   그래서 '자기가 연 번개'에 한해 대진을 짤 수 있게 열었다.

   정기 모임과 모임 미지정 대진은 그대로 임원만이다 —
   클럽 전체가 쓰는 것이라 아무나 고치면 안 된다.

   실행:  node test/flash-sim.js
*/
function canCreateEvent(role, tag, isMember){
  if(tag==='번개') return !!isMember;
  return role==='owner' || role==='officer';
}
function canEditBracket(role, uid, ev){
  if(role==='owner' || role==='officer') return true;
  if(!ev) return false;                       // 모임 미지정 대진은 임원만
  return ev.tag==='번개' && ev.created_by===uid;
}

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 모임 열기');
ok(canCreateEvent('member','번개',true)===true,'정회원이 번개를 연다');
ok(canCreateEvent('guest','번개',true)===true,'게스트도 회원이면 번개를 연다');
ok(canCreateEvent('member','번개',false)===false,'클럽 회원이 아니면 못 연다');
ok(canCreateEvent('member','정기',true)===false,'정회원은 정기 모임을 못 연다');
ok(canCreateEvent('officer','정기',true)===true,'임원은 정기 모임을 연다');

console.log('\n■ 대진 짜기');
const flashA={tag:'번개', created_by:10};
const flashB={tag:'번개', created_by:20};
const regular={tag:'정기', created_by:1};
ok(canEditBracket('member',10,flashA)===true,'번개를 연 사람 → 자기 번개 대진');
ok(canEditBracket('member',20,flashA)===false,'다른 회원 → 남의 번개 대진 불가');
ok(canEditBracket('member',10,flashB)===false,'남이 연 번개는 못 짠다');
ok(canEditBracket('member',10,regular)===false,'정회원 → 정기 모임 대진 불가');
ok(canEditBracket('officer',99,flashA)===true,'임원 → 남의 번개도 가능');
ok(canEditBracket('owner',99,regular)===true,'클럽장 → 정기 모임 가능');
ok(canEditBracket('member',10,null)===false,'모임 미지정 대진은 임원만');

console.log('\n■ 경계');
ok(canEditBracket('member',10,{tag:'번개',created_by:'10'})===false,
   '만든 사람 id 는 문자열·숫자를 구분한다 (서버는 같은 형으로 비교)');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
