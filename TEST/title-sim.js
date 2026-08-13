/* 직책(title) · 권한(role) 이름표 규칙 테스트

   role  = 앱에서 무엇을 할 수 있는가 (owner/officer/member/guest)
   title = 클럽 안에서 무슨 일을 맡았는가 (총무·경기이사·재무…)
   총무가 임원 권한 없이 회비만 챙기는 클럽도 있어서 둘은 따로 움직인다.

   실행:  node test/title-sim.js
*/
// 직책/권한 이름표 규칙 확인
const ROLE_LABEL={owner:'회장',officer:'임원',member:'정회원',guest:'게스트'};
function memberLabel(m){
  const t=(m&&m.title||'').trim();
  if(t) return t;
  const r=(m&&m.role)||'member';
  return (r==='owner'||r==='officer'||r==='guest')?ROLE_LABEL[r]:'';
}
function memberLabelCls(m){
  const r=(m&&m.role)||'member';
  return r==='owner'?'ow':r==='guest'?'gu':'of';
}
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 이름표');
ok(memberLabel({role:'owner'})==='회장','회장 · 직책 없음 → 회장');
ok(memberLabel({role:'owner',title:'회장'})==='회장','회장 · 직책 회장 → 회장');
ok(memberLabel({role:'officer'})==='임원','임원 · 직책 없음 → 임원');
ok(memberLabel({role:'officer',title:'총무'})==='총무','임원 · 총무 → 총무 (권한보다 직책)');
ok(memberLabel({role:'officer',title:'경기이사'})==='경기이사','임원 · 경기이사 → 경기이사');
ok(memberLabel({role:'member'})==='','정회원 · 직책 없음 → 이름표 없음');
ok(memberLabel({role:'member',title:'총무'})==='총무','정회원 · 총무 → 총무 (권한 없어도 직책은 표시)');
ok(memberLabel({role:'guest'})==='게스트','게스트 → 게스트');
ok(memberLabel({role:'guest',title:''})==='게스트','빈 직책은 무시');
ok(memberLabel({role:'officer',title:'  '})==='임원','공백만 있는 직책은 무시');

console.log('\n■ 색');
ok(memberLabelCls({role:'owner',title:'회장'})==='ow','회장 직책 → 코랄');
ok(memberLabelCls({role:'officer',title:'총무'})==='of','임원 총무 → 회색');
ok(memberLabelCls({role:'member',title:'총무'})==='of','권한 없는 총무 → 회색 (임원과 같게)');
ok(memberLabelCls({role:'guest'})==='gu','게스트 → 청회색');

console.log('\n■ 권한과 직책은 따로 움직인다');
const m={role:'officer',title:'총무'};
m.role='member';                                  // 임원 해제
ok(memberLabel(m)==='총무','임원 해제해도 총무는 유지');
m.title=null;                                     // 직책 뗌
ok(memberLabel(m)==='','직책 떼면 이름표 사라짐');


console.log('\n■ 클럽 규모 판정');
function clubScale(n){ return n>=40?'large':n>=15?'medium':'small'; }
const SCALE_TITLES={small:1,medium:4,large:8};
function canSetTitle(scale,myRole,myTitle){
  if(myRole==='owner') return true;
  return scale==='large' && myRole==='officer' && (myTitle||'')==='부회장';
}
let bad2=0; const ok2=(c,m)=>{ if(!c){bad2++;console.log('FAIL',m);} else console.log('ok  ',m); };
ok2(clubScale(1)==='small' && clubScale(14)==='small','1~14명 → 소규모');
ok2(clubScale(15)==='medium' && clubScale(39)==='medium','15~39명 → 중규모');
ok2(clubScale(40)==='large' && clubScale(200)==='large','40명 이상 → 대규모');
ok2(clubScale(0)==='small','0명이어도 터지지 않음');

console.log('\n■ 기본 노출 직책 수');
ok2(SCALE_TITLES.small===1,'소규모 1개');
ok2(SCALE_TITLES.medium===4,'중규모 4개');
ok2(SCALE_TITLES.large===8,'대규모 8개 (전체)');
const P=['총무','경기이사','재무이사','부회장','홍보이사','섭외이사','훈련이사','감사'];
ok2(P.slice(0,SCALE_TITLES.small)[0]==='총무','소규모에 보이는 하나는 총무');
ok2(P.slice(0,SCALE_TITLES.medium).includes('경기이사'),'중규모에 경기이사 포함');

console.log('\n■ 직책을 정할 수 있는 사람');
ok2(canSetTitle('small','owner')===true,'소규모 · 클럽장 → 가능');
ok2(canSetTitle('small','officer','부회장')===false,'소규모 · 부회장 → 불가');
ok2(canSetTitle('medium','officer','부회장')===false,'중규모 · 부회장 → 불가');
ok2(canSetTitle('large','officer','부회장')===true,'대규모 · 부회장 → 가능');
ok2(canSetTitle('large','officer','총무')===false,'대규모 · 총무 → 불가');
ok2(canSetTitle('large','member','부회장')===false,'권한 없는 부회장 직책만으로는 불가');

console.log('\n■ 지금 맡은 직책은 접혀도 보인다');
function shownList(scale, current, more){
  const n = more ? P.length : SCALE_TITLES[scale];
  const list = P.slice(0,n);
  if(current && !list.includes(current)) list.unshift(current);
  return list;
}
ok2(shownList('small','감사',0).includes('감사'),'소규모인데 감사를 맡고 있으면 감사가 보인다');
ok2(shownList('small',null,0).length===1,'직책 없으면 하나만');
ok2(shownList('small',null,1).length===8,'더 보기를 누르면 전체');

console.log(bad2?`\n${bad2}건 실패`:'\n전부 통과');
process.exit((bad||bad2)?1:0);
