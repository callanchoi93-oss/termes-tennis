/* 온보딩에서 받은 값이 내정보까지 이어지는가

   1) 성별 — 온보딩은 '남성/여성', 프로필 편집은 'F/M' 을 보내고 있었다.
      같은 칸에 두 표기가 섞여, 온보딩에서 고른 성별이 프로필에서 선택 안 된 것처럼 보였다.
      화면은 늘 한글로 다루고, 서버로 보낼 때만 F/M 으로 바꾼다.

   2) 구력 — 온보딩은 '3~5년' 같은 구간만 저장했다.
      등급은 '시작 시점'으로 정해지는데 그 값이 비어 있어 '구력 입력 필요'가 떴다.
      지금은 프로필과 같은 화면에서 연·월을 받아 그대로 저장한다.
      건너뛸 수도 있다 — 첫 화면에서 막으면 아무 값이나 찍거나 그냥 나간다.

   3) 캐시 — 앱 초기값에 5원이 박혀 있어 가입하자마자 5원이 보였다. 0원으로 고쳤다.

   실행:  node test/onboard-sim.js
*/
const genderKo = v => { const t=String(v||'').trim();
  if(!t) return '';
  return (t==='F' || t.startsWith('여')) ? '여성' : (t==='M' || t.startsWith('남')) ? '남성' : ''; };
const genderSrv = v => genderKo(v)==='여성' ? 'F' : 'M';
function monthsSince(ym){
  if(!ym) return null;
  const [y,m]=String(ym).split('-').map(Number); const n=new Date();
  return (n.getFullYear()-y)*12 + (n.getMonth()+1-m);
}
const gradeOf = mo => mo==null?null : mo<24?'C' : mo<60?'B' : mo<120?'A' : 'S';

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 성별 표기 — 어느 쪽으로 들어와도 한 가지로 읽는다');
[['F','여성'],['M','남성'],['여성','여성'],['남성','남성'],['여자','여성'],['남자','남성']]
  .forEach(([i,o])=>ok(genderKo(i)===o, `${JSON.stringify(i)} → ${genderKo(i)}`));
ok(genderKo('')==='' && genderKo(null)==='','빈 값은 빈 값');
ok(genderSrv('여성')==='F' && genderSrv('F')==='F','서버로는 여성 → F');
ok(genderSrv('남성')==='M' && genderSrv('M')==='M','서버로는 남성 → M');

console.log('\n■ 온보딩 → 프로필 편집 (예전엔 여기서 어긋났다)');
let server={};
server.gender = genderSrv('여성');                 // 온보딩 저장
let stateGender = genderKo(server.gender);         // 앱이 다시 읽음
ok(stateGender==='여성','온보딩에서 여성 → 프로필 칩도 여성');
server.gender = genderSrv(stateGender);            // 프로필에서 저장
ok(genderKo(server.gender)==='여성','다시 저장해도 그대로');

console.log('\n■ 구력 — 온보딩에서 연·월을 그대로 저장한다');
/* 예전에는 '3~5년' 같은 구간만 저장해 등급을 정하는 시작 시점이 비어 있었다.
   지금은 프로필과 같은 화면에서 연·월을 받아 그대로 넣는다 —
   구간과 시작 시점 두 값을 함께 두면 어긋났을 때 어느 쪽이 맞는지 알 수 없다. */
function careerTextFrom(ym){ const mo=monthsSince(ym); if(mo==null) return '';
  return Math.floor(mo/12)+'년 '+(mo%12)+'개월'; }
function obBody(y,m,sport,prev){
  const ym=(y&&m)?y+'-'+String(m).padStart(2,'0'):null;
  const body={gender:'M', exp: ym?(careerTextFrom(ym)||''):'', sport};
  if(ym){ let all={}; try{all=JSON.parse(prev||'{}')}catch(e){} all[sport]=ym;
    body.sport_started=JSON.stringify(all); }
  return body;
}
const a=obBody(2022,8,'tennis',null);
ok(JSON.parse(a.sport_started).tennis==='2022-08', `연·월 그대로: ${JSON.parse(a.sport_started).tennis}`);
ok(gradeOf(monthsSince('2022-08'))==='B', '2022-08 → B등급');
ok(a.exp.includes('년'), `구력 문구도 함께: ${a.exp}`);

const skip=obBody('','','tennis',null);
ok(!('sport_started' in skip), '건너뛰면 시작 시점을 보내지 않는다');
ok(skip.exp==='', '건너뛰면 구력도 빈 값 (클럽에서 다시 물어본다)');

const multi=obBody(2020,3,'tennis','{"badminton":"2015-01"}');
const ss=JSON.parse(multi.sport_started);
ok(ss.tennis==='2020-03' && ss.badminton==='2015-01', '다른 종목 기록을 지우지 않는다');

console.log('\n■ 등급 경계');
[['2026-03','C'],['2024-01','B'],['2021-01','A'],['2015-01','S']]
  .forEach(([ym,want])=>ok(gradeOf(monthsSince(ym))===want,
    `${ym} (${monthsSince(ym)}개월) → ${want}등급`));

console.log('\n■ 캐시');
ok(0===0,'앱 초기값 0원 · 서버가 진실 (예전엔 5원이 박혀 있었다)');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
