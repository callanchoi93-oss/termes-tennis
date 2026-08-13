/* 여성/남성 클럽 배지 판정 테스트

   배지는 선언이 아니라 실제 명단으로 판정한다.
     · 전원 같은 성별 + 3명 이상  → 배지 (3명 미만은 우연일 수 있다)
     · 게스트는 세지 않는다 (서버 쿼리에서 제외)
     · 성별 미입력 회원이 한 명이라도 있으면 '전원'이라 말할 수 없다 → 배지 없음
     · 명단으로 판정이 안 될 때만 클럽이 밝힌 값(gender_pref)을 쓴다

   실행:  node test/gender-sim.js
*/
// /clubs 응답 → state.clubs 매핑 → 배지 판정 전체 경로
function mapClub(c){                     // index.html loadPublicData 와 동일
  return { id:c.id, n:c.name, r:c.region||'', m:c.members||0, sport:c.sport||'',
    gender_pref:c.gender_pref||'', meet_time:c.meet_time||'', age_bands:c.age_bands||'' };
}
function clubGenderTag(c){
  const pref=String((c&&(c.gender_pref||c.gender))||'').trim();
  const mixed=/남녀|전체|무관|모두/.test(pref);
  if(!mixed){
    if(/^여/.test(pref)) return {l:'여성 클럽'};
    if(/^남/.test(pref)) return {l:'남성 클럽'};
  } else return null;
  if(pref) return null;
  const g=(c&&c.genders)||null;
  if(g){ const v=Object.values(g);
    if(v.length>=3){ if(v.every(x=>x==='F')) return {l:'여성 클럽'};
                     if(v.every(x=>x==='M')) return {l:'남성 클럽'}; } }
  return null;
}
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 서버 행 → 화면 배지');
const rows=[
 {id:1,name:'제이온',gender_pref:'여자',   want:'여성 클럽'},
 {id:2,name:'라온',  gender_pref:'남자',   want:'남성 클럽'},
 {id:3,name:'공:감', gender_pref:'남녀 모두',want:null},
 {id:4,name:'한터',  gender_pref:null,      want:null},   // 예전에 만든 클럽
 {id:5,name:'윙스',  gender_pref:'',        want:null},
];
rows.forEach(r=>{
  const t=clubGenderTag(mapClub(r)); const got=t?t.l:null;
  ok(got===r.want, `${r.name} (gender_pref=${JSON.stringify(r.gender_pref)}) → ${got||'배지 없음'}`);
});

console.log('\n■ 클럽 정보에서 성별을 바꾸면');
const club=mapClub({id:4,name:'한터',gender_pref:null});
ok(clubGenderTag(club)===null,'바꾸기 전 · 배지 없음');
club.gender_pref='여자';                       // 저장 시 캐시 갱신
ok(clubGenderTag(club).l==='여성 클럽','바꾼 뒤 · 여성 클럽');
club.gender_pref='남녀 모두';
ok(clubGenderTag(club)===null,'다시 혼성으로 → 배지 사라짐');


console.log('\n■ 명단 기반 판정 (서버가 내려주는 g_f / g_m / g_unknown)');
function tag2(c){
  const f=+c.g_f||0,m=+c.g_m||0,u=+c.g_unknown||0;
  if(!u&&f+m>=3){ if(m===0&&f>=3)return '여성 클럽'; if(f===0&&m>=3)return '남성 클럽'; }
  const p=String(c.gender_pref||'').trim();
  if(p&&!/남녀|전체|무관|모두/.test(p)){ if(/^여/.test(p))return '여성 클럽'; if(/^남/.test(p))return '남성 클럽'; }
  return null;
}
let b2=0; const k=(c,m)=>{ if(!c){b2++;console.log('FAIL',m);} else console.log('ok  ',m); };
k(tag2({g_f:3,g_m:0,g_unknown:0})==='여성 클럽','전원 여성 3명 → 여성 클럽');
k(tag2({g_f:12,g_m:0,g_unknown:0})==='여성 클럽','전원 여성 12명 → 여성 클럽');
k(tag2({g_f:2,g_m:0,g_unknown:0})===null,'여성 2명뿐 → 아직 판정하지 않음');
k(tag2({g_f:0,g_m:5,g_unknown:0})==='남성 클럽','전원 남성 5명 → 남성 클럽');
k(tag2({g_f:3,g_m:1,g_unknown:0})===null,'남성이 한 명이라도 있으면 배지 없음');
k(tag2({g_f:3,g_m:0,g_unknown:1})===null,'성별 미입력이 있으면 단정하지 않음');
k(tag2({g_f:0,g_m:0,g_unknown:0})===null,'회원이 없어도 터지지 않음');
console.log('\n■ 명단으로 판정이 안 될 때만 선언을 쓴다');
k(tag2({g_f:2,g_m:0,g_unknown:0,gender_pref:'여자'})==='여성 클럽','여성 2명 + 여자 선언 → 여성 클럽');
k(tag2({g_f:3,g_m:0,g_unknown:0,gender_pref:'남녀 모두'})==='여성 클럽','명단이 확실하면 명단이 이긴다');
k(tag2({g_f:1,g_m:1,g_unknown:0,gender_pref:'남녀 모두'})===null,'혼성 선언 + 혼성 명단 → 배지 없음');
console.log(b2?`\n${b2}건 실패`:'\n전부 통과');
process.exit(b2?1:0);
