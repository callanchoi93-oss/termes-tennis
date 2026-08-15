/* 참석 인원 세기 — 게스트를 두 번 세지 않는가

   게스트를 추가하면 CB2_GUESTS 에 넣으면서 CB2_SEL 에도 그 id 를 넣는다.
   그래서 CB2_SEL.size 만 세면 되는데, 예전엔 CB2_GUESTS.length 를 또 더했다.
   그 결과 18명 모임이 "35명 · 3코트는 전원 4경기로 안 떨어져요" 로 막혔다.

   cb2All() 도 마찬가지다 — 명부와 게스트를 이미 합쳐서 돌려준다.

   실행:  node test/head-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 코드에 두 번 세는 자리가 남아 있나');
ok(!/CB2_SEL\.size\s*\+\s*CB2_GUESTS\.length/.test(SRC),
   'CB2_SEL.size + CB2_GUESTS.length 가 없다');
{ /* cb2All() 을 돌면서 CB2_GUESTS 를 또 더하는 자리 */
  const re=/cb2All\(\)\.forEach[\s\S]{0,400}?CB2_GUESTS\.forEach/g;
  ok(!re.test(SRC), 'cb2All() 을 세고 나서 CB2_GUESTS 를 또 더하지 않는다');
}
ok(/function cb2Head\(\)\{ return CB2_SEL\.size; \}/.test(SRC.replace(/\s+/g,' ')
   .replace('function cb2Head(){ return CB2_SEL.size; }','function cb2Head(){ return CB2_SEL.size; }'))
   || /return CB2_SEL\.size;/.test(SRC), 'cb2Head 는 CB2_SEL.size 만 센다');

console.log('\n■ 실제로 세어본다 (회원 16 + 게스트 2 = 18명)');
{
  const CB2_SEL=new Set(), CB2_GUESTS=[];
  const roster=[...Array(16).keys()].map(i=>({user_id:'u'+i,name:'회원'+i,gender:i<12?'M':'F'}));
  roster.forEach(p=>CB2_SEL.add(String(p.user_id)));
  [['g1','게스트A','M'],['g2','게스트B','F']].forEach(([gid,name,gender])=>{
    CB2_GUESTS.push({gid,name,gender}); CB2_SEL.add(gid);      // 실제 코드와 같게 둘 다
  });
  const cb2All=()=>[...roster,...CB2_GUESTS.map(g=>({user_id:g.gid,name:g.name,gender:g.gender}))];
  const isFem=v=>String(v||'').trim()==='F';
  const head=()=>CB2_SEL.size;
  const sex=()=>{ let m=0,f=0;
    cb2All().forEach(p=>{ if(!CB2_SEL.has(String(p.user_id))) return; isFem(p.gender)?f++:m++; });
    return {m,f}; };
  ok(head()===18, `인원 ${head()}명`);
  const s=sex();
  ok(s.m===13 && s.f===5, `남 ${s.m} · 여 ${s.f}`);
  ok(s.m+s.f===head(), '남녀 합이 인원과 같다');
  ok(CB2_SEL.size+CB2_GUESTS.length===20, '옛 방식이었다면 20명 (두 번 셈)');
}

console.log('\n■ 게스트 없이도 맞는가');
{
  const CB2_SEL=new Set();
  [...Array(18).keys()].forEach(i=>CB2_SEL.add('u'+i));
  ok(CB2_SEL.size===18, '회원만 18명 → 18명');
}

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
