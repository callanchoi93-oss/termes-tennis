/* 코트가 비지 않는 대진

   한 코트가 먼저 끝났는데 남은 경기가 전부 '지금 뛰는 사람'을 끼고 있으면
   그 코트는 놀 수밖에 없다. 8/14 모임에서 3코트가 그랬다 —
   쉬는 사람이 10명인데도 넣을 경기가 하나도 없었다.

   해법: 한 바퀴에 쉬는 사람 중 넷으로 다음 바퀴의 한 경기를 미리 짜둔다.
   그 넷은 지금 코트에 없는 게 확실하니 어느 코트가 먼저 끝나도 바로 넣을 수 있다.

   함께 지켜야 하는 것 — 전원 4경기 · 남복/혼복/여복으로 떨어짐 · 같은 파트너 안 겹침.

   실행:  node test/idlefree-sim.js
*/
const fs=require('fs'), path=require('path');
const isFem=v=>{const t=String((v&&v.gender!==undefined?v.gender:v)||'').trim();
  return t==='F'||t.startsWith('여');};
/* index.html 의 cbPlanIdleFree 를 그대로 떼어 쓴다 — 사본이 어긋나지 않게 */
const src=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const st=src.indexOf('function cbPlanIdleFree');
const en=src.indexOf('function cbPack(', st);
if(st<0||en<0){ console.log('FAIL cbPlanIdleFree 를 찾지 못했습니다'); process.exit(1); }
const plan=new Function('isFem', src.slice(st,en)+'\nreturn cbPlanIdleFree;')(isFem);

const mk=(nM,nF)=>[...Array(nM).keys()].map(i=>({id:'M'+i,name:'M'+i,gender:'M'}))
  .concat([...Array(nF).keys()].map(i=>({id:'F'+i,name:'F'+i,gender:'F'})));

function judge(out, courts){
  if(!out) return null;
  const R=Math.max(...out.map(g=>g.r));
  const all=g=>[...g.t1,...g.t2];
  const cnt={}; out.forEach(g=>all(g).forEach(p=>cnt[p.name]=(cnt[p.name]||0)+1));
  let clash=0;
  for(let r=1;r<=R;r++){ const s=new Set();
    out.filter(g=>g.r===r).forEach(g=>all(g).forEach(p=>{ if(s.has(p.name))clash++; s.add(p.name); })); }
  let odd=0; out.forEach(g=>{ const f=all(g).filter(p=>isFem(p.gender)).length;
    if(f!==0&&f!==2&&f!==4) odd++; });
  let idle=0,cases=0;
  for(let r=1;r<R;r++) for(let d=1;d<=courts;d++){
    const busy=new Set(out.filter(g=>g.r===r&&g.c!==d).flatMap(g=>all(g).map(p=>p.name)));
    cases++;
    if(!out.filter(g=>g.r>r).some(g=>all(g).every(p=>!busy.has(p.name)))) idle++; }
  const pair={}; out.forEach(g=>[g.t1,g.t2].forEach(t=>{
    const k=[t[0].name,t[1].name].sort().join('-'); pair[k]=(pair[k]||0)+1; }));
  const games=[...new Set(Object.values(cnt))];
  return { R, n:out.length, games, clash, odd, idle, cases,
           dup:Object.values(pair).filter(v=>v>1).length };
}

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 8/14 인원 (남13 여5 · 3코트)');
{ const r=judge(plan(mk(13,5),3,1),3);
  ok(r!==null, '대진이 나온다');
  ok(r.games.length===1 && r.games[0]===4, `전원 ${r.games.join(',')}경기`);
  ok(r.clash===0, '같은 바퀴에 두 코트로 들어간 사람 없음');
  ok(r.odd===0, '모든 경기가 남복·혼복·여복으로 떨어짐');
  ok(r.idle===0, `코트 막힘 ${r.idle}/${r.cases}`);
  ok(r.dup===0, `같은 파트너 두 번 ${r.dup}쌍`);
}

console.log('\n■ 여러 인원 구성');
[[13,5,3],[12,6,3],[10,8,3],[14,4,3],[16,2,3],[8,4,2],[6,6,2],[10,2,2],[16,8,3],[20,4,4]]
 .forEach(([m,f,c])=>{
  const r=judge(plan(mk(m,f),c,1),c);
  if(!r){ bad++; console.log(`FAIL 남${m} 여${f} ${c}코트 — 못 만듦`); return; }
  const good = r.games.length===1 && r.games[0]===4 && !r.clash && !r.odd && !r.idle;
  ok(good, `남${String(m).padStart(2)} 여${String(f).padStart(2)} (${m+f}명) ${c}코트 → ` +
    `${r.R}바퀴 · 막힘 ${r.idle}/${r.cases} · 파트너겹침 ${r.dup}쌍`);
});

console.log('\n■ 규칙을 쓸 수 없는 성비 — null 을 돌려주고 기존 방식으로 물러난다');
/* 남9 여3 · 12명 2코트: 매 바퀴 8명 뛰고 4명 쉬는데,
   여성 3명이 4경기씩 하려면 매 바퀴 정확히 2명이 뛰어야 한다.
   그러면 쉬는 넷은 늘 '여1 남3' 이라 남복도 혼복도 여복도 될 수 없다.
   수학적으로 이 규칙을 적용할 수 없는 성비다. */
ok(plan(mk(9,3),2,1)===null, '남9 여3 (12명) 2코트 — 쉬는 넷이 늘 여1남3');

console.log('\n■ 안 되는 조합은 null 을 돌려준다 (기존 방식으로 물러남)');
ok(plan(mk(9,3),3,1)===null,  '12명 3코트 — 쉬는 사람 0명');
ok(plan(mk(6,2),2,1)===null,  '8명 2코트 — 쉬는 사람 0명');
ok(plan(mk(10,4),3,1)===null, '14명 3코트 — 바퀴가 안 떨어짐');
ok(plan(mk(2,2),3,1)===null,  '4명 3코트 — 인원 부족');

console.log('\n■ 빠르게 끝나는가');
{ const t=Date.now(); plan(mk(13,5),3,1); const ms=Date.now()-t;
  ok(ms<1500, `18명 3코트 ${ms}ms`); }

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
