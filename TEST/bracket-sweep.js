/* 대진 전수 검사 — 겹치는 대진이 나오는가

   대진은 이 앱에서 가장 중요한 부분이다. 한 사람이 같은 바퀴에 두 코트로 들어가면
   코트에서 진행이 통째로 꼬인다(8/14 에 실제로 그랬다).

   index.html 의 편성 함수를 그대로 떼어내 인원·코트·성비·늦참을 바꿔가며 돌린다.
   재구현이 아니라 실제 코드라, 편성기를 고치면 이 검사도 같이 따라간다.

   검사 항목
     ① 같은 바퀴에 같은 사람이 두 코트     ← 가장 중요
     ② 한 바퀴에 같은 코트 두 경기
     ③ 전원 정확히 4경기
     ④ 늦참자가 합류 전에 나오지 않는가
     ⑤ 한 경기는 네 명

   실행:  node test/bracket-sweep.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const isFem=v=>{const t=String((v&&v.gender!==undefined?v.gender:v)||'').trim();
  return t==='F'||t.startsWith('여');};
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));

/* 필요한 함수를 이름으로 찾아 통째로 떼어온다 */
function grab(name){
  let m=new RegExp('^function '+name+'\\s*\\(','m').exec(SRC);
  if(m){ let d=0,i=SRC.indexOf('{',m.index);
    for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d) return SRC.slice(m.index,j+1);} } }
  m=new RegExp('^const '+name+'\\s*=','m').exec(SRC);
  if(m){ let d=0; for(let j=m.index;j<SRC.length;j++){ const ch=SRC[j];
    if('([{'.includes(ch))d++; else if(')]}'.includes(ch))d--;
    else if(ch===';'&&!d) return SRC.slice(m.index,j+1); } }
  return null;
}
const NEED=['HN_GV','hnF','hnG','hnK','hnCombos','_rng','HANUL_AB','hnPlanAB',
  'hnPlanOnce','hnEval','hnPolish','cbPackExact','cbEaseIdle','cbPlanIdleFree',
  'cbPack','hnPlanGroup','cbCourtOk','lateMax'];
const parts=NEED.map(grab);
const miss=NEED.filter((n,i)=>!parts[i]);
if(miss.length){ console.log('FAIL 함수를 못 찾았습니다:', miss.join(', ')); process.exit(1); }
const F=new Function('isFem','clamp', parts.join('\n')+
  '\nreturn {hnPlanGroup,cbPack,cbPlanIdleFree,cbCourtOk,lateMax};')(isFem,clamp);

const GR=['C','B','A','S'];
const mk=(nM,nF,L,seed)=>{ let s=seed; const r=()=>((s=(s*1103515245+12345)&0x7fffffff)/0x7fffffff);
  const o=[]; for(let i=0;i<nM;i++) o.push({id:'M'+i,name:'M'+i,gender:'M',grade:GR[(r()*4)|0],rating:1000});
  for(let i=0;i<nF;i++) o.push({id:'F'+i,name:'F'+i,gender:'F',grade:GR[(r()*4)|0],rating:1000});
  o.map((_,i)=>i).sort(()=>r()-.5).slice(0,L).forEach(i=>o[i].late=true); return o; };

/* index.html 의 일반 대진 흐름 그대로 —
   늦참이 없으면 '코트가 안 비는' 편성, 있으면 기존 편성.
   만든 뒤 늦참 조건을 확인하고 어긋나면 합류를 한 게임씩 당긴다. */
function build(mem, courts, lateAfter, seed){
  const perR=Math.max(1,Math.min(courts,Math.floor(mem.length/4)));
  if(!lateAfter){
    const f=F.cbPlanIdleFree(mem, courts, seed);
    if(f) return {out:f, A:0};
  }
  const lateIds=new Set(mem.filter(p=>p.late).map(p=>String(p.id)));
  for(let A=lateAfter; A>=0; A--){
    const plan=F.hnPlanGroup(mem,{seed, lateAfter:A*perR, past:{}, style:'level', budget:120});
    if(!plan.length) continue;
    const out=F.cbPack(plan.map(([t1,t2])=>({t1,t2,ids:[...t1,...t2].map(p=>p.id),
      minR:[...t1,...t2].some(p=>p.late)?A+1:1})), courts);
    const early = A>0 && out.some(g=>g.r<=A &&
      [...g.t1,...g.t2].some(p=>lateIds.has(String(p.id))));
    if(!early) return {out, A};
  }
  return null;
}
function judge(r, mem){
  if(!r) return ['대진을 못 만듦'];
  const all=g=>[...g.t1,...g.t2], bad=[];
  let clash=0, dupCourt=0;
  [...new Set(r.out.map(g=>g.r))].forEach(x=>{ const seen=new Set(), cs=new Set();
    r.out.filter(g=>g.r===x).forEach(g=>{
      if(cs.has(g.c)) dupCourt++; cs.add(g.c);
      all(g).forEach(p=>{ if(seen.has(p.id)) clash++; seen.add(p.id); }); }); });
  if(clash) bad.push('같은 바퀴에 두 코트');
  if(dupCourt) bad.push('한 바퀴에 코트 중복');
  if(r.out.some(g=>all(g).length!==4)) bad.push('한 경기가 네 명이 아님');
  const cnt={}; mem.forEach(p=>cnt[p.id]=0);
  r.out.forEach(g=>all(g).forEach(p=>{ if(cnt[p.id]!==undefined) cnt[p.id]++; }));
  const v=[...new Set(Object.values(cnt))];
  if(!(v.length===1 && v[0]===4)) bad.push('전원 4경기가 아님');
  const lateIds=new Set(mem.filter(p=>p.late).map(p=>String(p.id)));
  if(r.A>0 && r.out.some(g=>g.r<=r.A && all(g).some(p=>lateIds.has(String(p.id)))))
    bad.push('늦참자가 합류 전에 나옴');
  return bad;
}

const HEADS=[8,12,16,18,20,24], COURTS=[1,2,3], RATIOS=[0,0.25,0.5], LATES=[0,1,3];
const SEEDS=2;
let total=0, ok=0, lowered=0;
const fails=[];
const t0=Date.now();
for(const n of HEADS) for(const c of COURTS){
  if(!F.cbCourtOk(n,c).ok) continue;                 // 앱이 막는 조합
  for(const rf of RATIOS){
    const nF=Math.round(n*rf), nM=n-nF;
    for(const L of LATES){
      if(L>=n) continue;
      const M=F.lateMax(n,c,L);
      if(L && !M) continue;                          // 앱이 막는 조합
      for(const A of (L? [...new Set([1,M])] : [0])){
        for(let s=1;s<=SEEDS;s++){
          total++;
          const mem=mk(nM,nF,L,s*7919+n*31+c*13);
          let r=null;
          try{ r=build(mem,c,A,s); }
          catch(e){ fails.push({n,c,nM,nF,L,A,s,why:'터짐 '+e.message}); continue; }
          if(r && r.A!==A) lowered++;
          const bad=judge(r,mem);
          if(bad.length) fails.push({n,c,nM,nF,L,A,s,why:bad.join(' · ')});
          else ok++;
        }
      }
    }
  }
}
console.log(`대진 ${total}개를 돌렸습니다 (${((Date.now()-t0)/1000).toFixed(1)}초)`);
console.log(`  이상 없음 ${ok}개 · 문제 ${fails.length}개`);
if(lowered) console.log(`  늦참 합류를 당긴 경우 ${lowered}개 (전원 4경기를 지키려고)`);
if(fails.length){
  const by={}; fails.forEach(f=>by[f.why]=(by[f.why]||0)+1);
  Object.entries(by).sort((a,b)=>b[1]-a[1]).forEach(([w,k])=>console.log(`FAIL ${w} — ${k}건`));
  fails.slice(0,8).forEach(f=>console.log(`     ${f.n}명(남${f.nM}여${f.nF}) ${f.c}코트 늦참${f.L}명 ${f.A}게임후 시드${f.s}`));
  process.exit(1);
}
console.log('\n전부 통과');
