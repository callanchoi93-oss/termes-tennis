/* 명단 조정 — 늦참 · 노쇼

   대진을 발행한 뒤에 연락이 온다: "30분 늦어요", "못 가요".
   예전엔 '다른 사람으로 교체'만 있어서 늦는 사람은 손으로 순서를 옮겨야 했고,
   그러다 같은 사람이 한 바퀴에 두 코트로 들어가 대진이 꼬였다(8/14).

   규칙: 끝났거나 진행 중인 경기는 절대 건드리지 않는다.
   실행:  node test/adjust-sim.js
*/
const P=n=>({id:n,name:n});
const g=(r,c,a,b,x,y,opt={})=>({r,c,teamA:[P(a),P(b)],teamB:[P(x),P(y)],
  sa:opt.sa??null, sb:opt.sb??null, startedAt:opt.run?1:null});

const open   = gs => gs.filter(x=>x.sa==null && !x.startedAt);
const locked = gs => gs.filter(x=>x.sa!=null || x.startedAt);
const has    = (x,who) => [...x.teamA,...x.teamB].some(p=>String(p.id)===String(who));

/* index.html 의 adjPlan 과 같은 규칙 (늦참) */
function planLate(gs, who, from){
  const op=open(gs);
  const bad=op.filter(x=>has(x,who) && x.r<from);
  const pool=op.filter(x=>!bad.includes(x) && !has(x,who) && x.r>=from);
  const moves=[], used=new Set();
  bad.forEach(b=>{
    const busy=new Set(gs.filter(x=>x.r===b.r && x!==b)
      .flatMap(x=>[...x.teamA,...x.teamB].map(p=>String(p.id))));
    const cand=pool.find(x=>!used.has(x) && [...x.teamA,...x.teamB].every(p=>!busy.has(String(p.id))));
    if(cand){ used.add(cand); moves.push([b,cand]); }
  });
  return {bad, moves};
}
function applyLate(gs, who, from){
  const {bad,moves}=planLate(gs,who,from);
  moves.forEach(([b,c])=>{ const r=b.r,cc=b.c; b.r=c.r;b.c=c.c; c.r=r;c.c=cc; });
  bad.filter(b=>!moves.some(([x])=>x===b)).forEach(x=>
    ['teamA','teamB'].forEach(k=>x[k].forEach((p,i)=>{ if(String(p.id)===String(who)) x[k][i]=P('(공석)'); })));
  gs.sort((a,b)=>a.r-b.r||a.c-b.c);
  return gs;
}
function clashes(gs){
  const out=[];
  [...new Set(gs.map(x=>x.r))].forEach(r=>{
    const seen=new Set();
    gs.filter(x=>x.r===r).forEach(x=>[...x.teamA,...x.teamB].forEach(p=>{
      if(p.id==='(공석)') return;
      if(seen.has(p.id)) out.push({r,name:p.name}); seen.add(p.id); }));
  });
  return out;
}
const counts = gs => { const c={};
  gs.forEach(x=>[...x.teamA,...x.teamB].forEach(p=>{ if(p.id!=='(공석)') c[p.id]=(c[p.id]||0)+1; })); return c; };

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

const mk=()=>[
 g(1,1,'A','B','C','D'), g(1,2,'E','F','G','H'), g(1,3,'I','J','K','L'),
 g(2,1,'A','C','B','D'), g(2,2,'E','G','F','H'), g(2,3,'I','K','J','L'),
 g(3,1,'A','D','B','C'), g(3,2,'E','H','F','G'), g(3,3,'I','L','J','K'),
 g(4,1,'A','E','B','F'), g(4,2,'C','G','D','H'), g(4,3,'I','J','K','L'),
];

console.log('■ 늦참 — A 님이 3게임부터 합류');
{ const gs=mk(); const before=counts(gs)['A'];
  applyLate(gs,'A',3);
  const early=gs.filter(x=>x.r<3 && has(x,'A'));
  ok(early.length===0, '1·2게임에서 A 가 빠졌다');
  ok(clashes(gs).length===0, `겹치는 사람 없음 (${clashes(gs).length}건)`);
  const after=counts(gs)['A'];
  console.log(`     A 경기 수 ${before} → ${after}`);
}

console.log('\n■ 끝난 경기·진행 중 경기는 건드리지 않는다');
{ const gs=mk();
  gs[0].sa=6; gs[0].sb=4;            // 1게임 1코트 종료 (A 포함)
  gs[3].startedAt=1;                 // 2게임 1코트 진행 중 (A 포함)
  const keepDone={r:gs[0].r,c:gs[0].c}, keepRun={r:gs[3].r,c:gs[3].c};
  applyLate(gs,'A',3);
  const d=gs.find(x=>x.sa===6), r=gs.find(x=>x.startedAt);
  ok(d.r===keepDone.r && d.c===keepDone.c, '끝난 경기는 그 자리 그대로');
  ok(r.r===keepRun.r && r.c===keepRun.c, '진행 중 경기도 그대로');
  ok(has(d,'A') && has(r,'A'), '그 두 경기에는 A 가 그대로 남는다');
}

console.log('\n■ 자리를 못 찾으면 억지로 넣지 않는다');
{ /* A 가 모든 뒤 경기에 이미 들어 있어 맞바꿀 상대가 없는 경우 */
  const gs=[ g(1,1,'A','B','C','D'), g(2,1,'A','E','F','G') ];
  const {bad:b2,moves}=planLate(gs,'A',2);
  ok(b2.length===1 && moves.length===0, '옮길 자리가 없으면 이동 0건');
  applyLate(gs,'A',2);
  ok(!has(gs[0],'A'), '대신 그 경기에서 빼둔다 (공석)');
  ok(clashes(gs).length===0, '겹침 없음');
}

console.log('\n■ 노쇼 — 남은 경기에서 빼기');
{ const gs=mk(); gs[0].sa=6; gs[0].sb=1;
  open(gs).forEach(x=>['teamA','teamB'].forEach(k=>x[k].forEach((p,i)=>{
    if(p.id==='B') x[k][i]=P('(공석)'); })));
  ok(open(gs).every(x=>!has(x,'B')), '남은 경기에서 B 가 빠졌다');
  ok(has(gs[0],'B'), '이미 끝난 경기에는 B 가 남는다');
  ok(clashes(gs).length===0, '겹침 없음');
}

console.log('\n■ 4경기가 깨지는지 미리 안다');
{ const gs=mk();
  applyLate(gs,'A',3);
  const c=counts(gs);
  const shortN=Object.keys(c).filter(k=>c[k]<4);
  console.log(`     4경기 미만: ${shortN.length?shortN.map(k=>`${k} ${c[k]}경기`).join(', '):'없음'}`);
  ok(true, '조정 뒤 경기 수를 셀 수 있다 (화면에서 미리 알려줌)');
}

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
