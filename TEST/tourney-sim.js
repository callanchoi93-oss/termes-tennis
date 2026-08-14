/* 대회 준비 대진 — 전원 정확히 4경기

   평소 대진은 파트너를 섞는다. 대회 준비는 반대로 나갈 조를 고정하고 그 조끼리 붙인다.
   '모두와 한 번씩'이 아니라 '넷만 골라' 붙는다 — 그래야 조가 몇이든 4경기가 된다.
   (모두와 붙이면 4조는 3경기, 6조는 5경기가 나온다.)

   실행:  node test/tourney-sim.js
*/

/* index.html 의 trEdges 와 같은 규칙 */
function trEdges(T){
  if(T===2) return [[0,1],[0,1],[0,1],[0,1]];
  if(T===3){ const o=[]; for(let i=0;i<3;i++) for(let j=i+1;j<3;j++){o.push([i,j]);o.push([i,j]);} return o; }
  if(T===4){ const o=[]; for(let i=0;i<4;i++) for(let j=i+1;j<4;j++) o.push([i,j]);
             o.push([0,1]); o.push([2,3]); return o; }
  if(T%2===0){
    const o=[]; let cur=[...Array(T).keys()];
    for(let r=0;r<4;r++){
      for(let i=0;i<T/2;i++) o.push([cur[i],cur[T-1-i]]);
      cur=[cur[0],cur[T-1],...cur.slice(1,T-1)];
    }
    return o;
  }
  const o=[]; for(let i=0;i<T;i++){ o.push([i,(i+1)%T]); o.push([i,(i+2)%T]); } return o;
}
/* index.html 의 배치와 같은 규칙 */
function schedule(T, courts){
  let rest=trEdges(T).slice();
  const left=Array(T).fill(0); rest.forEach(([a,b])=>{left[a]++;left[b]++;});
  const rounds=[]; let guard=0;
  while(rest.length && guard++<500){
    rest.sort((p,q)=>(left[q[0]]+left[q[1]])-(left[p[0]]+left[p[1]]));
    const used=new Set(), g=[], keep=[];
    for(const e of rest){
      if(g.length<courts && !used.has(e[0]) && !used.has(e[1])){
        g.push(e); used.add(e[0]); used.add(e[1]); left[e[0]]--; left[e[1]]--;
      } else keep.push(e);
    }
    if(!g.length) break;
    rounds.push(g); rest=keep;
  }
  return rounds;
}

let bad=0;
const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 전원 정확히 4경기 (2~12조 × 1~4코트)');
let checked=0;
for(let T=2;T<=12;T++){
  for(let C=1;C<=4;C++){
    const rounds=schedule(T,C);
    const per=Array(T).fill(0);
    let dup=false, over=false;
    rounds.forEach(g=>{
      const seen=new Set();
      if(g.length>C) over=true;
      g.forEach(([a,b])=>{
        if(seen.has(a)||seen.has(b)) dup=true;
        seen.add(a); seen.add(b); per[a]++; per[b]++;
      });
    });
    const all4 = per.every(v=>v===4);
    if(!(all4 && !dup && !over)){
      bad++; console.log(`FAIL ${T}조 ${C}코트 → ${per.join(',')}${dup?' 중복출전':''}${over?' 코트초과':''}`);
    }
    checked++;
  }
}
ok(bad===0, `${checked}가지 조합 모두 전원 4경기 · 중복 출전 없음 · 코트 초과 없음`);

console.log('\n■ 3코트 기준 바퀴 수');
[[2,4],[3,6],[4,4],[5,5],[6,4],[7,5],[8,6],[9,6],[10,7]].forEach(([T,want])=>{
  const n=schedule(T,3).length;
  ok(n===want, `${T}조(${T*2}명) → ${n}바퀴 · ${n*25}분`);
});

console.log('\n■ 같은 상대를 다시 만나는가');
const repeats = T => {
  const c={}; trEdges(T).forEach(([a,b])=>{ const k=a<b?`${a},${b}`:`${b},${a}`; c[k]=(c[k]||0)+1; });
  return Object.values(c).filter(v=>v>1).length;
};
ok(repeats(2)===1, '2조 — 같은 상대와 네 번 (상대가 하나뿐)');
ok(repeats(3)===3, '3조 — 두 상대와 두 번씩');
ok(repeats(4)===2, '4조 — 한 상대만 두 번');
[5,6,7,8,9,10,11,12].forEach(T=>ok(repeats(T)===0, `${T}조 — 상대가 겹치지 않는다`));

console.log('\n■ 혼복 인원 판정');
const mixedCap=(m,f)=>Math.min(m,f);
ok(mixedCap(5,5)===5, '남5 여5 → 5조(10명)');
ok(mixedCap(13,5)===5, '남13 여5 → 5조까지 · 남성 8명은 빠진다');
ok(mixedCap(6,6)===6, '남6 여6 → 6조(12명) · 가장 좋은 인원');
ok(mixedCap(4,0)===0, '여성이 없으면 혼복 불가');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
