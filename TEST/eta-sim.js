/* 예상 종료 시각 — 실제 진행 속도로 계산한다

   경기 하나하나의 길이를 재는 대신 '지금까지 몇 경기를 해냈나'로 본다.
   그래야 코트가 논 시간·쉬는 시간·늦어진 것이 전부 반영된다.
   총무가 가장 자주 묻는 건 "이 속도면 몇 시에 끝나지?" 다.

   실행:  node test/eta-sim.js
*/
const MIN=60000;
/* index.html 의 cbEta 와 같은 규칙 */
function cbEta(games, done, courts, now){
  const gs=games||[];
  const starts=gs.map(g=>g.startedAt).filter(Boolean);
  const doneN=gs.filter(done).length, tot=gs.length;
  if(!starts.length || doneN<2 || doneN>=tot) return null;
  const t0=Math.min(...starts);
  const elapsed=now-t0;
  if(elapsed<MIN) return null;
  const perGame=elapsed/doneN;
  const left=tot-doneN;
  const restMs=perGame*left;
  const end=new Date(now+restMs);
  const hh=String(end.getHours()).padStart(2,'0'), mm=String(end.getMinutes()).padStart(2,'0');
  return { end:`${hh}:${mm}`, avgMin:Math.round(perGame*Math.max(1,courts||1)/MIN),
           leftN:left, restMin:Math.round(restMs/MIN), doneN, tot };
}
const done=g=>g.sa!=null;
const mk=(n,doneN,t0)=>Array.from({length:n},(_,i)=>({
  startedAt: i<doneN? t0+i*MIN : null,
  sa: i<doneN? 6 : null, sb: i<doneN? 4 : null }));

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

/* 19:00 시작 기준으로 계산 */
const T0=new Date(2026,7,14,19,0,0).getTime();

console.log('■ 18경기 · 3코트 · 6경기 끝난 시점');
{ // 19:00 시작 · 6경기를 50분에 → 경기당 8분20초 · 남은 12경기 100분 → 21:30
  const gs=mk(18,6,T0); const now=T0+50*MIN;
  const e=cbEta(gs,done,3,now);
  ok(e!==null,'계산됨');
  ok(e.leftN===12, `남은 경기 ${e.leftN}`);
  ok(e.restMin===100, `남은 시간 ${e.restMin}분`);
  ok(e.end==='21:30', `예상 종료 ${e.end}  (19:50 + 100분)`);
  ok(e.avgMin===25, `한 코트 기준 평균 ${e.avgMin}분`);
}

console.log('\n■ 느려지면 예상도 늦춰진다');
{ const gs=mk(18,6,T0); const now=T0+72*MIN;      // 같은 6경기를 72분에 (경기당 12분)
  const e=cbEta(gs,done,3,now);
  ok(e.end==='22:36', `느린 진행 → ${e.end}  (빠를 때 21:30)`);
}

console.log('\n■ 언제 계산하지 않는가');
ok(cbEta(mk(18,0,T0),done,3,T0+10*MIN)===null, '아무것도 안 끝났으면 계산 안 함');
ok(cbEta(mk(18,1,T0),done,3,T0+10*MIN)===null, '1경기만으로는 속도를 못 잰다');
ok(cbEta(mk(18,18,T0),done,3,T0+150*MIN)===null, '다 끝났으면 계산 안 함');
ok(cbEta([],done,3,T0)===null, '경기가 없어도 터지지 않는다');
ok(cbEta(mk(18,6,T0),done,3,T0+30*1000)===null, '시작 1분도 안 됐으면 계산 안 함');

console.log('\n■ 코트 수는 평균 표시에만 쓴다');
{ const gs=mk(12,4,T0), now=T0+40*MIN;
  const a=cbEta(gs,done,2,now), b=cbEta(gs,done,4,now);
  ok(a.end===b.end, `종료 시각은 코트 수와 무관 (${a.end})`);
  ok(a.avgMin===20 && b.avgMin===40, `평균은 코트 수만큼 (2코트 ${a.avgMin}분 · 4코트 ${b.avgMin}분)`);
}

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
