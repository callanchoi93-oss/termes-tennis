/* 기록 화면 — 표본이 적을 때 무엇을 보여줄까

   한 경기로 승률 100%·0% 는 뜻이 없다. 특히 이름 옆의 0% 는 낙인처럼 보여
   "저 사람과 치면 진다" 로 읽힌다.
   예전에는 탭마다 기준이 달라서, 같은 사람에 대해 파트너 탭은 "최고의 파트너",
   리포트 탭은 "2경기 이상 필요" 라고 서로 다르게 말했다.

   실행:  node test/stats-sim.js
*/
const MINW=2;                                   // index.html 과 같은 값
const wrCell=(g,w)=> g<MINW ? '—' : Math.round(w/g*100)+'%';
const bestOf=list=>list.filter(p=>p.g>=MINW).sort((a,b)=>(b.w/b.g)-(a.w/a.g)||b.g-a.g)[0]||null;
/* 경기 기록 한 줄 */
const recLine=(partner,opps)=>(partner?`${partner} 님과 · `:'')+opps.join(' · ');

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 승률은 2경기부터');
ok(wrCell(1,1)==='—', '1승 0패 → —  (100% 아님)');
ok(wrCell(1,0)==='—', '0승 1패 → —  (0% 아님 · 낙인 방지)');
ok(wrCell(2,1)==='50%', '1승 1패 → 50%');
ok(wrCell(2,2)==='100%', '2승 0패 → 100%');
ok(wrCell(5,3)==='60%', '3승 2패 → 60%');

console.log('\n■ 최고의 파트너 — 세 탭이 같은 기준');
{ const one=[{n:'이기훈',g:1,w:1},{n:'서기훈',g:1,w:0}];
  ok(bestOf(one)===null, '모두 1경기면 "아직 몰라요"');
  const two=[{n:'이기훈',g:2,w:2},{n:'서기훈',g:3,w:1}];
  ok(bestOf(two).n==='이기훈', '2경기부터 뽑힌다 (이기훈 100%)');
  const tie=[{n:'A',g:2,w:2},{n:'B',g:5,w:5}];
  ok(bestOf(tie).n==='B', '승률이 같으면 많이 뛴 쪽');
}

console.log('\n■ 경기 기록 한 줄');
ok(recLine('이기훈',['진성천','김진수B'])==='이기훈 님과 · 진성천 · 김진수B',
   '이기훈 님과 · 진성천 · 김진수B');
ok(!recLine('이기훈',['진성천']).includes('vs'), '떠 있던 "· vs" 가 없다');
ok(recLine(null,['진성천','김진수B'])==='진성천 · 김진수B', '단식이면 파트너 없이');
ok(recLine('이기훈',[])==='이기훈 님과 · ', '상대가 비어도 터지지 않는다');

console.log('\n■ 리포트 문구');
const avgTxt=d=> d===0 ? '클럽 평균 · 같아요' : `클럽 평균 대비 ${d>0?'+':''}${d}%p`;
ok(avgTxt(0)==='클럽 평균 · 같아요', '0 이면 "같아요" (+0%p 아님)');
ok(avgTxt(12)==='클럽 평균 대비 +12%p', '높으면 +12%p');
ok(avgTxt(-8)==='클럽 평균 대비 -8%p', '낮으면 -8%p');
const recent=n=>`최근 ${n}경기`;
ok(recent(2)==='최근 2경기', '2경기밖에 없으면 "최근 2경기" (5경기 아님)');
ok(recent(5)==='최근 5경기', '5경기 이상이면 그대로');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
