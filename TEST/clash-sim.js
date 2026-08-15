/* 같은 바퀴에 같은 사람이 두 코트로 들어갔는지

   대진을 짜고 나서 순서를 손으로 바꾸면(늦참자를 뒤로 미룰 때 흔하다)
   한 사람이 한 바퀴에 두 코트에 서는 대진이 조용히 만들어진다.
   그러면 코트에서 진행이 꼬인다 — 실제로 8/14 에 그 일이 있었다.

   실행:  node test/clash-sim.js
*/
/* index.html 의 cb2ClashAt 과 같은 규칙 */
function clashAt(games, r){
  const seen={}, dup=[];
  games.forEach(g=>{
    if(g.r!==r) return;
    [...(g.teamA||[]),...(g.teamB||[])].forEach(p=>{
      const k=String(p.id||p.name);
      if(seen[k]){ if(!dup.some(d=>d.name===p.name)) dup.push({name:p.name,a:seen[k],b:g.c}); }
      else seen[k]=g.c;
    });
  });
  return dup;
}
function clashAll(games){
  return [...new Set(games.map(g=>g.r))].sort((a,b)=>a-b)
    .map(r=>({r,dup:clashAt(games,r)})).filter(x=>x.dup.length);
}
const P=n=>({id:n,name:n});
const g=(r,c,a,b,x,y)=>({r,c,teamA:[P(a),P(b)],teamB:[P(x),P(y)]});

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 8/14 실제 대진 (손으로 순서를 바꾼 뒤)');
const real=[
 g(1,1,'유승은','배충호','박희진','이광하'), g(1,2,'진성천','김진수B','이기훈','최민혁'),
 g(1,3,'박사라','강혜선','정윤희','이인애'),
 g(2,1,'이평화','서기훈','이정욱','강태민'), g(2,2,'이경태','김진수B','강태민','진성천'),
 g(2,3,'서기훈','최민혁','이평화','이정욱'),
 g(3,1,'이중호','서기훈','김진수B','최민혁'), g(3,2,'이기훈','이경태','이광하','배충호'),
 g(3,3,'박사라','진성천','유승은','강태민'),
 g(4,1,'이인애','강혜선','정윤희','박희진'), g(4,2,'박희진','유승은','정윤희','강혜선'),
 g(5,1,'이중호','이평화','이정욱','배충호'), g(5,2,'박사라','강태민','이인애','최민혁'),
 g(5,3,'유승은','이광하','정윤희','이경태'),
 g(6,1,'이기훈','이중호','이경태','이광하'), g(6,2,'김진수B','배충호','서기훈','이정욱'),
 g(6,3,'박희진','강혜선','박사라','이인애'),
 g(7,1,'진성천','이중호','이평화','이기훈'),
];
const found=clashAll(real);
ok(found.length===2, `겹치는 바퀴 ${found.length}개 발견 (2게임·4게임)`);
found.forEach(x=>console.log(`     ${x.r}게임 · ` + x.dup.map(d=>`${d.name}(${d.a}코트·${d.b}코트)`).join(', ')));
ok(found.some(x=>x.r===2 && x.dup.length===4), '2게임에서 4명 겹침');
ok(found.some(x=>x.r===4 && x.dup.length===3), '4게임에서 3명 겹침');

console.log('\n■ 정상 대진은 걸리지 않는다');
const clean=[
 g(1,1,'A','B','C','D'), g(1,2,'E','F','G','H'), g(1,3,'I','J','K','L'),
 g(2,1,'A','C','B','D'), g(2,2,'E','G','F','H'), g(2,3,'I','K','J','L'),
];
ok(clashAll(clean).length===0, '겹침 없음');

console.log('\n■ 경계');
ok(clashAll([]).length===0, '경기가 없어도 터지지 않는다');
ok(clashAll([g(1,1,'A','B','C','D')]).length===0, '한 경기뿐이면 겹칠 수 없다');
const same=[g(1,1,'A','B','C','D'), g(1,2,'A','E','F','G')];
ok(clashAll(same).length===1 && clashAll(same)[0].dup[0].name==='A', '한 명만 겹쳐도 잡는다');
const other=[g(1,1,'A','B','C','D'), g(2,2,'A','E','F','G')];
ok(clashAll(other).length===0, '바퀴가 다르면 같은 사람이어도 괜찮다');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
