/* 대진표 이동 안내 (덮기 + 탭해서 뒤집기)

   카드에서 <2번 코트에서 몸 풀다 3번 코트로> 안내를 받은 넷에게만
   그 두 칸을 안내로 덮는다. 다른 회원 표는 점수만 보인다.
   눌러서 점수 ↔ 안내를 번갈아 볼 수 있고, 경기가 시작되면 걷힌다.

   실행:  node test/movehint-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const m=/^function cbMoveHint\s*\(/m.exec(SRC);
if(!m){ console.log('FAIL cbMoveHint 없음'); process.exit(1); }
let d=0,i=SRC.indexOf('{',m.index),code=null;
for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d){code=SRC.slice(m.index,j+1);break;}} }

let CB2=null, state={serverUser:{id:'me',name:'나'}};
const call=()=>new Function('CB2ref','stateRef',
  'const state=stateRef;let CB2=CB2ref;\n'+code+'\nreturn cbMoveHint;')(CB2,state)();

const P=(id,n)=>({id,name:n}), ME=P('me','나');
const g=(r,c,A,B,o={})=>({r,c,teamA:A,teamB:B,sa:o.sa??null,sb:o.sb??null,startedAt:o.run??null});
let bad=0; const ok=(c,msg)=>{ if(!c){bad++;console.log('FAIL',msg);} else console.log('ok  ',msg); };

/* 내 경기는 3번 코트 3게임 · 3번 코트가 지금 돌고 있고 · 2번 코트는 비어 있다 */
const base=()=>({courts:3, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4}),
  g(1,2,[P('e','이경태'),P('f','김진수B')],[P('g','강태민'),P('h','진성천')],{sa:6,sb:4}),
  g(2,1,[P('a','A'),P('c','C')],[P('b','B'),P('d','D')],{run:Date.now()-12*60000}),
  g(2,3,[P('i','박사라'),P('j','진성천')],[P('k','유승은'),P('l','강태민')],{run:Date.now()-6*60000}),
  g(3,3,[ME,P('m','이광하')],[P('n','정윤희'),P('o','이경태')])]});

console.log('■ 이동 대상이면 두 칸이 덮인다');
CB2=base();
{ const r=call();
  ok(r!==null, '안내가 나온다');
  ok(r.warm.c===2, `몸 풀 곳 = ${r.warm.c}번 코트 (비어 있는 코트)`);
  ok(r.go.c===3 && r.go.r===3, `갈 곳 = ${r.go.c}번 코트 ${r.go.r}번째 게임`);
  ok(r.warmTxt.t1.startsWith('①'), `① ${r.warmTxt.t1}`);
  ok(r.goTxt.t1.startsWith('②'), `② ${r.goTxt.t1}`);
  ok(r.warmTxt.t2.includes('3번 코트'), `“${r.warmTxt.t2}”`);
  ok(r.goTxt.t2.includes('2번 코트'), `“${r.goTxt.t2}”`);
}

console.log('\n■ 다른 회원에게는 안 뜬다');
state={serverUser:{id:'zzz',name:'남'}};
ok(call()===null, '대진에 없는 사람 → 안내 없음');
state={serverUser:{id:'a',name:'A'}};
ok(call()===null, '이동 대상이 아닌 사람 → 안내 없음');
state={serverUser:{id:'me',name:'나'}};

console.log('\n■ 걷히는 경우');
{ CB2=base(); CB2.games[4].startedAt=Date.now();       // 내 경기를 시작함
  ok(call()===null, '내 경기를 시작하면 안내가 걷힌다'); }
{ CB2=base(); CB2.games[4].sa=6; CB2.games[4].sb=4;    // 점수가 들어감
  ok(call()===null, '점수가 들어가면 걷힌다'); }
{ CB2=base(); CB2.games[3].sa=6; CB2.games[3].sb=2;    // 내 코트가 비었음
  ok(call()===null, '내 코트가 비면 기다릴 게 없으니 안 뜬다'); }
{ CB2=base();
  /* 2번 코트에도 경기를 돌려 세 코트를 다 채운다 */
  CB2.games.push(g(2,2,[P('x','X'),P('y','Y')],[P('z','Z'),P('w','W')],{run:Date.now()-3*60000}));
  ok(call()===null, '세 코트가 다 차 있으면 몸 풀 곳이 없어 안 뜬다'); }

console.log('\n■ 내 앞에 안 한 경기가 있으면');
{ CB2=base();
  CB2.games.push(g(2,3,[P('p','P'),P('q','Q')],[P('r','R'),P('s','S')]));  // 3번 코트 2게임 미실시
  ok(call()===null, '그 코트 앞 경기가 남아 있으면 아직 내 차례가 아니다'); }

console.log('\n■ 화면에 붙었는가');
ok(/cb2Flip\(/.test(SRC), '탭해서 뒤집는 함수가 있다');
ok(/눌러서 점수 보기/.test(SRC), '덮인 칸에 “눌러서 점수 보기”');
ok(/눌러서 안내 보기/.test(SRC), '뒤집은 칸에 “눌러서 안내 보기”');
ok(/CB2_FLIP/.test(SRC), '뒤집은 상태를 기억한다');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
