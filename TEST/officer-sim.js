/* 운영진 카드 — 지금 손봐야 할 것

   운영진도 경기를 뛴다. 코트를 돌며 챙길 수가 없으니
   급한 순서로 <하나만> 보여준다. 여럿이면 나머지는 개수로 적는다.

   급한 순서
     1 겹치는 사람      — 진행 자체가 불가능
     2 점수가 안 들어옴  — 그 코트가 멈춘다
     3 코트가 비어 있음  — 기다려야 함
     4 시작을 안 누름    — 마감 시각을 못 알려줌
     5 늦참자 합류가 다가옴
     6 오늘이 거의 끝남

   실행:  node test/officer-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
function grab(n){
  const m=new RegExp('^function '+n+'\\s*\\(','m').exec(SRC);
  if(!m) throw new Error(n+' 없음');
  let d=0,i=SRC.indexOf('{',m.index);
  for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d) return SRC.slice(m.index,j+1);} }
}
let CB2=null;
// cbStartedAt 은 SRV_EVENTS·CB2_EVENT·evParseDate 를 쓰므로 흉내낸다
const stub='var SRV_EVENTS=[],CB2_EVENT=0,evParseDate=function(){return null;};\n';
const call=()=>new Function('CB2ref', stub+'let CB2=CB2ref;\n'+
  grab('cbFindClash')+'\n'+grab('cbStartedAt')+'\n'+grab('cbClock')+'\n'+grab('cbEta')+'\n'+
  grab('cbOfficerCard')+'\nreturn cbOfficerCard;')(CB2)();

const P=(id,n)=>({id,name:n});
const g=(r,c,A,B,o={})=>({r,c,teamA:A,teamB:B,sa:o.sa??null,sb:o.sb??null,startedAt:o.run||null});
const T=Date.now(), MIN=60000;
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };
const show=r=>r? `${r.kind} · ${r.big.replace(/\n/g,' / ')}` : 'null';

console.log('■ 아무 문제 없으면 안 뜬다');
CB2={courts:2, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:T-10*MIN}),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{run:T-8*MIN}),
  g(2,1,[P('a','A'),P('c','C')],[P('b','B'),P('d','D')]),
  g(2,2,[P('e','E'),P('g','G')],[P('f','F'),P('h','H')])]};
ok(call()===null, `문제 없음 → ${show(call())}`);

console.log('\n■ 점수가 오래 안 들어오면');
CB2={courts:2, games:[
  g(1,1,[P('a','최민혁'),P('b','B')],[P('c','C'),P('d','D')],{run:T-58*MIN}),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{sa:6,sb:4,run:T-30*MIN}),
  g(2,2,[P('e','E'),P('g','G')],[P('f','F'),P('h','H')],{sa:6,sb:2,run:T-5*MIN})]};
{ const r=call();
  ok(r && r.kind==='bad', `→ ${show(r)}`);
  ok(r.big.includes('1번 코트'), '어느 코트인지 나온다');
  ok(r.m.includes('최민혁'), '누가 뛴 경기인지 이름이 나온다');
  ok(r.btn==='대신 넣기 ›', '임원이 대신 넣을 수 있다');
}

console.log('\n■ 겹치는 사람이 있으면 그게 먼저');
CB2={courts:2, games:[
  g(2,1,[P('a','서기훈'),P('b','B')],[P('c','C'),P('d','D')]),
  g(2,2,[P('a','서기훈'),P('e','E')],[P('f','F'),P('g','G')]),
  g(1,1,[P('h','H'),P('i','I')],[P('j','J'),P('k','K')],{run:T-60*MIN})]};
{ const r=call();
  ok(r.big.includes('겹치는'), `점수 지연보다 먼저 → ${show(r)}`);
  ok(r.m.includes('서기훈'), '누가 겹쳤는지 나온다');
  ok(/그 밖에 \d가지/.test(r.m), '나머지는 개수로 적는다');
}

console.log('\n■ 코트가 비었는데 넣을 경기가 없으면');
CB2={courts:2, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:T-10*MIN}),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{sa:6,sb:4,run:T-28*MIN}),
  g(2,2,[P('a','A'),P('e','E')],[P('b','B'),P('f','F')])]};
{ const r=call();
  ok(r && r.big.includes('2번 코트'), `→ ${show(r)}`);
  ok(r.kind==='warn', '급한 건 아니라 경고 색');
}

console.log('\n■ 시작을 아무도 안 눌렀으면');
CB2={courts:2, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4}),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{sa:6,sb:2}),
  g(2,1,[P('a','A'),P('c','C')],[P('b','B'),P('d','D')]),
  g(2,2,[P('e','E'),P('g','G')],[P('f','F'),P('h','H')])]};
{ const r=call();
  ok(r && r.big.includes('시작을 누른'), `→ ${show(r)}`);
}

console.log('\n■ 오늘이 거의 끝나면');
CB2={courts:2, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4,run:T-50*MIN}),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{sa:6,sb:2,run:T-48*MIN}),
  g(2,1,[P('a','A'),P('c','C')],[P('b','B'),P('d','D')],{sa:6,sb:1,run:T-25*MIN}),
  g(2,2,[P('e','E'),P('g','G')],[P('f','F'),P('h','H')],{run:T-8*MIN})]};
{ const r=call();
  ok(r && r.kind==='ok' && r.big.includes('1경기'), `→ ${show(r)}`);
}

console.log('\n■ 코트가 빌 때 — 누구를 몸 풀게 할지 적는다');
CB2={courts:2, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:T-10*MIN}),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{sa:6,sb:4,run:T-28*MIN}),
  g(2,2,[P('a','A'),P('e','유승은')],[P('b','B'),P('f','이광하')])]};
{ const r=call();
  ok(r.big.includes('유승은') && r.big.includes('이광하'), '들어갈 넷의 이름이 나온다');
  ok(r.big.includes('몸 푸세요'), '“몸 푸세요” 로 지시한다');
  ok(r.m.includes('1번 코트가 끝나면'), '어느 코트가 끝나면 되는지 적는다');
  ok(r.lb.includes('2번 코트가 비어'), '어느 코트가 비었는지 라벨에');
}

console.log('\n■ 곧 끝나는 코트가 있으면 미리 부른다');
CB2={courts:2, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:T-24*MIN}),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{run:T-5*MIN}),
  g(2,1,[P('i','박희진'),P('j','강혜선')],[P('k','K'),P('l','L')])]};
{ const r=call();
  ok(r && r.big.includes('박희진'), `→ ${show(r)}`);
  ok(r.big.includes('미리 몸 푸세요'), '미리 부르라고 적는다');
  ok(r.m.includes('1번 코트가 끝나면'), '어느 코트가 끝나면 되는지');
}

console.log('\n■ 경계');
CB2={courts:2, games:[]};
ok(call()===null, '경기가 없으면 안 뜬다');
CB2=null;
ok(call()===null, '대진이 없어도 터지지 않는다');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
