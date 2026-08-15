/* 홈 요약 카드

   대진 화면 카드는 <지금 할 일> 하나만 말한다.
   홈에서는 어느 모임에서 · 몇 경기째 · 다음은 누구와 를 한 장에 담고,
   내 차례가 아니어도 경기가 도는 동안 계속 떠 있는다.

   실행:  node test/homecard-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const m=/^function cbHomeCard\s*\(/m.exec(SRC);
if(!m){ console.log('FAIL cbHomeCard 없음'); process.exit(1); }
let d=0,i=SRC.indexOf('{',m.index),code=null;
for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d){code=SRC.slice(m.index,j+1);break;}} }

let CB2=null; const state={serverUser:{id:'me',name:'나'}};
const call=()=>new Function('CB2ref','stateRef',
  'const state=stateRef;let CB2=CB2ref;\n'+code+'\nreturn cbHomeCard;')(CB2,state)();

const P=(id,n)=>({id,name:n}), ME=P('me','나');
const TODAY=new Date().toISOString().slice(0,10);
const g=(r,c,A,B,o={})=>({r,c,teamA:A,teamB:B,sa:o.sa??null,sb:o.sb??null,startedAt:o.run??null});
const ev={title:'테르메스 금요모임'};
let bad=0; const ok=(c,msg)=>{ if(!c){bad++;console.log('FAIL',msg);} else console.log('ok  ',msg); };
const show=r=>r? `${r.big.replace(/\n/g,' / ')}` : 'null';

console.log('■ 안 뜨는 경우');
CB2=null; ok(call()===null, '대진이 없으면 안 뜬다');
CB2={date:TODAY, event:ev, games:[g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')])]};
ok(call()===null, '내가 대진에 없으면 안 뜬다');
CB2={date:'2020-01-01', event:ev, games:[g(1,1,[ME,P('b','B')],[P('c','C'),P('d','D')])]};
ok(call()===null, '오늘 모임이 아니면 안 뜬다');

console.log('\n■ 내 경기가 도는 중 — 내 차례가 아니어도 계속 뜬다');
CB2={date:TODAY, event:ev, games:[
  g(1,1,[ME,P('b','이광하')],[P('c','정윤희'),P('d','이경태')],{run:Date.now()-10*60000}),
  g(2,2,[ME,P('e','박희진')],[P('f','강혜선'),P('g','이인애')])]};
{ const r=call();
  ok(r!==null, `→ ${show(r)}`);
  ok(r.big.includes('1번 코트에서 경기 중'), '지금 어느 코트인지');
  ok(r.m.includes('파트너 이광하 vs 정윤희'), '지금 누구와');
  ok(r.m.includes('다음 · 2번째 게임 2번 코트'), '다음 경기도 함께');
  ok(r.m.includes('파트너 박희진'), '다음 파트너까지');
  ok(r.lb.includes('테르메스 금요모임'), '어느 모임인지');
  ok(r.lb.includes('내 경기 0/2'), '몇 경기째인지');
}

console.log('\n■ 쉬는 중 — 다음 경기를 알려준다');
CB2={date:TODAY, event:ev, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:Date.now()-5*60000}),
  g(1,2,[ME,P('e','박희진')],[P('f','강혜선'),P('g','이인애')],{sa:6,sb:4,run:Date.now()-30*60000}),
  g(3,2,[ME,P('h','유승은')],[P('i','이광하'),P('j','정윤희')])]};
{ const r=call();
  ok(r.big.includes('다음은 3번째 게임 2번 코트'), `→ ${show(r)}`);
  ok(r.m.includes('파트너 유승은'), '다음 파트너');
  ok(r.lb.includes('내 경기 1/2'), '1경기 했다고 나온다');
}

console.log('\n■ 내 경기가 마지막이면');
CB2={date:TODAY, event:ev, games:[
  g(1,1,[ME,P('b','이광하')],[P('c','정윤희'),P('d','이경태')],{run:Date.now()-10*60000})]};
ok(call().m.includes('마지막이에요'), '“이 경기가 마지막이에요”');

console.log('\n■ 다 끝나면 전적을 보여준다');
{ const t=Date.now()-30*60000;
  CB2={date:TODAY, event:ev, games:[
    g(1,1,[ME,P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4,run:t}),
    g(2,1,[ME,P('c','C')],[P('b','B'),P('d','D')],{sa:3,sb:6,run:t})]};
  const r=call();
  ok(r.big.includes('다 끝났어요'), `→ ${show(r)}`);
  ok(r.m.includes('1승 1패'), '전적이 나온다');
}

console.log('\n■ 끝나고 3시간 지나면 사라진다');
{ const t=Date.now()-4*3600000;
  CB2={date:TODAY, event:ev, games:[g(1,1,[ME,P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4,run:t})]};
  ok(call()===null, '3시간 넘으면 안 뜬다'); }

console.log('\n■ 배너 위 카드는 지웠는가');
{ const home=SRC.slice(SRC.indexOf('function _renderHomeCore'), SRC.indexOf('function _renderHomeCore')+1500);
  ok(!/cbMyCard\(\)/.test(home), '홈에서 대진 화면용 카드(cbMyCard)를 안 쓴다');
  ok(/cbHomeCard\(\)/.test(home), '홈 전용 카드를 쓴다');
  ok(/openClubBracketView\(\)/.test(home), '누르면 대진으로 간다'); }

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
