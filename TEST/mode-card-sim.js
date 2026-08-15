/* 대진 방식별로 카드가 맞게 나오는가

   일반·성비는 코트를 옮겨 다니지만 한울·월례대회는 조가 코트에 고정된다.
   고정인데 "2번 코트에서 몸 풀다가 3번 코트로 옮겨요" 라고 하면 헷갈린다.
   청백전은 두 팀 단체전이라 끝나고 팀 점수도 궁금하다.

   실행:  node test/mode-card-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const m=/^function cbMyCard\s*\(/m.exec(SRC);
if(!m){ console.log('FAIL cbMyCard 없음'); process.exit(1); }
let d=0,i=SRC.indexOf('{',m.index),code=null;
for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d){code=SRC.slice(m.index,j+1);break;}} }

let CB2=null; const state={serverUser:{id:'me',name:'나'}};
const jsArg=v=>JSON.stringify(String(v));
const call=()=>new Function('CB2ref','stateRef','jsArg',
  'const state=stateRef;let CB2=CB2ref;\n'+code+'\nreturn cbMyCard;')(CB2,state,jsArg)();

const P=(id,n)=>({id,name:n}), ME=P('me','나');
const g=(r,c,A,B,o={})=>({r,c,teamA:A,teamB:B,sa:o.sa??null,sb:o.sb??null,startedAt:o.run||null});
let bad=0; const ok=(c,msg)=>{ if(!c){bad++;console.log('FAIL',msg);} else console.log('ok  ',msg); };
const show=r=>r? `${r.kind} · ${r.big.replace(/\n/g,' / ')}` : 'null';

/* 내 경기는 3번 코트인데 3번 코트가 아직 도는 중 · 2번 코트만 비어 있다 */
const layout=mode=>({courts:3, mode, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:Date.now()-20*60000}),
  g(1,3,[P('h','H'),P('i','I')],[P('j','J'),P('k','K')],{run:Date.now()-15*60000}),
  g(2,3,[ME,P('e','이광하')],[P('f','정윤희'),P('g','이경태')])]});

console.log('■ 일반 — 빈 코트에서 몸 풀다가 옮긴다');
CB2=layout('normal');
{ const r=call();
  ok(r.big.includes('2번 코트'), `빈 2번 코트로 안내 → ${show(r)}`);
  ok(r.m.includes('3번 코트가 나면'), '내 코트가 나면 옮기라고 한다');
}

console.log('\n■ 성비 — 일반과 같다');
CB2=layout('gender');
ok(call().big.includes('2번 코트'), `성비도 같게 동작한다 — ${show(call())}`);

console.log('\n■ 한울 — 조가 코트에 고정이라 옮기지 않는다');
CB2=layout('hanul');
{ const r=call();
  ok(r.big.includes('3번 코트'), `내 코트로 바로 → ${show(r)}`);
  ok(!r.m.includes('옮겨요'), '“옮겨요” 가 안 나온다');
}

console.log('\n■ 월례대회 — 한울과 같다');
CB2=layout('monthly');
{ const r=call();
  ok(r.big.includes('3번 코트') && !r.m.includes('옮겨요'), '조가 고정이라 옮기지 않는다');
}

console.log('\n■ 청백전 — 끝나면 팀 점수도 보여준다');
{ const t=Date.now()-30*60000;
  CB2={courts:2, mode:'cheongbaek', games:[
    g(1,1,[ME,P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4,run:t}),
    g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')],{sa:6,sb:2,run:t}),
    g(2,1,[ME,P('c','C')],[P('b','B'),P('d','D')],{sa:3,sb:6,run:t})]};
  const r=call();
  ok(r.kind==='done', `→ ${show(r)}`);
  ok(r.m.includes('우리 팀'), '팀 점수가 나온다');
  ok(/우리 팀 2승 · 상대 팀 1승/.test(r.m), `팀 점수가 맞다 — ${r.m.split('\n').pop()}`);
}

console.log('\n■ 대회 준비 — 조가 고정이지만 코트는 옮길 수 있다');
CB2=layout('tourney');
ok(call().big.includes('2번 코트'), `빈 코트에서 몸 푼다 — ${show(call())}`);

console.log('\n■ 홈 화면에도 같은 함수를 쓴다');
ok(/cbMyCard\(\)/.test(SRC.slice(SRC.indexOf('function _renderHomeCore'), SRC.indexOf('function _renderHomeCore')+2000)),
   '홈에서 cbMyCard 를 부른다');
ok(/openClubBracketView\(\)/.test(SRC.slice(SRC.indexOf('function _renderHomeCore'), SRC.indexOf('function _renderHomeCore')+2000)),
   '누르면 대진으로 간다');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
