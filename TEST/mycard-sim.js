/* 내 차례 카드 — 회원 각자에게 무엇을 보여줄까

   운영진도 경기를 뛴다. 아무도 누르지 않아도 회원 각자 화면에
   <어디로 · 언제 · 누구와> 가 떠야 한다.

   문구가 여럿이라 <어느 하나가 잘못 뜨면> 헷갈린다.
   특히 '오늘 다 끝남' 과 '대진에 없음' 을 구별 못 하면
   4경기 다 한 사람에게 "대진에 안 계세요" 가 뜬다.

   실행:  node test/mycard-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const m=/^function cbMyCard\s*\(/m.exec(SRC);
if(!m){ console.log('FAIL cbMyCard 를 찾지 못했습니다'); process.exit(1); }
let d=0,i=SRC.indexOf('{',m.index),code=null;
for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d){code=SRC.slice(m.index,j+1);break;}} }

let CB2=null, state={serverUser:{id:'me',name:'나'}};
const jsArg=v=>JSON.stringify(String(v));
const cbMyCard=new Function('CB2ref','stateRef','jsArg',
  'const state=stateRef; let CB2=CB2ref;\n'+code+'\nreturn cbMyCard;');
const call=()=>cbMyCard(CB2,state,jsArg)();

const P=(id,n)=>({id,name:n});
const g=(r,c,A,B,o={})=>({r,c,teamA:A,teamB:B,sa:o.sa??null,sb:o.sb??null,startedAt:o.run||null});
const ME=P('me','나');

let bad=0; const ok=(c,msg)=>{ if(!c){bad++;console.log('FAIL',msg);} else console.log('ok  ',msg); };
const show=r=>r? `${r.kind} · ${r.big.replace(/\n/g,' / ')}` : 'null';

console.log('■ 대진이 없거나 내가 없을 때');
CB2=null; ok(call()===null, '대진이 없으면 카드도 없다');
CB2={courts:3, games:[g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')])]};
{ const r=call(); ok(r && r.kind==='rest' && r.big.includes('대진에 안'), `내가 대진에 없으면 → ${show(r)}`); }

console.log('\n■ 지금 시작할 수 있을 때');
CB2={courts:3, games:[
  g(1,1,[ME,P('b','이광하')],[P('c','정윤희'),P('d','이경태')]),
  g(1,2,[P('e','E'),P('f','F')],[P('g','G'),P('h','H')])]};
{ const r=call();
  ok(r.kind==='now', `→ ${show(r)}`);
  ok(r.btn==='시작 ▶', '버튼은 시작 ▶');
  ok(r.m.includes('시작 버튼을 눌러주세요'), '“시작 버튼을 눌러주세요” 가 들어간다');
  ok(r.m.includes('파트너 이광하 vs 정윤희'), '파트너 이광하 vs 정윤희 — 사이에 점이 없다');
  ok(r.big.includes('1번 코트'), '“1번 코트” 로 적는다');
  ok(r.big.includes('1번째 게임'), '“1번째 게임” 으로 적는다');
}

console.log('\n■ 내 경기가 진행 중');
CB2={courts:3, games:[
  g(1,1,[ME,P('b','이광하')],[P('c','정윤희'),P('d','이경태')],{run:Date.now()-40*60000})]};
{ const r=call();
  ok(r.kind==='ask', `→ ${show(r)}`);
  ok(r.btn==='점수 입력하기 ›', '버튼은 점수 입력하기');
  ok(!/6:4|6:2/.test(JSON.stringify(r)), '빠른 점수(6:4 등)는 없다');
  ok(r.m.includes('40분째'), '몇 분째인지 나온다');
}

console.log('\n■ 곧 나갈 차례 (앞 경기가 도는 중)');
CB2={courts:2, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:Date.now()-20*60000}),
  g(2,1,[ME,P('e','이광하')],[P('f','정윤희'),P('g','이경태')])]};
{ const r=call();
  ok(r.kind==='go', `→ ${show(r)}`);
  ok(/몸 [푸풀]/.test(r.big), '“몸 풀기” 안내가 들어간다');
  ok(!r.btn, '아직 할 일이 없으니 버튼이 없다');
  ok(r.m.includes('파트너 이광하'), '파트너가 나온다');
}

console.log('\n■ 앞 코트가 점수를 안 넣어 멈춰 있을 때');
CB2={courts:1, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')],{run:Date.now()-50*60000}),
  g(2,1,[ME,P('e','이광하')],[P('f','정윤희'),P('g','이경태')])]};
{ const r=call();
  ok(r.kind==='go', `→ ${show(r)}`);
  ok(r.m.includes('점수가 들어오면'), '“점수가 들어오면 시작해요” 로 이유를 적는다');
}

console.log('\n■ 아직 먼 차례');
CB2={courts:1, games:[
  g(1,1,[P('a','A'),P('b','B')],[P('c','C'),P('d','D')]),
  g(2,1,[P('a','A'),P('c','C')],[P('b','B'),P('d','D')]),
  g(3,1,[P('a','A'),P('d','D')],[P('b','B'),P('c','C')]),
  g(4,1,[ME,P('e','이광하')],[P('f','정윤희'),P('g','이경태')])]};
{ const r=call();
  ok(r.kind==='rest', `→ ${show(r)}`);
  ok(!r.btn, '버튼 없음');
  ok(r.m.includes('경기 뒤'), '몇 경기 뒤인지 나온다');
  ok(/내 경기 \d+\/\d+/.test(r.lb), '내 경기 진행이 2/4 형식으로 나온다');
}

console.log('\n■ 오늘 다 끝났을 때');
{ const t=Date.now()-30*60000;
  CB2={courts:1, games:[
    g(1,1,[ME,P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4,run:t}),
    g(2,1,[ME,P('c','C')],[P('b','B'),P('d','D')],{sa:3,sb:6,run:t})]};
  const r=call();
  ok(r.kind==='done', `→ ${show(r)}`);
  ok(r.big.includes('2경기'), '몇 경기 했는지 나온다');
  ok(r.m.includes('1승 1패'), '전적이 나온다');
  ok(r.m.includes('득실 -1'), '득실이 나온다');
  ok(r.btn==='내 기록 보기 ›', '기록으로 이어준다');
}

console.log('\n■ 끝나고 3시간이 지나면 사라진다');
{ const t=Date.now()-4*3600000;
  CB2={courts:1, games:[g(1,1,[ME,P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4,run:t})]};
  ok(call()===null, '3시간 넘으면 카드가 없다');
  const t2=Date.now()-2*3600000;
  CB2={courts:1, games:[g(1,1,[ME,P('b','B')],[P('c','C'),P('d','D')],{sa:6,sb:4,run:t2})]};
  ok(call()!==null, '2시간이면 아직 보인다');
}

console.log('\n■ 용어');
{ CB2={courts:3, games:[g(3,2,[ME,P('b','B')],[P('c','C'),P('d','D')])]};
  const r=call(), all=JSON.stringify(r);
  ok(all.includes('2번 코트'), '코트는 “2번 코트”');
  ok(all.includes('3번째 게임'), '게임은 “3번째 게임”');
  ok(!/[^번]\dコート|\d코트[^가-힣]/.test(all.replace(/\d번 코트/g,'')), '“3코트” 같은 옛 표기가 없다');
}

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
