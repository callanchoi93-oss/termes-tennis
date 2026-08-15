/* 청백전 — 캡틴 오더와 4경기 고정

   청백전은 캡틴이 우리 팀 순서를 짜야 경기가 만들어진다.
   그때 <전원 정확히 4경기> 를 반드시 지켜야 한다 — 3경기도 5경기도 안 된다.
   덜 뛰면 억울하고 더 뛰면 지친다.

   실행:  node test/cheongbaek-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

/* 저장 문지기를 떼어 그대로 돌린다 */
const m=/^async function cb2OrderSave\s*\(/m.exec(SRC);
if(!m){ console.log('FAIL cb2OrderSave 없음'); process.exit(1); }
let d=0,i=SRC.indexOf('{',m.index),body=null;
for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d){body=SRC.slice(i+1,j);break;}} }
const guard=body.slice(body.indexOf('/* ── 안전장치'), body.indexOf('CB2.orders=CB2.orders||'));

let msg=null;
const toast=t=>{ msg=t; };
const run=(team,cur)=>{ msg=null;
  const o={team,cur,side:'blue'};
  const f=new Function('o','toast', guard+'\nreturn null;');
  f(o,toast); return msg; };

const P=(id,n)=>({id,name:n});
const team=[P('a','유승은'),P('b','이광하'),P('c','정윤희'),P('d','이경태')];
/* 4명 × 4경기 = 16자리 ÷ 2명 = 8게임 */
const good=[['a','b'],['c','d'],['a','c'],['b','d'],['a','d'],['b','c'],['a','b'],['c','d']];

console.log('■ 전원 4경기면 통과');
ok(run(team, good)===null, `4명 모두 4경기 → 통과`);

console.log('\n■ 3경기인 사람이 있으면 막는다');
{ const cur=good.slice(0,7);            // 8게임 중 7게임만 채우면 두 명이 3경기
  const r=run(team,cur);
  ok(r!==null, `막힘 → ${r}`);
  ok(/정윤희|이경태/.test(r), '누가 몇 경기인지 이름이 나온다');
}

console.log('\n■ 5경기인 사람이 있으면 막는다');
{ const cur=good.slice(0,7).concat([['a','b']]);
  const r=run(team,cur);
  ok(r!==null, `막힘 → ${r}`);
}

console.log('\n■ 자리가 비어 있으면 막는다');
{ const cur=good.slice(0,7).concat([[null,'d']]);
  ok(run(team,cur)!==null, `막힘 → ${run(team,cur)}`);
}

console.log('\n■ 한 게임에 같은 사람이 두 번이면 막는다');
{ const cur=[['a','a'],['b','b'],['c','d'],['a','c'],['b','d'],['a','d'],['b','c'],['c','d']];
  const r=run(team,cur);
  ok(r!==null, `막힘 → ${r}`);
}

console.log('\n■ 캡틴 카드가 있는가');
ok(/대진을 짜주세요/.test(SRC), '캡틴에게 “대진을 짜주세요” 카드');
ok(/cb2OrderSheet\(\)/.test(SRC), '누르면 오더 화면으로');
ok(/캡틴이 대진을/.test(SRC), '캡틴이 아닌 회원에게는 기다리라고');
ok(/상대 팀을 기다려요/.test(SRC), '우리 팀만 끝났으면 기다린다고');

console.log('\n■ 진행·종료된 경기는 못 고친다');
ok(/startedAt \|\| \(CB2\.games\|\|\[\]\)\[i\]\.sa!=null/.test(SRC.replace(/\s+/g,' '))
   || /locked=\(CB2\.games\|\|\[\]\)\[i\]/.test(SRC), '이미 시작한 경기는 잠긴다');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
