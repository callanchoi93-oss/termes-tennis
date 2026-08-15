/* 일반·성비를 쓸 수 있는 조건

   일반과 성비는 '바퀴로 도는' 방식이다 — 모두가 한 바퀴에 한 번씩 뛴다.
   그래서 인원과 코트가 맞아야 한다.
     ① 바퀴 수가 정수     — 인원×4 ÷ (코트×4)
     ② 쉬는 사람 1명 이상  — 0명이면 한 코트가 먼저 끝나도 넣을 경기가 없다
     ③ 늦참을 빼고도 코트를 채울 수 있어야 한다

   한울은 코트마다 따로 돌아 이 제약이 없다. 그래서 막힐 때는 늘 한울이 답이다.

   실행:  node test/mode-gate-sim.js
*/
const fs=require('fs'), path=require('path');
const src=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const grab=name=>{
  const st=src.indexOf('function '+name+'(');
  if(st<0) throw new Error(name+' 없음');
  let d=0,i=src.indexOf('{',st);
  for(let j=i;j<src.length;j++){ if(src[j]==='{')d++; else if(src[j]==='}'){d--; if(!d) return src.slice(st,j+1);} }
  throw new Error(name+' 끝을 못 찾음');
};
const F=new Function(grab('cbCourtOk')+'\n'+grab('cbCourtsFor')+'\n'+grab('lateMax')+
  '\nreturn {cbCourtOk,cbCourtsFor,lateMax};')();

const why=(n,c,L)=>{
  const r=F.cbCourtOk(n,c);
  if(!r.ok) return r.why;
  if(L){ if(n-L < c*4) return '늦참을 빼면 코트를 못 채움';
         if(!F.lateMax(n,c,L)) return '늦참을 미룰 수 없음'; }
  return null;
};
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 쓸 수 있는 조합');
[[12,2],[18,3],[16,2],[24,3],[20,4],[10,2]].forEach(([n,c])=>
  ok(why(n,c,0)===null, `${n}명 ${c}코트`));

console.log('\n■ 막아야 하는 조합');
ok(why(12,3,0)!==null, '12명 3코트 — 쉬는 사람 0명 (모두 매 바퀴 뜀)');
ok(why(8,2,0)!==null,  '8명 2코트 — 쉬는 사람 0명');
ok(why(16,4,0)!==null, '16명 4코트 — 쉬는 사람 0명');
ok(why(14,3,0)!==null, '14명 3코트 — 바퀴가 정수가 아님');
ok(why(16,3,0)!==null, '16명 3코트 — 바퀴가 정수가 아님');
ok(why(20,3,0)!==null, '20명 3코트 — 바퀴가 정수가 아님');
ok(why(6,2,0)!==null,  '6명 2코트 — 인원 부족');

console.log('\n■ 늦참까지 보면');
ok(why(10,2,2)===null, '10명 2코트 늦참 2명 — 가능');
ok(why(10,2,3)!==null, '10명 2코트 늦참 3명 — 정시 7명으로 8자리를 못 채움');
ok(why(12,2,4)===null, '12명 2코트 늦참 4명 — 가능');
ok(why(18,3,4)===null, '18명 3코트 늦참 4명 — 가능');
ok(why(8,2,1)!==null,  '8명 2코트 늦참 1명 — 코트부터 안 맞음');

console.log('\n■ 미룰 수 있는 한도 (2코트)');
[[10,1,1],[10,2,1],[12,1,2],[12,4,2],[14,3,3],[16,4,4]].forEach(([n,L,want])=>
  ok(F.lateMax(n,2,L)===want, `${n}명 늦참 ${L}명 → ${F.lateMax(n,2,L)}게임까지`));

console.log('\n■ 그 인원으로 되는 코트 수');
[[12,[1,2]],[18,[1,2,3]],[16,[1,2]],[24,[1,2,3,4]],[20,[1,2,4]]].forEach(([n,want])=>{
  const got=F.cbCourtsFor(n).filter(c=>c<=4);
  ok(JSON.stringify(got)===JSON.stringify(want), `${n}명 → ${got.join('·')}코트`);
});

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
