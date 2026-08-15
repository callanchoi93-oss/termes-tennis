/* 모임 시간 입력

   폰의 시계 굴림판은 두 번 굴려야 해서 느리다. 직접 타이핑하게 바꾸되,
   19:30 말고 다르게 적어도 알아듣게 한다. 못 읽으면 어떻게 적을지 알려준다.

   실행:  node test/time-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const m=/^function neParseTime\s*\(/m.exec(SRC);
if(!m){ console.log('FAIL neParseTime 없음'); process.exit(1); }
let d=0,i=SRC.indexOf('{',m.index),code=null;
for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d){code=SRC.slice(m.index,j+1);break;}} }
const f=new Function(code+'\nreturn neParseTime;')();

let bad=0; const ok=(c,msg)=>{ if(!c){bad++;console.log('FAIL',msg);} else console.log('ok  ',msg); };
const T=(inp,want)=>ok(f(inp)===want, `${JSON.stringify(inp).padEnd(16)} → ${f(inp)||'다시 입력'}`);

console.log('■ 제대로 적었을 때');
T('19:30','19:30'); T('09:00','09:00'); T('00:00','00:00'); T('23:59','23:59');

console.log('\n■ 다르게 적어도 알아듣는다');
T('1930','19:30');      T('930','09:30');
T('19시30분','19:30');   T('19시','19:00');
T('19.30','19:30');     T('7:5','07:05');
T('오후 7시 30분','19:30'); T('저녁 7시','19:00');
T('오전 9시','09:00');    T(' 19:30 ','19:30');

console.log('\n■ 못 읽는 것 — 다시 입력하라고 한다');
[['25:00','시가 24를 넘음'],['19:70','분이 60을 넘음'],['abc','글자'],
 ['','빈칸'],['저녁','숫자가 없음'],['19:','분이 없음']].forEach(([v,why])=>
  ok(f(v)===null, `${JSON.stringify(v).padEnd(10)} → 다시 입력 (${why})`));

console.log('\n■ 안내 문구가 있는가');
ok(/19:30\s*<\/b>\s*으로 적어주세요/.test(SRC.replace(/\s+/g,' '))
   || /19:30 으로 적어주세요/.test(SRC), '“19:30 으로 적어주세요” 안내');
ok(/placeholder="00:00"/.test(SRC), '입력창에 00:00 본보기');
ok(/inputmode="numeric"/.test(SRC), '폰에서 숫자판이 먼저 뜬다');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
