/* 알림 점과 대화 숫자가 서로 다른 버튼에 붙는가

   대화 버튼과 알림 종이 둘 다 class="bell" 이었다.
   document.querySelector('.bell') 은 <첫 번째> 만 잡는데 그게 대화 버튼이라,
   알림이 오면 주황 점이 대화 버튼에 찍혔다.

   실행:  node test/badge-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 두 버튼이 구별되는가');
{ const bells=[...SRC.matchAll(/<div class="bell"([^>]*)>/g)].map(m=>m[1]);
  ok(bells.length===2, `class="bell" 이 ${bells.length}개 (대화 · 알림)`);
  const chat=bells.find(a=>/aria-label="대화"/.test(a));
  const bell=bells.find(a=>/aria-label="알림"/.test(a));
  ok(!!chat, '대화 버튼이 있다');
  ok(!!bell, '알림 종이 있다');
  ok(/id="chatBtn"/.test(chat||''), '대화 버튼에 id="chatBtn"');
  ok(/id="bellBtn"/.test(bell||''), '알림 종에 id="bellBtn"');
}

console.log('\n■ 알림 점이 알림 종에만 붙는가');
ok(!/querySelector\('\.bell'\)/.test(SRC),
   "querySelector('.bell') 이 남아 있지 않다 — 첫 번째(대화)를 잡던 원인");
{ const n=(SRC.match(/getElementById\('bellBtn'\)/g)||[]).length;
  ok(n>=3, `알림 종을 id 로 집는 곳 ${n}곳`); }
{ /* has 클래스를 붙이고 떼는 자리가 모두 bellBtn 을 쓰는가 */
  const lines=SRC.split('\n').filter(l=>/classList\.(add|remove|toggle)\(\s*'has'/.test(l));
  ok(lines.length>0, `has 를 다루는 줄 ${lines.length}개`);
  ok(lines.every(l=>/bellBtn/.test(l)), '전부 알림 종(bellBtn)에만 붙인다');
}

console.log('\n■ 대화 숫자는 따로 논다');
ok(/id="chatCnt"/.test(SRC), '대화 숫자는 chatCnt 라는 따로 있는 칸');
{ const m=/function paintUnreadBadge\(\)\{[\s\S]*?\n\}/.exec(SRC);
  ok(m && /getElementById\('chatCnt'\)/.test(m[0]), '대화 숫자는 chatCnt 만 건드린다');
  ok(m && !/bell/.test(m[0]), '대화 숫자 그리는 곳에서 알림 종을 안 건드린다');
}

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
