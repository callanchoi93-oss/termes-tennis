/* 안전장치 — 겹친 대진은 발행되지 않는다

   편성기가 어떻게 바뀌든, 한 사람이 같은 바퀴에 두 코트에 들어간 대진이
   발행되면 코트에서 진행이 통째로 꼬인다(8/14 에 실제로 그랬다).
   그래서 발행 직전에 마지막으로 한 번 더 본다 — 편성기를 믿지 않는다.

   저장까지 막지는 않는다. 이미 꼬여 있는 대진을 순서 바꾸기로 되돌리려면
   그 결과가 저장돼야 하기 때문이다.

   실행:  node test/guard-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
const m=/^function cbFindClash\s*\(/m.exec(SRC);
if(!m){ console.log('FAIL cbFindClash 를 찾지 못했습니다'); process.exit(1); }
let d=0, i=SRC.indexOf('{',m.index), code=null;
for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d){ code=SRC.slice(m.index,j+1); break; }} }
const cbFindClash=new Function(code+'\nreturn cbFindClash;')();

const P=n=>({id:n,name:n});
const g=(r,c,a,b,x,y)=>({r,c,teamA:[P(a),P(b)],teamB:[P(x),P(y)]});
let bad=0; const ok=(c,m2)=>{ if(!c){bad++;console.log('FAIL',m2);} else console.log('ok  ',m2); };

console.log('■ 정상 대진은 통과');
ok(cbFindClash([g(1,1,'A','B','C','D'), g(1,2,'E','F','G','H'),
                g(2,1,'A','C','B','D'), g(2,2,'E','G','F','H')]).length===0,
   '겹침 없음 → 0건');
ok(cbFindClash([]).length===0, '경기가 없어도 터지지 않는다');
ok(cbFindClash(null).length===0, '아예 null 이어도 터지지 않는다');

console.log('\n■ 겹친 대진은 잡힌다');
{ const r=cbFindClash([g(2,1,'이평화','서기훈','이정욱','강태민'),
                       g(2,3,'서기훈','최민혁','이평화','이정욱')]);
  ok(r.length===3, `2게임에 세 명 겹침 → ${r.length}건`);
  ok(r.some(x=>x.includes('서기훈')), '서기훈 이름이 메시지에 나온다');
  ok(r[0].includes('1코트')&&r[0].includes('3코트'), '어느 코트끼리인지 적힌다');
  console.log('     예: '+r[0]);
}
{ const r=cbFindClash([g(1,1,'A','B','C','D'), g(1,1,'E','F','G','H')]);
  ok(r.some(x=>x.includes('코트가 두 번')), '한 바퀴에 같은 코트가 두 번이면 잡힌다');
}

console.log('\n■ 공석은 겹침으로 보지 않는다');
{ const x=g(1,1,'A','B','C','D'), y=g(1,2,'E','F','G','H');
  x.teamA[1]={id:'-',name:'(공석)'}; y.teamA[1]={id:'-',name:'(공석)'};
  ok(cbFindClash([x,y]).length===0, '노쇼로 비운 자리가 둘이어도 통과');
}

console.log('\n■ 8/14 실제 대진 (손으로 순서를 바꾼 뒤)');
{ const real=[
   g(2,1,'이평화','서기훈','이정욱','강태민'),
   g(2,2,'이경태','김진수B','강태민','진성천'),
   g(2,3,'서기훈','최민혁','이평화','이정욱'),
   g(4,1,'이인애','강혜선','정윤희','박희진'),
   g(4,2,'박희진','유승은','정윤희','강혜선')];
  const r=cbFindClash(real);
  ok(r.length===7, `겹침 ${r.length}건 (2게임 4명 · 4게임 3명)`);
  ok(r.some(x=>x.startsWith('2게임')) && r.some(x=>x.startsWith('4게임')),
     '두 바퀴 모두 잡는다');
}

console.log('\n■ 바퀴가 다르면 같은 사람이어도 괜찮다');
ok(cbFindClash([g(1,1,'A','B','C','D'), g(2,2,'A','E','F','G')]).length===0,
   '1게임과 2게임에 같은 사람 → 정상');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
