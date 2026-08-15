/* 늦참자를 성별까지 보고 막는다

   한 경기의 여성 수는 0(남복)·2(혼복)·4(여복) 뿐이다.
   그래서 한 바퀴에 뛰는 여성 수도 짝수여야 하고, 나머지 자리는 남성으로 채워져야 한다.

   늦참자를 빼고 남은 정시 인원이 이 조건을 못 맞추면 그 바퀴를 못 만든다.
   예) 정시 남7 여1 로 2코트(8자리) → 여성은 0명만 뛸 수 있는데 남자가 7명뿐이라 못 채운다.

   예전에는 <머릿수>만 봐서 이런 경우를 통과시켰고, 편성 단계에서 뒤늦게 실패했다.

   실행:  node test/latesex-sim.js
*/
const fs=require('fs'), path=require('path');
const SRC=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
function grab(name){
  const m=new RegExp('^function '+name+'\\s*\\(','m').exec(SRC);
  if(!m) throw new Error(name+' 없음');
  let d=0,i=SRC.indexOf('{',m.index);
  for(let j=i;j<SRC.length;j++){ if(SRC[j]==='{')d++; else if(SRC[j]==='}'){d--; if(!d) return SRC.slice(m.index,j+1);} }
}
const F=new Function(grab('cbSexFits')+'\n'+grab('cbCourtOk')+'\n'+grab('lateMax')+
  '\nreturn {cbSexFits,cbCourtOk,lateMax};')();

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };

console.log('■ 한 바퀴를 채울 수 있는 구성 (2코트 · 8자리)');
ok(F.cbSexFits(8,0,2)===true,  '남8 여0 → 남복 2경기');
ok(F.cbSexFits(6,2,2)===true,  '남6 여2 → 남복 1 · 혼복 1');
ok(F.cbSexFits(4,4,2)===true,  '남4 여4 → 혼복 2 (또는 남복+여복)');
ok(F.cbSexFits(0,8,2)===true,  '남0 여8 → 여복 2경기');
ok(F.cbSexFits(10,4,2)===true, '남는 사람이 있어도 된다');

console.log('\n■ 못 채우는 구성 — 남녀가 둘 다 홀수');
ok(F.cbSexFits(7,1,2)===false, '남7 여1 → 여성 0명만 뛸 수 있는데 남자가 7명');
ok(F.cbSexFits(5,3,2)===false, '남5 여3');
ok(F.cbSexFits(3,5,2)===false, '남3 여5');
ok(F.cbSexFits(1,7,2)===false, '남1 여7');
ok(F.cbSexFits(3,3,2)===false, '남3 여3 → 인원 자체가 모자람');

console.log('\n■ 3코트 (12자리)');
ok(F.cbSexFits(12,0,3)===true,  '남12 여0');
ok(F.cbSexFits(10,2,3)===true,  '남10 여2');
ok(F.cbSexFits(8,4,3)===true,   '남8 여4');
ok(F.cbSexFits(11,1,3)===false, '남11 여1 → 못 채움');
ok(F.cbSexFits(9,3,3)===false,  '남9 여3 → 못 채움');

console.log('\n■ 늦참자를 빼고 나서 판단한다');
const after=(m,f,lm,lf,c)=>F.cbSexFits(m-lm, f-lf, c);
ok(after(13,5,1,0,3)===true,  '남13 여5 에서 남자 1명 늦참 → 남12 여5 · 됨');
ok(after(13,5,0,1,3)===true,  '남13 여5 에서 여자 1명 늦참 → 남13 여4 · 됨');
ok(after(12,2,1,0,3)===true,  '남12 여2 에서 남자 1명 늦참 → 남11 여2 · 혼복1+남복2 로 됨');
ok(after(10,2,0,1,2)===true,  '남10 여2 에서 여자 1명 늦참 → 남10 여1 · 됨');
ok(after(9,3,1,0,2)===true,   '남9 여3 에서 남자 1명 늦참 → 남8 여3 · 됨');

console.log('\n■ 규칙 정리');
{ const cases=[];
  for(let m=0;m<=12;m++) for(let f=0;f<=12;f++){
    if(m+f<8) continue;
    if(!F.cbSexFits(m,f,2)) cases.push([m,f]);
  }
  ok(cases.every(([m,f])=>m%2===1 && f%2===1),
    `2코트에서 막히는 ${cases.length}가지 — 전부 남녀가 둘 다 홀수`);
}

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
