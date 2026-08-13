/* 연락처 입력 — 자동 하이픈 · 유효성 테스트

   임원이 실제로 전화를 거는 번호라 오타가 그대로 저장되면 안 된다.
   숫자만 눌러도 010-1234-5678 로 정리되고, 형식이 틀리면 저장을 막는다.

   실행:  node test/phone-sim.js
*/
function phoneFmt(raw){
  const d=String(raw||'').replace(/[^0-9]/g,'').slice(0,11);
  if(d.length<4) return d;
  /* 10자리(010-123-4567)와 11자리(010-1234-5678)를 나눠 자른다 */
  if(d.length<=7)  return d.slice(0,3)+'-'+d.slice(3);
  if(d.length<=10) return d.slice(0,3)+'-'+d.slice(3,6)+'-'+d.slice(6);
  return d.slice(0,3)+'-'+d.slice(3,7)+'-'+d.slice(7,11);
}
function phoneOk(v){ return /^01[016789]-?\d{3,4}-?\d{4}$/.test(String(v||'').replace(/\s/g,'')); }

let bad = 0;
const ok = (c, m) => { if (!c) { bad++; console.log('FAIL', m); } else console.log('ok  ', m); };
const t = (input, fmt, valid) => {
  const f = phoneFmt(input), v = phoneOk(f);
  ok(f === fmt && v === valid,
     `${JSON.stringify(input).padEnd(22)} → ${f.padEnd(14)} ${v ? '유효' : '무효'}`);
};

console.log('■ 자동 하이픈');
t('01012345678',  '010-1234-5678', true);   // 11자리
t('0101234567',   '010-123-4567',  true);   // 10자리 (옛 번호)
t('010-1234-5678','010-1234-5678', true);   // 이미 하이픈이 있어도 그대로
t('010 1234 5678','010-1234-5678', true);   // 공백은 무시
t('abc010!!1234@@5678', '010-1234-5678', true);  // 숫자만 남긴다
t('010123456789', '010-1234-5678', true);   // 11자리에서 자른다

console.log('\n■ 입력 중');
t('0',       '0',        false);
t('010',     '010',      false);
t('010123',  '010-123',  false);

console.log('\n■ 휴대폰이 아닌 번호는 막는다');
t('0212345678', '021-234-5678', false);     // 서울 지역번호
t('0311234567', '031-123-4567', false);     // 경기 지역번호
t('15881588',   '158-815-88',   false);     // 대표번호

console.log('\n■ 통신사 식별번호');
['010','011','016','017','018','019'].forEach(p =>
  ok(phoneOk(phoneFmt(p + '12345678')), `${p} 로 시작하면 유효`));
ok(!phoneOk(phoneFmt('01212345678')), '012 는 무효');

console.log('\n■ 비워두기');
ok(phoneFmt('') === '', '빈 값은 빈 값 그대로');
ok(!phoneOk(''), '빈 값은 유효하지 않다 (저장은 허용 — 선택 항목)');

console.log(bad ? `\n${bad}건 실패` : '\n전부 통과');
process.exit(bad ? 1 : 0);
