/* 선수 카드 — 어떤 칸이 그려지는가

   1:1 은 처음 만나는 사람과 코트에서 두 시간을 보내는 자리다.
   전적보다 '어떤 사람인가'(매너·스타일)가 먼저 궁금하므로 아랫줄 앞에 둔다.
   매너·스타일은 경기 수와 무관하니 배치 중에도 채워져 카드가 비지 않는다.

   값이 없는 칸은 '—' 를 그리지 않고 칸 자체를 없앤다 —
   빈 값이 나쁜 평가처럼 보이면 안 된다.

   실행:  node test/card-sim.js
*/
const PLACEMENT_GAMES = 5;

function cardCells(u){
  const age = u.birth_year ? (new Date().getFullYear()-u.birth_year+1) : null;
  return [
    ['나이',   age?age+'세':null],
    ['신장',   u.height?u.height+'cm':null],
    ['주 손',  u.handed||null],
    ['백핸드', u.backhand||null],
  ].filter(x=>x[1]).map(x=>x[0]);
}
function cardStats(u){
  const w=u.wins||0, l=u.losses||0, tot=w+l, wr=tot?Math.round(w/tot*100):null;
  return [
    ['매너',   u.manner ? String(u.manner) : null],
    ['스타일', u.style || null],
    ['통산',   tot?`${w}승 ${l}패`:null],
    ['승률',   wr==null?null:wr+'%'],
  ].filter(x=>x[1]).map(x=>x[0]);
}
function tierText(u){
  const pl = u.played||0;
  return pl < PLACEMENT_GAMES ? `배치 중 ${pl}/${PLACEMENT_GAMES}경기` : '티어';
}

let bad=0; const ok=(c,m)=>{ if(!c){bad++;console.log('FAIL',m);} else console.log('ok  ',m); };
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

console.log('■ 배치 중이어도 매너·스타일은 보인다');
const placing={birth_year:1993,height:180,handed:'오른손',backhand:'투핸드',
               manner:4.8,style:'베이스라이너',played:0,wins:0,losses:0};
ok(tierText(placing)==='배치 중 0/5경기','머리줄은 배치 중');
ok(eq(cardStats(placing),['매너','스타일']),`아랫줄: ${cardStats(placing).join(' · ')}`);
ok(cardStats(placing).length>0,'아랫줄이 비지 않는다 (예전엔 통째로 비었다)');

console.log('\n■ 배치 완료');
const placed=Object.assign({},placing,{played:12,wins:12,losses:7});
ok(tierText(placed)==='티어','머리줄에 티어가 뜬다');
ok(eq(cardStats(placed),['매너','스타일','통산','승률']),`아랫줄: ${cardStats(placed).join(' · ')}`);
ok(cardStats(placed).length===4,'네 칸 — 다섯이면 긴 값이 줄바꿈된다');
ok(!cardStats(placed).includes('최고'),'최고 레이팅은 넣지 않는다');

console.log('\n■ 값이 없으면 칸 자체를 없앤다');
ok(!cardStats({style:'올라운더'}).includes('매너'),'후기가 없으면 매너 칸이 없다');
ok(!cardStats({manner:4.2}).includes('스타일'),'스타일 미입력이면 스타일 칸이 없다');
ok(eq(cardStats({}),[]),'아무 값도 없으면 아랫줄 자체가 없다');
ok(eq(cardCells({}),[]),'윗줄도 같은 규칙');
ok(eq(cardCells({height:180}),['신장']),'있는 값만 그린다');

console.log('\n■ 매너 평균');
const { DatabaseSync } = await import('node:sqlite');
const db=new DatabaseSync(':memory:');
db.exec('CREATE TABLE om_reviews(to_user INTEGER, stars REAL)');
db.exec('INSERT INTO om_reviews VALUES (1,5),(1,4.5),(1,5),(1,4)');
const q=id=>db.prepare('SELECT ROUND(AVG(stars),1) avg, COUNT(*) n FROM om_reviews WHERE to_user=?').get(id);
ok(q(1).avg===4.6, `후기 4건 → 4.6 (실제 ${q(1).avg})`);
ok((q(99).avg||null)===null, '후기 0건 → null');

console.log(bad?`\n${bad}건 실패`:'\n전부 통과');
process.exit(bad?1:0);
