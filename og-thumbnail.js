/* ═══════════════════════════════════════════════════════════════
   MATSU — 오픈매치 카톡 썸네일(OG) 서버 모듈
   ----------------------------------------------------------------
   왜 필요한가: 카톡·문자 미리보기 봇은 자바스크립트를 실행하지 않아서,
   서버가 HTML을 줄 때 <head>에 매치별 og:title / og:image를
   "미리 심어서" 보내야 썸네일이 떠요.

   설치:  npm i @napi-rs/canvas
   준비:  프레첼 캐릭터 PNG 1장을 서버에 저장 (예: ./assets/pretzel.png)

   server.js 적용 (정적 서빙보다 "위"에 넣는 게 중요):
   ----------------------------------------------------------------
   const { ogPage, ogImage } = require('./og-thumbnail');

   app.get('/og/match/:id.png', ogImage({
     getMatch: async id => db.getOpenMatch(id),        // 기존 매치 조회 함수 연결
     pretzelPath: __dirname + '/assets/pretzel.png',
   }));

   app.use(ogPage({
     indexPath: __dirname + '/public/index.html',       // 앱 index.html 경로
     getMatch: async id => db.getOpenMatch(id),
     baseUrl: 'https://matsu.up.railway.app',
   }));

   app.use(express.static('public'));                   // ← 이 줄보다 위!
   ----------------------------------------------------------------
   프론트는 수정 없음: shareMatch()가 만드는 /?match=ID 링크 그대로 동작.
   카톡이 이미 캐시한 링크는 https://developers.kakao.com/tool/clear/og
   에서 URL 입력 후 캐시 삭제하면 새 썸네일이 떠요.
   ═══════════════════════════════════════════════════════════════ */
const fs = require('fs');

const escAttr = s => String(s || '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');

/* ── ① HTML에 OG 태그 주입 ─────────────────────────────────── */
function ogPage({ indexPath, getMatch, baseUrl }) {
  return async (req, res, next) => {
    const id = req.query.match || (req.path.match(/^\/m\/(\d+)/) || [])[1];
    if (!id) return next();

    let m = null;
    try { m = await getMatch(id); } catch (e) { /* 조회 실패 → 기본 페이지 */ }
    if (!m) return next();

    const title = `${m.loc || '오픈매치'} · MATSU 초대장`;
    const desc = [
      m.dt || '',
      [m.sido, m.sigungu].filter(Boolean).join(' '),
      m.price ? `참가비 ${Number(m.price).toLocaleString()}원` : '무료',
      `${m.cur || 0}/${m.cap || 0}명 모집`,
    ].filter(Boolean).join(' · ');

    const tags = `
<meta property="og:type" content="website">
<meta property="og:site_name" content="맞수 MATSU">
<meta property="og:title" content="${escAttr(title)}">
<meta property="og:description" content="${escAttr(desc)}">
<meta property="og:url" content="${baseUrl}/?match=${id}">
<meta property="og:image" content="${baseUrl}/og/match/${id}.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">`;

    const html = fs.readFileSync(indexPath, 'utf8');   // 배포 중 교체 대비 매번 읽기
    res.set('Cache-Control', 'no-store');
    res.send(html.replace('</head>', tags + '\n</head>'));
  };
}

/* ── ② 매치별 1200×630 썸네일 이미지 생성 ──────────────────── */
function ogImage({ getMatch, pretzelPath }) {
  const { createCanvas, loadImage } = require('@napi-rs/canvas');
  let pretzel = null;

  return async (req, res) => {
    let m = null;
    try { m = await getMatch(req.params.id); } catch (e) {}
    if (!m) return res.status(404).end();
    if (!pretzel) pretzel = await loadImage(pretzelPath);

    const W = 1200, H = 630;
    const cv = createCanvas(W, H);
    const x = cv.getContext('2d');

    /* 배경: 크림 + 프레첼 하프드롭 패턴 (여백 없이 꽉 채움) */
    x.fillStyle = '#f7dfad';
    x.fillRect(0, 0, W, H);
    const tw = 150, gx = 34, gy = 24;
    let col = 0;
    for (let px = -tw; px < W + tw; px += tw + gx, col++) {
      const y0 = (col % 2 === 0) ? -tw / 2 : -tw / 2 + (tw + gy) / 2;
      let row = 0;
      for (let py = y0; py < H + tw; py += tw + gy, row++) {
        const deg = ((col + row) % 2 === 0 ? 12 : -12) * Math.PI / 180;
        x.save();
        x.translate(px + tw / 2, py + tw / 2);
        x.rotate(deg);
        x.globalAlpha = 0.9;
        x.drawImage(pretzel, -tw / 2, -tw / 2, tw, tw);
        x.restore();
      }
    }
    x.globalAlpha = 1;

    /* 아웃라인 텍스트 헬퍼: 흰 외곽선 → 본색 채움 (초대장과 같은 스타일) */
    const F = (w, s) => `${w} ${s}px "Pretendard","Apple SD Gothic Neo","Malgun Gothic",sans-serif`;
    const outlined = (text, cx, cy, size, fill, weight = 900, stroke = 10) => {
      x.font = F(weight, size);
      x.textAlign = 'center';
      x.textBaseline = 'middle';
      x.lineJoin = 'round';
      x.lineWidth = stroke;
      x.strokeStyle = '#ffffff';
      x.strokeText(text, cx, cy);
      x.fillStyle = fill;
      x.fillText(text, cx, cy);
    };

    const loc = (m.loc || '오픈매치').slice(0, 16);
    const info = [
      m.dt || '',
      m.price ? `${Number(m.price).toLocaleString()}원` : '무료',
      `${m.cur || 0}/${m.cap || 0}명`,
    ].filter(Boolean).join(' · ');

    outlined('오픈매치 초대장', W / 2, 175, 42, '#cf5418', 800, 12);
    outlined(loc, W / 2, 300, loc.length > 10 ? 78 : 92, '#1c1b18', 900, 16);
    outlined(info, W / 2, 415, 40, '#6b5138', 800, 12);
    outlined('함께 칠 사람을 찾고 있어요 — MATSU', W / 2, 520, 32, '#8a5230', 800, 10);

    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=600'); // 10분 캐시 (모집 인원 갱신 반영)
    res.send(cv.toBuffer('image/png'));
  };
}

module.exports = { ogPage, ogImage };
