/* 정의 없이 참조되는 이름 찾기 (index.html)

   왜 필요한가:
   함수를 지울 때 블록 경계를 잘못 잡으면 옆에 있던 상수까지 딸려 나간다.
   실제로 회비 기능을 걷어내면서 바로 아래 있던 REGIONS(행정구역)와 WD(요일)가
   함께 사라졌고, 오픈매치 화면이 "REGIONS is not defined" 로 하얗게 떴다.
   문법 검사로는 절대 잡히지 않는다 — 문법은 멀쩡하기 때문이다.

   여기서는 최상위에 선언된 이름들을 모으고, 코드가 참조하는 대문자 상수
   (REGIONS, WD, ICONS 같은 것)가 그 목록에 있는지만 확인한다.
   대문자 상수로 좁힌 이유: 지역 변수·프로퍼티·브라우저 API 와 헷갈리지 않으면서
   "통째로 사라지면 화면이 죽는" 부류를 정확히 겨냥하기 때문이다.

   실행:  node test/undef-sim.js
*/
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const raw = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
/* 주석을 지우고 본다 — 주석 끝의 "…인라인 SVG." 같은 문장이 참조로 잡히면 안 된다.
   선언 수집에도 같은 소스를 쓰므로 주석 안의 예시 코드가 정의로 둔갑하지도 않는다. */
const src = raw.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');

/* 선언 수집 — let A=1, B=2 처럼 쉼표로 이어진 것도 모두 잡는다 */
const declared = new Set();
for (const m of src.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);
for (const m of src.matchAll(/\b(?:const|let|var)\s+([^;\n]+)/g)) {
  for (const d of m[1].split(',')) {
    const n = d.trim().match(/^([A-Za-z_$][\w$]*)/);
    if (n) declared.add(n[1]);
  }
}
/* 함수 매개변수도 정의로 친다 */
for (const m of src.matchAll(/\(([^)]*)\)\s*=>/g))
  for (const d of m[1].split(',')) {
    const n = d.trim().match(/^([A-Za-z_$][\w$]*)/); if (n) declared.add(n[1]);
  }

/* 브라우저·표준 전역 */
const GLOBALS = new Set(['Math','JSON','Object','Array','String','Number','Boolean','Date','RegExp',
  'Promise','Map','Set','WeakMap','Error','Intl','NaN','Infinity','URL','URLSearchParams','FileReader',
  'FormData','Blob','Image','Audio','XMLHttpRequest','WebSocket','Notification','ClipboardItem',
  'IntersectionObserver','MutationObserver','ResizeObserver','AbortController','TextEncoder','TextDecoder',
  'DOMParser','Element','HTMLElement','Node','Event','CustomEvent','Uint8Array','ArrayBuffer','BigInt',
  'Symbol','Proxy','Reflect','WeakSet','Function','JSON','Intl','PERFORMANCE','CSS']);

/* 참조 수집 — 실제로 '값을 꺼내 쓰는' 자리만 본다.
   NAME[...] · NAME.xxx · NAME(...) 세 가지.
   그냥 대문자 단어는 SVG path·문구·클래스명에도 흔해서 세지 않는다. */
const used = new Map();
for (const m of src.matchAll(/(?:^|[^\w$.'"`])([A-Z][A-Z0-9_]{2,})(?![\w$])\s*[[.(]/g)) {
  const n = m[1];
  if (!used.has(n)) used.set(n, src.slice(0, m.index).split('\n').length);
}

/* 실행 중에 외부에서 주입되는 전역 (CDN 스크립트 등) */
const RUNTIME = new Set(['XLSX']);      // 엑셀 내보내기용, window.XLSX 로 지연 로드

const missing = [...used.keys()]
  .filter(n => !declared.has(n) && !GLOBALS.has(n) && !RUNTIME.has(n))
  /* window.NAME 로만 쓰이면 런타임 주입이므로 넘어간다 */
  .filter(n => !new RegExp('window\\.' + n + '\\b').test(src));

if (missing.length) {
  console.log('정의 없이 참조되는 이름:');
  missing.forEach(n => console.log(`  !! ${n}  (첫 사용 ${used.get(n)}행)`));
  console.log('\n실패 — 함수를 지울 때 옆의 상수까지 딸려 나갔는지 확인하세요');
  process.exit(1);
}
console.log(`ok   대문자 상수 ${used.size}개 모두 정의돼 있음`);
console.log('\n전부 통과');
