#!/usr/bin/env bash
# 문법 검사 — 파일의 실제 실행 방식대로 파싱한다.
#
#   왜 따로 만들었나:
#   `node --check server.js` 는 파일을 CommonJS 로 본다. CommonJS 는 코드를
#   function(exports, require, module, ...) { ... } 로 감싸기 때문에,
#   짝이 맞지 않는 `});` 하나가 그 래퍼를 닫아버리면서 문법 오류가 사라진다.
#   실제로 그렇게 통과한 파일이 Railway 부팅에서 SyntaxError 로 죽은 적이 있다.
#
#   server.js  → ES 모듈 (import 문 사용) 이므로 .mjs 로 복사해 검사
#   index.html → 브라우저 <script> 는 래퍼가 없으므로 전역 스코프로 검사
set -u
cd "$(dirname "$0")/.."
fail=0

echo "server.js (ES 모듈)"
cp server.js /tmp/_chk.mjs
if node --check /tmp/_chk.mjs 2>/tmp/_err; then echo "  통과"
else echo "  실패"; sed 's/^/    /' /tmp/_err; fail=1; fi

if [ -f chat-rules.js ]; then
  echo "chat-rules.js (ES 모듈)"
  cp chat-rules.js /tmp/_chk2.mjs
  if node --check /tmp/_chk2.mjs 2>/tmp/_err; then echo "  통과"
  else echo "  실패"; sed 's/^/    /' /tmp/_err; fail=1; fi
fi

echo "public/index.html <script> (브라우저 전역)"
IDX=index.html
[ -f public/index.html ] && IDX=public/index.html
node -e '
const fs=require("fs"), vm=require("vm");
const src=fs.readFileSync(process.argv[1],"utf8");
const blocks=[...src.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
let bad=0;
blocks.forEach((b,i)=>{
  try{ new vm.Script(b, {filename:"block"+i}); }
  catch(e){ console.log("  실패 · 블록 "+i+": "+e.message); bad=1; }
});
if(!bad) console.log("  통과 ("+blocks.length+"개 블록)");
process.exitCode=bad;
' "$IDX" || fail=1

echo ""
if [ "$fail" -eq 0 ]; then echo "전부 통과"; else echo "문법 오류가 있습니다 — 배포하지 마세요"; fi
exit $fail
