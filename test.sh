#!/usr/bin/env bash
# 스모크 테스트 — 서버를 띄우고 핵심 엔드포인트를 점검
set -e
PORT=${PORT:-4555}
rm -f test.db test.db-*
DB_PATH=test.db npm run seed >/dev/null 2>&1
DB_PATH=test.db PORT=$PORT node --experimental-sqlite server.js >/tmp/matsu_test.log 2>&1 &
SRV=$!; sleep 2
B=http://localhost:$PORT
fail(){ echo "FAIL: $1"; kill $SRV 2>/dev/null; exit 1; }
curl -sf $B/health >/dev/null || fail health
TOK=$(curl -s -X POST $B/auth/dev-login -H 'Content-Type: application/json' -d '{"name":"tester"}' | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')
[ -n "$TOK" ] || fail login
curl -sf -X POST $B/posts -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"title":"t"}' >/dev/null || fail post
curl -sf "$B/rankings" >/dev/null || fail rankings
curl -sf "$B/admin/stats?key=${ADMIN_KEY:-matsu-admin}" >/dev/null || fail admin
echo "SMOKE TEST PASSED ✅"
kill $SRV 2>/dev/null; rm -f test.db test.db-*
