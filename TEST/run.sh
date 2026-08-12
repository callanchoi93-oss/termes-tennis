#!/usr/bin/env bash
# 대화 규칙 회귀 테스트 — 여러 시드로 돌린다.
# 한 시드만 돌리면 우연히 안 걸리는 조합이 생긴다.
set -u
cd "$(dirname "$0")/.."

SEEDS="${*:-1 7 42 1234 99991 20260812 555 8080 31337 777 2468 13579}"
fail=0

for s in $SEEDS; do
  out=$(node test/chat-sim.js "$s" 2>&1 | grep -v "ExperimentalWarning\|trace-warnings")
  if echo "$out" | grep -q "오류 없음"; then
    printf "  seed %-10s 통과\n" "$s"
  else
    printf "  seed %-10s 실패\n" "$s"
    echo "$out" | sed -n '/불변식 위반/,$p' | sed 's/^/      /'
    fail=1
  fi
done

echo ""
echo "모임 참석 응답(RSVP)"
if node test/rsvp-sim.js 2>&1 | grep -v "ExperimentalWarning\|trace-warnings" | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/rsvp-sim.js 2>&1 | grep -v "ExperimentalWarning\|trace-warnings" | grep FAIL | sed 's/^/  /'
  fail=1
fi

if [ "$fail" -eq 0 ]; then echo "" && echo "전부 통과"; else echo "" && echo "실패한 항목이 있습니다"; fi
exit $fail
