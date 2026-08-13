#!/usr/bin/env bash
# 대화 규칙 회귀 테스트 — 여러 시드로 돌린다.
# 한 시드만 돌리면 우연히 안 걸리는 조합이 생긴다.
set -u
cd "$(dirname "$0")/.."

SEEDS="${*:-1 7 42 1234 99991 20260812 555 8080 31337 777 2468 13579}"
fail=0

# 문법부터. 여기서 막히면 아래 테스트는 볼 필요도 없다.
echo "문법"
if ./test/syntax.sh >/tmp/_syn 2>&1; then
  echo "  통과"
else
  sed 's/^/  /' /tmp/_syn
  echo ""
  echo "문법 오류 — 배포하지 마세요"
  exit 1
fi

# 정의 없이 참조되는 이름 — 함수를 지울 때 옆 상수까지 딸려 나갔는지 본다.
# 문법 검사로는 안 잡힌다 (문법은 멀쩡하고 실행할 때 터진다).
echo "정의 누락"
if node test/undef-sim.js >/tmp/_undef 2>&1; then
  echo "  통과"
else
  sed 's/^/  /' /tmp/_undef
  echo ""
  echo "정의가 사라진 이름이 있습니다 — 배포하지 마세요"
  exit 1
fi

echo ""
echo "대화 규칙"

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

echo ""
echo "월례대회 조 · 게스트 제외"
if node test/tier-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/tier-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "직책 · 권한 이름표"
if node test/title-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/title-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "여성/남성 클럽 배지"
if node test/gender-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/gender-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "클럽 별칭 · 이름 일관성"
if node test/alias-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/alias-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "이름·클럽 관리"
if node test/club-admin-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/club-admin-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

if [ "$fail" -eq 0 ]; then echo "" && echo "전부 통과"; else echo "" && echo "실패한 항목이 있습니다"; fi
exit $fail
