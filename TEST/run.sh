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


# 진짜 서버를 띄우고 주요 API 를 눌러본다. 문법 검사가 못 잡는 500·404 를 여기서 잡는다.
# node_modules 가 없으면 건너뛴다 (CI 가 아닌 곳에서도 나머지는 돌아야 한다).
if [ -d node_modules/express ]; then
  echo "서버 연기 테스트"
  if ./test/smoke.sh >/tmp/_smoke 2>&1; then
    echo "  통과"
  else
    sed 's/^/  /' /tmp/_smoke | tail -25
    echo ""
    echo "API 가 실패했습니다 — 배포하지 마세요"
    exit 1
  fi
  echo ""
else
  echo "서버 연기 테스트"
  echo "  건너뜀 (npm install 후 다시 실행하세요)"
  echo ""
fi

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

echo ""
echo "연락처 입력"
if node test/phone-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/phone-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "선수 카드"
if node test/card-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/card-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "온보딩 → 내정보"
if node test/onboard-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/onboard-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "번개 모임 · 대진 권한"
if node test/flash-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/flash-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "대회 준비 대진 (전원 4경기)"
if node test/tourney-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/tourney-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "대진 겹침 검사"
if node test/clash-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/clash-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "예상 종료 시각"
if node test/eta-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/eta-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "명단 조정 (늦참·노쇼)"
if node test/adjust-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/adjust-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "기록 화면 표기"
if node test/stats-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/stats-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "코트가 비지 않는 대진"
if node test/idlefree-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/idlefree-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "일반·성비 가능 조건"
if node test/mode-gate-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/mode-gate-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "참석 인원 세기"
if node test/head-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/head-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "내 차례 카드"
if node test/mycard-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/mycard-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "대진 방식별 카드"
if node test/mode-card-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/mode-card-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "대진표 이동 안내"
if node test/movehint-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/movehint-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "모임 시간 입력"
if node test/time-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/time-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "홈 요약 카드"
if node test/homecard-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/homecard-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "청백전 캡틴 오더"
if node test/cheongbaek-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/cheongbaek-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "운영진 카드"
if node test/officer-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/officer-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "발행 안전장치"
if node test/guard-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/guard-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

echo ""
echo "늦참 성별 조건"
if node test/latesex-sim.js 2>&1 | grep -q "전부 통과"; then
  echo "  통과"
else
  node test/latesex-sim.js 2>&1 | grep FAIL | sed 's/^/  /'
  fail=1
fi

if [ "${SWEEP:-0}" = "1" ]; then
  echo ""
  echo "대진 전수 검사 (오래 걸림 · SWEEP=1 일 때만)"
  if node test/bracket-sweep.js 2>&1 | grep -q "전부 통과"; then
    echo "  통과"
  else
    node test/bracket-sweep.js 2>&1 | grep FAIL | sed 's/^/  /'
    fail=1
  fi
fi

if [ "$fail" -eq 0 ]; then echo "" && echo "전부 통과"; else echo "" && echo "실패한 항목이 있습니다"; fi
exit $fail
