#!/usr/bin/env bash
# 연기 테스트 — 진짜 서버를 띄우고 주요 화면의 API 를 실제로 눌러본다.
#
#   왜 필요한가:
#   함수를 지울 때 옆 함수까지 딸려 나가면 문법은 멀쩡한데 실행할 때만 500 이 난다.
#   실제로 회비·프리미엄을 걷어내며 settleReferral(초대 보상)이 함께 사라졌고,
#   '참석'을 누를 때만 그 함수를 부르기 때문에 불참·미정은 되고 참석만 실패했다.
#   문법 검사로는 절대 못 잡는다 — 눌러봐야 안다.
#
#   임시 DB 를 쓰므로 실제 데이터는 건드리지 않는다.
set -u
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
DB="$TMP/smoke.db"
PORT=4599
B="http://localhost:$PORT"
fail=0

cleanup(){ [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

DB_PATH="$DB" PORT=$PORT JWT_SECRET=smoke node server.js >"$TMP/server.log" 2>&1 &
PID=$!

for i in $(seq 1 40); do
  curl -s "$B/config" >/dev/null 2>&1 && break
  sleep 0.25
done
if ! curl -s "$B/config" >/dev/null 2>&1; then
  echo "  서버가 뜨지 않았습니다"
  sed 's/^/    /' "$TMP/server.log" | tail -20
  exit 1
fi

tok(){ curl -s -X POST "$B/auth/dev-login" -H 'content-type: application/json' \
        -d "{\"name\":\"$1\"}" | node -e \
        "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const j=JSON.parse(s);console.log(j.token+' '+j.user.id)}catch(e){console.log('')}})"; }

# 200 이 아니면 실패로 본다
hit(){ # hit <설명> <메서드> <경로> <토큰> [본문]
  local desc=$1 method=$2 path=$3 token=$4 body=${5:-}
  local code out
  out=$(curl -s -o "$TMP/body" -w '%{http_code}' -X "$method" "$B$path" \
        -H 'content-type: application/json' \
        ${token:+-H "authorization: Bearer $token"} \
        ${body:+-d "$body"})
  code=$out
  if [ "$code" = "200" ]; then
    echo "  ok   $desc"
  else
    echo "  실패 $desc → HTTP $code $(head -c 120 "$TMP/body")"
    fail=1
  fi
}

read -r OT OID <<<"$(tok 회장)"
read -r MT MID <<<"$(tok 회원)"
if [ -z "${OT:-}" ]; then echo "  로그인 실패"; sed 's/^/    /' "$TMP/server.log" | tail -20; exit 1; fi

CID=$(curl -s -X POST "$B/clubs" -H 'content-type: application/json' -H "authorization: Bearer $OT" \
      -d '{"name":"연기테스트클럽","region":"용인","sport":"tennis"}' \
      | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.parse(s).id)}catch(e){console.log('')}})")
curl -s -X POST "$B/clubs/$CID/join" -H "authorization: Bearer $MT" >/dev/null
curl -s -X POST "$B/clubs/$CID/members/$MID/approve" -H 'content-type: application/json' \
     -H "authorization: Bearer $OT" -d '{"approve":true}' >/dev/null
EID=$(curl -s -X POST "$B/clubs/$CID/events" -H 'content-type: application/json' -H "authorization: Bearer $OT" \
      -d '{"title":"연기테스트 모임","date":"8/18"}' \
      | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.parse(s).id)}catch(e){console.log('')}})")

echo "내 정보"
hit "내 정보 조회"        GET   "/me"                       "$MT"
hit "프로필 저장"         PATCH "/me"                       "$MT" '{"height":180,"birth_year":1993,"handed":"오른손"}'
hit "공개 프로필"         GET   "/users/$MID/profile"       ""

echo ""
echo "클럽"
hit "클럽 목록"          GET   "/clubs"                    ""
hit "회원 명단"          GET   "/clubs/$CID/members"       "$OT"
hit "모임 목록"          GET   "/clubs/$CID/events"        "$MT"
hit "대진 명단"          GET   "/clubs/$CID/roster"        "$OT"
hit "시즌 랭킹"          GET   "/clubs/$CID/rankings"      "$OT"

echo ""
echo "참석 응답 (settleReferral 이 사라졌을 때 여기서만 터졌다)"
hit "참석"               POST  "/events/$EID/rsvp"         "$MT" '{"status":"going"}'
hit "참석 취소"          POST  "/events/$EID/rsvp"         "$MT" '{"status":"going"}'
hit "불참"               POST  "/events/$EID/rsvp"         "$MT" '{"status":"absent"}'
hit "미정"               POST  "/events/$EID/rsvp"         "$MT" '{"status":"undecided"}'
hit "출석 체크 화면"      GET   "/events/$EID/attendance"   "$OT"

echo ""
echo "대화"
hit "대화 목록"          GET   "/dm/threads"               "$MT"
hit "알림함"             GET   "/me/unread"                "$MT"

echo ""
if [ "$fail" -eq 0 ]; then
  echo "전부 통과"
else
  echo "실패한 API 가 있습니다 — 배포하지 마세요"
  echo "서버 로그:"
  grep -i "error\|not defined" "$TMP/server.log" | head -10 | sed 's/^/  /'
fi
exit $fail
