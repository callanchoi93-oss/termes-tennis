# MATSU 백엔드 (MVP)

멀티 종목 스포츠 커뮤니티 MATSU의 **실제 동작하는 최소 백엔드**입니다.
Node.js + Express + SQLite + JWT. 프론트(데모 HTML)가 붙을 수 있는 REST API를 제공합니다.

> 이건 "모델하우스(데모)"에 **전기·수도(서버·DB)를 연결**하는 부분이에요.
> 코드는 실제로 돌아가지만, **배포·실계정(카카오/애플/PG) 키·앱스토어 심사**는 사업자 계정으로 별도 진행해야 합니다.

---

## 1. 로컬 실행
```bash
cd matsu-backend
npm install
npm run seed      # 데모 데이터
npm start         # http://localhost:4000
```
- API 확인: `curl http://localhost:4000/health`
- **연결된 웹앱: 브라우저로 `http://localhost:4000` 접속** → 로그인·라운지·클럽·검색이 **실제 DB와 통신**합니다 (public/index.html).
- 배포는 **DEPLOY.md**(Railway 단계별) 참고.

## 2. 빠른 사용 예시
```bash
# 개발용 로그인 → 토큰 발급
curl -X POST localhost:4000/auth/dev-login -H 'Content-Type: application/json' \
  -d '{"name":"곽주영","gender":"남성","region":"경기 용인","sport":"tennis"}'

# 토큰으로 내 정보
curl localhost:4000/me -H 'Authorization: Bearer <TOKEN>'

# 라운지 글 목록 / 작성
curl localhost:4000/posts
curl -X POST localhost:4000/posts -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/json' -d '{"title":"오늘 게임 구해요","category":"모임"}'
```

## 3. 제공 API (요약)
- **인증**: `POST /auth/dev-login`, `GET /me`, `PATCH /me`
- **클럽**: `GET/POST /clubs`, `POST /clubs/:id/join`, `GET /clubs/:id/members`, `PATCH /clubs/:id/fees`(임원), `PATCH /clubs/:id/roster`(등번호·주장)
- **경기**: `POST /matches`, `/accept` `/decline`, `POST /matches/:id/result`(상호 확정 시 Elo 반영), `POST /matches/:id/stats`(골·어시·홈런 등)
- **기록**: `POST /records`, `GET /records/leaderboard`
- **라운지**: `GET/POST /posts`, `POST /posts/:id/like`, `POST /report`(신고·누적3회 자동숨김), `POST /block`
- **M캐쉬**: `POST /cash/spend`, `POST /cash/purchase`(⚠️ 실제론 PG 웹훅에서만)
- **통합 검색**: `GET /search?q=`

## 4. 프론트 연결 (데모 HTML → 실서버)
데모는 지금 `state = {...}` 인메모리예요. 이걸 API 호출로 바꾸면 됩니다:
```js
const API = 'http://localhost:4000';
let TOKEN = localStorage.getItem('matsu_token');
async function api(path, opt={}) {
  const r = await fetch(API + path, {
    ...opt,
    headers: { 'Content-Type':'application/json', ...(TOKEN?{Authorization:'Bearer '+TOKEN}:{}) , ...(opt.headers||{}) }
  });
  return r.json();
}
// 예) 로그인
const { token, user } = await api('/auth/dev-login', { method:'POST', body: JSON.stringify({name:'곽주영'}) });
TOKEN = token; localStorage.setItem('matsu_token', token);
// 예) 라운지 로드
const posts = await api('/posts');
```

## 5. 실서비스로 가기 전 반드시 (백엔드 코드로 다 안 되는 것)
- **소셜 로그인 실연동**: 카카오/애플 OAuth → 서버에서 **토큰 검증** 후 발급 (dev-login 대체)
- **PG·에스크로**: 토스페이먼츠/포트원 등 — 결제 성공 **웹훅**에서만 `cash/purchase`·회비 처리
- **본인확인**: 통신사 본인인증(PASS 등) 연동
- **실시간**: 라이브스코어는 WebSocket(Socket.IO) 또는 SSE 추가
- **푸시**: FCM(안드로이드)/APNs(iOS)
- **스토리지**: 프로필/경기 사진은 S3 등 오브젝트 스토리지 + CDN
- **DB 이전**: 규모 커지면 SQLite → Postgres(Supabase/RDS)

## 6. 배포 (예시)
- 가장 쉬운 길: **Railway / Render / Fly.io** 에 이 폴더를 올리면 바로 뜹니다.
- 환경변수: `JWT_SECRET`(필수, 랜덤 문자열), `PORT`, `DB_PATH`
- SQLite는 단일 인스턴스/소규모용. 이용자 늘면 Postgres 권장.

## 7. 대략 비용 (운영)
- 서버(Railway/Render 소형): 월 **1만~5만원**대에서 시작
- Postgres(Supabase 무료→Pro): 무료~월 **3만원**대
- PG 수수료: 결제 **건당 2~3.5%**
- 본인인증/SMS: **건당 과금**
- 앱스토어: 애플 **연 ~13만원**, 구글 **1회 ~3.3만원**

> 즉 "API·PG 가입은 무료"여도 **사용량 기반 과금 + 서버 월정액**이 발생하고,
> 이 백엔드를 **연결·배포·유지보수하는 개발 공수**가 실제 예산의 큰 축입니다.

## 8. 카카오 로그인 켜기 (실연동)
1. https://developers.kakao.com → **내 애플리케이션 > 애플리케이션 추가**
2. **앱 키**에서 **JavaScript 키** 복사 → `public/index.html` 상단 `KAKAO_JS_KEY = '...'` 에 넣기
3. **플랫폼 > Web** 에 도메인 등록 (로컬: `http://localhost:4000`, 배포: 실제 도메인)
4. **카카오 로그인 > 활성화 ON**, 동의항목에서 **닉네임** 허용
5. 이제 앱의 "카카오로 시작하기" 버튼이 실제로 동작 → SDK가 access_token을 받고, 서버 `/auth/kakao`가 카카오에 검증 후 우리 JWT 발급

- SPA 방식(권장): 위 그대로. 서버는 `POST /auth/kakao { access_token }`.
- 인가코드 방식(선택): `POST /auth/kakao/code { code }` + env(`KAKAO_REST_KEY`,`KAKAO_REDIRECT_URI`).
- 애플 로그인도 동일 패턴(클라이언트 토큰 → 서버 검증 → JWT)으로 추가하면 됩니다.

## 9. 애플 로그인 켜기
1. https://developer.apple.com → Certificates, IDs & Profiles → **Services ID** 생성 (예: `com.matsu.web`)
2. 도메인·**Return URL**(리다이렉트) 등록 (로컬: `http://localhost:4000/`)
3. `public/index.html`의 `APPLE_CLIENT_ID`에 Services ID 입력
4. 서버 env `APPLE_CLIENT_ID`도 동일하게 설정 → 서버가 애플 공개키(JWKS)로 id_token을 검증
- 검증 로직은 로컬 RS256 키로 자체 테스트 완료(서명·iss·aud 확인).

## 10. 토스페이먼츠 결제(M캐쉬 충전) 켜기
1. https://developers.tosspayments.com → 테스트 **클라이언트 키/시크릿 키** 발급
2. `public/index.html`의 `TOSS_CLIENT_KEY` = 클라이언트 키(test_ck_...)
3. 서버 env `TOSS_SECRET_KEY` = 시크릿 키(test_sk_...)
4. 흐름: 서버가 **주문 생성(/pay/order)** → 토스 결제창 → 성공 시 서버가 **토스에 최종 승인(/pay/confirm)** → 캐쉬 지급
   - 금액·주문을 서버가 검증(위변조 방지)하고, **시크릿 키는 서버에만** 둡니다. 클라는 클라이언트 키만.
- 키가 없으면 앱은 자동으로 "데모 지급"으로 동작합니다.
