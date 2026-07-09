# MATSU 출시 실행 런북 (따라만 하면 됩니다)

계정 로그인·결제는 사장님이 직접 해야 해서, **명령어와 체크포인트**를 순서대로 드려요.

---

## PART A. 백엔드 배포 (Railway)

### A1. 코드 올리기
```bash
cd matsu-backend
git init && git add . && git commit -m "MATSU backend"
# GitHub에 빈 저장소 생성 후:
git remote add origin https://github.com/<본인>/matsu-backend.git
git branch -M main && git push -u origin main
```
✅ 체크: GitHub에 파일이 보이면 성공.

### A2. Railway 배포
1. https://railway.app → New Project → **Deploy from GitHub repo** → 저장소 선택
2. 자동 빌드(Dockerfile 감지). 끝나면 로그에 `MATSU API on ...` 출력
3. **Variables** 추가:
   ```
   JWT_SECRET   = (openssl rand -hex 32 결과)
   DB_PATH      = /data/matsu.db
   ADMIN_KEY    = (임의의 긴 문자열)
   ```
4. **Volumes** → New Volume → Mount `/data`  (SQLite 영구화)
5. **Settings → Networking → Generate Domain** → URL 확보
✅ 체크: `https://<도메인>/health` → `{"ok":true}` / `https://<도메인>/admin.html` 접속 → ADMIN_KEY로 로그인

### A3. 키 연동(선택, 실기능)
Variables에 필요한 것만 추가 후 재배포:
```
KAKAO_REST_KEY, KAKAO_REDIRECT_URI      # 카카오
APPLE_CLIENT_ID                          # 애플
TOSS_SECRET_KEY                          # 토스(코트비 정산용)
APPLE_IAP_SHARED_SECRET, GOOGLE_SA_EMAIL # 인앱결제
FCM_SERVER_KEY                           # 푸시
```

---

## PART B. 앱 빌드·배포 (EAS)

### B1. 준비
```bash
npm i -g eas-cli
eas login
cd matsu-app
```
- `api.js`의 `API_BASE`를 **A2에서 만든 Railway 도메인**으로 변경
- `auth.js`에 `KAKAO_REST_KEY`, (필요시) `TOSS_CLIENT_KEY` 입력

### B2. 빌드
```bash
eas build:configure
eas build -p android --profile production   # AAB
eas build -p ios --profile production       # IPA (Apple 로그인)
```
✅ 체크: 빌드 완료 후 다운로드 링크 표시

### B3. 제출
```bash
eas submit -p android --latest   # Play 서비스계정 JSON 필요
eas submit -p ios --latest       # App Store Connect 앱 필요
```
✅ 체크: 안드로이드 내부테스트 / iOS TestFlight에서 설치·실행 확인

### B4. 스토어 심사 준비
- 개인정보처리방침 URL, 계정 삭제 기능, 앱 아이콘/스크린샷
- **결제**: 디지털재화(M캐쉬·프리미엄)는 **IAP**로 (IAP_POLICY.md 참고)
- 소셜 로그인 프로덕션 Redirect/Services ID 등록

---

## PART C. 오픈 후
- 운영: `https://<도메인>/admin.html` 로 신고 처리·매출·회원 모니터링
- 확장: 실시간 SSE→WebSocket, SQLite→Postgres, 이미지 S3, 알림 정교화

## 비용 요약(초기)
- 서버 Railway 월 1~5만원대 · 앱 애플 연 ~13만원/구글 1회 ~3.3만원
- PG·IAP 수수료(건당), 본인인증·SMS(건당), 유지보수 인건비(가장 큼)

> 막히는 단계의 **에러 메시지/스크린샷**을 주시면 그 지점부터 같이 풀어드릴게요.
