# MATSU 배포 가이드 (Railway)

이 폴더는 **배포 준비가 끝난 상태**예요. Railway 계정만 있으면 아래 순서대로 올리면 됩니다.
(배포 "실행"은 사장님 계정 로그인이 필요해서 직접 해주셔야 해요. 그 앞까지 다 세팅해뒀습니다.)

---

## 0. 준비물
- GitHub 계정, Railway 계정(github로 가입 가능), 무료 크레딧으로 시작 가능

## 1. 코드를 GitHub에 올리기
```bash
cd matsu-backend
git init
git add .
git commit -m "MATSU backend + connected client"
# GitHub에서 빈 저장소 만든 뒤:
git remote add origin https://github.com/<본인>/matsu-backend.git
git push -u origin main
```

## 2. Railway에 배포
1. https://railway.app → **New Project** → **Deploy from GitHub repo** → `matsu-backend` 선택
2. Railway가 `Dockerfile`을 감지해 자동 빌드·배포합니다.
3. **Variables(환경변수)** 탭에서 추가:
   - `JWT_SECRET` = 길고 랜덤한 문자열 (예: `openssl rand -hex 32` 결과)
   - `DB_PATH` = `/data/matsu.db`
4. **Settings → Networking → Generate Domain** 을 눌러 공개 URL 생성 (예: `https://matsu-xxx.up.railway.app`)

## 3. SQLite 영구 저장 (중요)
Railway는 재배포 시 파일이 초기화돼요. 데이터를 유지하려면 **볼륨**을 붙이세요.
1. 서비스 → **Volumes** → **New Volume**
2. Mount Path: `/data`
3. 위에서 `DB_PATH=/data/matsu.db` 로 설정했으니, 이제 DB가 볼륨에 저장돼 유지됩니다.

> 이용자가 많아지면 SQLite 대신 **Postgres**(Railway가 원클릭 제공)로 옮기세요. 쿼리는 거의 그대로 재사용됩니다.

## 4. 확인
- `https://<도메인>/health` → `{"ok":true}`
- `https://<도메인>/` → 연결된 MATSU 웹앱 화면 (로그인→라운지/클럽/검색이 실제 DB와 통신)

## 5. (선택) 시드 데이터
로컬에선 `npm run seed`. 배포 서버에선 Railway의 **Shell**(또는 재배포 훅)에서 `npm run seed` 한 번 실행하면 데모 데이터가 들어갑니다. 실서비스 오픈 시엔 시드를 빼세요.

---

## 다른 배포 옵션
- **Render.com**: New → Web Service → repo 연결 → Build `npm install` / Start `npm start` / 환경변수 동일 / Disk 추가로 `/data` 영구화
- **Fly.io**: `fly launch` (Dockerfile 감지) → `fly volumes create data` → `DB_PATH=/data/matsu.db`

## 실서비스 전 반드시 (배포와 별개로 필요한 계정·연동)
- 카카오/애플 **OAuth 키** → `/auth/dev-login`을 실제 소셜 로그인으로 교체
- **PG·에스크로**(토스페이먼츠/포트원) → 결제 성공 웹훅에서만 충전/정산
- **본인인증(PASS)**, **푸시(FCM/APNs)**, **이미지 스토리지(S3)+CDN**
- CORS를 실제 도메인만 허용하도록 제한, `JWT_SECRET` 노출 금지
