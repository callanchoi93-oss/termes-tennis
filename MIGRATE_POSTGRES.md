# SQLite → Postgres 이전 가이드

**언제?** SQLite는 단일 인스턴스·수천 사용자까진 충분해요. 동시 쓰기/다중 인스턴스/대용량이 필요해지면 Postgres로.

## 준비된 것
- `schema.pg.sql` — Postgres용 스키마 (SERIAL·BIGINT 반영)
- `db.pg.js` — Postgres 어댑터 (`?`→`$n` 변환, INSERT `RETURNING id`, 커넥션 풀)

## 방법 A) 가장 안전 — 그대로 유지
- 지금 SQLite + Railway 볼륨으로 충분. 트래픽 늘 때 B로.

## 방법 B) Postgres 도입 (핵심: 동기→비동기 전환)
SQLite(node:sqlite)는 **동기**, pg는 **비동기**라 DB 호출을 `await` 로 바꿔야 합니다.
1. 설치: `npm i pg`
2. 서버 상단 교체:
   ```js
   // import { db, initSchema, now, rid } from './db.js';
   import { db, initSchema, now, rid } from './db.pg.js';
   ```
3. **모든 핸들러의 DB 호출에 await** + 함수 `async` 화:
   ```js
   // 전:  const u = getUser(req.uid);
   // 후:  const u = await getUser(req.uid);
   app.get('/me', auth, async (req,res)=> res.json(await getUser(req.uid)));
   ```
   - `getUser`도 `const getUser = (id) => db.prepare('...').get(id);` → 호출부에서 await
   - `initSchema()` 호출도 `await initSchema()` (서버 시작을 async IIFE로 감싸기)
4. 환경변수: `DATABASE_URL=postgres://...` (Railway는 Postgres 플러그인 추가 시 자동 주입), 필요시 `PGSSL=1`
5. 데이터 이전(선택): 기존 SQLite 데이터를 CSV로 export → Postgres COPY, 또는 초기 오픈이면 새로 시작.

## Railway에서
- 프로젝트에 **Postgres** 추가(원클릭) → `DATABASE_URL` 자동 연결 → 위 2~4 반영 후 배포.

> 팁: 규모가 커지면 쿼리빌더(Knex/Drizzle)나 ORM(Prisma)로 옮기면 유지보수가 쉬워집니다.
