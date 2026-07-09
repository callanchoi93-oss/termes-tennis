// db.pg.js — Postgres 어댑터 (규모 확장 시 SQLite 대체)
// ⚠️ pg는 비동기예요. 도입하려면 server.js의 db 호출을 await 로 바꿔야 합니다(아래 MIGRATE_POSTGRES.md 참고).
import pg from 'pg';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,         // 예: postgres://user:pass@host:5432/matsu
  ssl: process.env.PGSSL ? { rejectUnauthorized: false } : undefined,
});

// '?' 플레이스홀더 → '$1,$2...' 로 변환
function conv(sql) { let i = 0; return sql.replace(/\?/g, () => '$' + (++i)); }

export async function run(sql, ...params) {
  let text = conv(sql);
  if (/^\s*insert/i.test(text) && !/returning/i.test(text)) text += ' RETURNING id';
  const r = await pool.query(text, params);
  return { lastInsertRowid: r.rows[0] && r.rows[0].id, changes: r.rowCount };
}
export async function get(sql, ...params) { const r = await pool.query(conv(sql), params); return r.rows[0]; }
export async function all(sql, ...params) { const r = await pool.query(conv(sql), params); return r.rows; }
export async function exec(sql) { await pool.query(sql); }

// server.js 를 최소 수정으로 쓰려면 prepare 형태도 제공(모두 Promise 반환 → await 필요)
export const db = {
  prepare: (sql) => ({
    run: (...a) => run(sql, ...a),
    get: (...a) => get(sql, ...a),
    all: (...a) => all(sql, ...a),
  }),
  exec,
};
export const rid = (r) => Number(r.lastInsertRowid);
export const now = () => Date.now();
export async function initSchema() {
  const fs = await import('node:fs');
  await exec(fs.readFileSync(new URL('./schema.pg.sql', import.meta.url), 'utf8'));
}
