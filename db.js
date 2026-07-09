// db.js — Node 22 내장 SQLite (node:sqlite, 네이티브 빌드 불필요)
import { DatabaseSync } from 'node:sqlite';

export const db = new DatabaseSync(process.env.DB_PATH || 'matsu.db');
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// node:sqlite는 undefined 바인딩을 거부 → undefined를 null로 정규화하는 래퍼
const _prepare = db.prepare.bind(db);
db.prepare = (sql) => {
  const st = _prepare(sql);
  const fix = (a) => a.map((x) => (x === undefined ? null : x));
  return {
    run: (...a) => st.run(...fix(a)),
    get: (...a) => st.get(...fix(a)),
    all: (...a) => st.all(...fix(a)),
  };
};

export function initSchema() {
  db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT, provider_id TEXT,
    name TEXT NOT NULL, gender TEXT, region TEXT,
    sport TEXT DEFAULT 'tennis', exp TEXT,
    rating INTEGER DEFAULT 1000, mmr INTEGER DEFAULT 1000, cash INTEGER DEFAULT 5,
    anon_nick TEXT,
    phone_verified INTEGER DEFAULT 0, real_verified INTEGER DEFAULT 0, skill_verified INTEGER DEFAULT 0,
    premium INTEGER DEFAULT 0, premium_until BIGINT, suspended INTEGER DEFAULT 0,
    photos TEXT DEFAULT '[]', created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS clubs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, sport TEXT NOT NULL, region TEXT, owner_id INTEGER,
    entry_fee INTEGER DEFAULT 100000, season_fee INTEGER DEFAULT 240000,
    guest_fee INTEGER DEFAULT 25000, guest_cap INTEGER DEFAULT 4,
    premium INTEGER DEFAULT 0, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS club_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    club_id INTEGER, user_id INTEGER, role TEXT DEFAULT 'member',
    jersey_no INTEGER, is_captain INTEGER DEFAULT 0, status TEXT DEFAULT 'active',
    UNIQUE(club_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sport TEXT NOT NULL, kind TEXT NOT NULL,
    home_club_id INTEGER, away_club_id INTEGER, home_user_id INTEGER, away_user_id INTEGER,
    venue TEXT, scheduled_at INTEGER, status TEXT DEFAULT 'requested',
    home_score INTEGER, away_score INTEGER,
    home_confirmed INTEGER DEFAULT 0, away_confirmed INTEGER DEFAULT 0,
    score_deadline INTEGER, created_by INTEGER, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS match_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER, user_id INTEGER, stat TEXT NOT NULL, value INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, sport TEXT NOT NULL, event TEXT, value REAL, recorded_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, sport TEXT, category TEXT, title TEXT NOT NULL, body TEXT,
    anon_nick TEXT, gender TEXT, region TEXT,
    views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER, user_id INTEGER, anon_nick TEXT, body TEXT, hidden INTEGER DEFAULT 0, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER, target_type TEXT, target_id INTEGER, reason TEXT,
    status TEXT DEFAULT 'open', created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, blocked_user_id INTEGER, UNIQUE(user_id, blocked_user_id)
  );
  CREATE TABLE IF NOT EXISTS cash_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, delta INTEGER NOT NULL, reason TEXT, balance_after INTEGER, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT UNIQUE, user_id INTEGER, amount INTEGER, cash INTEGER,
    payment_key TEXT, status TEXT DEFAULT 'ready', created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, token TEXT, platform TEXT, created_at INTEGER,
    UNIQUE(token)
  );
  CREATE TABLE IF NOT EXISTS match_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER, minute TEXT, icon TEXT, text TEXT, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS iap_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    txn_id TEXT UNIQUE, user_id INTEGER, store TEXT, product TEXT, cash INTEGER, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS club_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    club_id INTEGER, title TEXT, date TEXT, tag TEXT, created_by INTEGER, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS event_attendees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER, user_id INTEGER, UNIQUE(event_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS open_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sport TEXT, dt TEXT, loc TEXT, fmt TEXT, gd TEXT, price INTEGER,
    cap INTEGER, min_cnt INTEGER, created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS open_match_joins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER, user_id INTEGER, UNIQUE(match_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, icon TEXT, title TEXT, sub TEXT, read INTEGER DEFAULT 0, created_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_members_club ON club_members(club_id);
  CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status);
  `);
}

export const rid = (r) => Number(r.lastInsertRowid);
export const now = () => Date.now();
