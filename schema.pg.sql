-- MATSU Postgres 스키마 (SQLite → Postgres 이전용)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  provider TEXT, provider_id TEXT,
  name TEXT NOT NULL, gender TEXT, region TEXT,
  sport TEXT DEFAULT 'tennis', exp TEXT,
  rating INTEGER DEFAULT 1000, mmr INTEGER DEFAULT 1000, cash INTEGER DEFAULT 5,
  anon_nick TEXT,
  phone_verified INTEGER DEFAULT 0, real_verified INTEGER DEFAULT 0, skill_verified INTEGER DEFAULT 0,
  premium INTEGER DEFAULT 0, photos TEXT DEFAULT '[]', created_at BIGINT
);
CREATE TABLE IF NOT EXISTS clubs (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL, sport TEXT NOT NULL, region TEXT, owner_id INTEGER,
  entry_fee INTEGER DEFAULT 100000, season_fee INTEGER DEFAULT 240000,
  guest_fee INTEGER DEFAULT 25000, guest_cap INTEGER DEFAULT 4,
  premium INTEGER DEFAULT 0, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS club_members (
  id SERIAL PRIMARY KEY,
  club_id INTEGER, user_id INTEGER, role TEXT DEFAULT 'member',
  jersey_no INTEGER, is_captain INTEGER DEFAULT 0, status TEXT DEFAULT 'active',
  UNIQUE(club_id, user_id)
);
CREATE TABLE IF NOT EXISTS matches (
  id SERIAL PRIMARY KEY,
  sport TEXT NOT NULL, kind TEXT NOT NULL,
  home_club_id INTEGER, away_club_id INTEGER, home_user_id INTEGER, away_user_id INTEGER,
  venue TEXT, scheduled_at BIGINT, status TEXT DEFAULT 'requested',
  home_score INTEGER, away_score INTEGER,
  home_confirmed INTEGER DEFAULT 0, away_confirmed INTEGER DEFAULT 0,
  score_deadline BIGINT, created_by INTEGER, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS match_stats (
  id SERIAL PRIMARY KEY, match_id INTEGER, user_id INTEGER, stat TEXT NOT NULL, value INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS records (
  id SERIAL PRIMARY KEY, user_id INTEGER, sport TEXT NOT NULL, event TEXT, value REAL, recorded_at BIGINT
);
CREATE TABLE IF NOT EXISTS posts (
  id SERIAL PRIMARY KEY, user_id INTEGER, sport TEXT, category TEXT, title TEXT NOT NULL, body TEXT,
  anon_nick TEXT, gender TEXT, region TEXT,
  views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS comments (
  id SERIAL PRIMARY KEY, post_id INTEGER, user_id INTEGER, anon_nick TEXT, body TEXT, hidden INTEGER DEFAULT 0, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS reports (
  id SERIAL PRIMARY KEY, reporter_id INTEGER, target_type TEXT, target_id INTEGER, reason TEXT,
  status TEXT DEFAULT 'open', created_at BIGINT
);
CREATE TABLE IF NOT EXISTS blocks (
  id SERIAL PRIMARY KEY, user_id INTEGER, blocked_user_id INTEGER, UNIQUE(user_id, blocked_user_id)
);
CREATE TABLE IF NOT EXISTS cash_ledger (
  id SERIAL PRIMARY KEY, user_id INTEGER, delta INTEGER NOT NULL, reason TEXT, balance_after INTEGER, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY, order_id TEXT UNIQUE, user_id INTEGER, amount INTEGER, cash INTEGER,
  payment_key TEXT, status TEXT DEFAULT 'ready', created_at BIGINT
);
CREATE TABLE IF NOT EXISTS devices (
  id SERIAL PRIMARY KEY, user_id INTEGER, token TEXT UNIQUE, platform TEXT, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS match_events (
  id SERIAL PRIMARY KEY, match_id INTEGER, minute TEXT, icon TEXT, text TEXT, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS iap_receipts (
  id SERIAL PRIMARY KEY, txn_id TEXT UNIQUE, user_id INTEGER, store TEXT, product TEXT, cash INTEGER, created_at BIGINT
);
CREATE TABLE IF NOT EXISTS notifications (
  id SERIAL PRIMARY KEY, user_id INTEGER, icon TEXT, title TEXT, sub TEXT, read INTEGER DEFAULT 0, created_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_members_club ON club_members(club_id);
CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status);
