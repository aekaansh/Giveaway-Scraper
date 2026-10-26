-- Initial schema. Plain SQLite-compatible SQL only (runs on sqlite3 and Turso).
-- No personal data tables: name/email/address live only in the local .env.
-- Statements are split on semicolons by the migration runner, so never put a
-- semicolon inside a comment or string literal here. IF NOT EXISTS everywhere so a
-- run interrupted halfway (DDL autocommits) can simply be re-run.

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    config_json TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_fetched_at TEXT
);

CREATE TABLE IF NOT EXISTS raw_items (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    external_id TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    title TEXT,
    body TEXT,
    author TEXT,
    published_at TEXT,
    fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS giveaways (
    id INTEGER PRIMARY KEY,
    canonical_key TEXT NOT NULL UNIQUE,
    raw_item_id INTEGER REFERENCES raw_items(id),
    url TEXT NOT NULL,
    host_url TEXT,
    domain TEXT NOT NULL,
    tier TEXT NOT NULL,
    platform TEXT,
    account_handle TEXT,
    title TEXT,
    summary TEXT,
    region TEXT,
    deadline TEXT,
    scam_likelihood TEXT NOT NULL DEFAULT 'medium'
        CHECK (scam_likelihood IN ('low', 'medium', 'high')),
    flags_json TEXT NOT NULL DEFAULT '[]',
    alerted_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS review_queue (
    id INTEGER PRIMARY KEY,
    giveaway_id INTEGER NOT NULL UNIQUE REFERENCES giveaways(id),
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'entered', 'skipped', 'scam')),
    reasons_json TEXT NOT NULL DEFAULT '[]',
    deadline TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_review_queue_status_deadline ON review_queue (status, deadline);

CREATE TABLE IF NOT EXISTS entries_log (
    id INTEGER PRIMARY KEY,
    giveaway_id INTEGER NOT NULL REFERENCES giveaways(id),
    action TEXT NOT NULL,
    note TEXT,
    at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS url_checks (
    kind TEXT NOT NULL,
    check_key TEXT NOT NULL,
    verdict TEXT NOT NULL,
    detail TEXT,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (kind, check_key)
);

CREATE TABLE IF NOT EXISTS fetch_log (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT,
    tier TEXT,
    verdict TEXT NOT NULL,
    status_code INTEGER,
    fetched_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fetch_log_fetched_at ON fetch_log (fetched_at);

CREATE TABLE IF NOT EXISTS filtered_items (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    rule TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL,
    later_human_verdict TEXT
);

CREATE INDEX IF NOT EXISTS idx_filtered_items_rule_created ON filtered_items (rule, created_at);

CREATE TABLE IF NOT EXISTS domain_tiers (
    domain TEXT PRIMARY KEY,
    tier TEXT NOT NULL CHECK (tier IN ('TRUSTED', 'PLATFORM', 'LINK_HUB', 'BLOCKED')),
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS known_accounts (
    platform TEXT NOT NULL,
    handle TEXT NOT NULL,
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    note TEXT,
    PRIMARY KEY (platform, handle)
);

CREATE TABLE IF NOT EXISTS run_log (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    items_found INTEGER NOT NULL DEFAULT 0,
    alerts_sent INTEGER NOT NULL DEFAULT 0,
    errors TEXT
);

CREATE TABLE IF NOT EXISTS widget_links (
    host_url TEXT NOT NULL,
    widget_url TEXT NOT NULL,
    kind TEXT NOT NULL,
    found_at TEXT NOT NULL,
    PRIMARY KEY (host_url, widget_url)
);
