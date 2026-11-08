-- Phase 2: alert bookkeeping, display-only odds hint, notifier state.
-- Plain SQLite-compatible SQL only. Never put a semicolon inside a comment here.

-- 1 when the item passed the ping rules. alerted_at stays NULL until Discord accepted
-- the alert, so a failed send is retried by the next run and never sent twice.
ALTER TABLE giveaways ADD COLUMN alert_eligible INTEGER NOT NULL DEFAULT 0;

-- "Fewer entrants" hint. Display only: never changes pinging, sorting or any gate.
ALTER TABLE giveaways ADD COLUMN entry_count INTEGER;
ALTER TABLE giveaways ADD COLUMN account_followers INTEGER;

-- Shown on every alert and queue item.
ALTER TABLE giveaways ADD COLUMN domain_age_days INTEGER;
ALTER TABLE giveaways ADD COLUMN account_age_days INTEGER;

CREATE INDEX IF NOT EXISTS idx_giveaways_pending ON giveaways (alert_eligible, alerted_at);

-- Small key/value state for the notifier (e.g. the date of the last daily digest).
CREATE TABLE IF NOT EXISTS notify_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
