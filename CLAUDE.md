# Pokemon Giveaway Radar

## Purpose
Discover, classify and alert on Pokemon TCG giveaways. The human enters manually.

## Phases
- Phase 1: foundation, DB, url_guard, scoring, widgets, accounts, tests (no live sources yet)
- Phase 2: adapters, classifier, run.py, Discord notify, poll.yml and backup.yml
- Phase 3: Streamlit dashboard (queue, Filtered, Runs tabs)
- Phase 4: assisted entry (local only, as described below)

## Sources and region
- Sources: Brave Search API, YouTube Data API, Reddit subreddit RSS (logged-out `.rss` feeds,
  honest User-Agent, polite rate limits). TRUSTED sites/forums are added only after human vetting.
- Reddit RSS is ON HOLD until Reddit's actual robots.txt is checked (Phase 2). If it disallows
  us, drop the feeds and use either the official Reddit API (via `api_client.py`) or Reddit
  posts found through Brave results.
- Instagram, TikTok and X are NEVER scraped or read logged-out. They enter only as links found
  in search results, and are judged with the PLATFORM account rules.
- Region: USA. USD, US-eligible giveaways only; skip ones limited to other countries.
  Region is configurable in `config/sources.yaml`.

## Hard rules (never violate)
- NEVER auto-submit entry forms, click "enter", or perform follows/likes/reposts/comments/tags.
- NEVER create accounts, use multiple accounts, or solve/bypass CAPTCHAs or bot checks.
- NEVER add stealth, fingerprint spoofing, proxy rotation or anti-detection code.
- Read-only access: official APIs, RSS, logged-out public pages. Respect robots.txt and rate limits.
- Personal data (name, email, address) lives ONLY in a local `.env` on the user's own computer.
  Never store it in Turso, GitHub secrets, logs, or send it to the LLM.

## Deployment overview
- The polling bot runs on **GitHub Actions** on a schedule (computer can be off).
- All state lives in a hosted **Turso** database shared by the bot and the dashboard.
- The dashboard runs on **Streamlit Community Cloud** (private) or locally.
- Alerts go to **Discord** via webhook.
- Assisted entry (Phase 4) runs locally only, in the user's own Chrome.

## Database (Turso)

### Connection
- Production: Turso remote DB via `turso_serverless` (`uv add turso_serverless`).
  ```python
  conn = turso_serverless.connect(os.environ["TURSO_DATABASE_URL"],
                                  auth_token=os.environ["TURSO_AUTH_TOKEN"])
  ```
- Local dev and tests: standard-library `sqlite3` (file or `:memory:`).
- `src/radar/db.py` is the ONLY module that opens connections. It picks the backend from
  `DB_BACKEND=turso|sqlite` (default `sqlite`). All other code goes through `store.py`.
- Use plain SQLite-compatible SQL only (no backend-specific features), `?` placeholders,
  and always `conn.commit()` after writes. Keep runs short: open once per run, close at the end.
- Tests NEVER touch Turso; they use in-memory SQLite.

### Schema & migrations
- Schema lives in `src/radar/migrations/NNN_name.sql`, applied in order and tracked in a
  `schema_version` table. `uv run python -m radar.admin migrate` applies pending migrations.
  Every run calls migrate first (idempotent). Never edit an applied migration; add a new one.
- Tables:
  - `sources`, `raw_items` (UNIQUE external_id), `giveaways` (UNIQUE canonical_key)
  - `review_queue` (status: new / entered / skipped / scam), `entries_log`
  - `url_checks` (reputation cache, 24h TTL), `fetch_log`, `filtered_items`
  - `domain_tiers` (domain, tier: TRUSTED / PLATFORM / LINK_HUB / BLOCKED, added_by, added_at, note)
  - `known_accounts` (platform, handle, added_by, added_at, note)
  - `run_log` (started_at, finished_at, items_found, alerts_sent, errors)
  - `widget_links` (host_url, widget_url, kind, found_at): host page -> embedded widget
- NO personal data tables in Turso. (The former `user_profile` table is local-only, if used at all.)

### Human-only lists
- `domain_tiers` and `known_accounts` replace `config/domains.yaml` / `config/known_accounts.yaml`
  at runtime. The YAML files remain only as SEED data, loaded once with
  `uv run python -m radar.admin seed` (inserts missing rows, never overwrites human edits).
- Only these may write TRUSTED/BLOCKED/known_accounts rows: dashboard buttons and `radar.admin`
  commands run by the human. Write functions live in `src/radar/admin_store.py`.
- The polling path (`run.py`, adapters, classify, scoring, url_guard, notify) must NEVER import
  `admin_store.py`. Exception: url_guard may add an UNKNOWN domain as BLOCKED after a Safe
  Browsing match (tightening only, never loosening), via `store.block_domain_from_guard`.
  A test enforces this import rule.

### Backups
- A weekly GitHub Actions job runs `radar.admin export` and uploads a SQL/JSON dump as a
  workflow artifact (retention 30 days). Restore with `radar.admin import <file>`.

## Scheduling (GitHub Actions)
- `.github/workflows/poll.yml`:
  - triggers: `schedule` cron `17 * * * *` (hourly at an offset minute) and `workflow_dispatch`
    (manual "Run workflow" button). Not `*/45`: that gives uneven gaps and roughly doubles
    Actions usage, since each run is billed rounded up to whole minutes.
  - `concurrency: { group: poll, cancel-in-progress: false }` so runs never overlap
  - `timeout-minutes: 10`
  - steps: checkout → setup uv/Python 3.12 → `uv sync` → `radar.admin migrate` → `radar.run --once`
  - Playwright browsers installed only if a TRUSTED JS-only source is configured.
- `.github/workflows/backup.yml`: weekly export (see Backups).
- Secrets (GitHub → Settings → Secrets and variables → Actions):
  `ANTHROPIC_API_KEY`, `BRAVE_API_KEY`, `YOUTUBE_API_KEY`, `SAFE_BROWSING_API_KEY`,
  `DISCORD_WEBHOOK`, `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`.
- Repository variable `PAUSE` (`1` stops all fetching). Workflow sets `DB_BACKEND=turso`.
- Never print secrets or full DB rows in logs. Log counts and URLs only.
- If Turso is unreachable, the run exits with a clear error and sends nothing; the next run
  catches up (dedup makes runs idempotent).
- Keep runs short (target < 2 min) to stay within the free Actions minutes on a private repo.

## Dashboard
- `app/dashboard.py` (Streamlit) reads/writes Turso through `store.py` / `admin_store.py`.
- Hosted on Streamlit Community Cloud as a PRIVATE app (viewer access limited to the owner),
  plus an `APP_PASSWORD` check in the app. Secrets set in Streamlit's secrets settings.
- Can also run locally: `DB_BACKEND=turso uv run streamlit run app/dashboard.py`.

## Link safety (phishing & scam sites)
All outbound page/feed URLs go through `src/radar/url_guard.py`. Keyed/official API calls go
through `src/radar/api_client.py`. No other module may make network calls (the Anthropic SDK in
`classify.py` is the only exception); an import-graph test enforces this.
Goal: block real threats, but prefer FLAG + review over BLOCK whenever a check is a heuristic,
so legitimate giveaways are not silently lost.

### Check before fetch
- Every URL is checked BEFORE any fetch or alert:
  1. Google Safe Browsing lookup → any match blocks that exact URL and writes a
     `filtered_items` row. If the domain is UNKNOWN, the whole domain is also added as
     BLOCKED. Domains already in `domain_tiers` (TRUSTED incl. platform hosts like gleam.io,
     PLATFORM like reddit.com, LINK_HUB like bit.ly) keep their tier: only the URL is blocked
     (the cached match keeps it blocked).
  2. Domain age via RDAP → younger than 30 days = NEW DOMAIN flag (goes to review, not blocked).
  3. Lookalike check (see below).
- Reputation results are cached in the `url_checks` table with a TTL of 24h.
- If a reputation service is unreachable, treat the URL as UNKNOWN, never as TRUSTED (fail closed).
  Use cached results where available.

### Lookalike check (`config/protected_names.yaml`)
- BLOCK only:
  - punycode/IDN domains (`xn--`) or mixed-script hostnames, and
  - close imitations of OFFICIAL domains listed in `official_domains`
    (e.g. pokemon.com, pokemoncenter.com, tcgplayer.com): edit distance ≤ 2, or the official
    brand plus a deceptive suffix like `-official`, `-giveaway`, `-support`, `-claim`.
- Everything else containing "pokemon"/"tcg"/a shop name (e.g. `pokemoncardshopuk.com`)
  is NOT blocked — it gets a LOOKALIKE? flag and goes to review.
- Official domains themselves must be seeded as TRUSTED.

### Tiers (`domain_tiers` table)
- TRUSTED: manually reviewed domains (e.g. gleam.io, kingsumo.com, viralsweep.com,
  tcgplayer.com, vetted shops/forums). Human-only (see "Human-only lists").
- PLATFORM: social/content hosts where the domain says nothing about the poster
  (instagram.com, x.com, youtube.com, tiktok.com, reddit.com, facebook.com, discord.com).
  A PLATFORM domain is NEVER treated as trusted. Judge the ACCOUNT instead (see below).
- LINK_HUB: link-in-bio and shortener hosts (linktr.ee, beacons.ai, bit.ly, etc.).
  Never alert on these directly — resolve to the final destination and judge that.
- UNKNOWN: anything not in the table. Plain fetcher only (no JavaScript). Goes to review.
- BLOCKED: failed Safe Browsing (UNKNOWN domains) / hard lookalike rule, or marked Scam on
  the dashboard.
  Never fetched again.

### Account signals (PLATFORM posts)
- Score the posting account, not the domain: account age, follower count, verified status,
  handle similarity to entries in `known_accounts`, and whether this is the ORIGINAL giveaway
  post rather than someone's entry/comment/repost.
- Ping Discord only if: account is in `known_accounts`, OR all of — not a lookalike handle,
  account older than 90 days (when available), original post, and low scam score.
  Even a known account goes to review if its post has scam signals or the URL is flagged.
- Otherwise send to the review queue with the failing signals shown.
- Dashboard "Trust account" button adds to `known_accounts` (human-only).

### Fetch sandbox
- Schemes: `http`/`https` only. Reject `javascript:`, `data:`, `file:`, `ftp:` etc.
- Re-run the guard on EVERY redirect hop; max 5 redirects. Shortener expansion counts as a fetch.
- Block private/loopback/link-local/metadata IPs after DNS resolution (SSRF protection).
  Resolve ONCE per hop, check every IP, then connect to a checked IP (DNS pinning via a custom
  httpcore network backend) with the real Host header and TLS hostname, so DNS rebinding
  can't swap in a private address.
- robots.txt per RFC 9309: 2xx → obey; 4xx (incl. 404) → no restrictions; 5xx or network
  failure → refuse for this run and retry next run. Successful results are cached in
  `url_checks` (24h). Also honour a per-host minimum interval and Crawl-delay.
- Timeout 10s. Read at most the first 2 MB and parse that (truncate, don't reject).
- Accept `text/html`, RSS/Atom XML, `application/json`; also accept `text/plain` and
  `application/octet-stream` ONLY for feed URLs listed in `config/sources.yaml`.
  Never download or save other content types (no PDFs, archives, executables).
- No cookies, no auth headers, no persistent sessions. Honest User-Agent identifying the bot.

### API client (`src/radar/api_client.py`)
- Fixed host allowlist: Brave Search, YouTube/Google APIs, Safe Browsing, IANA RDAP bootstrap,
  Discord webhooks (webhook paths only). RDAP registry servers are allowed only as named in
  IANA's bootstrap file. HTTPS only, no redirects followed, no cookies.
- Keys come from env only and are never logged: errors name the host and status, never the
  URL, query string or headers.
- Any URL found in API results still goes through url_guard before it is fetched.
- Playwright (JS execution) is allowed ONLY on TRUSTED domains, in a fresh context per page,
  and only in CI/container — never on the developer's personal machine or browser profile.

### Embedded giveaway widgets
- When an UNKNOWN or TRUSTED page is fetched without JS, scan raw HTML (script src, iframe src,
  anchors, data attributes) for embedded widget URLs: gleam.io, kingsumo.com, viralsweep.com.
- Pass each extracted widget URL through the guard and fetch it (these are TRUSTED), then
  classify the widget page together with the host page. Record the host→widget link.

### Deterministic rules override the LLM (`src/radar/scoring.py`)
- Match PHRASES that request something from the entrant, not single words:
  - fees: "pay shipping", "shipping fee", "cover shipping", "processing fee", "claim fee",
    "small fee", "send payment", "pay to claim"
  - claim: "DM to claim", "message us to claim", "contact to claim your prize"
  - crypto/payment: "connect wallet", "seed phrase", "send crypto", "USDT", "gift card code",
    "Cash App/Venmo/Zelle to claim"
  - credentials: "enter your password", "verify your card", "card details to claim"
  → scam_likelihood forced to "high".
- Do NOT flag benign phrases: "winner will be DM'd", "free shipping", "we cover shipping",
  "winner contacted by DM". Keep these in an allowlist with tests.
- The LLM can lower nothing that the guard or keyword rules raised. A BLOCKED or flagged
  domain/account cannot be upgraded by a classifier verdict.
- The classifier has NO tools. Page content is passed inside clearly delimited
  `<untrusted_page>` tags with an instruction that it is data, not instructions.

### Alerts and review queue
- Discord pings go out only for: TRUSTED domain + low scam score, or PLATFORM post passing the
  account rules above.
- Everything else goes to the review queue, sorted by deadline (soonest first) so short
  Instagram/TikTok giveaways aren't missed. Include a daily digest of the queue.
- Every alert and queue item shows the full real domain (or account handle), tier, domain/account
  age, and warning badges: NEW DOMAIN, LOOKALIKE?, NOT TRUSTED, SCAM SIGNALS.
- Never post shortened or redirecting links — post the final resolved URL only.
- Dashboard buttons: Open, Entered, Skip, Scam (→ BLOCKED), Trust domain, Trust account.

### Assisted entry (Claude in Chrome, Phase 4)
- Runs LOCALLY only. Reads the queue from Turso; personal details come from the local `.env`.
- Operate ONLY on TRUSTED domains. Refuse to open or pre-fill any other domain.
- Use a dedicated Chrome profile with no saved passwords or payment methods,
  and a dedicated giveaway-only email address.
- STOP and hand control back if a page asks for a login, password, payment, card details,
  crypto, or a fee of any kind. Never type credentials. The human clicks submit.

### Monitoring and tuning
- Log every fetched URL with tier, guard verdict and timestamp (`fetch_log`).
- Log every item dropped or held back by a guardrail with the rule that fired
  (`filtered_items`: url, rule, reason, timestamp, later_human_verdict).
- Dashboard "Filtered" tab shows weekly counts per rule plus samples, so over-strict rules
  can be loosened. When a human trusts a filtered item, record which rule caught it.
- Dashboard "Runs" tab shows `run_log` (last run time, items found, errors) so a stalled
  schedule is obvious.
- `PAUSE=1` (GitHub repo variable or local `.env`) stops all fetching; every entrypoint checks it first.

## Stack
Python 3.12, uv, httpx + selectolax, feedparser, Playwright (TRUSTED JS pages only),
anthropic SDK (Haiku 5.5, structured outputs), Turso (`turso_serverless`) / sqlite3 for dev,
Streamlit, Discord webhook, GitHub Actions.

## Layout
src/radar/adapters/*.py  - one SourceAdapter per source (fetch() -> list[RawItem])
src/radar/url_guard.py   - reputation checks, tiers, safe fetcher (only page/feed network path)
src/radar/api_client.py  - keyed API calls (allowlisted hosts), Safe Browsing + RDAP clients
src/radar/domains.py     - registrable-domain helpers (offline Public Suffix List)
src/radar/config.py      - env vars (require_env, PAUSE) and YAML loading
src/radar/migrate.py     - migration runner (schema_version)
src/radar/widgets.py     - extract embedded Gleam/KingSumo/ViralSweep URLs from raw HTML
src/radar/accounts.py    - account signals for PLATFORM posts
src/radar/classify.py    - Pydantic Giveaway schema + Haiku call (no tools)
src/radar/scoring.py     - deterministic scam phrase rules; override LLM verdicts
src/radar/db.py          - connection factory (turso | sqlite); ONLY place connections open
src/radar/store.py       - read/write for polling path (items, queue, logs, caches)
src/radar/admin_store.py - human-only writes (domain_tiers, known_accounts)
src/radar/migrations/    - NNN_name.sql schema migrations
src/radar/admin.py       - CLI: migrate, seed, export, import, trust/block domain
src/radar/notify.py      - Discord webhook
src/radar/run.py         - one polling cycle (idempotent, checks PAUSE)
app/dashboard.py         - review queue + Filtered + Runs tabs
config/domains.yaml      - SEED data for domain_tiers
config/known_accounts.yaml   - SEED data for known_accounts
config/protected_names.yaml  - official_domains + brand names for lookalike detection
config/sources.yaml      - feeds, search queries, region
.github/workflows/poll.yml   - scheduled polling
.github/workflows/backup.yml - weekly DB export
.env.example             - all variable names, no values
tests/fixtures/          - saved HTML/RSS samples; tests never hit the network or Turso

## Testing requirements
url_guard / scoring / widgets / accounts / store must have unit tests covering:
- blocked schemes, private IPs, redirect to blocked domain, 5-hop redirect limit
- punycode lookalike (BLOCK), near-miss of official domain (BLOCK),
  legit shop with "pokemon" in name (FLAG, not block)
- Safe Browsing match, reputation service down (fail closed, cache used)
- oversize response truncated, disallowed content type, text/plain feed allowed
- PLATFORM domain never treated as trusted; known account pings; unknown account → review
- Gleam widget URL extracted from a JS-only shop page fixture
- scam phrases flagged; benign phrases ("winner will be DM'd", "free shipping") NOT flagged
- every guardrail drop writes a `filtered_items` row
- migrations apply cleanly to an empty in-memory DB and are idempotent
- `seed` never overwrites a human-edited row
- polling-path modules do not import `admin_store` (import-graph test)
- running `run --once` twice on the same fixtures sends alerts only once (idempotency)
Any change to these modules requires the tests to pass.

## One-time setup (human)
1. Install the Turso CLI and log in (`turso auth login`).
2. `turso db create giveaway-radar`
3. `turso db show giveaway-radar --url` → `TURSO_DATABASE_URL`
4. `turso db tokens create giveaway-radar` → `TURSO_AUTH_TOKEN`
   (verify these CLI commands against docs.turso.tech if they error)
5. Add all secrets to GitHub Actions and Streamlit Cloud; put local values in `.env`.
6. `DB_BACKEND=turso uv run python -m radar.admin migrate && ... seed`
7. Trigger `poll.yml` once with "Run workflow" and check Discord + the Runs tab.

## Commands
uv run pytest -q ; uv run ruff check .
uv run python -m radar.admin migrate | seed | export | import <file>
uv run python -m radar.run --once            # local SQLite
DB_BACKEND=turso uv run python -m radar.run --once
uv run streamlit run app/dashboard.py
