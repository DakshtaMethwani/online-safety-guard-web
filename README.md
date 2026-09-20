<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/5f7f0658-c84f-44bf-a773-f544fb172afa

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Link-protection gateway

A backend that turns suspicious URLs from your email/notification script into short, safe gateway links. Run inspection asynchronously, then serve a redirect / warning / block page per link.

**Setup:** add `INSPECTOR_KEY`, `ADMIN_PASSWORD`, `DB_PATH` and `GATEWAY_URL` to `.env.local` (see [.env.example](.env.example)).

**Quick flow (using curl):**

```bash
# 1) Submit up to 20 URLs for one message. Keep the INSPECTOR_KEY secret.
curl -s -X POST http://localhost:3000/api/inspect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INSPECTOR_KEY" \
  -d '{"message_ref":"order-1234","urls":["https://example.com/track/123","https://www.paypal.com.evil.xyz/login"]}'
# → { "links": [ { "url": "...", "id": "...", "gateway_url": "http://localhost:3000/go/<id>", "status": "PENDING" }, ... ], "verdict": "PENDING" }

# 2) Poll until every link has a final status (your email script does this).
curl -s http://localhost:3000/api/message/order-1234/verdict
# → { "message_ref": "order-1234", "verdict": "BLOCKED", "links": [ ... ] }
```

Put `gateway_url` links in your emails. Recipients see:

- **PENDING** → animated "Checking this link…" page that auto-refreshes
- **SAFE** → instant 302 redirect to the real destination
- **UNVERIFIED** → caution page with the full destination + findings + "Continue anyway"
- **BLOCKED** → block page (destination shown as plain text, never a clickable link)

### curl examples

Assumes the server is at `http://localhost:3000` and `$INSPECTOR_KEY` is exported.

**1. Safe URL** — every check runs clean → `SAFE`:

```bash
curl -s -X POST http://localhost:3000/api/inspect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INSPECTOR_KEY" \
  -d '{"message_ref":"demo-safe","urls":["https://example.com/"]}'
```

**2. Suspicious URL** — brand in a subdomain of an unrelated host → `BLOCKED` (verdict `MALICIOUS`); a warning-level URL → `UNVERIFIED`:

```bash
curl -s -X POST http://localhost:3000/api/inspect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INSPECTOR_KEY" \
  -d '{"message_ref":"demo-suspicious","urls":["https://www.paypal.com.evil.xyz/login","https://example.com/?next=https%3A%2F%2Fevil.com"]}'
```

**3. Blocklisted URL** — either already on the blocklist or flagged by the scan, so the domain is auto-added and it short-circuits immediately:

```bash
# Flag it (also auto-adds its domain to the blocklist):
curl -s -X POST http://localhost:3000/api/inspect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INSPECTOR_KEY" \
  -d '{"message_ref":"demo-blocked","urls":["https://usps-post-redelivery.top/update"]}'
# Then any other link on the same domain is blocked without re-scanning:
curl -s -X POST http://localhost:3000/api/inspect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INSPECTOR_KEY" \
  -d '{"message_ref":"demo-blocked-2","urls":["https://another.usps-post-redelivery.top/"]}'
# You can also add entries manually (admin):
curl -s -u admin:CHANGE_ME -X POST http://localhost:3000/admin/blocklist \
  -d "type=domain&value=example.org&reason=phishing"
```

**4. Unreachable URL** — the redirect/connectivity check errors → verdict `UNVERIFIED` (never SAFE):

```bash
curl -s -X POST http://localhost:3000/api/inspect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INSPECTOR_KEY" \
  -d '{"message_ref":"demo-unreachable","urls":["https://this-host-does-not-exist.invalid/"]}'
```

Poll verdicts with `curl -s http://localhost:3000/api/message/<message_ref>/verdict`, review everything at `http://localhost:3000/admin` (HTTP Basic auth, any username, password = `ADMIN_PASSWORD`).

> **Note:** any check that cannot run (missing reputation key, timeout, unreachable host) forces a link to `UNVERIFIED` — a gateway link is **never** marked SAFE on incomplete results. Only a full clean scan (or a blocklist/allowlist match) decides the final status.

## Mail Activity

Optional module for your Gmail/Outlook add-on: it reports what it did with each message, and `/admin/mail` shows the history with live pop-up alerts.

### Report an event (add-on → server)

`POST /api/events` — same Bearer key and rate limiting as `/api/inspect`.

```bash
curl -s -X POST https://YOUR-SERVICE.onrender.com/api/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INSPECTOR_KEY" \
  -d '{"provider":"gmail","message_ref":"<message id>","mailbox":"you@example.com",
       "sender_domain":"evil.top","sender_display":"Acme <bad@evil.top>",
       "subject":"Account suspended","verdict":"BLOCKED",
       "action":"moved_to_spam","link_count":2}'
```

- `provider`: `gmail` | `outlook`; `verdict`: `SAFE` | `UNVERIFIED` | `BLOCKED` | `ERROR`; `action`: `none` | `labeled` | `moved_to_spam` | `protected_copy` | `restored`.
- Length limits: `subject`/`sender_display` 200, `message_ref` 128, `mailbox` 320. **Unknown fields are rejected** — there is deliberately no field for an email body, so bodies can never be stored.
- Repeating the same `provider` + `message_ref` updates the existing row instead of duplicating it.
- `mailbox` is hashed server-side: `SHA-256(mailbox + EVENT_SALT)` — only the hash is stored.

### Admin API (Basic auth)

| Endpoint | Purpose |
| --- | --- |
| `GET /api/events?provider=&verdict=&from=&to=&q=&limit=&offset=` | Paginated history + filters + `total`/`unread` |
| `GET /api/events?since=<id>` | Only events newer than `<id>` (used for polling) |
| `POST /api/events/read` | Body `{"ids":[…]}` or `{}` to mark read |
| `DELETE /api/events` | Wipe all mail events |

### /admin/mail

- Summary cards (Scanned / Safe / Needs review / Blocked / Last 24h) and a history table with Time, provider, sender, subject, verdict badge, action, link count and a **View links** button that shows the related gateway links with the existing SAFE/BLOCKED override buttons.
- Filters (provider, verdict, date range, text search) and a 10-second auto-refresh.
- **Pop-up alerts:** new `BLOCKED` (red, stays until closed) and `UNVERIFIED` (amber, auto-dismiss after 10 s) toasts, each with sender, subject, verdict, action and a **View** button that scrolls to the row. Bursts are grouped ("5 new suspicious emails"). Which verdicts trigger pop-ups is configurable. Unread badge in the nav, optional desktop notifications (opt-in, no sound), and no pop-ups for historical events on first load.
- **Store subjects** can be turned off from this page — only the sender domain is then kept.

All mail data is served **behind admin auth**; the public homepage never shows any of it. Subjects/senders are HTML-escaped and admin pages send a CSP that blocks inline scripts.

## URL inspector: scoring, sources and evaluation

`inspectUrl` returns **two numbers**:
- **`riskScore` (0–100)** — deterministic evidence only. Each signal carries signed points and a one-line reason in `signals[]`.
- **`confidence` (0–100)** — how many weighted checks actually ran. A missing/errored critical check (reputation, redirect, DNS, TLS) caps confidence below the low-risk bar, so an unverified URL is never called low risk.

Verdicts: `MALICIOUS` (risk ≥ 70 **or** any reputation hit) · `SUSPICIOUS` (40–69) · `LOW_RISK` (< 40 **and** confidence ≥ 60) · otherwise `UNVERIFIED`. Thresholds live in `url-scoring.ts` (`VERDICT_THRESHOLDS`).

### Scoring model (deterministic)

- **`riskScore = clamp(sum(signal.points), 0, 100)`** — nothing else is applied. Every signal, including negatives, is returned in `signals[]` and shown in "Why this score".
- **Only these reduce risk:** Tranco top-list membership, an allowlist match, a clean result from a reputation source that actually ran, and a known-legitimate destination after following redirects. Their total is **capped at −20**, and they **never cancel a high-severity signal** (brand impersonation, reputation hit, punycode/homograph, raw IP host, dangerous scheme) or drop a suspicious URL below the suspicious band.
- **Valid TLS, a resolving DNS name and a normal domain age add 0 points** — they are normal, not evidence of safety. They only add risk when abnormal (no DNS, TLS problem, very new/recently-registered domain).
- **Keyword review:** a single generic word (`update`, `delivery`, `verify`, `secure`) is a weak +5 alone; it becomes a real signal only alongside a second factor (brand mismatch, suspicious TLD, young domain, unrelated domain).
- **`confidence` = share of the documented check weights that actually succeeded.** The weights sum to 100:
  `reputation 30 · redirect 15 · structure 15 (url-structure 5, brand 5, subdomain 3, query 2) · domain-age 10 · Tranco 10 · AI 10 · DNS 5 · TLS 5`.
- **Missing checks lower confidence, never raise the score.** A URL whose critical live checks (reputation, redirect, DNS) did not return a clean result is `UNVERIFIED`, not `LOW_RISK`.

### Checks that actually run

- **Tranco**: the top-1M list is downloaded on startup, cached to `TRANCO_LIST_FILE` (default `data/tranco-top.txt`), refreshed daily, and held in memory. No key. If the download fails, the check reports "Not available right now".
- **Reputation**: URLhaus (`URLHAUS_API_KEY`), Google Safe Browsing (`GOOGLE_SAFE_BROWSING_API_KEY` or the `SAFE_BROWSING_API_KEY` alias) and an OpenPhish feed cached at `OPENPHISH_FEED_FILE` (default `data/openphish.txt`). Each is independent — one missing key never disables the others.
- **AI analysis** is advisory only. It is called **only when the deterministic score is borderline (25–70) and no reputation source gave a clear verdict**, behind a per-domain 24h cache, a global concurrency limit (`AI_MAX_CONCURRENCY`), a per-minute limiter (`AI_RPM`), and exponential backoff with jitter that honours `Retry-After`. `GEMINI_MODEL` sets the model with a fallback chain; on startup the server lists the models the key can access and flags a bad model ID. **A failure only lowers confidence — it never changes the score.**

### Debug view (admin only)

`GET /api/inspect?url=<url>` with admin Basic auth returns the inspection **plus a `debug` object** listing each check's status, duration and real reason (missing key, HTTP 429, timeout, …), plus the scoring weights, Tranco status, AI state/models and which env vars are set. Raw errors and env-var names are shown **only** here — end-user UI says "Not available right now".

### Reputation / intelligence sources

| Source | Type | Key / setup | Commercial use |
| --- | --- | --- | --- |
| URLhaus (abuse.ch) | malware/phishing URLs | `URLHAUS_API_KEY` | Free — check abuse.ch terms |
| Google Safe Browsing | phishing / malware | `GOOGLE_SAFE_BROWSING_API_KEY` (or `SAFE_BROWSING_API_KEY`) | Free with a key; commercial use permitted under Google's terms |
| OpenPhish / PhishTank feed | phishing URLs, cached locally | none — drop a feed at `OPENPHISH_FEED_FILE` (default `data/openphish.txt`) | OpenPhish's community feed is generally **non-commercial**; PhishTank has its own terms — verify before commercial use |
| Tranco | site popularity | none — downloaded to `TRANCO_LIST_FILE` on startup, refreshed daily | Free to use; please cite Tranco |
| RDAP (rdap.org) | domain age | none | Public registry data — be polite with rate limits |

> Each source sits behind the same `ReputationProvider`/`UrlIntel` interface; a missing key or absent feed reports **"not configured"** (never "clean") and only lowers confidence. **Review each provider's terms before commercial deployment** — the free tiers are not all commercial-use.

### Caching
- Verdicts are cached **per URL for 6h** at `/api/inspect-domain`.
- DNS, TLS, RDAP and Tranco results are cached **for 24h** in `url-scoring.ts`.

### Evaluation
```bash
npm run eval              # deterministic/offline metrics from tests/data/urls.csv
npm run eval -- --online  # use the real network
```
It prints precision, recall, false-positive rate and the risk-score distribution per class (`bad` / `safe` / `hard`), and a per-URL line so you can tune the weights in `url-scoring.ts`.

## Outlook add-in

A read-mode Outlook add-in that checks the links in the email you open and reports the result to `/admin/mail`.

### Setup

1. Set **`OUTLOOK_ADDIN_KEY`** on the server to a long random value (different from `INSPECTOR_KEY`) and redeploy. Leave it unset to disable add-in access entirely.
2. The manifest lives at **`outlook/manifest.xml`** — kept in the repo, **not served**. Every URL in it is under `https://safety-guard-web-ncra.onrender.com/outlook/`.
3. **Sideload** the manifest:
   - **Outlook on the web / new Outlook:** Settings → General → Manage add-ins → My add-ins → **Custom add-ins → Add from file** → pick `outlook/manifest.xml`.
   - **Outlook desktop (Windows):** File → Manage Add-ins → My add-ins → **Custom add-ins → Add from file**.
   - **Outlook for Mac:** Tools → Get Add-ins → My add-ins → **Custom add-ins → Add from file**.
   - **Centrally:** Microsoft 365 admin center → Settings → Integrated apps → **Upload custom apps**.
4. Open a received email, click **Analyze with Online Safety Guard**, and paste the add-in key once. It is stored in Outlook **roaming settings**; use the **Forget key** link to remove it.

### What it does
- Reads subject, sender and HTML body; extracts up to 20 `http/https` links (skipping the site's own domain); hashes the `itemId` to a `ref` (SHA-256); calls `POST /api/inspect`; polls `GET /api/message/:ref/verdict` every 3s for ~30s.
- Shows **Safe** (green), **Needs review** (amber) or **Blocked** (red), lists links **defanged** (`hxxps://example[.]com`) with a per-link verdict, and offers **Open safety check page** (the gateway URL).
- In parallel, sends the plain-text body to `POST /api/analyze-message` and shows a separate **Message content risk** panel: a Low/Medium/High badge, a 0–100 risk score, the scam type (e.g. "Account Takeover Phishing"), a one-line summary, and the top red flags — independent of the link check, so a scam with no links still gets flagged. The body is sent only for this one analysis call; it is never stored or logged server-side.
- Adds a **warning bar** to the message for Needs review/Blocked, and reports the event to `POST /api/events` (provider `outlook`, action `none`).
- **Fail-open:** if the server is asleep or a call fails it shows "Check failed — treat links with care" with a **Retry** button.

### Served files
`/outlook/*` is served with **add-in-only headers** (`Content-Security-Policy` with `frame-ancestors` for the Office hosts, and **no `X-Frame-Options`**) and is mounted **before** the SPA catch-all. No other route on the site gets those headers.

### Switching to Microsoft sign-in (before sharing widely)
The current model is a shared secret typed into the pane. Real per-user auth would use `Office.auth.getAccessToken()` (requires SSO — an Entra app registration plus `WebApplicationInfo` in the manifest), send that token instead of the key, and validate it server-side (verify the signature against the tenant's JWKS, check `aud`/`iss`/`scp`, map the user). That removes the shared secret from the pane and gives per-user revocation — the right step before distributing beyond yourself.

## Gmail add-on

A Gmail add-on (Google Apps Script, `gmail/`) that checks the links in the email you open and reports the result to `/admin/mail` — the Gmail counterpart to the Outlook add-in above. Like the Outlook add-in, it also shows a separate **Message content risk** section (risk score, scam type, red flags) from `POST /api/analyze-message`. See **[`gmail/README.md`](gmail/README.md)** for full setup.

Key difference from Outlook: this runs on Google's servers, not in the browser, so it needs a **publicly reachable HTTPS `GATEWAY_URL`** (e.g. your Render deployment) — it cannot call `http://localhost`. Set **`GMAIL_ADDIN_KEY`** on the server (a limited key, same model as `OUTLOOK_ADDIN_KEY`, scoped to `POST /api/inspect`, `GET /api/message/:ref/verdict` and `POST /api/events`, forcing `provider="gmail"`). Unset/empty ⇒ add-on access disabled.

## Deploy (persistent host)

The gateway keeps its SQLite database on disk, so it must run on a host with a **persistent filesystem** (a VM, a Docker host, or a managed container platform with a mounted volume) — **not** a serverless function.

### Build & run with Node

```bash
npm ci
npm run build   # vite client build + dist/server.cjs (compiled server bundle)

NODE_ENV=production \
PORT=3000 \
DB_PATH=/var/lib/online-safety-guard/gateway.db \
INSPECTOR_KEY=change-me \
ADMIN_PASSWORD=change-me \
GATEWAY_URL=https://links.example.com \
node dist/server.cjs
```

`npm start` runs the same command (`node dist/server.cjs`).

### Run with Docker

```bash
docker build -t online-safety-guard .

docker run -d --name guard \
  -p 3000:3000 \
  -v guard-data:/data \
  -e INSPECTOR_KEY=change-me \
  -e ADMIN_PASSWORD=change-me \
  -e GATEWAY_URL=https://links.example.com \
  online-safety-guard
```

The image runs the server as the non-root `node` user, sets `DB_PATH=/data/gateway.db`, and exposes/mounts `/data` — attach a persistent volume there so the link history, blocklist and allowlist survive restarts. If you use a **bind mount** instead of a named volume, `chown -R 1000:1000 <host-dir>` first: the process runs as uid 1000 (`node`).

### Deploy on Render (Docker)

> **One-click option:** this repo ships a [`render.yaml`](render.yaml) Blueprint. In Render choose **New + → Blueprint**, point it at this repo, and Render provisions the service **and** the `/data` disk and prompts you for the secrets. The manual steps below are the equivalent.

1. **New → Web Service**, connect the repo, set **Language: Docker**, branch `main`, root directory blank.
2. Pick a **paid instance** (e.g. 0.5 CPU / 512 MB). Persistent disks are **not available on the Free plan**, and Free instances spin down — the SQLite gateway data would be lost on every restart.
3. Under **Advanced → Add Disk**: mount path `/data`, size 1 GB. (The image's entrypoint fixes disk ownership, so the non-root process can write.)
4. Set **Health Check Path** to `/healthz`.
5. Add the environment variables below. Render injects `PORT` automatically (don't set it) and `RENDER_EXTERNAL_URL`, which is used as the fallback for `GATEWAY_URL`.

| Variable | Value |
| --- | --- |
| `INSPECTOR_KEY` | random secret (Render's **Generate** button works) |
| `ADMIN_PASSWORD` | strong password for `/admin` |
| `URLHAUS_API_KEY` | from https://auth.abuse.ch/ (or links stay `VERIFICATION_REQUIRED`) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | from Google (optional but recommended) |
| `GEMINI_API_KEY` | enables AI semantic analysis of messages (optional) |
| `TRUST_PROXY` | `1` (Render terminates TLS at its proxy) |
| `GATEWAY_URL` | `https://<your-service>.onrender.com` (optional — falls back to `RENDER_EXTERNAL_URL`) |
| `DB_PATH` | `/data/gateway.db` (already the image default) |

`NODE_ENV=production` is baked into the image; don't override it or the HTTPS-only guard and static serving turn off.

### Deploy checklist (environment variables)

| Variable | Required | Notes |
| --- | --- | --- |
| `INSPECTOR_KEY` | **Yes** | Bearer token the sender/email script uses for `POST /api/inspect`. The endpoint returns `503` when unset (fail-closed). |
| `OUTLOOK_ADDIN_KEY` | For the Outlook add-in | Optional **limited** Bearer key accepted only on `POST /api/inspect`, `GET /api/message/:ref/verdict` and `POST /api/events` (where it forces `provider="outlook"`). Unset/empty ⇒ add-in access disabled. Never grants admin access. Keep it different from `INSPECTOR_KEY`. |
| `GMAIL_ADDIN_KEY` | For the Gmail add-on | Same scope as `OUTLOOK_ADDIN_KEY`, but forces `provider="gmail"`. Unset/empty ⇒ add-on access disabled. Keep it different from `INSPECTOR_KEY` and `OUTLOOK_ADDIN_KEY`. |
| `ADMIN_PASSWORD` | **Yes** | Password for the `/admin` review page (HTTP Basic, any username). `/admin` returns `503` when unset. |
| `VIEWER_PASSWORD` | No | Optional **read-only** admin login. If set (and different from `ADMIN_PASSWORD`) it can open the new `/admin/mail` UI and read `/api/events` + `/api/events/stats` only; every POST/DELETE, Links, blocklist, allowlist, settings and `?legacy=1` return `403`. Unset/empty/equal-to-admin ⇒ disabled. |
| `GATEWAY_URL` | **Yes in production** | Public HTTPS base URL used to build the `/go/:id` links returned by the API. Falls back to the request's own origin, so set it explicitly behind a proxy. |
| `EVENT_SALT` | For Mail Activity | Server-side salt for hashing mailbox addresses (`SHA-256(mailbox + salt)`). Only the hash is stored. |
| `EVENT_RETENTION_DAYS` | No | Days of mail activity to keep before the daily cleanup deletes it. Default `30`. |
| `STORE_SUBJECTS` | No | Initial "Store subjects" setting (`1`/`0`), changeable at `/admin/mail`. Default `1`. |
| `DB_PATH` | **Yes in production/Docker** | SQLite file path. Must live on the persistent volume — `data/gateway.db` locally, `/data/gateway.db` in the image. |
| `URLHAUS_API_KEY` | Recommended | Enables the URLhaus malware/phishing reputation lookup (URL + host). **If unset, that source is skipped and a link can never be `SAFE`** — it stays `VERIFICATION_REQUIRED` until every check can run. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Recommended | Enables the Google Safe Browsing lookup (phishing/malware/unwanted software). Also applied to the post-redirect destination. |
| `NODE_ENV` | **Yes** | Must be `production` for the compiled server (enables the HTTPS guard + static serving). |
| `PORT` | No | TCP port to listen on. Defaults to `3000`. |
| `TRUST_PROXY` | Recommended behind a proxy | How many proxy hops to trust for `X-Forwarded-*` (so rate limiting and the HTTPS guard see the real client). Accepts `false`, `true`, a hop count (usually `1`), or a list of proxy addresses. Defaults to `1` in production. |
| `REQUIRE_HTTPS` | No | Refuses `/api/*` and `/admin` over plain HTTP. Defaults to `true` in production. Set `false` **only** for local testing of the production build. |
| `GEMINI_API_KEY` | No | Enables the optional AI semantic check. |
| `APP_URL` | No | Legacy self-reference URL (AI Studio). |

### HTTPS enforcement

With `NODE_ENV=production`, the server refuses to serve `/api/*` and `/admin` over plain HTTP (`403`). Behind a TLS-terminating proxy this is detected via `X-Forwarded-Proto`, so `TRUST_PROXY` must match your proxy setup. `GET /healthz` deliberately stays reachable over HTTP so load balancers and the Docker `HEALTHCHECK` can probe it.

### Health check

`GET /healthz` → `200 {"status":"ok","uptime":…}`. The Dockerfile declares a `HEALTHCHECK` against this endpoint.
