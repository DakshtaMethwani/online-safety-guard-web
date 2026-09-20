# Gmail add-on

A Gmail add-on that checks the links in the email you open and reports the result to `/admin/mail` — the Gmail
counterpart to `outlook/`. It's built with Google Apps Script (`CardService`), which is a different technology
from the Outlook add-in: there's no HTML/JS webview here, no manifest to sideload, and no localhost testing.
**Apps Script code runs on Google's servers**, so every call to the safety-guard backend is server-to-server —
`BASE_URL` in `Code.gs` must be a real, publicly reachable HTTPS URL (e.g. your Render deployment). It cannot
reach `http://localhost:3000`.

## Setup

1. Deploy the server somewhere with a public HTTPS URL (see the main README's Render section). You need this
   first — there is no way to point the add-on at your local dev server.
2. Set **`GMAIL_ADDIN_KEY`** on the server to a long random value, different from `INSPECTOR_KEY` and
   `OUTLOOK_ADDIN_KEY`. Leave it unset to disable add-on access entirely.
3. Edit `gmail/Code.gs`: change `BASE_URL` at the top to your deployed URL.
4. Edit `gmail/appsscript.json`: change `logoUrl` to `<your BASE_URL>/outlook/icon-128.png` (that route is
   already public — no new asset needed) if you changed the domain from the placeholder.
5. Create the Apps Script project and push these two files into it. Either:
   - **Apps Script editor (no local tooling):** go to script.google.com → New project → rename it "Online
     Safety Guard" → open **Project Settings** and check "Show `appsscript.json`" → paste the contents of
     `gmail/appsscript.json` over the generated manifest → create a new script file `Code.gs` and paste
     `gmail/Code.gs` into it → Save.
   - **`clasp` (Google's Apps Script CLI, if you prefer to keep this folder as the source of truth):**
     ```bash
     npm install -g @google/clasp
     clasp login
     clasp create --type standalone --title "Online Safety Guard" --rootDir gmail
     clasp push
     ```
6. In the Apps Script editor: **Deploy → Test deployments → Install add-on** (this installs it only for your
   own Google account — no Google review or Workspace Marketplace listing needed for personal use).
7. Open Gmail, open any email. The add-on icon appears in the right-hand rail. Click it, paste the add-on key
   once when prompted — it's stored in your personal Apps Script user properties (Google's per-user key/value
   store for the script), separate from anyone else who installs the same script.

## What it does

- Reads subject, sender and HTML body via `GmailApp.getMessageById`; extracts up to 20 `http/https` links
  (skipping the site's own domain); hashes the message id to a `ref` (SHA-256); calls `POST /api/inspect`;
  polls `GET /api/message/:ref/verdict` for up to ~12s.
- Shows **Safe** (green), **Needs review** (amber) or **Blocked** (red) in a card, lists links **defanged**
  (`hxxps://example[.]com`) with a per-link verdict, and offers **Open safety check page** (the gateway URL)
  and **Re-check**.
- Also sends the plain-text body (`message.getPlainBody()`) to `POST /api/analyze-message` and adds a
  **Message content risk** section to the same card: a Low/Medium/High badge, a 0–100 risk score, the scam
  type, a one-line summary, and the top red flags — independent of the link check, so a scam with no links
  (e.g. "call this number") is still flagged.
- Reports the event to `POST /api/events` (provider `gmail`, action `none`). The email body is only sent for
  the one stateless `/api/analyze-message` call and is never stored or logged server-side; `/api/events`
  itself never carries a body field.
- If the poll doesn't resolve in time, or a call fails, the card shows a retry action rather than blocking.

## Differences from the Outlook add-in

- No warning banner injected into the message — Gmail's add-on API doesn't offer an equivalent to Outlook's
  `notificationMessages`. The card itself is the only surface.
- No client-side polling loop with incremental UI updates — Apps Script builds a card once per invocation, so
  polling happens synchronously inside `runAnalysis_` before the card is returned. A manual **Re-check** button
  covers the case where the first attempt times out.
- The add-in key lives in Apps Script `PropertiesService.getUserProperties()` (Google's server-side per-user
  storage tied to your account), not in a browser-side roaming settings API.

## Switching to per-user Google sign-in (before sharing beyond yourself)

The current model is a shared secret pasted into the add-on, same tradeoff as the Outlook add-in. Real
per-user auth would exchange the add-on's own Google identity (`Session.getActiveUser().getEmail()` plus a
verified ID token via `ScriptApp.getIdentityToken()`) for server-side validation instead of a shared bearer
key. That's the right next step before installing this for other people, e.g. via a Google Workspace
domain-wide install or a Marketplace listing (both require Google's OAuth verification review).
