# Manus prompt: admin visual alignment without attachments

Work from these public sources instead of asking me to upload files:

- Live application: https://safety-guard-web.onrender.com
- Source repository: https://github.com/DakshtaMethwani/safety-guard

Redesign only the admin-facing UI so it uses the same visual language as the
public Online Safety Guard application: typography, colors, spacing, rounded
surfaces, borders, shadows, icons, responsive behavior, light/dark treatment,
and calm security-focused tone. Treat the live public scanner and URL checker
as the visual reference.

Cover the real admin routes and states:

- `/admin`: inspected links, verdicts, findings, allowlist/blocklist actions,
  and verdict overrides.
- `/admin/mail`: mail activity metrics, filters, events, unread state, alerts,
  related inspected links, subject-storage setting, loading, empty, error, and
  unauthorized states.
- Admin authentication and read-only viewer behavior.
- Protected gateway states: pending, safe, unverified, and blocked.

Preserve the existing Express routes, SQLite data model, HTTP Basic
authentication, API payloads, CSP, and security behavior. Do not invent a new
backend or inbox connection. A blocked destination must never be clickable,
and continuing from an unverified result must not change its verdict to safe.

The current admin pages are server-rendered by `gateway.ts`, with their client
behavior served from `/admin/mail.js`. Produce implementation-ready changes for
this repository, not a standalone mockup. Keep frontend-only changes isolated
from URL scoring and inspection logic. Return complete replacement files or a
unified diff that can be applied locally, plus a short list of changed files.

Do not request an attachment. Read the public repository and live URL directly.
