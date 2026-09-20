import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import fs from "node:fs";

/**
 * Gateway storage layer backed by the Node 24 built-in SQLite driver
 * (node:sqlite). Zero native dependencies — no better-sqlite3 / node-gyp.
 */

export type GatewayStatus = "PENDING" | "SAFE" | "UNVERIFIED" | "BLOCKED";

export interface GatewayLink {
  id: string;
  url: string;
  messageRef: string;
  status: GatewayStatus;
  /** JSON snapshot of the inspection result (may be null while PENDING). */
  findings: Record<string, unknown> | null;
  createdAt: string;
  inspectedAt: string | null;
  expiresAt: string;
}

export interface BlocklistRow {
  id: number;
  type: "domain" | "url";
  value: string;
  reason: string | null;
  createdAt: string;
}

export interface AllowlistRow {
  id: number;
  domain: string;
  createdAt: string;
}

// ---- Mail activity -------------------------------------------------------

export type MailProvider = "gmail" | "outlook";
export type MailVerdict = "SAFE" | "UNVERIFIED" | "BLOCKED" | "ERROR";
export type MailAction = "none" | "labeled" | "moved_to_spam" | "protected_copy" | "restored";

export interface MailEvent {
  id: number;
  provider: MailProvider;
  /** SHA-256 mailbox hash — the raw address is never stored. */
  accountHash: string;
  messageRef: string;
  senderDomain: string | null;
  senderDisplay: string | null;
  subject: string | null;
  verdict: MailVerdict;
  action: MailAction;
  linkCount: number;
  isRead: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MailEventInput {
  provider: MailProvider;
  accountHash: string;
  messageRef: string;
  senderDomain: string | null;
  senderDisplay: string | null;
  subject: string | null;
  verdict: MailVerdict;
  action: MailAction;
  linkCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface MailEventFilter {
  provider?: MailProvider;
  verdict?: MailVerdict;
  /** Inclusive ISO lower bound on created_at. */
  from?: string;
  /** Inclusive ISO upper bound on created_at. */
  to?: string;
  /** Free-text search across subject, sender display and sender domain. */
  q?: string;
  /** Restrict to events whose account_hash starts with this prefix (admin only). */
  accountPrefix?: string;
  /** Only return events with id greater than this (polling). */
  since?: number;
  limit?: number;
  offset?: number;
}

export interface MailSummary {
  scanned: number;
  safe: number;
  unverified: number;
  blocked: number;
  errors: number;
  unread: number;
  last24h: number;
}

export interface MailVerdictTotals {
  scanned: number;
  safe: number;
  unverified: number;
  blocked: number;
  error: number;
}

export interface MailStats {
  days: number;
  from: string;
  to: string;
  totals: MailVerdictTotals;
  previous: MailVerdictTotals;
  perDay: Array<{ date: string; safe: number; unverified: number; blocked: number; error: number }>;
  actions: Array<{ action: string; count: number }>;
  topSenders: Array<{ domain: string; needsReview: number; blocked: number }>;
  accounts: Array<{ prefix: string; count: number }>;
}

interface MailRow {
  id: number;
  provider: string;
  account_hash: string;
  message_ref: string;
  sender_domain: string | null;
  sender_display: string | null;
  subject: string | null;
  verdict: string;
  action: string;
  link_count: number;
  is_read: number;
  created_at: string;
  updated_at: string;
}

function mapMailEvent(row: MailRow): MailEvent {
  return {
    id: row.id,
    provider: row.provider as MailProvider,
    accountHash: row.account_hash,
    messageRef: row.message_ref,
    senderDomain: row.sender_domain,
    senderDisplay: row.sender_display,
    subject: row.subject,
    verdict: row.verdict as MailVerdict,
    action: row.action as MailAction,
    linkCount: row.link_count,
    isRead: row.is_read === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

interface LinkRow {
  id: string;
  url: string;
  message_ref: string;
  status: string;
  findings: string | null;
  created_at: string;
  inspected_at: string | null;
  expires_at: string;
}

interface BlocklistRowRaw {
  id: number;
  type: "domain" | "url";
  value: string;
  reason: string | null;
  created_at: string;
}

interface AllowlistRowRaw {
  id: number;
  domain: string;
  created_at: string;
}

function parseFindings(raw: string | null): Record<string, unknown> | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export class GatewayDb {
  private db: DatabaseSync;

  constructor(dbPath: string) {
    if (dbPath === ":memory:") {
      this.db = new DatabaseSync(":memory:");
    } else {
      fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
      this.db = new DatabaseSync(dbPath);
    }
    this.db.exec("PRAGMA journal_mode = WAL");
    this.migrate();
  }

  close(): void {
    try {
      this.db.close();
    } catch {
      /* already closed */
    }
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS links (
        id           TEXT PRIMARY KEY,
        url          TEXT NOT NULL,
        message_ref  TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'PENDING',
        findings     TEXT,
        created_at   TEXT NOT NULL,
        inspected_at TEXT,
        expires_at   TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_links_message_ref ON links(message_ref);
      CREATE INDEX IF NOT EXISTS idx_links_status ON links(status);
      CREATE INDEX IF NOT EXISTS idx_links_expires_at ON links(expires_at);

      CREATE TABLE IF NOT EXISTS blocklist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        type       TEXT NOT NULL,
        value      TEXT NOT NULL,
        reason     TEXT,
        created_at TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_value ON blocklist(type, value);

      CREATE TABLE IF NOT EXISTS allowlist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        domain     TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS mail_events (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        provider       TEXT NOT NULL,
        account_hash   TEXT NOT NULL,
        message_ref    TEXT NOT NULL,
        sender_domain  TEXT,
        sender_display TEXT,
        subject        TEXT,
        verdict        TEXT NOT NULL,
        action         TEXT NOT NULL DEFAULT 'none',
        link_count     INTEGER NOT NULL DEFAULT 0,
        is_read        INTEGER NOT NULL DEFAULT 0,
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_events_unique ON mail_events(provider, message_ref);
      CREATE INDEX IF NOT EXISTS idx_mail_events_created ON mail_events(created_at);
      CREATE INDEX IF NOT EXISTS idx_mail_events_verdict ON mail_events(verdict);
      CREATE INDEX IF NOT EXISTS idx_mail_events_provider ON mail_events(provider);
      CREATE INDEX IF NOT EXISTS idx_mail_events_read ON mail_events(is_read);

      CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }

  // ---- links -------------------------------------------------------------

  createLink(link: {
    id: string;
    url: string;
    messageRef: string;
    status: GatewayStatus;
    findings: Record<string, unknown> | null;
    createdAt: string;
    inspectedAt: string | null;
    expiresAt: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO links (id, url, message_ref, status, findings, created_at, inspected_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        link.id,
        link.url,
        link.messageRef,
        link.status,
        link.findings ? JSON.stringify(link.findings) : null,
        link.createdAt,
        link.inspectedAt,
        link.expiresAt
      );
  }

  getLink(id: string): GatewayLink | undefined {
    const row = this.db.prepare("SELECT * FROM links WHERE id = ?").get(id) as
      | unknown
      | undefined;
    return row ? this.mapLink(row as LinkRow) : undefined;
  }

  listByMessage(messageRef: string): GatewayLink[] {
    const rows = this.db
      .prepare("SELECT * FROM links WHERE message_ref = ? ORDER BY created_at ASC")
      .all(messageRef) as unknown as LinkRow[];
    return rows.map((r) => this.mapLink(r));
  }

  recentLinks(limit = 50): GatewayLink[] {
    const rows = this.db
      .prepare("SELECT * FROM links ORDER BY created_at DESC LIMIT ?")
      .all(limit) as unknown as LinkRow[];
    return rows.map((r) => this.mapLink(r));
  }

  updateInspection(
    id: string,
    update: { status: GatewayStatus; findings: Record<string, unknown> | null; inspectedAt: string }
  ): void {
    this.db
      .prepare("UPDATE links SET status = ?, findings = ?, inspected_at = ? WHERE id = ?")
      .run(update.status, update.findings ? JSON.stringify(update.findings) : null, update.inspectedAt, id);
  }

  /** Admin override of a link's status (does not re-run inspection). */
  overrideStatus(id: string, status: GatewayStatus): boolean {
    const result = this.db.prepare("UPDATE links SET status = ? WHERE id = ?").run(status, id);
    return result.changes > 0;
  }

  private mapLink(row: LinkRow): GatewayLink {
    return {
      id: row.id,
      url: row.url,
      messageRef: row.message_ref,
      status: row.status as GatewayStatus,
      findings: parseFindings(row.findings),
      createdAt: row.created_at,
      inspectedAt: row.inspected_at,
      expiresAt: row.expires_at,
    };
  }

  // ---- blocklist ---------------------------------------------------------

  /**
   * Exact- or domain-match a URL against the blocklist.
   * `hostname` is the lower-cased host and `registrableDomain` its eTLD+1.
   */
  isUrlBlocklisted(
    url: string,
    hostname: string,
    registrableDomain: string
  ): { type: "url" | "domain"; value: string; reason: string | null } | null {
    const urlRows = this.db
      .prepare("SELECT value, reason FROM blocklist WHERE type = 'url'")
      .all() as Array<{ value: string; reason: string | null }>;

    // Exact URL matches (normalized stored values short-circuit the common hits).
    const normUrl = url.toLowerCase();
    for (const row of urlRows) {
      const v = row.value.toLowerCase().replace(/\/+$/, "");
      const u = normUrl.replace(/\/+$/, "");
      if (u === v) return { type: "url", value: row.value, reason: row.reason };
    }

    const domainRows = this.db
      .prepare("SELECT value, reason FROM blocklist WHERE type = 'domain'")
      .all() as Array<{ value: string; reason: string | null }>;
    for (const row of domainRows) {
      const d = row.value.toLowerCase().replace(/\.$/, "");
      if (!d) continue;
      if (hostname === d || hostname.endsWith("." + d) || registrableDomain === d) {
        return { type: "domain", value: d, reason: row.reason };
      }
    }
    return null;
  }

  addBlocklist(type: "domain" | "url", value: string, reason: string | null, createdAt: string): void {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO blocklist (type, value, reason, created_at) VALUES (?, ?, ?, ?)"
      )
      .run(type, value.toLowerCase(), reason, createdAt);
  }

  deleteBlocklistById(id: number): boolean {
    const result = this.db.prepare("DELETE FROM blocklist WHERE id = ?").run(id);
    return result.changes > 0;
  }

  listBlocklist(): BlocklistRow[] {
    const rows = this.db.prepare("SELECT * FROM blocklist ORDER BY created_at DESC").all() as unknown as BlocklistRowRaw[];
    return rows.map((r) => ({
      id: r.id,
      type: r.type,
      value: r.value,
      reason: r.reason,
      createdAt: r.created_at,
    }));
  }

  // ---- allowlist ---------------------------------------------------------

  isAllowlisted(hostname: string, registrableDomain: string): boolean {
    const rows = this.db.prepare("SELECT domain FROM allowlist").all() as Array<{ domain: string }>;
    for (const row of rows) {
      const d = row.domain.toLowerCase().replace(/\.$/, "");
      if (!d) continue;
      if (hostname === d || hostname.endsWith("." + d) || registrableDomain === d) {
        return true;
      }
    }
    return false;
  }

  addAllowlist(domain: string, createdAt: string): void {
    this.db.prepare("INSERT OR IGNORE INTO allowlist (domain, created_at) VALUES (?, ?)").run(domain.toLowerCase(), createdAt);
  }

  deleteAllowlistById(id: number): boolean {
    const result = this.db.prepare("DELETE FROM allowlist WHERE id = ?").run(id);
    return result.changes > 0;
  }

  listAllowlist(): AllowlistRow[] {
    const rows = this.db.prepare("SELECT * FROM allowlist ORDER BY created_at ASC").all() as unknown as AllowlistRowRaw[];
    return rows.map((r) => ({ id: r.id, domain: r.domain, createdAt: r.created_at }));
  }

  // ---- mail events -------------------------------------------------------

  /**
   * Insert a mail event, or update the existing row for the same
   * (provider, message_ref). A repeat event never creates a duplicate, and it is
   * reset to unread so it surfaces again.
   */
  upsertMailEvent(event: MailEventInput): number {
    this.db
      .prepare(
        `INSERT INTO mail_events
           (provider, account_hash, message_ref, sender_domain, sender_display, subject,
            verdict, action, link_count, is_read, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
         ON CONFLICT(provider, message_ref) DO UPDATE SET
           account_hash   = excluded.account_hash,
           sender_domain  = excluded.sender_domain,
           sender_display = excluded.sender_display,
           subject        = excluded.subject,
           verdict        = excluded.verdict,
           action         = excluded.action,
           link_count     = excluded.link_count,
           is_read        = 0,
           updated_at     = excluded.updated_at`
      )
      .run(
        event.provider,
        event.accountHash,
        event.messageRef,
        event.senderDomain,
        event.senderDisplay,
        event.subject,
        event.verdict,
        event.action,
        event.linkCount,
        event.createdAt,
        event.updatedAt
      );

    const row = this.db
      .prepare("SELECT id FROM mail_events WHERE provider = ? AND message_ref = ?")
      .get(event.provider, event.messageRef) as { id: number } | undefined;
    return row ? row.id : 0;
  }

  private mailWhere(filter: MailEventFilter): { sql: string; params: Array<string | number> } {
    const clauses: string[] = [];
    const params: Array<string | number> = [];
    if (typeof filter.since === "number") {
      clauses.push("id > ?");
      params.push(filter.since);
    }
    if (filter.provider) {
      clauses.push("provider = ?");
      params.push(filter.provider);
    }
    if (filter.verdict) {
      clauses.push("verdict = ?");
      params.push(filter.verdict);
    }
    if (filter.from) {
      clauses.push("created_at >= ?");
      params.push(filter.from);
    }
    if (filter.to) {
      clauses.push("created_at <= ?");
      params.push(filter.to);
    }
    if (filter.q) {
      const like = `%${filter.q}%`;
      clauses.push("(subject LIKE ? OR sender_display LIKE ? OR sender_domain LIKE ?)");
      params.push(like, like, like);
    }
    if (filter.accountPrefix) {
      clauses.push("account_hash LIKE ?");
      params.push(`${filter.accountPrefix}%`);
    }
    return { sql: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
  }

  listMailEvents(filter: MailEventFilter = {}): MailEvent[] {
    const { sql, params } = this.mailWhere(filter);
    const order = typeof filter.since === "number" ? "id ASC" : "id DESC";
    const limit = Math.min(Math.max(filter.limit ?? 50, 1), 200);
    const offset = Math.max(filter.offset ?? 0, 0);
    const rows = this.db
      .prepare(`SELECT * FROM mail_events ${sql} ORDER BY ${order} LIMIT ? OFFSET ?`)
      .all(...params, limit, offset) as unknown as MailRow[];
    return rows.map(mapMailEvent);
  }

  countMailEvents(filter: MailEventFilter = {}): number {
    const { sql, params } = this.mailWhere(filter);
    const row = this.db.prepare(`SELECT COUNT(*) AS n FROM mail_events ${sql}`).get(...params) as
      | { n: number }
      | undefined;
    return row ? Number(row.n) : 0;
  }

  getMailEvent(id: number): MailEvent | undefined {
    const row = this.db.prepare("SELECT * FROM mail_events WHERE id = ?").get(id) as unknown as
      | MailRow
      | undefined;
    return row ? mapMailEvent(row) : undefined;
  }

  mailSummary(last24hSince: string): MailSummary {
    const row = this.db
      .prepare(
        `SELECT
           COUNT(*) AS scanned,
           SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END) AS safe,
           SUM(CASE WHEN verdict = 'UNVERIFIED' THEN 1 ELSE 0 END) AS unverified,
           SUM(CASE WHEN verdict = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked,
           SUM(CASE WHEN verdict = 'ERROR' THEN 1 ELSE 0 END) AS errors,
           SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) AS unread
         FROM mail_events`
      )
      .get() as Record<string, number | null> | undefined;
    const last = this.db
      .prepare("SELECT COUNT(*) AS n FROM mail_events WHERE created_at >= ?")
      .get(last24hSince) as { n: number } | undefined;
    const num = (v: number | null | undefined) => Number(v || 0);
    return {
      scanned: num(row?.scanned),
      safe: num(row?.safe),
      unverified: num(row?.unverified),
      blocked: num(row?.blocked),
      errors: num(row?.errors),
      unread: num(row?.unread),
      last24h: last ? Number(last.n) : 0,
    };
  }

  unreadMailCount(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM mail_events WHERE is_read = 0").get() as
      | { n: number }
      | undefined;
    return row ? Number(row.n) : 0;
  }

  markMailEventsRead(ids?: number[]): number {
    if (ids && ids.length) {
      const placeholders = ids.map(() => "?").join(", ");
      const result = this.db
        .prepare(`UPDATE mail_events SET is_read = 1 WHERE id IN (${placeholders})`)
        .run(...ids);
      return Number(result.changes);
    }
    const result = this.db.prepare("UPDATE mail_events SET is_read = 1 WHERE is_read = 0").run();
    return Number(result.changes);
  }

  deleteAllMailEvents(): number {
    const result = this.db.prepare("DELETE FROM mail_events").run();
    return Number(result.changes);
  }

  /** Retention: delete events created strictly before `cutoffIso`. */
  deleteOldMailEvents(cutoffIso: string): number {
    const result = this.db.prepare("DELETE FROM mail_events WHERE created_at < ?").run(cutoffIso);
    return Number(result.changes);
  }

  // ---- mail aggregates (admin Overview) ----------------------------------

  private verdictTotals(fromIso: string, toIso: string, provider?: MailProvider): MailVerdictTotals {
    const clause = provider ? " AND provider = ?" : "";
    const params: string[] = provider ? [fromIso, toIso, provider] : [fromIso, toIso];
    const row = this.db
      .prepare(
        `SELECT
           COUNT(*) AS scanned,
           SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END) AS safe,
           SUM(CASE WHEN verdict = 'UNVERIFIED' THEN 1 ELSE 0 END) AS unverified,
           SUM(CASE WHEN verdict = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked,
           SUM(CASE WHEN verdict = 'ERROR' THEN 1 ELSE 0 END) AS error
         FROM mail_events WHERE created_at >= ? AND created_at < ?${clause}`
      )
      .get(...params) as Record<string, number | null> | undefined;
    const num = (v: number | null | undefined) => Number(v || 0);
    return {
      scanned: num(row?.scanned),
      safe: num(row?.safe),
      unverified: num(row?.unverified),
      blocked: num(row?.blocked),
      error: num(row?.error),
    };
  }

  /**
   * Aggregates for the admin Overview, computed entirely in SQL so the page
   * never downloads every row.
   */
  mailStats(days: number, now: Date, provider?: MailProvider): MailStats {
    const dayMs = 86_400_000;
    const span = Math.min(Math.max(Math.trunc(days) || 7, 1), 90);
    const to = now;
    const from = new Date(to.getTime() - span * dayMs);
    const prevFrom = new Date(from.getTime() - span * dayMs);
    const fromIso = from.toISOString();
    const toIso = to.toISOString();

    const totals = this.verdictTotals(fromIso, toIso, provider);
    const previous = this.verdictTotals(prevFrom.toISOString(), from.toISOString(), provider);
    const providerClause = provider ? " AND provider = ?" : "";
    const rangeParams: string[] = provider ? [fromIso, toIso, provider] : [fromIso, toIso];

    const dayRows = this.db
      .prepare(
        `SELECT substr(created_at, 1, 10) AS day, verdict, COUNT(*) AS n
         FROM mail_events WHERE created_at >= ? AND created_at < ?${providerClause}
         GROUP BY day, verdict`
      )
      .all(...rangeParams) as unknown as Array<{ day: string; verdict: string; n: number }>;

    const byDay = new Map<string, { s: number; u: number; b: number; e: number }>();
    for (const r of dayRows) {
      const bucket = byDay.get(r.day) || { s: 0, u: 0, b: 0, e: 0 };
      if (r.verdict === "SAFE") bucket.s += Number(r.n);
      else if (r.verdict === "UNVERIFIED") bucket.u += Number(r.n);
      else if (r.verdict === "BLOCKED") bucket.b += Number(r.n);
      else bucket.e += Number(r.n);
      byDay.set(r.day, bucket);
    }
    const perDay: MailStats["perDay"] = [];
    const startDay = Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate());
    for (let i = 0; i <= span; i++) {
      const key = new Date(startDay + i * dayMs).toISOString().slice(0, 10);
      const b = byDay.get(key) || { s: 0, u: 0, b: 0, e: 0 };
      perDay.push({ date: key, safe: b.s, unverified: b.u, blocked: b.b, error: b.e });
    }

    const actionRows = this.db
      .prepare(
        `SELECT action, COUNT(*) AS n FROM mail_events
         WHERE created_at >= ? AND created_at < ?${providerClause}
         GROUP BY action ORDER BY n DESC`
      )
      .all(...rangeParams) as unknown as Array<{ action: string; n: number }>;

    const senderRows = this.db
      .prepare(
        `SELECT sender_domain AS domain,
           SUM(CASE WHEN verdict = 'UNVERIFIED' THEN 1 ELSE 0 END) AS needs_review,
           SUM(CASE WHEN verdict = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked
         FROM mail_events
         WHERE created_at >= ? AND created_at < ?${providerClause} AND sender_domain IS NOT NULL
           AND verdict IN ('UNVERIFIED', 'BLOCKED')
         GROUP BY sender_domain
         ORDER BY (SUM(CASE WHEN verdict = 'UNVERIFIED' THEN 1 ELSE 0 END)
                 + SUM(CASE WHEN verdict = 'BLOCKED' THEN 1 ELSE 0 END)) DESC, sender_domain ASC
         LIMIT 6`
      )
      .all(...rangeParams) as unknown as Array<{ domain: string; needs_review: number; blocked: number }>;

    const accountRows = this.db
      .prepare(
        `SELECT substr(account_hash, 1, 6) AS prefix, COUNT(*) AS n
         FROM mail_events GROUP BY prefix ORDER BY n DESC LIMIT 50`
      )
      .all() as unknown as Array<{ prefix: string; n: number }>;

    return {
      days: span,
      from: fromIso,
      to: toIso,
      totals,
      previous,
      perDay,
      actions: actionRows.map((r) => ({ action: r.action, count: Number(r.n) })),
      topSenders: senderRows.map((r) => ({
        domain: r.domain,
        needsReview: Number(r.needs_review || 0),
        blocked: Number(r.blocked || 0),
      })),
      accounts: accountRows.map((r) => ({ prefix: r.prefix, count: Number(r.n) })),
    };
  }

  /** Latest non-safe events (any time), newest first. */
  mailLatestAlerts(limit = 5): MailEvent[] {
    const rows = this.db
      .prepare("SELECT * FROM mail_events WHERE verdict <> 'SAFE' ORDER BY id DESC LIMIT ?")
      .all(Math.min(Math.max(limit, 1), 50)) as unknown as MailRow[];
    return rows.map(mapMailEvent);
  }

  // ---- settings ----------------------------------------------------------

  getSetting(key: string, fallback: string): string {
    const row = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as
      | { value: string }
      | undefined;
    return row ? row.value : fallback;
  }

  setSetting(key: string, value: string): void {
    this.db
      .prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(key, value);
  }
}