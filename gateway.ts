import express, { type Router, type Request, type Response, type NextFunction } from "express";
import crypto from "node:crypto";
import {
  GatewayDb,
  type GatewayStatus,
  type MailAction,
  type MailEvent,
  type MailEventFilter,
  type MailProvider,
  type MailVerdict,
} from "./gateway-db";
// Type-only import — erased at build time, so there is no runtime import cycle
// between gateway.ts and server.ts (server.ts injects the engine instead).
import type { InspectDeps } from "./server";
// Admin-only UI (scoped CSS + client script). See admin-ui.ts.
import { renderAdminApp, ADMIN_APP_JS, type AdminTab } from "./admin-ui";

/**
 * Link-protection gateway built on top of the existing heuristic URL inspector.
 *
 * Routes:
 *   POST /api/inspect                      — ingest up to 20 URLs (Bearer auth + rate limit)
 *   GET  /api/message/:message_ref/verdict — poll the aggregated verdict for a message
 *   GET  /go/:id                           — PENDING page / SAFE redirect / UNVERIFIED page / BLOCKED page
 *   GET  /admin (+ action endpoints)       — password-protected review + overrides
 */

/* ---------------------------------------------------------------------------
 * Mail-activity helpers (validation, account hashing)
 * ------------------------------------------------------------------------- */

const MAIL_LIMITS = {
  messageRef: 128,
  mailbox: 320,
  senderDomain: 253,
  senderDisplay: 200,
  subject: 200,
  linkCount: 1000,
} as const;

const MAIL_PROVIDERS: MailProvider[] = ["gmail", "outlook"];
const MAIL_VERDICTS: MailVerdict[] = ["SAFE", "UNVERIFIED", "BLOCKED", "ERROR"];
const MAIL_ACTIONS: MailAction[] = ["none", "labeled", "moved_to_spam", "protected_copy", "restored"];

// Initial value for the "Store subjects" setting (overridable from /admin/mail).
const DEFAULT_STORE_SUBJECTS = process.env.STORE_SUBJECTS === "0" ? "0" : "1";

// Exactly these fields are accepted; anything else is rejected. In particular
// there is no field for an email body/snippet, so bodies can never be stored.
const MAIL_ALLOWED_FIELDS = new Set([
  "provider",
  "message_ref",
  "mailbox",
  "sender_domain",
  "sender_display",
  "subject",
  "verdict",
  "action",
  "link_count",
]);

/** SHA-256 of the lower-cased mailbox plus a server-side salt. */
function hashMailbox(mailbox: string, salt: string): string {
  return crypto.createHash("sha256").update(`${mailbox.toLowerCase()}:${salt}`).digest("hex");
}

/** Best-effort domain from a display string like "Acme <billing@acme.top>". */
function deriveSenderDomain(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const at = value.lastIndexOf("@");
  if (at < 0) return null;
  const domain = value
    .slice(at + 1)
    .replace(/[>\s].*$/, "")
    .trim()
    .toLowerCase();
  return domain || null;
}

/** Normalise a date/date-time query value into an ISO bound. */
function toIsoBound(value: string | undefined, edge: "start" | "end"): string | undefined {
  if (!value) return undefined;
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return `${value}T${edge === "start" ? "00:00:00.000" : "23:59:59.999"}Z`;
  }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

interface ValidatedMailEvent {
  mailbox: string;
  provider: MailProvider;
  messageRef: string;
  senderDomain: string | null;
  senderDisplay: string | null;
  subject: string | null;
  verdict: MailVerdict;
  action: MailAction;
  linkCount: number;
}

function validateMailPayload(
  body: any,
  opts: { storeSubjects: boolean }
): { ok: true; value: ValidatedMailEvent } | { ok: false; error: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: "body must be a JSON object" };
  }

  const unknown = Object.keys(body).filter((k) => !MAIL_ALLOWED_FIELDS.has(k));
  if (unknown.length) {
    return { ok: false, error: `unknown field(s): ${unknown.join(", ")}` };
  }

  if (!MAIL_PROVIDERS.includes(body.provider)) {
    return { ok: false, error: "provider must be gmail or outlook" };
  }

  if (typeof body.message_ref !== "string" || !body.message_ref.trim()) {
    return { ok: false, error: "message_ref is required" };
  }
  if (body.message_ref.length > MAIL_LIMITS.messageRef) {
    return { ok: false, error: `message_ref must be at most ${MAIL_LIMITS.messageRef} characters` };
  }

  if (typeof body.mailbox !== "string" || !body.mailbox.includes("@")) {
    return { ok: false, error: "mailbox must be an email address" };
  }
  if (body.mailbox.length > MAIL_LIMITS.mailbox) {
    return { ok: false, error: `mailbox must be at most ${MAIL_LIMITS.mailbox} characters` };
  }

  if (!MAIL_VERDICTS.includes(body.verdict)) {
    return { ok: false, error: "verdict must be SAFE, UNVERIFIED, BLOCKED or ERROR" };
  }

  const action = body.action === undefined ? "none" : body.action;
  if (!MAIL_ACTIONS.includes(action)) {
    return { ok: false, error: `action must be one of ${MAIL_ACTIONS.join(", ")}` };
  }

  let linkCount = 0;
  if (body.link_count !== undefined) {
    if (!Number.isInteger(body.link_count) || body.link_count < 0 || body.link_count > MAIL_LIMITS.linkCount) {
      return { ok: false, error: `link_count must be an integer between 0 and ${MAIL_LIMITS.linkCount}` };
    }
    linkCount = body.link_count;
  }

  if (body.sender_domain !== undefined && (typeof body.sender_domain !== "string" || body.sender_domain.length > MAIL_LIMITS.senderDomain)) {
    return { ok: false, error: `sender_domain must be at most ${MAIL_LIMITS.senderDomain} characters` };
  }
  if (body.sender_display !== undefined && (typeof body.sender_display !== "string" || body.sender_display.length > MAIL_LIMITS.senderDisplay)) {
    return { ok: false, error: `sender_display must be at most ${MAIL_LIMITS.senderDisplay} characters` };
  }
  if (body.subject !== undefined && (typeof body.subject !== "string" || body.subject.length > MAIL_LIMITS.subject)) {
    return { ok: false, error: `subject must be at most ${MAIL_LIMITS.subject} characters` };
  }

  // The sender domain is always kept; display/subject only when allowed.
  const derivedDomain = deriveSenderDomain(body.sender_display);
  const senderDomain = (typeof body.sender_domain === "string" && body.sender_domain.trim()
    ? body.sender_domain.trim().toLowerCase()
    : derivedDomain) || null;
  const senderDisplay =
    opts.storeSubjects && typeof body.sender_display === "string" && body.sender_display.trim()
      ? body.sender_display.trim()
      : null;
  const subject =
    opts.storeSubjects && typeof body.subject === "string" && body.subject.trim()
      ? body.subject.trim()
      : null;

  return {
    ok: true,
    value: {
      mailbox: body.mailbox.trim(),
      provider: body.provider,
      messageRef: body.message_ref.trim(),
      senderDomain,
      senderDisplay,
      subject,
      verdict: body.verdict,
      action,
      linkCount,
    } as ValidatedMailEvent,
  };
}

function publicMailEvent(e: MailEvent) {
  return {
    id: e.id,
    provider: e.provider,
    messageRef: e.messageRef,
    senderDomain: e.senderDomain,
    senderDisplay: e.senderDisplay,
    subject: e.subject,
    verdict: e.verdict,
    action: e.action,
    linkCount: e.linkCount,
    isRead: e.isRead,
    createdAt: e.createdAt,
    updatedAt: e.updatedAt,
  };
}

export interface ParsedUrlShape {
  input: string;
  cleanUrl: string;
  scheme: string;
  hostname: string;
  port: string | null;
  username: string;
  hasAuth: boolean;
  isIpAddress: boolean;
  registrableDomain: string;
  subdomainLabels: string[];
  pathname: string;
  search: string;
  hash: string;
}

export interface GatewayEngine {
  parseUrl(raw: string): ParsedUrlShape;
  getRegistrableDomain(hostname: string): string;
  inspectUrl(raw: string, deps?: InspectDeps, opts?: { debug?: boolean }): Promise<Record<string, any>>;
  createDefaultInspectDeps?: () => InspectDeps;
}

export interface GatewayOptions {
  engine: GatewayEngine;
  /** Shared DB instance (tests). When omitted, a singleton at DB_PATH is used. */
  db?: GatewayDb;
  /** Reusable inspection deps (tests use fakes). When omitted, default deps are created per run. */
  deps?: InspectDeps;
  /** Hard timeout per URL inspection (ms). Default 20_000. */
  inspectTimeoutMs?: number;
  /** Link expiry window (ms). Default 30 days. */
  expireAfterMs?: number;
  /** Set false to disable rate limiting (tests). */
  rateLimit?: false | { inspectPerMinute?: number; verdictPerMinute?: number };
  now?: () => Date;
  log?: (msg: string) => void;
}

const MAX_URLS = 20;
const DEFAULT_EXPIRE_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_INSPECT_TIMEOUT_MS = 20_000;
const HEAL_AFTER_MS = 15_000; // re-enqueue PENDING links older than this on access

/* ---------------------------------------------------------------------------
 * In-memory rate limiting (fixed one-minute window per IP)
 * ------------------------------------------------------------------------- */

interface RateEntry {
  count: number;
  resetAt: number;
}

function makeRateLimiter(perMinute: number, log: (m: string) => void) {
  const hits = new Map<string, RateEntry>();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of hits) {
      if (entry.resetAt <= now) hits.delete(ip);
    }
  }, 60_000);
  timer.unref?.();

  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    let entry = hits.get(ip);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + 60_000 };
      hits.set(ip, entry);
    }
    entry.count += 1;
    if (entry.count > perMinute) {
      log(`rate limit hit for ${ip}`);
      res.set("Retry-After", String(Math.max(1, Math.ceil((entry.resetAt - now) / 1000))));
      res.status(429).json({ error: "rate limit exceeded, try again shortly" });
      return;
    }
    next();
  };
}

/* ---------------------------------------------------------------------------
 * Auth helpers
 * ------------------------------------------------------------------------- */

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function requireInspectorKey(req: Request, res: Response, next: NextFunction): void {
  const key = process.env.INSPECTOR_KEY;
  if (!key) {
    console.error("[gateway] INSPECTOR_KEY is not set — refusing to serve /api/inspect");
    res.status(503).json({ error: "inspector not configured on the server" });
    return;
  }
  const auth = req.headers.authorization || "";
  const match = /^Bearer\s+(.+)$/i.exec(auth);
  if (!match || !safeEqual(match[1], key)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

/** The optional, limited Outlook add-in key. Unset/empty ⇒ add-in access disabled. */
function outlookAddinKey(): string | null {
  const key = process.env.OUTLOOK_ADDIN_KEY;
  return key && key.length > 0 ? key : null;
}

/** The optional, limited Gmail add-on key. Unset/empty ⇒ add-on access disabled. */
function gmailAddinKey(): string | null {
  const key = process.env.GMAIL_ADDIN_KEY;
  return key && key.length > 0 ? key : null;
}

/**
 * Accepts the full INSPECTOR_KEY or either limited add-in key
 * (OUTLOOK_ADDIN_KEY / GMAIL_ADDIN_KEY) as a Bearer token, all compared in
 * constant time. `res.locals.addinProvider` is set to "outlook" or "gmail"
 * when the matching add-in key was used, so /api/events can force that
 * provider regardless of what the request body claims. Unset ⇒ that add-in
 * has no ingest access; if neither add-in key nor INSPECTOR_KEY is set, the
 * route is disabled entirely.
 */
function requireIngestKey(req: Request, res: Response, next: NextFunction): void {
  const inspector = process.env.INSPECTOR_KEY;
  const outlookKey = outlookAddinKey();
  const gmailKey = gmailAddinKey();
  if (!inspector && !outlookKey && !gmailKey) {
    console.error("[gateway] none of INSPECTOR_KEY, OUTLOOK_ADDIN_KEY, GMAIL_ADDIN_KEY is set — refusing to serve /api/inspect");
    res.status(503).json({ error: "inspector not configured on the server" });
    return;
  }
  const auth = req.headers.authorization || "";
  const match = /^Bearer\s+(.+)$/i.exec(auth);
  if (!match) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  const token = match[1];
  if (inspector && safeEqual(token, inspector)) {
    res.locals.addinProvider = undefined;
    next();
    return;
  }
  if (outlookKey && safeEqual(token, outlookKey)) {
    res.locals.addinProvider = "outlook";
    next();
    return;
  }
  if (gmailKey && safeEqual(token, gmailKey)) {
    res.locals.addinProvider = "gmail";
    next();
    return;
  }
  res.status(401).json({ error: "unauthorized" });
}

/**
 * Role resolution for the admin area.
 *
 * The ADMIN_PASSWORD Basic login keeps working exactly as before and yields the
 * "admin" role. An optional read-only "viewer" login is enabled only when
 * VIEWER_PASSWORD is set, non-empty, and different from the admin password.
 * Passwords are always compared in constant time.
 */
function viewerPassword(): string | null {
  const viewer = process.env.VIEWER_PASSWORD;
  const admin = process.env.ADMIN_PASSWORD;
  if (!viewer || viewer.length === 0) return null;
  if (admin && viewer === admin) return null;
  return viewer;
}

function authConfigured(): boolean {
  return Boolean(process.env.ADMIN_PASSWORD) || Boolean(viewerPassword());
}

function resolveRole(req: Request): "admin" | "viewer" | null {
  const admin = process.env.ADMIN_PASSWORD;
  const viewer = viewerPassword();
  if (!admin && !viewer) return null;
  const auth = req.headers.authorization || "";
  const match = /^Basic\s+(.+)$/i.exec(auth);
  if (!match) return null;
  const decoded = Buffer.from(match[1], "base64").toString("utf8");
  const sep = decoded.indexOf(":");
  if (sep < 0) return null;
  const pass = decoded.slice(sep + 1);
  if (admin && safeEqual(pass, admin)) return "admin";
  if (viewer && safeEqual(pass, viewer)) return "viewer";
  return null;
}

/** Middleware factory: `any` accepts admin or viewer; `admin` rejects viewers with 403. */
function requireAuth(level: "any" | "admin") {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!authConfigured()) {
      console.error("[gateway] neither ADMIN_PASSWORD nor VIEWER_PASSWORD is set — refusing to serve /admin");
      res.status(503).send("Admin panel is not configured. Set ADMIN_PASSWORD on the server and restart.");
      return;
    }
    const role = resolveRole(req);
    if (!role) {
      challengeAdmin(res);
      return;
    }
    if (level === "admin" && role !== "admin") {
      res.status(403).type("text/plain").send("Viewers cannot perform this action.");
      return;
    }
    res.locals.role = role;
    next();
  };
}

const requireAdmin = requireAuth("admin");
const requireAny = requireAuth("any");

function challengeAdmin(res: Response): void {
  res.set("WWW-Authenticate", 'Basic realm="Online Safety Guard Admin"');
  res.status(401).send("Authentication required");
}

/* ---------------------------------------------------------------------------
 * Inspection queue (in-process, sequential)
 * ------------------------------------------------------------------------- */

interface QueueItem {
  id: string;
  enqueuedAt: number;
}

function makeQueue(work: (id: string) => Promise<void>, log: (m: string) => void) {
  const items: QueueItem[] = [];
  let draining = false;

  function enqueue(id: string): void {
    items.push({ id, enqueuedAt: Date.now() });
    if (!draining) {
      draining = true;
      void drain();
    }
  }

  async function drain(): Promise<void> {
    while (items.length) {
      const item = items.shift()!;
      try {
        await work(item.id);
      } catch (err) {
        log(`inspection failed for ${item.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    draining = false;
  }

  return { enqueue };
}

/* ---------------------------------------------------------------------------
 * Timeout helper
 * ------------------------------------------------------------------------- */

class GatewayTimeoutError extends Error {
  constructor() {
    super("inspection timed out");
    this.name = "GatewayTimeoutError";
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new GatewayTimeoutError()), ms);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

/* ---------------------------------------------------------------------------
 * Router factory
 * ------------------------------------------------------------------------- */

let sharedDb: GatewayDb | null = null;

function defaultDb(): GatewayDb {
  if (!sharedDb) {
    sharedDb = new GatewayDb(process.env.DB_PATH || "data/gateway.db");
  }
  return sharedDb;
}

interface CheckSnapshot {
  id: string;
  label: string;
  status: string;
  detail: string | null;
}

interface FindingSnapshot {
  severity: string;
  title: string;
  explanation: string;
}

export function createGatewayRouter(options: GatewayOptions): Router {
  const db = options.db ?? defaultDb();
  const engine = options.engine;
  const timeoutMs = options.inspectTimeoutMs ?? DEFAULT_INSPECT_TIMEOUT_MS;
  const expireAfterMs = options.expireAfterMs ?? DEFAULT_EXPIRE_MS;
  const nowFn = options.now ?? (() => new Date());
  const log = options.log ?? ((msg: string) => console.error(`[gateway] ${msg}`));
  const rateLimit = options.rateLimit ?? { inspectPerMinute: 20, verdictPerMinute: 60 };

  const router = express.Router();
  router.use(express.json({ limit: "1mb" }));
  router.use(express.urlencoded({ extended: false }));

  const inspectLimiter = rateLimit === false
    ? ((_req: Request, _res: Response, next: NextFunction) => next())
    : makeRateLimiter(rateLimit.inspectPerMinute ?? 20, log);
  const verdictLimiter = rateLimit === false
    ? ((_req: Request, _res: Response, next: NextFunction) => next())
    : makeRateLimiter(rateLimit.verdictPerMinute ?? 60, log);

  /* ---------------- mail-activity retention ---------------- */

  const retentionDays = Number(process.env.EVENT_RETENTION_DAYS) || 30;

  function runRetention(): void {
    try {
      const cutoff = new Date(nowFn().getTime() - retentionDays * 86_400_000).toISOString();
      const removed = db.deleteOldMailEvents(cutoff);
      if (removed) log(`mail retention: removed ${removed} event(s) older than ${retentionDays} days`);
    } catch (err) {
      log(`mail retention failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  runRetention();
  const retentionTimer = setInterval(runRetention, 86_400_000);
  retentionTimer.unref?.();

  /* ---------------- inspection orchestration ---------------- */

  async function buildInspectionSnapshot(
    url: string,
    result: Record<string, any> | null,
    overrides?: { status: GatewayStatus; reason: string; findings?: FindingSnapshot[] },
    extra?: Record<string, unknown>
  ): Promise<{ status: GatewayStatus; findings: Record<string, unknown> }> {
    const rawResult = result ?? null;
    const checks: CheckSnapshot[] = Array.isArray(rawResult?.checks)
      ? (rawResult as any).checks.map((c: any) => ({
          id: c.id ?? "",
          label: c.label ?? "Check",
          status: c.status ?? "error",
          detail: c.detail ?? null,
        }))
      : [];
    const findings: FindingSnapshot[] = Array.isArray(rawResult?.findings)
      ? (rawResult as any).findings.slice(0, 12)
      : [];
    const anySkippedOrError = checks.some((c) => c.status === "skipped" || c.status === "error");
    const verdict: string = rawResult?.verdict ?? "UNVERIFIED";

    let status: GatewayStatus;
    let reason: string;
    if (overrides) {
      status = overrides.status;
      reason = overrides.reason;
      if (overrides.findings?.length) findings.unshift(...overrides.findings);
    } else {
      const highRisk = verdict === "HIGH_RISK" || verdict === "MALICIOUS";
      const lowRisk = verdict === "LOW_RISK" || verdict === "LOW_THREAT";
      if (highRisk) {
        status = "BLOCKED";
        reason = String(rawResult?.verdictReason || rawResult?.reason || "Confirmed high-risk indicators.");
      } else if (lowRisk && !anySkippedOrError) {
        status = "SAFE";
        reason = String(rawResult?.verdictReason || "All checks completed and no threats were detected.");
      } else {
        // SUSPICIOUS / VERIFICATION_REQUIRED, or any skipped/errored/timed-out check
        status = "UNVERIFIED";
        reason = String(rawResult?.verdictReason || rawResult?.reason || "Verification could not confirm safety.");
      }
    }

    const snapshot: Record<string, unknown> = {
      verdict,
      reason,
      checks,
      findings,
      redirects: rawResult?.redirects
        ? {
            status: (rawResult as any).redirects.status ?? null,
            finalUrl: (rawResult as any).redirects.finalUrl ?? null,
            note: (rawResult as any).redirects.note ?? null,
            hops: Array.isArray((rawResult as any).redirects.hops)
              ? (rawResult as any).redirects.hops.slice(0, 10)
              : [],
          }
        : null,
      reputation: rawResult?.reputation
        ? { status: (rawResult as any).reputation.status ?? null, source: (rawResult as any).reputation.source ?? null }
        : null,
      engine: (rawResult as any)?.engine ?? null,
      ...extra,
    };
    return { status, findings: snapshot };
  }

  async function inspectLink(id: string): Promise<void> {
    const link = db.getLink(id);
    if (!link || link.status !== "PENDING") return;

    const parsed = engine.parseUrl(link.url);
    const hostname = parsed.hostname.toLowerCase();
    const registrableDomain =
      (parsed.registrableDomain || "").toLowerCase() || engine.getRegistrableDomain(hostname);

    // 1) Blocklist short-circuit → BLOCKED immediately.
    const blockMatch = db.isUrlBlocklisted(link.url, hostname, registrableDomain);
    if (blockMatch) {
      const { status, findings } = await buildInspectionSnapshot(link.url, null, {
        status: "BLOCKED",
        reason: `Matched the ${blockMatch.type} blocklist entry "${blockMatch.value}".`,
        findings: [
          {
            severity: "critical",
            title: "Blocklisted destination",
            explanation: `This ${blockMatch.type} is on the blocklist.${blockMatch.reason ? ` Reason: ${blockMatch.reason}` : ""}`,
          },
        ],
      });
      db.updateInspection(id, {
        status,
        findings,
        inspectedAt: nowFn().toISOString(),
      });
      return;
    }

    // 2) Allowlist short-circuit → SAFE immediately.
    if (db.isAllowlisted(hostname, registrableDomain)) {
      const { status, findings } = await buildInspectionSnapshot(link.url, null, {
        status: "SAFE",
        reason: "Domain is on the allowlist.",
        findings: [
          { severity: "info", title: "Allowlisted domain", explanation: "This domain is trusted and bypasses inspection." },
        ],
      });
      db.updateInspection(id, {
        status,
        findings,
        inspectedAt: nowFn().toISOString(),
      });
      return;
    }

    // 3) Run the existing heuristic engine (capped timeout).
    const deps = options.deps ?? (engine.createDefaultInspectDeps ? engine.createDefaultInspectDeps() : undefined);
    let result: Record<string, any> | null = null;
    try {
      result = await withTimeout(Promise.resolve(engine.inspectUrl(link.url, deps)), timeoutMs);
    } catch (err) {
      log(`inspection of ${id} (${link.url}) did not complete: ${err instanceof Error ? err.message : String(err)}`);
    }

    const { status, findings } = await buildInspectionSnapshot(link.url, result, result
      ? undefined
      : {
          status: "UNVERIFIED",
          reason: "Inspection could not complete within the timeout.",
          findings: [
            { severity: "warning", title: "Inspection incomplete", explanation: "The scan timed out; this link was not confirmed safe." },
          ],
        });

    db.updateInspection(id, {
      status,
      findings,
      inspectedAt: nowFn().toISOString(),
    });

    // 4) When a scan result becomes BLOCKED, persist the domain to the blocklist
    //    so future links to it short-circuit immediately.
    if (status === "BLOCKED" && registrableDomain) {
      const blockReason = String(
        (findings as any).reason || "Blocked by automated inspection"
      ).slice(0, 400);
      db.addBlocklist("domain", registrableDomain, blockReason, nowFn().toISOString());
      log(`added ${registrableDomain} to blocklist (${blockReason})`);
    }
  }

  const queue = makeQueue(inspectLink, log);

  function enqueueIfPending(link: { id: string; status: GatewayStatus; createdAt: string }): void {
    if (link.status !== "PENDING") return;
    const age = nowFn().getTime() - new Date(link.createdAt).getTime();
    // Re-enqueue stale PENDING rows too (e.g. after a server restart).
    if (age > HEAL_AFTER_MS) queue.enqueue(link.id);
  }

  function gatewayUrlFor(req: Request, id: string): string {
    const base = (
      process.env.GATEWAY_URL ||
      process.env.RENDER_EXTERNAL_URL ||
      `${req.protocol}://${req.get("host")}`
    ).replace(/\/+$/, "");
    return `${base}/go/${id}`;
  }

  function aggregateVerdict(statuses: GatewayStatus[]): GatewayStatus {
    if (statuses.includes("BLOCKED")) return "BLOCKED";
    if (statuses.includes("PENDING")) return "PENDING";
    if (statuses.includes("UNVERIFIED")) return "UNVERIFIED";
    return "SAFE";
  }

  /* ---------------- API: ingest ---------------- */

  router.post("/api/inspect", requireIngestKey, inspectLimiter, (req, res) => {
    const body = (req.body ?? {}) as { message_ref?: unknown; urls?: unknown };
    const messageRef = typeof body.message_ref === "string" ? body.message_ref.trim() : "";
    const urlsRaw = Array.isArray(body.urls) ? body.urls : [];

    if (!messageRef) {
      res.status(400).json({ error: "message_ref (string) is required" });
      return;
    }
    if (urlsRaw.length === 0) {
      res.status(400).json({ error: "urls must be a non-empty array of strings" });
      return;
    }
    if (urlsRaw.length > MAX_URLS) {
      res.status(400).json({ error: `at most ${MAX_URLS} urls per request` });
      return;
    }
    if (urlsRaw.some((u) => typeof u !== "string")) {
      res.status(400).json({ error: "urls must contain only strings" });
      return;
    }

    const now = nowFn();
    const expiresAt = new Date(now.getTime() + expireAfterMs).toISOString();
    const seen = new Set<string>();
    const links: Array<{ url: string; id: string; gateway_url: string; status: GatewayStatus }> = [];

    for (const raw of urlsRaw as string[]) {
      const input = raw.trim();
      if (!input) continue;

      const parsed = engine.parseUrl(input);
      const normalized = parsed.cleanUrl || input;
      const dedupeKey = normalized.toLowerCase();
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      const id = crypto.randomBytes(16).toString("base64url");
      let status: GatewayStatus = "PENDING";
      let findings: Record<string, unknown> | null = null;

      if (parsed.scheme && !["http", "https"].includes(parsed.scheme)) {
        // Non-web schemes are never followed.
        status = "BLOCKED";
        findings = {
          verdict: "BLOCKED",
          reason: `Non-web scheme "${parsed.scheme}:" is blocked.`,
          checks: [],
          findings: [
            {
              severity: "critical",
              title: "Unsafe URL scheme",
              explanation: `Links using ${parsed.scheme}: are never followed by the gateway.`,
            },
          ],
          engine: "gateway",
        };
      } else if (!parsed.hostname) {
        status = "UNVERIFIED";
        findings = {
          verdict: "UNVERIFIED",
          reason: "The URL could not be parsed into a valid web address.",
          checks: [],
          findings: [
            {
              severity: "warning",
              title: "Unparseable URL",
              explanation: "The URL could not be parsed into a valid web address.",
            },
          ],
          engine: "gateway",
        };
      }

      db.createLink({
        id,
        url: normalized,
        messageRef,
        status,
        findings,
        createdAt: now.toISOString(),
        inspectedAt: status === "PENDING" ? null : now.toISOString(),
        expiresAt,
      });

      if (status === "PENDING") {
        queue.enqueue(id);
      } else {
        // Auto-block registered domains for instantly-blocked links (scheme attacks
        // have no meaningful domain, so only attempt when one parses).
        if (status === "BLOCKED" && parsed.hostname && parsed.registrableDomain) {
          db.addBlocklist("domain", parsed.registrableDomain.toLowerCase(), "Blocked: unsafe URL scheme", now.toISOString());
        }
      }

      links.push({
        url: normalized,
        id,
        gateway_url: gatewayUrlFor(req, id),
        status,
      });
    }

    if (links.length === 0) {
      res.status(400).json({ error: "no valid URLs provided" });
      return;
    }

    const verdict = aggregateVerdict(links.map((l) => l.status));
    res.json({ links, verdict });
  });

  /* ---------------- API: poll verdict ---------------- */

  // Admin-only debug view for the URL inspector. Lists per check: status,
  // duration and the real reason (env var names, HTTP 429, timeout, ...). This
  // is the ONLY place raw configuration/errors are exposed.
  router.get("/api/inspect", requireAdmin, async (req, res) => {
    const url = String((req.query as any)?.url || "");
    if (!url) {
      res.status(400).json({ error: "url is required" });
      return;
    }
    try {
      const result = await engine.inspectUrl(url, undefined, { debug: true });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "inspection failed" });
    }
  });

  router.get("/api/message/:messageRef/verdict", verdictLimiter, (req, res) => {
    const messageRef = req.params.messageRef || "";
    const rows = db.listByMessage(messageRef);
    if (rows.length === 0) {
      res.status(404).json({ error: "unknown message_ref" });
      return;
    }
    for (const row of rows) enqueueIfPending(row);

    const verdict = aggregateVerdict(rows.map((r) => r.status));
    res.json({
      message_ref: messageRef,
      verdict,
      links: rows.map((r) => ({
        url: r.url,
        id: r.id,
        status: r.status,
        findings: r.findings,
        gateway_url: gatewayUrlFor(req, r.id),
        created_at: r.createdAt,
        inspected_at: r.inspectedAt,
        expires_at: r.expiresAt,
      })),
    });
  });

  /* ---------------- go/:id pages ---------------- */

  router.get("/go/:id", (req, res) => {
    const id = req.params.id || "";
    const link = db.getLink(id);
    setNoindexHeaders(res);

    if (!link) return send404(res);
    if (new Date(link.expiresAt).getTime() < nowFn().getTime()) return send404(res);

    switch (link.status) {
      case "PENDING": {
        enqueueIfPending(link);
        return sendHtml(res, renderPendingPage());
      }
      case "SAFE": {
        return res.redirect(302, link.url);
      }
      case "UNVERIFIED": {
        return sendHtml(res, renderUnverifiedPage(link.url, link.findings));
      }
      case "BLOCKED":
      default: {
        return sendHtml(res, renderBlockedPage(link.url, link.findings));
      }
    }
  });

  /* ---------------- admin ---------------- */

  router.get("/admin", requireAdmin, (_req, res) => {
    setAdminSecurityHeaders(res);
    sendHtml(res, renderAdminPage(db, nowFn()));
  });

  router.post("/admin/links/:id/override", requireAdmin, (req, res) => {
    const status = String((req.body as any)?.status || "");
    const allowed: GatewayStatus[] = ["SAFE", "BLOCKED", "UNVERIFIED"];
    if (!allowed.includes(status as GatewayStatus)) {
      res.status(400).send(`status must be one of ${allowed.join(", ")}`);
      return;
    }
    const ok = db.overrideStatus(req.params.id, status as GatewayStatus);
    if (!ok) {
      res.status(404).send("link not found");
      return;
    }
    log(`admin overrode ${req.params.id} → ${status}`);
    const nextPath = String((req.body as any)?.next || "");
    res.redirect(302, nextPath.startsWith("/admin") ? nextPath : "/admin");
  });

  router.post("/admin/blocklist", requireAdmin, (req, res) => {
    const type = String((req.body as any)?.type || "") === "url" ? "url" : "domain";
    const value = String((req.body as any)?.value || "").trim();
    const reason = String((req.body as any)?.reason || "").trim() || null;
    if (!value) {
      res.status(400).send("value is required");
      return;
    }
    const stored =
      type === "url" ? (engine.parseUrl(value).cleanUrl || value.trim()) : value.trim();
    db.addBlocklist(type, stored, reason, nowFn().toISOString());
    log(`admin added blocklist ${type}: ${stored}`);
    res.redirect(302, "/admin");
  });

  router.post("/admin/blocklist/:id/delete", requireAdmin, (req, res) => {
    db.deleteBlocklistById(Number(req.params.id));
    res.redirect(302, "/admin");
  });

  router.post("/admin/allowlist", requireAdmin, (req, res) => {
    const domain = String((req.body as any)?.domain || "")
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0];
    if (!domain) {
      res.status(400).send("domain is required");
      return;
    }
    db.addAllowlist(domain, nowFn().toISOString());
    log(`admin added allowlist: ${domain}`);
    res.redirect(302, "/admin");
  });

  router.post("/admin/allowlist/:id/delete", requireAdmin, (req, res) => {
    db.deleteAllowlistById(Number(req.params.id));
    res.redirect(302, "/admin");
  });

  /* ---------------- mail activity API ---------------- */

  router.post("/api/events", requireIngestKey, inspectLimiter, (req, res) => {
    const storeSubjects = db.getSetting("store_subjects", DEFAULT_STORE_SUBJECTS) === "1";
    const parsed = validateMailPayload(req.body, { storeSubjects });
    if ("error" in parsed) {
      res.status(400).json({ error: parsed.error });
      return;
    }
    const salt = process.env.EVENT_SALT || "";
    if (!salt) log("EVENT_SALT is not set — mail account hashes are unsalted");
    const nowIso = nowFn().toISOString();
    const v = parsed.value;
    // A limited add-in/add-on key may only ever report its own provider.
    const provider = res.locals.addinProvider ?? v.provider;
    const id = db.upsertMailEvent({
      provider,
      accountHash: hashMailbox(v.mailbox, salt),
      messageRef: v.messageRef,
      senderDomain: v.senderDomain,
      senderDisplay: v.senderDisplay,
      subject: v.subject,
      verdict: v.verdict,
      action: v.action,
      linkCount: v.linkCount,
      createdAt: nowIso,
      updatedAt: nowIso,
    });
    res.json({ ok: true, id });
  });

  router.get("/api/events", requireAny, (req, res) => {
    const role = (res.locals.role as string) || "viewer";
    const q = req.query as Record<string, unknown>;
    const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

    const sinceRaw = str(q.since);
    let since: number | undefined;
    if (sinceRaw !== undefined) {
      since = Number(sinceRaw);
      if (!Number.isInteger(since) || since < 0) {
        res.status(400).json({ error: "since must be a non-negative integer" });
        return;
      }
    }

    const provider = MAIL_PROVIDERS.includes(str(q.provider) as MailProvider)
      ? (str(q.provider) as MailProvider)
      : undefined;
    const verdict = MAIL_VERDICTS.includes(str(q.verdict) as MailVerdict)
      ? (str(q.verdict) as MailVerdict)
      : undefined;
    const from = toIsoBound(str(q.from), "start");
    const to = toIsoBound(str(q.to), "end");
    const search = str(q.q);

    const limitNum = Number(str(q.limit) || 50);
    const limit = Number.isFinite(limitNum) ? Math.min(Math.max(Math.trunc(limitNum), 1), 200) : 50;
    const offsetNum = Number(str(q.offset) || 0);
    const offset = Number.isFinite(offsetNum) ? Math.max(Math.trunc(offsetNum), 0) : 0;

    const events = db.listMailEvents({
      provider,
      verdict,
      from,
      to,
      q: search,
      accountPrefix: role === "admin" ? str(q.account) : undefined,
      since,
      limit,
      offset,
    });
    const total = db.countMailEvents({
      provider,
      verdict,
      from,
      to,
      q: search,
      accountPrefix: role === "admin" ? str(q.account) : undefined,
    });
    res.json({
      events: events.map(publicMailEvent),
      total,
      limit,
      offset,
      unread: db.unreadMailCount(),
      serverTime: nowFn().toISOString(),
    });
  });

  router.post("/api/events/read", requireAdmin, (req, res) => {
    const raw = (req.body as any)?.ids;
    let ids: number[] | undefined;
    if (Array.isArray(raw)) {
      ids = raw.filter((n: unknown) => Number.isInteger(n) && (n as number) > 0).slice(0, 500) as number[];
    }
    const updated = db.markMailEventsRead(ids);
    res.json({ ok: true, updated, unread: db.unreadMailCount() });
  });

  router.delete("/api/events", requireAdmin, (_req, res) => {
    const deleted = db.deleteAllMailEvents();
    log(`admin wiped ${deleted} mail event(s)`);
    res.json({ ok: true, deleted, unread: 0 });
  });

  /* ---------------- admin: mail activity page ---------------- */

  router.get("/admin/mail", requireAny, (req, res) => {
    setAdminSecurityHeaders(res);
    const role = ((res.locals.role as string) || "viewer") as "admin" | "viewer";
    const q = req.query as Record<string, unknown>;
    const str = (v: unknown) => (typeof v === "string" ? v : "");

    // Keep the previous page reachable while the redesign is being verified.
    if (str(q.legacy) === "1") {
      if (role !== "admin") {
        res.status(403).type("text/plain").send("Viewers cannot open the legacy page.");
        return;
      }
      sendHtml(
        res,
        renderMailPage(db, nowFn(), {
          provider: str(q.provider),
          verdict: str(q.verdict),
          from: str(q.from),
          to: str(q.to),
          q: str(q.q),
        })
      );
      return;
    }

    const daysRaw = Number(str(q.days) || 7);
    const days = [7, 14, 30].includes(daysRaw) ? daysRaw : 7;
    const tabRaw = str(q.tab);
    const tab: AdminTab = tabRaw === "activity" || tabRaw === "links" || tabRaw === "settings" ? tabRaw : "overview";
    const offsetRaw = Number(str(q.offset) || 0);
    sendHtml(
      res,
      renderAdminApp({
        db,
        now: nowFn(),
        role,
        previewViewer: role === "admin" && str(q.viewer) === "1",
        tab,
        days,
        filters: {
          provider: str(q.provider),
          verdict: str(q.verdict),
          from: str(q.from),
          to: str(q.to),
          q: str(q.q),
          account: str(q.account),
          offset: Number.isFinite(offsetRaw) && offsetRaw > 0 ? Math.trunc(offsetRaw) : 0,
        },
      })
    );
  });

  // New admin client script (admin-only UI). Contains no secrets; the data it
  // fetches is still gated by the real server-side role.
  router.get("/admin/admin.js", (_req, res) => {
    res
      .type("application/javascript")
      .set("Cache-Control", "no-store")
      .send(ADMIN_APP_JS);
  });

  // Aggregates for the Overview tab (admin + viewer).
  router.get("/api/events/stats", requireAny, (req, res) => {
    const role = (res.locals.role as string) || "viewer";
    const daysRaw = Number((typeof req.query.days === "string" ? req.query.days : "") || 7);
    const days = [7, 14, 30].includes(daysRaw) ? daysRaw : 7;
    const stats = db.mailStats(days, nowFn());
    if (role !== "admin") stats.accounts = []; // mailbox prefixes are admin-only
    res.json({ ...stats, latestAlerts: db.mailLatestAlerts(5).map(publicMailEvent) });
  });

  // External script (CSP blocks inline scripts, so the page loads this instead).
  // It contains no secrets; the data it fetches still requires admin auth.
  router.get("/admin/mail.js", (_req, res) => {
    res
      .type("application/javascript")
      .set("Cache-Control", "no-store")
      .send(MAIL_CLIENT_JS);
  });

  router.post("/admin/mail/settings", requireAdmin, (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const on = (v: unknown) => (v === "on" || v === "1" || v === "true" ? "1" : "0");
    db.setSetting("store_subjects", on(body.store_subjects));
    const popups: string[] = [];
    if (on(body.popup_blocked) === "1") popups.push("BLOCKED");
    if (on(body.popup_unverified) === "1") popups.push("UNVERIFIED");
    db.setSetting("popup_verdicts", popups.join(","));
    log(`admin updated mail settings (store_subjects=${db.getSetting("store_subjects", "1")}, popups=${db.getSetting("popup_verdicts", "") || "none"})`);
    res.redirect(302, "/admin/mail?tab=settings");
  });

  return router;
}

/* ---------------------------------------------------------------------------
 * HTML rendering (matches the app's dark, rounded-card visual style)
 * ------------------------------------------------------------------------- */

function sendHtml(res: Response, html: string): void {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(html);
}

function setNoindexHeaders(res: Response): void {
  res.set("X-Robots-Tag", "noindex, nofollow");
  res.set("Referrer-Policy", "no-referrer");
  res.set("Cache-Control", "no-store");
}

/**
 * Admin pages also get a strict CSP. `script-src 'self'` (no 'unsafe-inline')
 * blocks any injected inline <script> from attacker-controlled data; admin
 * pages therefore load their behaviour from /admin/mail.js.
 */
function setAdminSecurityHeaders(res: Response): void {
  setNoindexHeaders(res);
  res.set(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; " +
      "img-src 'self' data:; connect-src 'self'; form-action 'self'; " +
      "base-uri 'none'; frame-ancestors 'none'"
  );
}

function send404(res: Response): void {
  setNoindexHeaders(res);
  res.status(404);
  sendHtml(
    res,
    pageShell(
      "Link not found",
      `
      <div class="card center">
        <div class="badge badge-neutral">404</div>
        <h1>Link not found or expired</h1>
        <p>This gateway link does not exist or is no longer valid. Ask the sender to generate a fresh link.</p>
      </div>`
    )
  );
}

function pageShell(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} · Online Safety Guard</title>
  <meta name="robots" content="noindex, nofollow" />
  <style>
    :root {
      color-scheme: dark;
      --bg: #020617;
      --card: #0f172a;
      --border: #1e293b;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --sky: #38bdf8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(1200px 600px at 50% -10%, #1e293b 0%, var(--bg) 55%);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 32px;
      max-width: 560px;
      width: 100%;
      box-shadow: 0 20px 50px rgb(0 0 0 / 0.4);
    }
    .center { text-align: center; }
    .badge {
      display: inline-block;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      padding: 4px 12px;
      border-radius: 999px;
      margin-bottom: 16px;
    }
    .badge-rose { background: rgb(244 63 94 / 0.15); color: var(--rose); border: 1px solid rgb(244 63 94 / 0.4); }
    .badge-amber { background: rgb(245 158 11 / 0.15); color: var(--amber); border: 1px solid rgb(245 158 11 / 0.4); }
    .badge-emerald { background: rgb(16 185 129 / 0.15); color: var(--emerald); border: 1px solid rgb(16 185 129 / 0.4); }
    .badge-neutral { background: rgb(148 163 184 / 0.12); color: var(--muted); border: 1px solid var(--border); }
    h1 { font-size: 22px; margin: 0 0 12px; }
    p { color: var(--muted); font-size: 15px; line-height: 1.6; margin: 0 0 16px; }
    .url {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13px;
      word-break: break-all;
      background: #0b1220;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
      margin: 4px 0 16px;
      text-align: left;
      line-height: 1.5;
    }
    .findings { text-align: left; margin-top: 8px; }
    .finding {
      display: flex;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 10px;
      background: #0b1220;
      border: 1px solid var(--border);
      margin-bottom: 8px;
      font-size: 13px;
    }
    .finding .dot { flex: 0 0 auto; margin-top: 3px; width: 8px; height: 8px; border-radius: 999px; }
    .finding .t { font-weight: 600; margin-bottom: 2px; }
    .finding .x { color: var(--muted); font-size: 12.5px; line-height: 1.45; }
    .dot-critical { background: var(--rose); }
    .dot-warning { background: var(--amber); }
    .dot-info { background: var(--sky); }
    .btn {
      display: inline-block;
      font-weight: 700;
      font-size: 14px;
      padding: 12px 22px;
      border-radius: 12px;
      border: 1px solid transparent;
      cursor: pointer;
      text-decoration: none;
      color: #fff;
      background: var(--emerald);
    }
    .btn-rose { background: var(--rose); }
    .btn-ghost {
      background: transparent;
      border-color: var(--border);
      color: var(--muted);
      margin-left: 8px;
    }
    .spinner {
      width: 34px;
      height: 34px;
      border: 4px solid rgb(245 158 11 / 0.25);
      border-top-color: var(--amber);
      border-radius: 999px;
      margin: 0 auto 20px;
      animation: spin 0.9s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .meta { font-size: 12px; color: #64748b; }
  </style>
</head>
<body>${body}</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function findFindingBadge(findings: Record<string, unknown> | null): string {
  const verdict = String(findings?.verdict || "VERIFICATION_REQUIRED");
  if (verdict === "BLOCKED" || verdict === "HIGH_RISK" || verdict === "MALICIOUS") return `<span class="badge badge-rose">Blocked</span>`;
  if (verdict === "SUSPICIOUS") return `<span class="badge badge-amber">Suspicious</span>`;
  if (verdict === "LOW_RISK" || verdict === "LOW_THREAT" || verdict === "SAFE") return `<span class="badge badge-emerald">Safe</span>`;
  return `<span class="badge badge-amber">Verification required</span>`;
}

function renderFindingsList(findings: Record<string, unknown> | null): string {
  const items = Array.isArray(findings?.findings) ? (findings!.findings as any[]) : [];
  if (!items.length) return "";
  const rows = items
    .map((f) => {
      const sev = String(f?.severity || "info");
      const dot = sev === "critical" ? "dot-critical" : sev === "warning" ? "dot-warning" : "dot-info";
      return `
      <div class="finding">
        <span class="dot ${dot}"></span>
        <div>
          <div class="t">${escapeHtml(String(f?.title || "Finding"))}</div>
          <div class="x">${escapeHtml(String(f?.explanation || ""))}</div>
        </div>
      </div>`;
    })
    .join("");
  return `<div class="findings">${rows}</div>`;
}

function renderPendingPage(): string {
  return pageShell(
    "Checking this link",
    `
    <div class="card center">
      <div class="spinner"></div>
      <span class="badge badge-amber">Pending</span>
      <h1>Checking this link…</h1>
      <p>Our safety scanner is inspecting the destination. This page refreshes automatically and will take you to the result.</p>
      <p class="meta">If the page does not refresh, open the original message again or ask the sender to re-send the link.</p>
    </div>
    <meta http-equiv="refresh" content="2" />`
  );
}

function renderUnverifiedPage(url: string, findings: Record<string, unknown> | null): string {
  const safeHref = url.replace(/["']/g, "");
  return pageShell(
    "Caution — unverified link",
    `
    <div class="card">
      <div class="center">${findFindingBadge(findings)}</div>
      <h1 class="center">Caution — this link is not verified</h1>
      <p class="center">The destination could not be confirmed safe, or was flagged as suspicious. Only continue if you trust the sender and recognise this website.</p>
      <div class="url">${escapeHtml(url)}</div>
      ${renderFindingsList(findings)}
      <p class="center" style="margin-top:20px">
        <a class="btn btn-rose" href="${safeHref}" rel="noopener noreferrer nofollow">Continue anyway</a>
        <a class="btn btn-ghost" href="javascript:history.back()">Go back</a>
      </p>
    </div>`
  );
}

function renderBlockedPage(url: string, findings: Record<string, unknown> | null): string {
  let host = "";
  try {
    host = new URL(url).hostname;
  } catch {
    host = url;
  }
  return pageShell(
    "This link is blocked",
    `
    <div class="card center">
      <span class="badge badge-rose">Blocked</span>
      <h1>This link is blocked</h1>
      <p>The destination was flagged as malicious or is on the blocklist. For your safety it cannot be opened.</p>
      <div>
        <div class="url" style="text-align:center">${escapeHtml(host || url)}</div>
      </div>
      ${renderFindingsList(findings)}
      <p class="meta" style="margin-top:16px">If you believe this is a mistake, ask the sender to contact the site administrator.</p>
    </div>`
  );
}

function renderAdminPage(db: GatewayDb, now: Date): string {
  const recent = db.recentLinks(50);
  const blocklist = db.listBlocklist();
  const allowlist = db.listAllowlist();

  const statusClass: Record<string, string> = {
    PENDING: "badge-amber",
    SAFE: "badge-emerald",
    UNVERIFIED: "badge-amber",
    BLOCKED: "badge-rose",
  };

  const linkRows = recent
    .map((l) => {
      let display = l.url;
      try {
        display = new URL(l.url).hostname + new URL(l.url).pathname;
      } catch {
        /* keep raw */
      }
      const truncated = display.length > 60 ? display.slice(0, 60) + "…" : display;
      return `
      <tr>
        <td><code title="${escapeHtml(l.url)}">${escapeHtml(truncated)}</code></td>
        <td><span class="badge ${statusClass[l.status] || "badge-neutral"}">${l.status}</span></td>
        <td class="muted">${escapeHtml(l.messageRef)}</td>
        <td class="muted">${new Date(l.createdAt).toLocaleString()}</td>
        <td>
          <form method="post" action="/admin/links/${l.id}/override" class="row-form">
            <select name="status" class="select">
              <option value="SAFE" ${l.status === "SAFE" ? "selected" : ""}>SAFE</option>
              <option value="BLOCKED" ${l.status === "BLOCKED" ? "selected" : ""}>BLOCKED</option>
              <option value="UNVERIFIED" ${l.status === "UNVERIFIED" ? "selected" : ""}>UNVERIFIED</option>
            </select>
            <button type="submit" class="btn btn-sm">Override</button>
          </form>
        </td>
      </tr>`;
    })
    .join("");

  const blockRows = blocklist
    .map(
      (b) => `
      <tr>
        <td><span class="badge ${b.type === "domain" ? "badge-amber" : "badge-neutral"}">${b.type}</span></td>
        <td><code>${escapeHtml(b.value)}</code></td>
        <td class="muted">${escapeHtml(b.reason || "")}</td>
        <td class="muted">${new Date(b.createdAt).toLocaleString()}</td>
        <td>
          <form method="post" action="/admin/blocklist/${b.id}/delete">
            <button type="submit" class="btn btn-sm btn-ghost-inline">Delete</button>
          </form>
        </td>
      </tr>`
    )
    .join("");

  const allowRows = allowlist
    .map(
      (a) => `
      <tr>
        <td><code>${escapeHtml(a.domain)}</code></td>
        <td class="muted">${new Date(a.createdAt).toLocaleString()}</td>
        <td>
          <form method="post" action="/admin/allowlist/${a.id}/delete">
            <button type="submit" class="btn btn-sm btn-ghost-inline">Delete</button>
          </form>
        </td>
      </tr>`
    )
    .join("");

  return pageShell(
    "Admin",
    `
    <div class="admin-shell">
      <aside class="admin-sidebar" aria-label="Admin navigation">
        <div class="admin-sidebar-brand"><span>◉</span>Safety Guard</div>
        <div class="admin-sidebar-label">Admin console</div>
        <nav>
          <a href="/admin/mail"><b>▦</b>Overview</a>
          <a href="/admin/mail?tab=activity"><b>✉</b>Mail activity${db.unreadMailCount() ? `<i>${db.unreadMailCount()}</i>` : ""}</a>
          <a class="active" href="/admin"><b>⊞</b>Allow &amp; block lists</a>
          <a href="/admin/mail?tab=settings"><b>⚙</b>Settings</a>
        </nav>
      </aside>
      <main class="admin card">
      <h1>Allow &amp; block lists</h1>
      <p>Link gateway administration. Authenticated as an administrator.</p>

      <h2>Recent links</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Destination</th><th>Status</th><th>Message</th><th>Created</th><th>Override</th></tr></thead>
          <tbody>${linkRows || `<tr><td colspan="5" class="muted">No links yet.</td></tr>`}</tbody>
        </table>
      </div>

      <h2>Blocklist</h2>
      <form method="post" action="/admin/blocklist" class="row-form">
        <select name="type" class="select">
          <option value="domain">domain</option>
          <option value="url">url</option>
        </select>
        <input name="value" placeholder="example.com or https://example.com/x" class="input" required />
        <input name="reason" placeholder="reason (optional)" class="input" />
        <button type="submit" class="btn btn-sm">Add to blocklist</button>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Reason</th><th>Added</th><th></th></tr></thead>
          <tbody>${blockRows || `<tr><td colspan="5" class="muted">Blocklist is empty.</td></tr>`}</tbody>
        </table>
      </div>

      <h2>Allowlist</h2>
      <form method="post" action="/admin/allowlist" class="row-form">
        <input name="domain" placeholder="trusted.example.com" class="input" required />
        <button type="submit" class="btn btn-sm">Add to allowlist</button>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Domain</th><th>Added</th><th></th></tr></thead>
          <tbody>${allowRows || `<tr><td colspan="3" class="muted">Allowlist is empty.</td></tr>`}</tbody>
        </table>
      </div>
      <p class="meta">Seen at ${escapeHtml(now.toISOString())}</p>
      </main>
    </div>
    ${ADMIN_STYLE}`
  );
}

/* ---------------------------------------------------------------------------
 * Admin styling (shared by /admin and /admin/mail)
 * ------------------------------------------------------------------------- */

const ADMIN_STYLE = `<style>
  .admin h2 { font-size: 16px; margin: 28px 0 12px; color: var(--text); }
  .admin h1 { margin-top: 4px; }
  .muted { color: var(--muted); font-size: 13px; }
  .admin code { font-family: ui-monospace, Menlo, monospace; font-size: 12.5px; color: var(--sky); word-break: break-all; }
  .table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; color: var(--muted); font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; font-size: 11px; border-bottom: 1px solid var(--border); background: #0b1220; }
  td { padding: 10px 12px; border-bottom: 1px solid rgb(30 41 59 / 0.6); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .row-form { display: flex; gap: 8px; flex-wrap: wrap; margin: 10px 0; align-items: center; }
  .row-form form { display: inline-flex; gap: 6px; }
  .select, .input {
    background: #0b1220; color: var(--text); border: 1px solid var(--border);
    border-radius: 10px; padding: 8px 10px; font-size: 13px; flex: 1 1 auto; min-width: 160px;
  }
  .select { flex: 0 0 auto; min-width: auto; }
  .btn-sm { padding: 8px 14px; font-size: 12.5px; border-radius: 10px; }
  .btn-ghost-inline { background: transparent; border-color: var(--border); color: var(--muted); }
  form { margin: 0; }

  .admin-nav { display: flex; gap: 6px; align-items: center; margin-bottom: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
  .admin-nav a { color: var(--muted); text-decoration: none; font-size: 13px; font-weight: 600; padding: 6px 12px; border-radius: 999px; }
  .admin-nav a:hover { color: var(--text); background: #0b1220; }
  .admin-nav a.active { color: #fff; background: rgb(56 189 248 / 0.15); border: 1px solid rgb(56 189 248 / 0.4); }
  .nav-badge { display: inline-block; min-width: 18px; text-align: center; padding: 0 5px; margin-left: 4px; border-radius: 999px; background: var(--rose); color: #fff; font-size: 11px; font-weight: 700; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin: 16px 0 8px; }
  .stat { background: #0b1220; border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; }
  .stat .n { font-size: 22px; font-weight: 800; color: var(--text); }
  .stat .l { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-top: 2px; }
  .stat.rose .n { color: var(--rose); }
  .stat.amber .n { color: var(--amber); }
  .stat.emerald .n { color: var(--emerald); }

  .filters { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 14px 0; }
  .toolbar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 10px; }
  .settings { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; margin: 14px 0; padding: 12px; border: 1px solid var(--border); border-radius: 12px; background: #0b1220; }
  .settings label { display: inline-flex; gap: 6px; align-items: center; font-size: 13px; color: var(--muted); }
  .mail-row.unread td { background: rgb(56 189 248 / 0.06); }
  .mail-row.row-flash td { background: rgb(245 158 11 / 0.18); transition: background 0.4s ease; }
  .subject-cell { max-width: 340px; }
  .sender-sub { display: block; color: var(--muted); font-size: 11px; }
  .links-detail { background: #0b1220; border: 1px solid var(--border); border-radius: 12px; padding: 12px; }
  .links-detail table { font-size: 12.5px; }
  .pill { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; background: rgb(245 158 11 / 0.15); color: var(--amber); border: 1px solid rgb(245 158 11 / 0.4); }

  .toast-container { position: fixed; right: 16px; top: 16px; z-index: 50; display: flex; flex-direction: column; gap: 10px; max-width: 360px; }
  .toast { border-radius: 14px; padding: 12px 14px; border: 1px solid var(--border); background: var(--card); box-shadow: 0 12px 30px rgb(0 0 0 / 0.45); animation: toastIn 0.2s ease-out; }
  .toast.blocked { border-color: rgb(244 63 94 / 0.5); background: #2a0b14; }
  .toast.unverified { border-color: rgb(245 158 11 / 0.5); background: #2a1d05; }
  .toast .t-head { display: flex; justify-content: space-between; gap: 8px; align-items: center; font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; }
  .toast.blocked .t-head { color: var(--rose); }
  .toast.unverified .t-head { color: var(--amber); }
  .toast .t-body { font-size: 13px; color: var(--text); margin-top: 6px; word-break: break-word; }
  .toast .t-actions { display: flex; gap: 8px; margin-top: 10px; }
  .toast button { cursor: pointer; }
  .toast .t-close { background: transparent; border: none; color: var(--muted); font-size: 16px; line-height: 1; padding: 0 4px; }
  @keyframes toastIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: none; } }

  /* Match the public Safety Guard shell: charcoal, lime accents, and compact surfaces. */
  body:has(.admin) {
    --bg: #101416;
    --card: #1b251e;
    --border: #3a4b3d;
    --text: #eef2ec;
    --muted: #a7b1a8;
    --emerald: #9fcd51;
    --sky: #d9f36b;
    background: radial-gradient(1100px 520px at 50% -12%, #202a21 0%, var(--bg) 58%);
    align-items: flex-start;
    padding: 28px 20px;
  }
  .admin-shell { width: min(1180px, 100%); margin: 0 auto; display: grid; grid-template-columns: 208px minmax(0, 1fr); gap: 18px; align-items: start; }
  .admin.card {
    width: 100% !important;
    max-width: none !important;
    margin: 0 auto;
    padding: 22px !important;
    border-radius: 18px;
    border-color: var(--border);
    box-shadow: 0 14px 34px rgb(8 13 9 / .2);
  }
  .admin-sidebar { position: sticky; top: 28px; padding: 12px; background: #1b251e; border: 1px solid var(--border); border-radius: 16px; box-shadow: 0 14px 34px rgb(8 13 9 / .2); }
  .admin-sidebar-brand { display: flex; align-items: center; gap: 9px; padding: 8px 9px 18px; font-size: 13px; font-weight: 800; }
  .admin-sidebar-brand span { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 9px; background: #d9f36b; color: #172014; }
  .admin-sidebar-label { padding: 7px 9px; color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
  .admin-sidebar nav { display: grid; gap: 3px; }
  .admin-sidebar a { display: flex; align-items: center; gap: 8px; padding: 9px; border-radius: 9px; color: var(--muted); text-decoration: none; font-size: 12.5px; font-weight: 600; }
  .admin-sidebar a b { width: 17px; color: #d9f36b; text-align: center; }
  .admin-sidebar a:hover { background: #202c23; color: var(--text); }
  .admin-sidebar a.active { color: var(--text); background: rgb(217 243 107 / .13); box-shadow: inset 3px 0 #d9f36b; }
  .admin-sidebar i { margin-left: auto; min-width: 17px; text-align: center; padding: 1px 5px; border-radius: 99px; background: var(--rose); color: #fff; font-style: normal; font-size: 10px; }
  .admin h1 { font: 800 30px/1.12 ui-sans-serif, system-ui, sans-serif; letter-spacing: -.035em; margin: 2px 0 6px; }
  .admin h2 { margin: 20px 0 8px; }
  .admin .admin-nav { margin-bottom: 14px; padding-bottom: 8px; }
  .admin .admin-nav a.active { color: #172014; background: #d9f36b; border-color: #d9f36b; }
  .admin .table-wrap { border-color: var(--border); border-radius: 12px; }
  .admin th { background: #151d18; border-color: var(--border); }
  .admin td { border-color: rgb(58 75 61 / .72); }
  .admin .select, .admin .input { background: #151d18; border-color: var(--border); }
  .admin .btn { background: #d9f36b; color: #172014; border-color: #d9f36b; }
  .admin .btn-ghost-inline { background: transparent; color: var(--muted); border-color: var(--border); }
  .admin .row-form { gap: 7px; margin: 8px 0; }
  @media (max-width: 780px) {
    body:has(.admin) { padding: 12px; }
    .admin-shell { grid-template-columns: 1fr; gap: 12px; }
    .admin-sidebar { position: static; }
    .admin-sidebar nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .admin.card { padding: 16px !important; }
  }
</style>`;

function adminNav(active: "links" | "mail", unread: number): string {
  return `
    <nav class="admin-nav">
      <a href="/admin" class="${active === "links" ? "active" : ""}">Links</a>
      <a href="/admin/mail" class="${active === "mail" ? "active" : ""}">Mail Activity<span class="nav-badge" id="nav-unread"${unread > 0 ? "" : " hidden"}>${unread > 0 ? unread : 0}</span></a>
    </nav>`;
}

interface MailFilterInput {
  provider: string;
  verdict: string;
  from: string;
  to: string;
  q: string;
}

function selectOptions(values: string[], selected: string, labels: Record<string, string> = {}): string {
  return values
    .map(
      (v) =>
        `<option value="${escapeHtml(v)}"${v === selected ? " selected" : ""}>${escapeHtml(labels[v] ?? v)}</option>`
    )
    .join("");
}

function renderMailPage(db: GatewayDb, now: Date, filters: MailFilterInput): string {
  const provider = MAIL_PROVIDERS.includes(filters.provider as MailProvider)
    ? (filters.provider as MailProvider)
    : undefined;
  const verdict = MAIL_VERDICTS.includes(filters.verdict as MailVerdict)
    ? (filters.verdict as MailVerdict)
    : undefined;
  const events = db.listMailEvents({
    provider,
    verdict,
    from: toIsoBound(filters.from, "start"),
    to: toIsoBound(filters.to, "end"),
    q: filters.q.trim() || undefined,
    limit: 100,
  });
  const summary = db.mailSummary(new Date(now.getTime() - 86_400_000).toISOString());
  const storeSubjects = db.getSetting("store_subjects", DEFAULT_STORE_SUBJECTS) === "1";
  const popupVerdicts = db.getSetting("popup_verdicts", "BLOCKED,UNVERIFIED");
  const latestId = db.listMailEvents({ limit: 1 })[0]?.id ?? 0;
  const filtersActive = provider || verdict || filters.from || filters.to || filters.q.trim() ? "1" : "0";
  const retentionDays = Math.max(1, Number(process.env.EVENT_RETENTION_DAYS) || 30);

  const verdictBadge: Record<string, string> = {
    SAFE: "badge-emerald",
    UNVERIFIED: "badge-amber",
    BLOCKED: "badge-rose",
    ERROR: "badge-neutral",
  };
  const actionLabel: Record<string, string> = {
    none: "\u2014",
    labeled: "Labeled",
    moved_to_spam: "Moved to spam",
    protected_copy: "Protected copy",
    restored: "Restored",
  };

  const rows = events
    .map((e) => {
      const linkRows = db
        .listByMessage(e.messageRef)
        .map((l) => {
          let display = l.url;
          try {
            display = new URL(l.url).hostname + new URL(l.url).pathname;
          } catch {
            /* keep raw */
          }
          const truncated = display.length > 60 ? display.slice(0, 60) + "\u2026" : display;
          return `
            <tr>
              <td><code title="${escapeHtml(l.url)}">${escapeHtml(truncated)}</code></td>
              <td><span class="badge ${verdictBadge[l.status] || "badge-neutral"}">${escapeHtml(l.status)}</span></td>
              <td>
                <form method="post" action="/admin/links/${encodeURIComponent(l.id)}/override" class="row-form">
                  <select name="status" class="select">
                    <option value="SAFE"${l.status === "SAFE" ? " selected" : ""}>SAFE</option>
                    <option value="BLOCKED"${l.status === "BLOCKED" ? " selected" : ""}>BLOCKED</option>
                    <option value="UNVERIFIED"${l.status === "UNVERIFIED" ? " selected" : ""}>UNVERIFIED</option>
                  </select>
                  <input type="hidden" name="next" value="/admin/mail" />
                  <button type="submit" class="btn btn-sm">Override</button>
                </form>
              </td>
            </tr>`;
        })
        .join("");

      const detail = `
        <tr class="mail-links-row" id="mail-links-${e.id}" hidden>
          <td colspan="8">
            <div class="links-detail" data-message-ref="${escapeHtml(e.messageRef)}" data-loaded="1">
              ${
                linkRows
                  ? `<div class="table-wrap"><table><thead><tr><th>Destination</th><th>Status</th><th>Override</th></tr></thead><tbody>${linkRows}</tbody></table></div>`
                  : `<p class="muted">No links recorded for this message (message_ref <code>${escapeHtml(e.messageRef)}</code>).</p>`
              }
            </div>
          </td>
        </tr>`;

      return `
        <tr class="mail-row${e.isRead ? "" : " unread"}" id="mail-row-${e.id}" data-id="${e.id}" data-verdict="${escapeHtml(e.verdict)}" data-provider="${escapeHtml(e.provider)}">
          <td class="muted">${escapeHtml(new Date(e.createdAt).toLocaleString())}</td>
          <td><span class="badge badge-neutral">${e.provider === "gmail" ? "Gmail" : "Outlook"}</span></td>
          <td>
            <span>${escapeHtml(e.senderDisplay || e.senderDomain || "(unknown sender)")}</span>
            ${e.senderDisplay && e.senderDomain ? `<span class="sender-sub">${escapeHtml(e.senderDomain)}</span>` : ""}
          </td>
          <td class="subject-cell">${e.subject ? escapeHtml(e.subject) : `<span class="muted">${storeSubjects ? "(no subject)" : "(subjects not stored)"}</span>`}</td>
          <td><span class="badge ${verdictBadge[e.verdict] || "badge-neutral"}">${escapeHtml(e.verdict)}</span></td>
          <td class="muted">${escapeHtml(actionLabel[e.action] || e.action)}</td>
          <td class="muted">${e.linkCount}</td>
          <td><button type="button" class="btn btn-sm" data-view-links="${e.id}">View links</button></td>
        </tr>
        ${detail}`;
    })
    .join("");

  return pageShell(
    "Mail Activity",
    `
    <div id="mail-app" class="admin card" style="max-width: 1100px; width: 100%"
         data-since="${latestId}"
         data-popup-verdicts="${escapeHtml(popupVerdicts)}"
         data-filters-active="${filtersActive}"
         data-store-subjects="${storeSubjects ? "1" : "0"}">
      ${adminNav("mail", summary.unread)}
      <h1>Mail Activity</h1>
      <p>Inspection results reported by your mail add-on. Subjects and senders are rendered as plain text.</p>

      <div class="cards">
        <div class="stat"><div class="n">${summary.scanned}</div><div class="l">Scanned</div></div>
        <div class="stat emerald"><div class="n">${summary.safe}</div><div class="l">Safe</div></div>
        <div class="stat amber"><div class="n">${summary.unverified}</div><div class="l">Needs review</div></div>
        <div class="stat rose"><div class="n">${summary.blocked}</div><div class="l">Blocked</div></div>
        <div class="stat"><div class="n">${summary.last24h}</div><div class="l">Last 24h</div></div>
      </div>

      <form method="get" action="/admin/mail" class="filters">
        <select name="provider" class="select" aria-label="Provider">${selectOptions(["", "gmail", "outlook"], filters.provider, { "": "All providers", gmail: "Gmail", outlook: "Outlook" })}</select>
        <select name="verdict" class="select" aria-label="Verdict">${selectOptions(["", ...MAIL_VERDICTS], filters.verdict, { "": "All verdicts" })}</select>
        <input type="date" name="from" value="${escapeHtml(filters.from)}" class="select" aria-label="From date" />
        <input type="date" name="to" value="${escapeHtml(filters.to)}" class="select" aria-label="To date" />
        <input name="q" value="${escapeHtml(filters.q)}" placeholder="Search sender or subject" class="input" aria-label="Search" />
        <button type="submit" class="btn btn-sm">Filter</button>
        <a class="btn btn-sm btn-ghost-inline" href="/admin/mail">Reset</a>
      </form>

      <div class="toolbar">
        <label class="muted"><input type="checkbox" id="auto-refresh" checked /> Auto-refresh (10s)</label>
        <button type="button" class="btn btn-sm" id="btn-mark-read">Mark all read</button>
        <button type="button" class="btn btn-sm btn-ghost-inline" id="btn-notify">Enable desktop notifications</button>
        <span id="new-pill" class="pill" style="display:none"></span>
      </div>

      <form method="post" action="/admin/mail/settings" class="settings">
        <label><input type="checkbox" name="store_subjects" ${storeSubjects ? "checked" : ""} /> Store subjects</label>
        <label><input type="checkbox" name="popup_blocked" ${popupVerdicts.includes("BLOCKED") ? "checked" : ""} /> Pop-up for BLOCKED</label>
        <label><input type="checkbox" name="popup_unverified" ${popupVerdicts.includes("UNVERIFIED") ? "checked" : ""} /> Pop-up for UNVERIFIED</label>
        <button type="submit" class="btn btn-sm">Save settings</button>
      </form>

      <h2>History</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Provider</th><th>Sender</th><th>Subject</th><th>Verdict</th><th>Action</th><th>Links</th><th></th></tr></thead>
          <tbody id="mail-tbody">${
            rows || `<tr><td colspan="8" class="muted">No mail events yet.</td></tr>`
          }</tbody>
        </table>
      </div>
      <p class="meta">Unread: <span id="unread-inline">${summary.unread}</span> \u00b7 Retention: events older than ${retentionDays} days are deleted automatically.</p>
    </div>

    <div id="toast-container" class="toast-container"></div>
    <script src="/admin/mail.js" defer></script>
    ${ADMIN_STYLE}`
  );
}

/* ---------------------------------------------------------------------------
 * /admin/mail.js — external client script (CSP blocks inline scripts).
 * Builds DOM nodes with textContent so attacker-controlled values can never
 * become markup. No sound; notifications are opt-in.
 * ------------------------------------------------------------------------- */

const MAIL_CLIENT_JS = `(function () {
  "use strict";
  var app = document.getElementById("mail-app");
  if (!app) return;

  var tbody = document.getElementById("mail-tbody");
  var toastBox = document.getElementById("toast-container");
  var newPill = document.getElementById("new-pill");
  var autoRefreshBox = document.getElementById("auto-refresh");
  var since = parseInt(app.getAttribute("data-since") || "0", 10) || 0;
  var popupVerdicts = (app.getAttribute("data-popup-verdicts") || "").split(",").filter(Boolean);
  var filtersActive = app.getAttribute("data-filters-active") === "1";
  var POLL_MS = 10000;

  function setUnread(n) {
    var badge = document.getElementById("nav-unread");
    if (badge) { if (n > 0) { badge.hidden = false; badge.textContent = String(n); } else { badge.hidden = true; badge.textContent = "0"; } }
    var inline = document.getElementById("unread-inline");
    if (inline) inline.textContent = String(n);
  }

  function markRead(ids) {
    var payload = ids && ids.length ? { ids: ids } : {};
    fetch("/api/events/read", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d && typeof d.unread === "number") setUnread(d.unread); })
      .catch(function () {});
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function openEvent(id) {
    var row = document.getElementById("mail-row-" + id);
    if (row) {
      row.scrollIntoView({ behavior: "smooth", block: "center" });
      row.classList.add("row-flash");
      window.setTimeout(function () { row.classList.remove("row-flash"); }, 2500);
    }
    markRead([id]);
  }

  function notify(title, body) {
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    if (localStorage.getItem("sg_notify") !== "1") return;
    try { new Notification(title, { body: body }); } catch (e) {}
  }

  function toast(kind, title, lines, viewId) {
    var box = el("div", "toast " + kind);
    var head = el("div", "t-head");
    head.appendChild(el("span", null, title));
    var close = el("button", "t-close", "\\u00d7");
    close.setAttribute("aria-label", "Dismiss");
    head.appendChild(close);
    box.appendChild(head);
    lines.forEach(function (line) { box.appendChild(el("div", "t-body", line)); });
    if (viewId != null) {
      var actions = el("div", "t-actions");
      var view = el("button", "btn btn-sm", "View");
      view.type = "button";
      view.addEventListener("click", function () { openEvent(viewId); box.remove(); });
      actions.appendChild(view);
      box.appendChild(actions);
    }
    close.addEventListener("click", function () { box.remove(); });
    toastBox.appendChild(box);
    if (kind !== "blocked") { window.setTimeout(function () { if (box.parentNode) box.remove(); }, 10000); }
    notify(title, lines.join(" "));
  }

  function uniq(list) { var out = []; list.forEach(function (v) { if (out.indexOf(v) === -1) out.push(v); }); return out; }

  function showToasts(events) {
    var qualifying = events.filter(function (e) { return popupVerdicts.indexOf(e.verdict) !== -1; });
    if (!qualifying.length) return;
    var anyBlocked = qualifying.some(function (e) { return e.verdict === "BLOCKED"; });
    if (qualifying.length === 1) {
      var e = qualifying[0];
      toast(anyBlocked ? "blocked" : "unverified", (anyBlocked ? "Blocked" : "Needs review") + " email", [
        "From: " + (e.senderDisplay || e.senderDomain || "unknown"),
        "Subject: " + (e.subject || "(not stored)"),
        "Verdict: " + e.verdict + " \\u00b7 Action: " + (e.action || "none")
      ], e.id);
    } else {
      toast(anyBlocked ? "blocked" : "unverified", qualifying.length + " new suspicious emails", [
        "Verdicts: " + uniq(qualifying.map(function (x) { return x.verdict; })).join(", ")
      ], qualifying[qualifying.length - 1].id);
    }
  }

  function badgeClass(v) { return v === "BLOCKED" ? "badge-rose" : v === "SAFE" ? "badge-emerald" : v === "UNVERIFIED" ? "badge-amber" : "badge-neutral"; }

  function buildRow(e) {
    var tr = el("tr", "mail-row" + (e.isRead ? "" : " unread"));
    tr.id = "mail-row-" + e.id;
    tr.setAttribute("data-id", String(e.id));
    tr.setAttribute("data-verdict", e.verdict);
    tr.appendChild(el("td", "muted", new Date(e.createdAt).toLocaleString()));
    var p = el("td"); p.appendChild(el("span", "badge badge-neutral", e.provider === "gmail" ? "Gmail" : "Outlook")); tr.appendChild(p);
    var s = el("td");
    s.appendChild(el("span", null, e.senderDisplay || e.senderDomain || "(unknown sender)"));
    if (e.senderDisplay && e.senderDomain) s.appendChild(el("span", "sender-sub", e.senderDomain));
    tr.appendChild(s);
    tr.appendChild(el("td", "subject-cell", e.subject || "(not stored)"));
    var v = el("td"); v.appendChild(el("span", "badge " + badgeClass(e.verdict), e.verdict)); tr.appendChild(v);
    tr.appendChild(el("td", "muted", e.action || "none"));
    tr.appendChild(el("td", "muted", String(e.linkCount || 0)));
    var a = el("td"); var btn = el("button", "btn btn-sm", "View links"); btn.type = "button"; btn.setAttribute("data-view-links", String(e.id)); a.appendChild(btn); tr.appendChild(a);
    return tr;
  }

  function buildLinkRow(l) {
    var tr = el("tr");
    var td1 = el("td"); var code = el("code"); code.textContent = l.url; td1.appendChild(code); tr.appendChild(td1);
    var td2 = el("td"); td2.appendChild(el("span", "badge " + badgeClass(l.status), l.status)); tr.appendChild(td2);
    var td3 = el("td");
    var form = document.createElement("form");
    form.method = "post"; form.action = "/admin/links/" + encodeURIComponent(l.id) + "/override"; form.className = "row-form";
    var sel = document.createElement("select"); sel.name = "status"; sel.className = "select";
    ["SAFE", "BLOCKED", "UNVERIFIED"].forEach(function (v) { var o = document.createElement("option"); o.value = v; if (v === l.status) o.selected = true; o.textContent = v; sel.appendChild(o); });
    var next = document.createElement("input"); next.type = "hidden"; next.name = "next"; next.value = "/admin/mail";
    var submit = document.createElement("button"); submit.type = "submit"; submit.className = "btn btn-sm"; submit.textContent = "Override";
    form.appendChild(sel); form.appendChild(next); form.appendChild(submit); td3.appendChild(form); tr.appendChild(td3);
    return tr;
  }

  function buildDetailRow(e) {
    var tr = el("tr", "mail-links-row");
    tr.id = "mail-links-" + e.id; tr.hidden = true;
    var td = el("td"); td.colSpan = 8;
    var box = el("div", "links-detail");
    box.setAttribute("data-message-ref", e.messageRef);
    box.appendChild(el("p", "muted", "Loading links\\u2026"));
    td.appendChild(box); tr.appendChild(td);
    return tr;
  }

  function loadLinks(box, messageRef) {
    fetch("/api/message/" + encodeURIComponent(messageRef) + "/verdict", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        box.textContent = "";
        var links = (data && data.links) || [];
        if (!links.length) { box.appendChild(el("p", "muted", "No links recorded for this message.")); return; }
        var wrap = el("div", "table-wrap");
        var table = el("table"); var thead = el("thead"); var htr = el("tr");
        ["Destination", "Status", "Override"].forEach(function (h) { htr.appendChild(el("th", null, h)); });
        thead.appendChild(htr); table.appendChild(thead);
        var tb = el("tbody");
        links.forEach(function (l) { tb.appendChild(buildLinkRow(l)); });
        table.appendChild(tb); wrap.appendChild(table); box.appendChild(wrap);
      })
      .catch(function () { box.textContent = ""; box.appendChild(el("p", "muted", "Could not load links.")); });
  }

  function handleViewLinks(id) {
    var detailRow = document.getElementById("mail-links-" + id);
    if (!detailRow) return;
    if (detailRow.hidden) {
      detailRow.hidden = false;
      var box = detailRow.querySelector(".links-detail");
      if (box && !box.getAttribute("data-loaded")) {
        var ref = box.getAttribute("data-message-ref");
        if (ref) { loadLinks(box, ref); box.setAttribute("data-loaded", "1"); }
      }
    } else {
      detailRow.hidden = true;
    }
  }

  function prependRows(events) {
    if (!tbody) return;
    var placeholder = tbody.querySelector("td[colspan]");
    if (placeholder && placeholder.parentNode) placeholder.parentNode.remove();
    events.slice().reverse().forEach(function (e) {
      var row = buildRow(e);
      tbody.insertBefore(row, tbody.firstChild);
      tbody.insertBefore(buildDetailRow(e), row.nextSibling);
    });
  }

  document.addEventListener("click", function (ev) {
    var target = ev.target;
    if (!target || !target.closest) return;
    var btn = target.closest("[data-view-links]");
    if (btn) handleViewLinks(btn.getAttribute("data-view-links"));
  });

  var markBtn = document.getElementById("btn-mark-read");
  if (markBtn) markBtn.addEventListener("click", function () {
    markRead(null);
    var rows = document.querySelectorAll(".mail-row.unread");
    for (var i = 0; i < rows.length; i++) rows[i].classList.remove("unread");
  });

  var notifyBtn = document.getElementById("btn-notify");
  function notifyLabel() {
    if (!notifyBtn) return;
    if (typeof Notification === "undefined") { notifyBtn.textContent = "Notifications unsupported"; return; }
    if (Notification.permission === "granted" && localStorage.getItem("sg_notify") === "1") notifyBtn.textContent = "Desktop notifications on";
    else if (Notification.permission === "denied") notifyBtn.textContent = "Notifications blocked";
  }
  notifyLabel();
  if (notifyBtn) notifyBtn.addEventListener("click", function () {
    if (typeof Notification === "undefined") return;
    Notification.requestPermission().then(function (p) {
      if (p === "granted") localStorage.setItem("sg_notify", "1"); else localStorage.removeItem("sg_notify");
      notifyLabel();
    });
  });

  function showNewPill(n) {
    if (!newPill) return;
    newPill.textContent = n + " new \\u00b7 reload";
    newPill.style.display = "";
    newPill.style.cursor = "pointer";
    newPill.onclick = function () { location.reload(); };
  }

  function poll() {
    if (autoRefreshBox && !autoRefreshBox.checked) return;
    fetch("/api/events?since=" + since, { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); })
      .then(function (data) {
        var events = (data && data.events) || [];
        if (data && typeof data.unread === "number") setUnread(data.unread);
        if (!events.length) return;
        since = events.reduce(function (m, e) { return Math.max(m, e.id); }, since);
        showToasts(events);
        if (!filtersActive) prependRows(events); else showNewPill(events.length);
      })
      .catch(function () {});
  }
  window.setInterval(poll, POLL_MS);
})();`;
