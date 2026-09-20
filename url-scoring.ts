/**
 * URL risk scoring, confidence and domain intelligence for the URL inspector.
 *
 * Model (this file is the single source of truth):
 *   riskScore = clamp(sum(signal.points), 0, 100)   ← nothing else applied.
 *   Reducers (negative points) are capped at -20 in total and can never cancel a
 *   high-severity signal; every signal, positive or negative, is listed.
 *   confidence = share of the documented check weights that actually succeeded.
 *
 * This module has no dependency on server.ts (it is imported by it).
 */
import { lookup as dnsLookup } from "dns/promises";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import tls from "node:tls";

/* ------------------------------------------------------------------ types */

export type ScoreVerdict = "MALICIOUS" | "SUSPICIOUS" | "LOW_RISK" | "UNVERIFIED";

export interface ScorableFlag {
  severity: "high" | "medium" | "low";
  title: string;
  evidence?: string;
  explanation?: string;
}

export interface ScorableCheck {
  id: string;
  label: string;
  status: "passed" | "warning" | "failed" | "skipped" | "error";
  detail?: string;
}

export interface UrlSignal {
  id: string;
  label: string;
  /** Signed points. Positive = risk, negative = reducer (max -20 in total), 0 = info. */
  points: number;
  reason: string;
  kind: "risk" | "safe" | "info";
}

/** Thresholds live here so they can be tuned by the eval harness. */
export const VERDICT_THRESHOLDS = {
  MALICIOUS: 70,
  SUSPICIOUS: 40,
  LOW_RISK_MIN_CONFIDENCE: 60,
} as const;

/** Total reducer budget: negative points can never exceed this in magnitude. */
export const MAX_NEGATIVE_POINTS = 20;

/**
 * Documented confidence weights — they sum to exactly 100.
 * `brand`, `subdomain` and `query-params` are the "structure" group (15 total).
 */
export const CHECK_WEIGHTS: Record<string, number> = {
  reputation: 30,
  redirect: 15,
  "url-structure": 5,
  brand: 5,
  subdomain: 3,
  "query-params": 2,
  "domain-age": 10,
  tranco: 10,
  "ai-semantic": 10,
  dns: 5,
  tls: 5,
};

/** Checks whose absence/error means "we could not verify" → not Low risk. */
export const CRITICAL_CHECK_IDS = new Set(["reputation", "redirect", "dns"]);

/** Signals that reducers must never cancel. */
export const HIGH_SEVERITY_IDS = new Set([
  "reputation-hit",
  "brand-embedded-domain",
  "brand-typosquat",
  "brand-in-subdomain",
  "punycode",
  "ip-host",
  "dangerous-scheme",
]);

/* --------------------------------------------------------------- signals */

// Flag title → signal id + points. Normal TLS/DNS/age are intentionally absent
// (or 0): they are not evidence of safety.
const FLAG_SIGNAL_MAP: Record<string, { id: string; points: number; kind: "risk" | "safe" | "info" }> = {
  "High-risk top-level domain": { id: "suspicious-tld", points: 30, kind: "risk" },
  "Brand domain planted inside a third-party hostname": { id: "brand-embedded-domain", points: 32, kind: "risk" },
  "Brand name embedded in an unrelated domain": { id: "brand-embedded-domain", points: 32, kind: "risk" },
  "Brand token inside the registered domain": { id: "brand-typosquat", points: 30, kind: "risk" },
  "Brand name hidden in subdomain of unrelated host": { id: "brand-in-subdomain", points: 26, kind: "risk" },
  "Possible open redirect via query parameter": { id: "open-redirect-param", points: 40, kind: "risk" },
  "Tracking parameters present": { id: "tracking-params", points: 0, kind: "info" },
  "Redirect crosses to a different registered domain": { id: "redirect-cross-domain", points: 20, kind: "risk" },
  "HTTPS downgrade on redirect": { id: "https-downgrade", points: 20, kind: "risk" },
  "Redirects through a URL shortener": { id: "shortener", points: 12, kind: "risk" },
  "Cross-host redirect (same registered domain)": { id: "redirect-cross-host", points: 4, kind: "risk" },
  "Credentials hidden before '@'": { id: "userinfo", points: 25, kind: "risk" },
  "Raw IP address instead of a domain": { id: "ip-host", points: 30, kind: "risk" },
  "Internationalised (punycode) hostname": { id: "punycode", points: 35, kind: "risk" },
  "Dangerous URL scheme": { id: "dangerous-scheme", points: 60, kind: "risk" },
  "Plain HTTP — no transport encryption": { id: "http", points: 12, kind: "risk" },
  "Deeply nested suspicious subdomains": { id: "many-subdomains", points: 15, kind: "risk" },
  "Excessive hyphens in domain": { id: "hyphenated-domain", points: 12, kind: "risk" },
  // Reviewed keyword rules: these are weak alone and only get full weight when a
  // second independent risk signal is present (see WEAK_KEYWORD_IDS below).
  "Login/credential context on an unverified domain": { id: "credential-keywords", points: 18, kind: "risk" },
  "Suspicious login page path": { id: "login-page-path", points: 16, kind: "risk" },
  "Path traversal or backslash tricks": { id: "path-traversal", points: 20, kind: "risk" },
  "Executable or archive download link": { id: "download-link", points: 20, kind: "risk" },
  // Informational only — never add or remove points.
  "Heavy percent-encoding in URL": { id: "percent-encoding", points: 0, kind: "info" },
  "Digit-heavy domain name": { id: "digit-heavy", points: 0, kind: "info" },
  "Unusually long hostname": { id: "long-hostname", points: 0, kind: "info" },
  "Uncommon network port": { id: "uncommon-port", points: 0, kind: "info" },
};

const WEAK_KEYWORD_IDS: Record<string, { alone: number; combined: number }> = {
  "credential-keywords": { alone: 5, combined: 18 },
  "login-page-path": { alone: 6, combined: 16 },
};

const SEVERITY_FALLBACK: Record<ScorableFlag["severity"], number> = { high: 28, medium: 14, low: 0 };

// Reducer magnitudes (only these may lower the score).
export const REDUCER_POINTS = {
  tranco: -15,
  allowlisted: -20,
  cleanReputation: -10,
  knownLegitimateDestination: -10,
} as const;

export interface SignalInput {
  flags: ScorableFlag[];
  reputationMalicious: boolean;
  /** A reputation source actually ran and returned clean. */
  reputationClean?: boolean;
  reputationSource?: string;
  reputationFlaggedUrl?: string | null;
  reputationFlaggedFinal?: boolean;
  allowlisted?: boolean;
  tracking?: { isTracking: boolean; destinationUnverified?: boolean; provider?: string } | null;
  finalDestination?: { url: string; wellKnown: boolean } | null;
  intel?: {
    tlsValid?: boolean | null;
    dnsExists?: boolean | null;
    domainAgeDays?: number | null;
    trancoRank?: number | null;
  } | null;
  /** Optional AI advisory. Never decides alone; never a reducer. */
  ai?: { threatLevel?: string } | null;
}

/** Build the full signal list. Sum of points == the risk score (after clamping). */
export function buildSignals(input: SignalInput): UrlSignal[] {
  const signals: UrlSignal[] = [];
  const seen = new Set<string>();

  for (const flag of input.flags) {
    const mapped = FLAG_SIGNAL_MAP[flag.title];
    const id = mapped ? mapped.id : `flag-${slug(flag.title)}`;
    let points = mapped ? mapped.points : SEVERITY_FALLBACK[flag.severity];
    let kind: UrlSignal["kind"] = points > 0 ? "risk" : "info";
    let reason = flag.explanation || flag.title;

    // Tracking links: the destination parameter is judged, not treated as an
    // open redirect.
    if (id === "open-redirect-param" && input.tracking?.isTracking) {
      points = 0;
      kind = "info";
      reason = "The destination is carried in a parameter on a known click-tracking link; it is judged after the redirect rather than treated as an open redirect.";
    }

    const key = `${id}|${flag.evidence || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    signals.push({ id, label: flag.title, points, reason, kind });
  }

  if (input.flags.some((f) => f.title === "Tracking parameters present")) {
    signals.push({
      id: "tracking-params-info",
      label: "Tracking parameters only",
      points: 0,
      reason: "utm_*/fbclid/gclid/`ref` style parameters do not change the destination.",
      kind: "info",
    });
  }

  if (input.tracking?.isTracking) {
    signals.push(
      input.tracking.destinationUnverified
        ? {
            id: "tracking-unverified",
            label: "Tracking link, destination unverified",
            points: 0,
            reason: `This looks like ${input.tracking.provider || "an email-service"} click-tracking; the final destination could not be resolved, so it is not scored as risk.`,
            kind: "info",
          }
        : {
            id: "tracking-neutral",
            label: "Email-service tracking link",
            points: 0,
            reason: "Known click-tracking host; the final destination is judged instead of the tracker.",
            kind: "info",
          }
    );
  }

  // ---- reducers (may lower risk; capped below) ----
  if (input.allowlisted) {
    signals.push({ id: "allowlisted", label: "Domain is on the allowlist", points: REDUCER_POINTS.allowlisted, reason: "Domain is explicitly trusted.", kind: "safe" });
  }
  if (input.intel && typeof input.intel.trancoRank === "number") {
    signals.push({ id: "tranco", label: "Popular site (Tranco)", points: REDUCER_POINTS.tranco, reason: `Ranked #${input.intel.trancoRank} in the Tranco top-sites list.`, kind: "safe" });
  }
  if (input.reputationClean) {
    signals.push({ id: "reputation-clean", label: "Reputation sources found no reports", points: REDUCER_POINTS.cleanReputation, reason: `${input.reputationSource || "A reputation source"} ran and found no reports for this URL/host.`, kind: "safe" });
  }
  if (input.finalDestination?.wellKnown) {
    signals.push({ id: "final-well-known", label: "Destination on a well-known domain", points: REDUCER_POINTS.knownLegitimateDestination, reason: `The link resolves to a well-known domain (${input.finalDestination.url}).`, kind: "safe" });
  }

  // ---- reputation threat (highest severity) ----
  if (input.reputationMalicious) {
    signals.push({
      id: "reputation-hit",
      label: "Listed by a threat source",
      points: 80,
      reason: input.reputationFlaggedFinal
        ? `${input.reputationSource || "A threat source"} lists the post-redirect destination as malicious.`
        : `${input.reputationSource || "A threat source"} lists this URL/host as malicious.`,
      kind: "risk",
    });
  }

  // ---- intelligence (normal states add nothing; failures/abnormal add risk) ----
  const intel = input.intel || {};
  if (intel.tlsValid === false) {
    signals.push({ id: "tls-invalid", label: "TLS certificate problem", points: 25, reason: "The HTTPS certificate is invalid, expired or untrusted.", kind: "risk" });
  } else if (intel.tlsValid === true) {
    signals.push({ id: "tls-valid", label: "Valid TLS certificate", points: 0, reason: "A valid certificate was presented — this is normal and is not evidence of safety.", kind: "info" });
  }
  if (intel.dnsExists === false) {
    signals.push({ id: "no-dns", label: "No DNS record", points: 20, reason: "The hostname does not resolve.", kind: "risk" });
  }
  if (typeof intel.domainAgeDays === "number") {
    if (intel.domainAgeDays < 30) {
      signals.push({ id: "very-new-domain", label: "Very new domain", points: 30, reason: `Registered only ${intel.domainAgeDays} day(s) ago.`, kind: "risk" });
    } else if (intel.domainAgeDays < 90) {
      signals.push({ id: "new-domain", label: "Recently registered domain", points: 20, reason: `Registered ${intel.domainAgeDays} days ago.`, kind: "risk" });
    }
    // A normal/old domain adds nothing — age is not safety evidence.
  }

  // ---- AI is advisory only (never decides alone, never a reducer) ----
  const aiLevel = (input.ai?.threatLevel || "").toUpperCase();
  if (aiLevel === "HIGH") {
    signals.push({ id: "ai-high", label: "AI flagged high risk", points: 15, reason: "The AI semantic analysis rated this URL high risk (advisory only).", kind: "risk" });
  } else if (aiLevel === "MEDIUM") {
    signals.push({ id: "ai-medium", label: "AI flagged medium risk", points: 5, reason: "The AI semantic analysis rated this URL medium risk (advisory only).", kind: "risk" });
  }

  // ---- weak keyword signals only count when combined with a second signal ----
  const secondRiskPresent = signals.some(
    (s) => s.points > 0 && !(s.id in WEAK_KEYWORD_IDS)
  );
  for (const s of signals) {
    const weak = WEAK_KEYWORD_IDS[s.id];
    if (weak && s.points > 0 && !secondRiskPresent) {
      s.points = weak.alone;
      s.reason += " A generic word alone carries little weight — this only becomes a real signal alongside another risk factor.";
    }
  }

  return finalizeReducers(signals);
}

/**
 * Cap the total reducer magnitude at MAX_NEGATIVE_POINTS and never let reducers
 * cancel a high-severity signal. Points are adjusted in place so that the sum of
 * the listed signals *is* the score.
 */
function finalizeReducers(signals: UrlSignal[]): UrlSignal[] {
  const positiveSum = signals.reduce((sum, s) => sum + Math.max(0, s.points), 0);
  const highSum = signals
    .filter((s) => HIGH_SEVERITY_IDS.has(s.id) && s.points > 0)
    .reduce((sum, s) => sum + s.points, 0);
  const reducerMag = signals.reduce((sum, s) => sum + Math.max(0, -s.points), 0);
  if (reducerMag === 0) return signals;

  let budget = Math.min(reducerMag, MAX_NEGATIVE_POINTS);
  if (highSum > 0) {
    // Never let a reducer cancel a high-severity signal (brand impersonation,
    // reputation hit, punycode, raw IP, dangerous scheme).
    budget = 0;
  } else if (positiveSum >= VERDICT_THRESHOLDS.SUSPICIOUS) {
    // Don't let reducers drop a suspicious URL into the low-risk band.
    budget = Math.min(budget, positiveSum - VERDICT_THRESHOLDS.SUSPICIOUS);
  }

  for (const s of signals) {
    if (s.points >= 0) continue;
    const mag = -s.points;
    const take = Math.min(mag, budget);
    budget -= take;
    if (take === mag) continue;
    s.points = -take;
    s.reason +=
      take === 0
        ? " (not applied — total risk reduction is capped and high-severity signals cannot be cancelled)"
        : " (partially applied — total risk reduction is capped)";
  }
  return signals;
}

/** The risk score is exactly the clamped sum of the listed signal points. */
export function riskScoreFromSignals(signals: UrlSignal[]): number {
  const total = signals.reduce((sum, s) => sum + s.points, 0);
  return Math.max(0, Math.min(100, Math.round(total)));
}

/** Confidence = share of the documented check weights that actually succeeded. */
export function confidenceFromChecks(checks: ScorableCheck[]): number {
  let total = 0;
  let ran = 0;
  for (const check of checks) {
    const weight = CHECK_WEIGHTS[check.id] ?? 0;
    total += weight;
    if (check.status !== "skipped" && check.status !== "error") ran += weight;
  }
  if (total === 0) return 0;
  return Math.round((ran / total) * 100);
}

export interface VerdictInput {
  riskScore: number;
  confidence: number;
  reputationMalicious: boolean;
  /** True only when the critical live checks (reputation/redirect/DNS) succeeded. */
  criticalOk: boolean;
}

export function verdictFromScore(input: VerdictInput): ScoreVerdict {
  const { riskScore, confidence, reputationMalicious, criticalOk } = input;
  if (reputationMalicious || riskScore >= VERDICT_THRESHOLDS.MALICIOUS) return "MALICIOUS";
  if (riskScore >= VERDICT_THRESHOLDS.SUSPICIOUS) return "SUSPICIOUS";
  if (riskScore < VERDICT_THRESHOLDS.SUSPICIOUS && confidence >= VERDICT_THRESHOLDS.LOW_RISK_MIN_CONFIDENCE && criticalOk) {
    return "LOW_RISK";
  }
  return "UNVERIFIED";
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

/* ------------------------------------------------------- tracking links */

const TRACKER_DOMAINS = new Set([
  "sendgrid.net", "sendgrid.com", "mailchimp.com", "list-manage.com", "sendclean.com", "sendclean.net",
  "constantcontact.com", "hubspotlinks.com", "exacttarget.com", "mailgun.org", "sparkpostmail.com",
  "mandrillapp.com", "amazonses.com", "campaign-archive.com", "createsend.com", "cmail19.com",
  "cmail20.com", "rs6.net", "klclick.com", "klclick1.com", "convertkit-mail.com", "mailerlite.com",
  "braze.com", "customeriomail.com", "iterable.com", "salesforce.com",
]);
const TRACKER_SUBDOMAINS = new Set(["track", "tracking", "click", "clicks", "links", "link", "email", "go", "mail", "e", "r", "t", "url", "url1", "url2", "ct", "trk", "mkt", "news"]);

export function trackingInfo(url: URL): { isTracking: boolean; provider?: string; embeddedDestination?: string } {
  const host = url.hostname.toLowerCase();
  const provider = [...TRACKER_DOMAINS].find((d) => host === d || host.endsWith("." + d));
  const firstLabel = host.split(".")[0];
  const bySubdomain = TRACKER_SUBDOMAINS.has(firstLabel);

  let embeddedDestination: string | undefined;
  for (const key of ["u", "url", "redirect", "redirect_uri", "target", "link", "to", "destination", "next"]) {
    const raw = url.searchParams.get(key);
    if (!raw) continue;
    const candidate = raw.startsWith("//") ? `https:${raw}` : raw;
    if (/^https?:\/\//i.test(candidate)) {
      try {
        embeddedDestination = new URL(candidate).href;
        break;
      } catch {
        /* not a URL */
      }
    }
  }
  return { isTracking: Boolean(provider) || bySubdomain, provider, embeddedDestination };
}

const WELL_KNOWN_DOMAINS = new Set([
  "google.com", "youtube.com", "facebook.com", "instagram.com", "wikipedia.org", "amazon.com",
  "apple.com", "microsoft.com", "netflix.com", "linkedin.com", "x.com", "twitter.com", "paypal.com",
  "github.com", "cloudflare.com", "mozilla.org", "adobe.com", "dropbox.com", "zoom.us", "slack.com",
]);

export function isWellKnownDomain(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return [...WELL_KNOWN_DOMAINS].some((d) => host === d || host.endsWith("." + d));
}

/* ----------------------------------------------------- intel + caching */

interface CacheEntry {
  expires: number;
  value: unknown;
}
const intelCache = new Map<string, CacheEntry>();

function cacheGet<T>(key: string): T | undefined {
  const hit = intelCache.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expires) {
    intelCache.delete(key);
    return undefined;
  }
  return hit.value as T;
}
function cacheSet(key: string, value: unknown, ttlMs: number): void {
  intelCache.set(key, { expires: Date.now() + ttlMs, value });
}

export const INTEL_TTL_MS = { verdict: 6 * 60 * 60 * 1000, intel: 24 * 60 * 60 * 1000 };

export interface UrlIntel {
  dns(host: string): Promise<{ exists: boolean | null; error?: string }>;
  tls(host: string): Promise<{ valid: boolean | null; daysToExpiry?: number | null; error?: string }>;
  domainAgeDays(domain: string): Promise<{ ageDays: number | null; error?: string }>;
  trancoRank(domain: string): Promise<{ rank: number | null; error?: string }>;
}

const TLS_TIMEOUT_MS = 6000;
const RDAP_TIMEOUT_MS = 7000;

async function withTimeout<T>(promise: Promise<T>, ms: number, onTimeout: () => T): Promise<T> {
  return new Promise<T>((resolve) => {
    const timer = setTimeout(() => resolve(onTimeout()), ms);
    timer.unref?.();
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      () => {
        clearTimeout(timer);
        resolve(onTimeout());
      }
    );
  });
}

async function checkTls(host: string): Promise<{ valid: boolean | null; daysToExpiry?: number | null; error?: string }> {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":")) return { valid: null, error: "ip-literal" };
  return withTimeout(
    new Promise((resolve) => {
      const socket = tls.connect(
        { host, port: 443, servername: host, rejectUnauthorized: true, timeout: TLS_TIMEOUT_MS },
        () => {
          const cert = socket.getPeerCertificate();
          const valid = socket.authorized === true;
          const daysToExpiry = cert?.valid_to ? Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000) : null;
          socket.destroy();
          resolve({ valid, daysToExpiry });
        }
      );
      socket.on("error", (err: Error) => {
        socket.destroy();
        resolve({ valid: false, error: err.message });
      });
    }),
    TLS_TIMEOUT_MS + 500,
    () => ({ valid: null, error: "tls-timeout" })
  );
}

async function rdapDomainAgeDays(domain: string): Promise<{ ageDays: number | null; error?: string }> {
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS);
    const res = await fetch(url, { headers: { Accept: "application/rdap+json, application/json", "User-Agent": "Mozilla/5.0 (compatible; OnlineSafetyGuard)" }, signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return { ageDays: null, error: `HTTP ${res.status}` };
    const data: any = await res.json();
    const reg = Array.isArray(data?.events) ? data.events.find((e: any) => e?.eventAction === "registration") : null;
    if (!reg?.eventDate) return { ageDays: null, error: "no registration event" };
    const age = Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86_400_000);
    return { ageDays: Number.isFinite(age) ? age : null };
  } catch (err: any) {
    return { ageDays: null, error: err?.message || "rdap failed" };
  }
}

/* ------------------------------------------------------- Tranco (offline) */

const TRANCO_URL = process.env.TRANCO_LIST_URL || "https://tranco-list.eu/top-1m.csv.zip";
const TRANCO_CACHE = process.env.TRANCO_LIST_FILE || "data/tranco-top.txt";
const TRANCO_MAX = Math.max(1000, Number(process.env.TRANCO_MAX) || 100_000);
const TRANCO_TTL_MS = 24 * 60 * 60 * 1000;

let trancoMap: Map<string, number> | null = null;
let trancoMeta: { loadedAt: number; source: string; count: number; error?: string } = {
  loadedAt: 0,
  source: "",
  count: 0,
  error: "not loaded",
};

export function trancoStatus(): { available: boolean; count: number; source: string; error?: string; loadedAt: number } {
  return { available: Boolean(trancoMap), count: trancoMeta.count, source: trancoMeta.source, error: trancoMeta.error, loadedAt: trancoMeta.loadedAt };
}

function parseTranco(text: string): string[] {
  const domains: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const csv = trimmed.match(/^\d+\s*,\s*([^\s,]+)/);
    const domain = (csv ? csv[1] : trimmed).toLowerCase();
    if (!domain || domain.includes(",") || /^\d+$/.test(domain)) continue;
    domains.push(domain);
    if (domains.length >= TRANCO_MAX) break;
  }
  return domains;
}

function setTranco(domains: string[], source: string): void {
  trancoMap = new Map();
  domains.forEach((d, i) => trancoMap!.set(d, i + 1));
  trancoMeta = { loadedAt: Date.now(), source, count: domains.length };
}

function loadTrancoFromCache(): boolean {
  try {
    if (!fs.existsSync(TRANCO_CACHE)) return false;
    const domains = parseTranco(fs.readFileSync(TRANCO_CACHE, "utf8"));
    if (!domains.length) return false;
    setTranco(domains, `cache:${TRANCO_CACHE}`);
    return true;
  } catch {
    return false;
  }
}

/** Minimal ZIP reader (stored/deflated) — avoids adding a dependency. */
function unzipFirstText(buf: Buffer): string | null {
  try {
    // Locate the End Of Central Directory record.
    let eocd = -1;
    for (let i = buf.length - 22; i >= 0 && i > buf.length - 65558; i--) {
      if (buf.readUInt32LE(i) === 0x06054b50) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return null;
    const count = buf.readUInt16LE(eocd + 10);
    let offset = buf.readUInt32LE(eocd + 16);
    for (let n = 0; n < count; n++) {
      if (buf.readUInt32LE(offset) !== 0x02014b50) return null;
      const method = buf.readUInt16LE(offset + 10);
      const compSize = buf.readUInt32LE(offset + 20);
      const nameLen = buf.readUInt16LE(offset + 28);
      const extraLen = buf.readUInt16LE(offset + 30);
      const commentLen = buf.readUInt16LE(offset + 32);
      const localOffset = buf.readUInt32LE(offset + 42);
      const name = buf.slice(offset + 46, offset + 46 + nameLen).toString("utf8");
      if (name.toLowerCase().endsWith(".csv")) {
        const lnameLen = buf.readUInt16LE(localOffset + 26);
        const lextraLen = buf.readUInt16LE(localOffset + 28);
        const dataStart = localOffset + 30 + lnameLen + lextraLen;
        const comp = buf.slice(dataStart, dataStart + compSize);
        const raw = method === 0 ? comp : zlib.inflateRawSync(comp);
        return raw.toString("utf8");
      }
      offset += 46 + nameLen + extraLen + commentLen;
    }
    return null;
  } catch {
    return null;
  }
}

export async function refreshTranco(): Promise<void> {
  try {
    const res = await fetch(TRANCO_URL, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; OnlineSafetyGuard)" },
      signal: AbortSignal.timeout(90_000),
    });
    if (!res.ok) {
      trancoMeta = { loadedAt: Date.now(), source: TRANCO_URL, count: trancoMeta.count, error: `HTTP ${res.status}` };
      return;
    }
    const buf = Buffer.from(await res.arrayBuffer());
    const text = unzipFirstText(buf) ?? buf.toString("utf8");
    const domains = parseTranco(text);
    if (!domains.length) {
      trancoMeta = { loadedAt: Date.now(), source: TRANCO_URL, count: trancoMeta.count, error: "empty list" };
      return;
    }
    setTranco(domains, TRANCO_URL);
    try {
      fs.mkdirSync(path.dirname(path.resolve(TRANCO_CACHE)), { recursive: true });
      fs.writeFileSync(TRANCO_CACHE, domains.join("\n"));
    } catch {
      /* cache write is best-effort */
    }
  } catch (err: any) {
    trancoMeta = { loadedAt: Date.now(), source: TRANCO_URL, count: trancoMeta.count, error: err?.message || "download failed" };
  }
}

/** Load the cache immediately, then download and refresh daily. */
export function startTrancoLoader(): void {
  loadTrancoFromCache();
  void refreshTranco();
  const timer = setInterval(() => void refreshTranco(), TRANCO_TTL_MS);
  timer.unref?.();
}

export function trancoRank(domain: string): number | null {
  if (!trancoMap) return null;
  let host = domain.toLowerCase().replace(/\.$/, "");
  while (host.includes(".")) {
    const rank = trancoMap.get(host);
    if (rank) return rank;
    host = host.slice(host.indexOf(".") + 1);
  }
  return null;
}

export const defaultIntel: UrlIntel = {
  async dns(host) {
    const key = `dns:${host}`;
    const cached = cacheGet<{ exists: boolean | null; error?: string }>(key);
    if (cached) return cached;
    let result: { exists: boolean | null; error?: string };
    try {
      const addrs = await dnsLookup(host, { all: true });
      result = { exists: addrs.length > 0 };
    } catch (err: any) {
      const code = String(err?.code || "");
      result = code === "ENOTFOUND" || code === "ENODATA" ? { exists: false, error: code } : { exists: null, error: err?.message || "dns error" };
    }
    cacheSet(key, result, INTEL_TTL_MS.intel);
    return result;
  },
  async tls(host) {
    const key = `tls:${host}`;
    const cached = cacheGet<{ valid: boolean | null; daysToExpiry?: number | null; error?: string }>(key);
    if (cached) return cached;
    const result = await checkTls(host);
    cacheSet(key, result, INTEL_TTL_MS.intel);
    return result;
  },
  async domainAgeDays(domain) {
    const key = `age:${domain}`;
    const cached = cacheGet<{ ageDays: number | null; error?: string }>(key);
    if (cached) return cached;
    const result = await rdapDomainAgeDays(domain);
    cacheSet(key, result, INTEL_TTL_MS.intel);
    return result;
  },
  async trancoRank(domain) {
    if (!trancoMap) {
      loadTrancoFromCache();
    }
    if (!trancoMap) return { rank: null, error: trancoMeta.error || "list not available" };
    return { rank: trancoRank(domain) };
  },
};

/* --------------------------------------------------------- verdict cache */

const verdictCache = new Map<string, CacheEntry>();
export function verdictCacheGet(key: string): any | undefined {
  return cacheGet<any>(key);
}
export function verdictCacheSet(key: string, value: unknown): void {
  cacheSet(key, value, INTEL_TTL_MS.verdict);
}
