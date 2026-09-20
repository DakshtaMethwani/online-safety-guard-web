import express, { type Express, type Response as ExpressResponse } from "express";
import path from "path";
import fs from "node:fs";
import { fileURLToPath } from "url";
import { lookup as dnsLookup } from "dns/promises";
import dotenv from "dotenv";
import { GoogleGenAI, Type } from "@google/genai";
import { parse as parseTldts } from "tldts";
import {
  buildSignals,
  riskScoreFromSignals,
  confidenceFromChecks,
  verdictFromScore,
  trackingInfo,
  isWellKnownDomain,
  defaultIntel,
  startTrancoLoader,
  trancoStatus,
  verdictCacheGet,
  verdictCacheSet,
  CHECK_WEIGHTS,
  MAX_NEGATIVE_POINTS,
  CRITICAL_CHECK_IDS,
  VERDICT_THRESHOLDS,
  type UrlIntel,
  type UrlSignal,
  type ScoreVerdict,
} from "./url-scoring";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: "15mb" }));

// --- Production hardening -------------------------------------------------
//
// Trust proxy: derive the real client IP / protocol from X-Forwarded-* so
// rate limiting and the HTTPS-only guard see actual clients behind the host's
// reverse proxy. TRUST_PROXY accepts `false`, `true`, a hop count (e.g. `1`),
// or a comma-separated list of proxy addresses. Default: 1 hop in production,
// disabled locally.
function parseTrustProxy(value: string | undefined, fallback: unknown): unknown {
  if (value === undefined || value.trim() === "") return fallback;
  const v = value.trim().toLowerCase();
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^\d+$/.test(v)) return Number(v);
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
app.set("trust proxy", parseTrustProxy(process.env.TRUST_PROXY, process.env.NODE_ENV === "production" ? 1 : false));

// Liveness probe — reachable over HTTP so load balancers / Docker healthchecks
// can ping it without going through the proxy.
app.get("/healthz", (_req, res) => {
  res.status(200).json({ status: "ok", uptime: Math.round(process.uptime()) });
});

// In production, refuse to serve the admin panel and the API over plain HTTP.
// Behind a TLS-terminating proxy this is detected via X-Forwarded-Proto (trust
// proxy must be on). Set REQUIRE_HTTPS=false to disable (e.g. local testing).
const REQUIRE_HTTPS =
  process.env.REQUIRE_HTTPS !== undefined
    ? process.env.REQUIRE_HTTPS !== "false"
    : process.env.NODE_ENV === "production";
if (REQUIRE_HTTPS) {
  app.use((req, res, next) => {
    const p = req.path;
    if (!req.secure && (p.startsWith("/api") || p.startsWith("/admin"))) {
      res.status(403);
      if (p.startsWith("/admin")) {
        res.set("Content-Type", "text/plain; charset=utf-8");
        res.send("HTTPS is required for the admin panel.");
      } else {
        res.json({ error: "HTTPS is required" });
      }
      return;
    }
    next();
  });
}

// Lazy initialization for Gemini client
let genAIClient: GoogleGenAI | null = null;
function getGenAI(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  if (!genAIClient) {
    genAIClient = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return genAIClient;
}

// ---------------------------------------------------------------------------
// Message threat-analysis engine (deterministic, weighted signals)
//
// The rule engine owns the risk score: each signal category has an explicit
// weight plus a quoted reason. Gemini later adds semantic reasoning, but it can
// never downgrade a strong deterministic signal — see combineMessageAnalysis().
// ---------------------------------------------------------------------------

type SignalSeverity = "high" | "medium" | "low";
type SignalCategory =
  | "urgency"
  | "threat"
  | "credential_request"
  | "sensitive_credential"
  | "suspicious_url"
  | "impersonation"
  | "call_to_action"
  | "financial"
  | "job_offer"
  | "reward"
  | "combined";

interface MessageSignal {
  category: SignalCategory;
  flag: string;
  evidence: string;
  severity: SignalSeverity;
  weight: number;
  tactic: string;
  explanation: string;
  /** Evidence is a verbatim quote that can be highlighted in the message. */
  highlight?: boolean;
}

const MESSAGE_SIGNAL_WEIGHTS = {
  urgencyStrong: 22,
  urgencyWeak: 8,
  threat: 26,
  credentialRequest: 28,
  sensitiveCredential: 32,
  suspiciousUrl: 30,
  urlMedium: 16,
  impersonation: 24,
  callToAction: 13,
  financial: 16,
  jobOffer: 30,
  reward: 26,
  combined: 40,
} as const;

const HIGH_RISK_TLDS = [
  ".top", ".xyz", ".cc", ".buzz", ".cam", ".rest", ".club", ".fit", ".tk",
  ".ml", ".ga", ".cf", ".gq", ".work", ".zip", ".mov", ".click", ".surf",
  ".loan", ".win", ".bid", ".icu", ".vip", ".ticket", ".website", ".ooo",
];

const MESSAGE_URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "tiny.cc", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co", "t.ly",
]);

const MESSAGE_AUTHORITIES: Array<{ term: string; domains: string[] }> = [
  { term: "paypal", domains: ["paypal.com"] },
  { term: "apple", domains: ["apple.com", "icloud.com"] },
  { term: "icloud", domains: ["icloud.com", "apple.com"] },
  { term: "amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.in"] },
  { term: "microsoft", domains: ["microsoft.com", "live.com", "outlook.com", "office.com"] },
  { term: "netflix", domains: ["netflix.com"] },
  { term: "google", domains: ["google.com", "gmail.com"] },
  { term: "gmail", domains: ["gmail.com", "google.com"] },
  { term: "facebook", domains: ["facebook.com", "fb.com"] },
  { term: "instagram", domains: ["instagram.com"] },
  { term: "whatsapp", domains: ["whatsapp.com"] },
  { term: "usps", domains: ["usps.com"] },
  { term: "ups", domains: ["ups.com"] },
  { term: "fedex", domains: ["fedex.com"] },
  { term: "dhl", domains: ["dhl.com"] },
  { term: "irs", domains: ["irs.gov"] },
  { term: "social security", domains: ["ssa.gov"] },
  { term: "medicare", domains: ["medicare.gov"] },
  { term: "coinbase", domains: ["coinbase.com"] },
  { term: "binance", domains: ["binance.com"] },
  { term: "chase", domains: ["chase.com"] },
  { term: "wells fargo", domains: ["wellsfargo.com"] },
  { term: "hsbc", domains: ["hsbc.com"] },
  { term: "bank", domains: [] },
];

function matchEvidence(source: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const m = source.match(pattern);
    if (m) return (m[0] || "").trim();
  }
  return null;
}

function extractMessageLinks(message: string): string[] {
  const found = new Map<string, string>();
  const add = (raw: string) => {
    const link = raw.replace(/[.,;:!?)\]]+$/, "");
    const host = messageLinkHost(link);
    let pathname = "";
    if (host) {
      try {
        pathname = new URL(link.includes("://") ? link : `http://${link}`).pathname;
      } catch {
        pathname = "";
      }
    }
    const key = host ? `${host}${pathname}` : link.toLowerCase();
    const existing = found.get(key);
    // Prefer the version that carries an explicit scheme.
    if (!existing || (!existing.includes("://") && link.includes("://"))) found.set(key, link);
  };
  for (const raw of message.match(/https?:\/\/[^\s<>"')\]]+/gi) || []) add(raw);
  const bare = message.match(/\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:top|xyz|cc|buzz|club|cam|work|rest|shop|live|fit|online|link|info|tk|ml|ga|cf|gq|zip|mov|click|surf|loan|win|bid|icu|vip|ticket|website|ooo)\b[^\s<>"')\]]*/gi) || [];
  for (const raw of bare) add(raw);
  return [...found.values()];
}

function messageLinkHost(link: string): string | null {
  try {
    return new URL(link.includes("://") ? link : `http://${link}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function analyzeMessageLinks(message: string): { links: string[]; signals: MessageSignal[] } {
  const links = extractMessageLinks(message);
  const signals: MessageSignal[] = [];

  for (const link of links) {
    const host = messageLinkHost(link);
    const problems: string[] = [];
    let severity: SignalSeverity = "medium";
    let weight: number = MESSAGE_SIGNAL_WEIGHTS.urlMedium;

    if (host) {
      const tld = "." + host.split(".").slice(-1)[0];
      if (HIGH_RISK_TLDS.includes(tld)) {
        problems.push("high-abuse top-level domain");
        severity = "high";
        weight = MESSAGE_SIGNAL_WEIGHTS.suspiciousUrl;
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        problems.push("bare IP address instead of a domain");
        severity = "high";
        weight = MESSAGE_SIGNAL_WEIGHTS.suspiciousUrl;
      }
      if (host.includes("xn--")) {
        problems.push("punycode look-alike host");
        severity = "high";
        weight = MESSAGE_SIGNAL_WEIGHTS.suspiciousUrl;
      }
      if (MESSAGE_URL_SHORTENERS.has(host)) {
        problems.push("URL shortener hides the destination");
        severity = "high";
        weight = MESSAGE_SIGNAL_WEIGHTS.suspiciousUrl;
      }
      if (/^http:\/\//i.test(link)) problems.push("unencrypted http:// link");
      if (link.includes("@")) {
        problems.push("credentials embedded before the host");
        severity = "high";
        weight = MESSAGE_SIGNAL_WEIGHTS.suspiciousUrl;
      }
      if (/\b(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|password|billing|wallet)\b/.test((host + link).toLowerCase())) {
        problems.push("login/verification path on an unverified domain");
        weight = Math.max(weight, MESSAGE_SIGNAL_WEIGHTS.urlMedium);
      }
    } else {
      problems.push("malformed link");
    }

    if (problems.length) {
      signals.push({
        category: "suspicious_url",
        flag: "Suspicious / unverified link",
        evidence: link,
        severity,
        weight,
        tactic: "Malicious or Unverified Link",
        explanation: `The message links to ${host || link} (${problems.join("; ")}). Open the official site yourself instead of clicking this link.`,
        highlight: true,
      });
    }
  }

  return { links, signals };
}

function pickScamType(signals: MessageSignal[]): string {
  const has = (c: SignalCategory) => signals.some((s) => s.category === c);
  if (has("sensitive_credential") || has("credential_request")) return "Phishing & Credential Theft";
  if (has("job_offer")) return "Advance-Fee Job / Task Scam";
  if (has("reward")) return "Prize / Lottery Scam";
  if (has("threat")) return "Account Suspension / Threat Phishing";
  if (has("impersonation")) return "Brand / Authority Impersonation";
  if (has("financial")) return "Payment / Invoice Fraud";
  if (has("suspicious_url")) return "Malicious Link";
  if (has("urgency")) return "Pressure / Urgency Manipulation";
  return "Standard Message";
}

// Weighted, deterministic rule engine. Used as the authoritative risk signal.
export function ruleBasedScan(message: string, sender: string = "", platform: string = "") {
  const rawMessage = message || "";
  const text = `${rawMessage} ${sender}`.toLowerCase();
  const signals: MessageSignal[] = [];

  // 1) Urgency / time pressure --------------------------------------------
  const strongUrgency = matchEvidence(rawMessage, [
    /\bwithin\s+\d+\s*(?:minutes?|mins?|hours?|hrs?|days?|business\s+days?)\b/i,
    /\b(?:in|after)\s+the\s+next\s+\d+\s*(?:minutes?|mins?|hours?|hrs?|days?)\b/i,
    /\b(?:expires?|ends?|closes?|deactivated?)\b[^.\n]{0,24}\b(?:today|tonight|in\s+\d+|soon|within)\b/i,
    /\b(?:final|last)\s+(?:notice|warning|reminder|chance)\b/i,
    /\b(?:immediately|right\s+away|act\s+now|urgent(?:ly)?|asap|time[-\s]?sensitive|without\s+delay|act\s+fast)\b/i,
  ]);
  if (strongUrgency) {
    signals.push({
      category: "urgency",
      flag: "Artificial urgency / time pressure",
      evidence: strongUrgency,
      severity: "high",
      weight: MESSAGE_SIGNAL_WEIGHTS.urgencyStrong,
      tactic: "False Urgency & Time Pressure",
      explanation: "A hard deadline is used to rush you past the point where you would normally verify the sender.",
      highlight: true,
    });
  } else {
    const weakUrgency = matchEvidence(rawMessage, [/\b(?:urgent|important|attention|immediate|alert)\b/i]);
    if (weakUrgency) {
      signals.push({
        category: "urgency",
        flag: "Attention-grabbing language",
        evidence: weakUrgency,
        severity: "low",
        weight: MESSAGE_SIGNAL_WEIGHTS.urgencyWeak,
        tactic: "False Urgency & Time Pressure",
        explanation: "Attention-grabbing wording; harmless on its own but frequently used in scams.",
        highlight: true,
      });
    }
  }

  // 2) Fear / threat / account-suspension language -------------------------
  const threat = matchEvidence(rawMessage, [
    /\b(?:account|profile|card|access|service|subscription)\b[^.\n]{0,48}\b(?:suspend(?:ed|ing|sion)?|locked|blocked|closed|deactivated|disabled|restricted|terminated|frozen|compromised)\b/i,
    /\b(?:suspend(?:ed|ing)?|deactivat(?:e|ed)|terminat(?:e|ed)|lock(?:ed)?|restrict(?:ed)?|freez(?:e|ing|ed))\b[^.\n]{0,36}\b(?:account|profile|card|access|service)\b/i,
    /\b(?:unauthori[sz]ed|unusual|suspicious|unrecogni[sz]ed)\s+(?:access|activity|login|log-in|sign[-\s]?in|transaction|device|attempt)/i,
    /\b(?:legal action|law enforcement|permanent(?:ly)?\s+(?:disabled|closed|deleted|suspended)|failure to\s+(?:comply|verify|confirm|update|act))\b/i,
    /\b(?:avoid|prevent|stop)\b[^.\n]{0,30}\b(?:suspension|closure|termination|deactivation|blocking)\b/i,
    /\b(?:security alert|we (?:noticed|detected|observed)|important notice (?:about|regarding) your account)\b/i,
  ]);
  if (threat) {
    signals.push({
      category: "threat",
      flag: "Account threat / suspension language",
      evidence: threat,
      severity: "high",
      weight: MESSAGE_SIGNAL_WEIGHTS.threat,
      tactic: "Fear, Threat & Account Suspension",
      explanation: "Threatens that the account will be suspended, blocked or compromised in order to trigger panic.",
      highlight: true,
    });
  }

  // 3) Credential / account verification request ---------------------------
  const credentialRequest = matchEvidence(rawMessage, [
    /\b(?:verify|confirm|validate|update|re-?verify|reactivate|unlock|restore|secure)\b[^.\n]{0,32}\byour\s+(?:account|identity|details|information|info|password|payment|billing|profile|card|credentials)\b/i,
    /\b(?:confirm|verify)\s+(?:that\s+)?you\s+are\b/i,
    /\b(?:enter|provide|submit|confirm|send|re-?enter)\s+your\s+(?:password|pin|otp|one[-\s]?time\s+(?:code|password)|login|credentials|card|bank|security\s+code)\b/i,
    /\b(?:click|tap|follow)\b[^.\n]{0,24}\b(?:to|and)\b[^.\n]{0,24}\b(?:verify|confirm|validate|update|unlock|secure|reactivate)\b/i,
    /\b(?:unusual\s+sign[-\s]?in|new\s+device|someone\s+(?:has\s+)?(?:logged|signed)\s+in)\b/i,
    /\b(?:account|identity)\s+(?:verification|confirmation)\b/i,
  ]);
  if (credentialRequest) {
    signals.push({
      category: "credential_request",
      flag: "Request to verify account details",
      evidence: credentialRequest,
      severity: "high",
      weight: MESSAGE_SIGNAL_WEIGHTS.credentialRequest,
      tactic: "Credential / Identity Harvesting",
      explanation: "Asks you to verify or confirm account/identity details — the credential-harvesting step of a phishing attack.",
      highlight: true,
    });
  }

  // 4) Direct demand for a secret code / irreversible payment --------------
  // Benign security notices ("never share this code") are NOT treated as a demand.
  const benignSecretContext = /\b(?:never|do\s+not|don'?t|will\s+never|nobody|no\s+one)\b[^.\n]{0,40}\b(?:share|disclose|reveal|give|ask|request)\b/i;
  const secretDemand = matchEvidence(rawMessage, [
    /\b(?:share|send|enter|provide|give|tell|forward|confirm)\b[^.\n]{0,30}\b(?:passcode|otp|one[-\s]?time\s+(?:code|password)|2fa\s+code|verification\s+code|security\s+code|pin|password|seed\s+phrase|social\s+security\s+number|ssn)\b/i,
    /\b(?:gift\s+card|itunes\s+card|apple\s+card|google\s+play\s+card|wire\s+transfer|bitcoin|btc|cryptocurrency|usdt)\b/i,
  ]);
  if (secretDemand && !benignSecretContext.test(rawMessage)) {
    signals.push({
      category: "sensitive_credential",
      flag: "Demand for a secret code or untraceable payment",
      evidence: secretDemand,
      severity: "high",
      weight: MESSAGE_SIGNAL_WEIGHTS.sensitiveCredential,
      tactic: "Credential Harvesting / Irreversible Payment",
      explanation: "Requests a secret code, password or an untraceable payment method. Legitimate organisations never do this.",
      highlight: true,
    });
  }

  // 5) Links ----------------------------------------------------------------
  const linkAnalysis = analyzeMessageLinks(rawMessage);
  signals.push(...linkAnalysis.signals);
  const hasLink = linkAnalysis.links.length > 0;

  // 6) Impersonation (brand/authority named, link not on its official domain)
  const authority = MESSAGE_AUTHORITIES.find((a) => text.includes(a.term));
  if (authority) {
    const onOfficial = linkAnalysis.links.some((l) => {
      const h = messageLinkHost(l);
      return h ? authority.domains.some((d) => h === d || h.endsWith("." + d)) : false;
    });
    const suspiciousContext = signals.some(
      (s) => s.category === "threat" || s.category === "credential_request" || s.category === "urgency" || s.category === "suspicious_url"
    );
    if (linkAnalysis.links.length > 0 && !onOfficial && suspiciousContext) {
      signals.push({
        category: "impersonation",
        flag: "Brand / authority impersonation",
        evidence: authority.term,
        severity: "high",
        weight: MESSAGE_SIGNAL_WEIGHTS.impersonation,
        tactic: "Brand / Authority Impersonation",
        explanation: `The message names "${authority.term}" but links to a domain that is not its official website.`,
        highlight: true,
      });
    } else if (!linkAnalysis.links.length && suspiciousContext) {
      signals.push({
        category: "impersonation",
        flag: "Brand / authority impersonation",
        evidence: authority.term,
        severity: "medium",
        weight: MESSAGE_SIGNAL_WEIGHTS.impersonation,
        tactic: "Brand / Authority Impersonation",
        explanation: `The message claims to come from "${authority.term}" while also using pressure tactics.`,
        highlight: true,
      });
    }
  }

  // 7) Call to action -------------------------------------------------------
  const cta = matchEvidence(rawMessage, [
    /\bclick\s+(?:here|below|the\s+link|this\s+link|now)\b/i,
    /\b(?:sign|log)[-\s]?in\b/i,
    /\b(?:tap|open|follow)\s+(?:here|the\s+link|this\s+link|below)\b/i,
    /\b(?:call|phone|contact)\s+(?:us\s+)?(?:at|on|now|immediately|\+?\d)/i,
    /\b(?:download|open)\s+(?:and\s+)?(?:the\s+)?attachment\b/i,
    /\b(?:track|reschedule|redeliver)\s+(?:your\s+)?(?:package|parcel|order|shipment|delivery)\b/i,
    /\b(?:verify|update|confirm|claim|unlock|pay)\s+now\b/i,
    /\breply\s+(?:yes|now|stop|\d)\b/i,
  ]);
  if (cta) {
    signals.push({
      category: "call_to_action",
      flag: "Call to action / click pressure",
      evidence: cta,
      severity: "medium",
      weight: MESSAGE_SIGNAL_WEIGHTS.callToAction,
      tactic: "Action Pressure / Call To Action",
      explanation: "Pushes you towards an action (click, log in, call) without giving you a chance to verify independently.",
      highlight: true,
    });
  }

  // 8) Financial request ----------------------------------------------------
  const financial = matchEvidence(rawMessage, [
    /\b(?:outstanding\s+balance|unpaid\s+(?:balance|invoice|bill)|payment\s+(?:required|due|failed)|billing\s+(?:problem|issue)|refund|invoice\s+(?:attached|due))\b/i,
    /\b(?:wire|bank)\s+transfer\b/i,
    /\b(?:send|pay)\s+(?:us|me|\$|money)\b/i,
  ]);
  if (financial) {
    signals.push({
      category: "financial",
      flag: "Financial request / billing hook",
      evidence: financial,
      severity: "medium",
      weight: MESSAGE_SIGNAL_WEIGHTS.financial,
      tactic: "Financial Request",
      explanation: "Uses money (a payment, refund or billing problem) as the hook.",
      highlight: true,
    });
  }

  // 9) Unrealistic job / easy money ----------------------------------------
  const job = matchEvidence(rawMessage, [
    /\b(?:work\s+from\s+home|daily\s+pay|task\s+reviewer|hr\s+recruiter|telegram\s+recruiter|\$\d[\d,]*\s*[-–/]\s*\$\d[\d,]*\s*(?:\/|per\s+)?(?:day|week)|(?:\$|usd\s*)\d[\d,]*\s*(?:\/|per\s+)?(?:day|hour|week))\b/i,
  ]);
  if (job) {
    signals.push({
      category: "job_offer",
      flag: "Unrealistic high-pay job / task offer",
      evidence: job,
      severity: "high",
      weight: MESSAGE_SIGNAL_WEIGHTS.jobOffer,
      tactic: "Advance-Fee Task Scam",
      explanation: "Promises unusually high pay for trivial work — a hallmark of task and advance-fee scams.",
      highlight: true,
    });
  }

  // 10) Prize / reward bait -------------------------------------------------
  const reward = matchEvidence(rawMessage, [
    /\b(?:you(?:'ve|\s+have)?\s+won|winner|lottery|jackpot|claim\s+your\s+(?:prize|reward|gift)|free\s+(?:gift|money|prize)|selected\s+as\s+a\s+winner)\b/i,
  ]);
  if (reward) {
    signals.push({
      category: "reward",
      flag: "Too-good-to-be-true reward",
      evidence: reward,
      severity: "high",
      weight: MESSAGE_SIGNAL_WEIGHTS.reward,
      tactic: "Prize / Lottery Bait",
      explanation: "Claims you won something you never entered for — bait to harvest details or fees.",
      highlight: true,
    });
  }

  // 11) Combined phishing anatomy ------------------------------------------
  const hasUrgency = signals.some((s) => s.category === "urgency" && s.severity === "high");
  const hasThreat = signals.some((s) => s.category === "threat");
  const hasCredential = signals.some((s) => s.category === "credential_request" || s.category === "sensitive_credential");
  const hasSuspiciousLink = signals.some((s) => s.category === "suspicious_url" && s.severity === "high");
  if (hasUrgency && hasThreat && hasCredential && (hasSuspiciousLink || hasLink)) {
    signals.push({
      category: "combined",
      flag: "Multi-signal phishing pattern",
      evidence: "urgency + account threat + credential request + suspicious link",
      severity: "high",
      weight: MESSAGE_SIGNAL_WEIGHTS.combined,
      tactic: "Multi-Signal Phishing Attack",
      explanation: "Combines time pressure, an account threat, a request to verify account details and a suspicious login link — the textbook anatomy of a phishing attack.",
      highlight: false,
    });
  }

  // ---- Score + verdict (rule engine is authoritative) ---------------------
  const highCount = signals.filter((s) => s.severity === "high").length;
  const mediumCount = signals.filter((s) => s.severity === "medium").length;
  let score = Math.min(100, 6 + signals.reduce((sum, s) => sum + s.weight, 0));

  let safetyStatus: "SAFE" | "SUSPICIOUS" | "DANGEROUS_SCAM" = "SAFE";
  // Multiple high-risk signals, or a high aggregate score, = HIGH RISK.
  if (highCount >= 2 || score >= 60) {
    score = Math.max(score, 60);
    safetyStatus = "DANGEROUS_SCAM";
  } else if (highCount >= 1 || mediumCount >= 2 || score >= 28) {
    safetyStatus = "SUSPICIOUS";
  }

  const redFlags = Array.from(
    new Map(
      signals.map((s) => [
        `${s.flag}|${s.evidence}`,
        { flag: s.flag, evidence: s.evidence, severity: s.severity },
      ])
    ).values()
  );
  const tacticsUsed = Array.from(new Set(signals.map((s) => s.tactic)));
  const highlightPhrases = Array.from(
    new Map(
      signals
        .filter((s) => s.highlight)
        .filter((s) => rawMessage.toLowerCase().includes(s.evidence.toLowerCase()))
        .map((s) => [
          s.evidence.toLowerCase(),
          {
            text: s.evidence,
            category: s.category === "suspicious_url" ? ("suspicious_link" as const) : s.severity === "high" ? ("danger" as const) : ("warning" as const),
            explanation: s.explanation,
          },
        ])
    ).values()
  );

  const topReasons = Array.from(new Set(signals.filter((s) => s.severity === "high").map((s) => s.flag))).slice(0, 4);
  const scamType = pickScamType(signals);

  let verdictSummary: string;
  if (safetyStatus === "DANGEROUS_SCAM") {
    verdictSummary = `High risk — ${topReasons.length ? topReasons.join("; ") : "multiple fraud indicators"}. Do not click links, reply, or share any codes or payment details.`;
  } else if (safetyStatus === "SUSPICIOUS") {
    const reasons = (topReasons.length ? topReasons : Array.from(new Set(signals.map((s) => s.flag)))).slice(0, 3);
    verdictSummary = `Caution — ${reasons.length ? reasons.join("; ") : "signals of concern"}. Verify the sender through an official channel before acting.`;
  } else {
    verdictSummary = "No significant scam signals detected. Still verify the sender if the message was unexpected.";
  }

  const isSafe = safetyStatus === "SAFE";

  return {
    safetyStatus,
    riskScore: score,
    scamType,
    verdictSummary,
    redFlags,
    tacticsUsed,
    highlightPhrases,
    safetyAdvice: {
      immediateActions: isSafe
        ? [
            "No immediate action needed.",
            "If the message was unexpected, confirm with the sender through a channel you already trust.",
          ]
        : [
            "Do NOT click links or download attachments in this message.",
            "Open the organisation's official app, or type its web address manually.",
            "Report the message as phishing/spam and block the sender.",
          ],
      whatNeverToDo: isSafe
        ? ["Never share One-Time Passcodes (OTP), passwords or 2FA codes — even if someone claims to be support."]
        : [
            "Never share One-Time Passcodes (OTP), passwords or 2FA credentials.",
            "Never pay via gift cards, wire transfer or cryptocurrency.",
            "Never call back a phone number supplied in the message.",
          ],
      officialVerificationStep: "Navigate to the company's official website or app directly — never use the link or phone number provided in the message.",
    },
    recommendedResponse: isSafe
      ? "No response needed. If unexpected, ignore or delete the message."
      : "Do not reply, click, or call. Block the sender and report the message as phishing.",
    senderAssessment: {
      isSenderSuspicious:
        signals.some((s) => s.category === "impersonation") ||
        (Boolean(sender) && /(?:\.top|\.xyz|\.cc|\.buzz|\.tk|\.ml|\.ga|\.cf|\.gq|\.icu|\.vip|\.click|\.link|\.online|\.live)$/i.test(sender.trim())),
      notes: sender ? `Sender identifier '${sender}' was not independently verified.` : "Sender details not specified.",
    },
    signalBreakdown: signals.map((s) => ({
      category: s.category,
      flag: s.flag,
      severity: s.severity,
      weight: s.weight,
      tactic: s.tactic,
    })),
  };
}

export type MessageHeuristic = ReturnType<typeof ruleBasedScan>;

function normalizeSafetyStatus(value: any): "SAFE" | "SUSPICIOUS" | "DANGEROUS_SCAM" {
  const v = String(value || "").toUpperCase();
  if (v.includes("DANGER") || v.includes("SCAM") || v.includes("HIGH") || v.includes("MALICIOUS")) return "DANGEROUS_SCAM";
  if (v.includes("SUSPIC") || v.includes("CAUTION") || v.includes("WARN") || v.includes("MEDIUM")) return "SUSPICIOUS";
  return "SAFE";
}

function dedupeBy<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    const k = key(item);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(item);
  }
  return out;
}

/**
 * Combine the deterministic rule engine with Gemini's semantic analysis.
 *
 * The rule engine owns the score. Gemini supplies semantic reasoning and can
 * RAISE the severity (semantic catch) but can NEVER lower a stronger
 * deterministic verdict — so a message with confirmed urgency, account-threat,
 * credential-request and suspicious-link signals stays HIGH RISK even if the
 * model calls it "safe".
 */
export function combineMessageAnalysis(heuristic: MessageHeuristic, gemini: any | null) {
  if (!gemini) {
    return { ...heuristic, engine: "heuristic-rules" };
  }

  const rank: Record<string, number> = { SAFE: 0, SUSPICIOUS: 1, DANGEROUS_SCAM: 2 };
  const hStatus = heuristic.safetyStatus as string;
  const gStatus = normalizeSafetyStatus(gemini.safetyStatus);
  const gemScore = typeof gemini.riskScore === "number" ? Math.max(0, Math.min(100, gemini.riskScore)) : 0;

  // Rule engine dominates the score; deterministic signals set a hard floor.
  const blended = Math.round(heuristic.riskScore * 0.6 + gemScore * 0.4);
  const deterministicFloor = hStatus === "DANGEROUS_SCAM" ? 70 : hStatus === "SUSPICIOUS" ? 45 : 0;
  const riskScoreFloor = Math.min(100, Math.max(blended, deterministicFloor));
  let riskScore = riskScoreFloor;

  const hRank = rank[hStatus] ?? 0;
  const gRank = rank[gStatus] ?? 0;
  // Gemini can escalate but never de-escalate a stronger deterministic verdict.
  let safetyStatus: "SAFE" | "SUSPICIOUS" | "DANGEROUS_SCAM" = (hRank >= gRank ? hStatus : gStatus) as any;
  if (riskScore >= 60 && (rank[safetyStatus] ?? 0) < 2) safetyStatus = "DANGEROUS_SCAM";
  else if (riskScore >= 28 && (rank[safetyStatus] ?? 0) < 1) safetyStatus = "SUSPICIOUS";

  // Keep the numeric score consistent with the final badge.
  if (safetyStatus === "DANGEROUS_SCAM") riskScore = Math.max(riskScore, 65);
  else if (safetyStatus === "SUSPICIOUS") riskScore = Math.max(riskScore, 30);

  const redFlags = dedupeBy(
    [...(heuristic.redFlags || []), ...(Array.isArray(gemini.redFlags) ? gemini.redFlags : [])],
    (f: any) => `${String(f?.flag || "").toLowerCase()}|${String(f?.evidence || "").toLowerCase()}`
  );
  const tacticsUsed = Array.from(new Set([...(heuristic.tacticsUsed || []), ...(Array.isArray(gemini.tacticsUsed) ? gemini.tacticsUsed : [])]));
  const highlightPhrases = dedupeBy(
    [...(heuristic.highlightPhrases || []), ...(Array.isArray(gemini.highlightPhrases) ? gemini.highlightPhrases : [])],
    (h: any) => String(h?.text || "").toLowerCase()
  );

  const highReasons = Array.from(
    new Set((heuristic.redFlags || []).filter((f: any) => f.severity === "high").map((f: any) => f.flag))
  ).slice(0, 4) as string[];
  const deterministicOverride = hRank > gRank;

  let verdictSummary = "";
  if (hRank >= 1 && highReasons.length) {
    verdictSummary += `Deterministic threat signals: ${highReasons.join("; ")}. `;
  }
  if (typeof gemini.verdictSummary === "string" && gemini.verdictSummary.trim()) {
    verdictSummary += gemini.verdictSummary.trim();
  }
  if (!verdictSummary.trim()) verdictSummary = heuristic.verdictSummary;
  if (deterministicOverride) {
    verdictSummary += " (The AI assessment was overridden by these deterministic security signals.)";
  }

  return {
    safetyStatus,
    riskScore,
    scamType:
      typeof gemini.scamType === "string" && gemini.scamType && !/legitimate/i.test(gemini.scamType)
        ? gemini.scamType
        : heuristic.scamType,
    verdictSummary,
    redFlags,
    tacticsUsed,
    highlightPhrases,
    safetyAdvice: gemini.safetyAdvice || heuristic.safetyAdvice,
    recommendedResponse:
      typeof gemini.recommendedResponse === "string" && gemini.recommendedResponse
        ? gemini.recommendedResponse
        : heuristic.recommendedResponse,
    senderAssessment: {
      isSenderSuspicious: Boolean(heuristic.senderAssessment?.isSenderSuspicious || gemini.senderAssessment?.isSenderSuspicious),
      notes: (gemini.senderAssessment?.notes && String(gemini.senderAssessment.notes)) || heuristic.senderAssessment?.notes || "",
    },
    signalBreakdown: heuristic.signalBreakdown,
    deterministicVerdict: hStatus,
    aiVerdict: gStatus,
    deterministicOverride,
    engine: "gemini-3.8-flash+heuristic",
  };
}

// API Health Check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    hasGeminiKey: Boolean(process.env.GEMINI_API_KEY),
    time: new Date().toISOString(),
  });
});

// Extract text from image (Screenshot OCR)
app.post("/api/extract-image", async (req, res) => {
  try {
    const { imageBase64, mimeType = "image/png" } = req.body;
    if (!imageBase64) {
      return res.status(400).json({ error: "Missing imageBase64 data" });
    }

    const ai = getGenAI();
    if (!ai) {
      return res.status(503).json({ error: "Gemini API key is not configured" });
    }

    // Clean base64 header if included
    const cleanBase64 = imageBase64.replace(/^data:image\/[a-z]+;base64,/, "");

    const response = await ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: {
        parts: [
          {
            inlineData: {
              mimeType: mimeType,
              data: cleanBase64,
            },
          },
          {
            text: `Carefully inspect this screenshot of an inbox message, text message, or social app DM.
Extract:
1. The message body text exactly as written.
2. The sender name, phone number, email address, or social handle if visible.
3. The platform interface (e.g., 'SMS / iMessage', 'Gmail / Email', 'WhatsApp', 'Instagram DM', 'Telegram', 'Bank SMS').
Return JSON format matching:
{
  "extractedText": "exact text from the message bubble or email",
  "sender": "sender info or empty string if not visible",
  "platform": "detected platform"
}`,
          },
        ],
      },
      config: {
        responseMimeType: "application/json",
      },
    });

    const parsed = JSON.parse(response.text || "{}");
    return res.json({
      success: true,
      extractedText: parsed.extractedText || "",
      sender: parsed.sender || "",
      platform: parsed.platform || "Other",
    });
  } catch (error: any) {
    console.error("Error in /api/extract-image:", error);
    return res.status(500).json({ error: error?.message || "Failed to parse image screenshot" });
  }
});

// Deep Scam & Safety Analysis endpoint
app.post("/api/analyze-message", async (req, res) => {
  try {
    const { message, sender = "", platform = "Other", imageBase64 = null, imageMime = "image/png" } = req.body;

    if (!message && !imageBase64) {
      return res.status(400).json({ error: "Please provide a message or screenshot to analyze." });
    }

    const ai = getGenAI();
    const heuristic = ruleBasedScan(message || "", sender, platform);

    // If no Gemini API key available, return the deterministic rule engine.
    if (!ai) {
      return res.json({
        ...heuristic,
        engine: "heuristic-rules",
        notice: "AI engine key not detected; running the deterministic threat rule engine.",
      });
    }

    const promptText = `You are the semantic-analysis layer of "Online Safety Guard", a cybersecurity and anti-fraud detection system.
Analyze the message, sender and platform context for scam, phishing, social engineering, smishing, identity theft or financial fraud.

Message Text:
"""
${message || "(Message provided via screenshot)"}
"""

Sender details: ${sender || "Not provided"}
Platform: ${platform || "General Message"}

Rules you MUST follow:
1. NEVER return SAFE / low risk when the message contains any of:
   - artificial urgency or a deadline (e.g. "within 30 minutes", "immediately", "final notice");
   - account-suspension or threat language (suspended, blocked, locked, unauthorized access, legal action);
   - a request to verify / confirm / update account, identity, password or payment details;
   - a suspicious, shortened, unverified or login/verify link.
   Any such signal makes the message AT LEAST SUSPICIOUS; multiple such signals make it DANGEROUS_SCAM.
2. Only use SAFE when there are genuinely no significant suspicious signals (e.g. an authentic 2FA code that says "never share this code", a real calendar invite, a benign greeting).
3. Explain the EXACT reasons with short quotes, identify psychological tactics (urgency, fear, greed, authority spoofing) and break down deceptive links.
4. Focus on semantic understanding and explanation: a deterministic rule engine independently scores this message, so be accurate rather than lenient.

Provide the analysis as valid JSON matching the exact schema.`;

    const parts: any[] = [];
    if (imageBase64) {
      const cleanBase64 = imageBase64.replace(/^data:image\/[a-z]+;base64,/, "");
      parts.push({
        inlineData: {
          mimeType: imageMime,
          data: cleanBase64,
        },
      });
    }
    parts.push({ text: promptText });

    let analyzeTimer: NodeJS.Timeout | undefined;
    const response: any = await Promise.race([
      ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: { parts },
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            safetyStatus: {
              type: Type.STRING,
              description: "'SAFE', 'SUSPICIOUS', or 'DANGEROUS_SCAM'",
            },
            riskScore: {
              type: Type.INTEGER,
              description: "Scam probability score from 0 (completely benign/safe) to 100 (definite scam/malicious)",
            },
            scamType: {
              type: Type.STRING,
              description: "Category of scam (e.g., 'Phishing & Credential Theft', 'Urgent Banking Smishing', 'Advance-Fee Job Scam', 'Delivery Fee Phishing', 'Romance Scam', 'Tech Support Extortion', 'Crypto Fraud', or 'Legitimate Notification')",
            },
            verdictSummary: {
              type: Type.STRING,
              description: "Clear, direct 2-sentence summary explaining why this is or isn't a scam.",
            },
            redFlags: {
              type: Type.ARRAY,
              description: "Specific red flags identified in the message",
              items: {
                type: Type.OBJECT,
                properties: {
                  flag: { type: Type.STRING, description: "Name of the red flag" },
                  evidence: { type: Type.STRING, description: "Specific quote or indicator from message" },
                  severity: { type: Type.STRING, description: "'high', 'medium', or 'low'" },
                },
                required: ["flag", "evidence", "severity"],
              },
            },
            tacticsUsed: {
              type: Type.ARRAY,
              description: "Psychological and technical tactics used (e.g. 'False Urgency', 'Brand Impersonation', 'Typosquatting')",
              items: { type: Type.STRING },
            },
            highlightPhrases: {
              type: Type.ARRAY,
              description: "Key phrases to highlight for the user with an explanation",
              items: {
                type: Type.OBJECT,
                properties: {
                  text: { type: Type.STRING, description: "Exact excerpt from the message" },
                  category: { type: Type.STRING, description: "'danger', 'warning', or 'suspicious_link'" },
                  explanation: { type: Type.STRING, description: "Why this phrase is dangerous or notable" },
                },
                required: ["text", "category", "explanation"],
              },
            },
            safetyAdvice: {
              type: Type.OBJECT,
              properties: {
                immediateActions: {
                  type: Type.ARRAY,
                  items: { type: Type.STRING },
                  description: "Safe steps the user should do right now",
                },
                whatNeverToDo: {
                  type: Type.ARRAY,
                  items: { type: Type.STRING },
                  description: "Dangerous actions the user must avoid",
                },
                officialVerificationStep: {
                  type: Type.STRING,
                  description: "How to safely contact or verify the genuine organization",
                },
              },
              required: ["immediateActions", "whatNeverToDo", "officialVerificationStep"],
            },
            recommendedResponse: {
              type: Type.STRING,
              description: "Recommended response or defensive action (e.g., 'Do not reply, block and report', or safe neutral template)",
            },
            senderAssessment: {
              type: Type.OBJECT,
              properties: {
                isSenderSuspicious: { type: Type.BOOLEAN },
                notes: { type: Type.STRING, description: "Assessment of the sender address, handle, or number" },
              },
              required: ["isSenderSuspicious", "notes"],
            },
          },
          required: [
            "safetyStatus",
            "riskScore",
            "scamType",
            "verdictSummary",
            "redFlags",
            "tacticsUsed",
            "highlightPhrases",
            "safetyAdvice",
            "recommendedResponse",
            "senderAssessment",
          ],
        },
      },
      }),
      new Promise((_resolve, reject) => {
        analyzeTimer = setTimeout(() => reject(new Error("ai-timeout")), GEMINI_TIMEOUT_MS);
        analyzeTimer.unref?.();
      }),
    ]);
    if (analyzeTimer) clearTimeout(analyzeTimer);

    const parsed = JSON.parse(response.text || "{}");
    // Combine ALL signals: Gemini supplies semantic reasoning/explanation, the
    // rule engine owns the score and cannot be overridden by a "safe" AI verdict.
    return res.json(combineMessageAnalysis(heuristic, parsed));
  } catch (error: any) {
    console.error("Error analyzing message with Gemini:", error);
    // Graceful fallback to the deterministic rule engine
    const fallback = ruleBasedScan(req.body.message || "", req.body.sender, req.body.platform);
    return res.json({
      ...combineMessageAnalysis(fallback, null),
      errorDetails: error?.message || "AI service temporarily unavailable; using the deterministic rule engine.",
    });
  }
});

// ============================================================================
// URL / Link Threat Inspection Engine
// Analyses the COMPLETE URL: scheme, userinfo, subdomains, registrable domain,
// path, query, redirects, typosquatting and brand impersonation, plus a live
// malware-reputation check. Verdicts are evidence-gated: we only claim
// "Likely Authentic" when there is affirmative evidence (exact match against a
// vetted brand's official domain or an AI confirmation + clean reputation).
// ============================================================================

const SUSPICIOUS_TLDS = [
  ".top", ".xyz", ".cc", ".buzz", ".cam", ".rest", ".club", ".fit", ".tk",
  ".ml", ".ga", ".cf", ".gq", ".work", ".zip", ".mov", ".click", ".link",
  ".surf", ".loan", ".win", ".bid", ".racing", ".stream", ".download",
  ".review", ".date", ".party", ".mom", ".lol", ".kim", ".gdn", ".vip",
  ".icu", ".trade", ".science", ".sucks", ".website", ".ooo", ".ticket",
];

const MULTI_PART_SUFFIXES = [
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "com.mx", "org.mx", "net.mx", "gob.mx", "edu.mx",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in",
  "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
  "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
  "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "biz.tr",
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar", "gob.ar",
  "co.kr", "or.kr", "ne.kr", "re.kr", "go.kr", "ac.kr",
  "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua", "in.ua",
  "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
  "com.my", "net.my", "org.my", "edu.my", "gov.my",
  "co.id", "or.id", "web.id", "ac.id", "go.id", "net.id", "sch.id",
  "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
  "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
  "com.eg", "org.eg", "net.eg", "gov.eg", "edu.eg",
  "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
  "co.il", "org.il", "ac.il", "gov.il", "muni.il", "net.il",
  "co.th", "or.th", "ac.th", "go.th", "in.th", "net.th",
  "com.ng", "org.ng", "net.ng", "gov.ng", "edu.ng",
  "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
];

interface BrandEntry {
  name: string;
  domains: string[];
  tokens: string[];
}

const KNOWN_BRANDS: BrandEntry[] = [
  { name: "PayPal", domains: ["paypal.com"], tokens: ["paypal", "paypa"] },
  { name: "Apple", domains: ["apple.com", "icloud.com", "appleid.apple.com"], tokens: ["apple", "icloud", "appl"] },
  { name: "Google", domains: ["google.com", "gmail.com", "youtube.com", "youtu.be", "googleusercontent.com"], tokens: ["google", "gmail", "youtube", "g0ogle"] },
  { name: "Microsoft", domains: ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"], tokens: ["microsoft", "outlook", "msn", "office365", "live"] },
  { name: "Amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in", "amazon.ca", "amazon.co.jp", "amazon.com.au"], tokens: ["amazon", "amzn", "prime"] },
  { name: "Netflix", domains: ["netflix.com"], tokens: ["netflix"] },
  { name: "Instagram", domains: ["instagram.com"], tokens: ["instagram", "insta"] },
  { name: "WhatsApp", domains: ["whatsapp.com", "whatsapp.net"], tokens: ["whatsapp"] },
  { name: "Facebook", domains: ["facebook.com", "fb.com", "fb.me"], tokens: ["facebook", "fb"] },
  { name: "Meta", domains: ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"], tokens: ["meta"] },
  { name: "X / Twitter", domains: ["twitter.com", "x.com", "t.co"], tokens: ["twitter", "twtr"] },
  { name: "LinkedIn", domains: ["linkedin.com", "lnkd.in"], tokens: ["linkedin", "lnkd"] },
  { name: "TikTok", domains: ["tiktok.com"], tokens: ["tiktok", "tik-tok"] },
  { name: "Snapchat", domains: ["snapchat.com"], tokens: ["snapchat", "snap"] },
  { name: "Bank of America", domains: ["bankofamerica.com", "bofa.com"], tokens: ["bankofamerica", "bofa"] },
  { name: "Chase", domains: ["chase.com", "jpmorgan.com", "chase.com"], tokens: ["chase", "jpmorgan"] },
  { name: "Wells Fargo", domains: ["wellsfargo.com"], tokens: ["wellsfargo", "wf"] },
  { name: "Citibank", domains: ["citi.com", "citibank.com"], tokens: ["citi", "citibank"] },
  { name: "Capital One", domains: ["capitalone.com"], tokens: ["capitalone", "capone"] },
  { name: "American Express", domains: ["americanexpress.com", "amex.com"], tokens: ["americanexpress", "amex"] },
  { name: "HSBC", domains: ["hsbc.com"], tokens: ["hsbc"] },
  { name: "Barclays", domains: ["barclays.com", "barclays.co.uk"], tokens: ["barclays"] },
  { name: "USPS", domains: ["usps.com"], tokens: ["usps", "postal"] },
  { name: "FedEx", domains: ["fedex.com"], tokens: ["fedex"] },
  { name: "UPS", domains: ["ups.com"], tokens: ["ups"] },
  { name: "DHL", domains: ["dhl.com", "dhlexpress.com"], tokens: ["dhl", "express"] },
  { name: "Coinbase", domains: ["coinbase.com"], tokens: ["coinbase"] },
  { name: "Binance", domains: ["binance.com"], tokens: ["binance"] },
  { name: "Ethereum", domains: ["ethereum.org"], tokens: ["ethereum", "eth"] },
  { name: "MetaMask", domains: ["metamask.io"], tokens: ["metamask"] },
  { name: "eBay", domains: ["ebay.com"], tokens: ["ebay"] },
  { name: "Adobe", domains: ["adobe.com"], tokens: ["adobe"] },
  { name: "GitHub", domains: ["github.com"], tokens: ["github"] },
  { name: "Dropbox", domains: ["dropbox.com"], tokens: ["dropbox"] },
  { name: "Steam", domains: ["steampowered.com", "steamcommunity.com"], tokens: ["steam"] },
  { name: "Zoom", domains: ["zoom.us", "zoom.com"], tokens: ["zoom"] },
  { name: "Slack", domains: ["slack.com"], tokens: ["slack"] },
  { name: "Robinhood", domains: ["robinhood.com"], tokens: ["robinhood"] },
  { name: "Venmo", domains: ["venmo.com"], tokens: ["venmo"] },
  { name: "Zelle", domains: ["zellepay.com"], tokens: ["zelle"] },
  { name: "Western Union", domains: ["westernunion.com"], tokens: ["westernunion"] },
  { name: "Walmart", domains: ["walmart.com"], tokens: ["walmart", "walmar"] },
  { name: "Target", domains: ["target.com"], tokens: ["target"] },
  { name: "Costco", domains: ["costco.com"], tokens: ["costco"] },
  { name: "Home Depot", domains: ["homedepot.com"], tokens: ["homedepot"] },
  { name: "Best Buy", domains: ["bestbuy.com"], tokens: ["bestbuy"] },
  { name: "Verizon", domains: ["verizon.com", "verizonwireless.com"], tokens: ["verizon"] },
  { name: "AT&T", domains: ["att.com"], tokens: ["att"] },
  { name: "T-Mobile", domains: ["t-mobile.com"], tokens: ["tmobile", "t-mobile"] },
  { name: "Samsung", domains: ["samsung.com"], tokens: ["samsung"] },
  { name: "Spotify", domains: ["spotify.com"], tokens: ["spotify"] },
  { name: "Uber", domains: ["uber.com"], tokens: ["uber"] },
  { name: "Lyft", domains: ["lyft.com"], tokens: ["lyft"] },
  { name: "Airbnb", domains: ["airbnb.com"], tokens: ["airbnb"] },
  { name: "Booking.com", domains: ["booking.com"], tokens: ["booking"] },
  { name: "Expedia", domains: ["expedia.com"], tokens: ["expedia"] },
  { name: "Payoneer", domains: ["payoneer.com"], tokens: ["payoneer"] },
  { name: "Skrill", domains: ["skrill.com"], tokens: ["skrill"] },
  { name: "Cash App", domains: ["cash.app"], tokens: ["cashapp"] },
  { name: "IRS", domains: ["irs.gov"], tokens: ["irs", "taxrefund"] },
  { name: "U.S. Treasury", domains: ["treasury.gov"], tokens: ["treasury"] },
  { name: "Social Security Administration", domains: ["ssa.gov"], tokens: ["ssa", "socialsecurity"] },
];

// Basic homoglyph normalisation (Cyrillic & lookalike scripts mapped to ASCII)
const HOMOGLYPHS: Record<string, string> = {
  а: "a", е: "e", і: "i", о: "o", р: "p", с: "c", у: "y", х: "x", һ: "h",
  ј: "j", к: "k", ѕ: "s", т: "t", ѵ: "v", ո: "n", ⅼ: "l", ı: "i", ɑ: "a",
  ɢ: "g", ʀ: "r", ʙ: "b", ʟ: "l", ǫ: "q", ɡ: "g", ⅰ: "i", ⅴ: "v", ⅹ: "x",
  ᴇ: "e", ᴡ: "w",
};

function normalizeForMatch(s: string): string {
  return s
    .toLowerCase()
    .replace(/[а-яіїєґѡ]/gi, (ch) => HOMOGLYPHS[ch.toLowerCase()] ?? ch)
    .replace(/ı/g, "i")
    .replace(/ⅼ/g, "l")
    .replace(/ⅰ/g, "i")
    .replace(/ⅴ/g, "v")
    .replace(/ⅹ/g, "x");
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

interface UrlFlag {
  severity: "high" | "medium" | "low";
  title: string;
  evidence: string;
  explanation: string;
}

interface ParsedUrl {
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

// eTLD+1 extraction backed by the public suffix list (tldts). Falls back to a
// compact multi-part-suffix table for hosts the PSL parse cannot classify.
export function getRegistrableDomain(hostnameRaw: string): string {
  let host = hostnameRaw.toLowerCase().replace(/\.$/, "");
  if (!host) return host;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":")) return host;
  try {
    const parsedTldts = parseTldts(host);
    if (parsedTldts.domain) return parsedTldts.domain;
  } catch {
    // fall through to the manual table below
  }
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    if (MULTI_PART_SUFFIXES.includes(labels.slice(i).join("."))) {
      return labels.slice(Math.max(0, i - 1)).join(".");
    }
  }
  if (labels.length < 2) return host;
  return labels.slice(-2).join(".");
}

export function parseUrl(raw: string): ParsedUrl {
  let input = raw.trim();
  let cleanUrl = input;
  let scheme = "";
  const schemeMatch = input.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase();
    if (!["http", "https"].includes(scheme)) {
      // Non-http(s) scheme – keep as-is, we will flag it.
    } else if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input)) {
      // http:foo  -> normalise to http://foo
      cleanUrl = input.replace(/^http:/, "http://").replace(/^https:/, "https://");
    }
  } else {
    cleanUrl = "https://" + input;
    scheme = "https";
  }

  const fallback: ParsedUrl = {
    input,
    cleanUrl,
    scheme,
    hostname: cleanUrl.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "").split(/[/?#]/)[0],
    port: null,
    username: "",
    hasAuth: false,
    isIpAddress: false,
    registrableDomain: cleanUrl.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "").split(/[/?#]/)[0],
    subdomainLabels: [],
    pathname: "",
    search: "",
    hash: "",
  };

  let u: URL;
  try {
    u = new URL(cleanUrl);
  } catch {
    return fallback;
  }

  let hostname = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");
  const registrableDomain = isIpAddress ? hostname : getRegistrableDomain(hostname);
  const subdomainPart = hostname.slice(0, hostname.length - registrableDomain.length).replace(/\.$/, "");
  const subdomainLabels = subdomainPart ? subdomainPart.split(".") : [];

  return {
    input,
    cleanUrl: u.href,
    scheme: u.protocol.replace(":", ""),
    hostname,
    port: u.port || null,
    username: u.username,
    hasAuth: Boolean(u.username || u.password),
    isIpAddress,
    registrableDomain,
    subdomainLabels,
    pathname: u.pathname,
    search: u.search,
    hash: u.hash,
  };
}

interface BrandAnalysis {
  flags: UrlFlag[];
  spoofedBrand: string | null;
  officialBrandName: string | null;
  officialDomain: string | null;
  officialMatch: boolean; // hostname equals a known official domain or is a legitimate subdomain of one
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Suffixes commonly appended to brand names in phishing domains (no hyphens).
const PHISH_WORD_SUFFIXES = [
  "verify", "verification", "verified", "login", "signin", "sign-in", "secure", "security",
  "support", "help", "restore", "redelivery", "recovery", "recover", "appeal", "account",
  "update", "confirm", "confirmacion", "validate", "password", "reset", "billing",
  "invoice", "payment", "auth", "authentication", "2fa", "otp", "track", "tracking",
  "page", "form", "claim", "prize", "reward", "bonus", "free", "official", "center",
  "service", "portal", "wallet", "protection",
];

// Does a suspected-brand token plausibly appear inside an unrelated registrable domain?
function tokenMatchesRegistrableDomain(regNorm: string, tokenNorm: string): boolean {
  if (tokenNorm.length < 3) return false;
  // 1) Exact match against a hyphen/dot-separated segment: chase-security-restore.cc -> "chase"
  if (regNorm.split(/[-.]/).some((s) => s === tokenNorm)) return true;
  // 2) Long, distinctive token appears anywhere: bankofamericaverify.com
  if (tokenNorm.length >= 7 && regNorm.includes(tokenNorm)) return true;
  // 3) Registered single-label domain starts with the token followed by a phishing-y suffix (chaseverify.com)
  const sld = regNorm.split(".")[0];
  if (sld.startsWith(tokenNorm) && sld.length > tokenNorm.length) {
    if (tokenNorm.length >= 7) return true;
    const remainder = sld.slice(tokenNorm.length);
    if (PHISH_WORD_SUFFIXES.some((suf) => remainder.startsWith(suf))) return true;
  }
  return false;
}

// Does a brand token appear inside the subdomain labels of an unrelated host?
function tokenMatchesSubdomains(labelsJoined: string, tokenNorm: string, officialDomains: string[], hostname: string): boolean {
  if (tokenNorm.length < 3) return false;
  if (officialDomains.some((d) => hostname.toLowerCase().endsWith("." + d.toLowerCase()) || hostname.toLowerCase() === d.toLowerCase())) {
    return false; // legitimate subdomain of an official domain
  }
  for (const label of labelsJoined.split(".")) {
    if (label === tokenNorm) return true;
    if (new RegExp(`(^|[-_.])${escapeRegExp(tokenNorm)}([-_.]|$)`).test(label)) return true;
    if (tokenNorm.length >= 7 && label.length > tokenNorm.length && label.startsWith(tokenNorm)) return true;
  }
  return false;
}

function analyzeBrand(parsed: ParsedUrl): BrandAnalysis {
  const flags: UrlFlag[] = [];
  const host = parsed.hostname.replace(/\.$/, "");
  const reg = parsed.registrableDomain.replace(/\.$/, "");
  const regNorm = normalizeForMatch(reg);

  let officialMatch = false;
  let officialBrandName: string | null = null;
  let officialDomain: string | null = null;
  let spoofedBrand: string | null = null;

  for (const brand of KNOWN_BRANDS) {
    const officialHit = brand.domains.find((d) => {
      const off = d.toLowerCase().replace(/\.$/, "");
      return host === off || host.endsWith("." + off);
    });

    if (officialHit) {
      officialMatch = true;
      officialBrandName = brand.name;
      officialDomain = officialHit;
      continue; // legitimate official match – skip impersonation checks for this brand
    }

    // 1) Brand domain planted inside a third-party hostname:
    //    paypal.com.evil.xyz, www.paypal.com.evil.xyz, secure-paypal.com.login.evil.xyz
    for (const off of brand.domains.map((d) => d.toLowerCase().replace(/\.$/, ""))) {
      // Matches "paypal.com." appearing anywhere in the hostname with another
      // label following it (the "." after the brand domain is required so
      // "notpaypal.com" is not a hit).
      const embedded = new RegExp(`(^|\\.)${escapeRegExp(off)}\\.`);
      if (embedded.test(host)) {
        flags.push({
          severity: "high",
          title: "Brand domain planted inside a third-party hostname",
          evidence: host,
          explanation: `The hostname contains '${off}' followed by more labels (${parsed.registrableDomain} is the real registered domain). Text before the first '/' is the actual destination host, so this is a classic domain-embedding trick.`,
        });
        if (!spoofedBrand) spoofedBrand = brand.name;
        break;
      }
    }

    // 2) Typosquatting against the registrable domain (Levenshtein <= 2)
    const brandReg = getRegistrableDomain(brand.domains[0]).replace(/\.$/, "");
    const brandRegNorm = normalizeForMatch(brandReg);
    if (regNorm !== brandRegNorm && brandRegNorm.length >= 5) {
      const dist = levenshtein(regNorm, brandRegNorm);
      if (dist <= 2) {
        flags.push({
          severity: "high",
          title: "Typosquatted domain",
          evidence: reg,
          explanation: `The registered domain is one or two characters away from "${brandReg}", a pattern used for look-alike phishing domains that exploit typing mistakes.`,
        });
        if (!spoofedBrand) spoofedBrand = brand.name;
      }
    }

    // 3) Homoglyph / unicode-lookalike impersonation
    if (regNorm !== reg && brand.domains.some((d) => normalizeForMatch(d.toLowerCase().replace(/\.$/, "")) === regNorm)) {
      flags.push({
        severity: "high",
        title: "Unicode lookalike (homoglyph) impersonation",
        evidence: reg,
        explanation: `The registered domain uses visually identical foreign characters (e.g. Cyrillic) that spell "${spoofedBrand ?? brand.name}" to a human eye but resolve to a different site.`,
      });
      if (!spoofedBrand) spoofedBrand = brand.name;
    }

    // 4) Brand token inside an unrelated registrable domain: chase-security-restore.cc
    for (const token of brand.tokens) {
      const tokenNorm = normalizeForMatch(token);
      if (regNorm !== brandRegNorm && tokenMatchesRegistrableDomain(regNorm, tokenNorm)) {
        flags.push({
          severity: "medium",
          title: "Brand name embedded in an unrelated domain",
          evidence: reg,
          explanation: `The registered domain contains the brand name "${brand.name}" but does not actually belong to that organisation. Brand-token domains are heavily used for phishing.`,
        });
        if (!spoofedBrand) spoofedBrand = brand.name;
        break;
      }
    }
  }

  // 5) Brand token inside subdomains of an unrelated registrable domain
  //    is handled by the endpoint after this analysis (needs brand DB loop).

  return { flags, spoofedBrand, officialBrandName, officialDomain, officialMatch };
}

function structuralUrlFlags(parsed: ParsedUrl, officialMatch: boolean): UrlFlag[] {
  const flags: UrlFlag[] = [];

  const { scheme, hostname, registrableDomain, pathname, search, username, isIpAddress, port, subdomainLabels } = parsed;

  // ---- Scheme ----
  if (scheme && !["http", "https"].includes(scheme)) {
    flags.push({
      severity: "high",
      title: "Dangerous URL scheme",
      evidence: `${scheme}:`,
      explanation: `Only http:// and https:// addresses are legitimate for browsing. Schemes like ${scheme}: can execute code or access local resources.`,
    });
  }

  // ---- Userinfo (@ trick) ----
  if (username) {
    flags.push({
      severity: "high",
      title: "Credentials hidden before '@'",
      evidence: `${username}@${hostname}`,
      explanation: "Anything before the last '@' is ignored by browsers when resolving the destination host. The real website is only what comes after '@'.",
    });
  }

  // ---- Transport ----
  if (scheme === "http") {
    flags.push({
      severity: "medium",
      title: "Plain HTTP — no transport encryption",
      evidence: "http://",
      explanation: "The connection is unencrypted, so anything you enter can be read or modified in transit.",
    });
  }

  // ---- Hostname ----
  if (isIpAddress) {
    flags.push({
      severity: "high",
      title: "Raw IP address instead of a domain",
      evidence: hostname,
      explanation: "Legitimate organisations use their own domain name. Direct IP addresses are typical of phishing pages hosted on compromised or throwaway servers.",
    });
  }

  const tld = "." + hostname.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld.toLowerCase())) {
    flags.push({
      severity: "high",
      title: "High-risk top-level domain",
      evidence: tld,
      explanation: "This TLD is cheap or free and disproportionately used by phishing kits and automated scam campaigns.",
    });
  }

  if (/^xn--/i.test(hostname)) {
    flags.push({
      severity: "high",
      title: "Internationalised (punycode) hostname",
      evidence: hostname,
      explanation: "The hostname is encoded with punycode (xn--), a common technique for unicode look-alike (homograph) impersonation.",
    });
  }

  const subdomainCount = subdomainLabels.length;
  if (subdomainCount >= 3 && !officialMatch) {
    flags.push({
      severity: "medium",
      title: "Deeply nested suspicious subdomains",
      evidence: subdomainLabels.join("."),
      explanation: "Multiple stacked subdomains on an unrelated domain are used to bury the real destination and imitate brands ('secure.login.account.…').",
    });
  }

  const regHyphens = (registrableDomain.match(/-/g) || []).length;
  if (regHyphens >= 2) {
    flags.push({
      severity: "medium",
      title: "Excessive hyphens in domain",
      evidence: registrableDomain,
      explanation: "Hyphenated registered domains are commonly auto-generated by scam link tools (e.g. 'paypal-verify-login.com').",
    });
  }

  if (/\d/.test(registrableDomain) && registrableDomain.length >= 8) {
    flags.push({
      severity: "low",
      title: "Digit-heavy domain name",
      evidence: registrableDomain,
      explanation: "Random digits in a domain name often indicate auto-generated scam infrastructure.",
    });
  }

  if (hostname.length > 60) {
    flags.push({
      severity: "low",
      title: "Unusually long hostname",
      evidence: hostname,
      explanation: "Long hostnames are frequently generated to hide a brand name inside a longer fake domain.",
    });
  }

  // ---- Path / Query ----
  // Query-parameter analysis (tracking params, open-redirect targets) is done
  // in queryParameterFindings() so that values are never fed into brand checks.

  if (!officialMatch && /(login|signin|verify|secure|account|auth|bank|wallet|password|recover|update|invoice|payment|suspend|banned|confirm|claim)/i.test(hostname + pathname)) {
    flags.push({
      severity: "medium",
      title: "Login/credential context on an unverified domain",
      evidence: pathname || hostname,
      explanation: "The URL mimics a login or account page but belongs to a domain not operated by the named organisation.",
    });
  }

  const encoded = (pathname + search).match(/%[0-9a-f]{2}/gi) || [];
  if (encoded.length >= 3) {
    flags.push({
      severity: "medium",
      title: "Heavy percent-encoding in URL",
      evidence: (pathname + search).slice(0, 120),
      explanation: "Excessive percent-encoding obscures the true destination from glance inspection.",
    });
  }

  if (/(\.exe|\.msi|\.scr|\.bat|\.cmd|\.apk|\.jar|\.zip|\.rar|\.docm|\.xlsm)$/i.test(pathname)) {
    flags.push({
      severity: "medium",
      title: "Executable or archive download link",
      evidence: pathname,
      explanation: "The link points directly to an executable or installer file, a common malware delivery technique.",
    });
  }

  if (/\/(login|signin|verify|2fa|otp|secure|auth|password-reset)(\.|\/|$)/i.test(pathname) && !officialMatch) {
    flags.push({
      severity: "medium",
      title: "Suspicious login page path",
      evidence: pathname,
      explanation: "This path mimics a credential-entry page outside an official brand domain.",
    });
  }

  if ((pathname + search).includes("\\") || (pathname + search).includes("..%2f") || (pathname + search).includes("..\\")) {
    flags.push({
      severity: "medium",
      title: "Path traversal or backslash tricks",
      evidence: (pathname + search).slice(0, 120),
      explanation: "Backslashes and encoded '..' are used to confuse parsing and hide the real resource.",
    });
  }

  if (port && !["", "80", "443", "8080", "8443"].includes(port)) {
    flags.push({
      severity: "low",
      title: "Uncommon network port",
      evidence: `:${port}`,
      explanation: "Non-standard ports usually indicate self-hosted test infrastructure rather than an official service.",
    });
  }

  return flags;
}

// Params that are pure analytics/tracking noise. `ref` is tracker-style too —
// it is NEVER treated as an open-redirect vector here.
const TRACKING_PARAM_NAMES = new Set(["fbclid", "gclid", "ref", "mc_cid", "mc_eid", "s_cid", "mkt_tok"]);

// Params that classic open-redirect vulnerabilities read from to build the
// next URL. Only flagged when the value points at a *different* host/domain.
const OPEN_REDIRECT_PARAM_NAMES = [
  "url", "redirect", "next", "return", "returnurl", "returnto", "goto",
  "dest", "destination", "target", "continue", "out", "redir", "link", "u",
];

// Query-parameter analysis. Values are parsed *only* to classify the param
// (tracking vs. redirect target). They are never run through brand-spoof or
// spoofing logic — brand checks only ever receive hostname / registered domain.
function queryParameterFindings(parsed: ParsedUrl): UrlFlag[] {
  const flags: UrlFlag[] = [];
  if (!parsed.search) return flags;

  let params: URLSearchParams;
  try {
    params = new URLSearchParams(parsed.search.startsWith("?") ? parsed.search.slice(1) : parsed.search);
  } catch {
    return flags;
  }
  if (params.size === 0) return flags;

  const trackingList: string[] = [];
  for (const [key, rawValue] of params) {
    const lowerKey = key.toLowerCase();

    // --- Tracking / analytics params: informational only ---
    if (lowerKey.startsWith("utm_") || TRACKING_PARAM_NAMES.has(lowerKey)) {
      const value = rawValue.trim();
      trackingList.push(value ? `${key}=${value}` : key);
      continue;
    }

    // --- Redirect-target params: warn only when value is a different domain ---
    if (OPEN_REDIRECT_PARAM_NAMES.includes(lowerKey)) {
      const value = rawValue.trim();
      if (!value) continue;
      let decoded: string;
      try {
        decoded = decodeURIComponent(value);
      } catch {
        decoded = value;
      }
      // Strip leading "//" (protocol-relative) for host extraction
      const candidate = decoded.startsWith("//") ? `https:${decoded}` : decoded;
      let target: URL;
      try {
        target = new URL(candidate);
      } catch {
        continue; // not a URL — nothing to redirect to
      }
      if (!["http:", "https:"].includes(target.protocol)) continue;
      const targetHost = target.hostname.toLowerCase().replace(/\.$/, "");
      const sourceHost = parsed.hostname.toLowerCase().replace(/\.$/, "");
      if (targetHost === sourceHost) continue; // same-host redirect is benign

      const targetReg = getRegistrableDomain(targetHost);
      const sourceReg = getRegistrableDomain(sourceHost);
      const crossDomain = targetReg !== sourceReg;

      flags.push({
        severity: "medium",
        title: "Possible open redirect via query parameter",
        evidence: `${key}=${value}`,
        explanation:
          `The '${key}' parameter hands the browser a ${crossDomain ? "different website's" : "different "} address (${targetHost}). ` +
          `Open-redirect parameters like these are abused to route victims from a trusted-looking link to a malicious page.`,
      });
    }
  }

  if (trackingList.length > 0) {
    // Only describe the first few so the finding stays one line.
    const shown = trackingList.slice(0, 3).join(", ");
    const extra = trackingList.length > 3 ? ` (+${trackingList.length - 3} more)` : "";
    flags.push({
      severity: "low",
      title: "Tracking parameters present",
      evidence: shown + extra,
      explanation:
        "The query string contains analytics/tracking parameters (utm_*, fbclid, gclid, ref). Informational only; they do not affect which site you land on.",
    });
  }

  return flags;
}
// ---------------------------------------------------------------------------
// Reputation checks — provider-based so Google Safe Browsing, PhishTank etc.
// can be added later behind the same interface.
// ---------------------------------------------------------------------------

export type ReputationStatus =
  | "clean"
  | "malicious"
  | "not_configured"
  | "error"
  | "timeout"
  | "rate_limited";

export interface ReputationDetail {
  url: string;
  threat: string;
  dateAdded: string;
}

export interface ReputationLookupResult {
  status: ReputationStatus;
  source: string;
  note?: string;
  reference?: string | null;
  details?: ReputationDetail[];
  /** Every URL that was actually submitted to the sources (original and, if it differs, the post-redirect destination). */
  checkedUrls?: string[];
  /** The URL that the winning malicious source flagged. */
  flaggedUrl?: string;
}

export interface ReputationProviderContext {
  /** Full URL being inspected. */
  url: string;
  /** Hostname (no scheme/path). */
  host: string;
}

export interface ReputationProvider {
  readonly id: string;
  readonly label: string;
  isConfigured(): boolean;
  lookup(ctx: ReputationProviderContext, opts?: { fetchImpl?: typeof fetch; signal?: AbortSignal }): Promise<Omit<ReputationLookupResult, "source">>;
}

const URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1";
const REPUTATION_TIMEOUT_MS = 7000;

async function postForm(
  absoluteUrl: string,
  body: string,
  opts?: { fetchImpl?: typeof fetch; signal?: AbortSignal }
): Promise<Response> {
  const fetchImpl = opts?.fetchImpl || fetch;
  return fetchImpl(absoluteUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": "Mozilla/5.0 (compatible; OnlineSafetyGuard)",
    },
    body,
    signal: opts?.signal,
  });
}

/**
 * URLhaus provider: queries the full URL first then the host. Explicitly
 * handles "no_results", "listed"/"ok", "invalid_url", rate limits, timeouts
 * and other transport failures. Never counts a failed/absent lookup as clean.
 */
export const urlhausProvider: ReputationProvider = {
  id: "urlhaus",
  label: "URLhaus malware database",
  isConfigured() {
    return Boolean(process.env.URLHAUS_API_KEY);
  },
  async lookup(ctx, opts) {
    const apiKey = process.env.URLHAUS_API_KEY;
    if (!apiKey) {
      return {
        status: "not_configured",
        note: "Reputation lookup is not configured for this deployment.",
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REPUTATION_TIMEOUT_MS);
    const signal = opts?.signal ?? controller.signal;
    const fetchImpl = opts?.fetchImpl;

    const runQuery = async (endpoint: "url" | "host", value: string) => {
      const res = await postForm(
        `${URLHAUS_API_URL}/${endpoint}/`,
        `${endpoint}=${encodeURIComponent(value)}`,
        { fetchImpl, signal }
      );
      if (res.status === 429 || res.status === 401) {
        throw { kind: "rate_limited" };
      }
      if (!res.ok) {
        throw { kind: "http", status: res.status };
      }
      return res.json() as Promise<any>;
    };

    try {
      const clean: Omit<ReputationLookupResult, "source"> = {
        status: "clean",
        note: "No malware reports for this URL or host in the URLhaus database.",
      };

      // 1) Exact URL lookup
      let urlData: any;
      try {
        urlData = await runQuery("url", ctx.url);
      } catch {
        urlData = null; // tolerate per-endpoint failures; host lookup below is the fallback
      }
      if (urlData?.query_status === "listed" && Array.isArray(urlData.urls)) {
        const first = urlData.urls[0] || {};
        return {
          status: "malicious",
          note: "This exact URL is actively listed in the URLhaus malware database.",
          reference: urlData.urlhaus_reference || null,
          flaggedUrl: ctx.url,
          details: urlData.urls.slice(0, 5).map((u: any) => ({
            url: u.url || ctx.url,
            threat: u.threat || "malware",
            dateAdded: u.date_added || "",
          })),
        };
      }
      if (urlData?.query_status === "rate_limit_reached" || urlData?.error === "rate_limit") {
        return { status: "rate_limited", note: "Reputation service rate limit reached; retry later." };
      }
      // "no_results", "invalid_url", "ok" without urls → continue to host lookup

      // 2) Host lookup
      let hostData: any = null;
      let hostErr: any = null;
      try {
        hostData = await runQuery("host", ctx.host);
      } catch (e) {
        hostErr = e;
      }

      if (hostData?.query_status === "ok" && Array.isArray(hostData.urls)) {
        const first = hostData.urls[0] || {};
        return {
          status: "malicious",
          note: "Host is actively listed in the URLhaus malware database.",
          reference: hostData.urlhaus_reference || null,
          flaggedUrl: ctx.url,
          details: hostData.urls.slice(0, 5).map((u: any) => ({
            url: u.url || ctx.host,
            threat: u.threat || "malware",
            dateAdded: u.date_added || "",
          })),
        };
      }
      if (hostData?.query_status === "no_results") {
        return clean;
      }
      if (hostData?.query_status === "rate_limit_reached") {
        return { status: "rate_limited", note: "Reputation service rate limit reached; retry later." };
      }
      if (hostErr) throw hostErr;
      // Unknown but successful response
      return {
        status: "error",
        note: `Unexpected reputation response (${hostData?.query_status || "unknown"}).`,
      };
    } catch (err: any) {
      clearTimeout(timer);
      if (err?.kind === "rate_limited") {
        return { status: "rate_limited", note: "Reputation service rate limit reached; retry later." };
      }
      if (err?.name === "AbortError" || err?.kind === "timeout") {
        return { status: "timeout", note: "Reputation lookup timed out." };
      }
      if (err?.kind === "http") {
        return { status: "error", note: `Reputation service returned HTTP ${err.status}.` };
      }
      return { status: "error", note: "Reputation lookup failed (network error)." };
    } finally {
      clearTimeout(timer);
    }
  },
};

const GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

function threatLabel(t: string): string {
  const map: Record<string, string> = {
    MALWARE: "Malware",
    SOCIAL_ENGINEERING: "Phishing / social engineering",
    UNWANTED_SOFTWARE: "Unwanted software",
    POTENTIALLY_HARMFUL_APPLICATION: "Potentially harmful application",
  };
  return map[t] || t;
}

/**
 * Google Safe Browsing API key. Accepts the historical name and the shorter
 * SAFE_BROWSING_API_KEY alias.
 */
function safeBrowsingKey(): string | null {
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.SAFE_BROWSING_API_KEY;
  return key && key.length > 0 ? key : null;
}

/**
 * Google Safe Browsing provider — a canonical trusted source for phishing
 * (SOCIAL_ENGINEERING), malware and unwanted software. A single request covers
 * every threat type for the URL being inspected.
 */
export const googleSafeBrowsingProvider: ReputationProvider = {
  id: "google-safe-browsing",
  label: "Google Safe Browsing",
  isConfigured() {
    return safeBrowsingKey() !== null;
  },
  async lookup(ctx, opts) {
    const apiKey = safeBrowsingKey();
    if (!apiKey) {
      return { status: "not_configured", note: "Not available right now." };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REPUTATION_TIMEOUT_MS);
    const fetchImpl = opts?.fetchImpl || fetch;
    const signal = opts?.signal ?? controller.signal;

    try {
      const res = await fetchImpl(`${GOOGLE_SAFE_BROWSING_URL}?key=${encodeURIComponent(apiKey)}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "Mozilla/5.0 (compatible; OnlineSafetyGuard)",
        },
        signal,
        body: JSON.stringify({
          client: { clientId: "online-safety-guard", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: ctx.url }],
          },
        }),
      });

      if (res.status === 429) {
        return { status: "rate_limited", note: "Reputation service rate limit reached; retry later." };
      }
      if (res.status === 400 || res.status === 403) {
        return { status: "error", note: `Reputation service rejected the request (HTTP ${res.status}).` };
      }
      if (!res.ok) {
        return { status: "error", note: `Reputation service returned HTTP ${res.status}.` };
      }

      const data: any = await res.json().catch(() => ({}));
      const matches: any[] = Array.isArray(data?.matches) ? data.matches : [];
      if (matches.length === 0) {
        return { status: "clean", note: "No threats detected for this URL in Google Safe Browsing." };
      }

      const threatTypes = [...new Set(matches.map((m) => String(m?.threatType || "THREAT")))];
      return {
        status: "malicious",
        note: "Google Safe Browsing lists this URL as a confirmed threat.",
        reference: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(ctx.url)}`,
        flaggedUrl: ctx.url,
        details: threatTypes.map((t) => ({ url: ctx.url, threat: threatLabel(t), dateAdded: "" })),
      };
    } catch (err: any) {
      if (err?.name === "AbortError") return { status: "timeout", note: "Reputation lookup timed out." };
      return { status: "error", note: "Reputation lookup failed (network error)." };
    } finally {
      clearTimeout(timer);
    }
  },
};

const OPENPHISH_TTL_MS = 24 * 60 * 60 * 1000;
let openPhishCache: { loadedAt: number; urls: Set<string>; hosts: Set<string> } | null = null;

function loadOpenPhish(): { loadedAt: number; urls: Set<string>; hosts: Set<string> } | null {
  if (openPhishCache && Date.now() - openPhishCache.loadedAt < OPENPHISH_TTL_MS) return openPhishCache;
  const file = process.env.OPENPHISH_FEED_FILE || "data/openphish.txt";
  try {
    if (!fs.existsSync(file)) return null;
    const urls = new Set<string>();
    const hosts = new Set<string>();
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const value = line.trim();
      if (!value || value.startsWith("#")) continue;
      try {
        const u = new URL(value);
        urls.add(u.href);
        hosts.add(u.hostname.toLowerCase());
      } catch {
        /* skip malformed line */
      }
    }
    openPhishCache = { loadedAt: Date.now(), urls, hosts };
    return openPhishCache;
  } catch {
    return null;
  }
}

/**
 * OpenPhish (or PhishTank) phishing feed, cached locally at
 * OPENPHISH_FEED_FILE (default data/openphish.txt) for 24h. No key is needed;
 * when the file is absent the source reports "not configured" rather than clean.
 */
export const openPhishProvider: ReputationProvider = {
  id: "openphish",
  label: "OpenPhish phishing feed (local cache)",
  isConfigured() {
    return loadOpenPhish() !== null;
  },
  async lookup(ctx) {
    const feed = loadOpenPhish();
    if (!feed) {
      return { status: "not_configured", note: "Threat feed is not configured for this deployment." };
    }
    const host = ctx.host.toLowerCase().replace(/\.$/, "");
    if (feed.urls.has(ctx.url) || feed.hosts.has(host)) {
      return {
        status: "malicious",
        note: "Listed in the local OpenPhish phishing feed.",
        flaggedUrl: ctx.url,
        details: [{ url: ctx.url, threat: "phishing", dateAdded: "" }],
      };
    }
    return { status: "clean", note: "No match in the local OpenPhish phishing feed." };
  },
};

const DEFAULT_REPUTATION_PROVIDERS: ReputationProvider[] = [urlhausProvider, googleSafeBrowsingProvider, openPhishProvider];

/**
 * Combine the per-URL reputation results (the original link and, when it
 * differs, the post-redirect destination). A confirmed threat from ANY source
 * for ANY checked URL wins immediately; otherwise every checked URL must come
 * back clean before the aggregate can be "clean".
 */
function combineReputationResults(
  entries: Array<{ url: string; result: ReputationLookupResult }>
): ReputationLookupResult {
  if (entries.length === 0) {
    return { status: "error", source: "none", note: "No reputation check was performed." };
  }
  const checkedUrls = entries.map((e) => e.url);

  const malicious = entries.find((e) => e.result.status === "malicious");
  if (malicious) {
    return {
      ...malicious.result,
      checkedUrls,
      flaggedUrl: malicious.result.flaggedUrl || malicious.url,
    };
  }

  if (entries.every((e) => e.result.status === "clean")) {
    return { ...entries[0].result, note: entries[0].result.note, checkedUrls };
  }

  // Something prevented verification → propagate the most serious non-clean state.
  const precedence: ReputationStatus[] = ["rate_limited", "timeout", "error", "not_configured"];
  for (const status of precedence) {
    const hit = entries.find((e) => e.result.status === status);
    if (hit) return { ...hit.result, checkedUrls };
  }
  return { ...entries[0].result, checkedUrls };
}

/**
 * Aggregate reputation across the configured providers. Malicious listings win;
 * otherwise at least one clean provider is required for "clean". Any provider
 * that cannot run moves the aggregate to an explicit non-clean status.
 */
async function runReputationLookup(
  ctx: ReputationProviderContext,
  providers: ReputationProvider[] = DEFAULT_REPUTATION_PROVIDERS,
  opts?: { fetchImpl?: typeof fetch }
): Promise<ReputationLookupResult> {
  const configured = providers.filter((p) => p.isConfigured());
  if (configured.length === 0) {
    console.info("[reputation] No reputation provider configured on this deployment; skipping lookup.");
    return providers.length === 0
      ? { status: "not_configured", source: "none", note: "Reputation lookup is not available." }
      : {
          status: "not_configured",
          source: providers[0].id,
          note: "Reputation lookup is not configured for this deployment.",
        };
  }

  const results = await Promise.all(
    configured.map(async (p) => {
      try {
        const r = await p.lookup(ctx, { fetchImpl: opts?.fetchImpl });
        return { provider: p, result: r };
      } catch (err: any) {
        console.error(`[reputation] Provider ${p.id} failed:`, err?.message || err);
        return {
          provider: p,
          result: { status: "error" as ReputationStatus, note: "Reputation provider failed unexpectedly." },
        };
      }
    })
  );

  const malicious = results.find((r) => r.result.status === "malicious");
  if (malicious) {
    return { ...malicious.result, source: malicious.provider.id };
  }

  const cleanProviders = results.filter((r) => r.result.status === "clean");
  if (cleanProviders.length === configured.length) {
    return { ...cleanProviders[0].result, source: cleanProviders[0].provider.id };
  }

  // Some provider could not complete → explicit non-clean status.
  const blocked = results.find((r) => r.result.status === "rate_limited");
  if (blocked) return { ...blocked.result, source: blocked.provider.id };
  const timedOut = results.find((r) => r.result.status === "timeout");
  if (timedOut) return { ...timedOut.result, source: timedOut.provider.id };
  const errored = results.find((r) => r.result.status === "error");
  if (errored) return { ...errored.result, source: errored.provider.id };

  return { status: "clean", source: configured[0].id, note: "No malware reports found." };
}

// ---- Live redirect-chain follower (SSRF-safe) ----
function isPrivateIpLiteral(ip: string): boolean {
  if (ip.includes(":")) {
    const low = ip.toLowerCase();
    return low === "::1" || low === "::" || low.startsWith("fc") || low.startsWith("fd") || low.startsWith("fe8");
  }
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return true;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

const defaultDnsLookup: RedirectFollowerOptions["dnsLookupImpl"] = (hostname, opts) =>
  dnsLookup(hostname, opts) as Promise<Array<{ address: string }>>;

async function resolvesToPrivate(
  hostname: string,
  dnsLookupImpl: (hostname: string, opts?: { all?: boolean }) => Promise<Array<{ address: string }>> = defaultDnsLookup
): Promise<boolean> {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return isPrivateIpLiteral(host);
  try {
    const addrs = await dnsLookupImpl(host, { all: true });
    return addrs.length === 0 || addrs.some((a) => isPrivateIpLiteral(a.address));
  } catch {
    return false; // unresolvable host – the fetch below will fail naturally
  }
}

// Hosts commonly used as URL shorteners. Brand-owned shorteners (t.co,
// lnkd.in, youtu.be, amzn.to, fb.me) are intentionally excluded so official
// brand links are not flagged as suspicious.
const URL_SHORTENER_HOSTS = new Set([
  "bit.ly", "tinyurl.com", "tiny.cc", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "s.id", "t2m.io", "t.ly",
  "short.io", "surl.li", "onelink.to", "db.tt", "qr.ae", "adf.ly", "j.gs",
  "bl.ink", "snip.ly", "v.gd", "soo.gd", "u.nu",
]);

// After the GET fallback, these statuses mean "we could not verify the link
// resolves cleanly" — never "reachable / no redirect".
const INCONCLUSIVE_STATUSES = new Set([403, 405, 429]);
const MAX_REDIRECT_HOPS = 10;
const HOP_TIMEOUT_MS = 8000;

export interface UrlRedirectHopShape {
  url: string;
  status: number;
}

export interface UrlRedirectCheckShape {
  status: "none" | "redirect" | "skipped" | "inconclusive" | "error";
  hops: UrlRedirectHopShape[];
  finalUrl: string | null;
  method?: "HEAD" | "GET" | null;
  note?: string;
  flags?: UrlFlag[];
}

export interface RedirectFollowerOptions {
  fetchImpl?: typeof fetch;
  dnsLookupImpl?: (hostname: string, opts?: { all?: boolean }) => Promise<Array<{ address: string }>>;
  maxHops?: number;
}

// HEAD first, then GET on 405/501 or transport failure. GET bodies are
// cancelled (streamed, never downloaded). Useful for tests via injected fakes.
export async function followRedirectChain(
  startUrl: string,
  options?: RedirectFollowerOptions
): Promise<UrlRedirectCheckShape> {
  const fetchImpl = options?.fetchImpl || fetch;
  const dnsLookupImpl = options?.dnsLookupImpl || defaultDnsLookup;
  const maxHops = options?.maxHops ?? MAX_REDIRECT_HOPS;

  const hops: UrlRedirectHopShape[] = [];
  const flags: UrlFlag[] = [];
  let current = startUrl;
  let currentMethod: "HEAD" | "GET" = "HEAD";
  const seen = new Set<string>([startUrl]);
  const HOPS_USER_AGENT = "Mozilla/5.0 (compatible; OnlineSafetyGuard)";

  const requestOnce = async (method: "HEAD" | "GET", url: string, signal: AbortSignal): Promise<{ res: Response } | { err: any }> => {
    try {
      const res = await fetchImpl(url, {
        method,
        redirect: "manual",
        signal,
        headers: { "User-Agent": HOPS_USER_AGENT },
      });
      return { res };
    } catch (err) {
      return { err };
    }
  };

  try {
    for (let i = 0; i <= maxHops; i++) {
      let u: URL;
      try {
        u = new URL(current);
      } catch {
        return { status: "error", hops, finalUrl: null, method: currentMethod, note: "Unable to parse URL for connectivity check." };
      }
      if (!["http:", "https:"].includes(u.protocol)) {
        return { status: "skipped", hops, finalUrl: null, method: null, note: `Non-web protocol (${u.protocol}) – not followed.` };
      }
      if (await resolvesToPrivate(u.hostname, dnsLookupImpl)) {
        return {
          status: "skipped",
          hops,
          finalUrl: null,
          method: null,
          note: "Refused to follow: host resolves to a private/internal network address.",
        };
      }

      // Hop-level timeout. Reset between HEAD and GET attempts so a slow HEAD
      // does not starve the GET fallback.
      const controller = new AbortController();
      let timer = setTimeout(() => controller.abort(), HOP_TIMEOUT_MS);

      let attempt = await requestOnce("HEAD", current, controller.signal);
      if ("err" in attempt || [405, 501].includes(attempt.res.status)) {
        // HEAD failed (network/timeout) or refused → retry with GET.
        clearTimeout(timer);
        timer = setTimeout(() => controller.abort(), HOP_TIMEOUT_MS);
        attempt = await requestOnce("GET", current, controller.signal);
        if ("res" in attempt) currentMethod = "GET";
      }
      clearTimeout(timer);

      if ("err" in attempt) {
        const err: any = attempt.err;
        return {
          status: "error",
          hops,
          finalUrl: null,
          method: currentMethod,
          note:
            err?.name === "AbortError"
              ? "Timed out while connecting."
              : err?.cause?.code || err?.cause?.message || err?.message || "Network error while checking the link.",
        };
      }

      const res = attempt.res;
      const status = res.status;
      // Never download the body — cancel the stream as soon as we have headers.
      res.body?.cancel().catch(() => {});
      hops.push({ url: current, status });

      const location = res.headers.get("location");

      if ([301, 302, 303, 307, 308].includes(status) && location) {
        let next: string;
        try {
          next = new URL(location, current).toString();
        } catch {
          return { status: "error", hops, finalUrl: null, method: currentMethod, note: "Redirect target could not be parsed." };
        }

        const from = current;
        const to = next;
        flags.push(...redirectTransitionFlags(from, to));

        if (seen.has(next)) {
          return { status: "error", hops, finalUrl: null, method: currentMethod, note: "Redirect loop detected." };
        }
        if (i === maxHops) {
          return { status: "error", hops, finalUrl: null, method: currentMethod, note: `Too many redirects (max ${maxHops}).` };
        }
        seen.add(next);
        current = next;
        continue;
      }

      // Terminal hop. 403/405/429/5xx after the fallback are INCONCLUSIVE, not
      // "reachable / clean".
      if (INCONCLUSIVE_STATUSES.has(status) || status >= 500 || (status >= 400 && status < 500 && currentMethod === "GET")) {
        return {
          status: "inconclusive",
          hops,
          finalUrl: current,
          method: currentMethod,
          note: `Server responded HTTP ${status} — link could not be verified as reachable.`,
        };
      }

      const redirected = hops.length > 1;
      return {
        status: redirected ? "redirect" : "none",
        hops,
        finalUrl: current,
        method: currentMethod,
        note: redirected
          ? `Reached ${current} (HTTP ${status}) after ${hops.length - 1} redirect hop(s).`
          : `Reachable (HTTP ${status}). No redirect.`,
        flags,
      };
    }
    return { status: "error", hops, finalUrl: null, method: currentMethod, note: `Too many redirects (max ${maxHops}).` };
  } catch (err: any) {
    return {
      status: "error",
      hops,
      finalUrl: null,
      method: currentMethod,
      note:
        err?.name === "AbortError"
          ? "Timed out while connecting."
          : err?.cause?.code || err?.cause?.message || err?.message || "Network error while checking the link.",
    };
  }
}

// Flags describing what a single redirect transition does.
function redirectTransitionFlags(fromUrl: string, toUrl: string): UrlFlag[] {
  const flags: UrlFlag[] = [];
  let from: URL;
  let to: URL;
  try {
    from = new URL(fromUrl);
    to = new URL(toUrl);
  } catch {
    return flags;
  }

  // Downgrade and shortener checks must run even when the host does not change.
  if (to.protocol === "http:" && from.protocol === "https:") {
    flags.push({
      severity: "medium",
      title: "HTTPS downgrade on redirect",
      evidence: `${fromUrl} → ${toUrl}`,
      explanation: "An HTTPS page redirects to a plain-HTTP address, removing encryption. Attackers use this to strip protections mid-chain.",
    });
  }

  const fromHost = from.hostname.toLowerCase().replace(/\.$/, "");
  const toHost = to.hostname.toLowerCase().replace(/\.$/, "");

  if (URL_SHORTENER_HOSTS.has(toHost)) {
    flags.push({
      severity: "medium",
      title: "Redirects through a URL shortener",
      evidence: toHost,
      explanation: "The link passes through a URL-shortening service, hiding the true destination until it resolves.",
    });
  }

  if (fromHost === toHost) return flags;

  const fromReg = getRegistrableDomain(fromHost);
  const toReg = getRegistrableDomain(toHost);

  if (toReg !== fromReg) {
    flags.push({
      severity: "medium",
      title: "Redirect crosses to a different registered domain",
      evidence: `${fromUrl} → ${toUrl}`,
      explanation: `The link bounces from ${fromReg} to the unrelated registered domain ${toReg}. Cross-domain redirects are a staple of redirect-based phishing.`,
    });
  } else if (toHost !== fromHost) {
    flags.push({
      severity: "low",
      title: "Cross-host redirect (same registered domain)",
      evidence: `${fromHost} → ${toHost}`,
      explanation: `The redirect stays within ${fromReg} but switches hosts (e.g. www → mobile). Usually benign, but the final host still determines what you actually load.`,
    });
  }

  return flags;
}

/**
 * Final risk classification.
 *  - HIGH_RISK            a trusted source confirmed a threat, or a failed/critical check found one
 *  - SUSPICIOUS           verification ran and found warning-level risk signals
 *  - VERIFICATION_REQUIRED verification could not be performed (missing key, timeout, unreachable…)
 *  - LOW_RISK             every check ran and no threats were detected
 */
type UrlVerdict = ScoreVerdict; // MALICIOUS | SUSPICIOUS | LOW_RISK | UNVERIFIED (gateway.ts already maps these)

export interface UrlCheckShape {
  id: string;
  label: string;
  status: "passed" | "warning" | "failed" | "skipped" | "error";
  detail?: string;
}

// Internal flag severity → public finding severity
function toPublicFinding(f: UrlFlag): { severity: "critical" | "warning" | "info"; title: string; evidence: string; explanation: string } {
  const severity = f.severity === "high" ? "critical" : f.severity === "medium" ? "warning" : "info";
  return { severity, title: f.title, evidence: f.evidence, explanation: f.explanation };
}

// Compare two URLs ignoring a trailing slash / default formatting.
function urlsMatch(a: string, b: string): boolean {
  const norm = (u: string): string => {
    try {
      const x = new URL(u);
      return `${x.protocol}//${x.host}${x.pathname.replace(/\/+$/, "")}${x.search}`;
    } catch {
      return u.trim().replace(/\/+$/, "");
    }
  };
  return norm(a) === norm(b);
}

// Lower-cased hostname for an http(s) URL, or null when it cannot be parsed.
function safeHostname(u: string): string | null {
  try {
    const x = new URL(u);
    if (x.protocol !== "http:" && x.protocol !== "https:") return null;
    return x.hostname.toLowerCase().replace(/\.$/, "") || null;
  } catch {
    return null;
  }
}

/**
 * Final risk score is computed from the deterministic signal list (see
 * url-scoring.ts). The old verdict-based score — including the fixed 45 for
 * "verification required" that turned unknown into a medium score — is gone.
 */

// A check that ran and found no problem → passed. Any red flag → warning/failed.
function statusFromFlags(flags: UrlFlag[]): UrlCheckShape["status"] {
  if (flags.some((f) => f.severity === "high")) return "failed";
  if (flags.some((f) => f.severity === "medium")) return "warning";
  return "passed";
}

function redirectCheckStatus(r: UrlRedirectCheckShape): UrlCheckShape["status"] {
  switch (r.status) {
    case "none":
      return "passed";
    case "redirect":
      return r.flags?.some((f) => f.severity === "high" || f.severity === "medium") ? "warning" : "passed";
    case "skipped":
      return "skipped";
    case "inconclusive": // could NOT be verified reachable → never "passed"
    case "error":
      return "error";
  }
}

function reputationCheckStatus(r: ReputationLookupResult): UrlCheckShape["status"] {
  switch (r.status) {
    case "clean":
      return "passed";
    case "malicious":
      return "failed";
    case "not_configured":
      return "skipped";
    case "error":
    case "timeout":
    case "rate_limited":
      return "error";
  }
}

function reputationCheckDetail(r: ReputationLookupResult): string {
  switch (r.status) {
    case "clean":
      return "no threats detected";
    case "malicious":
      return "confirmed threat listed";
    case "not_configured":
      return "not run — Not available right now";
    case "rate_limited":
      return "not run — rate limited";
    case "timeout":
      return "not run — timed out";
    case "error":
      return "not run — lookup failed";
  }
}

interface BuildInspectionArgs {
  parsed: ParsedUrl;
  brandFlags: UrlFlag[];
  structuralFlags: UrlFlag[];
  subdomainFlags: UrlFlag[];
  queryFlags: UrlFlag[];
  spoofedBrand: string | null;
  officialDomain: string | null;
  officialBrandName: string | null;
  checks: UrlCheckShape[];
  reputation: ReputationLookupResult;
  redirects: UrlRedirectCheckShape;
  gemini?: any;
  engine: string;
  tracking?: { isTracking: boolean; destinationUnverified?: boolean; provider?: string } | null;
  finalDestination?: { url: string; wellKnown: boolean } | null;
  intel?: {
    tlsValid?: boolean | null;
    dnsExists?: boolean | null;
    domainAgeDays?: number | null;
    trancoRank?: number | null;
  } | null;
  ai?: { threatLevel?: string } | null;
  /** Admin-only debug payload (per-check timing/reasons). Omitted normally. */
  debug?: Record<string, unknown> | null;
}

function buildInspectionResponse(args: BuildInspectionArgs): Record<string, any> {
  const { parsed, brandFlags, structuralFlags, subdomainFlags, queryFlags, spoofedBrand, officialDomain, officialBrandName, checks, reputation, redirects, gemini, engine } = args;

  // Confirmed reputation threats become first-class findings so the detected
  // threat, its source and the exact flagged URL are always visible.
  const reputationFlags: UrlFlag[] = [];
  if (reputation?.status === "malicious") {
    const flaggedUrl = reputation.flaggedUrl || parsed.cleanUrl;
    const finalUrl = redirects?.finalUrl || null;
    const flaggedIsFinal =
      Boolean(finalUrl) && !urlsMatch(flaggedUrl, parsed.cleanUrl) && urlsMatch(flaggedUrl, finalUrl!);
    const threats = [...new Set((reputation.details || []).map((d) => d.threat).filter(Boolean))];
    reputationFlags.push({
      severity: "high",
      title: flaggedIsFinal
        ? "Redirect destination flagged as a confirmed threat"
        : `${reputation.source} flagged this URL as a confirmed threat`,
      evidence: flaggedUrl,
      explanation:
        `${reputation.note || "A trusted security source lists this URL as malicious."}` +
        (threats.length ? ` Detected: ${threats.join(", ")}.` : "") +
        (flaggedIsFinal ? " The original link looked clean but redirects to this flagged destination." : ""),
    });
  }

  // Deduplicate identical flags before scoring / rendering.
  const seenKeys = new Set<string>();
  const allFlags = [...reputationFlags, ...brandFlags, ...subdomainFlags, ...structuralFlags, ...queryFlags].filter((f) => {
    const key = `${f.title}|${f.evidence}`;
    if (seenKeys.has(key)) return false;
    seenKeys.add(key);
    return true;
  });

  // Split the "Status Verdict" into structure + overall risk.
  const structuralIssueCount = structuralFlags.length;
  const urlStructure = structuralIssueCount === 0
    ? { status: "valid" as const, detail: "Scheme, hostname, port, path and query parse cleanly." }
    : { status: "flagged" as const, detail: `${structuralIssueCount} structural issue(s) found — see findings below.` };

  const reputationMalicious = reputation?.status === "malicious";
  const flaggedUrl = reputation?.flaggedUrl || parsed.cleanUrl;
  const reputationFlaggedFinal =
    reputationMalicious &&
    Boolean(redirects?.finalUrl) &&
    !urlsMatch(flaggedUrl, parsed.cleanUrl) &&
    urlsMatch(flaggedUrl, redirects.finalUrl!);

  // Deterministic, explainable scoring: evidence drives riskScore; how many
  // (weighted) checks actually ran drives confidence. Missing checks NEVER
  // inflate the score — they only lower confidence.
  const signals = buildSignals({
    flags: allFlags,
    reputationMalicious,
    reputationClean: reputation?.status === "clean",
    reputationSource: reputation?.source,
    reputationFlaggedUrl: reputation?.flaggedUrl ?? null,
    reputationFlaggedFinal,
    tracking: args.tracking ?? null,
    finalDestination: args.finalDestination ?? null,
    intel: args.intel ?? null,
    ai: args.ai ?? null,
  });
  const riskScore = riskScoreFromSignals(signals);
  const confidence = confidenceFromChecks(checks);
  // A critical live check that did not return a clean result means we could not
  // verify the URL — it can be SUSPICIOUS/MALICIOUS but never LOW_RISK.
  const criticalOk = !checks.some(
    (c) => CRITICAL_CHECK_IDS.has(c.id) && c.status !== "passed" && c.status !== "warning"
  );
  const verdict = verdictFromScore({ riskScore, confidence, reputationMalicious, criticalOk });

  const isSuspicious = verdict === "MALICIOUS" || verdict === "SUSPICIOUS";
  const threatLevel: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" =
    verdict === "MALICIOUS"
      ? "HIGH"
      : verdict === "SUSPICIOUS"
      ? "MEDIUM"
      : verdict === "UNVERIFIED"
      ? "UNKNOWN"
      : "LOW";

  const topSignals = signals.filter((s) => s.points > 0).slice(0, 3).map((s) => s.label);
  const missingChecks = checks
    .filter((c) => c.status === "skipped" || c.status === "error")
    .map((c) => `${c.label} (${(c.detail || c.status).replace(/^not run — /, "")})`);

  // One-line reason shown next to the badge (always consistent with the verdict).
  let verdictReason: string;
  if (verdict === "MALICIOUS") {
    verdictReason = reputationMalicious
      ? `${reputation.source} confirmed a threat${reputation.flaggedUrl ? ` at ${reputation.flaggedUrl}` : ""}.`
      : `${topSignals.length ? topSignals.join("; ") + ". " : ""}Risk score ${riskScore}/100.`;
  } else if (verdict === "SUSPICIOUS") {
    verdictReason = `${topSignals.length ? topSignals.join("; ") + ". " : ""}Risk score ${riskScore}/100 (confidence ${confidence}%).`;
  } else if (verdict === "UNVERIFIED") {
    verdictReason = `Unverified — ${
      missingChecks.length ? `checks not run: ${missingChecks.join(", ")}` : "not enough checks ran"
    }. Evidence so far scores ${riskScore}/100 with ${confidence}% confidence; the link is not confirmed safe.`;
  } else {
    verdictReason = `Low risk — all key checks ran and no risk signals were found (confidence ${confidence}%).`;
  }

  // Compose the legacy human-readable reason from the strongest signals.
  const reasonParts: string[] = [];
  if (allFlags.length) {
    const top = allFlags.slice(0, 3).map((f) => f.title);
    reasonParts.push(`Detected: ${top.join("; ")}.`);
  }
  if (reputation?.status === "malicious") {
    reasonParts.push(
      `Trusted threat source (${reputation.source}) confirmed a threat${reputation.flaggedUrl ? ` for ${reputation.flaggedUrl}` : ""}.`
    );
  } else if (reputation?.status === "clean") {
    reasonParts.push(`Threat reputation check (${reputation.source}) found no reports.`);
  } else if (reputation?.status === "not_configured") {
    reasonParts.push("Threat reputation checking isn't available right now.");
  } else if (reputation?.status) {
    reasonParts.push(`Threat reputation verification could not complete (${reputation.status}).`);
  }
  if (redirects?.status === "redirect" && redirects.hops.length > 1) {
    reasonParts.push(`The link redirects (${redirects.hops.map((h) => h.url).join(" → ")}).`);
  } else if (redirects?.status === "none") {
    reasonParts.push("Connectivity check: no redirect observed.");
  } else if (redirects?.status === "inconclusive" || redirects?.status === "error" || redirects?.status === "skipped") {
    reasonParts.push(`Connectivity check: ${redirects.note}`);
  }
  reasonParts.push(verdictReason);
  const reason = reasonParts.join(" ");

  return {
    domain: parsed.hostname,
    registrableDomain: parsed.registrableDomain,
    fullUrl: parsed.cleanUrl,
    isSuspicious,
    threatLevel,
    verdict,
    verdictReason,
    riskScore,
    confidence,
    signals: signals.map((s) => ({ id: s.id, label: s.label, points: s.points, reason: s.reason, kind: s.kind })),
    urlStructure,
    spoofedBrand: spoofedBrand ?? gemini?.spoofedBrand ?? null,
    officialDomain: officialDomain ?? gemini?.officialDomain ?? null,
    reason,
    findings: allFlags.map(toPublicFinding),
    redirects: {
      status: redirects.status,
      hops: redirects.hops.map((h) => ({ url: h.url, status: h.status })),
      finalUrl: redirects.finalUrl,
      method: redirects.method ?? null,
      note: redirects.note,
      flags: (redirects.flags || []).map(toPublicFinding),
    },
    reputation: {
      status: reputation.status,
      source: reputation.source,
      note: reputation.note,
      reference: reputation.reference ?? null,
      details: reputation.details ?? [],
      checkedUrls: reputation.checkedUrls ?? [parsed.cleanUrl],
      flaggedUrl: reputation.flaggedUrl ?? null,
    },
    checks: checks.map((c) => ({ id: c.id, label: c.label, status: c.status, detail: c.detail })),
    checksPerformed: checks.map((c) => (c.status === "passed" ? c.label : `${c.label} — ${c.status}`)),
    ...(args.debug ? { debug: args.debug } : {}),
    engine,
  };
}

export interface InspectDeps {
  /** Reputation providers to consult (see ReputationProvider interface). */
  providers: ReputationProvider[];
  /** Redirect-chain follower. Injected for tests. */
  followRedirects: (url: string) => Promise<UrlRedirectCheckShape>;
  /** Optional AI analysis; return null when no AI is configured. */
  gemini: (ctx: {
    cleanUrl: string;
    hostname: string;
    registrableDomain: string;
    subdomainLabels: string[];
    pathname: string;
    search: string;
    flags: UrlFlag[];
    reputation: ReputationLookupResult;
    redirects: UrlRedirectCheckShape;
  }) => Promise<any>;
  /** Optional fetch impl passed down to reputation providers (tests). */
  fetchImpl?: typeof fetch;
  /** DNS/TLS/RDAP/Tranco intelligence. Injected for tests. */
  intel?: UrlIntel;
}

const GEMINI_MODELS = [
  process.env.GEMINI_MODEL || "gemini-3.8-flash",
  "gemini-2.0-flash",
  "gemini-1.5-flash",
].filter((m, i, arr) => Boolean(m) && arr.indexOf(m) === i);
const GEMINI_TIMEOUT_MS = 9000;
const AI_COOLDOWN_MS = 5 * 60 * 1000;
const AI_RPM = Math.max(1, Number(process.env.AI_RPM) || 10);
const AI_MAX_CONCURRENCY = Math.max(1, Number(process.env.AI_MAX_CONCURRENCY) || 1);
const AI_DOMAIN_TTL_MS = 24 * 60 * 60 * 1000;

let aiCooldownUntil = 0;
let aiInFlight = 0;
let aiWindowStart = 0;
let aiWindowCount = 0;
const aiDomainCache = new Map<string, { expires: number; value: any }>();

/** Short, log-safe summary of an AI failure (the SDK message is a whole JSON blob). */
function aiErrorSummary(err: any): { status: number | string; message: string; rateLimited: boolean; modelNotFound: boolean } {
  const status = err?.status ?? err?.statusCode ?? err?.code ?? "n/a";
  let message = String(err?.message || err || "unknown error");
  const rateLimited = /429/.test(String(status)) || /RESOURCE_EXHAUSTED|quota exceeded|rate limit/i.test(message);
  const modelNotFound = /404/.test(String(status)) || /model.*(not found|not supported)|not found.*model|unsupported model/i.test(message);
  if (rateLimited) message = "rate limit / quota exceeded";
  else if (message.length > 160) message = message.slice(0, 160) + "…";
  return { status, message, rateLimited, modelNotFound };
}

function aiSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

/** Honour a Retry-After header, or the "Please retry in Ns" text in the message. */
function aiRetryAfterMs(err: any): number | null {
  const header = err?.headers?.["retry-after"] ?? err?.response?.headers?.["retry-after"] ?? err?.retryAfter;
  const fromHeader = header != null ? Number(header) * 1000 : NaN;
  if (Number.isFinite(fromHeader) && fromHeader > 0) return fromHeader;
  const match = /retry in ([\d.]+)\s*s/i.exec(String(err?.message || ""));
  return match ? Math.ceil(parseFloat(match[1]) * 1000) : null;
}

/** Startup check: list the models the key can access and flag a bad GEMINI_MODEL. */
async function logGeminiModels(): Promise<void> {
  const ai = getGenAI();
  if (!ai) {
    console.info("[ai] GEMINI_API_KEY not set — AI analysis is disabled (checks fall back to deterministic signals)");
    return;
  }
  const configured = GEMINI_MODELS[0];
  try {
    const pager: any = await (ai as any).models.list();
    const ids: string[] = [];
    for await (const m of pager) {
      const id = String(m?.name || "").replace(/^models\//, "");
      if (id) ids.push(id);
      if (ids.length >= 200) break;
    }
    const valid = ids.includes(configured);
    console.info(
      `[ai] configured model "${configured}" ${valid ? "is available" : "was NOT found for this key"}; available: ${ids.slice(0, 40).join(", ") || "(none)"}${ids.length > 40 ? ", …" : ""}`
    );
  } catch (err: any) {
    const info = aiErrorSummary(err);
    console.error(`[ai] could not list models (status=${info.status}): ${info.message}`);
  }
}

async function defaultGeminiAnalyze(ctx: Parameters<InspectDeps["gemini"]>[0]): Promise<any> {
  const ai = getGenAI();
  if (!ai) return null; // not configured → check is simply omitted

  // Per-domain cache (24h) — the model's verdict for a domain rarely changes.
  const cacheKey = (ctx.registrableDomain || ctx.hostname || "").toLowerCase();
  const cached = cacheKey ? aiDomainCache.get(cacheKey) : undefined;
  if (cached && Date.now() < cached.expires) return cached.value;

  // Global guards: cooldown after a quota error, concurrency limit, RPM limiter.
  if (Date.now() < aiCooldownUntil) return { _error: true, rateLimited: true, message: "AI temporarily rate limited" };
  if (aiInFlight >= AI_MAX_CONCURRENCY) return { _error: true, rateLimited: true, message: "AI concurrency limit reached" };
  const now = Date.now();
  if (now - aiWindowStart >= 60_000) {
    aiWindowStart = now;
    aiWindowCount = 0;
  }
  if (aiWindowCount >= AI_RPM) return { _error: true, rateLimited: true, message: "AI requests-per-minute limit reached" };
  aiWindowCount++;
  aiInFlight++;

  const prompt = `You are the URL threat-intelligence engine of "Online Safety Guard".
Analyze the COMPLETE URL below — not just the domain. Consider the scheme, any credentials before '@', subdomain structure, registrable domain, path, query string, and parameters.

Full URL: ${ctx.cleanUrl}
Hostname: ${ctx.hostname}
Registered domain: ${ctx.registrableDomain}
Subdomains: ${ctx.subdomainLabels.join(".") || "(none)"}
Path: ${ctx.pathname || "/"}
Query: ${ctx.search || "(none)"}

Local structural findings:
${JSON.stringify(ctx.flags)}

Malware reputation result:
${JSON.stringify(ctx.reputation)}

Redirect behaviour:
${JSON.stringify(ctx.redirects)}

Evaluate: typosquatting, brand impersonation (PayPal, Apple, Google, Microsoft, Amazon, Netflix, banks, USPS, FedEx, UPS, DHL, Coinbase, Meta, etc.), deceptive subdomains, phishing/malware reputation, open redirects, credential-harvesting paths, and suspicious parameters.
Return strict JSON:
{
  "isSuspicious": boolean,
  "threatLevel": "'HIGH', 'MEDIUM' or 'LOW'",
  "spoofedBrand": "Brand being impersonated or null",
  "officialDomain": "The genuine official domain if a brand was identified, otherwise null",
  "verifiedOfficial": "true only if you can confidently confirm this is the official site of an identified, well-known organisation",
  "reason": "Clear, specific explanation of findings in the full URL"
}`;

  try {
    let lastError: any = null;
    for (const model of GEMINI_MODELS) {
      for (let attempt = 1; attempt <= 2; attempt++) {
        let timer: NodeJS.Timeout | undefined;
        try {
          const response = await Promise.race([
            ai.models.generateContent({ model, contents: prompt, config: { responseMimeType: "application/json" } }),
            new Promise((_resolve, reject) => {
              timer = setTimeout(() => reject(new Error("ai-timeout")), GEMINI_TIMEOUT_MS);
              timer.unref?.();
            }),
          ]);
          if (timer) clearTimeout(timer);
          const parsed = JSON.parse((response as any)?.text || "{}");
          if (cacheKey) aiDomainCache.set(cacheKey, { expires: Date.now() + AI_DOMAIN_TTL_MS, value: parsed });
          return parsed;
        } catch (err: any) {
          if (timer) clearTimeout(timer);
          lastError = err;
          const info = aiErrorSummary(err);
          console.error(`[ai] model=${model} attempt ${attempt}/2 failed (status=${info.status}): ${info.message}`);
          if (info.rateLimited) {
            // Respect Retry-After, else exponential-ish cooldown; never retry a quota error.
            const wait = aiRetryAfterMs(err) ?? AI_COOLDOWN_MS;
            aiCooldownUntil = Date.now() + Math.min(wait, AI_COOLDOWN_MS * 4);
            return { _error: true, rateLimited: true, message: "AI rate limit / quota exceeded" };
          }
          if (info.modelNotFound) break; // fall through to the next model in the chain
          // Transient: back off with jitter, then retry once.
          await aiSleep(Math.min(4000, 400 * 2 ** (attempt - 1)) + Math.floor(Math.random() * 250));
        }
      }
    }
    return { _error: true, message: aiErrorSummary(lastError).message };
  } finally {
    aiInFlight = Math.max(0, aiInFlight - 1);
  }
}

export function createDefaultInspectDeps(): InspectDeps {
  return {
    providers: [...DEFAULT_REPUTATION_PROVIDERS],
    followRedirects: (url) => followRedirectChain(url),
    gemini: defaultGeminiAnalyze,
    intel: defaultIntel,
  };
}

/**
 * Full inspection pipeline: local heuristics + live reputation + redirect
 * following + optional AI. Exported so tests can inject fake network deps.
 */
export async function inspectUrl(
  rawUrl: string,
  deps: InspectDeps = createDefaultInspectDeps(),
  opts?: { debug?: boolean }
): Promise<Record<string, any>> {
  const timeIt = async <T>(fn: () => Promise<T>): Promise<{ ms: number; value: T }> => {
    const start = Date.now();
    const value = await fn();
    return { ms: Date.now() - start, value };
  };
  const parsed = parseUrl(String(rawUrl));
  const webScheme = parsed.scheme === "http" || parsed.scheme === "https";

  // 1) Local, instant analysis
  const brand = analyzeBrand(parsed);
  const subdomainFlags: UrlFlag[] = [];
  if (!brand.officialMatch && parsed.subdomainLabels.length) {
    const labelsJoined = parsed.subdomainLabels.join(".");
    for (const b of KNOWN_BRANDS) {
      const hitToken = b.tokens.find((t) => {
        const tokenNorm = normalizeForMatch(t);
        return tokenMatchesSubdomains(labelsJoined, tokenNorm, b.domains.map((d) => d.toLowerCase()), parsed.hostname.toLowerCase());
      });
      if (hitToken) {
        subdomainFlags.push({
          severity: "medium",
          title: "Brand name hidden in subdomain of unrelated host",
          evidence: labelsJoined,
          explanation: `A subdomain contains the brand name "${b.name}", but the registered domain belongs to someone else. The real owner of the page is the registrable domain.`,
        });
        if (!brand.spoofedBrand) brand.spoofedBrand = b.name;
        break;
      }
    }
  }
  const structuralFlags = structuralUrlFlags(parsed, brand.officialMatch);
  const queryFlags = queryParameterFindings(parsed);

  // Click-tracking detection (track./click./links./email./go. hosts, ESP domains
  // and embedded destination URLs). Trackers are judged on their destination.
  let tracking: { isTracking: boolean; provider?: string; embeddedDestination?: string } | null = null;
  if (webScheme) {
    try {
      tracking = trackingInfo(new URL(parsed.cleanUrl));
    } catch {
      tracking = null;
    }
  }

  // 2) Live redirect + reputation checks. The original URL and the redirect
  //    chain are resolved in parallel; once the final destination is known the
  //    reputation sources are queried for it as well, so a clean-looking entry
  //    URL cannot hide a malicious landing page.
  const [repT, redirT] = await Promise.all([
    timeIt(() =>
      webScheme
        ? runReputationLookup({ url: parsed.cleanUrl, host: parsed.hostname }, deps.providers, { fetchImpl: deps.fetchImpl })
        : Promise.resolve({ status: "not_configured", source: "none", note: "No reputation lookup for non-web scheme." } as ReputationLookupResult)
    ),
    timeIt(() =>
      webScheme
        ? deps.followRedirects(parsed.cleanUrl)
        : Promise.resolve({ status: "skipped", hops: [], finalUrl: null, method: null, note: "Non-web protocol." } as UrlRedirectCheckShape)
    ),
  ]);
  const originalReputation = repT.value;
  const redirects = redirT.value;
  let reputationMs = repT.ms;
  const redirectMs = redirT.ms;

  const reputationEntries: Array<{ url: string; result: ReputationLookupResult }> = [
    { url: parsed.cleanUrl, result: originalReputation },
  ];
  const finalUrl = redirects.finalUrl;
  if (webScheme && finalUrl && !urlsMatch(finalUrl, parsed.cleanUrl)) {
    const finalHost = safeHostname(finalUrl);
    if (finalHost) {
      const finalRep = await timeIt(() =>
        runReputationLookup({ url: finalUrl, host: finalHost }, deps.providers, { fetchImpl: deps.fetchImpl })
      );
      reputationMs += finalRep.ms;
      reputationEntries.push({ url: finalUrl, result: finalRep.value });
    }
  }
  const reputationRaw = combineReputationResults(reputationEntries);

  // Domain intelligence (DNS, TLS, RDAP age, Tranco). Each lookup is independent
  // and cached (24h); a missing/failed lookup lowers confidence, never risk.
  let dnsResult: { exists: boolean | null } = { exists: null };
  let tlsResult: { valid: boolean | null } = { valid: null };
  let ageResult: { ageDays: number | null } = { ageDays: null };
  let trancoResult: { rank: number | null; error?: string } = { rank: null, error: "not available right now" };
  let dnsMs = 0;
  let tlsMs = 0;
  let ageMs = 0;
  let trancoMs = 0;
  const intelDeps = deps.intel;
  if (intelDeps && webScheme) {
    const [d, t, a, tr] = await Promise.all([
      timeIt(() => intelDeps.dns(parsed.hostname).catch(() => ({ exists: null as boolean | null }))),
      timeIt(() =>
        parsed.scheme === "https"
          ? intelDeps.tls(parsed.hostname).catch(() => ({ valid: null as boolean | null }))
          : Promise.resolve({ valid: null as boolean | null })
      ),
      timeIt(() => intelDeps.domainAgeDays(parsed.registrableDomain).catch(() => ({ ageDays: null as number | null }))),
      timeIt(() => intelDeps.trancoRank(parsed.hostname).catch(() => ({ rank: null as number | null, error: "lookup failed" }))),
    ]);
    dnsResult = d.value;
    dnsMs = d.ms;
    tlsResult = t.value;
    tlsMs = t.ms;
    ageResult = a.value;
    ageMs = a.ms;
    trancoResult = tr.value as { rank: number | null; error?: string };
    trancoMs = tr.ms;
  }

  const finalDestHost = redirects.finalUrl ? safeHostname(redirects.finalUrl) : null;
  const finalDestination =
    redirects.status === "redirect" && finalDestHost
      ? { url: redirects.finalUrl as string, wellKnown: isWellKnownDomain(finalDestHost) }
      : null;
  const trackingUnverified =
    Boolean(tracking?.isTracking) &&
    (redirects.status === "inconclusive" || redirects.status === "error" || redirects.status === "skipped");

  // 3) Optional AI analysis. It is advisory only and is called ONLY when the
  //    deterministic score is borderline (25–70) and no reputation source gave a
  //    clear verdict — otherwise it adds cost/noise without changing the result.
  const flaggedUrl = reputationRaw.flaggedUrl || parsed.cleanUrl;
  const reputationFlaggedFinal =
    reputationRaw.status === "malicious" &&
    Boolean(redirects.finalUrl) &&
    !urlsMatch(flaggedUrl, parsed.cleanUrl) &&
    urlsMatch(flaggedUrl, redirects.finalUrl!);
  const baseFlags = [...brand.flags, ...subdomainFlags, ...structuralFlags, ...queryFlags];
  const deterministicScore = riskScoreFromSignals(
    buildSignals({
      flags: baseFlags,
      reputationMalicious: reputationRaw.status === "malicious",
      reputationClean: reputationRaw.status === "clean",
      reputationSource: reputationRaw.source,
      reputationFlaggedUrl: reputationRaw.flaggedUrl ?? null,
      reputationFlaggedFinal,
      tracking: tracking
        ? { isTracking: tracking.isTracking, provider: tracking.provider, destinationUnverified: trackingUnverified }
        : null,
      finalDestination,
      intel: intelDeps
        ? { tlsValid: tlsResult.valid, dnsExists: dnsResult.exists, domainAgeDays: ageResult.ageDays, trancoRank: trancoResult.rank }
        : null,
    })
  );
  const reputationClear = reputationRaw.status === "malicious" || reputationRaw.status === "clean";
  const aiEligible = Boolean(deps.gemini) && !reputationClear && deterministicScore >= 25 && deterministicScore <= 70;
  let aiMs = 0;
  let gemini: any = null;
  if (aiEligible) {
    const aiT = await timeIt(() =>
      deps.gemini!({
        cleanUrl: parsed.cleanUrl,
        hostname: parsed.hostname,
        registrableDomain: parsed.registrableDomain,
        subdomainLabels: parsed.subdomainLabels,
        pathname: parsed.pathname,
        search: parsed.search,
        flags: baseFlags,
        reputation: reputationRaw,
        redirects,
      })
    );
    gemini = aiT.value;
    aiMs = aiT.ms;
  }

  // 4) Per-check statuses — a check that could not run NEVER counts as passed.
  const checks: UrlCheckShape[] = ([
    {
      id: "url-structure",
      label: "URL structure",
      status: statusFromFlags(structuralFlags),
      detail: structuralFlags.length ? `${structuralFlags.length} structural issue(s)` : undefined,
    },
    {
      id: "brand",
      label: "Brand & typosquatting",
      status: statusFromFlags(brand.flags),
      detail: brand.spoofedBrand ? `possible impersonation of ${brand.spoofedBrand}` : undefined,
    },
    {
      id: "subdomain",
      label: "Subdomain analysis",
      status: statusFromFlags(subdomainFlags),
      detail: subdomainFlags.length ? "suspicious subdomain layout" : undefined,
    },
    {
      id: "query-params",
      label: "Query parameter analysis",
      status: statusFromFlags(queryFlags),
      detail: queryFlags.length ? queryFlags.filter((f) => f.title === "Tracking parameters present").length ? "tracking params only — informational" : "possible open redirect parameter" : undefined,
    },
    {
      id: "redirect",
      label: "Redirect behaviour",
      status: redirectCheckStatus(redirects),
      detail: redirects.status === "inconclusive" || redirects.status === "error"
        ? `not run — ${redirects.note || "could not verify"}`
        : redirects.status === "skipped"
        ? `not run — ${redirects.note || "skipped"}`
        : redirects.status === "redirect"
        ? redirects.flags?.length ? `${redirects.flags.length} redirect flag(s)` : "redirected"
        : undefined,
    },
    {
      id: "reputation",
      label: "Reputation & threat databases",
      status: reputationCheckStatus(reputationRaw),
      detail: reputationCheckDetail(reputationRaw),
    },
    intelDeps
      ? {
          id: "dns",
          label: "DNS resolution",
          status: dnsResult.exists === true ? "passed" : dnsResult.exists === false ? "failed" : "error",
          detail: dnsResult.exists === true ? "host resolves" : dnsResult.exists === false ? "no DNS record" : "lookup failed",
        }
      : null,
    intelDeps && parsed.scheme === "https"
      ? {
          id: "tls",
          label: "TLS certificate",
          status: tlsResult.valid === true ? "passed" : tlsResult.valid === false ? "failed" : "error",
          detail: tlsResult.valid === true ? "valid certificate" : tlsResult.valid === false ? "certificate problem" : "could not verify",
        }
      : null,
    intelDeps
      ? {
          id: "domain-age",
          label: "Domain age (RDAP)",
          status: ageResult.ageDays === null ? "error" : "passed",
          detail: ageResult.ageDays === null ? "not run — RDAP unavailable" : `${ageResult.ageDays} day(s) old`,
        }
      : null,
    intelDeps
      ? {
          id: "tranco",
          label: "Tranco popularity",
          status: trancoResult.error ? "skipped" : "passed",
          detail: trancoResult.error ? "not run — Not available right now" : trancoResult.rank ? `rank #${trancoResult.rank}` : "not in top list",
        }
      : null,
    tracking?.isTracking
      ? {
          id: "tracking",
          label: "Click-tracking link",
          status: "passed",
          detail: trackingUnverified ? "destination not resolved" : `tracker: ${tracking.provider || "email service"}`,
        }
      : null,
  ] as Array<UrlCheckShape | null>).filter((c): c is UrlCheckShape => c !== null);

  if (gemini && gemini._error) {
    checks.push({
      id: "ai-semantic",
      label: "AI semantic analysis",
      // End users get a friendly reason; the raw status/message is admin-only (debug view).
      status: gemini.rateLimited ? "skipped" : "error",
      detail: "not run — Not available right now",
    });
  }

  const debugPayload = opts?.debug
    ? {
        url: parsed.cleanUrl,
        checks: checks.map((c) => ({
          id: c.id,
          label: c.label,
          status: c.status,
          durationMs:
            c.id === "redirect"
              ? redirectMs
              : c.id === "reputation"
              ? reputationMs
              : c.id === "dns"
              ? dnsMs
              : c.id === "tls"
              ? tlsMs
              : c.id === "domain-age"
              ? ageMs
              : c.id === "tranco"
              ? trancoMs
              : c.id === "ai-semantic"
              ? aiMs
              : 0,
          reason: c.detail || "",
        })),
        reputation: {
          status: reputationRaw.status,
          source: reputationRaw.source,
          note: reputationRaw.note || null,
          checkedUrls: reputationRaw.checkedUrls || null,
        },
        tranco: trancoStatus(),
        ai: {
          eligible: aiEligible,
          models: GEMINI_MODELS,
          state: gemini ? ((gemini as any)._error ? ((gemini as any).rateLimited ? "rate_limited" : "error") : "ok") : "not_run",
          message: (gemini as any)?.message ?? null,
        },
        intel: {
          dnsExists: dnsResult.exists,
          tlsValid: tlsResult.valid,
          domainAgeDays: ageResult.ageDays,
          trancoRank: trancoResult.rank,
          trancoError: trancoResult.error || null,
        },
        timings: { reputation: reputationMs, redirect: redirectMs, dns: dnsMs, tls: tlsMs, domainAge: ageMs, tranco: trancoMs, ai: aiMs },
        scoring: {
          weights: CHECK_WEIGHTS,
          maxNegativePoints: MAX_NEGATIVE_POINTS,
          thresholds: VERDICT_THRESHOLDS,
          deterministicScore,
          criticalCheckIds: [...CRITICAL_CHECK_IDS],
        },
        env: {
          GEMINI_MODEL: GEMINI_MODELS[0],
          URLHAUS_API_KEY: Boolean(process.env.URLHAUS_API_KEY),
          GOOGLE_SAFE_BROWSING_API_KEY: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.SAFE_BROWSING_API_KEY),
          OPENPHISH_FEED_FILE: process.env.OPENPHISH_FEED_FILE || "data/openphish.txt",
          TRANCO_LIST_URL: process.env.TRANCO_LIST_URL || "https://tranco-list.eu/top-1m.csv.zip",
          EVENT_SALT: Boolean(process.env.EVENT_SALT),
        },
      }
    : null;

  return buildInspectionResponse({
    parsed,
    brandFlags: brand.flags,
    structuralFlags,
    subdomainFlags,
    queryFlags,
    spoofedBrand: brand.spoofedBrand,
    officialDomain: brand.officialDomain,
    officialBrandName: brand.officialBrandName,
    checks,
    reputation: reputationRaw,
    redirects,
    tracking: tracking ? { isTracking: tracking.isTracking, provider: tracking.provider, destinationUnverified: trackingUnverified } : null,
    finalDestination,
    intel: intelDeps
      ? { tlsValid: tlsResult.valid, dnsExists: dnsResult.exists, domainAgeDays: ageResult.ageDays, trancoRank: trancoResult.rank }
      : null,
    ai: gemini && !gemini._error ? { threatLevel: gemini.threatLevel } : null,
    debug: debugPayload,
    gemini,
    engine: deps.gemini ? (getGenAI() ? "gemini-3.8-flash" : "heuristic-url-engine") : "heuristic-url-engine",
  });
}

// Domain and URL Threat Inspector
app.post("/api/inspect-domain", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: "URL or domain is required" });
    }
    const cacheKey = `inspect:${String(url).trim().toLowerCase()}`;
    const cachedResult = verdictCacheGet(cacheKey);
    if (cachedResult) return res.json({ ...cachedResult, cached: true });
    const result = await inspectUrl(String(url), createDefaultInspectDeps());
    verdictCacheSet(cacheKey, result);
    return res.json(result);
  } catch (error: any) {
    console.error("Error inspecting domain:", error);
    return res.status(500).json({ error: error?.message || "Domain inspection failed" });
  }
});

// ---------------------------------------------------------------------------
// Outlook add-in static assets (/outlook/*)
//
// Served with add-in-only headers so Outlook can frame the task pane. No
// X-Frame-Options is set here (it would block framing); frame-ancestors is
// limited to the Office hosts. Nothing else on the server uses these headers.
// ---------------------------------------------------------------------------

function outlookDir(): string {
  const distOutlook = path.join(process.cwd(), "dist", "outlook");
  if (fs.existsSync(distOutlook)) return distOutlook;
  return path.join(process.cwd(), "outlook");
}

const OUTLOOK_FRAME_ANCESTORS = [
  "https://outlook.office.com",
  "https://outlook.office365.com",
  "https://outlook.live.com",
  "https://*.office.com",
].join(" ");

function setOutlookHeaders(res: ExpressResponse): void {
  res.set(
    "Content-Security-Policy",
    "default-src 'none'; " +
      "script-src 'self' https://appsforoffice.microsoft.com; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; " +
      "connect-src 'self'; " +
      "object-src 'none'; base-uri 'self'; " +
      `frame-ancestors ${OUTLOOK_FRAME_ANCESTORS}`
  );
  res.set("X-Robots-Tag", "noindex, nofollow");
  res.set("Referrer-Policy", "no-referrer");
  res.set("Cache-Control", "no-store");
}

/** Mounts /outlook/* with add-in-only headers, before any SPA catch-all. */
export function mountOutlook(target: Express): void {
  target.use("/outlook", (req, res, next) => {
    setOutlookHeaders(res);
    // The manifest stays in the repo and must never be served.
    if (/^\/manifest\.(xml|json)$/i.test(req.path)) {
      res.status(404).send("Not found");
      return;
    }
    next();
  });
  target.use(
    "/outlook",
    express.static(outlookDir(), { index: false, fallthrough: false })
  );
}

// Vite middleware for local development only
export async function attachViteDevServer() {
  if (process.env.NODE_ENV === "production") return;
  const { createServer: createViteServer } = await import("vite");
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: "spa",
  });
  app.use(vite.middlewares);
}

// Production static serving (standalone Node deployment)
export async function startServer() {
  // Link-protection gateway (POST /api/inspect, GET /go/:id, /admin).
  // Mounted before the SPA/static middleware so its routes are never shadowed.
  const { createGatewayRouter } = await import("./gateway");
  app.use(
    createGatewayRouter({
      engine: { parseUrl, getRegistrableDomain, inspectUrl, createDefaultInspectDeps },
    })
  );

  // Outlook add-in assets, served with add-in-only headers before any catch-all.
  mountOutlook(app);

  // Background intelligence: load/refresh the Tranco list and log model access.
  startTrancoLoader();
  void logGeminiModels();

  if (process.env.NODE_ENV !== "production") {
    await attachViteDevServer();
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Online Safety Guard server running on http://0.0.0.0:${PORT}`);
  });
}

export { app, PORT };

// Only start automatically when run directly (not when imported by the tests
// or the Vercel function). Handles both the ESM dev path (tsx) and the compiled
// CommonJS bundle, where `import.meta.url` is not available.
function isEntryPoint(): boolean {
  try {
    if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
      return true;
    }
  } catch {
    // Not a CommonJS runtime — fall through to the ESM check.
  }
  try {
    const metaUrl = (import.meta as { url?: string } | undefined)?.url;
    if (metaUrl && process.argv[1] && fileURLToPath(metaUrl) === path.resolve(process.argv[1])) {
      return true;
    }
  } catch {
    // import.meta.url is unavailable here.
  }
  return false;
}

if (isEntryPoint()) {
  startServer();
}
