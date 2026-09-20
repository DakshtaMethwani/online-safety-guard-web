export type SafetyStatus = 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS_SCAM';

export interface RedFlag {
  flag: string;
  evidence: string;
  severity: 'high' | 'medium' | 'low';
}

export interface HighlightPhrase {
  text: string;
  category: 'danger' | 'warning' | 'suspicious_link';
  explanation: string;
}

export interface SafetyAdvice {
  immediateActions: string[];
  whatNeverToDo: string[];
  officialVerificationStep: string;
}

export interface SenderAssessment {
  isSenderSuspicious: boolean;
  notes: string;
}

export interface SignalBreakdownItem {
  category: string;
  flag: string;
  severity: 'high' | 'medium' | 'low';
  weight: number;
  tactic: string;
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  originalMessage: string;
  sender?: string;
  platform?: string;
  safetyStatus: SafetyStatus;
  riskScore: number;
  scamType: string;
  verdictSummary: string;
  redFlags: RedFlag[];
  tacticsUsed: string[];
  highlightPhrases: HighlightPhrase[];
  safetyAdvice: SafetyAdvice;
  recommendedResponse: string;
  senderAssessment: SenderAssessment;
  engine?: string;
  /** Deterministic weighted signals that drove the score. */
  signalBreakdown?: SignalBreakdownItem[];
  /** Verdict from the rule engine alone. */
  deterministicVerdict?: SafetyStatus;
  /** Verdict from Gemini alone (may be more lenient than the final one). */
  aiVerdict?: SafetyStatus;
  /** True when deterministic signals overruled a more lenient AI verdict. */
  deterministicOverride?: boolean;
}

export interface PresetMessage {
  id: string;
  title: string;
  category: string;
  platform: string;
  sender: string;
  text: string;
  expectedRisk: 'SAFE' | 'DANGEROUS';
  badge: string;
}

// ---------------------------------------------------------------------------
// Suspicious Link & Domain Inspector
// ---------------------------------------------------------------------------

/**
 * Every check the engine runs ends in exactly one of these states.
 * - passed:  the check ran and produced a healthy result
 * - warning: the check ran and found something worth caution
 * - failed:  the check ran and found a definite problem
 * - skipped: the check could not run because it was not configured/eligible
 * - error:   the check could not run (timeout, 4xx/5xx, network failure)
 *
 * Skipped/errored checks must NEVER count as "passed" and downgrade the
 * overall verdict to UNVERIFIED.
 */
export type CheckStatus = 'passed' | 'warning' | 'failed' | 'skipped' | 'error';

export interface UrlCheck {
  /** Stable machine id, e.g. "url-structure", "malware-reputation" */
  id: string;
  /** Short human label shown in the "Checks performed" chips */
  label: string;
  status: CheckStatus;
  /** One-line detail shown with the chip (e.g. "not run — HTTP 403") */
  detail?: string;
}

export type UrlVerdict = 'HIGH_RISK' | 'SUSPICIOUS' | 'VERIFICATION_REQUIRED' | 'LOW_RISK';
// Legacy verdicts kept for backward-compat with old saved results.
export type LegacyUrlVerdict =
  | 'MALICIOUS'
  | 'UNVERIFIED'
  | 'LOW_THREAT'
  | 'STRUCTURALLY_VALID'
  | 'LIKELY_AUTHENTIC';

export interface UrlFinding {
  /** Display severity: critical / warning / info */
  severity: 'critical' | 'warning' | 'info';
  title: string;
  evidence?: string;
  explanation: string;
}

export interface UrlStructureSummary {
  status: 'valid' | 'flagged';
  detail: string;
}

export interface UrlSignalItem {
  id: string;
  label: string;
  points: number;
  reason: string;
  kind: 'risk' | 'safe' | 'info';
}

export interface UrlRedirectHop {
  url: string;
  /** HTTP status code observed for this hop (0 = network failure) */
  status: number;
}

export type UrlRedirectStatus = 'none' | 'redirect' | 'skipped' | 'inconclusive' | 'error';

export interface UrlRedirectCheck {
  status: UrlRedirectStatus;
  hops: UrlRedirectHop[];
  finalUrl: string | null;
  /** HTTP method used for the final request of the last hop */
  method?: 'HEAD' | 'GET' | null;
  note?: string;
  flags?: UrlFinding[];
}

export type UrlReputationStatus =
  | 'clean'
  | 'malicious'
  | 'not_configured'
  | 'error'
  | 'timeout'
  | 'rate_limited';

export interface UrlReputationCheck {
  status: UrlReputationStatus;
  source: string;
  note?: string;
  reference?: string | null;
  details?: Array<{ url: string; threat: string; dateAdded: string }>;
  /** URLs submitted to the sources (original link + post-redirect destination). */
  checkedUrls?: string[];
  /** The URL that a source actually flagged as a threat. */
  flaggedUrl?: string | null;
}

export interface DomainInspectionResult {
  domain: string;
  registrableDomain?: string;
  fullUrl: string;
  isSuspicious: boolean;
  threatLevel: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  verdict?: UrlVerdict;
  /** Final risk score (0–100) derived from the verified results. */
  riskScore?: number;
  /** Confidence (0–100): how many weighted checks actually ran. */
  confidence?: number;
  /** Deterministic "why this score" signals with signed points. */
  signals?: UrlSignalItem[];
  /** One-line reason shown next to the badge (esp. for VERIFICATION_REQUIRED) */
  verdictReason?: string;
  spoofedBrand?: string | null;
  reason: string;
  officialDomain?: string | null;
  findings?: UrlFinding[];
  /** Legacy flat labels; use `checks` for real per-check statuses. */
  checksPerformed?: string[];
  /** Real per-check statuses used by the "Checks performed" UI. */
  checks?: UrlCheck[];
  /** Split-out structure status for the "URL structure: Valid" field. */
  urlStructure?: UrlStructureSummary;
  redirects?: UrlRedirectCheck | null;
  reputation?: UrlReputationCheck | null;
  engine?: string;
}