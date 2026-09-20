import React, { useState } from 'react';
import { DomainInspectionResult, UrlCheck, UrlFinding } from '../types';
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Loader2,
  Search,
  Link2,
  Bug,
  Database,
  CheckCircle2,
  MinusCircle,
  Info,
  XCircle,
  HelpCircle,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Verdict / badge metadata
// ---------------------------------------------------------------------------

type VerdictKey = 'HIGH_RISK' | 'SUSPICIOUS' | 'VERIFICATION_REQUIRED' | 'LOW_RISK';

const verdictMeta: Record<VerdictKey, { label: string; short: string; text: string; badge: string }> = {
  HIGH_RISK: {
    label: 'High Risk — Do Not Open',
    short: 'High Risk',
    text: 'text-rose-600 dark:text-rose-400',
    badge:
      'bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300 border border-rose-300 dark:border-rose-500/40',
  },
  SUSPICIOUS: {
    label: 'Proceed With High Caution',
    short: 'Suspicious',
    text: 'text-amber-600 dark:text-amber-400',
    badge:
      'bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300 border border-amber-300 dark:border-amber-500/40',
  },
  VERIFICATION_REQUIRED: {
    label: 'Unverified',
    short: 'Unverified',
    text: 'text-amber-600/90 dark:text-amber-400/90',
    badge:
      'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300/90 border border-amber-300/70 dark:border-amber-500/30',
  },
  LOW_RISK: {
    label: 'Low Risk / Safe',
    short: 'Low Risk',
    text: 'text-emerald-600 dark:text-emerald-400',
    badge:
      'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-500/40',
  },
};

function resolveVerdictKey(result: DomainInspectionResult): VerdictKey {
  const v = result.verdict as string | undefined;
  if (v === 'HIGH_RISK' || v === 'SUSPICIOUS' || v === 'VERIFICATION_REQUIRED' || v === 'LOW_RISK') return v;
  // Backward-compatible fallback for older saved results.
  if (v === 'MALICIOUS') return 'HIGH_RISK';
  if (v === 'UNVERIFIED') return 'VERIFICATION_REQUIRED';
  if (v === 'LOW_THREAT' || v === 'LIKELY_AUTHENTIC' || v === 'STRUCTURALLY_VALID') return 'LOW_RISK';
  if (result.threatLevel === 'HIGH') return 'HIGH_RISK';
  if (result.threatLevel === 'MEDIUM') return 'SUSPICIOUS';
  if (result.threatLevel === 'UNKNOWN') return 'VERIFICATION_REQUIRED';
  return 'LOW_RISK';
}

// ---------------------------------------------------------------------------
// Findings severity metadata (public severities: critical / warning / info)
// ---------------------------------------------------------------------------

const findingSeverityMeta: Record<
  UrlFinding['severity'],
  { label: string; badge: string; icon: 'shield' | 'triangle' | 'minus' | 'info' }
> = {
  critical: {
    label: 'Critical',
    badge:
      'bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300 border-rose-300 dark:border-rose-500/40',
    icon: 'shield',
  },
  warning: {
    label: 'Warning',
    badge:
      'bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300 border-amber-300 dark:border-amber-500/40',
    icon: 'triangle',
  },
  info: {
    label: 'Info',
    badge:
      'bg-slate-100 text-slate-700 dark:bg-slate-500/20 dark:text-slate-300 border-slate-300 dark:border-slate-500/40',
    icon: 'info',
  },
};

function FindingIcon({ sev }: { sev: UrlFinding['severity'] }) {
  if (sev === 'critical') return <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400" />;
  if (sev === 'warning') return <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />;
  return <Info className="w-4 h-4 text-slate-500 dark:text-slate-400" />;
}

function FindingRow({ f, key }: { f: UrlFinding; legacy?: boolean; key?: React.Key }) {
  const meta = findingSeverityMeta[f.severity] ?? findingSeverityMeta.info;
  return (
    <li className="flex gap-2.5 p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
      <div className="shrink-0 mt-0.5">
        <FindingIcon sev={f.severity} />
      </div>
      <div className="min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-bold text-slate-800 dark:text-slate-200">{f.title}</span>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${meta.badge}`}>
            {meta.label}
          </span>
        </div>
        {f.evidence && (
          <p className="text-[11px] font-mono text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-900 rounded px-1.5 py-0.5 mt-1 break-all inline-block">
            {f.evidence}
          </p>
        )}
        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed mt-1">{f.explanation}</p>
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
// "Checks performed" chips — real statuses, never a fabricated pass
// ---------------------------------------------------------------------------

const checkChipStyles: Record<UrlCheck['status'], { chip: string; icon: React.ReactNode }> = {
  passed: {
    chip: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-500/30',
    icon: <CheckCircle2 className="w-3 h-3" />,
  },
  warning: {
    chip: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-500/30',
    icon: <AlertTriangle className="w-3 h-3" />,
  },
  failed: {
    chip: 'bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-500/30',
    icon: <ShieldAlert className="w-3 h-3" />,
  },
  skipped: {
    chip: 'bg-slate-100 dark:bg-slate-500/10 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-600/40',
    icon: <MinusCircle className="w-3 h-3" />,
  },
  error: {
    chip: 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-300/90 border border-amber-200/80 dark:border-amber-500/30',
    icon: <XCircle className="w-3 h-3" />,
  },
};

function ChecksChips({ checks, legacy }: { checks?: UrlCheck[]; legacy?: string[] }) {
  if (checks && checks.length > 0) {
    return (
      <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
        <span className="text-slate-500 dark:text-slate-400 font-semibold">Checks performed:</span>
        {checks.map((c, i) => {
          const style = checkChipStyles[c.status];
          const notRun = c.status === 'skipped' || c.status === 'error';
          const label = notRun ? `${c.label} — not run` : c.label;
          return (
            <span
              key={`${c.id ?? i}-${i}`}
              title={c.detail}
              className={`px-2 py-0.5 rounded-full flex items-center gap-1 ${style.chip}`}
            >
              {style.icon}
              {label}
            </span>
          );
        })}
      </div>
    );
  }
  if (legacy && legacy.length > 0) {
    return (
      <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
        <span className="text-slate-500 dark:text-slate-400 font-semibold">Checks performed:</span>
        {legacy.map((c, i) => (
          <span
            key={i}
            className="px-2 py-0.5 rounded-full bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-500/30"
          >
            {c}
          </span>
        ))}
      </div>
    );
  }
  return null;
}

// ---------------------------------------------------------------------------
// Redirect card helpers
// ---------------------------------------------------------------------------

function redirectCardStyle(status?: string, hasFlags?: boolean) {
  if (status === 'redirect') {
    return hasFlags
      ? 'bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-500/40'
      : 'bg-sky-50 dark:bg-sky-950/20 border-sky-300 dark:border-sky-500/40';
  }
  if (status === 'none') return 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-300 dark:border-emerald-500/40';
  if (status === 'error') return 'bg-rose-50 dark:bg-rose-950/30 border-rose-300 dark:border-rose-500/40';
  if (status === 'inconclusive') return 'bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-500/40';
  return 'bg-slate-50 dark:bg-slate-950/60 border-slate-200 dark:border-slate-800';
}

function chainLabel(status: string): string {
  switch (status) {
    case 'redirect':
      return 'Redirect Chain';
    case 'none':
      return 'No Redirect';
    case 'error':
      return 'Unreachable';
    case 'inconclusive':
      return 'Inconclusive';
    case 'skipped':
      return 'Skipped';
    default:
      return 'Redirect Check';
  }
}

function RedirectCard({ redirects }: { redirects: NonNullable<DomainInspectionResult['redirects']> }) {
  const hasFlags = Boolean(redirects.flags && redirects.flags.length > 0);
  const status = redirects.status;
  return (
    <div className={`p-3.5 rounded-xl border text-xs space-y-1.5 ${redirectCardStyle(status, hasFlags)}`}>
      <div className="flex items-center gap-2 text-slate-800 dark:text-slate-200 font-bold uppercase tracking-wider">
        {status === 'error' ? (
          <XCircle className="w-4 h-4 text-rose-600 dark:text-rose-400" />
        ) : status === 'redirect' ? (
          <Link2 className="w-4 h-4 text-amber-600 dark:text-amber-400" />
        ) : status === 'inconclusive' ? (
          <HelpCircle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
        ) : status === 'none' ? (
          <Link2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
        ) : (
          <Link2 className="w-4 h-4 text-slate-500 dark:text-slate-400" />
        )}
        Redirect Check
      </div>

      {redirects.hops.length > 0 ? (
        <ol className="list-none space-y-0.5">
          {redirects.hops.map((h, i) => {
            // Legacy saved results may hold plain strings instead of objects.
            const hopUrl = typeof h === 'string' ? h : h.url;
            const hopStatus = typeof h === 'string' ? null : h.status;
            return (
              <li key={i} className="flex items-start gap-1.5 font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all">
                <span className="shrink-0 text-slate-400">{i + 1}.</span>
                <span className="min-w-0 break-all">{hopUrl}</span>
                {hopStatus !== null && (
                  <span
                    className={`shrink-0 px-1 rounded text-[10px] font-bold ${
                      hopStatus >= 400
                        ? 'bg-rose-100 dark:bg-rose-500/20 text-rose-700 dark:text-rose-300'
                        : hopStatus >= 300
                        ? 'bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-300'
                        : 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300'
                    }`}
                  >
                    {hopStatus || 'ERR'}
                  </span>
                )}
              </li>
            );
          })}
        </ol>
      ) : (
        <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
          {status === 'error'
            ? redirects.note || 'Could not reach the host.'
            : status === 'skipped'
            ? redirects.note || 'Redirect check was skipped.'
            : redirects.note || 'No redirects observed.'}
        </p>
      )}

      {redirects.note && redirects.hops.length > 0 && (
        <p className="text-slate-600 dark:text-slate-400 leading-relaxed">{redirects.note}</p>
      )}

      {redirects.finalUrl && (
        <div className="pt-0.5">
          <span className="text-slate-500 dark:text-slate-400 font-semibold">Final URL:</span>{' '}
          <span className="font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all">{redirects.finalUrl}</span>
          {redirects.method && <span className="text-slate-400 dark:text-slate-500"> (via {redirects.method})</span>}
        </div>
      )}

      {redirects.flags && redirects.flags.length > 0 && (
        <ul className="space-y-1 pt-0.5">
          {redirects.flags.map((f, i) => (
            <li key={i} className="flex gap-1.5 items-start">
              <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
              <div className="min-w-0">
                <span className="font-semibold text-amber-800 dark:text-amber-300">{f.title}</span>
                <p className="text-[11px] text-amber-700/80 dark:text-amber-400/70 leading-relaxed">{f.explanation}</p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reputation card helpers
// ---------------------------------------------------------------------------

function ReputationCard({ reputation }: { reputation: NonNullable<DomainInspectionResult['reputation']> }) {
  const s = reputation.status;
  const isMalicious = s === 'malicious';
  const isClean = s === 'clean';
  const isNotConfigured = s === 'not_configured';
  const isBlocked = s === 'error' || s === 'timeout' || s === 'rate_limited';
  const checkedCount = reputation.checkedUrls?.length ?? 1;

  return (
    <div
      className={`p-3.5 rounded-xl border text-xs space-y-1.5 ${
        isMalicious
          ? 'bg-rose-50 dark:bg-rose-950/30 border-rose-300 dark:border-rose-500/40'
          : isClean
          ? 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-300 dark:border-emerald-500/40'
          : isNotConfigured
          ? 'bg-slate-50 dark:bg-slate-950/60 border-slate-200 dark:border-slate-800'
          : 'bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-500/40'
      }`}
    >
      <div className="flex items-center gap-2 text-slate-800 dark:text-slate-200 font-bold uppercase tracking-wider">
        {isMalicious ? (
          <Bug className="w-4 h-4 text-rose-600 dark:text-rose-400" />
        ) : isClean ? (
          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
        ) : isNotConfigured ? (
          <Database className="w-4 h-4 text-slate-500 dark:text-slate-400" />
        ) : (
          <HelpCircle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
        )}
        Reputation Check
      </div>

      {isNotConfigured ? (
        <>
          <p className="text-amber-700 dark:text-amber-300/90 leading-relaxed">
            Verification required — {reputation.note || 'no reputation source is configured for this deployment.'}
          </p>
          <p className="text-slate-500 dark:text-slate-400 leading-relaxed">
            This URL has <span className="font-semibold">not</span> been checked against a threat database, so it is not reported as safe.
          </p>
        </>
      ) : isMalicious ? (
        <>
          <p className="text-rose-700 dark:text-rose-300 leading-relaxed">
            {reputation.note || 'Listed as a confirmed threat.'}
          </p>
          {reputation.flaggedUrl && (
            <p className="text-[11px] font-mono text-rose-700 dark:text-rose-300 break-all">
              Flagged: {reputation.flaggedUrl}
            </p>
          )}
          {reputation.details && reputation.details.length > 0 && (
            <ul className="space-y-1">
              {reputation.details.map((d, i) => (
                <li key={i} className="text-[11px] font-mono text-slate-700 dark:text-slate-300 break-all">
                  • {d.threat} {d.dateAdded ? `(${d.dateAdded})` : ''}
                </li>
              ))}
            </ul>
          )}
          {reputation.reference && (
            <a
              href={reputation.reference}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-rose-700 dark:text-rose-300 font-semibold hover:underline"
            >
              View report <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </>
      ) : isClean ? (
        <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
          {reputation.note || 'No threats detected.'}
        </p>
      ) : (
        <p className="text-amber-700 dark:text-amber-300/90 leading-relaxed">
          Verification incomplete — {reputation.note || 'the reputation lookup could not complete.'}
        </p>
      )}

      {checkedCount > 1 && (
        <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed pt-0.5">
          Checked {checkedCount} URLs — the original link and its post-redirect destination.
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export const DomainChecker: React.FC<{ initialUrl?: string }> = ({ initialUrl = '' }) => {
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<DomainInspectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sampleUrls = [
    'https://usps-post-redelivery.top/tracking',
    'https://chase-security-restore.cc/auth',
    'https://meta-appeal-form-verify.xyz',
    'https://www.paypal.com',
  ];

  const handleInspect = async (urlToTest?: string) => {
    const target = (urlToTest || urlInput).trim();
    if (!target) return;

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/inspect-domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target }),
      });

      if (!res.ok) {
        throw new Error('Inspection service error');
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to inspect domain');
    } finally {
      setIsLoading(false);
    }
  };

  const activeVerdictKey = result ? resolveVerdictKey(result) : null;
  const activeVerdict = activeVerdictKey ? verdictMeta[activeVerdictKey] : null;

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Intro info banner */}
      <div className="page-flat-surface bg-white/85 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 space-y-3 backdrop-blur-sm shadow-xs transition-colors">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl bg-blue-500/15 text-blue-600 dark:text-blue-400 flex items-center justify-center">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">Suspicious Link & Domain Inspector</h2>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Analyzes the complete URL — scheme, subdomains, path, query parameters, redirects and malware reputation — for brand spoofing, typosquatting and deceptive links.
            </p>
          </div>
        </div>

        {/* Input box */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleInspect();
          }}
          className="pt-2 flex flex-col sm:flex-row items-center gap-2"
        >
          <div className="relative flex-1 w-full">
            <input
              id="domain-input"
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Paste suspicious URL or domain (e.g. usps-track-fee.top/login, chase-login-restore.cc/auth)"
              className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-slate-900 dark:text-slate-100 text-sm placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-rose-500/40 font-mono transition-colors"
            />
          </div>

          <button
            type="submit"
            id="btn-inspect-domain"
            disabled={isLoading || !urlInput.trim()}
            className="w-full sm:w-auto px-6 py-3 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-sm shadow-md transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Inspect Link
          </button>
        </form>

        {/* Quick Sample Links */}
        <div className="flex items-center gap-2 flex-wrap pt-1 text-xs">
          <span className="text-slate-500">Try sample:</span>
          {sampleUrls.map((sUrl, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setUrlInput(sUrl);
                handleInspect(sUrl);
              }}
              className="font-mono text-[11px] text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 bg-slate-100 dark:bg-slate-950 px-2 py-1 rounded border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition-colors cursor-pointer"
            >
              {sUrl.replace('https://', '').split('/')[0]}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-600/50 text-rose-800 dark:text-rose-200 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Result Card */}
      {result && activeVerdict && (
        <div className="page-flat-surface page-result-surface bg-white/90 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 space-y-4 shadow-md dark:shadow-xl animate-fadeIn backdrop-blur-sm transition-colors">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-200 dark:border-slate-800">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold">Analyzed URL</span>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${activeVerdict.badge}`}>
                  {activeVerdict.label}
                </span>
                {result.spoofedBrand && (
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300 border border-rose-300 dark:border-rose-500/40">
                    Impersonating {result.spoofedBrand}
                  </span>
                )}
              </div>
              <p className="text-lg font-mono font-bold text-slate-900 dark:text-white pt-1 break-all">{result.fullUrl}</p>
              {result.registrableDomain && result.registrableDomain !== result.domain && (
                <p className="text-[11px] font-mono text-slate-500 dark:text-slate-400 pt-0.5 break-all">
                  Registered domain: {result.registrableDomain} · Host: {result.domain}
                </p>
              )}
            </div>

            <div className="text-right shrink-0">
              <span className="text-xs text-slate-500 dark:text-slate-400 block">
                Overall risk:{' '}
                <span className={`font-bold normal-case tracking-normal ${activeVerdict.text}`}>
                  {activeVerdict.short}
                </span>
              </span>
              {typeof result.riskScore === 'number' && (
                <span className="text-xs text-slate-500 dark:text-slate-400 block pt-0.5">
                  Evidence score so far:{' '}
                  <span className={`font-bold normal-case tracking-normal ${activeVerdict.text}`}>
                    {result.riskScore}/100
                  </span>
                </span>
              )}
              {typeof result.confidence === 'number' && (
                <span className="text-xs text-slate-500 dark:text-slate-400 block pt-0.5">
                  Confidence:{' '}
                  <span className="font-bold normal-case tracking-normal">
                    {result.confidence}%
                  </span>
                </span>
              )}
              {activeVerdictKey === 'VERIFICATION_REQUIRED' && (
                <span className="text-[11px] text-slate-500 dark:text-slate-400 block pt-0.5">
                  A 0 is only "no risk evidence yet" — not a clean bill of health; some checks did not run.
                </span>
              )}
              {result.urlStructure && (
                <span className="text-xs text-slate-500 dark:text-slate-400 block pt-0.5">
                  URL structure:{' '}
                  <span
                    className={`font-bold normal-case tracking-normal ${
                      result.urlStructure.status === 'valid'
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-amber-600 dark:text-amber-400'
                    }`}
                  >
                    {result.urlStructure.status === 'valid' ? 'Valid' : 'Issues found'}
                  </span>
                </span>
              )}
              {result.verdictReason && (
                <span className="text-[11px] text-slate-500 dark:text-slate-400 block pt-1 max-w-[280px] sm:max-w-[340px] ml-auto">
                  {result.verdictReason}
                </span>
              )}
              {result.engine && (
                <span className="text-[10px] text-slate-400 dark:text-slate-500 block pt-0.5">
                  engine: {result.engine}
                </span>
              )}
            </div>
          </div>

          {/* Checks performed — real statuses */}
          <ChecksChips checks={result.checks} legacy={result.checksPerformed} />

          {/* Why this score — deterministic signals with signed points */}
          {result.signals && result.signals.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-800 dark:text-slate-300 uppercase tracking-wider">
                Why this score ({result.signals.length})
              </h4>
              <ul className="space-y-1.5">
                {result.signals.map((s, i) => (
                  <li
                    key={`${s.id}-${i}`}
                    className="flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800"
                  >
                    <span
                      className={`shrink-0 mt-0.5 px-2 py-0.5 rounded text-[11px] font-bold tabular-nums ${
                        s.points > 0
                          ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300'
                          : s.points < 0
                          ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-300'
                          : 'bg-slate-200 text-slate-700 dark:bg-slate-500/20 dark:text-slate-300'
                      }`}
                    >
                      {s.points > 0 ? `+${s.points}` : s.points}
                    </span>
                    <div className="min-w-0">
                      <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">{s.label}</span>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">{s.reason}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Spoofed brand comparison */}
          {result.spoofedBrand && (
            <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-600/40 space-y-2">
              <div className="flex items-center gap-2 text-rose-800 dark:text-rose-300 text-xs font-bold uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400" />
                Impersonation Alert: Spoofing {result.spoofedBrand}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-1">
                <div className="p-2.5 rounded-lg bg-white dark:bg-slate-950/80 border border-rose-200 dark:border-rose-500/30 font-mono shadow-2xs">
                  <span className="text-rose-600 dark:text-rose-400 font-bold block mb-0.5">Checked Link:</span>
                  <span className="text-slate-800 dark:text-slate-300 break-all">{result.fullUrl}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-white dark:bg-slate-950/80 border border-emerald-200 dark:border-emerald-500/30 font-mono shadow-2xs">
                  <span className="text-emerald-600 dark:text-emerald-400 font-bold block mb-0.5">Real Official Site:</span>
                  <span className="text-slate-800 dark:text-slate-300 break-all">
                    {result.officialDomain ? `https://${result.officialDomain}` : 'Official verified domain'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Analysis Findings — severity, short title, one-line explanation */}
          {result.findings && result.findings.length > 0 ? (
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-800 dark:text-slate-300 uppercase tracking-wider">
                Analysis Findings ({result.findings.length})
              </h4>
              <ul className="space-y-2">
                {result.findings.map((f, i) => (
                  <FindingRow key={`${f.title}-${i}`} f={f} />
                ))}
              </ul>
            </div>
          ) : (
            <div className="space-y-1.5">
              <h4 className="text-xs font-bold text-slate-800 dark:text-slate-300 uppercase tracking-wider">Analysis Findings</h4>
              <div className="flex gap-2.5 p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
                <div className="shrink-0 mt-0.5">
                  {activeVerdictKey === 'LOW_RISK' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <HelpCircle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
                  )}
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  {activeVerdictKey === 'LOW_RISK'
                    ? 'No threats were detected in this URL — every check ran and came back clean.'
                    : activeVerdictKey === 'VERIFICATION_REQUIRED'
                    ? 'No specific risk signals were identified, but verification could not be completed — this is not a clean bill of health.'
                    : 'No additional findings were reported — see the risk summary above.'}
                </p>
              </div>
            </div>
          )}

          {/* Live network evidence */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {result.redirects && <RedirectCard redirects={result.redirects} />}
            {result.reputation && <ReputationCard reputation={result.reputation} />}
          </div>

          {/* Safety rules for links */}
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 space-y-1">
            <span className="text-slate-900 dark:text-slate-200 font-semibold block">Safety Guard Rule:</span>
            Never log in or type credentials into a page opened from an unverified text message or email link. Always open a fresh browser tab and manually search or type the official organization address.
          </div>
        </div>
      )}
    </div>
  );
};
