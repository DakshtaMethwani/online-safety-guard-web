import React, { useState } from 'react';
import { AnalysisResult } from '../types';
import { HighlightedMessage } from './HighlightedMessage';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  ArrowLeft,
  Share2,
  ExternalLink,
  Info,
  Sparkles,
  PhoneCall,
  Lock,
  Flag
} from 'lucide-react';

interface AnalysisReportProps {
  result: AnalysisResult;
  onScanAnother: () => void;
  onInspectDomain?: (url: string) => void;
}

export const AnalysisReport: React.FC<AnalysisReportProps> = ({
  result,
  onScanAnother,
  onInspectDomain,
}) => {
  const [copiedReport, setCopiedReport] = useState(false);
  const [copiedResponse, setCopiedResponse] = useState(false);

  const isDangerous = result.safetyStatus === 'DANGEROUS_SCAM';
  const isSuspicious = result.safetyStatus === 'SUSPICIOUS';
  const isSafe = result.safetyStatus === 'SAFE';

  // Status configuration
  let statusBadge = {
    label: 'High-Risk Scam Alert',
    bgColor: 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-500/15 dark:border-rose-500/40 dark:text-rose-300',
    icon: ShieldAlert,
    barColor: 'from-rose-600 to-red-500',
    headerGlow: 'border-rose-200 dark:border-rose-500/30 shadow-rose-500/5 dark:shadow-rose-950/40',
  };

  if (isSuspicious) {
    statusBadge = {
      label: 'Suspicious / Caution Advised',
      bgColor: 'bg-amber-100 text-amber-900 border-amber-300 dark:bg-amber-500/15 dark:border-amber-500/40 dark:text-amber-300',
      icon: AlertTriangle,
      barColor: 'from-amber-500 to-yellow-500',
      headerGlow: 'border-amber-200 dark:border-amber-500/30 shadow-amber-500/5 dark:shadow-amber-950/40',
    };
  } else if (isSafe) {
    statusBadge = {
      label: 'Legitimate / Safe Notice',
      bgColor: 'bg-emerald-100 text-emerald-900 border-emerald-300 dark:bg-emerald-500/15 dark:border-emerald-500/40 dark:text-emerald-300',
      icon: ShieldCheck,
      barColor: 'from-emerald-600 to-teal-500',
      headerGlow: 'border-emerald-200 dark:border-emerald-500/30 shadow-emerald-500/5 dark:shadow-emerald-950/40',
    };
  }

  const handleCopyReport = () => {
    const reportText = `[ONLINE SAFETY GUARD SCAN REPORT]
Timestamp: ${new Date(result.timestamp).toLocaleString()}
Status: ${result.safetyStatus} (Risk Score: ${result.riskScore}/100)
Scam Type: ${result.scamType}
Verdict: ${result.verdictSummary}

RED FLAGS IDENTIFIED:
${result.redFlags.map(rf => `- [${rf.severity.toUpperCase()}] ${rf.flag}: "${rf.evidence}"`).join('\n')}

TACTICS DETECTED:
${result.tacticsUsed.join(', ')}

SAFETY DEFENSE PLAN:
Immediate Actions:
${result.safetyAdvice.immediateActions.map(a => `• ${a}`).join('\n')}

Never Do:
${result.safetyAdvice.whatNeverToDo.map(a => `✗ ${a}`).join('\n')}

Official Verification:
${result.safetyAdvice.officialVerificationStep}
`;

    navigator.clipboard.writeText(reportText);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleCopyResponse = () => {
    navigator.clipboard.writeText(result.recommendedResponse);
    setCopiedResponse(true);
    setTimeout(() => setCopiedResponse(false), 2000);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top action bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-slate-200 dark:border-slate-800">
        <button
          id="btn-scan-another-top"
          onClick={onScanAnother}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 transition-colors border border-slate-200 dark:border-slate-700 cursor-pointer shadow-2xs"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Scan Another Message
        </button>

        <div className="flex items-center gap-2">
          {result.engine && (
            <span className="text-[11px] text-slate-600 dark:text-slate-400 flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
              <Sparkles className="w-3 h-3 text-rose-500 dark:text-rose-400" />
              Engine: {result.engine?.includes('heuristic') && result.engine?.includes('gemini')
                ? 'Gemini + Threat Rules'
                : result.engine?.includes('gemini')
                ? 'Gemini 3.8 Flash'
                : 'Threat Rules Engine'}
            </span>
          )}

          <button
            id="btn-copy-report"
            onClick={handleCopyReport}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white bg-slate-100 hover:bg-slate-200 dark:bg-slate-800/80 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer shadow-2xs"
          >
            {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedReport ? 'Report Copied' : 'Copy Full Report'}
          </button>
        </div>
      </div>

      {/* Main Alert Card */}
      <div className={`p-5 sm:p-6 rounded-2xl bg-white/90 dark:bg-slate-900/90 border ${statusBadge.headerGlow} shadow-md dark:shadow-xl relative overflow-hidden backdrop-blur-sm transition-colors`}>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          {/* Left: Status & Verdict */}
          <div className="space-y-3 flex-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${statusBadge.bgColor}`}>
                <statusBadge.icon className="w-3.5 h-3.5" />
                {statusBadge.label}
              </span>
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 px-2.5 py-1 rounded-full border border-slate-200 dark:border-slate-700/60">
                {result.scamType}
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white leading-snug">
              {result.verdictSummary}
            </h2>

            {/* Sender Note */}
            {result.senderAssessment && (
              <div className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300 pt-1">
                <span className={`w-2 h-2 rounded-full ${result.senderAssessment.isSenderSuspicious ? 'bg-rose-500' : 'bg-emerald-500'}`}></span>
                <span>
                  <strong className="text-slate-900 dark:text-slate-200">Sender Check:</strong> {result.senderAssessment.notes}
                </span>
              </div>
            )}
          </div>

          {/* Right: Threat Score Gauge */}
          <div className="bg-slate-50/90 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col items-center justify-center min-w-[170px] text-center shadow-xs">
            <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">
              Threat Risk Score
            </div>
            <div className="relative flex items-center justify-center my-1">
              <span className={`text-4xl sm:text-5xl font-extrabold tracking-tight ${
                isDangerous ? 'text-rose-600 dark:text-rose-400' : isSuspicious ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
              }`}>
                {result.riskScore}
              </span>
              <span className="text-xs text-slate-400 dark:text-slate-500 font-bold ml-1 self-end pb-1">/100</span>
            </div>

            {/* Visual Risk Bar */}
            <div className="w-full bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden mt-2">
              <div
                className={`h-full bg-gradient-to-r ${statusBadge.barColor} transition-all duration-700`}
                style={{ width: `${Math.max(5, result.riskScore)}%` }}
              ></div>
            </div>
            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-medium mt-1.5">
              {result.riskScore >= 70 ? 'Extreme Hazard' : result.riskScore >= 35 ? 'Moderate Hazard' : 'Minimal Hazard'}
            </span>
          </div>
        </div>
      </div>

      {/* Interactive Highlighted Message Inspector */}
      <div className="bg-white/85 dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800/90 rounded-2xl p-5 sm:p-6 space-y-4 backdrop-blur-sm shadow-xs transition-colors">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flag className="w-4 h-4 text-rose-600 dark:text-rose-400" />
            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              Interactive Message Breakdown
            </h3>
          </div>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {result.highlightPhrases?.length || 0} flagged element{result.highlightPhrases?.length === 1 ? '' : 's'}
          </span>
        </div>

        <HighlightedMessage
          message={result.originalMessage}
          sender={result.sender}
          platform={result.platform}
          highlights={result.highlightPhrases || []}
        />
      </div>

      {/* Red Flags & Psychological Tactics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Identified Red Flags */}
        <div className="bg-white/85 dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800/90 rounded-2xl p-5 space-y-3.5 backdrop-blur-sm shadow-xs transition-colors">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500 dark:text-amber-400" />
              Identified Red Flags ({result.redFlags?.length || 0})
            </h3>
          </div>

          {result.redFlags && result.redFlags.length > 0 ? (
            <div className="space-y-2.5">
              {result.redFlags.map((rf, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
                      {rf.flag}
                    </span>
                    <span
                      className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                        rf.severity === 'high'
                          ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300 border border-rose-300 dark:border-rose-500/30'
                          : rf.severity === 'medium'
                          ? 'bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300 border border-amber-300 dark:border-amber-500/30'
                          : 'bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-300'
                      }`}
                    >
                      {rf.severity} severity
                    </span>
                  </div>
                  {rf.evidence && (
                    <p className="text-xs text-slate-600 dark:text-slate-400 font-mono italic bg-slate-100 dark:bg-slate-900/60 px-2 py-1 rounded border border-slate-200 dark:border-slate-800">
                      "{rf.evidence}"
                    </p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 dark:text-slate-400 italic">No overt red flags detected.</p>
          )}
        </div>

        {/* Psychological Tactics Used */}
        <div className="bg-white/85 dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800/90 rounded-2xl p-5 space-y-3.5 backdrop-blur-sm shadow-xs transition-colors">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-rose-600 dark:text-rose-400" />
            Social Engineering Tactics
          </h3>

          {result.tacticsUsed && result.tacticsUsed.length > 0 ? (
            <div className="flex flex-wrap gap-2 pt-1">
              {result.tacticsUsed.map((tactic, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200 border border-rose-200 dark:border-rose-800/40 flex items-center gap-1.5"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500 dark:bg-rose-400"></span>
                  {tactic}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 dark:text-slate-400 italic">No high-pressure manipulation tactics identified.</p>
          )}

          <div className="mt-4 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 space-y-1">
            <span className="font-bold text-slate-900 dark:text-slate-200 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              Scammer Mindset
            </span>
            <p className="text-slate-600 dark:text-slate-400 text-xs leading-relaxed">
              Scammers exploit adrenaline and urgency so victims react instinctively before verifying through separate channels.
            </p>
          </div>
        </div>
      </div>

      {/* Safety Defense Plan */}
      <div className="bg-white/85 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 space-y-5 backdrop-blur-sm shadow-xs transition-colors">
        <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
          Recommended Safety Defense Plan
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Immediate DOs */}
          <div className="bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-500/20 rounded-xl p-4 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              Immediate Steps To Take
            </div>
            <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
              {result.safetyAdvice.immediateActions.map((action, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-emerald-600 dark:text-emerald-400 font-bold mt-0.5">•</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Critical DONTs */}
          <div className="bg-rose-50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-500/20 rounded-xl p-4 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-rose-800 dark:text-rose-300">
              <XCircle className="w-4 h-4 text-rose-600 dark:text-rose-400" />
              What You Must NEVER Do
            </div>
            <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
              {result.safetyAdvice.whatNeverToDo.map((action, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-rose-600 dark:text-rose-400 font-bold mt-0.5">✕</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Verification Step Callout */}
        <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center flex-shrink-0 mt-0.5">
            <PhoneCall className="w-4 h-4" />
          </div>
          <div className="space-y-1">
            <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              Independent Verification Method
            </h4>
            <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
              {result.safetyAdvice.officialVerificationStep}
            </p>
          </div>
        </div>
      </div>

      {/* Recommended Response or Block Instruction */}
      <div className="bg-white/85 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3 backdrop-blur-sm shadow-xs transition-colors">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Share2 className="w-4 h-4 text-slate-500 dark:text-slate-400" />
            Recommended Action / Response
          </h3>
          <button
            id="btn-copy-response"
            onClick={handleCopyResponse}
            className="text-xs font-medium text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer shadow-2xs"
          >
            {copiedResponse ? <Check className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedResponse ? 'Copied' : 'Copy'}
          </button>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-xs text-slate-800 dark:text-slate-300 leading-relaxed">
          {result.recommendedResponse}
        </div>
      </div>

      {/* Bottom Scan Another Button */}
      <div className="flex justify-center pt-2">
        <button
          id="btn-scan-another-bottom"
          onClick={onScanAnother}
          className="px-6 py-3 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-sm shadow-md shadow-rose-600/20 dark:shadow-rose-950/40 transition-all flex items-center gap-2 hover:scale-[1.02] cursor-pointer"
        >
          <ShieldCheck className="w-4 h-4" />
          Scan Another Suspicious Message
        </button>
      </div>
    </div>
  );
};
