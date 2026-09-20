import React from 'react';
import { AnalysisResult } from '../types';
import { ShieldAlert, ShieldCheck, AlertTriangle, Trash2, ArrowRight, Clock } from 'lucide-react';

interface ScanHistoryViewProps {
  history: AnalysisResult[];
  onSelectScan: (scan: AnalysisResult) => void;
  onClearHistory: () => void;
  onNewScan: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  history,
  onSelectScan,
  onClearHistory,
  onNewScan,
}) => {
  if (history.length === 0) {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center space-y-4">
        <div className="w-14 h-14 rounded-2xl bg-slate-100 dark:bg-slate-800 text-slate-400 mx-auto flex items-center justify-center">
          <Clock className="w-7 h-7" />
        </div>
        <h3 className="text-lg font-bold text-slate-900 dark:text-white">No Message Scans Yet</h3>
        <p className="text-xs text-slate-600 dark:text-slate-400 max-w-sm mx-auto">
          Scan suspicious texts, emails, or DMs to store safety reports locally on your device for future reference.
        </p>
        <button
          onClick={onNewScan}
          className="px-5 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition-all shadow-md cursor-pointer"
        >
          Scan Your First Message
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-5 animate-fadeIn">
      <div className="flex items-center justify-between pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-900 dark:text-white">Scanned Messages History</h2>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            {history.length} saved alert report{history.length === 1 ? '' : 's'} (stored securely in browser)
          </p>
        </div>

        <button
          onClick={onClearHistory}
          className="text-xs text-rose-700 dark:text-rose-400 hover:text-rose-900 dark:hover:text-rose-300 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 dark:bg-rose-500/10 dark:hover:bg-rose-500/20 border border-rose-200 dark:border-rose-500/20 transition-colors cursor-pointer"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear History
        </button>
      </div>

      <div className="space-y-3">
        {history.map((scan) => {
          const isDangerous = scan.safetyStatus === 'DANGEROUS_SCAM';
          const isSuspicious = scan.safetyStatus === 'SUSPICIOUS';
          const Icon = isDangerous ? ShieldAlert : isSuspicious ? AlertTriangle : ShieldCheck;

          return (
            <div
              key={scan.id}
              onClick={() => onSelectScan(scan)}
              className="page-flat-surface p-4 rounded-xl bg-white/85 dark:bg-slate-900/80 hover:bg-slate-50 dark:hover:bg-slate-800/80 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition-all cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 group backdrop-blur-sm shadow-xs"
            >
              <div className="flex items-start gap-3.5 flex-1 min-w-0">
                <div
                  className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 mt-0.5 ${
                    isDangerous
                      ? 'bg-rose-100 text-rose-600 dark:bg-rose-500/20 dark:text-rose-400'
                      : isSuspicious
                      ? 'bg-amber-100 text-amber-600 dark:bg-amber-500/20 dark:text-amber-400'
                      : 'bg-emerald-100 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                </div>

                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-slate-900 dark:text-white truncate">
                      {scan.scamType}
                    </span>
                    <span
                      className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                        isDangerous
                          ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300'
                          : isSuspicious
                          ? 'bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300'
                          : 'bg-emerald-100 text-emerald-900 dark:bg-emerald-500/20 dark:text-emerald-300'
                      }`}
                    >
                      {scan.safetyStatus.replace('_', ' ')}
                    </span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">
                      {new Date(scan.timestamp).toLocaleDateString()}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-400 truncate max-w-xl font-mono">
                    {scan.originalMessage}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3 self-end sm:self-center">
                <div className="text-right">
                  <span className="text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400 block">Threat Score</span>
                  <span className={`text-sm font-extrabold ${isDangerous ? 'text-rose-600 dark:text-rose-400' : isSuspicious ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                    {scan.riskScore}/100
                  </span>
                </div>

                <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800 group-hover:bg-slate-200 dark:group-hover:bg-slate-700 flex items-center justify-center text-slate-600 dark:text-slate-400 group-hover:text-slate-950 dark:group-hover:text-white transition-colors">
                  <ArrowRight className="w-4 h-4" />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
