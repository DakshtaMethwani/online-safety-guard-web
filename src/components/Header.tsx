import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Sparkles,
  History,
  Globe,
  HelpCircle,
  AlertOctagon,
  Sun,
  Moon,
  Layers
} from 'lucide-react';

interface HeaderProps {
  activeTab: 'scanner' | 'domain' | 'quiz' | 'emergency' | 'history';
  onSelectTab: (tab: 'scanner' | 'domain' | 'quiz' | 'emergency' | 'history') => void;
  historyCount: number;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  watermarkIntensity?: 'subtle' | 'balanced' | 'vivid';
  onCycleWatermark?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSelectTab,
  historyCount,
  theme,
  onToggleTheme,
  watermarkIntensity,
  onCycleWatermark,
}) => {
  return (
    <header className="border-b border-slate-200/90 dark:border-slate-800/90 bg-white/85 dark:bg-slate-900/90 backdrop-blur-md sticky top-0 z-30 transition-colors duration-200 shadow-xs">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3 w-full sm:w-auto justify-between sm:justify-start">
            <div 
              onClick={() => onSelectTab('scanner')}
              className="flex items-center gap-3 cursor-pointer group"
              title="Return to Message Scanner"
            >
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-600 via-rose-500 to-amber-500 flex items-center justify-center shadow-md shadow-rose-600/20 dark:shadow-rose-950/40 text-white group-hover:scale-105 transition-transform duration-200">
                <ShieldAlert className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-lg font-bold tracking-tight text-slate-900 dark:text-white group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors">
                    Online Safety Guard
                  </h1>
                  <span className="text-[10px] font-bold tracking-wider uppercase px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-700 dark:text-rose-300 border border-rose-500/25">
                    Live Anti-Fraud
                  </span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Phishing, scam & impersonation alert system
                </p>
              </div>
            </div>

            {/* Mobile Controls: Theme toggle & AI Status */}
            <div className="sm:hidden flex items-center gap-2">
              <button
                type="button"
                onClick={onToggleTheme}
                aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
                className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200"
              >
                {theme === 'dark' ? (
                  <Sun className="w-4 h-4 text-amber-400" />
                ) : (
                  <Moon className="w-4 h-4 text-slate-700" />
                )}
              </button>
              <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-700 dark:text-emerald-400 text-[11px] font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 dark:bg-emerald-400 animate-pulse"></span>
                <span>Active</span>
              </div>
            </div>
          </div>

          {/* Navigation Controls */}
          <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto pb-1 sm:pb-0 scrollbar-none">
            <button
              id="nav-scanner-btn"
              onClick={() => onSelectTab('scanner')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                activeTab === 'scanner'
                  ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              <span>Scanner</span>
            </button>

            <button
              id="nav-domain-btn"
              onClick={() => onSelectTab('domain')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                activeTab === 'domain'
                  ? 'bg-blue-500/15 text-blue-700 dark:text-blue-300 border border-blue-500/30 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>Link Inspector</span>
            </button>

            <button
              id="nav-quiz-btn"
              onClick={() => onSelectTab('quiz')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                activeTab === 'quiz'
                  ? 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <HelpCircle className="w-4 h-4" />
              <span>Scam Quiz</span>
            </button>

            <button
              id="nav-emergency-btn"
              onClick={() => onSelectTab('emergency')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                activeTab === 'emergency'
                  ? 'bg-amber-500/15 text-amber-800 dark:text-amber-300 border border-amber-500/30 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <AlertOctagon className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              <span>Emergency</span>
            </button>

            <button
              id="nav-history-btn"
              onClick={() => onSelectTab('history')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                activeTab === 'history'
                  ? 'bg-slate-200 text-slate-900 border border-slate-300 dark:bg-slate-800 dark:text-white dark:border-slate-700 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <History className="w-4 h-4" />
              <span>History</span>
              {historyCount > 0 && (
                <span className="w-4 h-4 rounded-full bg-slate-300 text-slate-800 dark:bg-slate-700 dark:text-slate-200 text-[10px] flex items-center justify-center font-bold">
                  {historyCount}
                </span>
              )}
            </button>

            {/* Light Mode Watermark Adjuster Chip */}
            {theme === 'light' && onCycleWatermark && (
              <button
                type="button"
                id="btn-watermark-intensity"
                onClick={onCycleWatermark}
                title="Click to cycle watermark visibility: Subtle -> Balanced -> Vivid"
                className="hidden lg:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-blue-200 bg-blue-50/90 text-blue-800 hover:bg-blue-100 transition-all cursor-pointer shadow-2xs"
              >
                <Layers className="w-3.5 h-3.5 text-blue-600" />
                <span>Watermark: <strong className="capitalize">{watermarkIntensity || 'balanced'}</strong></span>
              </button>
            )}

            {/* Desktop Theme Switcher */}
            <div className="hidden sm:flex items-center ml-1 border-l border-slate-200 dark:border-slate-800 pl-2">
              <button
                id="theme-toggle-btn"
                type="button"
                onClick={onToggleTheme}
                aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
                title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border border-slate-200 dark:border-slate-700 bg-slate-100/90 hover:bg-slate-200/90 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 cursor-pointer shadow-xs"
              >
                {theme === 'dark' ? (
                  <>
                    <Sun className="w-4 h-4 text-amber-400" />
                    <span>Light Mode</span>
                  </>
                ) : (
                  <>
                    <Moon className="w-4 h-4 text-slate-700" />
                    <span>Dark Mode</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
