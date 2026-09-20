import React from 'react';
import { AlertOctagon, Lock, CreditCard, Key, ShieldAlert, PhoneCall, ExternalLink, CheckSquare } from 'lucide-react';

export const EmergencyGuide: React.FC = () => {
  return (
    <div className="space-y-6 max-w-4xl mx-auto animate-fadeIn">
      {/* Header Banner */}
      <div className="page-flat-surface bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-500/40 rounded-2xl p-5 sm:p-6 space-y-3 backdrop-blur-sm shadow-xs transition-colors">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/15 text-amber-600 dark:text-amber-400 flex items-center justify-center flex-shrink-0">
            <AlertOctagon className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">Emergency Response Protocol</h2>
            <p className="text-xs text-amber-900/80 dark:text-amber-200/80">
              Follow these immediate containment steps if you clicked a suspicious link, entered credentials, or transferred funds.
            </p>
          </div>
        </div>
      </div>

      {/* 4 Phases Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Scenario 1: Entered Credentials / Password */}
        <div className="page-flat-surface bg-white/85 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3.5 backdrop-blur-sm shadow-xs transition-colors">
          <div className="flex items-center gap-2.5 text-rose-600 dark:text-rose-400 font-bold text-sm">
            <Key className="w-4 h-4" />
            <h3 className="text-slate-900 dark:text-white">1. If You Entered a Password or OTP</h3>
          </div>
          <ul className="space-y-2.5 text-xs text-slate-700 dark:text-slate-300">
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-rose-600 dark:text-rose-400">Step 1:</span>
              <span>Immediately go to the official website and change the password for that account.</span>
            </li>
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-rose-600 dark:text-rose-400">Step 2:</span>
              <span>Enable an Authenticator App (like Google Authenticator) instead of SMS-based 2FA.</span>
            </li>
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-rose-600 dark:text-rose-400">Step 3:</span>
              <span>If you reuse this password on any other websites, change them immediately.</span>
            </li>
          </ul>
        </div>

        {/* Scenario 2: Financial Info / Credit Card */}
        <div className="page-flat-surface bg-white/85 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3.5 backdrop-blur-sm shadow-xs transition-colors">
          <div className="flex items-center gap-2.5 text-rose-600 dark:text-rose-400 font-bold text-sm">
            <CreditCard className="w-4 h-4" />
            <h3 className="text-slate-900 dark:text-white">2. If You Entered Banking or Card Info</h3>
          </div>
          <ul className="space-y-2.5 text-xs text-slate-700 dark:text-slate-300">
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-rose-600 dark:text-rose-400">Step 1:</span>
              <span>Call the official fraud department phone number on the physical back of your bank card.</span>
            </li>
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-rose-600 dark:text-rose-400">Step 2:</span>
              <span>Request an immediate freeze on the compromised card and dispute any recent unauthorized charges.</span>
            </li>
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-rose-600 dark:text-rose-400">Step 3:</span>
              <span>Place a free credit freeze on your credit reports at Equifax, Experian, and TransUnion.</span>
            </li>
          </ul>
        </div>

        {/* Scenario 3: Clicked a Link Only */}
        <div className="page-flat-surface bg-white/85 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3.5 backdrop-blur-sm shadow-xs transition-colors">
          <div className="flex items-center gap-2.5 text-amber-600 dark:text-amber-400 font-bold text-sm">
            <ShieldAlert className="w-4 h-4" />
            <h3 className="text-slate-900 dark:text-white">3. If You Only Clicked The Link</h3>
          </div>
          <ul className="space-y-2.5 text-xs text-slate-700 dark:text-slate-300">
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-amber-600 dark:text-amber-400">Step 1:</span>
              <span>Close the browser tab immediately. Do not interact with popups or prompts.</span>
            </li>
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-amber-600 dark:text-amber-400">Step 2:</span>
              <span>Check your browser downloads folder. If any unknown file (.apk, .exe, .zip) downloaded, delete it immediately without opening it.</span>
            </li>
            <li className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950/70 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-amber-600 dark:text-amber-400">Step 3:</span>
              <span>Clear your browser cache and cookies for that site.</span>
            </li>
          </ul>
        </div>

        {/* Scenario 4: Official Reporting Channels */}
        <div className="page-flat-surface bg-white/85 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3.5 backdrop-blur-sm shadow-xs transition-colors">
          <div className="flex items-center gap-2.5 text-blue-600 dark:text-blue-400 font-bold text-sm">
            <PhoneCall className="w-4 h-4" />
            <h3 className="text-slate-900 dark:text-white">4. Where to Report Scams</h3>
          </div>
          <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
            <li className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-slate-900 dark:text-white block mb-0.5">Spam SMS (US/CA/UK):</span>
              Forward the text message to <span className="text-rose-600 dark:text-rose-400 font-mono font-bold">7726</span> (spells SPAM). It reports directly to wireless telecom carriers to block the number.
            </li>
            <li className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-slate-900 dark:text-white block mb-0.5">US FTC (Federal Trade Commission):</span>
              Report fraudulent activity at <span className="text-blue-600 dark:text-blue-400 font-mono">ReportFraud.ftc.gov</span>
            </li>
            <li className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80">
              <span className="font-bold text-slate-900 dark:text-white block mb-0.5">FBI Internet Crime Complaint Center:</span>
              File internet cybercrime complaints at <span className="text-blue-600 dark:text-blue-400 font-mono">IC3.gov</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};
