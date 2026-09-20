import React, { useState, useRef, useEffect } from 'react';
import { PRESET_MESSAGES } from '../data/presets';
import { PresetMessage, AnalysisResult } from '../types';
import {
  ShieldAlert,
  Sparkles,
  Upload,
  Image as ImageIcon,
  X,
  AlertTriangle,
  Clipboard,
  Check,
  Send,
  Zap,
  Info,
  Loader2,
  Mail,
  MessageSquare,
  Smartphone,
  Flame,
  Globe
} from 'lucide-react';

interface MessageScannerProps {
  onAnalysisComplete: (result: AnalysisResult) => void;
}

const PLATFORMS = [
  { id: 'SMS / Text', label: 'SMS / Text', icon: Smartphone },
  { id: 'Email / Inbox', label: 'Email / Inbox', icon: Mail },
  { id: 'WhatsApp', label: 'WhatsApp', icon: MessageSquare },
  { id: 'Instagram DM', label: 'Instagram DM', icon: MessageSquare },
  { id: 'Telegram', label: 'Telegram', icon: MessageSquare },
  { id: 'LinkedIn', label: 'LinkedIn', icon: Globe },
  { id: 'Other App', label: 'Other App', icon: Globe },
];

const platformTabTone = (platform: string, isSelected: boolean) => {
  const tones: Record<string, { active: string; idle: string }> = {
    'SMS / Text': {
      active: 'bg-pink-50 text-pink-700 border-pink-300 shadow-pink-500/10 dark:bg-pink-500/20 dark:text-pink-200 dark:border-pink-400/60',
      idle: 'text-pink-700/80 border-pink-200 hover:bg-pink-50 hover:border-pink-300 dark:text-pink-300/80 dark:border-pink-500/20 dark:hover:bg-pink-500/10 dark:hover:border-pink-400/40',
    },
    'Email / Inbox': {
      active: 'bg-sky-50 text-sky-700 border-sky-300 shadow-sky-500/10 dark:bg-sky-500/20 dark:text-sky-200 dark:border-sky-400/60',
      idle: 'text-sky-700/80 border-sky-200 hover:bg-sky-50 hover:border-sky-300 dark:text-sky-300/80 dark:border-sky-500/20 dark:hover:bg-sky-500/10 dark:hover:border-sky-400/40',
    },
    WhatsApp: {
      active: 'bg-emerald-50 text-emerald-700 border-emerald-300 shadow-emerald-500/10 dark:bg-emerald-500/20 dark:text-emerald-200 dark:border-emerald-400/60',
      idle: 'text-emerald-700/80 border-emerald-200 hover:bg-emerald-50 hover:border-emerald-300 dark:text-emerald-300/80 dark:border-emerald-500/20 dark:hover:bg-emerald-500/10 dark:hover:border-emerald-400/40',
    },
    'Instagram DM': {
      active: 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-300 shadow-fuchsia-500/10 dark:bg-fuchsia-500/20 dark:text-fuchsia-200 dark:border-fuchsia-400/60',
      idle: 'text-fuchsia-700/80 border-fuchsia-200 hover:bg-fuchsia-50 hover:border-fuchsia-300 dark:text-fuchsia-300/80 dark:border-fuchsia-500/20 dark:hover:bg-fuchsia-500/10 dark:hover:border-fuchsia-400/40',
    },
    Telegram: {
      active: 'bg-cyan-50 text-cyan-700 border-cyan-300 shadow-cyan-500/10 dark:bg-cyan-500/20 dark:text-cyan-200 dark:border-cyan-400/60',
      idle: 'text-cyan-700/80 border-cyan-200 hover:bg-cyan-50 hover:border-cyan-300 dark:text-cyan-300/80 dark:border-cyan-500/20 dark:hover:bg-cyan-500/10 dark:hover:border-cyan-400/40',
    },
    LinkedIn: {
      active: 'bg-blue-50 text-blue-700 border-blue-300 shadow-blue-500/10 dark:bg-blue-600/25 dark:text-blue-200 dark:border-blue-400/60',
      idle: 'text-blue-700/80 border-blue-200 hover:bg-blue-50 hover:border-blue-300 dark:text-blue-300/80 dark:border-blue-500/20 dark:hover:bg-blue-600/10 dark:hover:border-blue-400/40',
    },
    'Other App': {
      active: 'bg-violet-50 text-violet-700 border-violet-300 shadow-violet-500/10 dark:bg-violet-500/20 dark:text-violet-200 dark:border-violet-400/60',
      idle: 'text-violet-700/80 border-violet-200 hover:bg-violet-50 hover:border-violet-300 dark:text-violet-300/80 dark:border-violet-500/20 dark:hover:bg-violet-500/10 dark:hover:border-violet-400/40',
    },
  };

  const tone = tones[platform] ?? tones['Other App'];
  return `${isSelected ? tone.active : tone.idle} bg-white dark:bg-slate-950/60 border`;
};

export const MessageScanner: React.FC<MessageScannerProps> = ({ onAnalysisComplete }) => {
  const [message, setMessage] = useState('');
  const [sender, setSender] = useState('');
  const [platform, setPlatform] = useState('SMS / Text');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Screenshot upload state
  const [screenshotBase64, setScreenshotBase64] = useState<string | null>(null);
  const [isExtractingOcr, setIsExtractingOcr] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Clipboard copy state
  const [copiedSuccess, setCopiedSuccess] = useState(false);

  // Live Heuristic Warnings (instant client-side preview before full AI run)
  const [liveHeuristicWarning, setLiveHeuristicWarning] = useState<string | null>(null);

  useEffect(() => {
    const text = (message + ' ' + sender).toLowerCase();
    if (/(\.top|\.xyz|\.cc|\.buzz|\.cam|\.tk|\.ml|\.ga|\.cf|\.gq|\.zip|\.mov)/i.test(text)) {
      setLiveHeuristicWarning('Potentially hazardous domain detected (.top, .xyz, .cc, etc.) commonly used in malicious phishing redirects.');
    } else if (text.includes('otp') || text.includes('2fa code') || text.includes('passcode') || text.includes('gift card')) {
      setLiveHeuristicWarning('Demand for sensitive codes or gift cards detected. Authentic organizations never solicit 2FA codes or gift cards.');
    } else if (text.includes('within 15 minutes') || text.includes('account will be terminated') || text.includes('card suspended')) {
      setLiveHeuristicWarning('Extreme time urgency detected. Scammers use artificial fear to provoke hasty clicks.');
    } else {
      setLiveHeuristicWarning(null);
    }
  }, [message, sender]);

  // Load Preset
  const handleLoadPreset = (preset: PresetMessage) => {
    setMessage(preset.text);
    setSender(preset.sender);
    setPlatform(preset.platform);
    setScreenshotBase64(null);
    setErrorMessage(null);
  };

  // Handle Screenshot Upload
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setErrorMessage('Please upload an image file (PNG, JPG, WebP).');
      return;
    }

    const reader = new FileReader();
    reader.onload = async (event) => {
      const base64 = event.target?.result as string;
      setScreenshotBase64(base64);
      setErrorMessage(null);
      // Auto-extract text from image
      extractTextFromImage(base64, file.type);
    };
    reader.readAsDataURL(file);
  };

  const extractTextFromImage = async (base64: string, mimeType: string) => {
    setIsExtractingOcr(true);
    setErrorMessage(null);
    try {
      const res = await fetch('/api/extract-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageBase64: base64,
          mimeType: mimeType || 'image/png',
        }),
      });

      if (!res.ok) {
        throw new Error('Image analysis failed');
      }

      const data = await res.json();
      if (data.extractedText) {
        setMessage(data.extractedText);
      }
      if (data.sender) {
        setSender(data.sender);
      }
      if (data.platform) {
        setPlatform(data.platform);
      }
    } catch (err: any) {
      console.warn('OCR extraction note:', err);
      // Not fatal; user can still type or scan directly
    } finally {
      setIsExtractingOcr(false);
    }
  };

  // Paste from clipboard
  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setMessage(text);
        setCopiedSuccess(true);
        setTimeout(() => setCopiedSuccess(false), 1500);
      }
    } catch (err) {
      // Clipboard permissions may fail in iframe
      setErrorMessage('Please use Ctrl+V or Cmd+V to paste message text directly.');
    }
  };

  // Analyze Message
  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim() && !screenshotBase64) {
      setErrorMessage('Please enter the message text or upload a screenshot.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await fetch('/api/analyze-message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: message.trim(),
          sender: sender.trim(),
          platform,
          imageBase64: screenshotBase64,
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Server responded with ${response.status}`);
      }

      const data = await response.json();
      const finalResult: AnalysisResult = {
        id: 'scan-' + Date.now(),
        timestamp: new Date().toISOString(),
        originalMessage: message.trim() || '(Screenshot analysis)',
        sender: sender.trim() || undefined,
        platform,
        safetyStatus: data.safetyStatus || 'SUSPICIOUS',
        riskScore: typeof data.riskScore === 'number' ? data.riskScore : 50,
        scamType: data.scamType || 'Suspicious Communication',
        verdictSummary: data.verdictSummary || 'Analysis complete.',
        redFlags: data.redFlags || [],
        tacticsUsed: data.tacticsUsed || [],
        highlightPhrases: data.highlightPhrases || [],
        safetyAdvice: data.safetyAdvice || {
          immediateActions: ['Do not click links or send information.'],
          whatNeverToDo: ['Never share passwords or 2FA verification codes.'],
          officialVerificationStep: 'Contact the organization directly via official verified channels.',
        },
        recommendedResponse: data.recommendedResponse || 'Block and mark as spam.',
        senderAssessment: data.senderAssessment || {
          isSenderSuspicious: false,
          notes: 'No conclusive sender anomaly.',
        },
        engine: data.engine || 'gemini-3.8-flash',
      };

      onAnalysisComplete(finalResult);
    } catch (err: any) {
      console.error('Scan error:', err);
      setErrorMessage(err.message || 'Analysis failed. Please check your connection and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Sample Scam Attack Presets */}
      <div className="scanner-section-charcoal bg-white/85 dark:bg-slate-900/80 border border-slate-200/90 dark:border-slate-800 rounded-2xl p-4 sm:p-5 backdrop-blur-sm shadow-xs transition-colors">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-500 dark:text-amber-400" />
            <h3 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              Quick Test: Common Scam Templates
            </h3>
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400 hidden sm:inline">
            Click to simulate realistic threat attacks
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
          {PRESET_MESSAGES.map((preset) => (
            <button
              key={preset.id}
              type="button"
              id={`preset-${preset.id}`}
              onClick={() => handleLoadPreset(preset)}
              className="p-2.5 text-left rounded-xl bg-slate-50/90 hover:bg-slate-100 dark:bg-slate-950/60 dark:hover:bg-slate-800/80 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition-all group flex flex-col justify-between cursor-pointer"
            >
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-xs font-semibold text-slate-800 dark:text-slate-200 group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors truncate">
                  {preset.title}
                </span>
              </div>
              <div className="flex items-center gap-1.5 mt-1">
                <span
                  className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                    preset.expectedRisk === 'DANGEROUS'
                      ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300'
                      : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-300'
                  }`}
                >
                  {preset.badge}
                </span>
                <span className="text-[10px] text-slate-500 truncate">
                  {preset.platform}
                </span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Analysis Form */}
      <form onSubmit={handleAnalyze} className="scanner-form-charcoal bg-white/90 dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800 rounded-2xl p-5 sm:p-6 shadow-md dark:shadow-xl space-y-5 backdrop-blur-sm transition-colors">
        {/* Platform selection pills */}
        <div className="space-y-2">
          <label className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-300 flex items-center justify-between">
            <span>1. Where did you receive this message?</span>
            <span className="text-slate-500 text-[11px] font-normal">Context helps identify brand impersonation</span>
          </label>
          <div className="flex flex-wrap gap-2">
            {PLATFORMS.map((p) => {
              const Icon = p.icon;
              const isSelected = platform === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setPlatform(p.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${platformTabTone(p.id, isSelected)} ${isSelected ? 'font-semibold shadow-sm' : ''}`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {p.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Sender details */}
        <div className="space-y-1.5">
          <label htmlFor="sender-input" className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-300 flex items-center justify-between">
            <span>2. Sender address, phone, or handle (optional)</span>
            <span className="text-slate-500 text-[11px] font-normal">e.g. +1 (833) ..., support@bofa-auth.co, @recruiter_hr</span>
          </label>
          <input
            id="sender-input"
            type="text"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder="e.g. +1 (800) 123-4567 or notifications@updates-chase.top"
            className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50/90 dark:bg-slate-950/80 border border-slate-300 dark:border-slate-800 text-slate-900 dark:text-slate-100 text-sm placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-rose-500/40 focus:border-rose-500 font-mono transition-colors"
          />
        </div>

        {/* Message Input Textarea & Screenshot Upload */}
        <div className="space-y-2">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <label htmlFor="message-input" className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-300">
              3. Message text content
            </label>
            <div className="flex items-center gap-2">
              <button
                type="button"
                id="btn-paste-clipboard"
                onClick={handlePasteClipboard}
                className="text-xs text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800/60 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700/60 transition-colors cursor-pointer"
              >
                {copiedSuccess ? <Check className="w-3 h-3 text-emerald-500 dark:text-emerald-400" /> : <Clipboard className="w-3 h-3" />}
                Paste Text
              </button>

              <button
                type="button"
                id="btn-upload-screenshot"
                onClick={() => fileInputRef.current?.click()}
                className="text-xs text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800/60 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700/60 transition-colors cursor-pointer"
              >
                <ImageIcon className="w-3 h-3 text-rose-500 dark:text-rose-400" />
                Upload Screenshot
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileChange}
                className="hidden"
              />

              {message && (
                <button
                  type="button"
                  onClick={() => {
                    setMessage('');
                    setScreenshotBase64(null);
                  }}
                  className="text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 flex items-center gap-1 cursor-pointer"
                >
                  <X className="w-3 h-3" />
                  Clear
                </button>
              )}
            </div>
          </div>

          <textarea
            id="message-input"
            rows={5}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Paste the suspicious email, text message, DM, or chat here... (e.g. 'URGENT: Your account has been restricted. Click here to confirm your password...')"
            className="w-full px-4 py-3 rounded-xl bg-slate-50/90 dark:bg-slate-950/80 border border-slate-300 dark:border-slate-800 text-slate-900 dark:text-slate-100 text-sm placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-rose-500/40 focus:border-rose-500 leading-relaxed font-mono resize-y transition-colors"
          />

          {/* Screenshot preview badge */}
          {screenshotBase64 && (
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-100 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <img
                  src={screenshotBase64}
                  alt="Uploaded preview"
                  className="w-12 h-12 object-cover rounded-lg border border-slate-300 dark:border-slate-700"
                />
                <div>
                  <span className="text-xs font-semibold text-slate-800 dark:text-slate-200 block">
                    Screenshot Attached
                  </span>
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">
                    {isExtractingOcr ? 'Extracting text with AI OCR...' : 'Text successfully scanned from screenshot.'}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setScreenshotBase64(null)}
                className="text-slate-500 hover:text-rose-600 dark:text-slate-400 dark:hover:text-rose-400 p-1 cursor-pointer"
                title="Remove image"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Live Heuristic Warning Banner */}
          {liveHeuristicWarning && (
            <div className="flex items-start gap-2.5 p-3 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-600/40 text-amber-900 dark:text-amber-200 text-xs animate-fadeIn">
              <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
              <div className="space-y-0.5">
                <span className="font-bold text-amber-800 dark:text-amber-300">Live Red-Flag Alert: </span>
                <span>{liveHeuristicWarning}</span>
              </div>
            </div>
          )}
        </div>

        {/* Error message */}
        {errorMessage && (
          <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-600/50 text-rose-800 dark:text-rose-200 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 flex-shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Action Button */}
        <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
            <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400" />
            <span>Multi-tactic scam classification & defense checklist</span>
          </div>

          <button
            type="submit"
            id="btn-analyze-submit"
            disabled={isLoading || isExtractingOcr || (!message.trim() && !screenshotBase64)}
            className="w-full sm:w-auto px-7 py-3 rounded-xl bg-gradient-to-r from-rose-600 via-rose-500 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-sm shadow-md shadow-rose-600/20 dark:shadow-rose-950/50 transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Scanning for Fraud & Phishing...
              </>
            ) : isExtractingOcr ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Reading Screenshot...
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                Scan Message for Scams
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
