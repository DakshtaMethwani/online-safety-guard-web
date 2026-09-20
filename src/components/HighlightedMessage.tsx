import React, { useState } from 'react';
import { HighlightPhrase } from '../types';
import { AlertCircle, AlertTriangle, ExternalLink, Info } from 'lucide-react';

interface HighlightedMessageProps {
  message: string;
  sender?: string;
  platform?: string;
  highlights: HighlightPhrase[];
}

export const HighlightedMessage: React.FC<HighlightedMessageProps> = ({
  message,
  sender,
  platform,
  highlights = [],
}) => {
  const [selectedHighlight, setSelectedHighlight] = useState<HighlightPhrase | null>(
    highlights.length > 0 ? highlights[0] : null
  );

  // If no highlights or plain message, render styled text
  if (!highlights || highlights.length === 0 || !message) {
    return (
      <div className="bg-slate-100/80 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-xl p-4 font-mono text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed">
        {message || 'No message text'}
      </div>
    );
  }

  // Sort highlights by starting index to avoid collision
  const sortedHighlights = [...highlights].sort((a, b) => {
    const idxA = message.toLowerCase().indexOf(a.text.toLowerCase());
    const idxB = message.toLowerCase().indexOf(b.text.toLowerCase());
    return idxA - idxB;
  });

  // Build segments
  const segments: Array<{ text: string; highlight?: HighlightPhrase }> = [];
  let currentIndex = 0;
  const lowerMessage = message.toLowerCase();

  for (const h of sortedHighlights) {
    if (!h.text || h.text.trim() === '') continue;
    const pos = lowerMessage.indexOf(h.text.toLowerCase(), currentIndex);
    if (pos >= currentIndex) {
      if (pos > currentIndex) {
        segments.push({ text: message.slice(currentIndex, pos) });
      }
      segments.push({
        text: message.slice(pos, pos + h.text.length),
        highlight: h,
      });
      currentIndex = pos + h.text.length;
    }
  }

  if (currentIndex < message.length) {
    segments.push({ text: message.slice(currentIndex) });
  }

  return (
    <div className="space-y-3">
      <div className="bg-slate-100/90 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-5 relative overflow-hidden transition-colors">
        {/* Context Bar */}
        <div className="flex items-center justify-between gap-2 pb-3 mb-3 border-b border-slate-200 dark:border-slate-800/80 text-xs text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium">
              {platform || 'Message'}
            </span>
            {sender && (
              <span className="text-slate-500 dark:text-slate-400 font-mono truncate max-w-[200px] sm:max-w-xs">
                From: <span className="text-slate-900 dark:text-slate-200 font-medium">{sender}</span>
              </span>
            )}
          </div>
          <span className="text-[11px] text-slate-500 hidden sm:inline">
            Click highlighted sections to inspect
          </span>
        </div>

        {/* Message Content with Interactive Highlights */}
        <div className="font-mono text-sm leading-relaxed text-slate-800 dark:text-slate-200 whitespace-pre-wrap selection:bg-rose-500/30">
          {segments.map((seg, idx) => {
            if (!seg.highlight) {
              return <span key={idx}>{seg.text}</span>;
            }

            const h = seg.highlight;
            const isSelected = selectedHighlight?.text === h.text;

            let badgeClass = 'bg-rose-100 text-rose-800 border-rose-300 hover:bg-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-600/40 dark:hover:bg-rose-900/60';
            if (h.category === 'warning') {
              badgeClass = 'bg-amber-100 text-amber-900 border-amber-300 hover:bg-amber-200 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-600/40 dark:hover:bg-amber-900/60';
            } else if (h.category === 'suspicious_link') {
              badgeClass = 'bg-purple-100 text-purple-900 border-purple-300 hover:bg-purple-200 dark:bg-purple-950/60 dark:text-purple-300 dark:border-purple-600/40 dark:hover:bg-purple-900/60';
            }

            if (isSelected) {
              badgeClass += ' ring-2 ring-slate-800 dark:ring-white/60 underline font-bold';
            }

            return (
              <button
                key={idx}
                type="button"
                onClick={() => setSelectedHighlight(h)}
                className={`inline-block px-1.5 py-0.5 rounded border text-xs cursor-pointer transition-all mx-0.5 align-baseline text-left font-mono font-medium ${badgeClass}`}
                title="Click to view why this is flagged"
              >
                {seg.text}
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected Highlight Inspector Card */}
      {selectedHighlight && (
        <div className="bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-700/70 shadow-sm rounded-xl p-3.5 flex items-start gap-3 transition-all animate-fadeIn">
          <div className="mt-0.5 flex-shrink-0">
            {selectedHighlight.category === 'danger' && (
              <div className="w-6 h-6 rounded-lg bg-rose-500/20 text-rose-600 dark:text-rose-400 flex items-center justify-center">
                <AlertCircle className="w-4 h-4" />
              </div>
            )}
            {selectedHighlight.category === 'warning' && (
              <div className="w-6 h-6 rounded-lg bg-amber-500/20 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                <AlertTriangle className="w-4 h-4" />
              </div>
            )}
            {selectedHighlight.category === 'suspicious_link' && (
              <div className="w-6 h-6 rounded-lg bg-purple-500/20 text-purple-600 dark:text-purple-400 flex items-center justify-center">
                <ExternalLink className="w-4 h-4" />
              </div>
            )}
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 truncate bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                "{selectedHighlight.text}"
              </span>
              <span
                className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${
                  selectedHighlight.category === 'danger'
                    ? 'bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300'
                    : selectedHighlight.category === 'warning'
                    ? 'bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300'
                    : 'bg-purple-100 text-purple-900 dark:bg-purple-500/20 dark:text-purple-300'
                }`}
              >
                {selectedHighlight.category.replace('_', ' ')}
              </span>
            </div>
            <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
              {selectedHighlight.explanation}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

