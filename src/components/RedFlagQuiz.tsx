import React, { useState } from 'react';
import { HelpCircle, ShieldAlert, ShieldCheck, CheckCircle2, AlertTriangle, RotateCcw } from 'lucide-react';

interface Question {
  id: string;
  title: string;
  description: string;
  pointsIfYes: number;
}

const QUESTIONS: Question[] = [
  {
    id: 'unsolicited',
    title: 'Did they reach out to you unexpectedly?',
    description: 'You did not initiate the conversation or request customer support, but they messaged claiming to be your bank, postal service, Amazon, or a recruiter.',
    pointsIfYes: 25,
  },
  {
    id: 'urgency',
    title: 'Is there intense urgency or a threat?',
    description: 'They say your account will be "suspended within 24 hours", a fee must be paid "immediately", or you will face legal action unless you act right now.',
    pointsIfYes: 30,
  },
  {
    id: 'sensitive_request',
    title: 'Are they asking for a link click, OTP code, or untraceable payment?',
    description: 'Asking you to click an unfamiliar link, share a 6-digit text verification code, buy gift cards, or wire cryptocurrency.',
    pointsIfYes: 35,
  },
  {
    id: 'too_good',
    title: 'Is the offer or reward unusually generous?',
    description: 'Promising $500/day for 30 minutes of simple tasks, a crypto giveaway claiming to double your money, or an unexpected inheritance/lottery prize.',
    pointsIfYes: 30,
  },
];

export const RedFlagQuiz: React.FC = () => {
  const [answers, setAnswers] = useState<Record<string, boolean>>({});

  const toggleAnswer = (qId: string, value: boolean) => {
    setAnswers((prev) => ({ ...prev, [qId]: value }));
  };

  const answeredCount = Object.keys(answers).length;
  const totalScore = Object.entries(answers).reduce((sum, [qId, isYes]) => {
    if (!isYes) return sum;
    const q = QUESTIONS.find((item) => item.id === qId);
    return sum + (q ? q.pointsIfYes : 0);
  }, 0);

  const resetQuiz = () => setAnswers({});

  let riskLevel = 'Low Scam Probability';
  let riskColor = 'text-emerald-800 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-500/15 border-emerald-300 dark:border-emerald-500/30';
  let riskDescription = 'While caution is always smart, this message does not exhibit the typical pressure tactics used in active fraud.';

  if (totalScore >= 55) {
    riskLevel = 'EXTREME SCAM PROBABILITY';
    riskColor = 'text-rose-800 dark:text-rose-400 bg-rose-100 dark:bg-rose-500/15 border-rose-300 dark:border-rose-500/30';
    riskDescription = 'Almost certainly a scam or phishing attack. Stop interacting immediately, do not click any links, and do not provide codes.';
  } else if (totalScore >= 25) {
    riskLevel = 'MODERATE TO HIGH RISK';
    riskColor = 'text-amber-900 dark:text-amber-400 bg-amber-100 dark:bg-amber-500/15 border-amber-300 dark:border-amber-500/30';
    riskDescription = 'Contains key scam hallmarks. Proceed with heavy skepticism and verify through an independent channel.';
  }

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <div className="bg-white/85 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 space-y-3 backdrop-blur-sm shadow-xs transition-colors">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-amber-500/15 text-amber-600 dark:text-amber-400 flex items-center justify-center">
              <HelpCircle className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">30-Second Scam Self-Assessment</h2>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                Answer these 4 universal questions to instantly gauge if any message or phone call is fraudulent.
              </p>
            </div>
          </div>

          {answeredCount > 0 && (
            <button
              onClick={resetQuiz}
              className="text-xs text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset
            </button>
          )}
        </div>

        {/* Questions List */}
        <div className="space-y-3 pt-3">
          {QUESTIONS.map((q, idx) => {
            const currentAnswer = answers[q.id];
            return (
              <div
                key={q.id}
                className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/90 space-y-2.5 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span className="text-sm font-bold text-slate-900 dark:text-slate-200">
                    {idx + 1}. {q.title}
                  </span>

                  <div className="flex items-center gap-1.5 self-end sm:self-auto">
                    <button
                      type="button"
                      onClick={() => toggleAnswer(q.id, true)}
                      className={`px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                        currentAnswer === true
                          ? 'bg-rose-600 text-white shadow-xs'
                          : 'bg-slate-200 dark:bg-slate-900 text-slate-700 dark:text-slate-400 hover:bg-slate-300 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white border border-slate-300 dark:border-slate-800'
                      }`}
                    >
                      YES
                    </button>
                    <button
                      type="button"
                      onClick={() => toggleAnswer(q.id, false)}
                      className={`px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                        currentAnswer === false
                          ? 'bg-emerald-600 text-white shadow-xs'
                          : 'bg-slate-200 dark:bg-slate-900 text-slate-700 dark:text-slate-400 hover:bg-slate-300 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white border border-slate-300 dark:border-slate-800'
                      }`}
                    >
                      NO
                    </button>
                  </div>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  {q.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Real-time Assessment Output */}
      {answeredCount > 0 && (
        <div className="bg-white/90 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 sm:p-6 space-y-3 animate-fadeIn backdrop-blur-sm shadow-xs transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Evaluation Outcome ({answeredCount} of 4 answered)
            </span>
            <span className={`text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wider border ${riskColor}`}>
              {riskLevel}
            </span>
          </div>

          <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">
            {riskDescription}
          </p>

          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300">
            <span className="font-bold text-slate-900 dark:text-white block mb-1">Golden Rule of Online Safety:</span>
            Legitimate organizations never force you to resolve account emergencies via a rushed text link. Always contact the official customer support number printed on your physical card or found directly via an independent web search.
          </div>
        </div>
      )}
    </div>
  );
};
