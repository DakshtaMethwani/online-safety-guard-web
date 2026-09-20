/**
 * Tests for the message threat-analysis engine and the Gemini + rule-engine
 * combination logic.
 *
 * The rule engine is deterministic, so these run without any network or API
 * key. The combination tests inject a fake Gemini result to prove that a
 * "safe" AI verdict can never override strong deterministic signals.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

process.env.GEMINI_API_KEY = '';

import { app, ruleBasedScan, combineMessageAnalysis } from '../server';

// The exact scenario from the requirements: urgency + account-suspension threat
// + request to verify account details + a suspicious/unverified login link.
const PHISHING_COMBO =
  'Dear customer, we detected unauthorized access to your account. ' +
  'Your account will be suspended within 30 minutes unless you act. ' +
  'Please verify your account details immediately at http://secure-login-verify.top/account to confirm your identity.';

// ---------------------------------------------------------------------------
// Deterministic rule engine
// ---------------------------------------------------------------------------

test('urgency + suspension threat + verify-account + suspicious link → HIGH RISK (never SAFE)', () => {
  const r = ruleBasedScan(PHISHING_COMBO, 'alerts@secure-login-verify.top');

  assert.equal(r.safetyStatus, 'DANGEROUS_SCAM');
  assert.ok(r.riskScore >= 60, `risk score must be high (got ${r.riskScore})`);

  const flags = r.redFlags.map((f) => f.flag.toLowerCase());
  assert.ok(flags.some((f) => f.includes('urgency')), 'expected an urgency signal');
  assert.ok(flags.some((f) => f.includes('threat') || f.includes('suspension')), 'expected a threat signal');
  assert.ok(flags.some((f) => f.includes('verify account')), 'expected a credential-verification signal');
  assert.ok(flags.some((f) => f.includes('link')), 'expected a suspicious-link signal');

  // The summary must explain the exact reasons.
  assert.match(r.verdictSummary, /urgency|threat|verification|link/i);

  // Weighted breakdown is exposed for the UI / debugging.
  const categories = r.signalBreakdown.map((s) => s.category);
  assert.ok(categories.includes('urgency'));
  assert.ok(categories.includes('threat'));
  assert.ok(categories.includes('credential_request'));
  assert.ok(categories.includes('suspicious_url'));
  assert.ok(categories.includes('combined'), 'expected the combined phishing signal');
});

test('a benign personal message is SAFE', () => {
  const r = ruleBasedScan('Hey, are we still meeting for lunch at 1pm tomorrow? Let me know if that works.');
  assert.equal(r.safetyStatus, 'SAFE');
  assert.ok(r.riskScore < 28, `benign message should score low (got ${r.riskScore})`);
});

test('an authentic 2FA notice ("never share this code") is not flagged as a credential demand', () => {
  const r = ruleBasedScan('Your verification code is 482913. Never share this code with anyone, not even support.');
  assert.equal(r.safetyStatus, 'SAFE');
  assert.ok(!r.redFlags.some((f) => /credential|secret code/i.test(f.flag)), 'benign "never share" notice must not be flagged');
});

test('brand impersonation with a look-alike verification link → HIGH RISK', () => {
  const r = ruleBasedScan('PayPal: your account is limited. Verify your information at http://paypal-secure.xyz/login');
  assert.equal(r.safetyStatus, 'DANGEROUS_SCAM');
  assert.ok(r.redFlags.some((f) => /impersonation/i.test(f.flag)), 'expected an impersonation signal');
});

test('a single weak signal does not produce a HIGH RISK verdict', () => {
  const r = ruleBasedScan('Reminder: your appointment is tomorrow at 10am.');
  assert.notEqual(r.safetyStatus, 'DANGEROUS_SCAM');
  assert.ok(r.riskScore < 60);
});

// ---------------------------------------------------------------------------
// Gemini + rule-engine combination
// ---------------------------------------------------------------------------

test('a "SAFE" Gemini verdict cannot override strong deterministic signals', () => {
  const heuristic = ruleBasedScan(PHISHING_COMBO, 'alerts@secure-login-verify.top');
  assert.equal(heuristic.safetyStatus, 'DANGEROUS_SCAM');

  const combined = combineMessageAnalysis(heuristic, {
    safetyStatus: 'SAFE',
    riskScore: 4,
    scamType: 'Legitimate Notification',
    verdictSummary: 'This looks like a normal account notice.',
    redFlags: [],
    tacticsUsed: [],
    highlightPhrases: [],
  });

  assert.equal(combined.safetyStatus, 'DANGEROUS_SCAM');
  assert.ok(combined.riskScore >= 60, `deterministic floor must hold (got ${combined.riskScore})`);
  assert.equal(combined.deterministicOverride, true);
  assert.equal(combined.aiVerdict, 'SAFE');
  assert.match(combined.verdictSummary, /overridden|deterministic/i);
  // The exact deterministic reasons are still present.
  assert.ok(combined.redFlags.some((f) => /urgency/i.test(f.flag)));
  assert.ok(combined.redFlags.some((f) => /link/i.test(f.flag)));
});

test('Gemini can escalate a clean heuristic result', () => {
  const heuristic = ruleBasedScan('Hi, quick question about the invoice when you get a chance.');
  assert.notEqual(heuristic.safetyStatus, 'DANGEROUS_SCAM');

  const combined = combineMessageAnalysis(heuristic, {
    safetyStatus: 'DANGEROUS_SCAM',
    riskScore: 92,
    scamType: 'Business Email Compromise',
    verdictSummary: 'Semantic analysis reveals a payment-redirection attempt.',
    redFlags: [{ flag: 'Semantic: payment redirection', evidence: 'invoice', severity: 'high' }],
    tacticsUsed: ['Authority Spoofing'],
    highlightPhrases: [],
  });

  assert.equal(combined.safetyStatus, 'DANGEROUS_SCAM');
  assert.ok(combined.riskScore >= 60);
});

test('Gemini agreeing on SAFE keeps the message SAFE', () => {
  const heuristic = ruleBasedScan('Thanks! See you at the meeting.');
  const combined = combineMessageAnalysis(heuristic, {
    safetyStatus: 'SAFE',
    riskScore: 3,
    scamType: 'Legitimate Notification',
    verdictSummary: 'Benign message.',
    redFlags: [],
    tacticsUsed: [],
    highlightPhrases: [],
  });
  assert.equal(combined.safetyStatus, 'SAFE');
  assert.equal(combined.deterministicOverride, false);
});

test('combineMessageAnalysis with no AI returns the deterministic engine result', () => {
  const heuristic = ruleBasedScan(PHISHING_COMBO);
  const combined = combineMessageAnalysis(heuristic, null);
  assert.equal(combined.safetyStatus, 'DANGEROUS_SCAM');
  assert.equal(combined.engine, 'heuristic-rules');
});

// ---------------------------------------------------------------------------
// Endpoint wiring
// ---------------------------------------------------------------------------

test('POST /api/analyze-message returns HIGH RISK for the phishing combo (no Gemini key)', async () => {
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/analyze-message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: PHISHING_COMBO, sender: 'alerts@secure-login-verify.top', platform: 'SMS / iMessage' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.safetyStatus, 'DANGEROUS_SCAM');
    assert.ok(body.riskScore >= 60);
    assert.equal(body.engine, 'heuristic-rules');
    assert.ok(Array.isArray(body.redFlags) && body.redFlags.length >= 4);
  } finally {
    server.close();
    server.closeAllConnections?.();
  }
});
