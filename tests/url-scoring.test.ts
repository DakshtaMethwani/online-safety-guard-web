/**
 * Unit tests for the URL scoring model, confidence, tracking handling and SSRF
 * protection. Network stages are injected, so these are deterministic.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { inspectUrl, followRedirectChain, type InspectDeps, type UrlRedirectCheckShape } from '../server';
import { buildSignals, riskScoreFromSignals, verdictFromScore, VERDICT_THRESHOLDS, MAX_NEGATIVE_POINTS } from '../url-scoring';

const PUBLIC_DNS = async () => [{ address: '8.8.8.8' }];

function cleanProvider() {
  return {
    id: 'fixture-clean',
    label: 'Fixture clean',
    isConfigured: () => true,
    lookup: async () => ({ status: 'clean' as const, note: 'no reports' }),
  };
}

function noneRedirects() {
  return async (url: string): Promise<UrlRedirectCheckShape> => ({
    status: 'none',
    hops: [{ url, status: 200 }],
    finalUrl: url,
    method: 'GET',
    note: 'reachable',
  });
}

const GOOD_INTEL = {
  dns: async () => ({ exists: true }),
  tls: async () => ({ valid: true }),
  domainAgeDays: async () => ({ ageDays: 3000 }),
  trancoRank: async () => ({ rank: null }),
};

// Every live check reports "not run" — confidence must fall, risk must not rise.
const MISSING_INTEL = {
  dns: async () => ({ exists: null }),
  tls: async () => ({ valid: null }),
  domainAgeDays: async () => ({ ageDays: null }),
  trancoRank: async () => ({ rank: null, error: 'not-configured' }),
};

function deps(overrides: Partial<InspectDeps> = {}): InspectDeps {
  return {
    providers: [cleanProvider()],
    followRedirects: noneRedirects(),
    gemini: async () => null,
    intel: GOOD_INTEL,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Determinism + score separation
// ---------------------------------------------------------------------------

test('different inputs give different scores; the same input is stable', async () => {
  const a = await inspectUrl('https://www.paypal.com.evil.xyz/login', deps());
  const b = await inspectUrl('https://example.com/', deps());
  const a2 = await inspectUrl('https://www.paypal.com.evil.xyz/login', deps());

  assert.ok(a.riskScore > b.riskScore, `risky URL should outscore a benign one (${a.riskScore} vs ${b.riskScore})`);
  assert.equal(a.riskScore, a2.riskScore, 'the same input must produce the same score');
  assert.equal(a.verdict, a2.verdict, 'the same input must produce the same verdict');
});

test('missing checks lower confidence, not the risk score', async () => {
  const full = await inspectUrl('https://www.paypal.com.evil.xyz/login', deps({ intel: GOOD_INTEL }));
  const partial = await inspectUrl('https://www.paypal.com.evil.xyz/login', deps({ intel: MISSING_INTEL }));

  assert.equal(partial.riskScore, full.riskScore, 'risk must be evidence-based, not inflated by missing checks');
  assert.ok(partial.confidence < full.confidence, `confidence must drop when checks do not run (${partial.confidence} vs ${full.confidence})`);
});

test('a low score with low confidence is Unverified, never Low risk', () => {
  assert.equal(verdictFromScore({ riskScore: 5, confidence: 30, reputationMalicious: false, criticalOk: true }), 'UNVERIFIED');
  assert.equal(verdictFromScore({ riskScore: 5, confidence: 90, reputationMalicious: false, criticalOk: true }), 'LOW_RISK');
  assert.equal(verdictFromScore({ riskScore: 50, confidence: 90, reputationMalicious: false, criticalOk: true }), 'SUSPICIOUS');
  assert.equal(verdictFromScore({ riskScore: 90, confidence: 90, reputationMalicious: false, criticalOk: true }), 'MALICIOUS');
  assert.equal(
    verdictFromScore({ riskScore: 0, confidence: 0, reputationMalicious: true, criticalOk: false }),
    'MALICIOUS',
    'a reputation hit is MALICIOUS even with no other checks'
  );
  // A failed critical check can never be Low risk, whatever the confidence.
  assert.equal(verdictFromScore({ riskScore: 5, confidence: 95, reputationMalicious: false, criticalOk: false }), 'UNVERIFIED');
});

test('signals carry signed points and a one-line reason', () => {
  const signals = buildSignals({
    flags: [{ severity: 'high', title: 'High-risk top-level domain', evidence: '.top', explanation: 'cheap TLD' }],
    reputationMalicious: false,
    intel: { trancoRank: 12, tlsValid: true, domainAgeDays: 4000 },
  });
  assert.equal(riskScoreFromSignals(signals), 15, 'only the reducer reduces; valid TLS/age add nothing');
  for (const s of signals) {
    assert.equal(typeof s.points, 'number');
    assert.ok(s.reason && s.reason.length > 0, `${s.id} needs a reason`);
  }
  const risky = riskScoreFromSignals(buildSignals({ flags: [{ severity: 'high', title: 'High-risk top-level domain', explanation: 'x' }], reputationMalicious: false }));
  assert.equal(risky, 30);
});

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

test('SSRF: localhost, private ranges and cloud metadata are refused', async () => {
  const cases: Array<{ url: string; dns?: any }> = [
    { url: 'http://127.0.0.1/' },
    { url: 'http://169.254.169.254/latest/meta-data/' },
    { url: 'http://10.0.0.5/' },
    { url: 'http://192.168.1.1/' },
    { url: 'http://internal.local/' },
    { url: 'http://metadata.google.internal/', dns: async () => [{ address: '169.254.169.254' }] },
  ];
  for (const c of cases) {
    let fetched = false;
    const result = await followRedirectChain(c.url, {
      fetchImpl: (async () => {
        fetched = true;
        return { status: 200, headers: new Headers(), body: { cancel: async () => {} } } as unknown as Response;
      }) as unknown as typeof fetch,
      dnsLookupImpl: c.dns || PUBLIC_DNS,
    });
    assert.equal(result.status, 'skipped', `${c.url} must be skipped`);
    assert.equal(fetched, false, `${c.url} must never be fetched`);
  }
});

// ---------------------------------------------------------------------------
// Tracking links
// ---------------------------------------------------------------------------

test('a tracking URL with a long encoded query gets no risk penalty from length', async () => {
  const token = 'R2l0aHViQmFzZTY0T3BhcXVlVG9rZW5UaGF0SXNMb25nQW5kRW5jb2RlZA';
  const r = await inspectUrl(`https://links.sendclean.com/track/click?u=https%3A%2F%2Fexample.com%2F&id=${token}`, deps());
  assert.equal(r.riskScore, 0, 'tracking + long encoded query must not add risk on its own');
  assert.ok(
    r.signals.some((s: any) => s.id === 'tracking-neutral' || s.id === 'tracking-unverified'),
    'tracking signal expected'
  );
  assert.ok(
    r.signals.every((s: any) => !(s.points > 0 && s.id === 'open-redirect-param')),
    'a tracker destination parameter must not be scored as an open redirect'
  );
});

test('an unresolved tracking destination is "unverified" and does not add a big penalty', async () => {
  const r = await inspectUrl(
    'https://links.sendclean.com/track/click?u=https%3A%2F%2Fexample.com%2F',
    deps({
      followRedirects: async () => ({ status: 'inconclusive', hops: [], finalUrl: null, method: 'GET', note: 'tracker blocked HEAD and GET' }),
    })
  );
  assert.ok(r.riskScore < VERDICT_THRESHOLDS.SUSPICIOUS, `no big penalty (got ${r.riskScore})`);
  assert.ok(r.signals.some((s: any) => s.id === 'tracking-unverified'), 'expected a tracking-unverified signal');
  assert.ok(r.confidence < 100, 'unresolved destination must lower confidence');
});

// ---------------------------------------------------------------------------
// Scoring invariants (BUG 1 + BUG 2)
// ---------------------------------------------------------------------------

const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

test('riskScore is exactly clamp(sum of the listed signals)', async () => {
  for (const url of [
    'https://www.paypal.com.evil.xyz/login',
    'https://example.com/delivery-update',
    'https://usps-post-redelivery.top/tracking',
    'https://github.com/',
  ]) {
    const r = await inspectUrl(url, deps());
    const sum = r.signals.reduce((acc: number, s: any) => acc + s.points, 0);
    assert.equal(r.riskScore, clamp(sum), `${url}: score must equal the clamped signal sum (sum=${sum})`);
    // A positive signal may only be 0 when the breakdown visibly cancels it.
    const positives = r.signals.filter((s: any) => s.points > 0);
    if (positives.length && r.riskScore === 0) {
      const negatives = r.signals.filter((s: any) => s.points < 0);
      assert.ok(negatives.length, `${url}: score 0 with a positive signal needs visible negatives`);
    }
  }
});

test('valid TLS, a resolving DNS name and a normal domain age never lower risk', () => {
  const signals = buildSignals({
    flags: [],
    reputationMalicious: false,
    intel: { tlsValid: true, dnsExists: true, domainAgeDays: 4000 },
  });
  assert.equal(riskScoreFromSignals(signals), 0, 'these are not negative evidence');
  assert.ok(!signals.some((s) => s.points < 0), 'no normal TLS/DNS/age signal may carry negative points');
});

test('negative points are capped at -20 in total', () => {
  const signals = buildSignals({
    flags: [],
    reputationMalicious: false,
    reputationClean: true,
    allowlisted: true,
    intel: { trancoRank: 5 },
    finalDestination: { url: 'https://www.google.com/', wellKnown: true },
  });
  const negatives = signals.filter((s) => s.points < 0).reduce((acc, s) => acc + s.points, 0);
  assert.equal(negatives, -MAX_NEGATIVE_POINTS, `total reduction must be capped (got ${negatives})`);
  assert.equal(riskScoreFromSignals(signals), 0);
});

test('negative points never cancel a high-severity signal', () => {
  const signals = buildSignals({
    flags: [{ severity: 'high', title: 'Brand name embedded in an unrelated domain', evidence: 'paypal', explanation: 'brand' }],
    reputationMalicious: false,
    reputationClean: true,
    allowlisted: true,
    intel: { trancoRank: 5 },
    finalDestination: { url: 'https://www.google.com/', wellKnown: true },
  });
  assert.equal(riskScoreFromSignals(signals), 32, 'the brand-impersonation signal must survive reducers');
  assert.ok(!signals.some((s) => s.points < 0), 'reducers must be dropped entirely');
});

test('a generic keyword alone is weak and only strengthens with a second signal', () => {
  const alone = riskScoreFromSignals(
    buildSignals({
      flags: [{ severity: 'medium', title: 'Login/credential context on an unverified domain', evidence: '/login', explanation: 'login copy' }],
      reputationMalicious: false,
    })
  );
  const combined = riskScoreFromSignals(
    buildSignals({
      flags: [
        { severity: 'medium', title: 'Login/credential context on an unverified domain', evidence: '/login', explanation: 'login copy' },
        { severity: 'high', title: 'High-risk top-level domain', evidence: '.top', explanation: 'cheap TLD' },
      ],
      reputationMalicious: false,
    })
  );
  assert.ok(alone <= 5, `a single generic word must stay small (got ${alone})`);
  assert.ok(combined >= 30, `combined with a TLD it is a real signal (got ${combined})`);
});

// ---------------------------------------------------------------------------
// Expected behaviour with test doubles (BUG 3)
// ---------------------------------------------------------------------------

const TRANCO_INTEL = {
  dns: async () => ({ exists: true }),
  tls: async () => ({ valid: true }),
  domainAgeDays: async () => ({ ageDays: 3000 }),
  trancoRank: async () => ({ rank: 42 }),
};

test('a Tranco-listed domain with all checks run: low risk and confidence >= 80', async () => {
  const r = await inspectUrl('https://www.example-tranco.test/', deps({ intel: TRANCO_INTEL }));
  assert.equal(r.verdict, 'LOW_RISK');
  assert.ok(r.riskScore < VERDICT_THRESHOLDS.SUSPICIOUS);
  assert.ok(r.confidence >= 80, `confidence should be high when checks run (got ${r.confidence})`);
  assert.ok(r.checks.every((c: any) => c.status !== 'skipped' && c.status !== 'error'), 'all checks ran');
});

test('usps-post-redelivery.top scores high risk', async () => {
  const r = await inspectUrl('https://usps-post-redelivery.top/tracking', deps());
  assert.equal(r.verdict, 'MALICIOUS');
  assert.ok(r.riskScore >= VERDICT_THRESHOLDS.MALICIOUS);
});

test('an unresolvable domain is an error state with a non-zero score, not 0', async () => {
  const r = await inspectUrl(
    'https://does-not-resolve.invalid/',
    deps({
      intel: {
        dns: async () => ({ exists: false, error: 'ENOTFOUND' }),
        tls: async () => ({ valid: null }),
        domainAgeDays: async () => ({ ageDays: null }),
        trancoRank: async () => ({ rank: null, error: 'not available' }),
      },
      followRedirects: async () => ({ status: 'error', hops: [], finalUrl: null, method: 'GET', note: 'ENOTFOUND' }),
    })
  );
  assert.notEqual(r.verdict, 'LOW_RISK');
  assert.equal(r.verdict, 'UNVERIFIED');
  assert.ok(r.riskScore > 0, `no-DNS is real evidence, not 0 (got ${r.riskScore})`);
});
