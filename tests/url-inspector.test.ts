/**
 * Tests for the Suspicious Link & Domain Inspector engine (heuristic-url-engine).
 *
 * Network-dependent stages (reputation lookup, redirect following, AI) are
 * injected as fakes so the fixtures are deterministic. The redirect follower
 * itself is unit-tested against a fake fetch to prove HEAD→GET fallback,
 * inconclusive statuses, chain recording and loop detection.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  inspectUrl,
  followRedirectChain,
  urlhausProvider,
  googleSafeBrowsingProvider,
  type InspectDeps,
  type ReputationProvider,
  type UrlRedirectCheckShape,
} from '../server';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PUBLIC_DNS = async () => [{ address: '8.8.8.8' }];

function response(status: number, init?: { location?: string; json?: unknown }) {
  const headers = new Headers();
  if (init?.location) headers.set('location', init.location);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers,
    body: { cancel: async () => {} },
    json: async () => init?.json ?? {},
    arrayBuffer: async () => new ArrayBuffer(0),
  } as unknown as Response;
}

function cleanProvider(): ReputationProvider {
  return {
    id: 'fixture-clean',
    label: 'Fixture clean provider',
    isConfigured: () => true,
    lookup: async () => ({ status: 'clean' as const, note: 'No reports (fixture).' }),
  };
}

function noneRedirects(method: 'HEAD' | 'GET' = 'GET') {
  return async (url: string): Promise<UrlRedirectCheckShape> => ({
    status: 'none',
    hops: [{ url, status: 200 }],
    finalUrl: url,
    method,
    note: method === 'GET' ? 'Reachable (HTTP 200). No redirect. (GET fallback used)' : 'Reachable (HTTP 200). No redirect.',
  });
}

function baseDeps(overrides: Partial<InspectDeps> & { providers?: ReputationProvider[] } = {}): InspectDeps {
  return {
    providers: [cleanProvider()],
    followRedirects: noneRedirects(),
    gemini: async () => null,
    ...overrides,
  };
}

async function withUrlhausKey(value: string | undefined, fn: () => Promise<void>) {
  const prev = process.env.URLHAUS_API_KEY;
  if (value === undefined) delete process.env.URLHAUS_API_KEY;
  else process.env.URLHAUS_API_KEY = value;
  try {
    await fn();
  } finally {
    if (prev === undefined) delete process.env.URLHAUS_API_KEY;
    else process.env.URLHAUS_API_KEY = prev;
  }
}

async function withGsbKey(value: string | undefined, fn: () => Promise<void>) {
  const prev = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (value === undefined) delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  else process.env.GOOGLE_SAFE_BROWSING_API_KEY = value;
  try {
    await fn();
  } finally {
    if (prev === undefined) delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    else process.env.GOOGLE_SAFE_BROWSING_API_KEY = prev;
  }
}

// ---------------------------------------------------------------------------
// End-to-end fixtures (network faked)
// ---------------------------------------------------------------------------

test('urlvoid.com?utm_source=chatgpt.com with no API key → Unverified, reputation not configured', async () => {
  await withUrlhausKey(undefined, async () => {
    const r = await inspectUrl(
      'https://www.urlvoid.com/?utm_source=chatgpt.com',
      baseDeps({ providers: [urlhausProvider] })
    );

    assert.equal(r.verdict, 'UNVERIFIED');
    // Missing checks lower confidence; they never inflate the risk score.
    assert.equal(r.threatLevel, 'UNKNOWN');
    assert.match(r.verdictReason, /unverified/i);
    assert.ok(r.confidence <= 55, `missing reputation key must cap confidence (got ${r.confidence})`);
    assert.ok(r.riskScore < 40, `no evidence must mean a low score, not a medium one (got ${r.riskScore})`);

    // Reputation card → "not configured", and never counted as a pass.
    assert.equal(r.reputation.status, 'not_configured');
    const repCheck = r.checks.find((c) => c.id === 'reputation');
    assert.equal(repCheck?.status, 'skipped');

    // Redirect resolves via GET fallback.
    assert.equal(r.redirects.status, 'none');
    assert.equal(r.redirects.method, 'GET');
    assert.equal(r.redirects.hops.length, 1);
    assert.equal(r.redirects.finalUrl, 'https://www.urlvoid.com/?utm_source=chatgpt.com');

    // utm param surfaces as an informational finding, not a spoof flag.
    const tracking = r.findings.find((f) => f.title === 'Tracking parameters present');
    assert.ok(tracking, 'expected a tracking-parameter finding');
    assert.equal(tracking.severity, 'info');
    assert.match(tracking.evidence, /utm_source=chatgpt\.com/);
    assert.ok(!r.findings.some((f) => f.title.includes('Brand') || f.title.includes('spoof')), 'no brand/spoof findings from query values');
    assert.equal(r.urlStructure.status, 'valid');
  });
});

test('a clean check with no threats detected → LOW RISK (low score)', async () => {
  await withUrlhausKey('fixture-key', async () => {
    const r = await inspectUrl('https://www.urlvoid.com/?utm_source=chatgpt.com', baseDeps());

    assert.equal(r.verdict, 'LOW_RISK');
    assert.equal(r.threatLevel, 'LOW');
    assert.ok(r.riskScore <= 20, `a clean result must score low (got ${r.riskScore})`);
    assert.equal(r.reputation.status, 'clean');
    assert.ok(r.checks.every((c) => c.status === 'passed'), 'every check must have actually run and passed');
    assert.equal(r.redirects.status, 'none');
    assert.equal(r.redirects.method, 'GET');
  });
});

test('usps-post-redelivery.top → high risk (suspicious TLD + brand keyword)', async () => {
  const r = await inspectUrl('https://usps-post-redelivery.top/tracking', baseDeps());

  assert.equal(r.verdict, 'MALICIOUS');
  assert.equal(r.threatLevel, 'HIGH');
  const tld = r.findings.find((f) => f.title === 'High-risk top-level domain');
  assert.ok(tld, 'expected suspicious-TLD finding');
  assert.equal(tld.severity, 'critical');
  assert.ok(
    r.findings.some((f) => f.title === 'Brand name embedded in an unrelated domain'),
    'expected brand-keyword finding (USPS)'
  );
  assert.equal(r.checks.find((c) => c.id === 'url-structure')?.status, 'failed');
});

test('www.paypal.com.evil.xyz/login → high risk (brand in subdomain, not the registered domain)', async () => {
  const r = await inspectUrl('https://www.paypal.com.evil.xyz/login', baseDeps());

  assert.equal(r.verdict, 'MALICIOUS');
  assert.equal(r.threatLevel, 'HIGH');
  assert.equal(r.spoofedBrand, 'PayPal');
  assert.equal(r.registrableDomain, 'evil.xyz');
  assert.ok(
    r.findings.some((f) => f.title === 'Brand domain planted inside a third-party hostname'),
    'expected domain-embedding finding'
  );
  assert.ok(
    r.findings.some((f) => f.title === 'Brand name hidden in subdomain of unrelated host'),
    'expected subdomain brand finding'
  );
});

test('example.com/?next=https://evil.com → warning: possible open redirect', async () => {
  const r = await inspectUrl('https://example.com/?next=https://evil.com', baseDeps());

  const f = r.findings.find((x) => x.title === 'Possible open redirect via query parameter');
  assert.ok(f, 'expected open-redirect finding');
  assert.equal(f.severity, 'warning');
  assert.match(f.evidence, /next=https:\/\/evil\.com/);
  assert.equal(r.verdict, 'SUSPICIOUS');
  assert.equal(r.checks.find((c) => c.id === 'query-params')?.status, 'warning');
});

test('an unreachable host → redirect check error, verdict Unverified', async () => {
  const r = await inspectUrl(
    'https://nxdomain.example/',
    baseDeps({
      followRedirects: async () => ({
        status: 'error',
        hops: [],
        finalUrl: null,
        method: 'HEAD',
        note: 'ENETUNREACH: Network error while checking the link.',
      }),
    })
  );

  assert.equal(r.redirects.status, 'error');
  assert.equal(r.verdict, 'UNVERIFIED');
  assert.match(r.verdictReason, /unverified/i);
  assert.equal(r.threatLevel, 'UNKNOWN');
  const redirCheck = r.checks.find((c) => c.id === 'redirect');
  assert.equal(redirCheck?.status, 'error');
  assert.notEqual(r.redirects.status, 'none', 'an error must never be reported as reachable/clean');
});

test('a provider-confirmed threat is HIGH RISK with the detected threat shown', async () => {
  const threatProvider: ReputationProvider = {
    id: 'fixture-threat',
    label: 'Fixture threat feed',
    isConfigured: () => true,
    lookup: async (ctx) => ({
      status: 'malicious' as const,
      note: 'Fixture feed lists this URL as a confirmed threat.',
      reference: 'https://example.org/report',
      flaggedUrl: ctx.url,
      details: [{ url: ctx.url, threat: 'Phishing / social engineering', dateAdded: '2026-09-01' }],
    }),
  };

  const r = await inspectUrl('https://login-secure.example/verify', baseDeps({ providers: [threatProvider] }));

  assert.equal(r.verdict, 'MALICIOUS');
  assert.equal(r.threatLevel, 'HIGH');
  assert.ok(r.riskScore >= 70);
  assert.equal(r.reputation.status, 'malicious');
  assert.equal(r.reputation.flaggedUrl, 'https://login-secure.example/verify');
  assert.equal(r.checks.find((c) => c.id === 'reputation')?.status, 'failed');

  const finding = r.findings.find((f) => f.severity === 'critical' && /confirmed threat/i.test(f.title));
  assert.ok(finding, 'expected a critical reputation finding');
  assert.match(finding.explanation, /Phishing/i);
  assert.equal(finding.evidence, 'https://login-secure.example/verify');
  // The confirmed threat must also dominate the human-readable summary.
  assert.match(r.verdictReason, /confirmed a threat/i);
});

test('a missing key cannot be masked: the warning still raises the score, and confidence is capped', async () => {
  await withUrlhausKey(undefined, async () => {
    const r = await inspectUrl(
      'https://example.com/?next=https://evil.com',
      baseDeps({ providers: [urlhausProvider] })
    );
    // The open-redirect signal is real evidence, so the verdict is not low risk.
    assert.notEqual(r.verdict, 'LOW_RISK');
    assert.ok(r.riskScore >= 40, `open-redirect evidence should score >= 40 (got ${r.riskScore})`);
    // A missing critical check caps confidence.
    assert.ok(r.confidence <= 55, `confidence must be capped (got ${r.confidence})`);
    // The open-redirect warning is still surfaced as a finding.
    assert.ok(
      r.findings.some((f) => f.title === 'Possible open redirect via query parameter'),
      'warning finding must remain visible'
    );
  });
});

test('a malicious post-redirect destination is caught even when the entry URL is clean', async () => {
  const provider: ReputationProvider = {
    id: 'fixture-threat',
    label: 'Fixture threat feed',
    isConfigured: () => true,
    lookup: async (ctx) =>
      ctx.url.includes('evil-final.example')
        ? {
            status: 'malicious' as const,
            note: 'Redirect destination is a confirmed phishing page.',
            flaggedUrl: ctx.url,
            details: [{ url: ctx.url, threat: 'Phishing / social engineering', dateAdded: '' }],
          }
        : { status: 'clean' as const, note: 'No reports for the entry URL.' },
  };

  const redirects: UrlRedirectCheckShape = {
    status: 'redirect',
    hops: [
      { url: 'https://safe-start.example/go', status: 301 },
      { url: 'https://evil-final.example/steal', status: 200 },
    ],
    finalUrl: 'https://evil-final.example/steal',
    method: 'GET',
    note: 'Redirected to a different registered domain.',
    flags: [],
  };

  const r = await inspectUrl(
    'https://safe-start.example/go',
    baseDeps({ providers: [provider], followRedirects: async () => redirects })
  );

  assert.equal(r.verdict, 'MALICIOUS');
  assert.ok(r.riskScore >= 70);
  assert.equal(r.reputation.status, 'malicious');
  assert.equal(r.reputation.flaggedUrl, 'https://evil-final.example/steal');
  assert.deepEqual(r.reputation.checkedUrls, [
    'https://safe-start.example/go',
    'https://evil-final.example/steal',
  ]);
  const finding = r.findings.find((f) => f.title === 'Redirect destination flagged as a confirmed threat');
  assert.ok(finding, 'expected a redirect-destination threat finding');
  assert.equal(finding.severity, 'critical');
});

// ---------------------------------------------------------------------------
// Redirect follower unit tests (fake fetch)
// ---------------------------------------------------------------------------

test('followRedirectChain: HEAD 405 → GET fallback resolves, records method and no redirect', async () => {
  let headCount = 0;
  let getCount = 0;
  const fetchImpl = async (url: string, init?: any) => {
    if (init?.method === 'HEAD') {
      headCount++;
      return response(405);
    }
    getCount++;
    return response(200);
  };

  const r = await followRedirectChain('https://www.urlvoid.com/', { fetchImpl, dnsLookupImpl: PUBLIC_DNS });
  assert.equal(headCount, 1);
  assert.equal(getCount, 1);
  assert.equal(r.status, 'none');
  assert.equal(r.method, 'GET');
  assert.equal(r.hops.length, 1);
  assert.equal(r.hops[0].status, 200);
  assert.equal(r.finalUrl, 'https://www.urlvoid.com/');
});

test('followRedirectChain: HEAD 405 → GET 403 is inconclusive, not reachable/clean', async () => {
  const fetchImpl = async (url: string, init?: any) => response(init?.method === 'HEAD' ? 405 : 403);
  const r = await followRedirectChain('https://example.com/', { fetchImpl, dnsLookupImpl: PUBLIC_DNS });
  assert.equal(r.status, 'inconclusive');
  assert.match(r.note ?? '', /403/);
});

test('followRedirectChain: HEAD 405 → GET 429 is inconclusive', async () => {
  const fetchImpl = async (url: string, init?: any) => response(init?.method === 'HEAD' ? 405 : 429);
  const r = await followRedirectChain('https://example.com/', { fetchImpl, dnsLookupImpl: PUBLIC_DNS });
  assert.equal(r.status, 'inconclusive');
});

test('followRedirectChain: records full chain and flags cross-domain redirect', async () => {
  const fetchImpl = async (url: string) => {
    if (url === 'https://example.com/') return response(301, { location: 'https://evil.com/' });
    return response(200);
  };
  const r = await followRedirectChain('https://example.com/', { fetchImpl, dnsLookupImpl: PUBLIC_DNS });

  assert.equal(r.status, 'redirect');
  assert.equal(r.hops.length, 2);
  assert.equal(r.hops[0].url, 'https://example.com/');
  assert.equal(r.hops[0].status, 301);
  assert.equal(r.hops[1].url, 'https://evil.com/');
  assert.equal(r.hops[1].status, 200);
  assert.equal(r.finalUrl, 'https://evil.com/');
  assert.ok(
    r.flags?.some((f) => f.title === 'Redirect crosses to a different registered domain'),
    'expected cross-registered-domain flag'
  );
});

test('followRedirectChain: flags HTTPS downgrade (https → http)', async () => {
  const fetchImpl = async (url: string) => {
    if (url === 'https://example.com/') return response(302, { location: 'http://example.com/' });
    return response(200);
  };
  const r = await followRedirectChain('https://example.com/', { fetchImpl, dnsLookupImpl: PUBLIC_DNS });
  assert.ok(r.flags?.some((f) => f.title === 'HTTPS downgrade on redirect'), 'expected downgrade flag');
});

test('followRedirectChain: redirect loop → error', async () => {
  const fetchImpl = async (url: string) => response(302, { location: url });
  const r = await followRedirectChain('https://example.com/', { fetchImpl, dnsLookupImpl: PUBLIC_DNS });
  assert.equal(r.status, 'error');
  assert.match(r.note ?? '', /loop/i);
});

test('followRedirectChain: network failure → error', async () => {
  const fetchImpl = async () => {
    throw new Error('ENETUNREACH');
  };
  const r = await followRedirectChain('https://example.com/', { fetchImpl, dnsLookupImpl: PUBLIC_DNS });
  assert.equal(r.status, 'error');
  assert.match(r.note ?? '', /ENETUNREACH/);
});

test('followRedirectChain: private-IP host → skipped, never fetched', async () => {
  let fetched = false;
  const dnsLookupImpl = async () => [{ address: '10.0.0.5' }];
  const r = await followRedirectChain('https://internal.example.com/', {
    fetchImpl: async () => {
      fetched = true;
      return response(200);
    },
    dnsLookupImpl,
  });
  assert.equal(r.status, 'skipped');
  assert.equal(fetched, false);
});

// ---------------------------------------------------------------------------
// Reputation provider unit tests (fake fetch)
// ---------------------------------------------------------------------------

test('urlhausProvider: no_results for URL and host → clean', async () => {
  await withUrlhausKey('fixture-key', async () => {
    const fetchImpl = async (url: string) => {
      if (String(url).includes('/v1/url/')) return response(200, { json: { query_status: 'no_results' } });
      return response(200, { json: { query_status: 'no_results' } });
    };
    const r = await urlhausProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl });
    assert.equal(r.status, 'clean');
  });
});

test('urlhausProvider: listed URL → malicious with details and reference', async () => {
  await withUrlhausKey('fixture-key', async () => {
    const fetchImpl = async () =>
      response(200, {
        json: {
          query_status: 'listed',
          urlhaus_reference: 'https://urlhaus.abuse.ch/url/abc/',
          urls: [{ url: 'https://example.com/', threat: 'malware_download', date_added: '2026-01-01' }],
        },
      });
    const r = await urlhausProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl });
    assert.equal(r.status, 'malicious');
    assert.equal(r.reference, 'https://urlhaus.abuse.ch/url/abc/');
    assert.equal(r.details?.[0].threat, 'malware_download');
  });
});

test('urlhausProvider: HTTP 429 (rate limit) → rate_limited', async () => {
  await withUrlhausKey('fixture-key', async () => {
    const fetchImpl = async () => response(429);
    const r = await urlhausProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl });
    assert.equal(r.status, 'rate_limited');
  });
});

test('urlhausProvider: timeout (AbortError) → timeout', async () => {
  await withUrlhausKey('fixture-key', async () => {
    const fetchImpl = async () => {
      const e = new Error('The operation was aborted');
      e.name = 'AbortError';
      throw e;
    };
    const r = await urlhausProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl });
    assert.equal(r.status, 'timeout');
  });
});

test('urlhausProvider: missing key → not_configured, note never leaks env names or setup instructions', async () => {
  await withUrlhausKey(undefined, async () => {
    const r = await urlhausProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl: async () => response(200) });
    assert.equal(r.status, 'not_configured');
    assert.ok(!/URLHAUS|Auth-Key|setup|sign up|auth\.abuse/i.test(r.note ?? ''), 'end-user note must not leak env var names or setup instructions');
  });
});

test('reputation aggregation: clean provider + malicious provider → malicious wins', async () => {
  const maliciousProvider: ReputationProvider = {
    id: 'fixture-malicious',
    label: 'Fixture malicious provider',
    isConfigured: () => true,
    lookup: async () => ({ status: 'malicious' as const, note: 'Listed (fixture).' }),
  };
  const r = await inspectUrl('https://evil.example/', baseDeps({ providers: [cleanProvider(), maliciousProvider] }));
  assert.equal(r.reputation.status, 'malicious');
  assert.equal(r.verdict, 'MALICIOUS');
});

// ---------------------------------------------------------------------------
// Google Safe Browsing provider
// ---------------------------------------------------------------------------

test('googleSafeBrowsingProvider: a threat match → malicious with the threat type', async () => {
  await withGsbKey('fixture-key', async () => {
    const fetchImpl = async () =>
      response(200, {
        json: {
          matches: [
            { threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: 'https://phish.example/' } },
          ],
        },
      });
    const r = await googleSafeBrowsingProvider.lookup({ url: 'https://phish.example/', host: 'phish.example' }, { fetchImpl });
    assert.equal(r.status, 'malicious');
    assert.equal(r.flaggedUrl, 'https://phish.example/');
    assert.ok(r.details?.some((d) => /phishing/i.test(d.threat)), 'expected a phishing threat label');
  });
});

test('googleSafeBrowsingProvider: no matches → clean', async () => {
  await withGsbKey('fixture-key', async () => {
    const fetchImpl = async () => response(200, { json: {} });
    const r = await googleSafeBrowsingProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl });
    assert.equal(r.status, 'clean');
  });
});

test('googleSafeBrowsingProvider: HTTP 429 → rate_limited, never clean', async () => {
  await withGsbKey('fixture-key', async () => {
    const fetchImpl = async () => response(429);
    const r = await googleSafeBrowsingProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl });
    assert.equal(r.status, 'rate_limited');
  });
});

test('googleSafeBrowsingProvider: missing key → not_configured, no env/setup leakage', async () => {
  await withGsbKey(undefined, async () => {
    const r = await googleSafeBrowsingProvider.lookup({ url: 'https://example.com/', host: 'example.com' }, { fetchImpl: async () => response(200) });
    assert.equal(r.status, 'not_configured');
    assert.ok(
      !/GOOGLE|SAFE_BROWSING|API[_ ]?KEY|setup|sign up/i.test(r.note ?? ''),
      'end-user note must not leak env var names or setup instructions'
    );
  });
});