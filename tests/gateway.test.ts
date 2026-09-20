/**
 * Tests for the link-protection gateway (POST /api/inspect, GET /api/message/
 * :ref/verdict, GET /go/:id, /admin).
 *
 * Each group spins up an ephemeral Express server backed by an in-memory
 * SQLite database and a fake inspection engine, so nothing touches the network
 * or the real data/ directory.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import express from 'express';

import { parseUrl, getRegistrableDomain, type InspectDeps } from '../server';
import { createGatewayRouter, type GatewayOptions, type GatewayEngine } from '../gateway';
import { GatewayDb } from '../gateway-db';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

process.env.INSPECTOR_KEY = 'test-key';
process.env.ADMIN_PASSWORD = 'admin-pass';

interface EngineFixture {
  verdict: string;
  checks?: Array<{ id: string; label: string; status: string; detail?: string }>;
  findings?: Array<{ severity: string; title: string; explanation: string }>;
}

function makeEngine(
  fixtureFor: (url: string) => EngineFixture,
  opts: { onInspect?: (url: string) => void } = {}
): GatewayEngine {
  return {
    parseUrl,
    getRegistrableDomain,
    createDefaultInspectDeps: () => ({} as InspectDeps),
    async inspectUrl(raw: string, _deps?: InspectDeps) {
      opts.onInspect?.(raw);
      const f = fixtureFor(raw);
      const parsed = parseUrl(raw);
      return {
        domain: parsed.hostname,
        registrableDomain: parsed.registrableDomain,
        fullUrl: parsed.cleanUrl,
        verdict: f.verdict,
        verdictReason: `fixture: ${f.verdict}`,
        urlStructure: { status: 'valid', detail: 'parses cleanly' },
        spoofedBrand: null,
        officialDomain: null,
        reason: `fixture reason for ${raw}`,
        findings: f.findings ?? [],
        redirects: { status: 'none', hops: [], finalUrl: parsed.cleanUrl, method: 'GET', note: '' },
        reputation: { status: 'clean', source: 'fixture' },
        checks: f.checks ?? [{ id: 'fixture', label: 'Fixture check', status: 'passed', detail: 'ok' }],
        checksPerformed: ['Fixture check'],
        engine: 'test',
      };
    },
  };
}

const safeEngine = () => makeEngine(() => ({ verdict: 'LOW_RISK' }));

interface TestGateway {
  base: string;
  db: GatewayDb;
  close: () => Promise<void>;
}

async function startGateway(opts?: Partial<GatewayOptions>): Promise<TestGateway> {
  const db = new GatewayDb(':memory:');
  const app = express();
  app.use(
    createGatewayRouter({
      engine: safeEngine(),
      db,
      rateLimit: false,
      ...opts,
    })
  );
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${port}`;
  return {
    base,
    db,
    close: async () => {
      server.close();
      server.closeAllConnections?.();
      db.close();
    },
  };
}

const AUTH = { authorization: 'Bearer test-key', 'content-type': 'application/json' };

function postInspect(gw: TestGateway, messageRef: string, urls: string[]) {
  return fetch(`${gw.base}/api/inspect`, {
    method: 'POST',
    headers: AUTH,
    body: JSON.stringify({ message_ref: messageRef, urls }),
  });
}

async function fetchVerdict(gw: TestGateway, messageRef: string): Promise<any> {
  const res = await fetch(`${gw.base}/api/message/${messageRef}/verdict`);
  assert.equal(res.status, 200, `verdict fetch for ${messageRef} should be 200`);
  return res.json();
}

async function waitForVerdict(gw: TestGateway, ref: string, expected: string, timeoutMs = 4000) {
  const start = Date.now();
  for (;;) {
    const v = await fetchVerdict(gw, ref);
    if (v.verdict === expected) return v;
    if (Date.now() - start > timeoutMs) {
      assert.fail(`verdict for ${ref} did not become ${expected} (last: ${v.verdict})`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}

const ADMIN = {
  authorization: 'Basic ' + Buffer.from('admin:admin-pass').toString('base64'),
};

function adminPost(gw: TestGateway, path: string, body: string) {
  return fetch(`${gw.base}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { authorization: ADMIN.authorization, 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
}

// ---------------------------------------------------------------------------
// POST /api/inspect
// ---------------------------------------------------------------------------

test('POST /api/inspect rejects requests without a bearer key', async () => {
  const gw = await startGateway();
  try {
    const res = await fetch(`${gw.base}/api/inspect`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message_ref: 'x', urls: ['https://example.com'] }),
    });
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: 'unauthorized' });
  } finally {
    await gw.close();
  }
});

test('POST /api/inspect ingests links as PENDING and reports SAFE after inspection', async () => {
  const gw = await startGateway();
  try {
    const res = await postInspect(gw, 'm-ingest', ['https://example.com/page', 'https://example.org']);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.verdict, 'PENDING');
    assert.equal(body.links.length, 2);
    for (const link of body.links) {
      // 128-bit, URL-safe id
      assert.match(link.id, /^[A-Za-z0-9_-]{22}$/);
      assert.equal(link.status, 'PENDING');
      assert.ok(link.gateway_url.endsWith(`/go/${link.id}`));
    }

    const v = await waitForVerdict(gw, 'm-ingest', 'SAFE');
    assert.ok(v.links.every((l: any) => l.status === 'SAFE'));
    assert.ok(v.links.every((l: any) => l.inspected_at !== null));
  } finally {
    await gw.close();
  }
});

test('POST /api/inspect normalizes, dedupes and caps at 20 URLs', async () => {
  const gw = await startGateway();
  try {
    // duplicate normalized URL (whitespace variant) → single link
    const res = await postInspect(gw, 'm-dedupe', [' https://example.com/a ', 'https://example.com/a']);
    const body = await res.json();
    assert.equal(body.links.length, 1);
    assert.equal(body.links[0].url, 'https://example.com/a');

    // more than 20 → 400
    const tooMany = await postInspect(gw, 'm-many', Array.from({ length: 21 }, (_, i) => `https://x${i}.example`));
    assert.equal(tooMany.status, 400);

    // non-string entry → 400
    const badType = await postInspect(gw, 'm-bad', ['https://example.com', 42 as any]);
    assert.equal(badType.status, 400);
  } finally {
    await gw.close();
  }
});

test('POST /api/inspect blocks non-web schemes instantly without queuing', async () => {
  const gw = await startGateway();
  try {
    const res = await postInspect(gw, 'm-scheme', ['javascript:alert(1)', 'https://example.com']);
    const body = await res.json();
    const js = body.links.find((l: any) => l.url.startsWith('javascript:'));
    assert.equal(js.status, 'BLOCKED');

    // overall verdict: BLOCKED wins over any PENDING links
    assert.equal(body.verdict, 'BLOCKED');

    // the go page for it is a block page
    const page = await fetch(`${gw.base}/go/${js.id}`);
    assert.equal(page.status, 200);
    assert.ok((await page.text()).includes('This link is blocked'));
  } finally {
    await gw.close();
  }
});

test('POST /api/inspect requires validation of message_ref and urls', async () => {
  const gw = await startGateway();
  try {
    const noRef = await postInspect(gw, '', ['https://example.com']);
    assert.equal(noRef.status, 400);
    assert.deepEqual(await noRef.json(), { error: 'message_ref (string) is required' });

    const noUrls = await postInspect(gw, 'm', []);
    assert.equal(noUrls.status, 400);
    assert.deepEqual(await noUrls.json(), { error: 'urls must be a non-empty array of strings' });
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Verdict aggregation / status mapping
// ---------------------------------------------------------------------------

test('a malicious verdict blocks the link and auto-adds its domain to the blocklist', async () => {
  const gw = await startGateway({
    engine: makeEngine((url) =>
      url.includes('evil')
        ? { verdict: 'HIGH_RISK', findings: [{ severity: 'critical', title: 'Evil domain', explanation: 'test' }] }
        : { verdict: 'LOW_RISK' }
    ),
  });
  try {
    const res = await postInspect(gw, 'm-evil', ['https://good.example', 'https://shop.evil.com/x']);
    assert.equal((await res.json()).verdict, 'PENDING');

    const v = await waitForVerdict(gw, 'm-evil', 'BLOCKED');
    const evil = v.links.find((l: any) => l.url.includes('evil'));
    assert.equal(evil.status, 'BLOCKED');
    assert.deepEqual(evil.findings.verdict, 'HIGH_RISK');

    // registrable domain was persisted to the blocklist
    assert.ok(gw.db.listBlocklist().some((b) => b.type === 'domain' && b.value === 'evil.com'));

    // subsequent links to that domain short-circuit (no engine call needed)
    let engineCalls = 0;
    const gw2 = await startGateway({
      db: gw.db,
      engine: makeEngine(
        () => ({ verdict: 'LOW_RISK' }),
        { onInspect: () => { engineCalls += 1; } }
      ),
    });
    try {
      const res2 = await postInspect(gw2, 'm-evil2', ['https://other.evil.com/path']);
      await waitForVerdict(gw2, 'm-evil2', 'BLOCKED', 4000);
      assert.equal(engineCalls, 0, 'blocklisted domain must not run the engine');
    } finally {
      await gw2.close();
    }
  } finally {
    await gw.close();
  }
});

test('SUSPICIOUS / UNVERIFIED verdicts map to UNVERIFIED; skipped checks never yield SAFE', async () => {
  const gw = await startGateway({
    engine: makeEngine((url) => {
      if (url.includes('skip')) {
        return {
          verdict: 'LOW_RISK', // even a clean verdict cannot win with a skipped check
          checks: [{ id: 'rep', label: 'Reputation', status: 'skipped', detail: 'not configured' }],
        };
      }
      return {
        verdict: 'UNVERIFIED',
        checks: [{ id: 'rep', label: 'Reputation', status: 'error', detail: 'timeout' }],
      };
    }),
  });
  try {
    await postInspect(gw, 'm-unv1', ['https://incomplete.example']);
    const v1 = await waitForVerdict(gw, 'm-unv1', 'UNVERIFIED');
    assert.equal(v1.links[0].findings.verdict, 'UNVERIFIED');

    await postInspect(gw, 'm-unv2', ['https://skip.example']);
    const v2 = await waitForVerdict(gw, 'm-unv2', 'UNVERIFIED');
    assert.equal(v2.links[0].findings.verdict, 'LOW_RISK');
    assert.ok(v2.links[0].findings.checks.some((c: any) => c.status === 'skipped'));
  } finally {
    await gw.close();
  }
});

test('a timed-out inspection becomes UNVERIFIED, never SAFE', async () => {
  const gw = await startGateway({
    inspectTimeoutMs: 50,
    engine: makeEngine(() => {
      throw new Error('boom'); // engine rejects → treated like a timeout wall
    }),
  });
  try {
    await postInspect(gw, 'm-fail', ['https://flaky.example']);
    const v = await waitForVerdict(gw, 'm-fail', 'UNVERIFIED');
    assert.equal(v.links[0].status, 'UNVERIFIED');
    assert.ok(String(v.links[0].findings.reason).includes('could not complete'));
  } finally {
    await gw.close();
  }
});

test('overall verdict: ANY blocked link wins; mixed sets are BLOCKED', async () => {
  const gw = await startGateway({
    engine: makeEngine((url) =>
      url.includes('evil') ? { verdict: 'HIGH_RISK' } : { verdict: 'LOW_RISK' }
    ),
  });
  try {
    await postInspect(gw, 'm-mix', ['https://safe.example', 'https://evil.example/x']);
    const v = await waitForVerdict(gw, 'm-mix', 'BLOCKED');
    assert.equal(v.verdict, 'BLOCKED');
  } finally {
    await gw.close();
  }
});

test('allowlisted domains become SAFE without running the engine', async () => {
  const now = new Date().toISOString();
  let engineCalls = 0;
  const gw = await startGateway({
    engine: makeEngine(
      () => ({ verdict: 'LOW_RISK' }),
      { onInspect: () => { engineCalls += 1; } }
    ),
  });
  try {
    gw.db.addAllowlist('trusted.example', now);
    await postInspect(gw, 'm-allow', ['https://shop.trusted.example/pay']);
    const v = await waitForVerdict(gw, 'm-allow', 'SAFE');
    assert.equal(engineCalls, 0, 'allowlist must bypass inspection');
    assert.ok(v.links[0].findings.findings.some((f: any) => f.title.includes('Allowlist')));
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// GET /go/:id
// ---------------------------------------------------------------------------

test('/go/:id redirects safe links with a 302 and anti-leak headers', async () => {
  const gw = await startGateway();
  try {
    await postInspect(gw, 'm-gosafe', ['https://example.com/hi?x=1']);
    const v = await waitForVerdict(gw, 'm-gosafe', 'SAFE');
    const id = v.links[0].id;

    const res = await fetch(`${gw.base}/go/${id}`, { redirect: 'manual' });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), 'https://example.com/hi?x=1');
    assert.equal(res.headers.get('x-robots-tag'), 'noindex, nofollow');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  } finally {
    await gw.close();
  }
});

test('/go/:id serves a pending page that auto-refreshes', async () => {
  const gw = await startGateway();
  try {
    const nowIso = new Date().toISOString();
    gw.db.createLink({
      id: 'pendingid00000000000000',
      url: 'https://example.com/slow',
      messageRef: 'm-pending',
      status: 'PENDING',
      findings: null,
      createdAt: nowIso,
      inspectedAt: null,
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    });
    const res = await fetch(`${gw.base}/go/pendingid00000000000000`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('Checking this link'));
    assert.ok(html.includes('http-equiv="refresh"'));
    assert.equal(res.headers.get('x-robots-tag'), 'noindex, nofollow');
  } finally {
    await gw.close();
  }
});

test('/go/:id block pages show the domain as plain text with no clickable link', async () => {
  const gw = await startGateway({
    engine: makeEngine(() => ({ verdict: 'HIGH_RISK' })),
  });
  try {
    await postInspect(gw, 'm-goblock', ['https://scam.evil.com/login']);
    const v = await waitForVerdict(gw, 'm-goblock', 'BLOCKED');
    const id = v.links[0].id;

    const res = await fetch(`${gw.base}/go/${id}`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('This link is blocked'));
    assert.ok(html.includes('scam.evil.com'));
    // the destination must never be a clickable anchor
    assert.ok(!/<a\s[^>]*href=/.test(html), 'block page must contain no anchor tags');
  } finally {
    await gw.close();
  }
});

test('/go/:id unverified pages show the destination and a continue-anyway action', async () => {
  const gw = await startGateway({
    engine: makeEngine((url) => ({
      verdict: 'SUSPICIOUS',
      findings: [{ severity: 'warning', title: 'Open redirect', explanation: 'test warning' }],
    })),
  });
  try {
    await postInspect(gw, 'm-gounv', ['https://example.com/?next=https%3A%2F%2Fevil.com']);
    const v = await waitForVerdict(gw, 'm-gounv', 'UNVERIFIED');
    const id = v.links[0].id;

    const res = await fetch(`${gw.base}/go/${id}`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('not verified'));
    assert.ok(html.includes('https://example.com/?next=https%3A%2F%2Fevil.com'));
    assert.ok(html.includes('Continue anyway'));
    assert.ok(html.includes('href="https://example.com/?next=https%3A%2F%2Fevil.com"'));
  } finally {
    await gw.close();
  }
});

test('/go/:id returns 404 for unknown and expired links', async () => {
  const gw = await startGateway();
  try {
    const unknown = await fetch(`${gw.base}/go/nope`);
    assert.equal(unknown.status, 404);

    gw.db.createLink({
      id: 'expiredlink0000000000',
      url: 'https://example.com/old',
      messageRef: 'm-old',
      status: 'SAFE',
      findings: null,
      createdAt: new Date(Date.now() - 40 * 86_400_000).toISOString(),
      inspectedAt: null,
      expiresAt: new Date(Date.now() - 10 * 86_400_000).toISOString(),
    });
    const expired = await fetch(`${gw.base}/go/expiredlink0000000000`, { redirect: 'manual' });
    assert.equal(expired.status, 404);
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

test('admin requires Basic auth and supports overrides, blocklist and allowlist edits', async () => {
  const gw = await startGateway();
  try {
    // 401 without credentials
    const noAuth = await fetch(`${gw.base}/admin`);
    assert.equal(noAuth.status, 401);

    // 200 with credentials
    const page = await fetch(`${gw.base}/admin`, { headers: ADMIN });
    assert.equal(page.status, 200);
    assert.ok((await page.text()).includes('Link gateway'));

    // override a link to BLOCKED
    await postInspect(gw, 'm-admin', ['https://x.example']);
    await waitForVerdict(gw, 'm-admin', 'SAFE');
    const link = (await fetchVerdict(gw, 'm-admin')).links[0];
    const ov = await adminPost(gw, `/admin/links/${link.id}/override`, 'status=BLOCKED');
    assert.equal(ov.status, 302);
    assert.equal((await fetchVerdict(gw, 'm-admin')).verdict, 'BLOCKED');

    // blocklist add + verify rows
    const addBl = await adminPost(gw, '/admin/blocklist', 'type=domain&value=bad.example&reason=manual');
    assert.equal(addBl.status, 302);
    assert.ok(gw.db.listBlocklist().some((b) => b.value === 'bad.example' && b.reason === 'manual'));

    // allowlist add + verify + delete
    const addAl = await adminPost(gw, '/admin/allowlist', 'domain=https://Trusted.Example/path');
    assert.equal(addAl.status, 302);
    assert.ok(gw.db.listAllowlist().some((a) => a.domain === 'trusted.example'));
    const row = gw.db.listAllowlist().find((a) => a.domain === 'trusted.example')!;
    await adminPost(gw, `/admin/allowlist/${row.id}/delete`, '');
    assert.ok(!gw.db.listAllowlist().some((a) => a.domain === 'trusted.example'));

    // invalid override status rejected
    const bad = await adminPost(gw, `/admin/links/${link.id}/override`, 'status=PENDING');
    assert.equal(bad.status, 400);
  } finally {
    await gw.close();
  }
});

test('admin endpoints are unavailable when ADMIN_PASSWORD is unset', async () => {
  const prev = process.env.ADMIN_PASSWORD;
  process.env.ADMIN_PASSWORD = '';
  const gw = await startGateway();
  try {
    const res = await fetch(`${gw.base}/admin`);
    assert.equal(res.status, 503);
  } finally {
    process.env.ADMIN_PASSWORD = prev;
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Polling endpoint
// ---------------------------------------------------------------------------

test('GET /api/message/:ref/verdict returns 404 for unknown message refs', async () => {
  const gw = await startGateway();
  try {
    const res = await fetch(`${gw.base}/api/message/does-not-exist/verdict`);
    assert.equal(res.status, 404);
  } finally {
    await gw.close();
  }
});