/**
 * Tests for the Mail Activity feature: ingest API, admin API, XSS escaping,
 * retention and polling. Uses an in-memory SQLite DB and a fake inspection
 * engine, so nothing touches the network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import crypto from 'node:crypto';
import express from 'express';

import { parseUrl, getRegistrableDomain, type InspectDeps } from '../server';
import { createGatewayRouter, type GatewayOptions, type GatewayEngine } from '../gateway';
import { GatewayDb } from '../gateway-db';

process.env.INSPECTOR_KEY = 'test-key';
process.env.ADMIN_PASSWORD = 'admin-pass';
process.env.EVENT_SALT = 'test-salt';

const AUTH = { authorization: 'Bearer test-key', 'content-type': 'application/json' };
const ADMIN = { authorization: 'Basic ' + Buffer.from('admin:admin-pass').toString('base64') };

function fakeEngine(): GatewayEngine {
  return {
    parseUrl,
    getRegistrableDomain,
    createDefaultInspectDeps: () => ({} as InspectDeps),
    async inspectUrl() {
      return {
        verdict: 'LOW_RISK',
        verdictReason: 'fixture',
        findings: [],
        checks: [{ id: 'fixture', label: 'Fixture', status: 'passed' }],
        redirects: { status: 'none', hops: [], finalUrl: null, note: '' },
        reputation: { status: 'clean', source: 'fixture' },
        engine: 'test',
      };
    },
  };
}

interface TestGateway {
  base: string;
  db: GatewayDb;
  close: () => Promise<void>;
}

async function startGateway(opts: Partial<GatewayOptions> = {}): Promise<TestGateway> {
  const db = opts.db ?? new GatewayDb(':memory:');
  const app = express();
  app.use(createGatewayRouter({ engine: fakeEngine(), db, rateLimit: false, ...opts }));
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    db,
    close: async () => {
      server.close();
      server.closeAllConnections?.();
      db.close();
    },
  };
}

function payload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    provider: 'gmail',
    message_ref: 'msg-1',
    mailbox: 'owner@example.com',
    sender_domain: 'evil.top',
    sender_display: 'Evil Sender <bad@evil.top>',
    subject: 'Your account will be suspended',
    verdict: 'BLOCKED',
    action: 'moved_to_spam',
    link_count: 2,
    ...overrides,
  };
}

function postEvent(gw: TestGateway, body: unknown, headers: Record<string, string> = AUTH) {
  return fetch(`${gw.base}/api/events`, { method: 'POST', headers, body: JSON.stringify(body) });
}

async function listEvents(gw: TestGateway, query = ''): Promise<any> {
  const res = await fetch(`${gw.base}/api/events${query}`, { headers: ADMIN });
  assert.equal(res.status, 200, `GET /api/events${query} should be 200`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

test('mail endpoints require auth', async () => {
  const gw = await startGateway();
  try {
    // ingest needs the Bearer key
    assert.equal((await postEvent(gw, payload(), { 'content-type': 'application/json' })).status, 401);
    // admin endpoints need Basic auth
    assert.equal((await fetch(`${gw.base}/api/events`)).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events/read`, { method: 'POST' })).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'DELETE' })).status, 401);
    assert.equal((await fetch(`${gw.base}/admin/mail`)).status, 401);
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Ingest: upsert, validation, hashing
// ---------------------------------------------------------------------------

test('a repeated event updates the row instead of duplicating it', async () => {
  const gw = await startGateway();
  try {
    const first = await postEvent(gw, payload());
    assert.equal(first.status, 200);
    const firstId = (await first.json()).id;

    const second = await postEvent(gw, payload({ verdict: 'UNVERIFIED', subject: 'Updated subject' }));
    assert.equal(second.status, 200);
    const secondId = (await second.json()).id;
    assert.equal(secondId, firstId, 'upsert must reuse the same row id');

    const data = await listEvents(gw);
    assert.equal(data.events.length, 1);
    assert.equal(data.events[0].verdict, 'UNVERIFIED');
    assert.equal(data.events[0].subject, 'Updated subject');
  } finally {
    await gw.close();
  }
});

test('oversize and unknown fields are rejected and nothing is stored', async () => {
  const gw = await startGateway();
  try {
    assert.equal((await postEvent(gw, payload({ subject: 'x'.repeat(201) }))).status, 400);
    assert.equal((await postEvent(gw, payload({ sender_display: 'x'.repeat(201) }))).status, 400);
    assert.equal((await postEvent(gw, payload({ message_ref: 'x'.repeat(129) }))).status, 400);
    assert.equal((await postEvent(gw, payload({ verdict: 'MAYBE' }))).status, 400);
    assert.equal((await postEvent(gw, payload({ provider: 'yahoo' }))).status, 400);
    assert.equal((await postEvent(gw, payload({ link_count: -1 }))).status, 400);
    assert.equal((await postEvent(gw, payload({ action: 'deleted' }))).status, 400);

    // Email bodies are not an accepted field — they must be rejected outright.
    assert.equal((await postEvent(gw, payload({ body: 'the full email text' }))).status, 400);
    assert.equal((await postEvent(gw, { ...payload(), snippet: 'x' })).status, 400);

    assert.equal((await postEvent(gw, payload({ bogus: 1 }))).status, 400);

    const data = await listEvents(gw);
    assert.equal(data.events.length, 0, 'rejected payloads must not be stored');
  } finally {
    await gw.close();
  }
});

test('account_hash is a salted SHA-256 of the mailbox (raw address never stored)', async () => {
  const gw = await startGateway();
  try {
    const res = await postEvent(gw, payload({ mailbox: 'Owner@Example.com' }));
    const { id } = await res.json();
    const stored = gw.db.getMailEvent(id);
    assert.ok(stored);
    const expected = crypto.createHash('sha256').update('owner@example.com:test-salt').digest('hex');
    assert.equal(stored!.accountHash, expected);
    // The raw mailbox must not appear anywhere in the stored row.
    assert.ok(!JSON.stringify(stored).includes('owner@example.com'));
  } finally {
    await gw.close();
  }
});

test('"Store subjects" off keeps only the sender domain', async () => {
  const gw = await startGateway();
  try {
    gw.db.setSetting('store_subjects', '0');
    const res = await postEvent(gw, payload({ sender_display: 'Evil <bad@evil.top>', subject: 'Secret subject' }));
    const { id } = await res.json();
    const stored = gw.db.getMailEvent(id);
    assert.equal(stored!.subject, null);
    assert.equal(stored!.senderDisplay, null);
    assert.equal(stored!.senderDomain, 'evil.top', 'sender domain is always kept');
  } finally {
    await gw.close();
  }
});

test('the ingest endpoint is rate limited like /api/inspect', async () => {
  const gw = await startGateway({ rateLimit: { inspectPerMinute: 2, verdictPerMinute: 60 } });
  try {
    assert.equal((await postEvent(gw, payload({ message_ref: 'r1' }))).status, 200);
    assert.equal((await postEvent(gw, payload({ message_ref: 'r2' }))).status, 200);
    assert.equal((await postEvent(gw, payload({ message_ref: 'r3' }))).status, 429);
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// XSS / escaping
// ---------------------------------------------------------------------------

test('an XSS payload in the subject and sender renders as plain text', async () => {
  const gw = await startGateway();
  try {
    await postEvent(
      gw,
      payload({
        subject: '<script>alert(1)</script>',
        sender_display: '<img src=x onerror=alert(1)>',
        message_ref: 'xss-1',
      })
    );
    const html = await (await fetch(`${gw.base}/admin/mail`, { headers: ADMIN })).text();
    assert.ok(html.includes('&lt;script&gt;'), 'script tag must be HTML-escaped');
    assert.ok(!html.includes('<script>alert(1)'), 'raw script payload must not appear');
    assert.ok(html.includes('&lt;img'), 'img payload must be HTML-escaped');
    assert.ok(!html.includes('<img src=x onerror='), 'raw img payload must not appear');
  } finally {
    await gw.close();
  }
});

test('admin pages set a CSP that blocks inline scripts', async () => {
  const gw = await startGateway();
  try {
    const res = await fetch(`${gw.base}/admin/mail`, { headers: ADMIN });
    const csp = res.headers.get('content-security-policy') || '';
    assert.match(csp, /script-src 'self'/);
    assert.ok(!/script-src[^;]*unsafe-inline/.test(csp), 'inline scripts must be blocked');
    assert.equal(res.headers.get('x-robots-tag'), 'noindex, nofollow');
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Listing: filters, pagination, since
// ---------------------------------------------------------------------------

test('?since returns only events newer than the given id', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw, payload({ message_ref: 'a' }));
    await postEvent(gw, payload({ message_ref: 'b' }));
    const before = await listEvents(gw);
    const maxId = Math.max(...before.events.map((e: any) => e.id));

    await postEvent(gw, payload({ message_ref: 'c' }));
    const delta = await listEvents(gw, `?since=${maxId}`);
    assert.equal(delta.events.length, 1);
    assert.equal(delta.events[0].messageRef, 'c');
    assert.ok(delta.events[0].id > maxId);
  } finally {
    await gw.close();
  }
});

test('filters and pagination work', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw, payload({ provider: 'gmail', message_ref: 'g1', verdict: 'SAFE', subject: 'Invoice' }));
    await postEvent(gw, payload({ provider: 'outlook', message_ref: 'o1', verdict: 'BLOCKED', subject: 'Password reset' }));
    await postEvent(gw, payload({ provider: 'outlook', message_ref: 'o2', verdict: 'BLOCKED', subject: 'Delivery fee' }));

    const blocked = await listEvents(gw, '?verdict=BLOCKED');
    assert.equal(blocked.total, 2);
    assert.ok(blocked.events.every((e: any) => e.verdict === 'BLOCKED'));

    const outlook = await listEvents(gw, '?provider=outlook');
    assert.equal(outlook.total, 2);
    assert.ok(outlook.events.every((e: any) => e.provider === 'outlook'));

    const search = await listEvents(gw, '?q=delivery');
    assert.equal(search.total, 1);
    assert.equal(search.events[0].messageRef, 'o2');

    const page = await listEvents(gw, '?limit=1&offset=1');
    assert.equal(page.events.length, 1);
    assert.equal(page.total, 3);
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Read / wipe
// ---------------------------------------------------------------------------

test('marking read updates the unread count and DELETE wipes everything', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw, payload({ message_ref: 'a' }));
    await postEvent(gw, payload({ message_ref: 'b' }));
    let data = await listEvents(gw);
    assert.equal(data.unread, 2);

    const readRes = await fetch(`${gw.base}/api/events/read`, {
      method: 'POST',
      headers: { ...ADMIN, 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(readRes.status, 200);
    data = await listEvents(gw);
    assert.equal(data.unread, 0);

    const del = await fetch(`${gw.base}/api/events`, { method: 'DELETE', headers: ADMIN });
    assert.equal(del.status, 200);
    assert.equal((await del.json()).deleted, 2);
    assert.equal((await listEvents(gw)).total, 0);
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

test('retention deletes events older than the window', async () => {
  const db = new GatewayDb(':memory:');
  const old = new Date(Date.now() - 40 * 86_400_000).toISOString();
  const fresh = new Date().toISOString();
  const base = {
    provider: 'gmail' as const,
    accountHash: 'h',
    senderDomain: null,
    senderDisplay: null,
    subject: null,
    verdict: 'SAFE' as const,
    action: 'none' as const,
    linkCount: 0,
    updatedAt: fresh,
  };
  db.upsertMailEvent({ ...base, messageRef: 'old', createdAt: old });
  db.upsertMailEvent({ ...base, messageRef: 'fresh', createdAt: fresh });

  // Creating the router runs the retention job immediately (default 30 days).
  createGatewayRouter({ engine: fakeEngine(), db, rateLimit: false });

  const remaining = db.listMailEvents();
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].messageRef, 'fresh');
  db.close();
});

// ---------------------------------------------------------------------------
// Public boundary
// ---------------------------------------------------------------------------

test('mail data is not exposed without admin auth', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw, payload());
    // No public endpoint returns mail data.
    assert.equal((await fetch(`${gw.base}/api/events`)).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events/read`, { method: 'POST' })).status, 401);
  } finally {
    await gw.close();
  }
});
