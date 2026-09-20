/**
 * Tests for the redesigned admin UI and the viewer role.
 *
 * Network-free: in-memory SQLite + a fake inspection engine. Roles are enforced
 * server-side, so these requests exercise the real middleware.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import express from 'express';

import { parseUrl, getRegistrableDomain, type InspectDeps } from '../server';
import { createGatewayRouter, type GatewayOptions, type GatewayEngine } from '../gateway';
import { GatewayDb } from '../gateway-db';

process.env.INSPECTOR_KEY = 'test-key';
process.env.ADMIN_PASSWORD = 'admin-pass';
process.env.EVENT_SALT = 'test-salt';
process.env.VIEWER_PASSWORD = 'viewer-pass';

const BEARER = { authorization: 'Bearer test-key', 'content-type': 'application/json' };
const basic = (user: string, pass: string) => ({
  authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64'),
});
const ADMIN = basic('admin', 'admin-pass');
// A different username must still work (the username is ignored).
const ADMIN_ALT_USER = basic('dakshta', 'admin-pass');
const VIEWER = basic('viewer', 'viewer-pass');

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

async function startGateway(opts: Partial<GatewayOptions> = {}) {
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

function postEvent(gw: { base: string }, overrides: Record<string, unknown> = {}) {
  return fetch(`${gw.base}/api/events`, {
    method: 'POST',
    headers: BEARER,
    body: JSON.stringify({
      provider: 'gmail',
      message_ref: 'm1',
      mailbox: 'owner@example.com',
      sender_domain: 'evil.top',
      sender_display: 'Evil <bad@evil.top>',
      subject: 'Account suspended',
      verdict: 'BLOCKED',
      action: 'moved_to_spam',
      link_count: 2,
      ...overrides,
    }),
  });
}

// ---------------------------------------------------------------------------
// Existing admin login keeps working (unchanged credentials)
// ---------------------------------------------------------------------------

test('the existing admin login still works with the same username and password', async () => {
  const gw = await startGateway();
  try {
    const admin = await fetch(`${gw.base}/admin`, { headers: ADMIN });
    assert.equal(admin.status, 200);
    assert.match(await admin.text(), /Link gateway/);

    const mail = await fetch(`${gw.base}/admin/mail`, { headers: ADMIN });
    assert.equal(mail.status, 200);
    assert.match(await mail.text(), /sg-admin/);

    // Username is irrelevant — same password works with any username.
    const altUser = await fetch(`${gw.base}/admin`, { headers: ADMIN_ALT_USER });
    assert.equal(altUser.status, 200);
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Viewer role
// ---------------------------------------------------------------------------

test('a viewer can read the new UI and data, but gets 403 on every change', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw);

    // allowed reads
    assert.equal((await fetch(`${gw.base}/admin/mail`, { headers: VIEWER })).status, 200);
    assert.equal((await fetch(`${gw.base}/admin/admin.js`)).status, 200);
    assert.equal((await fetch(`${gw.base}/api/events`, { headers: VIEWER })).status, 200);
    assert.equal((await fetch(`${gw.base}/api/events/stats`, { headers: VIEWER })).status, 200);

    // forbidden: everything that mutates, plus Links and legacy
    assert.equal((await fetch(`${gw.base}/admin`, { headers: VIEWER })).status, 403);
    assert.equal((await fetch(`${gw.base}/admin/mail?legacy=1`, { headers: VIEWER })).status, 403);
    assert.equal((await fetch(`${gw.base}/api/events/read`, { method: 'POST', headers: { ...VIEWER, 'content-type': 'application/json' }, body: '{}' })).status, 403);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'DELETE', headers: VIEWER })).status, 403);
    assert.equal((await fetch(`${gw.base}/admin/mail/settings`, { method: 'POST', headers: VIEWER, body: 'store_subjects=on' })).status, 403);
    assert.equal((await fetch(`${gw.base}/admin/links/abc/override`, { method: 'POST', headers: VIEWER, body: 'status=SAFE' })).status, 403);
    assert.equal((await fetch(`${gw.base}/admin/blocklist`, { method: 'POST', headers: VIEWER, body: 'type=domain&value=x.com' })).status, 403);
    assert.equal((await fetch(`${gw.base}/admin/allowlist`, { method: 'POST', headers: VIEWER, body: 'domain=x.com' })).status, 403);
  } finally {
    await gw.close();
  }
});

test('the ingest route and its response shape are unchanged', async () => {
  const gw = await startGateway();
  try {
    const res = await postEvent(gw, { message_ref: 'shape-1' });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(typeof body.id, 'number');
    // GET /api/events still returns events for admin
    const list = await (await fetch(`${gw.base}/api/events`, { headers: ADMIN })).json();
    assert.equal(list.events.length, 1);
  } finally {
    await gw.close();
  }
});

test('viewer reads never expose mailbox prefixes', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw);
    const asAdmin = await (await fetch(`${gw.base}/api/events/stats`, { headers: ADMIN })).json();
    const asViewer = await (await fetch(`${gw.base}/api/events/stats`, { headers: VIEWER })).json();
    assert.ok(Array.isArray(asAdmin.accounts));
    assert.deepEqual(asViewer.accounts, []);
  } finally {
    await gw.close();
  }
});

test('viewer login is disabled when VIEWER_PASSWORD is unset, empty, or equals admin', async () => {
  const prev = process.env.VIEWER_PASSWORD;
  const gw = await startGateway();
  try {
    // empty
    process.env.VIEWER_PASSWORD = '';
    assert.equal((await fetch(`${gw.base}/api/events`, { headers: VIEWER })).status, 401);
    // equal to admin → resolves to admin (viewer stays disabled)
    process.env.VIEWER_PASSWORD = 'admin-pass';
    assert.equal((await fetch(`${gw.base}/admin`, { headers: ADMIN })).status, 200);
    assert.equal((await fetch(`${gw.base}/api/events`, { headers: basic('someone', 'admin-pass') })).status, 200);
    // unset
    delete process.env.VIEWER_PASSWORD;
    assert.equal((await fetch(`${gw.base}/api/events`, { headers: VIEWER })).status, 401);
  } finally {
    process.env.VIEWER_PASSWORD = prev;
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// Legacy page stays reachable for admin
// ---------------------------------------------------------------------------

test('?legacy=1 still opens the previous page for admin', async () => {
  const gw = await startGateway();
  try {
    const legacy = await fetch(`${gw.base}/admin/mail?legacy=1`, { headers: ADMIN });
    assert.equal(legacy.status, 200);
    const html = await legacy.text();
    assert.match(html, /id="mail-app"/);
    assert.ok(!html.includes('id="sg-admin"'), 'legacy page must not be the new shell');
    // legacy script route unchanged
    assert.equal((await fetch(`${gw.base}/admin/mail.js`)).status, 200);
  } finally {
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// New page: structure + CSP compliance
// ---------------------------------------------------------------------------

test('the new admin page renders Overview with charts and no inline script', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw);
    const res = await fetch(`${gw.base}/admin/mail`, { headers: ADMIN });
    const html = await res.text();
    assert.equal(res.status, 200);
    assert.match(html, /id="sg-admin"/);
    assert.match(html, /<svg/); // server-rendered charts
    assert.match(html, /Messages per day/);
    assert.match(html, /Senders that need attention/);
    // external script only
    assert.match(html, /<script src="\/admin\/admin.js"/);
    assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html), 'no inline <script> allowed');
    assert.ok(!/\son(click|load|error|mouseover|change|submit)\s*=/i.test(html), 'no inline event handlers allowed');
    assert.ok(!/ style="/.test(html), 'no inline style attributes');
    // tabs
    assert.match(html, />Overview</);
    assert.match(html, />Mail activity/);
    assert.match(html, />Links</);
  } finally {
    await gw.close();
  }
});

test('the admin CSP is unchanged and blocks inline scripts', async () => {
  const gw = await startGateway();
  try {
    const res = await fetch(`${gw.base}/admin/mail`, { headers: ADMIN });
    const csp = res.headers.get('content-security-policy') || '';
    assert.match(csp, /script-src 'self'/);
    assert.ok(!/script-src[^;]*unsafe-inline/.test(csp));
  } finally {
    await gw.close();
  }
});

test('stats endpoint returns SQL-computed aggregates', async () => {
  const gw = await startGateway();
  try {
    await postEvent(gw, { message_ref: 's1', verdict: 'SAFE' });
    await postEvent(gw, { message_ref: 's2', verdict: 'BLOCKED' });
    await postEvent(gw, { message_ref: 's3', verdict: 'UNVERIFIED' });
    const res = await fetch(`${gw.base}/api/events/stats?days=7`, { headers: ADMIN });
    assert.equal(res.status, 200);
    const stats = await res.json();
    assert.equal(stats.days, 7);
    assert.equal(stats.totals.scanned, 3);
    assert.equal(stats.totals.safe, 1);
    assert.equal(stats.totals.blocked, 1);
    assert.equal(stats.totals.unverified, 1);
    // per-day series is filled for the whole window (days + 1 buckets)
    assert.equal(stats.perDay.length, 8);
    assert.ok(Array.isArray(stats.actions));
    assert.ok(Array.isArray(stats.topSenders));
    assert.equal(stats.latestAlerts.length, 2); // non-safe only
  } finally {
    await gw.close();
  }
});
