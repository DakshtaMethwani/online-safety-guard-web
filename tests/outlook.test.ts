/**
 * Outlook add-in tests: static /outlook headers, the limited OUTLOOK_ADDIN_KEY
 * (only on 3 routes, forcing provider "outlook"), INSPECTOR_KEY/Gmail unchanged,
 * and XSS-as-text in the dashboard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import express from 'express';

import { mountOutlook, parseUrl, getRegistrableDomain, type InspectDeps } from '../server';
import { createGatewayRouter, type GatewayOptions, type GatewayEngine } from '../gateway';
import { GatewayDb } from '../gateway-db';

process.env.INSPECTOR_KEY = 'inspector-full-key';
process.env.OUTLOOK_ADDIN_KEY = 'outlook-limited-key';
process.env.ADMIN_PASSWORD = 'admin-pass';
process.env.EVENT_SALT = 'test-salt';

const INSPECTOR = { authorization: 'Bearer inspector-full-key', 'content-type': 'application/json' };
const ADDIN = { authorization: 'Bearer outlook-limited-key', 'content-type': 'application/json' };
const BAD = { authorization: 'Bearer nope', 'content-type': 'application/json' };
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

async function listen(app: express.Express) {
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    close: async () => {
      server.close();
      server.closeAllConnections?.();
    },
  };
}

async function startGateway(opts: Partial<GatewayOptions> = {}) {
  const db = opts.db ?? new GatewayDb(':memory:');
  const app = express();
  app.use(createGatewayRouter({ engine: fakeEngine(), db, rateLimit: false, ...opts }));
  const srv = await listen(app);
  return {
    ...srv,
    db,
    close: async () => {
      await srv.close();
      db.close();
    },
  };
}

function eventBody(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    provider: 'outlook',
    mailbox: 'user@example.com',
    message_ref: 'ref-1',
    sender_domain: 'evil.top',
    sender_display: 'Evil <bad@evil.top>',
    subject: 'Account suspended',
    verdict: 'BLOCKED',
    action: 'none',
    link_count: 2,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// Static /outlook assets + headers
// ---------------------------------------------------------------------------

test('/outlook assets are served with add-in headers, and only /outlook gets them', async () => {
  const app = express();
  app.get('/plain', (_req, res) => { res.status(200).send('ok'); });
  mountOutlook(app);
  const srv = await listen(app);
  try {
    const page = await fetch(`${srv.base}/outlook/taskpane.html`);
    assert.equal(page.status, 200);
    const csp = page.headers.get('content-security-policy') || '';
    assert.match(csp, /frame-ancestors[^;]*https:\/\/outlook\.office\.com/);
    assert.match(csp, /frame-ancestors[^;]*https:\/\/outlook\.office365\.com/);
    assert.match(csp, /frame-ancestors[^;]*https:\/\/outlook\.live\.com/);
    assert.match(csp, /frame-ancestors[^;]*https:\/\/\*\.office\.com/);
    assert.match(csp, /script-src 'self' https:\/\/appsforoffice\.microsoft\.com/);
    assert.match(csp, /connect-src 'self'/);
    assert.match(csp, /object-src 'none'/);
    assert.match(csp, /base-uri 'self'/);
    assert.equal(page.headers.get('x-frame-options'), null, 'must not set X-Frame-Options DENY');
    assert.equal(page.headers.get('x-robots-tag'), 'noindex, nofollow');

    // taskpane.js / css / icons are served
    assert.equal((await fetch(`${srv.base}/outlook/taskpane.js`)).status, 200);
    assert.equal((await fetch(`${srv.base}/outlook/taskpane.css`)).status, 200);
    assert.equal((await fetch(`${srv.base}/outlook/commands.html`)).status, 200);
    assert.equal((await fetch(`${srv.base}/outlook/icon-16.png`)).status, 200);
    assert.equal((await fetch(`${srv.base}/outlook/icon-128.png`)).status, 200);

    // the manifest is never served
    assert.equal((await fetch(`${srv.base}/outlook/manifest.xml`)).status, 404);

    // other routes keep their normal headers
    const plain = await fetch(`${srv.base}/plain`);
    assert.equal(plain.status, 200);
    assert.equal(plain.headers.get('content-security-policy'), null);
  } finally {
    await srv.close();
  }
});

test('the task pane has no inline scripts or inline event handlers', async () => {
  const app = express();
  mountOutlook(app);
  const srv = await listen(app);
  try {
    for (const file of ['/outlook/taskpane.html', '/outlook/commands.html']) {
      const html = await (await fetch(`${srv.base}${file}`)).text();
      assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html), `${file}: no inline <script>`);
      assert.ok(!/\son(click|load|error|change)\s*=/i.test(html), `${file}: no inline handlers`);
    }
  } finally {
    await srv.close();
  }
});

// ---------------------------------------------------------------------------
// Auth scoping
// ---------------------------------------------------------------------------

test('OUTLOOK_ADDIN_KEY works on the 3 routes and nowhere else', async () => {
  const gw = await startGateway();
  try {
    // POST /api/inspect
    assert.equal((await fetch(`${gw.base}/api/inspect`, { method: 'POST', headers: ADDIN, body: JSON.stringify({ message_ref: 'a', urls: ['https://example.com'] }) })).status, 200);
    // GET /api/message/:ref/verdict (accepted; unknown ref ⇒ 404, not 401)
    assert.equal((await fetch(`${gw.base}/api/message/whatever/verdict`, { headers: ADDIN })).status, 404);
    // POST /api/events
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: ADDIN, body: eventBody() })).status, 200);

    // not accepted elsewhere
    assert.equal((await fetch(`${gw.base}/admin`, { headers: ADDIN })).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events/read`, { method: 'POST', headers: ADDIN, body: '{}' })).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'DELETE', headers: ADDIN })).status, 401);
  } finally {
    await gw.close();
  }
});

test('the add-in key forces provider "outlook"; INSPECTOR_KEY and Gmail flow still work', async () => {
  const gw = await startGateway();
  try {
    // add-in key + provider "gmail" → stored as outlook
    await fetch(`${gw.base}/api/events`, { method: 'POST', headers: ADDIN, body: eventBody({ message_ref: 'addin-1', provider: 'gmail' }) });
    // inspector key + provider gmail → unchanged
    await fetch(`${gw.base}/api/events`, { method: 'POST', headers: INSPECTOR, body: eventBody({ message_ref: 'gmail-1', provider: 'gmail' }) });

    const list = await (await fetch(`${gw.base}/api/events?limit=50`, { headers: ADMIN })).json();
    const addin = list.events.find((e: any) => e.messageRef === 'addin-1');
    const gmail = list.events.find((e: any) => e.messageRef === 'gmail-1');
    assert.equal(addin.provider, 'outlook', 'add-in key must force provider outlook');
    assert.equal(gmail.provider, 'gmail', 'INSPECTOR_KEY keeps the requested provider');

    // bad key rejected on all three
    assert.equal((await fetch(`${gw.base}/api/inspect`, { method: 'POST', headers: BAD, body: '{"message_ref":"x","urls":["https://e.com"]}' })).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: BAD, body: eventBody() })).status, 401);
  } finally {
    await gw.close();
  }
});

test('the add-in key is disabled when OUTLOOK_ADDIN_KEY is unset', async () => {
  const prev = process.env.OUTLOOK_ADDIN_KEY;
  process.env.OUTLOOK_ADDIN_KEY = '';
  const gw = await startGateway();
  try {
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: ADDIN, body: eventBody() })).status, 401);
    // INSPECTOR_KEY still works
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: INSPECTOR, body: eventBody({ message_ref: 'insp-2', provider: 'gmail' }) })).status, 200);
  } finally {
    process.env.OUTLOOK_ADDIN_KEY = prev;
    await gw.close();
  }
});

// ---------------------------------------------------------------------------
// XSS
// ---------------------------------------------------------------------------

test('an XSS payload in an Outlook subject renders as plain text in the dashboard', async () => {
  const gw = await startGateway();
  try {
    await fetch(`${gw.base}/api/events`, {
      method: 'POST',
      headers: ADDIN,
      body: eventBody({ message_ref: 'xss-1', subject: '<script>alert(1)</script>', sender_display: '<img src=x onerror=alert(1)>' }),
    });
    const html = await (await fetch(`${gw.base}/admin/mail`, { headers: ADMIN })).text();
    assert.ok(html.includes('&lt;script&gt;'), 'script tag must be escaped');
    assert.ok(!html.includes('<script>alert(1)'), 'raw script must not appear');
    assert.ok(html.includes('&lt;img'), 'img payload must be escaped');
  } finally {
    await gw.close();
  }
});
