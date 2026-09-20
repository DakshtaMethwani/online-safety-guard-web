/**
 * Gmail add-on tests: the limited GMAIL_ADDIN_KEY (only on 3 routes, forcing
 * provider "gmail"), independence from OUTLOOK_ADDIN_KEY, and INSPECTOR_KEY
 * unaffected. Mirrors tests/outlook.test.ts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import express from 'express';

import { parseUrl, getRegistrableDomain, type InspectDeps } from '../server';
import { createGatewayRouter, type GatewayOptions, type GatewayEngine } from '../gateway';
import { GatewayDb } from '../gateway-db';

process.env.INSPECTOR_KEY = 'inspector-full-key';
process.env.OUTLOOK_ADDIN_KEY = 'outlook-limited-key';
process.env.GMAIL_ADDIN_KEY = 'gmail-limited-key';
process.env.ADMIN_PASSWORD = 'admin-pass';
process.env.EVENT_SALT = 'test-salt';

const INSPECTOR = { authorization: 'Bearer inspector-full-key', 'content-type': 'application/json' };
const GMAIL = { authorization: 'Bearer gmail-limited-key', 'content-type': 'application/json' };
const OUTLOOK = { authorization: 'Bearer outlook-limited-key', 'content-type': 'application/json' };
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
    provider: 'gmail',
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

test('GMAIL_ADDIN_KEY works on the 3 routes and nowhere else', async () => {
  const gw = await startGateway();
  try {
    assert.equal((await fetch(`${gw.base}/api/inspect`, { method: 'POST', headers: GMAIL, body: JSON.stringify({ message_ref: 'a', urls: ['https://example.com'] }) })).status, 200);
    assert.equal((await fetch(`${gw.base}/api/message/whatever/verdict`, { headers: GMAIL })).status, 404);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: GMAIL, body: eventBody() })).status, 200);

    assert.equal((await fetch(`${gw.base}/admin`, { headers: GMAIL })).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events/read`, { method: 'POST', headers: GMAIL, body: '{}' })).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'DELETE', headers: GMAIL })).status, 401);
  } finally {
    await gw.close();
  }
});

test('the Gmail key forces provider "gmail"; the Outlook key and INSPECTOR_KEY are unaffected', async () => {
  const gw = await startGateway();
  try {
    // gmail key + provider "outlook" in the body → stored as gmail anyway
    await fetch(`${gw.base}/api/events`, { method: 'POST', headers: GMAIL, body: eventBody({ message_ref: 'gmail-1', provider: 'outlook' }) });
    // outlook key still forces "outlook" regardless of the gmail key existing
    await fetch(`${gw.base}/api/events`, { method: 'POST', headers: OUTLOOK, body: eventBody({ message_ref: 'outlook-1', provider: 'gmail' }) });
    // inspector key keeps whatever the body says
    await fetch(`${gw.base}/api/events`, { method: 'POST', headers: INSPECTOR, body: eventBody({ message_ref: 'insp-1', provider: 'outlook' }) });

    const list = await (await fetch(`${gw.base}/api/events?limit=50`, { headers: ADMIN })).json();
    const gmail = list.events.find((e: any) => e.messageRef === 'gmail-1');
    const outlook = list.events.find((e: any) => e.messageRef === 'outlook-1');
    const insp = list.events.find((e: any) => e.messageRef === 'insp-1');
    assert.equal(gmail.provider, 'gmail', 'gmail key must force provider gmail');
    assert.equal(outlook.provider, 'outlook', 'outlook key must force provider outlook');
    assert.equal(insp.provider, 'outlook', 'INSPECTOR_KEY keeps the requested provider');

    assert.equal((await fetch(`${gw.base}/api/inspect`, { method: 'POST', headers: BAD, body: '{"message_ref":"x","urls":["https://e.com"]}' })).status, 401);
  } finally {
    await gw.close();
  }
});

test('the Gmail key is disabled when GMAIL_ADDIN_KEY is unset, without affecting the other keys', async () => {
  const prev = process.env.GMAIL_ADDIN_KEY;
  process.env.GMAIL_ADDIN_KEY = '';
  const gw = await startGateway();
  try {
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: GMAIL, body: eventBody() })).status, 401);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: OUTLOOK, body: eventBody({ message_ref: 'still-works' }) })).status, 200);
    assert.equal((await fetch(`${gw.base}/api/events`, { method: 'POST', headers: INSPECTOR, body: eventBody({ message_ref: 'insp-2' }) })).status, 200);
  } finally {
    process.env.GMAIL_ADDIN_KEY = prev;
    await gw.close();
  }
});
