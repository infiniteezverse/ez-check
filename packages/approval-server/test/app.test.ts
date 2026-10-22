import { mkdtempSync, rmSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEzCheck, hashToolCall, HttpApprover } from '@ezcheck/mcp-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import type { Config } from '../src/config.js';
import { Store } from '../src/store.js';

const TOKEN = 'test-token';
let base: string;
let store: Store;
let dataDir: string;
let close: () => void;

beforeEach(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'ezcheck-'));
  store = new Store(dataDir);
  const config: Config = {
    port: 0,
    host: '127.0.0.1',
    rpID: 'localhost',
    rpName: 'EZ CHECK test',
    origin: 'http://localhost:0',
    agentToken: TOKEN,
    dataDir,
    approvalTtlMs: 60_000,
  };
  const server = createApp(config, store).listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => server.close();
});

afterEach(() => {
  close();
  rmSync(dataDir, { recursive: true, force: true });
});

const agent = (path: string, init: RequestInit = {}) =>
  fetch(base + path, {
    ...init,
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', ...init.headers },
  });

const request = (tool: string, args: unknown) => ({
  tool,
  args,
  argsHash: hashToolCall(tool, args),
  summary: `${tool} test`,
});

describe('agent API', () => {
  it('rejects requests without the agent token', async () => {
    const res = await fetch(`${base}/api/approvals`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request('wipe', {})),
    });
    expect(res.status).toBe(401);
  });

  it('rejects a hash that does not match the arguments shown to the human', async () => {
    const res = await agent('/api/approvals', {
      method: 'POST',
      body: JSON.stringify({ ...request('wipe', { db: 'test' }), args: { db: 'prod' } }),
    });
    expect(res.status).toBe(400);
  });

  it('creates a pending approval with a page link', async () => {
    const res = await agent('/api/approvals', { method: 'POST', body: JSON.stringify(request('wipe', { db: 'test' })) });
    expect(res.status).toBe(201);
    const { id, url } = await res.json();
    expect(url).toBe(`http://localhost:0/approve/${id}`);

    const status = await (await agent(`/api/approvals/${id}`)).json();
    expect(status).toEqual({ status: 'pending' });
  });

  it('reports expiry once the TTL passes', async () => {
    const { id } = await (await agent('/api/approvals', { method: 'POST', body: JSON.stringify(request('wipe', {})) })).json();
    store.approvals.get(id)!.expiresAt = Date.now() - 1;
    expect(await (await agent(`/api/approvals/${id}`)).json()).toEqual({ status: 'expired' });
  });
});

describe('human side', () => {
  it('shows the exact arguments and lets the human deny without a passkey', async () => {
    const { id } = await (await agent('/api/approvals', { method: 'POST', body: JSON.stringify(request('wipe', { db: 'prod' })) })).json();

    const shown = await (await fetch(`${base}/webauthn/approvals/${id}`)).json();
    expect(shown).toMatchObject({ tool: 'wipe', args: { db: 'prod' }, status: 'pending' });

    const deny = await fetch(`${base}/webauthn/approvals/${id}/deny`, { method: 'POST' });
    expect(deny.status).toBe(200);
    expect(await (await agent(`/api/approvals/${id}`)).json()).toEqual({ status: 'denied' });

    // A decided request cannot be decided again.
    expect((await fetch(`${base}/webauthn/approvals/${id}/deny`, { method: 'POST' })).status).toBe(409);
  });

  it('will not issue an approval challenge before a passkey is registered', async () => {
    const { id } = await (await agent('/api/approvals', { method: 'POST', body: JSON.stringify(request('wipe', {})) })).json();
    const res = await fetch(`${base}/webauthn/approvals/${id}/options`, { method: 'POST' });
    expect(res.status).toBe(409);
  });
});

describe('end to end with the SDK', () => {
  it('blocks the protected tool when the human denies', async () => {
    let ran = false;
    const approver = new HttpApprover({
      baseUrl: base,
      token: TOKEN,
      pollIntervalMs: 20,
      // Play the human: deny as soon as the page link arrives.
      onPending: (url) => {
        const id = url.split('/').pop();
        void fetch(`${base}/webauthn/approvals/${id}/deny`, { method: 'POST' });
      },
    });
    const wipe = createEzCheck({ approver }).protect(
      async () => {
        ran = true;
      },
      { name: 'wipe', riskTier: 'HIGH' },
    );

    await expect(wipe({ db: 'prod' })).rejects.toMatchObject({ status: 'denied' });
    expect(ran).toBe(false);
  });
});
