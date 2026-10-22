import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEzCheck, hashToolCall, HttpApprover } from '@ezcheck/mcp-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { approvalChallenge, createApp } from '../src/app.js';
import type { Config } from '../src/config.js';
import { Store } from '../src/store.js';
import { SoftAuthenticator } from './soft-authenticator.js';

const TOKEN = 'test-token';
const ORIGIN = 'http://localhost:4747';
let base: string;
let store: Store;
let dataDir: string;
let close: () => void;
let device: SoftAuthenticator;

beforeEach(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'ezcheck-'));
  store = new Store(dataDir);
  const config: Config = {
    port: 0,
    host: '127.0.0.1',
    rpID: 'localhost',
    rpName: 'EZ CHECK test',
    origin: ORIGIN,
    agentToken: TOKEN,
    dataDir,
    approvalTtlMs: 60_000,
  };
  const server = createApp(config, store).listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => server.close();
  device = new SoftAuthenticator('localhost', ORIGIN);
});

afterEach(() => {
  close();
  rmSync(dataDir, { recursive: true, force: true });
});

const post = async (path: string, body?: unknown) => {
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  return { status: res.status, body: await res.json() };
};

const register = async () => {
  const options = await post('/webauthn/register/options');
  return post('/webauthn/register/verify', device.register(options.body));
};

const createApproval = async (tool: string, args: unknown) => {
  const res = await fetch(`${base}/api/approvals`, {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tool, args, argsHash: hashToolCall(tool, args), summary: tool }),
  });
  return (await res.json()).id as string;
};

const status = async (id: string) =>
  (await fetch(`${base}/api/approvals/${id}`, { headers: { authorization: `Bearer ${TOKEN}` } })).json();

describe('passkey registration', () => {
  it('registers one passkey and refuses a second', async () => {
    expect(await register()).toEqual({ status: 200, body: { verified: true } });
    expect(store.findCredential(device.id)).toBeDefined();
    expect((await post('/webauthn/register/options')).status).toBe(409);
  });
});

describe('approving with a passkey', () => {
  beforeEach(async () => {
    await register();
  });

  it('approves when the passkey signs the challenge bound to the args', async () => {
    const args = { db: 'prod' };
    const id = await createApproval('wipe', args);
    const options = await post(`/webauthn/approvals/${id}/options`);

    const nonce = store.approvals.get(id)!.nonce!;
    expect(options.body.challenge).toBe(approvalChallenge(hashToolCall('wipe', args), nonce));
    expect(options.body.userVerification).toBe('required');

    expect(await post(`/webauthn/approvals/${id}/verify`, device.authenticate(options.body))).toEqual({
      status: 200,
      body: { status: 'approved' },
    });
    expect(await status(id)).toEqual({ status: 'approved', argsHash: hashToolCall('wipe', args) });

    const events = readFileSync(store.auditFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(events.at(-1)).toMatchObject({ event: 'approved', id, approvedBy: device.id });
  });

  it('rejects a signature made for a different approval', async () => {
    const harmless = await createApproval('list', {});
    const dangerous = await createApproval('wipe', { db: 'prod' });
    const harmlessOptions = await post(`/webauthn/approvals/${harmless}/options`);
    await post(`/webauthn/approvals/${dangerous}/options`);

    const replayed = await post(`/webauthn/approvals/${dangerous}/verify`, device.authenticate(harmlessOptions.body));
    expect(replayed.status).toBe(400);
    expect(await status(dangerous)).toEqual({ status: 'pending' });
  });

  it('rejects an assertion without user verification (no biometric/PIN)', async () => {
    const id = await createApproval('wipe', {});
    const options = await post(`/webauthn/approvals/${id}/options`);

    expect((await post(`/webauthn/approvals/${id}/verify`, device.authenticate(options.body, 0x01))).status).toBe(400);
    expect(await status(id)).toEqual({ status: 'pending' });
  });

  it('rejects an unregistered passkey', async () => {
    const id = await createApproval('wipe', {});
    const options = await post(`/webauthn/approvals/${id}/options`);
    const stranger = new SoftAuthenticator('localhost', ORIGIN);

    expect((await post(`/webauthn/approvals/${id}/verify`, stranger.authenticate(options.body))).status).toBe(400);
  });

  it('lets the SDK run the protected tool after a real passkey approval', async () => {
    let deleted = '';
    const approver = new HttpApprover({
      baseUrl: base,
      token: TOKEN,
      pollIntervalMs: 20,
      // Play the human: open the page, then approve with the passkey.
      onPending: async (url) => {
        const id = url.split('/').pop()!;
        const options = await post(`/webauthn/approvals/${id}/options`);
        await post(`/webauthn/approvals/${id}/verify`, device.authenticate(options.body));
      },
    });
    const deleteBackup = createEzCheck({ approver }).protect(
      async ({ name }: { name: string }) => {
        deleted = name;
        return 'ok';
      },
      { name: 'delete_backup', riskTier: 'HIGH' },
    );

    await expect(deleteBackup({ name: 'orders-2026-10-20' })).resolves.toBe('ok');
    expect(deleted).toBe('orders-2026-10-20');
  });
});
