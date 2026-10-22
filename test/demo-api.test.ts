// Drives the hosted demo's Vercel functions directly with a software passkey.
import { beforeAll, describe, expect, it } from 'vitest';
import { SoftAuthenticator } from '../packages/approval-server/test/soft-authenticator.js';

process.env.EZCHECK_DEMO_SECRET = 'test-secret';
const ORIGIN = 'https://ez-check.example';

const routes = {
  'register-options': (await import('../api/register-options.mjs')).POST,
  'register-verify': (await import('../api/register-verify.mjs')).POST,
  action: (await import('../api/action.mjs')).POST,
  approve: (await import('../api/approve.mjs')).POST,
};

async function call(route: keyof typeof routes, body: unknown = {}, origin = ORIGIN) {
  const res = await routes[route](
    new Request(`${origin}/api/${route}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
  return { status: res.status, body: await res.json() };
}

const device = new SoftAuthenticator('ez-check.example', ORIGIN);
let ticket: string;

beforeAll(async () => {
  const { body } = await call('register-options');
  const verified = await call('register-verify', { response: device.register(body.options), token: body.token });
  expect(verified.status).toBe(200);
  ticket = verified.body.ticket;
});

const refund = { charge: 'ch_demo_1002', amount: 50000 };

describe('hosted demo API', () => {
  it('runs low-risk tools without approval', async () => {
    const { status, body } = await call('action', { tool: 'list_charges' });
    expect(status).toBe(200);
    expect(body.status).toBe('ran');
    expect(body.result.charges).toHaveLength(3);
  });

  it('pauses high-risk tools and runs them once the passkey signs', async () => {
    const pending = (await call('action', { tool: 'refund_charge', args: refund, ticket })).body;
    expect(pending).toMatchObject({ status: 'needs_approval', summary: 'Refund $500.00 on ch_demo_1002' });

    const { status, body } = await call('approve', {
      approval: pending.approval,
      ticket,
      response: device.authenticate(pending.options),
    });
    expect(status).toBe(200);
    expect(body.result.refund).toMatchObject({ charge: 'ch_demo_1002', amount: 50000, status: 'succeeded' });
  });

  it('blocks the bait and switch: a signature for $5 cannot run $5,000', async () => {
    const pending = (await call('action', { tool: 'refund_charge', args: { charge: 'ch_demo_1003', amount: 500 }, ticket })).body;
    const { status, body } = await call('approve', {
      approval: pending.approval,
      ticket,
      response: device.authenticate(pending.options),
      executeArgs: { charge: 'ch_demo_1003', amount: 500000 },
    });
    expect(status).toBe(403);
    expect(body.error).toMatch(/does not cover these arguments/);
  });

  it('requires user verification (biometric or PIN)', async () => {
    const pending = (await call('action', { tool: 'refund_charge', args: refund, ticket })).body;
    const { status } = await call('approve', {
      approval: pending.approval,
      ticket,
      response: device.authenticate(pending.options, 0x01),
    });
    expect(status).toBe(403);
  });

  it('rejects another passkey, a forged ticket and a forged approval', async () => {
    const pending = (await call('action', { tool: 'refund_charge', args: refund, ticket })).body;
    const stranger = new SoftAuthenticator('ez-check.example', ORIGIN);

    expect((await call('approve', { approval: pending.approval, ticket, response: stranger.authenticate(pending.options) })).status).toBe(403);

    const [body] = ticket.split('.');
    const forgedTicket = `${body}.${'A'.repeat(43)}`;
    expect((await call('approve', { approval: pending.approval, ticket: forgedTicket, response: device.authenticate(pending.options) })).status).toBe(400);

    const [, mac] = pending.approval.split('.');
    const tampered = JSON.parse(Buffer.from(pending.approval.split('.')[0], 'base64url').toString());
    tampered.args.amount = 500000;
    const forgedApproval = `${Buffer.from(JSON.stringify(tampered)).toString('base64url')}.${mac}`;
    expect((await call('approve', { approval: forgedApproval, ticket, response: device.authenticate(pending.options) })).status).toBe(400);
  });

  it('rejects a passkey ticket from another site', async () => {
    const { status, body } = await call('action', { tool: 'refund_charge', args: refund, ticket }, 'https://other.example');
    expect(status).toBe(400);
    expect(body.error).toMatch(/another site/);
  });

  it('validates tool arguments', async () => {
    const { status } = await call('action', { tool: 'refund_charge', args: { charge: 'ch_nope', amount: 1 }, ticket });
    expect(status).toBe(400);
  });
});
