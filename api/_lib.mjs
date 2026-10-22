// Shared code for the hosted judge demo (Vercel functions).
//
// The demo is stateless so it runs on serverless without a database: every piece of state the server
// needs later (registration challenge, the visitor's passkey, a pending approval) round-trips through
// the browser inside an HMAC-signed token. Each visitor gets their own passkey; nothing is stored.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const secret = () => {
  const s = process.env.EZCHECK_DEMO_SECRET;
  if (!s) throw new Error('EZCHECK_DEMO_SECRET is not set');
  return s;
};

export function seal(payload, ttlMs) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlMs })).toString('base64url');
  return `${body}.${createHmac('sha256', secret()).update(body).digest('base64url')}`;
}

export function unseal(token, kind) {
  const [body, mac] = String(token ?? '').split('.');
  if (!body || !mac) throw new HttpError(400, 'Malformed token');
  const expected = createHmac('sha256', secret()).update(body).digest();
  const given = Buffer.from(mac, 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new HttpError(400, 'Invalid token');
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (payload.kind !== kind) throw new HttpError(400, 'Wrong token type');
  if (Date.now() > payload.exp) throw new HttpError(410, 'Expired. Start again.');
  return payload;
}

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** Relying party = the host serving the page, so the same code works on *.vercel.app and a custom domain. */
export function relyingParty(request) {
  const url = new URL(request.url);
  const host = request.headers.get('x-forwarded-host') ?? url.host;
  const proto = request.headers.get('x-forwarded-proto') ?? url.protocol.replace(':', '');
  const rpID = host.split(':')[0];
  return { rpID, origin: `${proto}://${host}` };
}

/** Wraps a handler: parses JSON, maps HttpError to a status code, never leaks stack traces. */
export function handler(fn) {
  return async (request) => {
    try {
      const body = request.method === 'POST' ? await request.json().catch(() => ({})) : {};
      return Response.json(await fn(body, request));
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(err);
      return Response.json({ error: status === 500 ? 'Server error' : err.message }, { status });
    }
  };
}

export const newId = (prefix) => `${prefix}_${randomBytes(6).toString('hex')}`;

// ---------- The pretend agent's tools ----------

export const CHARGES = [
  { id: 'ch_demo_1001', amount: 4900, currency: 'usd', description: 'Pro plan, monthly' },
  { id: 'ch_demo_1002', amount: 129900, currency: 'usd', description: 'Team plan, annual' },
  { id: 'ch_demo_1003', amount: 1500, currency: 'usd', description: 'Add-on seats' },
];

export const money = (minor, currency = 'usd') =>
  new Intl.NumberFormat('en-US', { style: 'currency', currency: currency.toUpperCase() }).format(minor / 100);

export const TOOLS = {
  list_charges: {
    riskTier: 'LOW',
    run: () => ({ charges: CHARGES }),
  },
  refund_charge: {
    riskTier: 'HIGH',
    describe: ({ charge, amount }) => `Refund ${money(amount)} on ${charge}`,
    validate: ({ charge, amount }) => {
      const c = CHARGES.find((x) => x.id === charge);
      if (!c) throw new HttpError(400, `No such charge: ${charge}`);
      if (!Number.isInteger(amount) || amount <= 0) throw new HttpError(400, 'Amount must be a positive whole number of cents');
    },
    run: ({ charge, amount }) => ({ refund: { id: newId('re_demo'), charge, amount, currency: 'usd', status: 'succeeded' } }),
  },
};
