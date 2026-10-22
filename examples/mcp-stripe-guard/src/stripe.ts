export interface Charge {
  id: string;
  amount: number; // minor units
  amount_refunded: number;
  currency: string;
  description: string | null;
  created: number;
}

export interface Refund {
  id: string;
  charge: string;
  amount: number;
  currency: string;
  status: string;
}

export interface Payments {
  readonly mode: string;
  listCharges(limit: number): Promise<Charge[]>;
  refund(charge: string, amount?: number, reason?: string): Promise<Refund>;
}

/** Talks to the Stripe REST API. Only accepts test-mode keys: this is a demo. */
export class StripePayments implements Payments {
  readonly mode = 'Stripe test mode';

  constructor(private readonly key: string) {
    if (!key.startsWith('sk_test_') && !key.startsWith('rk_test_')) {
      throw new Error('This example only runs with a Stripe test-mode key (sk_test_… or rk_test_…).');
    }
  }

  async listCharges(limit: number): Promise<Charge[]> {
    return (await this.call<{ data: Charge[] }>('GET', `/v1/charges?limit=${limit}`)).data;
  }

  refund(charge: string, amount?: number, reason?: string): Promise<Refund> {
    const form = new URLSearchParams({ charge });
    if (amount !== undefined) form.set('amount', String(amount));
    if (reason) form.set('reason', reason);
    return this.call<Refund>('POST', '/v1/refunds', form);
  }

  private async call<T>(method: string, path: string, form?: URLSearchParams): Promise<T> {
    const res = await fetch(`https://api.stripe.com${path}`, {
      method,
      headers: { authorization: `Bearer ${this.key}` },
      body: form,
    });
    const body = await res.json();
    if (!res.ok) throw new Error(`Stripe: ${body?.error?.message ?? res.statusText}`);
    return body as T;
  }
}

/** In-memory stand-in so the demo runs with no Stripe account. */
export class MockPayments implements Payments {
  readonly mode = 'mock data (set STRIPE_SECRET_KEY=sk_test_… to use Stripe test mode)';
  private refunds = 0;
  private readonly charges: Charge[] = [
    { id: 'ch_mock_1001', amount: 4900, amount_refunded: 0, currency: 'usd', description: 'Pro plan, monthly', created: 1792540800 },
    { id: 'ch_mock_1002', amount: 129900, amount_refunded: 0, currency: 'usd', description: 'Team plan, annual', created: 1792627200 },
    { id: 'ch_mock_1003', amount: 1500, amount_refunded: 0, currency: 'usd', description: 'Add-on seats', created: 1792713600 },
  ];

  async listCharges(limit: number): Promise<Charge[]> {
    return this.charges.slice(0, limit);
  }

  async refund(chargeId: string, amount?: number): Promise<Refund> {
    const charge = this.charges.find((c) => c.id === chargeId);
    if (!charge) throw new Error(`No such charge: ${chargeId}`);
    const refundable = charge.amount - charge.amount_refunded;
    const value = amount ?? refundable;
    if (value <= 0 || value > refundable) throw new Error(`Can refund at most ${refundable} on ${chargeId}`);
    charge.amount_refunded += value;
    return { id: `re_mock_${++this.refunds}`, charge: chargeId, amount: value, currency: charge.currency, status: 'succeeded' };
  }
}

export function formatMoney(minor: number, currency: string): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: currency.toUpperCase() }).format(minor / 100);
}
