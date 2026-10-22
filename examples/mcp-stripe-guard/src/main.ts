import { ApprovalDeniedError, createEzCheck, HttpApprover } from '@ezcheck/mcp-sdk';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { formatMoney, MockPayments, StripePayments, type Payments } from './stripe.js';

const token = process.env.EZCHECK_AGENT_TOKEN;
if (!token) {
  console.error('Set EZCHECK_AGENT_TOKEN to the token the approval server uses.');
  process.exit(1);
}

const payments: Payments = process.env.STRIPE_SECRET_KEY
  ? new StripePayments(process.env.STRIPE_SECRET_KEY)
  : new MockPayments();
console.error(`[stripe-guard] using ${payments.mode}`);

const ezCheck = createEzCheck({
  approver: new HttpApprover({
    baseUrl: process.env.EZCHECK_URL ?? 'http://localhost:4747',
    token,
    openInBrowser: process.env.EZCHECK_OPEN_BROWSER !== '0',
  }),
});

const text = (t: string) => ({ content: [{ type: 'text' as const, text: t }] });

const refundSchema = {
  charge: z.string().describe('Charge id, e.g. ch_…'),
  amount: z.number().int().positive().optional().describe('Amount in cents. Omit to refund the remaining balance.'),
  currency: z.string().length(3).describe('Currency of the charge, e.g. usd. Shown to the approver.'),
  reason: z.enum(['duplicate', 'fraudulent', 'requested_by_customer']).optional(),
};
type RefundArgs = { charge: string; amount?: number; currency: string; reason?: string };

const refund = ezCheck.protect(
  async ({ charge, amount, reason }: RefundArgs) => {
    const r = await payments.refund(charge, amount, reason);
    return text(`Refund ${r.id}: ${formatMoney(r.amount, r.currency)} on ${r.charge} (${r.status}).`);
  },
  {
    name: 'refund_charge',
    riskTier: 'HIGH',
    describe: ({ charge, amount, currency, reason }) =>
      `Refund ${amount === undefined ? 'the full remaining amount' : formatMoney(amount, currency)} on ${charge}` +
      (reason ? ` (${reason.replaceAll('_', ' ')})` : ''),
  },
);

const server = new McpServer({ name: 'ez-check-stripe-guard', version: '0.1.0' });

server.registerTool(
  'list_charges',
  {
    description: 'List recent Stripe charges. Read-only: runs without approval.',
    inputSchema: { limit: z.number().int().min(1).max(100).default(10) },
    annotations: { readOnlyHint: true },
  },
  ezCheck.protect(
    async ({ limit }: { limit: number }) => {
      const charges = await payments.listCharges(limit);
      if (!charges.length) return text('No charges.');
      return text(
        charges
          .map((c) => {
            const refunded = c.amount_refunded ? `, ${formatMoney(c.amount_refunded, c.currency)} refunded` : '';
            return `${c.id}  ${formatMoney(c.amount, c.currency)}${refunded}  ${c.description ?? ''}`;
          })
          .join('\n'),
      );
    },
    { name: 'list_charges', riskTier: 'LOW' },
  ),
);

server.registerTool(
  'refund_charge',
  {
    description: 'Refund a Stripe charge. Moves money: the user must approve with their passkey first.',
    inputSchema: refundSchema,
    annotations: { destructiveHint: true },
  },
  async (args) => {
    try {
      return await refund(args);
    } catch (err) {
      // Tell the agent plainly so it doesn't retry or work around the refusal.
      if (err instanceof ApprovalDeniedError) {
        return { ...text(`The user did not approve this refund (${err.status}). Do not retry unless they ask.`), isError: true };
      }
      return { ...text((err as Error).message), isError: true };
    }
  },
);

await server.connect(new StdioServerTransport());
