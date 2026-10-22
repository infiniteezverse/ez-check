import { describe, expect, it, vi } from 'vitest';
import {
  ApprovalDeniedError,
  canonicalJson,
  createEzCheck,
  hashToolCall,
  type ApprovalRequest,
  type Approver,
} from '../src/index.js';

function approverReturning(decide: (req: ApprovalRequest) => Awaited<ReturnType<Approver['requestApproval']>>) {
  return { requestApproval: vi.fn(async (req: ApprovalRequest) => decide(req)) };
}

describe('hashToolCall', () => {
  it('ignores object key order', () => {
    expect(hashToolCall('t', { a: 1, b: { c: 2, d: 3 } })).toBe(hashToolCall('t', { b: { d: 3, c: 2 }, a: 1 }));
  });

  it('changes with the tool name or any argument', () => {
    const base = hashToolCall('transfer', { amount: 10 });
    expect(hashToolCall('transfer', { amount: 11 })).not.toBe(base);
    expect(hashToolCall('refund', { amount: 10 })).not.toBe(base);
  });

  it('keeps array order significant', () => {
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });
});

describe('protect', () => {
  it('runs LOW tools without asking', async () => {
    const approver = approverReturning(() => ({ status: 'denied' }));
    const tool = createEzCheck({ approver }).protect(async (n: number) => n * 2, { name: 'double', riskTier: 'LOW' });

    await expect(tool(21)).resolves.toBe(42);
    expect(approver.requestApproval).not.toHaveBeenCalled();
  });

  it('runs HIGH tools once the matching hash is approved', async () => {
    const approver = approverReturning((req) => ({ status: 'approved', argsHash: req.argsHash }));
    const handler = vi.fn(async (args: { to: string; amount: number }) => `sent ${args.amount}`);
    const tool = createEzCheck({ approver }).protect(handler, {
      name: 'transfer',
      riskTier: 'HIGH',
      describe: (a) => `Send ${a.amount} to ${a.to}`,
    });

    await expect(tool({ to: 'acct-1', amount: 5 })).resolves.toBe('sent 5');
    expect(approver.requestApproval).toHaveBeenCalledWith({
      tool: 'transfer',
      args: { to: 'acct-1', amount: 5 },
      argsHash: hashToolCall('transfer', { to: 'acct-1', amount: 5 }),
      summary: 'Send 5 to acct-1',
    });
    expect(handler).toHaveBeenCalledOnce();
  });

  it.each(['denied', 'expired'] as const)('blocks HIGH tools when %s', async (status) => {
    const handler = vi.fn();
    const tool = createEzCheck({ approver: approverReturning(() => ({ status })) }).protect(handler, {
      name: 'wipe',
      riskTier: 'HIGH',
    });

    await expect(tool({})).rejects.toBeInstanceOf(ApprovalDeniedError);
    expect(handler).not.toHaveBeenCalled();
  });

  it('blocks when the approval was signed over different arguments', async () => {
    const handler = vi.fn();
    const approver = approverReturning(() => ({ status: 'approved', argsHash: hashToolCall('wipe', { db: 'test' }) }));
    const tool = createEzCheck({ approver }).protect(handler, { name: 'wipe', riskTier: 'HIGH' });

    await expect(tool({ db: 'prod' })).rejects.toMatchObject({ status: 'mismatch' });
    expect(handler).not.toHaveBeenCalled();
  });

  it('passes extra handler arguments through (MCP request context)', async () => {
    const approver = approverReturning((req) => ({ status: 'approved', argsHash: req.argsHash }));
    const tool = createEzCheck({ approver }).protect(async (_args: object, extra: { requestId: number }) => extra.requestId, {
      name: 'ctx',
      riskTier: 'HIGH',
    });

    await expect(tool({}, { requestId: 7 })).resolves.toBe(7);
  });
});
