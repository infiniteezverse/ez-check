import { ApprovalDeniedError, createEzCheck, HttpApprover } from '@ezcheck/mcp-sdk';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const token = process.env.EZCHECK_AGENT_TOKEN;
if (!token) {
  console.error('Set EZCHECK_AGENT_TOKEN to the token the approval server uses.');
  process.exit(1);
}

const ezCheck = createEzCheck({
  approver: new HttpApprover({
    baseUrl: process.env.EZCHECK_URL ?? 'http://localhost:4747',
    token,
    openInBrowser: process.env.EZCHECK_OPEN_BROWSER !== '0',
  }),
});

// Pretend backup storage, so the demo is safe to run.
const backups = new Map([
  ['orders-2026-10-20', '4.1 GB'],
  ['orders-2026-10-21', '4.2 GB'],
  ['orders-2026-10-22', '4.2 GB'],
]);

const text = (t: string) => ({ content: [{ type: 'text' as const, text: t }] });

const server = new McpServer({ name: 'ez-check-demo', version: '0.1.0' });

server.registerTool(
  'list_backups',
  { description: 'List database backups. Low risk: runs without approval.', inputSchema: {} },
  ezCheck.protect(async () => text([...backups].map(([name, size]) => `${name}  ${size}`).join('\n')), {
    name: 'list_backups',
    riskTier: 'LOW',
  }),
);

const deleteBackup = ezCheck.protect(
  async ({ name }: { name: string }) => {
    if (!backups.delete(name)) return text(`No backup named ${name}.`);
    return text(`Deleted ${name}.`);
  },
  { name: 'delete_backup', riskTier: 'HIGH', describe: ({ name }) => `Permanently delete backup ${name}` },
);

server.registerTool(
  'delete_backup',
  {
    description: 'Delete a database backup. High risk: the user must approve with their passkey first.',
    inputSchema: { name: z.string().describe('Backup name from list_backups') },
    annotations: { destructiveHint: true },
  },
  async (args) => {
    try {
      return await deleteBackup(args);
    } catch (err) {
      // Tell the agent plainly so it doesn't retry or work around the refusal.
      if (err instanceof ApprovalDeniedError) {
        return { ...text(`The user did not approve this (${err.status}). Do not retry unless they ask.`), isError: true };
      }
      throw err;
    }
  },
);

await server.connect(new StdioServerTransport());
