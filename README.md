# EZ CHECK

Human sign-off for AI agents. When an agent calls a tool you've marked high-risk over MCP, EZ CHECK pauses
the call, shows you exactly what it's about to do, and runs it only after you approve with your device passkey
(Touch ID, Windows Hello, Android screen lock). Low-risk tools run with no prompt at all.

```
agent ──tool call──▶ MCP server ──protect()──▶ HIGH risk? ──no──▶ run
                                                   │
                                                  yes
                                                   ▼
                                    approval server (localhost)
                                    page shows tool + exact args
                                                   │
                                     you tap Touch ID / Hello
                                                   ▼
                          passkey signs sha256(args hash + nonce) ──▶ run
```

## Packages

| Package | What it is |
| --- | --- |
| [`@ezcheck/mcp-sdk`](packages/mcp-sdk) | `createEzCheck().protect(handler, { riskTier })` wraps any tool handler. `HttpApprover` talks to the approval server. |
| [`@ezcheck/approval-server`](packages/approval-server) | Local Express server: passkey registration, the approval page, WebAuthn verification (SimpleWebAuthn), audit log. |
| [`@ezcheck/example-mcp-server`](packages/example-mcp-server) | Demo MCP server to try the whole flow from Claude Code. |

## Quick start

```bash
npm install
npm run server
```

Open http://localhost:4747/register and create your passkey. The server prints an agent token on start; set
`EZCHECK_AGENT_TOKEN` to keep a fixed one.

Wrap a tool in your MCP server:

```ts
import { createEzCheck, HttpApprover } from '@ezcheck/mcp-sdk';

const ezCheck = createEzCheck({
  approver: new HttpApprover({
    baseUrl: 'http://localhost:4747',
    token: process.env.EZCHECK_AGENT_TOKEN!,
    openInBrowser: true, // pops the approval page so the passkey prompt is one click away
  }),
});

server.registerTool(
  'database_backup',
  { description: 'Back up a database', inputSchema: { database: z.string(), destination: z.string() } },
  ezCheck.protect(backupHandler, {
    name: 'database_backup',
    riskTier: 'HIGH',
    describe: (a) => `Back up ${a.database} to ${a.destination}`,
  }),
);
```

If the human denies, doesn't answer within the TTL (2 minutes by default), or approves different arguments,
the wrapped call throws `ApprovalDeniedError` and the handler never runs.

## Try it with Claude Code

[`packages/example-mcp-server`](packages/example-mcp-server/src/main.ts) is a demo MCP server with two tools on
pretend data: `list_backups` (low risk, runs immediately) and `delete_backup` (high risk, needs your passkey).

```bash
export EZCHECK_AGENT_TOKEN=$(openssl rand -base64 24)
npm run build -w @ezcheck/mcp-sdk
npm run server
```

In another terminal, from the repo root:

```bash
claude mcp add ez-check-demo -e EZCHECK_AGENT_TOKEN=$EZCHECK_AGENT_TOKEN -- npx tsx "$PWD/packages/example-mcp-server/src/main.ts"
```

Then ask Claude to "delete the oldest backup." The approval page opens in your browser; approve with Touch ID
and it's deleted, or deny and Claude is told no.

## Audit log

Every request and decision (`requested`, `approved`, `denied`, `expired`) is appended to
`$EZCHECK_DATA_DIR/audit.jsonl` with the tool, summary, exact args, args hash and, for approvals, the passkey
credential id that signed. The file is created `0600`.

## Security model

- **The approval is bound to the exact call.** The SDK hashes the tool name plus canonical JSON args. The server
  recomputes that hash from the args it displays, rejects any mismatch, and makes the WebAuthn challenge
  `sha256("ezcheck:v1:" + argsHash + ":" + nonce)`. The passkey signature therefore covers what you saw.
- **User verification is required.** Registration and approval both demand biometric/PIN verification, not just presence.
- **No silent fallback.** A high-risk call that isn't approved does not run. There is deliberately no option to skip.
- **Loopback only by default.** The server binds `127.0.0.1`, so pending requests (which include tool arguments)
  aren't visible to the network. Agent endpoints need the bearer token; denying never needs a passkey.

## Configuration (approval server)

| Env var | Default |
| --- | --- |
| `PORT` | `4747` |
| `EZCHECK_HOST` | `127.0.0.1` |
| `EZCHECK_RP_ID` | `localhost` |
| `EZCHECK_ORIGIN` | `http://<rp id>:<port>` |
| `EZCHECK_AGENT_TOKEN` | random per run |
| `EZCHECK_DATA_DIR` | `.ezcheck` (holds the registered public key) |
| `EZCHECK_APPROVAL_TTL_MS` | `120000` |

## Development

```bash
npm run typecheck
npm test
```

## Status and next steps

v0.1, single user, local machine. Not yet built:

- Approval from a phone (needs the server on a real HTTPS origin so the phone's passkey can be used).
- Native notifications instead of opening a browser tab.
- The SDK verifying the signed assertion itself instead of trusting the local server.
- Web surface: see [docs/web-surface.md](docs/web-surface.md).
