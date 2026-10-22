# Demo guide

A 2-minute screen recording: Claude Code tries to refund a payment, EZ CHECK pauses it, you approve with
Touch ID, then deny a second one and Claude backs off.

## Setup (once, about 5 minutes)

```bash
gh repo clone infiniteezverse/ez-check && cd ez-check
npm install
npm run demo
```

`npm run demo`:

1. builds the SDK and creates an agent token (kept in `.ezcheck/agent-token`);
2. starts the approval server on http://localhost:4747 with a 5-minute approval window;
3. opens the register page the first time. Click **Create passkey** and use Touch ID;
4. adds `ez-check-stripe` and `ez-check-backup` to Claude Code (user scope) with your passkey pinned;
5. shows a live feed of every request and decision.

Leave it running. Re-running it later skips the steps that are already done. Use `--no-install` to print the
`claude mcp add` commands instead of running them, and `--no-open` to skip opening the browser.

Rehearse the whole flow once before recording.

## Recording layout

- **Left:** a terminal running `claude`.
- **Right:** the `npm run demo` terminal (live feed), with the browser approval page popping over it.

## Script

| Time | On screen | Say |
| --- | --- | --- |
| 0:00–0:15 | README "Why" section | "Agents can now refund payments and delete data. The usual safeguard is a 'yes' in chat, and a prompt injection can type that too." |
| 0:15–0:30 | `claude`: *Show me recent Stripe charges* | "Read-only tools run instantly. No friction." |
| 0:30–1:00 | *Refund $500 of the Team plan charge*, then the approval page: "Refund $500.00 on ch_mock_1002" + exact args. The feed shows ⏸ requested | "Refunds are high-risk. Claude is paused, and I see exactly what it wants to do." |
| 1:00–1:15 | **Approve with passkey**, Touch ID, Claude: "Refund succeeded". Feed shows ✓ approved | "One touch. The signature covers this exact refund: not $5,000, not another charge." |
| 1:15–1:35 | *Refund the $49 Pro plan charge too*, then **Deny**. Claude: "not approved, won't retry". Feed shows ✗ denied | "Deny, and the call never runs. Claude is told not to work around it." |
| 1:35–1:50 | [`examples/mcp-stripe-guard/src/main.ts`](../examples/mcp-stripe-guard/src/main.ts), the `riskTier: 'HIGH'` line | "Protecting a tool is one line." |
| 1:50–2:00 | README security model | "Even if our server is compromised, the agent verifies your passkey signature itself. Only you can approve." |

## Optional: real Stripe test mode

With a Stripe test key, refunds show up in your Stripe dashboard, which makes a convincing extra shot:

```bash
claude mcp remove ez-check-stripe --scope user
```

Then run `npm run demo -- --no-install` and add `-e STRIPE_SECRET_KEY=sk_test_…` to the printed
`ez-check-stripe` command before running it. Live keys are refused.

## Troubleshooting

- **No Touch ID prompt:** use Chrome or Safari, and open the page via `http://localhost:4747`, not `127.0.0.1`.
- **"Approval server exited":** something else is on port 4747. Stop it or run `PORT=4800 npm run demo`.
- **Start over:** stop the demo, delete `.ezcheck/`, and run `npm run demo` again.
