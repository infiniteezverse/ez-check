// The "agent" calls a tool. LOW risk runs now; HIGH risk comes back as an approval request whose
// WebAuthn challenge commits to the exact arguments, using the same SDK helpers as the MCP gate.
import { approvalChallenge, hashToolCall } from '@ezcheck/mcp-sdk';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { randomBytes } from 'node:crypto';
import { handler, HttpError, relyingParty, seal, TOOLS, unseal } from './_lib.mjs';

export const POST = handler(async ({ tool, args = {}, ticket }, request) => {
  const spec = TOOLS[tool];
  if (!spec) throw new HttpError(400, `Unknown tool: ${tool}`);
  if (spec.riskTier === 'LOW') return { status: 'ran', result: spec.run(args) };

  spec.validate(args);
  const credential = unseal(ticket, 'cred');
  const { rpID } = relyingParty(request);
  if (credential.rpID !== rpID) throw new HttpError(400, 'Passkey was created on another site. Create a new one.');

  const argsHash = hashToolCall(tool, args);
  const nonce = randomBytes(16).toString('base64url');
  const options = await generateAuthenticationOptions({
    rpID,
    challenge: Buffer.from(approvalChallenge(argsHash, nonce), 'base64url'),
    userVerification: 'required',
    allowCredentials: [{ id: credential.id }],
  });
  const summary = spec.describe(args);
  return {
    status: 'needs_approval',
    summary,
    args,
    argsHash,
    options,
    approval: seal({ kind: 'approval', tool, args, argsHash, nonce, summary }, 5 * 60_000),
  };
});
