// Runs a HIGH-risk tool only if the visitor's passkey signed these exact arguments.
//
// `executeArgs` is what the agent is about to run. Normally it equals what was approved; the demo's
// "bait and switch" scenario sends different args to show the signature no longer matches.
import { approvalChallenge, hashToolCall } from '@ezcheck/mcp-sdk';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { handler, HttpError, relyingParty, TOOLS, unseal } from './_lib.mjs';

export const POST = handler(async ({ approval, ticket, response, executeArgs }, request) => {
  const pending = unseal(approval, 'approval');
  const credential = unseal(ticket, 'cred');
  const { rpID, origin } = relyingParty(request);
  if (response?.id !== credential.id) throw new HttpError(403, 'Signed by a different passkey');

  const args = executeArgs ?? pending.args;
  const argsHash = hashToolCall(pending.tool, args);
  let verified = false;
  try {
    ({ verified } = await verifyAuthenticationResponse({
      response,
      expectedChallenge: approvalChallenge(argsHash, pending.nonce),
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: { id: credential.id, publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64url')), counter: 0 },
      requireUserVerification: true,
    }));
  } catch (err) {
    const reason = /challenge/i.test(err.message)
      ? 'Your signature does not cover these arguments. The agent changed the request after you approved it.'
      : err.message;
    throw new HttpError(403, `Blocked: ${reason}`);
  }
  if (!verified) throw new HttpError(403, 'Blocked: signature not verified');

  const spec = TOOLS[pending.tool];
  spec.validate(args);
  return { status: 'ran', argsHash, result: spec.run(args) };
});
