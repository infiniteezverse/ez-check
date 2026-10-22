import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { handler, HttpError, relyingParty, seal, unseal } from './_lib.mjs';

export const POST = handler(async ({ response, token }, request) => {
  const { challenge } = unseal(token, 'reg');
  const { rpID, origin } = relyingParty(request);
  let result;
  try {
    result = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (err) {
    throw new HttpError(400, err.message);
  }
  if (!result.verified) throw new HttpError(400, 'Passkey not verified');
  const { id, publicKey } = result.registrationInfo.credential;
  // The browser keeps this sealed ticket; it's the server's memory of "this visitor's passkey".
  const ticket = seal({ kind: 'cred', id, publicKey: Buffer.from(publicKey).toString('base64url'), rpID }, 30 * 86_400_000);
  return { ticket, credentialId: id };
});
