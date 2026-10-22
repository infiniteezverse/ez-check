import { generateRegistrationOptions } from '@simplewebauthn/server';
import { handler, relyingParty, seal } from './_lib.mjs';

export const POST = handler(async (_body, request) => {
  const { rpID } = relyingParty(request);
  const options = await generateRegistrationOptions({
    rpName: 'EZ CHECK demo',
    rpID,
    userName: `ez-check-demo-${new Date().toISOString().slice(0, 10)}`,
    userDisplayName: 'EZ CHECK demo',
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  return { options, token: seal({ kind: 'reg', challenge: options.challenge }, 5 * 60_000) };
});
