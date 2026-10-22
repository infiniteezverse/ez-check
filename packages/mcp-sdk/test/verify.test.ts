import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { approvalChallenge, hashToolCall, verifyApprovalProof, type ApprovalProof, type TrustedPasskey } from '../src/index.js';

const ORIGIN = 'http://localhost:4747';
const RP_ID = 'localhost';
const argsHash = hashToolCall('refund_charge', { charge: 'ch_1', amount: 500 });

const keyPairs = {
  ES256: { alg: -7, ...generateKeyPairSync('ec', { namedCurve: 'P-256' }) },
  RS256: { alg: -257, ...generateKeyPairSync('rsa', { modulusLength: 2048 }) },
  EdDSA: { alg: -8, ...generateKeyPairSync('ed25519') },
};

function pin(id: string, alg: number, publicKey: KeyObject): TrustedPasskey {
  return { id, alg, jwk: publicKey.export({ format: 'jwk' }) };
}

/** Builds the assertion a platform authenticator would return for this challenge. */
function assertion(
  privateKey: KeyObject,
  alg: number,
  {
    hash = argsHash,
    nonce = randomBytes(8).toString('base64url'),
    flags = 0x05,
    origin = ORIGIN,
    rpID = RP_ID,
    type = 'webauthn.get',
  } = {},
): ApprovalProof {
  const authData = Buffer.concat([createHash('sha256').update(rpID).digest(), Buffer.from([flags]), Buffer.alloc(4, 1)]);
  const clientData = Buffer.from(JSON.stringify({ type, challenge: approvalChallenge(hash, nonce), origin }));
  const signed = Buffer.concat([authData, createHash('sha256').update(clientData).digest()]);
  const signature = alg === -8 ? sign(null, signed, privateKey) : sign('sha256', signed, privateKey);
  return {
    credentialId: 'cred-1',
    authenticatorData: authData.toString('base64url'),
    clientDataJSON: clientData.toString('base64url'),
    signature: signature.toString('base64url'),
    nonce,
  };
}

describe.each(Object.entries(keyPairs))('verifyApprovalProof with %s', (_name, { alg, publicKey, privateKey }) => {
  const options = { origin: ORIGIN, rpID: RP_ID, trustedKeys: [pin('cred-1', alg, publicKey)] };

  it('accepts a valid, user-verified signature over this call', () => {
    expect(() => verifyApprovalProof(assertion(privateKey, alg), argsHash, options)).not.toThrow();
  });

  it('rejects a signature over a different call', () => {
    const other = hashToolCall('refund_charge', { charge: 'ch_1', amount: 50000 });
    expect(() => verifyApprovalProof(assertion(privateKey, alg, { hash: other }), argsHash, options)).toThrow(
      'not over this tool call',
    );
  });

  it('rejects a tampered signature', () => {
    const proof = assertion(privateKey, alg);
    const sig = Buffer.from(proof.signature, 'base64url');
    sig[sig.length - 1]! ^= 0xff;
    expect(() => verifyApprovalProof({ ...proof, signature: sig.toString('base64url') }, argsHash, options)).toThrow();
  });
});

describe('verifyApprovalProof checks', () => {
  const { alg, publicKey, privateKey } = keyPairs.ES256;
  const options = { origin: ORIGIN, rpID: RP_ID, trustedKeys: [pin('cred-1', alg, publicKey)] };

  it.each([
    ['user presence only (no biometric/PIN)', { flags: 0x01 }, 'user was not verified'],
    ['another origin', { origin: 'https://evil.example' }, 'unexpected origin'],
    ['another relying party', { rpID: 'evil.example' }, 'wrong relying party'],
    ['a registration, not an assertion', { type: 'webauthn.create' }, 'not an assertion'],
  ])('rejects %s', (_label, overrides, message) => {
    expect(() => verifyApprovalProof(assertion(privateKey, alg, overrides), argsHash, options)).toThrow(message);
  });

  it('rejects a passkey that is not pinned', () => {
    const stranger = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const proof = { ...assertion(stranger.privateKey, -7), credentialId: 'cred-2' };
    expect(() => verifyApprovalProof(proof, argsHash, options)).toThrow('not pinned');
  });

  it('rejects a valid signature from a different key claiming a pinned id', () => {
    const stranger = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(() => verifyApprovalProof(assertion(stranger.privateKey, -7), argsHash, options)).toThrow('bad signature');
  });
});
