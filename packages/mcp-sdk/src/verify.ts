import { createHash, createPublicKey, verify, type JsonWebKey } from 'node:crypto';

/** A passkey's public half, pinned in the agent's config so the approval server can't substitute its own. */
export interface TrustedPasskey {
  id: string;
  /** COSE algorithm: -7 ES256, -257 RS256, -8 EdDSA. */
  alg: number;
  jwk: JsonWebKey;
}

/** The raw WebAuthn assertion behind an approval, all base64url. */
export interface ApprovalProof {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  nonce: string;
}

export interface VerifyOptions {
  /** Origin of the approval page, e.g. http://localhost:4747 */
  origin: string;
  rpID: string;
  trustedKeys: TrustedPasskey[];
}

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;

/** The WebAuthn challenge commits to the exact tool call, so the signature is over what the human saw. */
export function approvalChallenge(argsHash: string, nonce: string): string {
  return createHash('sha256').update(`ezcheck:v1:${argsHash}:${nonce}`).digest('base64url');
}

export class ProofError extends Error {
  constructor(message: string) {
    super(`EZ CHECK proof rejected: ${message}`);
    this.name = 'ProofError';
  }
}

/**
 * Checks, without trusting the approval server, that a pinned passkey signed an approval of `argsHash`
 * with the user verified (biometric or PIN). Throws ProofError otherwise.
 */
export function verifyApprovalProof(proof: ApprovalProof, argsHash: string, options: VerifyOptions): void {
  const key = options.trustedKeys.find((k) => k.id === proof.credentialId);
  if (!key) throw new ProofError('signed by a passkey that is not pinned');

  const clientDataBytes = Buffer.from(proof.clientDataJSON, 'base64url');
  let clientData: { type?: string; challenge?: string; origin?: string };
  try {
    clientData = JSON.parse(clientDataBytes.toString('utf8'));
  } catch {
    throw new ProofError('clientDataJSON is not JSON');
  }
  if (clientData.type !== 'webauthn.get') throw new ProofError('not an assertion');
  if (clientData.challenge !== approvalChallenge(argsHash, proof.nonce)) {
    throw new ProofError('signature is not over this tool call');
  }
  if (clientData.origin !== options.origin) throw new ProofError(`unexpected origin ${clientData.origin}`);

  const authData = Buffer.from(proof.authenticatorData, 'base64url');
  if (authData.length < 37) throw new ProofError('authenticatorData too short');
  if (!authData.subarray(0, 32).equals(createHash('sha256').update(options.rpID).digest())) {
    throw new ProofError('wrong relying party');
  }
  const flags = authData[32]!;
  if (!(flags & FLAG_USER_PRESENT) || !(flags & FLAG_USER_VERIFIED)) {
    throw new ProofError('user was not verified');
  }

  const signed = Buffer.concat([authData, createHash('sha256').update(clientDataBytes).digest()]);
  const signature = Buffer.from(proof.signature, 'base64url');
  const publicKey = createPublicKey({ key: key.jwk, format: 'jwk' });
  const valid =
    key.alg === -7
      ? verify('sha256', signed, { key: publicKey, dsaEncoding: 'der' }, signature)
      : key.alg === -257
        ? verify('sha256', signed, publicKey, signature)
        : key.alg === -8
          ? verify(null, signed, publicKey, signature)
          : false;
  if (!valid) throw new ProofError('bad signature');
}
