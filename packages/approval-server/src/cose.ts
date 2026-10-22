import type { JsonWebKey } from 'node:crypto';
import type { TrustedPasskey } from '@ezcheck/mcp-sdk';
import { isoCBOR } from '@simplewebauthn/server/helpers';

const b64 = (v: unknown) => Buffer.from(v as Uint8Array).toString('base64url');

/** Converts a stored COSE public key to the JWK form agents pin. Supports ES256, RS256 and EdDSA. */
export function toTrustedPasskey(id: string, cosePublicKey: Uint8Array): TrustedPasskey {
  const cose = isoCBOR.decodeFirst<Map<number, unknown>>(new Uint8Array(cosePublicKey));
  const kty = cose.get(1);
  const alg = cose.get(3) as number;
  let jwk: JsonWebKey;
  if (kty === 2 && cose.get(-1) === 1) {
    jwk = { kty: 'EC', crv: 'P-256', x: b64(cose.get(-2)), y: b64(cose.get(-3)) };
  } else if (kty === 3) {
    jwk = { kty: 'RSA', n: b64(cose.get(-1)), e: b64(cose.get(-2)) };
  } else if (kty === 1 && cose.get(-1) === 6) {
    jwk = { kty: 'OKP', crv: 'Ed25519', x: b64(cose.get(-2)) };
  } else {
    throw new Error(`Unsupported passkey key type ${String(kty)}`);
  }
  return { id, alg, jwk };
}
