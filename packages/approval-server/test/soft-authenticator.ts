import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

/**
 * A software passkey (ES256, "none" attestation) that produces the same JSON a browser's
 * startRegistration/startAuthentication would. Lets tests drive the real WebAuthn verification.
 */
export class SoftAuthenticator {
  private readonly keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  readonly credentialId = randomBytes(16);
  private counter = 0;

  constructor(
    private readonly rpID: string,
    private readonly origin: string,
  ) {}

  get id(): string {
    return this.credentialId.toString('base64url');
  }

  register(options: { challenge: string }) {
    const jwk = this.keys.publicKey.export({ format: 'jwk' });
    const cosePublicKey = isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, new Uint8Array(Buffer.from(jwk.x!, 'base64url'))],
        [-3, new Uint8Array(Buffer.from(jwk.y!, 'base64url'))],
      ]),
    );
    const credIdLength = Buffer.alloc(2);
    credIdLength.writeUInt16BE(this.credentialId.length);
    const authData = Buffer.concat([
      this.authDataHeader(0x45), // UP | UV | AT
      Buffer.alloc(16), // aaguid
      credIdLength,
      this.credentialId,
      Buffer.from(cosePublicKey),
    ]);
    const attestationObject = isoCBOR.encode(
      new Map<string, string | Map<string, never> | Uint8Array>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', new Uint8Array(authData)],
      ]),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: this.clientData('webauthn.create', options.challenge).toString('base64url'),
        attestationObject: Buffer.from(attestationObject).toString('base64url'),
        transports: ['internal'],
      },
    };
  }

  /** Signs an assertion over `challenge`. `flags` defaults to user present + verified. */
  authenticate(options: { challenge: string }, flags = 0x05) {
    const authenticatorData = this.authDataHeader(flags);
    const clientDataJSON = this.clientData('webauthn.get', options.challenge);
    const signature = sign(
      'sha256',
      Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]),
      this.keys.privateKey,
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        authenticatorData: authenticatorData.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    };
  }

  private authDataHeader(flags: number): Buffer {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(++this.counter);
    return Buffer.concat([createHash('sha256').update(this.rpID).digest(), Buffer.from([flags]), count]);
  }

  private clientData(type: string, challenge: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }));
  }
}
