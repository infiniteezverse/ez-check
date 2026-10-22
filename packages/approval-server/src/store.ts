import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { WebAuthnCredential } from '@simplewebauthn/server';

export type ApprovalState = 'pending' | 'approved' | 'denied' | 'expired';

export interface Approval {
  id: string;
  tool: string;
  args: unknown;
  argsHash: string;
  summary: string;
  status: ApprovalState;
  createdAt: number;
  expiresAt: number;
  /** Random value mixed into the WebAuthn challenge along with argsHash. */
  nonce?: string;
  challenge?: string;
  /** Kept for audit: which credential signed, and when. */
  approvedBy?: string;
  decidedAt?: number;
}

interface StoredCredential {
  id: string;
  publicKey: string; // base64url
  counter: number;
  transports?: string[];
}

/** Passkeys persist to disk; approvals live in memory and die with the process. */
export class Store {
  readonly approvals = new Map<string, Approval>();
  registrationChallenge?: string;
  private credentials: StoredCredential[];
  private readonly file: string;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.file = join(dataDir, 'credentials.json');
    try {
      this.credentials = JSON.parse(readFileSync(this.file, 'utf8'));
    } catch {
      this.credentials = [];
    }
  }

  hasCredentials(): boolean {
    return this.credentials.length > 0;
  }

  listCredentials(): WebAuthnCredential[] {
    return this.credentials.map((c) => ({
      id: c.id,
      publicKey: new Uint8Array(Buffer.from(c.publicKey, 'base64url')),
      counter: c.counter,
      transports: c.transports,
    }));
  }

  findCredential(id: string): WebAuthnCredential | undefined {
    return this.listCredentials().find((c) => c.id === id);
  }

  saveCredential(credential: WebAuthnCredential): void {
    const stored: StoredCredential = {
      id: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter,
      transports: credential.transports,
    };
    this.credentials = [...this.credentials.filter((c) => c.id !== stored.id), stored];
    writeFileSync(this.file, JSON.stringify(this.credentials, null, 2), { mode: 0o600 });
  }

  updateCounter(id: string, counter: number): void {
    const cred = this.credentials.find((c) => c.id === id);
    if (!cred) return;
    cred.counter = counter;
    writeFileSync(this.file, JSON.stringify(this.credentials, null, 2), { mode: 0o600 });
  }

  /** Returns the approval, flipping it to expired first if its time is up. */
  getApproval(id: string, now = Date.now()): Approval | undefined {
    const approval = this.approvals.get(id);
    if (approval?.status === 'pending' && now > approval.expiresAt) approval.status = 'expired';
    return approval;
  }
}
