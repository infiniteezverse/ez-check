import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { approvalChallenge, hashToolCall } from '@ezcheck/mcp-sdk';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import express, { type NextFunction, type Request, type Response } from 'express';
import type { Config } from './config.js';
import { toTrustedPasskey } from './cose.js';
import type { Approval, Store } from './store.js';

const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
const browserBundle = join(
  dirname(fileURLToPath(import.meta.resolve('@simplewebauthn/browser'))),
  '..',
  'dist',
  'bundle',
  'index.umd.min.js',
);

export function createApp(config: Config, store: Store) {
  const app = express();
  app.use(express.json({ limit: '256kb' }));

  // ---------- Agent API (bearer token) ----------

  const requireAgent = (req: Request, res: Response, next: NextFunction) => {
    const given = Buffer.from(req.get('authorization')?.replace(/^Bearer /, '') ?? '');
    const expected = Buffer.from(config.agentToken);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    next();
  };

  app.post('/api/approvals', requireAgent, (req, res) => {
    const { tool, args, argsHash, summary } = req.body ?? {};
    if (typeof tool !== 'string' || typeof argsHash !== 'string' || typeof summary !== 'string') {
      res.status(400).json({ error: 'tool, argsHash and summary are required' });
      return;
    }
    // Never trust the agent's hash: the human approves what we display, and we display `args`.
    if (hashToolCall(tool, args) !== argsHash) {
      res.status(400).json({ error: 'argsHash does not match tool and args' });
      return;
    }
    const now = Date.now();
    const approval: Approval = {
      id: randomUUID(),
      tool,
      args,
      argsHash,
      summary,
      status: 'pending',
      createdAt: now,
      expiresAt: now + config.approvalTtlMs,
    };
    store.approvals.set(approval.id, approval);
    store.audit('requested', approval);
    const { id } = approval;
    res.status(201).json({ id, url: new URL(`/approve/${id}`, config.origin).toString() });
  });

  app.get('/api/approvals/:id', requireAgent, (req, res) => {
    const approval = store.getApproval(req.params.id as string);
    if (!approval) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    res.json({
      status: approval.status,
      ...(approval.status === 'approved' ? { argsHash: approval.argsHash, proof: approval.proof } : {}),
    });
  });

  // Public keys for agents to pin, so they can verify approvals without trusting this server.
  app.get('/api/passkeys', requireAgent, (_req, res) => {
    res.json(store.listCredentials().map((c) => toTrustedPasskey(c.id, c.publicKey)));
  });

  // ---------- Human pages ----------

  app.get('/', (_req, res) => res.redirect(store.hasCredentials() ? '/status' : '/register'));
  app.get('/register', (_req, res) => res.sendFile(join(publicDir, 'register.html')));
  app.get('/approve/:id', (_req, res) => res.sendFile(join(publicDir, 'approve.html')));
  app.get('/status', (_req, res) => res.sendFile(join(publicDir, 'status.html')));
  app.get('/static/page.css', (_req, res) => res.sendFile(join(publicDir, 'page.css')));
  app.get('/static/simplewebauthn.js', (_req, res) => res.sendFile(browserBundle));

  app.get('/webauthn/status', (_req, res) => res.json({ registered: store.hasCredentials() }));

  // ---------- Passkey registration (only while none is registered) ----------

  app.post('/webauthn/register/options', async (_req, res) => {
    if (store.hasCredentials()) {
      res.status(409).json({ error: `A passkey is already registered. Delete ${config.dataDir}/credentials.json to reset.` });
      return;
    }
    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userName: 'owner',
      userDisplayName: 'EZ CHECK owner',
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'required',
      },
    });
    store.registrationChallenge = options.challenge;
    res.json(options);
  });

  app.post('/webauthn/register/verify', async (req, res) => {
    const expectedChallenge = store.registrationChallenge;
    store.registrationChallenge = undefined;
    if (!expectedChallenge || store.hasCredentials()) {
      res.status(409).json({ error: 'No registration in progress' });
      return;
    }
    try {
      const { verified, registrationInfo } = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        requireUserVerification: true,
      });
      if (!verified || !registrationInfo) throw new Error('Registration not verified');
      store.saveCredential(registrationInfo.credential);
      res.json({ verified: true });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  // ---------- Approving a tool call ----------

  const loadPending = (req: Request, res: Response) => {
    const approval = store.getApproval(req.params.id as string);
    if (!approval) {
      res.status(404).json({ error: 'not found' });
      return undefined;
    }
    if (approval.status !== 'pending') {
      res.status(409).json({ error: `already ${approval.status}`, status: approval.status });
      return undefined;
    }
    return approval;
  };

  app.get('/webauthn/approvals/:id', (req, res) => {
    const approval = store.getApproval(req.params.id as string);
    if (!approval) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    const { tool, args, argsHash, summary, status, expiresAt } = approval;
    res.json({ tool, args, argsHash, summary, status, expiresAt });
  });

  app.post('/webauthn/approvals/:id/options', async (req, res) => {
    const approval = loadPending(req, res);
    if (!approval) return;
    if (!store.hasCredentials()) {
      res.status(409).json({ error: 'No passkey registered yet. Open /register first.' });
      return;
    }
    approval.nonce = randomBytes(16).toString('base64url');
    approval.challenge = approvalChallenge(approval.argsHash, approval.nonce);
    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      challenge: Buffer.from(approval.challenge, 'base64url'),
      userVerification: 'required',
      allowCredentials: store.listCredentials().map((c) => ({ id: c.id, transports: c.transports })),
    });
    res.json(options);
  });

  app.post('/webauthn/approvals/:id/verify', async (req, res) => {
    const approval = loadPending(req, res);
    if (!approval) return;
    const credential = store.findCredential(req.body?.id);
    if (!approval.challenge || !credential) {
      res.status(400).json({ error: 'Unknown credential or no challenge issued' });
      return;
    }
    try {
      const { verified, authenticationInfo } = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: approval.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        credential,
        requireUserVerification: true,
      });
      if (!verified) throw new Error('Signature not verified');
      store.updateCounter(credential.id, authenticationInfo.newCounter);
      const { authenticatorData, clientDataJSON, signature } = req.body.response;
      Object.assign(approval, {
        status: 'approved',
        approvedBy: credential.id,
        decidedAt: Date.now(),
        proof: { credentialId: credential.id, authenticatorData, clientDataJSON, signature, nonce: approval.nonce! },
      });
      store.audit('approved', approval);
      res.json({ status: 'approved' });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  // Denying needs no passkey: refusing is always safe.
  app.post('/webauthn/approvals/:id/deny', (req, res) => {
    const approval = loadPending(req, res);
    if (!approval) return;
    Object.assign(approval, { status: 'denied', decidedAt: Date.now() });
    store.audit('denied', approval);
    res.json({ status: 'denied' });
  });

  return app;
}
