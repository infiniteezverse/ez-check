import { randomBytes } from 'node:crypto';

export interface Config {
  port: number;
  /** Interface to bind. Defaults to loopback so only this machine can see pending approvals. */
  host: string;
  rpID: string;
  rpName: string;
  origin: string;
  /** Shared secret agents send as `Authorization: Bearer <token>`. */
  agentToken: string;
  /** Where the registered passkey is stored. */
  dataDir: string;
  approvalTtlMs: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config & { generatedToken: boolean } {
  const port = Number(env.PORT ?? 4747);
  const rpID = env.EZCHECK_RP_ID ?? 'localhost';
  return {
    port,
    host: env.EZCHECK_HOST ?? '127.0.0.1',
    rpID,
    rpName: env.EZCHECK_RP_NAME ?? 'EZ CHECK',
    origin: env.EZCHECK_ORIGIN ?? `http://${rpID}:${port}`,
    agentToken: env.EZCHECK_AGENT_TOKEN ?? randomBytes(24).toString('base64url'),
    generatedToken: !env.EZCHECK_AGENT_TOKEN,
    dataDir: env.EZCHECK_DATA_DIR ?? '.ezcheck',
    approvalTtlMs: Number(env.EZCHECK_APPROVAL_TTL_MS ?? 120_000),
  };
}
