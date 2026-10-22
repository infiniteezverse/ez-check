import { execFile } from 'node:child_process';
import type { ApprovalDecision, ApprovalRequest, Approver } from './types.js';
import { verifyApprovalProof, type ApprovalProof, type VerifyOptions } from './verify.js';

export interface HttpApproverOptions {
  /** Base URL of the EZ CHECK approval server, e.g. http://localhost:4747 */
  baseUrl: string;
  /** Shared secret the server expects on agent-side requests (EZCHECK_AGENT_TOKEN). */
  token: string;
  /** Called with the approval page URL. Defaults to printing it on stderr. */
  onPending?: (url: string, request: ApprovalRequest) => void;
  /** Open the approval page in the default browser (macOS, Windows, Linux). */
  openInBrowser?: boolean;
  /**
   * Check the passkey signature here against pinned keys instead of trusting the server's "approved".
   * Get the keys from the server's GET /api/passkeys once, at setup.
   */
  verify?: VerifyOptions;
  pollIntervalMs?: number;
  timeoutMs?: number;
}

/** Sends approval requests to the approval server and waits for the human's decision. */
export class HttpApprover implements Approver {
  private readonly pollIntervalMs: number;
  private readonly timeoutMs: number;

  constructor(private readonly options: HttpApproverOptions) {
    this.pollIntervalMs = options.pollIntervalMs ?? 1000;
    this.timeoutMs = options.timeoutMs ?? 120_000;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalDecision> {
    const created = await this.call<{ id: string; url: string }>('POST', '/api/approvals', request);

    // stdout belongs to the MCP stdio transport, so the default notice goes to stderr.
    (this.options.onPending ?? ((url) => console.error(`[ez-check] Approve "${request.tool}" at ${url}`)))(
      created.url,
      request,
    );
    if (this.options.openInBrowser) openUrl(created.url);

    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const decision = await this.call<Omit<ApprovalDecision, 'status'> & { status: ApprovalDecision['status'] | 'pending' }>(
        'GET',
        `/api/approvals/${encodeURIComponent(created.id)}`,
      );
      if (decision.status === 'approved' && this.options.verify) {
        return this.checkProof(decision, request, created.id);
      }
      if (decision.status !== 'pending') return { ...decision, status: decision.status, id: created.id };
      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs));
    }
    return { status: 'expired', id: created.id };
  }

  private checkProof({ proof }: { proof?: ApprovalProof }, request: ApprovalRequest, id: string): ApprovalDecision {
    try {
      if (!proof) throw new Error('server returned no proof');
      // Verify against the hash we computed, not anything the server echoes back.
      verifyApprovalProof(proof, request.argsHash, this.options.verify!);
      return { status: 'approved', argsHash: request.argsHash, proof, id };
    } catch (err) {
      console.error(`[ez-check] ${(err as Error).message}`);
      return { status: 'unverified', id };
    }
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(new URL(path, this.options.baseUrl), {
      method,
      headers: {
        authorization: `Bearer ${this.options.token}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(`EZ CHECK approval server: ${method} ${path} -> ${res.status}`);
    return (await res.json()) as T;
  }
}

function openUrl(url: string): void {
  const [cmd, args] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['cmd', ['/c', 'start', '', url]]
        : ['xdg-open', [url]];
  execFile(cmd, args as string[], () => {});
}
