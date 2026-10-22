import type { ApprovalProof } from './verify.js';

export type RiskTier = 'LOW' | 'HIGH';

/** What the human is asked to approve. `argsHash` binds the approval to these exact arguments. */
export interface ApprovalRequest {
  tool: string;
  args: unknown;
  argsHash: string;
  summary: string;
}

/** `unverified`: the server said approved, but the passkey signature didn't check out. */
export type ApprovalStatus = 'approved' | 'denied' | 'expired' | 'unverified';

export interface ApprovalDecision {
  status: ApprovalStatus;
  /** Approval id issued by the approver, useful for audit logs. */
  id?: string;
  /** The argsHash the human actually signed. Must equal the request's argsHash. */
  argsHash?: string;
  /** The passkey assertion, when the approver provides one. */
  proof?: ApprovalProof;
}

export interface Approver {
  requestApproval(request: ApprovalRequest): Promise<ApprovalDecision>;
}

export class ApprovalDeniedError extends Error {
  constructor(
    readonly tool: string,
    readonly status: Exclude<ApprovalStatus, 'approved'> | 'mismatch',
  ) {
    super(`EZ CHECK: call to "${tool}" was not approved (${status})`);
    this.name = 'ApprovalDeniedError';
  }
}
