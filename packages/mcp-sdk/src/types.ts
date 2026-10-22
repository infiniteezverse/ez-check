export type RiskTier = 'LOW' | 'HIGH';

/** What the human is asked to approve. `argsHash` binds the approval to these exact arguments. */
export interface ApprovalRequest {
  tool: string;
  args: unknown;
  argsHash: string;
  summary: string;
}

export type ApprovalStatus = 'approved' | 'denied' | 'expired';

export interface ApprovalDecision {
  status: ApprovalStatus;
  /** Approval id issued by the approver, useful for audit logs. */
  id?: string;
  /** The argsHash the human actually signed. Must equal the request's argsHash. */
  argsHash?: string;
}

export interface Approver {
  requestApproval(request: ApprovalRequest): Promise<ApprovalDecision>;
}

export class ApprovalDeniedError extends Error {
  constructor(
    readonly tool: string,
    readonly status: ApprovalStatus | 'mismatch',
  ) {
    super(`EZ CHECK: call to "${tool}" was not approved (${status})`);
    this.name = 'ApprovalDeniedError';
  }
}
