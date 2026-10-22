export { createEzCheck, type EzCheck, type ProtectOptions } from './protect.js';
export { HttpApprover, type HttpApproverOptions } from './http-approver.js';
export { canonicalJson, hashToolCall } from './hash.js';
export {
  approvalChallenge,
  ProofError,
  verifyApprovalProof,
  type ApprovalProof,
  type TrustedPasskey,
  type VerifyOptions,
} from './verify.js';
export {
  ApprovalDeniedError,
  type ApprovalDecision,
  type ApprovalRequest,
  type ApprovalStatus,
  type Approver,
  type RiskTier,
} from './types.js';
