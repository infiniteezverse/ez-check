import { canonicalJson, hashToolCall } from './hash.js';
import { ApprovalDeniedError, type Approver, type RiskTier } from './types.js';

export interface ProtectOptions<A> {
  /** Tool name shown to the human and bound into the approval hash. */
  name: string;
  /** LOW runs immediately. HIGH waits for a passkey-signed human approval. */
  riskTier: RiskTier;
  /** One-line, human-readable description of what this call will do. */
  describe?: (args: A) => string;
}

export interface EzCheck {
  protect<A, R, X extends unknown[]>(
    handler: (args: A, ...rest: X) => R | Promise<R>,
    options: ProtectOptions<A>,
  ): (args: A, ...rest: X) => Promise<R>;
}

const MAX_SUMMARY = 500;

export function createEzCheck({ approver }: { approver: Approver }): EzCheck {
  return {
    protect(handler, options) {
      return async (args, ...rest) => {
        if (options.riskTier === 'HIGH') {
          const argsHash = hashToolCall(options.name, args);
          const summary = options.describe
            ? options.describe(args)
            : `${options.name}(${truncate(canonicalJson(args))})`;

          const decision = await approver.requestApproval({
            tool: options.name,
            args,
            argsHash,
            summary,
          });

          if (decision.status !== 'approved') {
            throw new ApprovalDeniedError(options.name, decision.status);
          }
          // An approval for different arguments is not an approval for these.
          if (decision.argsHash !== argsHash) {
            throw new ApprovalDeniedError(options.name, 'mismatch');
          }
        }
        return handler(args, ...rest);
      };
    },
  };
}

function truncate(text: string): string {
  return text.length > MAX_SUMMARY ? `${text.slice(0, MAX_SUMMARY)}…` : text;
}
