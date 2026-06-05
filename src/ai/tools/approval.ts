import { sha256Hex, canonicalJson } from '../../lib/hash.js';

/**
 * Human-approval gate for dangerous tools. A dangerous tool cannot execute
 * until a human with sufficient privilege has approved THIS exact invocation
 * (tool name + canonical arguments). Approvals are keyed by content hash so an
 * approval for one set of arguments cannot be replayed for different ones.
 */
export interface ApprovalGate {
  isApproved(toolName: string, args: unknown): boolean | Promise<boolean>;
}

export function approvalKey(toolName: string, args: unknown): string {
  return `${toolName}:${sha256Hex(canonicalJson(args))}`;
}

/**
 * Simple in-memory approval store. P0 backs this with the `approvals` table +
 * an authorized approve/deny endpoint; the gate contract is identical.
 */
export class InMemoryApprovalStore implements ApprovalGate {
  private readonly approved = new Set<string>();

  approve(toolName: string, args: unknown): void {
    this.approved.add(approvalKey(toolName, args));
  }

  revoke(toolName: string, args: unknown): void {
    this.approved.delete(approvalKey(toolName, args));
  }

  isApproved(toolName: string, args: unknown): boolean {
    return this.approved.has(approvalKey(toolName, args));
  }
}

/** Default gate: nothing is approved (fail-closed). */
export class DenyAllApprovals implements ApprovalGate {
  isApproved(): boolean {
    return false;
  }
}
