/**
 * Approval Service - Handles human-in-the-loop approval gates
 */
import { ApprovalRequest, OperationType } from '../types.js';
/**
 * Create a new approval request
 */
export declare function createApprovalRequest(operation: OperationType, description: string, details?: Record<string, unknown>, timeoutMs?: number): ApprovalRequest;
/**
 * Get an approval request by ID
 */
export declare function getApprovalRequest(id: string): ApprovalRequest | undefined;
/**
 * Approve or deny a pending request
 */
export declare function processApproval(id: string, approve: boolean, reason?: string): {
    success: boolean;
    message: string;
    request?: ApprovalRequest;
};
/**
 * Check if an operation is approved (for use after requesting approval)
 */
export declare function isApproved(id: string): boolean;
/**
 * Wait for approval with timeout (returns when approved, denied, or expired)
 * This is a polling-based approach - in production, you'd use webhooks or WebSockets
 */
export declare function waitForApproval(id: string, pollIntervalMs?: number, maxWaitMs?: number): Promise<{
    approved: boolean;
    request: ApprovalRequest;
}>;
/**
 * Get all pending approval requests
 */
export declare function getPendingApprovals(): ApprovalRequest[];
/**
 * Get approval statistics
 */
export declare function getApprovalStats(): {
    pending: number;
    approved: number;
    denied: number;
    expired: number;
};
/**
 * Cancel a pending approval request
 */
export declare function cancelApprovalRequest(id: string): boolean;
//# sourceMappingURL=approval.d.ts.map