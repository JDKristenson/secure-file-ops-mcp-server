/**
 * Approval Service - Handles human-in-the-loop approval gates
 */

import { randomUUID } from 'crypto';
import { ApprovalRequest, OperationType } from '../types.js';
import { DEFAULT_APPROVAL_TIMEOUT_MS } from '../constants.js';
import { createSecurityAlert } from './security.js';

// In-memory store for pending approvals
const pendingApprovals: Map<string, ApprovalRequest> = new Map();

// Cleanup expired approvals every minute
setInterval(() => {
  const now = new Date();
  for (const [id, request] of pendingApprovals.entries()) {
    if (request.status === 'pending' && request.expiresAt < now) {
      request.status = 'expired';
      // Keep expired entries for a while for status checking
      setTimeout(() => pendingApprovals.delete(id), 60000);
    }
  }
}, 60000);

/**
 * Create a new approval request
 */
export function createApprovalRequest(
  operation: OperationType,
  description: string,
  details?: Record<string, unknown>,
  timeoutMs: number = DEFAULT_APPROVAL_TIMEOUT_MS
): ApprovalRequest {
  const id = randomUUID();
  const now = new Date();
  
  const request: ApprovalRequest = {
    id,
    operation,
    details: {
      description,
      ...details
    },
    timestamp: now,
    expiresAt: new Date(now.getTime() + timeoutMs),
    status: 'pending'
  };
  
  pendingApprovals.set(id, request);
  
  return request;
}

/**
 * Get an approval request by ID
 */
export function getApprovalRequest(id: string): ApprovalRequest | undefined {
  const request = pendingApprovals.get(id);
  
  // Check if expired
  if (request && request.status === 'pending' && request.expiresAt < new Date()) {
    request.status = 'expired';
  }
  
  return request;
}

/**
 * Approve or deny a pending request
 */
export function processApproval(
  id: string,
  approve: boolean,
  reason?: string
): { success: boolean; message: string; request?: ApprovalRequest } {
  const request = pendingApprovals.get(id);
  
  if (!request) {
    return {
      success: false,
      message: `Approval request ${id} not found`
    };
  }
  
  if (request.status !== 'pending') {
    return {
      success: false,
      message: `Approval request is no longer pending (status: ${request.status})`
    };
  }
  
  if (request.expiresAt < new Date()) {
    request.status = 'expired';
    return {
      success: false,
      message: 'Approval request has expired'
    };
  }
  
  request.status = approve ? 'approved' : 'denied';
  if (reason) {
    request.details.approvalReason = reason;
  }
  request.details.processedAt = new Date().toISOString();
  
  return {
    success: true,
    message: approve ? 'Operation approved' : 'Operation denied',
    request
  };
}

/**
 * Check if an operation is approved (for use after requesting approval)
 */
export function isApproved(id: string): boolean {
  const request = pendingApprovals.get(id);
  return request?.status === 'approved';
}

/**
 * Wait for approval with timeout (returns when approved, denied, or expired)
 * This is a polling-based approach - in production, you'd use webhooks or WebSockets
 */
export async function waitForApproval(
  id: string,
  pollIntervalMs: number = 1000,
  maxWaitMs?: number
): Promise<{ approved: boolean; request: ApprovalRequest }> {
  const request = pendingApprovals.get(id);
  
  if (!request) {
    throw new Error(`Approval request ${id} not found`);
  }
  
  const startTime = Date.now();
  const maxWait = maxWaitMs || (request.expiresAt.getTime() - startTime);
  
  while (true) {
    // Check status
    if (request.status === 'approved') {
      return { approved: true, request };
    }
    
    if (request.status === 'denied') {
      return { approved: false, request };
    }
    
    if (request.status === 'expired' || request.expiresAt < new Date()) {
      request.status = 'expired';
      return { approved: false, request };
    }
    
    // Check if we've exceeded max wait
    if (Date.now() - startTime > maxWait) {
      return { approved: false, request };
    }
    
    // Wait before next poll
    await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
  }
}

/**
 * Get all pending approval requests
 */
export function getPendingApprovals(): ApprovalRequest[] {
  const now = new Date();
  const pending: ApprovalRequest[] = [];
  
  for (const request of pendingApprovals.values()) {
    if (request.status === 'pending') {
      if (request.expiresAt < now) {
        request.status = 'expired';
      } else {
        pending.push(request);
      }
    }
  }
  
  return pending.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
}

/**
 * Get approval statistics
 */
export function getApprovalStats(): {
  pending: number;
  approved: number;
  denied: number;
  expired: number;
} {
  let pending = 0, approved = 0, denied = 0, expired = 0;
  
  for (const request of pendingApprovals.values()) {
    switch (request.status) {
      case 'pending':
        if (request.expiresAt < new Date()) {
          expired++;
        } else {
          pending++;
        }
        break;
      case 'approved':
        approved++;
        break;
      case 'denied':
        denied++;
        break;
      case 'expired':
        expired++;
        break;
    }
  }
  
  return { pending, approved, denied, expired };
}

/**
 * Cancel a pending approval request
 */
export function cancelApprovalRequest(id: string): boolean {
  const request = pendingApprovals.get(id);
  
  if (request && request.status === 'pending') {
    pendingApprovals.delete(id);
    return true;
  }
  
  return false;
}
