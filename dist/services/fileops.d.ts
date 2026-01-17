/**
 * File Operations Service - Handles secure file access with policy enforcement
 */
import { AccessPolicy, FileMetadata } from '../types.js';
import { scanForInjection } from './security.js';
/**
 * Update the access policy
 */
export declare function setAccessPolicy(policy: Partial<AccessPolicy>): AccessPolicy;
/**
 * Get current access policy
 */
export declare function getAccessPolicy(): AccessPolicy;
/**
 * Check if a path is allowed by the current policy
 */
export declare function isPathAllowed(path: string): {
    allowed: boolean;
    reason?: string;
};
/**
 * Check if a path is considered sensitive
 */
export declare function isPathSensitive(path: string): boolean;
/**
 * Securely read a file with all security checks
 */
export declare function secureReadFile(path: string, scanForInjectionPatterns?: boolean): Promise<{
    success: boolean;
    content?: string;
    metadata?: FileMetadata;
    injectionScan?: ReturnType<typeof scanForInjection>;
    error?: string;
    blocked?: boolean;
    blockReason?: string;
}>;
/**
 * Securely write a file with approval gate
 */
export declare function secureWriteFile(path: string, content: string, requireApproval?: boolean): Promise<{
    success: boolean;
    approvalId?: string;
    approvalRequired?: boolean;
    error?: string;
    blocked?: boolean;
    blockReason?: string;
    metadata?: FileMetadata;
}>;
/**
 * Execute a previously approved write operation
 */
export declare function executeApprovedWrite(approvalId: string, path: string, content: string): Promise<{
    success: boolean;
    error?: string;
    metadata?: FileMetadata;
}>;
//# sourceMappingURL=fileops.d.ts.map