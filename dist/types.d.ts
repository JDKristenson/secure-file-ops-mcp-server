/**
 * Type definitions for Secure File Operations MCP Server
 */
interface BaseRecord {
    [key: string]: unknown;
}
export interface AccessPolicy extends BaseRecord {
    allowedDirectories: string[];
    blockedDirectories: string[];
    blockedPatterns: RegExp[];
    sensitivePatterns: RegExp[];
    maxFileSizeBytes: number;
}
export type OperationType = 'read_file' | 'write_file' | 'api_call' | 'directory_access' | 'file_upload';
export interface ApprovalRequest extends BaseRecord {
    id: string;
    operation: OperationType;
    details: Record<string, unknown>;
    timestamp: Date;
    expiresAt: Date;
    status: 'pending' | 'approved' | 'denied' | 'expired';
}
export interface AuditLogEntry extends BaseRecord {
    id: string;
    timestamp: Date;
    operation: OperationType;
    path?: string;
    contentHash?: string;
    apiEndpoint?: string;
    destinationApiKey?: string;
    sourceApiKey?: string;
    approved: boolean;
    approvalId?: string;
    blocked: boolean;
    blockReason?: string;
    injectionDetected: boolean;
    injectionPatterns?: string[];
    metadata?: Record<string, unknown>;
}
export interface InjectionScanResult extends BaseRecord {
    isClean: boolean;
    detectedPatterns: string[];
    riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
    recommendation: string;
    quarantined: boolean;
}
export interface ApiValidationResult extends BaseRecord {
    isValid: boolean;
    reason?: string;
    sourceKey?: string;
    destinationKey?: string;
    mismatch: boolean;
}
export interface FileMetadata extends BaseRecord {
    path: string;
    size: number;
    hash: string;
    mimeType?: string;
    accessedAt: Date;
    containsSensitivePatterns: boolean;
    detectedSensitiveTypes: string[];
}
export interface SecurityAlert extends BaseRecord {
    id: string;
    timestamp: Date;
    severity: 'info' | 'warning' | 'critical';
    type: 'injection_attempt' | 'api_mismatch' | 'unauthorized_access' | 'anomalous_pattern';
    message: string;
    details: Record<string, unknown>;
    acknowledged: boolean;
}
export declare enum ResponseFormat {
    JSON = "json",
    MARKDOWN = "markdown"
}
export {};
//# sourceMappingURL=types.d.ts.map