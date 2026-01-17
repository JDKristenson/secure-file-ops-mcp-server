/**
 * Security Service - Handles injection detection, API validation, and security alerts
 */
import { InjectionScanResult, ApiValidationResult, SecurityAlert, AuditLogEntry, OperationType, FileMetadata } from '../types.js';
/**
 * Scan content for prompt injection patterns
 */
export declare function scanForInjection(content: string, source?: string, quarantineIfDetected?: boolean): InjectionScanResult;
/**
 * Validate that an API call destination matches the source credentials
 */
export declare function validateApiDestination(destinationUrl: string, destinationApiKey?: string, sourceApiKey?: string): ApiValidationResult;
/**
 * Scan content for sensitive data patterns
 */
export declare function scanForSensitiveData(content: string): string[];
/**
 * Calculate SHA-256 hash of content
 */
export declare function hashContent(content: string): string;
/**
 * Create file metadata including security scan
 */
export declare function createFileMetadata(path: string, content: string, mimeType?: string): FileMetadata;
/**
 * Add entry to audit log
 */
export declare function addAuditEntry(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry;
/**
 * Query audit log with filters
 */
export declare function queryAuditLog(options: {
    limit?: number;
    offset?: number;
    operationType?: OperationType;
    blockedOnly?: boolean;
    injectionDetectedOnly?: boolean;
    startTime?: Date;
    endTime?: Date;
}): {
    entries: AuditLogEntry[];
    total: number;
    hasMore: boolean;
};
/**
 * Create a security alert
 */
export declare function createSecurityAlert(alert: Omit<SecurityAlert, 'id' | 'timestamp' | 'acknowledged'>): SecurityAlert;
/**
 * Get security alerts with filters
 */
export declare function getSecurityAlerts(options: {
    limit?: number;
    severity?: SecurityAlert['severity'];
    unacknowledgedOnly?: boolean;
}): SecurityAlert[];
/**
 * Acknowledge a security alert
 */
export declare function acknowledgeAlert(alertId: string): boolean;
/**
 * Get quarantined content by ID
 */
export declare function getQuarantinedContent(quarantineId: string): {
    content: string;
    source?: string;
    timestamp: Date;
} | undefined;
/**
 * Clear quarantined content (after human review)
 */
export declare function clearQuarantinedContent(quarantineId: string): boolean;
//# sourceMappingURL=security.d.ts.map