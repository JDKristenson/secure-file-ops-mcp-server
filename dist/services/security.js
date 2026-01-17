/**
 * Security Service - Handles injection detection, API validation, and security alerts
 */
import { createHash, randomUUID } from 'crypto';
import { INJECTION_PATTERNS, SENSITIVE_DATA_PATTERNS, MAX_AUDIT_LOG_ENTRIES } from '../constants.js';
// In-memory stores (in production, these would be persistent)
const auditLog = [];
const securityAlerts = [];
const quarantinedContent = new Map();
/**
 * Scan content for prompt injection patterns
 */
export function scanForInjection(content, source, quarantineIfDetected = true) {
    const detectedPatterns = [];
    for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(content)) {
            detectedPatterns.push(pattern.toString());
        }
    }
    const isClean = detectedPatterns.length === 0;
    // Determine risk level based on detected patterns
    let riskLevel = 'none';
    if (detectedPatterns.length > 0) {
        if (detectedPatterns.length >= 5) {
            riskLevel = 'critical';
        }
        else if (detectedPatterns.length >= 3) {
            riskLevel = 'high';
        }
        else if (detectedPatterns.length >= 2) {
            riskLevel = 'medium';
        }
        else {
            riskLevel = 'low';
        }
    }
    // Generate recommendation
    let recommendation = 'Content appears safe for processing.';
    if (!isClean) {
        if (riskLevel === 'critical' || riskLevel === 'high') {
            recommendation = 'BLOCK: High-risk injection patterns detected. Do not process this content.';
        }
        else if (riskLevel === 'medium') {
            recommendation = 'REVIEW: Moderate risk detected. Require human approval before processing.';
        }
        else {
            recommendation = 'CAUTION: Low-risk patterns detected. Proceed with monitoring.';
        }
    }
    // Quarantine if requested and patterns detected
    let quarantined = false;
    if (!isClean && quarantineIfDetected) {
        const quarantineId = randomUUID();
        quarantinedContent.set(quarantineId, {
            content,
            source,
            timestamp: new Date()
        });
        quarantined = true;
        // Create security alert for high-risk detections
        if (riskLevel === 'critical' || riskLevel === 'high') {
            createSecurityAlert({
                severity: riskLevel === 'critical' ? 'critical' : 'warning',
                type: 'injection_attempt',
                message: `Prompt injection attempt detected in ${source || 'unknown source'}`,
                details: {
                    detectedPatterns: detectedPatterns.slice(0, 5), // Limit for readability
                    riskLevel,
                    quarantineId
                }
            });
        }
    }
    return {
        isClean,
        detectedPatterns,
        riskLevel,
        recommendation,
        quarantined
    };
}
/**
 * Validate that an API call destination matches the source credentials
 */
export function validateApiDestination(destinationUrl, destinationApiKey, sourceApiKey) {
    // Check if this is an Anthropic API call
    const isAnthropicApi = /api\.anthropic\.com/i.test(destinationUrl);
    // If both keys are provided, check for mismatch
    if (destinationApiKey && sourceApiKey) {
        // Extract key prefixes for comparison (first 10 chars should match for same account)
        const destPrefix = destinationApiKey.substring(0, 10);
        const srcPrefix = sourceApiKey.substring(0, 10);
        if (destPrefix !== srcPrefix) {
            // Create security alert for mismatched keys
            createSecurityAlert({
                severity: 'critical',
                type: 'api_mismatch',
                message: 'API key mismatch detected - potential exfiltration attempt',
                details: {
                    destinationUrl,
                    destinationKeyPrefix: destPrefix.substring(0, 4) + '...',
                    sourceKeyPrefix: srcPrefix.substring(0, 4) + '...'
                }
            });
            return {
                isValid: false,
                reason: 'Destination API key does not match authenticated user key. This may be an exfiltration attempt.',
                sourceKey: srcPrefix.substring(0, 4) + '***',
                destinationKey: destPrefix.substring(0, 4) + '***',
                mismatch: true
            };
        }
    }
    // Check for suspicious file upload endpoints
    if (/files\/upload|\/upload|\/v1\/files/i.test(destinationUrl)) {
        if (!sourceApiKey) {
            return {
                isValid: false,
                reason: 'File upload to external API requires source key validation. Cannot verify destination matches authenticated user.',
                mismatch: false
            };
        }
        if (!destinationApiKey) {
            return {
                isValid: false,
                reason: 'File upload API call detected but no destination API key provided for validation.',
                mismatch: false
            };
        }
    }
    return {
        isValid: true,
        sourceKey: sourceApiKey ? sourceApiKey.substring(0, 4) + '***' : undefined,
        destinationKey: destinationApiKey ? destinationApiKey.substring(0, 4) + '***' : undefined,
        mismatch: false
    };
}
/**
 * Scan content for sensitive data patterns
 */
export function scanForSensitiveData(content) {
    const detectedTypes = [];
    for (const { name, pattern } of SENSITIVE_DATA_PATTERNS) {
        if (pattern.test(content)) {
            detectedTypes.push(name);
        }
    }
    return detectedTypes;
}
/**
 * Calculate SHA-256 hash of content
 */
export function hashContent(content) {
    return createHash('sha256').update(content).digest('hex');
}
/**
 * Create file metadata including security scan
 */
export function createFileMetadata(path, content, mimeType) {
    const sensitiveTypes = scanForSensitiveData(content);
    return {
        path,
        size: Buffer.byteLength(content, 'utf8'),
        hash: hashContent(content),
        mimeType,
        accessedAt: new Date(),
        containsSensitivePatterns: sensitiveTypes.length > 0,
        detectedSensitiveTypes: sensitiveTypes
    };
}
/**
 * Add entry to audit log
 */
export function addAuditEntry(entry) {
    const fullEntry = {
        id: randomUUID(),
        timestamp: new Date(),
        operation: entry.operation,
        path: entry.path,
        contentHash: entry.contentHash,
        apiEndpoint: entry.apiEndpoint,
        destinationApiKey: entry.destinationApiKey,
        sourceApiKey: entry.sourceApiKey,
        approved: entry.approved,
        approvalId: entry.approvalId,
        blocked: entry.blocked,
        blockReason: entry.blockReason,
        injectionDetected: entry.injectionDetected,
        injectionPatterns: entry.injectionPatterns,
        metadata: entry.metadata
    };
    auditLog.unshift(fullEntry); // Add to beginning for newest first
    // Trim log if it exceeds maximum
    if (auditLog.length > MAX_AUDIT_LOG_ENTRIES) {
        auditLog.length = MAX_AUDIT_LOG_ENTRIES;
    }
    return fullEntry;
}
/**
 * Query audit log with filters
 */
export function queryAuditLog(options) {
    let filtered = [...auditLog];
    if (options.operationType) {
        filtered = filtered.filter(e => e.operation === options.operationType);
    }
    if (options.blockedOnly) {
        filtered = filtered.filter(e => e.blocked);
    }
    if (options.injectionDetectedOnly) {
        filtered = filtered.filter(e => e.injectionDetected);
    }
    if (options.startTime) {
        filtered = filtered.filter(e => e.timestamp >= options.startTime);
    }
    if (options.endTime) {
        filtered = filtered.filter(e => e.timestamp <= options.endTime);
    }
    const total = filtered.length;
    const offset = options.offset || 0;
    const limit = options.limit || 20;
    const entries = filtered.slice(offset, offset + limit);
    return {
        entries,
        total,
        hasMore: offset + limit < total
    };
}
/**
 * Create a security alert
 */
export function createSecurityAlert(alert) {
    const fullAlert = {
        id: randomUUID(),
        timestamp: new Date(),
        acknowledged: false,
        severity: alert.severity,
        type: alert.type,
        message: alert.message,
        details: alert.details
    };
    securityAlerts.unshift(fullAlert);
    // Keep only last 1000 alerts
    if (securityAlerts.length > 1000) {
        securityAlerts.length = 1000;
    }
    return fullAlert;
}
/**
 * Get security alerts with filters
 */
export function getSecurityAlerts(options) {
    let filtered = [...securityAlerts];
    if (options.severity) {
        filtered = filtered.filter(a => a.severity === options.severity);
    }
    if (options.unacknowledgedOnly) {
        filtered = filtered.filter(a => !a.acknowledged);
    }
    return filtered.slice(0, options.limit || 10);
}
/**
 * Acknowledge a security alert
 */
export function acknowledgeAlert(alertId) {
    const alert = securityAlerts.find(a => a.id === alertId);
    if (alert) {
        alert.acknowledged = true;
        return true;
    }
    return false;
}
/**
 * Get quarantined content by ID
 */
export function getQuarantinedContent(quarantineId) {
    return quarantinedContent.get(quarantineId);
}
/**
 * Clear quarantined content (after human review)
 */
export function clearQuarantinedContent(quarantineId) {
    return quarantinedContent.delete(quarantineId);
}
//# sourceMappingURL=security.js.map