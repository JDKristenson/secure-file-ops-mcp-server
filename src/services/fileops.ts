/**
 * File Operations Service - Handles secure file access with policy enforcement
 */

import { readFile, writeFile, stat, access, constants } from 'fs/promises';
import { resolve, normalize, dirname, extname, basename } from 'path';
import { AccessPolicy, FileMetadata, OperationType } from '../types.js';
import { 
  MAX_FILE_SIZE_BYTES, 
  DEFAULT_BLOCKED_DIRECTORIES,
  HIGH_RISK_EXTENSIONS
} from '../constants.js';
import {
  scanForInjection,
  scanForSensitiveData,
  hashContent,
  createFileMetadata,
  addAuditEntry,
  createSecurityAlert
} from './security.js';
import {
  createApprovalRequest,
  isApproved,
  getApprovalRequest
} from './approval.js';

// Current access policy (configurable at runtime)
let accessPolicy: AccessPolicy = {
  allowedDirectories: [],  // Empty means all directories allowed (except blocked)
  blockedDirectories: DEFAULT_BLOCKED_DIRECTORIES,
  blockedPatterns: [],
  sensitivePatterns: HIGH_RISK_EXTENSIONS.map(ext => new RegExp(`\\${ext}$`, 'i')),
  maxFileSizeBytes: MAX_FILE_SIZE_BYTES
};

/**
 * Update the access policy
 */
export function setAccessPolicy(policy: Partial<AccessPolicy>): AccessPolicy {
  accessPolicy = {
    ...accessPolicy,
    ...policy
  };
  return accessPolicy;
}

/**
 * Get current access policy
 */
export function getAccessPolicy(): AccessPolicy {
  return { ...accessPolicy };
}

/**
 * Check if a path is allowed by the current policy
 */
export function isPathAllowed(path: string): { allowed: boolean; reason?: string } {
  const normalizedPath = normalize(resolve(path));
  
  // Check blocked directories
  for (const blocked of accessPolicy.blockedDirectories) {
    const normalizedBlocked = blocked.startsWith('~') 
      ? blocked // Keep home dir patterns as-is for matching
      : normalize(resolve(blocked));
    
    if (normalizedPath.includes(normalizedBlocked) || 
        normalizedPath.startsWith(normalizedBlocked)) {
      return {
        allowed: false,
        reason: `Path is in blocked directory: ${blocked}`
      };
    }
  }
  
  // Check blocked patterns
  for (const pattern of accessPolicy.blockedPatterns) {
    if (pattern.test(normalizedPath)) {
      return {
        allowed: false,
        reason: `Path matches blocked pattern: ${pattern.toString()}`
      };
    }
  }
  
  // Check allowed directories (if specified)
  if (accessPolicy.allowedDirectories.length > 0) {
    const isInAllowed = accessPolicy.allowedDirectories.some(allowed => {
      const normalizedAllowed = normalize(resolve(allowed));
      return normalizedPath.startsWith(normalizedAllowed);
    });
    
    if (!isInAllowed) {
      return {
        allowed: false,
        reason: 'Path is not in any allowed directory'
      };
    }
  }
  
  return { allowed: true };
}

/**
 * Check if a path is considered sensitive
 */
export function isPathSensitive(path: string): boolean {
  const ext = extname(path).toLowerCase();
  const name = basename(path).toLowerCase();
  
  // Check extension
  if (HIGH_RISK_EXTENSIONS.includes(ext)) {
    return true;
  }
  
  // Check filename patterns
  if (name.includes('.env') || 
      name.includes('secret') || 
      name.includes('credential') ||
      name.includes('password') ||
      name.includes('key') ||
      name.includes('token')) {
    return true;
  }
  
  return false;
}

/**
 * Securely read a file with all security checks
 */
export async function secureReadFile(
  path: string,
  scanForInjectionPatterns: boolean = true
): Promise<{
  success: boolean;
  content?: string;
  metadata?: FileMetadata;
  injectionScan?: ReturnType<typeof scanForInjection>;
  error?: string;
  blocked?: boolean;
  blockReason?: string;
}> {
  const normalizedPath = normalize(resolve(path));
  
  // Check access policy
  const pathCheck = isPathAllowed(normalizedPath);
  if (!pathCheck.allowed) {
    addAuditEntry({
      operation: 'read_file',
      path: normalizedPath,
      approved: false,
      blocked: true,
      blockReason: pathCheck.reason,
      injectionDetected: false
    });
    
    return {
      success: false,
      blocked: true,
      blockReason: pathCheck.reason,
      error: `Access denied: ${pathCheck.reason}`
    };
  }
  
  // Check if file exists and is accessible
  try {
    await access(normalizedPath, constants.R_OK);
  } catch {
    return {
      success: false,
      error: `File not accessible: ${normalizedPath}`
    };
  }
  
  // Check file size
  const fileStat = await stat(normalizedPath);
  if (fileStat.size > accessPolicy.maxFileSizeBytes) {
    return {
      success: false,
      blocked: true,
      blockReason: 'File exceeds maximum size limit',
      error: `File size (${fileStat.size} bytes) exceeds limit (${accessPolicy.maxFileSizeBytes} bytes)`
    };
  }
  
  // Read file content
  let content: string;
  try {
    content = await readFile(normalizedPath, 'utf-8');
  } catch (err) {
    return {
      success: false,
      error: `Failed to read file: ${err instanceof Error ? err.message : 'Unknown error'}`
    };
  }
  
  // Create metadata
  const metadata = createFileMetadata(normalizedPath, content);
  
  // Scan for injection if requested
  let injectionScan: ReturnType<typeof scanForInjection> | undefined;
  if (scanForInjectionPatterns) {
    injectionScan = scanForInjection(content, normalizedPath);
    
    if (!injectionScan.isClean) {
      // Log the detection
      addAuditEntry({
        operation: 'read_file',
        path: normalizedPath,
        contentHash: metadata.hash,
        approved: true, // File was read but flagged
        blocked: false,
        injectionDetected: true,
        injectionPatterns: injectionScan.detectedPatterns.slice(0, 5),
        metadata: {
          riskLevel: injectionScan.riskLevel,
          fileSize: fileStat.size
        }
      });
      
      // For critical risk, block the content
      if (injectionScan.riskLevel === 'critical') {
        return {
          success: false,
          blocked: true,
          blockReason: 'Critical prompt injection risk detected',
          injectionScan,
          metadata,
          error: injectionScan.recommendation
        };
      }
    }
  }
  
  // Warn about sensitive data
  if (metadata.containsSensitivePatterns) {
    createSecurityAlert({
      severity: 'warning',
      type: 'unauthorized_access',
      message: `File contains sensitive data patterns: ${metadata.detectedSensitiveTypes.join(', ')}`,
      details: {
        path: normalizedPath,
        sensitiveTypes: metadata.detectedSensitiveTypes,
        fileSize: fileStat.size
      }
    });
  }
  
  // Log successful read
  addAuditEntry({
    operation: 'read_file',
    path: normalizedPath,
    contentHash: metadata.hash,
    approved: true,
    blocked: false,
    injectionDetected: injectionScan ? !injectionScan.isClean : false,
    metadata: {
      fileSize: fileStat.size,
      containsSensitiveData: metadata.containsSensitivePatterns
    }
  });
  
  return {
    success: true,
    content,
    metadata,
    injectionScan
  };
}

/**
 * Securely write a file with approval gate
 */
export async function secureWriteFile(
  path: string,
  content: string,
  requireApproval: boolean = true
): Promise<{
  success: boolean;
  approvalId?: string;
  approvalRequired?: boolean;
  error?: string;
  blocked?: boolean;
  blockReason?: string;
  metadata?: FileMetadata;
}> {
  const normalizedPath = normalize(resolve(path));
  
  // Check access policy
  const pathCheck = isPathAllowed(normalizedPath);
  if (!pathCheck.allowed) {
    addAuditEntry({
      operation: 'write_file',
      path: normalizedPath,
      approved: false,
      blocked: true,
      blockReason: pathCheck.reason,
      injectionDetected: false
    });
    
    return {
      success: false,
      blocked: true,
      blockReason: pathCheck.reason,
      error: `Access denied: ${pathCheck.reason}`
    };
  }
  
  // Check content size
  const contentSize = Buffer.byteLength(content, 'utf-8');
  if (contentSize > accessPolicy.maxFileSizeBytes) {
    return {
      success: false,
      blocked: true,
      blockReason: 'Content exceeds maximum size limit',
      error: `Content size (${contentSize} bytes) exceeds limit (${accessPolicy.maxFileSizeBytes} bytes)`
    };
  }
  
  // Scan content for injection patterns
  const injectionScan = scanForInjection(content, normalizedPath);
  if (!injectionScan.isClean && (injectionScan.riskLevel === 'critical' || injectionScan.riskLevel === 'high')) {
    addAuditEntry({
      operation: 'write_file',
      path: normalizedPath,
      contentHash: hashContent(content),
      approved: false,
      blocked: true,
      blockReason: 'High-risk injection patterns in content',
      injectionDetected: true,
      injectionPatterns: injectionScan.detectedPatterns.slice(0, 5)
    });
    
    return {
      success: false,
      blocked: true,
      blockReason: 'Content contains high-risk injection patterns',
      error: injectionScan.recommendation
    };
  }
  
  // Check if path is sensitive and requires approval
  const isSensitivePath = isPathSensitive(normalizedPath);
  
  // Request approval if required
  if (requireApproval || isSensitivePath) {
    const approval = createApprovalRequest(
      'write_file',
      `Write ${contentSize} bytes to ${normalizedPath}`,
      {
        path: normalizedPath,
        contentSize,
        contentHash: hashContent(content),
        isSensitivePath,
        injectionRisk: injectionScan.riskLevel
      }
    );
    
    return {
      success: false,
      approvalRequired: true,
      approvalId: approval.id,
      error: `Operation requires approval. Approval ID: ${approval.id}`
    };
  }
  
  // Perform the write
  try {
    await writeFile(normalizedPath, content, 'utf-8');
  } catch (err) {
    return {
      success: false,
      error: `Failed to write file: ${err instanceof Error ? err.message : 'Unknown error'}`
    };
  }
  
  const metadata = createFileMetadata(normalizedPath, content);
  
  // Log successful write
  addAuditEntry({
    operation: 'write_file',
    path: normalizedPath,
    contentHash: metadata.hash,
    approved: true,
    blocked: false,
    injectionDetected: !injectionScan.isClean,
    metadata: {
      contentSize,
      isSensitivePath
    }
  });
  
  return {
    success: true,
    metadata
  };
}

/**
 * Execute a previously approved write operation
 */
export async function executeApprovedWrite(
  approvalId: string,
  path: string,
  content: string
): Promise<{
  success: boolean;
  error?: string;
  metadata?: FileMetadata;
}> {
  // Verify approval
  const approval = getApprovalRequest(approvalId);
  
  if (!approval) {
    return {
      success: false,
      error: 'Approval request not found'
    };
  }
  
  if (approval.status !== 'approved') {
    return {
      success: false,
      error: `Operation not approved (status: ${approval.status})`
    };
  }
  
  // Verify the operation matches
  const normalizedPath = normalize(resolve(path));
  if (approval.details.path !== normalizedPath) {
    return {
      success: false,
      error: 'Path does not match approved operation'
    };
  }
  
  const contentHash = hashContent(content);
  if (approval.details.contentHash !== contentHash) {
    return {
      success: false,
      error: 'Content hash does not match approved operation'
    };
  }
  
  // Perform the write
  try {
    await writeFile(normalizedPath, content, 'utf-8');
  } catch (err) {
    return {
      success: false,
      error: `Failed to write file: ${err instanceof Error ? err.message : 'Unknown error'}`
    };
  }
  
  const metadata = createFileMetadata(normalizedPath, content);
  
  // Log successful write
  addAuditEntry({
    operation: 'write_file',
    path: normalizedPath,
    contentHash: metadata.hash,
    approved: true,
    approvalId,
    blocked: false,
    injectionDetected: false
  });
  
  return {
    success: true,
    metadata
  };
}
