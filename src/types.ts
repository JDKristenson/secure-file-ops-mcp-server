/**
 * Type definitions for Secure File Operations MCP Server
 */

// Base interface with index signature for SDK compatibility
interface BaseRecord {
  [key: string]: unknown;
}

// File access policy types
export interface AccessPolicy extends BaseRecord {
  allowedDirectories: string[];
  blockedDirectories: string[];
  blockedPatterns: RegExp[];
  sensitivePatterns: RegExp[];
  maxFileSizeBytes: number;
}

// Operation types
export type OperationType = 
  | 'read_file'
  | 'write_file'
  | 'api_call'
  | 'directory_access'
  | 'file_upload';

// Pending approval request
export interface ApprovalRequest extends BaseRecord {
  id: string;
  operation: OperationType;
  details: Record<string, unknown>;
  timestamp: Date;
  expiresAt: Date;
  status: 'pending' | 'approved' | 'denied' | 'expired';
}

// Audit log entry
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

// Injection scan result
export interface InjectionScanResult extends BaseRecord {
  isClean: boolean;
  detectedPatterns: string[];
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  recommendation: string;
  quarantined: boolean;
}

// API call validation result
export interface ApiValidationResult extends BaseRecord {
  isValid: boolean;
  reason?: string;
  sourceKey?: string;
  destinationKey?: string;
  mismatch: boolean;
}

// File metadata
export interface FileMetadata extends BaseRecord {
  path: string;
  size: number;
  hash: string;
  mimeType?: string;
  accessedAt: Date;
  containsSensitivePatterns: boolean;
  detectedSensitiveTypes: string[];
}

// Security alert
export interface SecurityAlert extends BaseRecord {
  id: string;
  timestamp: Date;
  severity: 'info' | 'warning' | 'critical';
  type: 'injection_attempt' | 'api_mismatch' | 'unauthorized_access' | 'anomalous_pattern';
  message: string;
  details: Record<string, unknown>;
  acknowledged: boolean;
}

// Response formats
export enum ResponseFormat {
  JSON = 'json',
  MARKDOWN = 'markdown'
}
