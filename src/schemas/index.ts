/**
 * Zod schemas for input validation
 */

import { z } from 'zod';
import { ResponseFormat } from '../types.js';

// Common response format schema
export const ResponseFormatSchema = z.nativeEnum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe("Output format: 'markdown' for human-readable or 'json' for structured data");

// Secure read file input schema
export const SecureReadFileInputSchema = z.object({
  path: z.string()
    .min(1, "Path cannot be empty")
    .max(4096, "Path too long")
    .describe("Absolute or relative path to the file to read"),
  scan_for_injection: z.boolean()
    .default(true)
    .describe("Whether to scan file contents for prompt injection patterns"),
  response_format: ResponseFormatSchema
}).strict();

export type SecureReadFileInput = z.infer<typeof SecureReadFileInputSchema>;

// Secure write file input schema
export const SecureWriteFileInputSchema = z.object({
  path: z.string()
    .min(1, "Path cannot be empty")
    .max(4096, "Path too long")
    .describe("Absolute or relative path for the file to write"),
  content: z.string()
    .max(10 * 1024 * 1024, "Content exceeds 10MB limit")
    .describe("Content to write to the file"),
  require_approval: z.boolean()
    .default(true)
    .describe("Whether to require human approval before writing"),
  response_format: ResponseFormatSchema
}).strict();

export type SecureWriteFileInput = z.infer<typeof SecureWriteFileInputSchema>;

// Validate API destination input schema
export const ValidateApiDestinationInputSchema = z.object({
  destination_url: z.string()
    .url("Must be a valid URL")
    .describe("The API endpoint URL being called"),
  destination_api_key: z.string()
    .optional()
    .describe("The API key being used for the destination (if applicable)"),
  source_api_key: z.string()
    .optional()
    .describe("The authenticated user's API key for comparison"),
  response_format: ResponseFormatSchema
}).strict();

export type ValidateApiDestinationInput = z.infer<typeof ValidateApiDestinationInputSchema>;

// Scan for injection input schema
export const ScanForInjectionInputSchema = z.object({
  content: z.string()
    .max(10 * 1024 * 1024, "Content exceeds 10MB limit")
    .describe("Text content to scan for prompt injection patterns"),
  source: z.string()
    .optional()
    .describe("Source identifier for logging (e.g., filename)"),
  quarantine_if_detected: z.boolean()
    .default(true)
    .describe("Whether to quarantine the content if injection is detected"),
  response_format: ResponseFormatSchema
}).strict();

export type ScanForInjectionInput = z.infer<typeof ScanForInjectionInputSchema>;

// Request approval input schema
export const RequestApprovalInputSchema = z.object({
  operation: z.enum(['read_file', 'write_file', 'api_call', 'directory_access', 'file_upload'])
    .describe("Type of operation requiring approval"),
  description: z.string()
    .min(1, "Description cannot be empty")
    .max(1000, "Description too long")
    .describe("Human-readable description of the operation"),
  details: z.record(z.unknown())
    .optional()
    .describe("Additional details about the operation"),
  timeout_seconds: z.number()
    .int()
    .min(30)
    .max(3600)
    .default(300)
    .describe("Seconds to wait for approval before auto-denying (default: 300)"),
  response_format: ResponseFormatSchema
}).strict();

export type RequestApprovalInput = z.infer<typeof RequestApprovalInputSchema>;

// Check approval status input schema
export const CheckApprovalInputSchema = z.object({
  approval_id: z.string()
    .min(1, "Approval ID cannot be empty")
    .describe("The approval request ID to check"),
  response_format: ResponseFormatSchema
}).strict();

export type CheckApprovalInput = z.infer<typeof CheckApprovalInputSchema>;

// Approve operation input schema
export const ApproveOperationInputSchema = z.object({
  approval_id: z.string()
    .min(1, "Approval ID cannot be empty")
    .describe("The approval request ID to approve"),
  approve: z.boolean()
    .describe("True to approve, false to deny"),
  reason: z.string()
    .max(500)
    .optional()
    .describe("Optional reason for the decision"),
  response_format: ResponseFormatSchema
}).strict();

export type ApproveOperationInput = z.infer<typeof ApproveOperationInputSchema>;

// Set access policy input schema
export const SetAccessPolicyInputSchema = z.object({
  allowed_directories: z.array(z.string())
    .optional()
    .describe("List of directories to allow access to"),
  blocked_directories: z.array(z.string())
    .optional()
    .describe("List of directories to block access to"),
  blocked_patterns: z.array(z.string())
    .optional()
    .describe("Regex patterns for paths to block"),
  max_file_size_mb: z.number()
    .min(1)
    .max(100)
    .optional()
    .describe("Maximum file size in MB (default: 10)"),
  response_format: ResponseFormatSchema
}).strict();

export type SetAccessPolicyInput = z.infer<typeof SetAccessPolicyInputSchema>;

// Query audit log input schema
export const QueryAuditLogInputSchema = z.object({
  limit: z.number()
    .int()
    .min(1)
    .max(100)
    .default(20)
    .describe("Maximum number of entries to return"),
  offset: z.number()
    .int()
    .min(0)
    .default(0)
    .describe("Number of entries to skip"),
  operation_type: z.enum(['read_file', 'write_file', 'api_call', 'directory_access', 'file_upload'])
    .optional()
    .describe("Filter by operation type"),
  blocked_only: z.boolean()
    .default(false)
    .describe("Only show blocked operations"),
  injection_detected_only: z.boolean()
    .default(false)
    .describe("Only show operations with injection detected"),
  start_time: z.string()
    .datetime()
    .optional()
    .describe("Filter entries after this ISO timestamp"),
  end_time: z.string()
    .datetime()
    .optional()
    .describe("Filter entries before this ISO timestamp"),
  response_format: ResponseFormatSchema
}).strict();

export type QueryAuditLogInput = z.infer<typeof QueryAuditLogInputSchema>;

// Get security alerts input schema
export const GetSecurityAlertsInputSchema = z.object({
  limit: z.number()
    .int()
    .min(1)
    .max(50)
    .default(10)
    .describe("Maximum number of alerts to return"),
  severity: z.enum(['info', 'warning', 'critical'])
    .optional()
    .describe("Filter by severity level"),
  unacknowledged_only: z.boolean()
    .default(true)
    .describe("Only show unacknowledged alerts"),
  response_format: ResponseFormatSchema
}).strict();

export type GetSecurityAlertsInput = z.infer<typeof GetSecurityAlertsInputSchema>;

// Acknowledge alert input schema
export const AcknowledgeAlertInputSchema = z.object({
  alert_id: z.string()
    .min(1, "Alert ID cannot be empty")
    .describe("The alert ID to acknowledge"),
  response_format: ResponseFormatSchema
}).strict();

export type AcknowledgeAlertInput = z.infer<typeof AcknowledgeAlertInputSchema>;
