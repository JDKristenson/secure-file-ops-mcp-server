/**
 * Secure File Operations MCP Server
 * 
 * Provides secure file operations with:
 * - Prompt injection detection and quarantine
 * - API key validation to prevent exfiltration
 * - Human-in-the-loop approval gates
 * - Comprehensive audit logging
 * - Configurable access policies
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";

import { ResponseFormat } from './types.js';
import {
  SecureReadFileInputSchema,
  SecureWriteFileInputSchema,
  ValidateApiDestinationInputSchema,
  ScanForInjectionInputSchema,
  RequestApprovalInputSchema,
  CheckApprovalInputSchema,
  ApproveOperationInputSchema,
  SetAccessPolicyInputSchema,
  QueryAuditLogInputSchema,
  GetSecurityAlertsInputSchema,
  AcknowledgeAlertInputSchema,
  type SecureReadFileInput,
  type SecureWriteFileInput,
  type ValidateApiDestinationInput,
  type ScanForInjectionInput,
  type RequestApprovalInput,
  type CheckApprovalInput,
  type ApproveOperationInput,
  type SetAccessPolicyInput,
  type QueryAuditLogInput,
  type GetSecurityAlertsInput,
  type AcknowledgeAlertInput
} from './schemas/index.js';

import {
  scanForInjection,
  validateApiDestination,
  queryAuditLog,
  getSecurityAlerts,
  acknowledgeAlert,
  addAuditEntry
} from './services/security.js';

import {
  createApprovalRequest,
  getApprovalRequest,
  processApproval,
  getPendingApprovals,
  getApprovalStats
} from './services/approval.js';

import {
  secureReadFile,
  secureWriteFile,
  executeApprovedWrite,
  setAccessPolicy,
  getAccessPolicy,
  isPathAllowed
} from './services/fileops.js';

// Initialize MCP Server
const server = new McpServer({
  name: "secure-file-ops-mcp-server",
  version: "1.0.0"
});

// ============================================================================
// TOOL: secure_read_file
// ============================================================================
server.registerTool(
  "secure_read_file",
  {
    title: "Secure Read File",
    description: `Securely read a file with injection scanning and access policy enforcement.

This tool reads files while:
- Checking against configurable access policies (allowed/blocked directories)
- Scanning content for prompt injection patterns
- Detecting sensitive data (PII, credentials, API keys)
- Logging all access attempts for audit

Args:
  - path (string): Absolute or relative path to the file
  - scan_for_injection (boolean): Whether to scan for injection patterns (default: true)
  - response_format ('markdown' | 'json'): Output format (default: 'markdown')

Returns:
  Success: File content with metadata and injection scan results
  Blocked: Error with reason why access was denied
  
Security Features:
  - Blocks access to sensitive directories (.ssh, .env, etc.)
  - Detects and flags prompt injection patterns
  - Quarantines critical-risk content
  - Creates security alerts for suspicious patterns

Example use cases:
  - Reading configuration files safely
  - Processing uploaded documents with injection protection
  - Accessing files while maintaining audit trail`,
    inputSchema: SecureReadFileInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async (params: SecureReadFileInput) => {
    const result = await secureReadFile(params.path, params.scan_for_injection);
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    // Markdown format
    let text = '';
    
    if (result.success) {
      text = `## File Read Successfully\n\n`;
      text += `**Path:** \`${result.metadata?.path}\`\n`;
      text += `**Size:** ${result.metadata?.size} bytes\n`;
      text += `**Hash:** \`${result.metadata?.hash?.substring(0, 16)}...\`\n\n`;
      
      if (result.injectionScan && !result.injectionScan.isClean) {
        text += `### ⚠️ Injection Patterns Detected\n\n`;
        text += `**Risk Level:** ${result.injectionScan.riskLevel}\n`;
        text += `**Recommendation:** ${result.injectionScan.recommendation}\n\n`;
      }
      
      if (result.metadata?.containsSensitivePatterns) {
        text += `### ⚠️ Sensitive Data Detected\n\n`;
        text += `Types: ${result.metadata.detectedSensitiveTypes.join(', ')}\n\n`;
      }
      
      text += `### Content\n\n\`\`\`\n${result.content?.substring(0, 5000)}`;
      if (result.content && result.content.length > 5000) {
        text += `\n... (truncated, ${result.content.length - 5000} more bytes)`;
      }
      text += `\n\`\`\``;
    } else {
      text = `## ❌ File Read Failed\n\n`;
      if (result.blocked) {
        text += `**Blocked:** Yes\n`;
        text += `**Reason:** ${result.blockReason}\n\n`;
      }
      text += `**Error:** ${result.error}`;
    }
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: secure_write_file
// ============================================================================
server.registerTool(
  "secure_write_file",
  {
    title: "Secure Write File",
    description: `Securely write content to a file with approval gates and injection scanning.

This tool writes files while:
- Enforcing access policies
- Scanning content for injection patterns
- Requiring human approval for sensitive operations
- Maintaining audit trail

Args:
  - path (string): Path for the file to write
  - content (string): Content to write (max 10MB)
  - require_approval (boolean): Whether to require human approval (default: true)
  - response_format ('markdown' | 'json'): Output format

Returns:
  If approval required: Returns approval_id to use with approve_operation
  If approved/not required: Writes file and returns metadata
  If blocked: Returns error with reason

Workflow:
  1. Call secure_write_file with require_approval=true
  2. Get approval_id from response
  3. Human reviews and calls approve_operation
  4. If approved, call secure_write_file again (approval tracked internally)`,
    inputSchema: SecureWriteFileInputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    }
  },
  async (params: SecureWriteFileInput) => {
    const result = await secureWriteFile(params.path, params.content, params.require_approval);
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    let text = '';
    
    if (result.success) {
      text = `## ✅ File Written Successfully\n\n`;
      text += `**Path:** \`${result.metadata?.path}\`\n`;
      text += `**Size:** ${result.metadata?.size} bytes\n`;
      text += `**Hash:** \`${result.metadata?.hash?.substring(0, 16)}...\`\n`;
    } else if (result.approvalRequired) {
      text = `## 🔒 Approval Required\n\n`;
      text += `**Approval ID:** \`${result.approvalId}\`\n\n`;
      text += `This operation requires human approval. Use \`approve_operation\` with the approval ID to proceed.\n`;
    } else {
      text = `## ❌ Write Failed\n\n`;
      if (result.blocked) {
        text += `**Blocked:** Yes\n`;
        text += `**Reason:** ${result.blockReason}\n\n`;
      }
      text += `**Error:** ${result.error}`;
    }
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: validate_api_destination
// ============================================================================
server.registerTool(
  "validate_api_destination",
  {
    title: "Validate API Destination",
    description: `Validate that an API call destination matches the authenticated user's credentials.

This is the key mitigation for the Files API exfiltration attack described in the article.
It checks whether a destination API key matches the source (authenticated) key.

Args:
  - destination_url (string): The API endpoint URL being called
  - destination_api_key (string, optional): API key for the destination
  - source_api_key (string, optional): Authenticated user's API key
  - response_format ('markdown' | 'json'): Output format

Returns:
  - isValid: Whether the API call should proceed
  - mismatch: True if keys don't match (potential exfiltration)
  - reason: Explanation of the validation result

Use this before any external API calls that handle sensitive data.`,
    inputSchema: ValidateApiDestinationInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async (params: ValidateApiDestinationInput) => {
    const result = validateApiDestination(
      params.destination_url,
      params.destination_api_key,
      params.source_api_key
    );
    
    // Log the validation
    addAuditEntry({
      operation: 'api_call',
      apiEndpoint: params.destination_url,
      destinationApiKey: result.destinationKey,
      sourceApiKey: result.sourceKey,
      approved: result.isValid,
      blocked: !result.isValid,
      blockReason: result.reason,
      injectionDetected: false
    });
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    let text = '';
    if (result.isValid) {
      text = `## ✅ API Destination Valid\n\n`;
      text += `The API call destination appears legitimate.\n`;
    } else {
      text = `## ❌ API Destination Invalid\n\n`;
      text += `**Mismatch Detected:** ${result.mismatch ? 'Yes - POTENTIAL EXFILTRATION' : 'No'}\n`;
      text += `**Reason:** ${result.reason}\n\n`;
      text += `⚠️ **Do not proceed with this API call.**`;
    }
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: scan_for_injection
// ============================================================================
server.registerTool(
  "scan_for_injection",
  {
    title: "Scan for Prompt Injection",
    description: `Scan text content for prompt injection patterns.

Detects patterns including:
- Direct instruction manipulation ("ignore previous instructions")
- Command execution (curl, wget, exec, eval)
- API/credential patterns (API keys, tokens, authorization headers)
- File exfiltration commands (upload, send, transmit)
- Shell injection patterns
- Base64 encoded commands
- Anthropic API specific patterns

Args:
  - content (string): Text content to scan
  - source (string, optional): Source identifier for logging
  - quarantine_if_detected (boolean): Auto-quarantine risky content (default: true)
  - response_format ('markdown' | 'json'): Output format

Returns:
  - isClean: Whether content is free of detected patterns
  - detectedPatterns: List of patterns found
  - riskLevel: none/low/medium/high/critical
  - recommendation: Suggested action
  - quarantined: Whether content was quarantined`,
    inputSchema: ScanForInjectionInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (params: ScanForInjectionInput) => {
    const result = scanForInjection(params.content, params.source, params.quarantine_if_detected);
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    let text = '';
    if (result.isClean) {
      text = `## ✅ Content Clean\n\nNo prompt injection patterns detected.`;
    } else {
      text = `## ⚠️ Injection Patterns Detected\n\n`;
      text += `**Risk Level:** ${result.riskLevel}\n`;
      text += `**Quarantined:** ${result.quarantined ? 'Yes' : 'No'}\n`;
      text += `**Recommendation:** ${result.recommendation}\n\n`;
      text += `### Detected Patterns\n\n`;
      result.detectedPatterns.slice(0, 10).forEach((p, i) => {
        text += `${i + 1}. \`${p}\`\n`;
      });
      if (result.detectedPatterns.length > 10) {
        text += `\n... and ${result.detectedPatterns.length - 10} more`;
      }
    }
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: request_approval
// ============================================================================
server.registerTool(
  "request_approval",
  {
    title: "Request Human Approval",
    description: `Create a human-in-the-loop approval request for sensitive operations.

This implements the approval gate that should be required before:
- Writing to sensitive files
- Making external API calls
- Accessing new directories
- Uploading files

Args:
  - operation: Type of operation (read_file, write_file, api_call, directory_access, file_upload)
  - description: Human-readable description of what's being approved
  - details: Additional context for the reviewer
  - timeout_seconds: How long to wait for approval (default: 300)
  - response_format ('markdown' | 'json'): Output format

Returns:
  - id: Approval request ID to check status or approve
  - status: Current status (pending)
  - expiresAt: When the request will auto-deny`,
    inputSchema: RequestApprovalInputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false
    }
  },
  async (params: RequestApprovalInput) => {
    const request = createApprovalRequest(
      params.operation,
      params.description,
      params.details,
      params.timeout_seconds * 1000
    );
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(request, null, 2) }],
        structuredContent: request
      };
    }
    
    let text = `## 🔒 Approval Request Created\n\n`;
    text += `**ID:** \`${request.id}\`\n`;
    text += `**Operation:** ${request.operation}\n`;
    text += `**Status:** ${request.status}\n`;
    text += `**Expires:** ${request.expiresAt.toISOString()}\n\n`;
    text += `Use \`approve_operation\` with this ID to approve or deny.`;
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: check_approval_status
// ============================================================================
server.registerTool(
  "check_approval_status",
  {
    title: "Check Approval Status",
    description: `Check the status of a pending approval request.

Args:
  - approval_id: The approval request ID
  - response_format ('markdown' | 'json'): Output format

Returns current status: pending, approved, denied, or expired`,
    inputSchema: CheckApprovalInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (params: CheckApprovalInput) => {
    const request = getApprovalRequest(params.approval_id);
    
    if (!request) {
      return {
        content: [{ type: "text", text: `Approval request \`${params.approval_id}\` not found.` }]
      };
    }
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(request, null, 2) }],
        structuredContent: request
      };
    }
    
    const statusEmoji = {
      pending: '⏳',
      approved: '✅',
      denied: '❌',
      expired: '⏰'
    };
    
    let text = `## ${statusEmoji[request.status]} Approval Status: ${request.status.toUpperCase()}\n\n`;
    text += `**ID:** \`${request.id}\`\n`;
    text += `**Operation:** ${request.operation}\n`;
    text += `**Created:** ${request.timestamp.toISOString()}\n`;
    text += `**Expires:** ${request.expiresAt.toISOString()}\n`;
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: approve_operation
// ============================================================================
server.registerTool(
  "approve_operation",
  {
    title: "Approve or Deny Operation",
    description: `Approve or deny a pending operation request.

This is the human-in-the-loop decision point. Only call this after reviewing
the operation details.

Args:
  - approval_id: The approval request ID
  - approve: true to approve, false to deny
  - reason: Optional explanation for the decision
  - response_format ('markdown' | 'json'): Output format

Returns confirmation of the decision.`,
    inputSchema: ApproveOperationInputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (params: ApproveOperationInput) => {
    const result = processApproval(params.approval_id, params.approve, params.reason);
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    let text = '';
    if (result.success) {
      text = `## ${params.approve ? '✅ Approved' : '❌ Denied'}\n\n`;
      text += `${result.message}\n`;
      if (params.reason) {
        text += `\n**Reason:** ${params.reason}`;
      }
    } else {
      text = `## ⚠️ Could Not Process\n\n${result.message}`;
    }
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: set_access_policy
// ============================================================================
server.registerTool(
  "set_access_policy",
  {
    title: "Set Access Policy",
    description: `Configure the file access policy for secure operations.

Args:
  - allowed_directories: List of directories to allow (empty = all except blocked)
  - blocked_directories: List of directories to block
  - blocked_patterns: Regex patterns for paths to block
  - max_file_size_mb: Maximum file size limit (1-100 MB)
  - response_format ('markdown' | 'json'): Output format

Returns the updated policy configuration.`,
    inputSchema: SetAccessPolicyInputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (params: SetAccessPolicyInput) => {
    const update: Record<string, unknown> = {};
    
    if (params.allowed_directories) {
      update.allowedDirectories = params.allowed_directories;
    }
    if (params.blocked_directories) {
      update.blockedDirectories = params.blocked_directories;
    }
    if (params.blocked_patterns) {
      update.blockedPatterns = params.blocked_patterns.map(p => new RegExp(p));
    }
    if (params.max_file_size_mb) {
      update.maxFileSizeBytes = params.max_file_size_mb * 1024 * 1024;
    }
    
    const policy = setAccessPolicy(update as any);
    
    const result = {
      allowedDirectories: policy.allowedDirectories,
      blockedDirectories: policy.blockedDirectories,
      blockedPatterns: policy.blockedPatterns.map(p => p.toString()),
      maxFileSizeMB: policy.maxFileSizeBytes / (1024 * 1024)
    };
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    let text = `## ⚙️ Access Policy Updated\n\n`;
    text += `**Allowed Directories:** ${result.allowedDirectories.length ? result.allowedDirectories.join(', ') : '(all except blocked)'}\n`;
    text += `**Blocked Directories:** ${result.blockedDirectories.join(', ')}\n`;
    text += `**Blocked Patterns:** ${result.blockedPatterns.length} patterns\n`;
    text += `**Max File Size:** ${result.maxFileSizeMB} MB\n`;
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: query_audit_log
// ============================================================================
server.registerTool(
  "audit_log",
  {
    title: "Query Audit Log",
    description: `Query the audit log of all file and API operations.

The audit log records:
- All file read/write attempts
- API call validations
- Blocked operations and reasons
- Injection pattern detections
- Approval decisions

Args:
  - limit: Max entries to return (1-100, default: 20)
  - offset: Entries to skip for pagination
  - operation_type: Filter by operation type
  - blocked_only: Only show blocked operations
  - injection_detected_only: Only show injection detections
  - start_time: ISO timestamp filter (after)
  - end_time: ISO timestamp filter (before)
  - response_format ('markdown' | 'json'): Output format

Returns paginated list of audit log entries.`,
    inputSchema: QueryAuditLogInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (params: QueryAuditLogInput) => {
    const result = queryAuditLog({
      limit: params.limit,
      offset: params.offset,
      operationType: params.operation_type,
      blockedOnly: params.blocked_only,
      injectionDetectedOnly: params.injection_detected_only,
      startTime: params.start_time ? new Date(params.start_time) : undefined,
      endTime: params.end_time ? new Date(params.end_time) : undefined
    });
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    let text = `## 📋 Audit Log\n\n`;
    text += `**Total Entries:** ${result.total}\n`;
    text += `**Showing:** ${result.entries.length} (offset: ${params.offset})\n`;
    text += `**More Available:** ${result.hasMore ? 'Yes' : 'No'}\n\n`;
    
    if (result.entries.length === 0) {
      text += `No entries found matching the criteria.`;
    } else {
      text += `| Time | Operation | Path/Endpoint | Status | Injection |\n`;
      text += `|------|-----------|---------------|--------|------------|\n`;
      
      for (const entry of result.entries) {
        const time = entry.timestamp.toISOString().substring(11, 19);
        const pathOrEndpoint = entry.path || entry.apiEndpoint || '-';
        const status = entry.blocked ? '❌ Blocked' : (entry.approved ? '✅ OK' : '⏳ Pending');
        const injection = entry.injectionDetected ? '⚠️ Yes' : '-';
        text += `| ${time} | ${entry.operation} | ${pathOrEndpoint.substring(0, 30)} | ${status} | ${injection} |\n`;
      }
    }
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: get_security_alerts
// ============================================================================
server.registerTool(
  "security_alerts",
  {
    title: "Get Security Alerts",
    description: `Get current security alerts.

Alerts are generated for:
- Prompt injection attempts (high/critical risk)
- API key mismatches (potential exfiltration)
- Unauthorized access attempts
- Anomalous access patterns

Args:
  - limit: Max alerts to return (1-50, default: 10)
  - severity: Filter by severity (info, warning, critical)
  - unacknowledged_only: Only show unacknowledged alerts (default: true)
  - response_format ('markdown' | 'json'): Output format

Returns list of security alerts.`,
    inputSchema: GetSecurityAlertsInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (params: GetSecurityAlertsInput) => {
    const alerts = getSecurityAlerts({
      limit: params.limit,
      severity: params.severity,
      unacknowledgedOnly: params.unacknowledged_only
    });
    
    const result = { alerts, count: alerts.length };
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    let text = `## 🚨 Security Alerts\n\n`;
    
    if (alerts.length === 0) {
      text += `No ${params.unacknowledged_only ? 'unacknowledged ' : ''}alerts found.`;
    } else {
      for (const alert of alerts) {
        const severityIcon = {
          info: 'ℹ️',
          warning: '⚠️',
          critical: '🔴'
        };
        
        text += `### ${severityIcon[alert.severity]} ${alert.type}\n\n`;
        text += `**ID:** \`${alert.id}\`\n`;
        text += `**Time:** ${alert.timestamp.toISOString()}\n`;
        text += `**Message:** ${alert.message}\n`;
        text += `**Acknowledged:** ${alert.acknowledged ? 'Yes' : 'No'}\n\n`;
      }
    }
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// TOOL: acknowledge_alert
// ============================================================================
server.registerTool(
  "acknowledge_alert",
  {
    title: "Acknowledge Security Alert",
    description: `Acknowledge a security alert after review.

Args:
  - alert_id: The alert ID to acknowledge
  - response_format ('markdown' | 'json'): Output format

Returns confirmation of acknowledgment.`,
    inputSchema: AcknowledgeAlertInputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  async (params: AcknowledgeAlertInput) => {
    const success = acknowledgeAlert(params.alert_id);
    const result = { success, alertId: params.alert_id };
    
    if (params.response_format === ResponseFormat.JSON) {
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result
      };
    }
    
    const text = success
      ? `## ✅ Alert Acknowledged\n\nAlert \`${params.alert_id}\` has been acknowledged.`
      : `## ⚠️ Alert Not Found\n\nNo alert found with ID \`${params.alert_id}\`.`;
    
    return { content: [{ type: "text", text }] };
  }
);

// ============================================================================
// SERVER STARTUP
// ============================================================================

async function runStdio() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Secure File Ops MCP server running on stdio");
}

async function runHTTP() {
  const app = express();
  app.use(express.json());
  
  app.get('/health', (req, res) => {
    res.json({ status: 'healthy', server: 'secure-file-ops-mcp-server' });
  });
  
  app.post('/mcp', async (req, res) => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });
    res.on('close', () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  
  const port = parseInt(process.env.PORT || '3000');
  app.listen(port, () => {
    console.error(`Secure File Ops MCP server running on http://localhost:${port}/mcp`);
  });
}

// Choose transport based on environment
const transport = process.env.TRANSPORT || 'stdio';
if (transport === 'http') {
  runHTTP().catch(error => {
    console.error("Server error:", error);
    process.exit(1);
  });
} else {
  runStdio().catch(error => {
    console.error("Server error:", error);
    process.exit(1);
  });
}
