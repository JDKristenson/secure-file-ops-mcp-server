/**
 * Zod schemas for input validation
 */
import { z } from 'zod';
import { ResponseFormat } from '../types.js';
export declare const ResponseFormatSchema: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
export declare const SecureReadFileInputSchema: z.ZodObject<{
    path: z.ZodString;
    scan_for_injection: z.ZodDefault<z.ZodBoolean>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    path: string;
    scan_for_injection: boolean;
    response_format: ResponseFormat;
}, {
    path: string;
    scan_for_injection?: boolean | undefined;
    response_format?: ResponseFormat | undefined;
}>;
export type SecureReadFileInput = z.infer<typeof SecureReadFileInputSchema>;
export declare const SecureWriteFileInputSchema: z.ZodObject<{
    path: z.ZodString;
    content: z.ZodString;
    require_approval: z.ZodDefault<z.ZodBoolean>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    path: string;
    response_format: ResponseFormat;
    content: string;
    require_approval: boolean;
}, {
    path: string;
    content: string;
    response_format?: ResponseFormat | undefined;
    require_approval?: boolean | undefined;
}>;
export type SecureWriteFileInput = z.infer<typeof SecureWriteFileInputSchema>;
export declare const ValidateApiDestinationInputSchema: z.ZodObject<{
    destination_url: z.ZodString;
    destination_api_key: z.ZodOptional<z.ZodString>;
    source_api_key: z.ZodOptional<z.ZodString>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    destination_url: string;
    destination_api_key?: string | undefined;
    source_api_key?: string | undefined;
}, {
    destination_url: string;
    response_format?: ResponseFormat | undefined;
    destination_api_key?: string | undefined;
    source_api_key?: string | undefined;
}>;
export type ValidateApiDestinationInput = z.infer<typeof ValidateApiDestinationInputSchema>;
export declare const ScanForInjectionInputSchema: z.ZodObject<{
    content: z.ZodString;
    source: z.ZodOptional<z.ZodString>;
    quarantine_if_detected: z.ZodDefault<z.ZodBoolean>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    content: string;
    quarantine_if_detected: boolean;
    source?: string | undefined;
}, {
    content: string;
    response_format?: ResponseFormat | undefined;
    source?: string | undefined;
    quarantine_if_detected?: boolean | undefined;
}>;
export type ScanForInjectionInput = z.infer<typeof ScanForInjectionInputSchema>;
export declare const RequestApprovalInputSchema: z.ZodObject<{
    operation: z.ZodEnum<["read_file", "write_file", "api_call", "directory_access", "file_upload"]>;
    description: z.ZodString;
    details: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
    timeout_seconds: z.ZodDefault<z.ZodNumber>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    operation: "read_file" | "write_file" | "api_call" | "directory_access" | "file_upload";
    response_format: ResponseFormat;
    description: string;
    timeout_seconds: number;
    details?: Record<string, unknown> | undefined;
}, {
    operation: "read_file" | "write_file" | "api_call" | "directory_access" | "file_upload";
    description: string;
    details?: Record<string, unknown> | undefined;
    response_format?: ResponseFormat | undefined;
    timeout_seconds?: number | undefined;
}>;
export type RequestApprovalInput = z.infer<typeof RequestApprovalInputSchema>;
export declare const CheckApprovalInputSchema: z.ZodObject<{
    approval_id: z.ZodString;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    approval_id: string;
}, {
    approval_id: string;
    response_format?: ResponseFormat | undefined;
}>;
export type CheckApprovalInput = z.infer<typeof CheckApprovalInputSchema>;
export declare const ApproveOperationInputSchema: z.ZodObject<{
    approval_id: z.ZodString;
    approve: z.ZodBoolean;
    reason: z.ZodOptional<z.ZodString>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    approval_id: string;
    approve: boolean;
    reason?: string | undefined;
}, {
    approval_id: string;
    approve: boolean;
    reason?: string | undefined;
    response_format?: ResponseFormat | undefined;
}>;
export type ApproveOperationInput = z.infer<typeof ApproveOperationInputSchema>;
export declare const SetAccessPolicyInputSchema: z.ZodObject<{
    allowed_directories: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    blocked_directories: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    blocked_patterns: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    max_file_size_mb: z.ZodOptional<z.ZodNumber>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    allowed_directories?: string[] | undefined;
    blocked_directories?: string[] | undefined;
    blocked_patterns?: string[] | undefined;
    max_file_size_mb?: number | undefined;
}, {
    response_format?: ResponseFormat | undefined;
    allowed_directories?: string[] | undefined;
    blocked_directories?: string[] | undefined;
    blocked_patterns?: string[] | undefined;
    max_file_size_mb?: number | undefined;
}>;
export type SetAccessPolicyInput = z.infer<typeof SetAccessPolicyInputSchema>;
export declare const QueryAuditLogInputSchema: z.ZodObject<{
    limit: z.ZodDefault<z.ZodNumber>;
    offset: z.ZodDefault<z.ZodNumber>;
    operation_type: z.ZodOptional<z.ZodEnum<["read_file", "write_file", "api_call", "directory_access", "file_upload"]>>;
    blocked_only: z.ZodDefault<z.ZodBoolean>;
    injection_detected_only: z.ZodDefault<z.ZodBoolean>;
    start_time: z.ZodOptional<z.ZodString>;
    end_time: z.ZodOptional<z.ZodString>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    limit: number;
    offset: number;
    blocked_only: boolean;
    injection_detected_only: boolean;
    operation_type?: "read_file" | "write_file" | "api_call" | "directory_access" | "file_upload" | undefined;
    start_time?: string | undefined;
    end_time?: string | undefined;
}, {
    response_format?: ResponseFormat | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
    operation_type?: "read_file" | "write_file" | "api_call" | "directory_access" | "file_upload" | undefined;
    blocked_only?: boolean | undefined;
    injection_detected_only?: boolean | undefined;
    start_time?: string | undefined;
    end_time?: string | undefined;
}>;
export type QueryAuditLogInput = z.infer<typeof QueryAuditLogInputSchema>;
export declare const GetSecurityAlertsInputSchema: z.ZodObject<{
    limit: z.ZodDefault<z.ZodNumber>;
    severity: z.ZodOptional<z.ZodEnum<["info", "warning", "critical"]>>;
    unacknowledged_only: z.ZodDefault<z.ZodBoolean>;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    limit: number;
    unacknowledged_only: boolean;
    severity?: "critical" | "info" | "warning" | undefined;
}, {
    severity?: "critical" | "info" | "warning" | undefined;
    response_format?: ResponseFormat | undefined;
    limit?: number | undefined;
    unacknowledged_only?: boolean | undefined;
}>;
export type GetSecurityAlertsInput = z.infer<typeof GetSecurityAlertsInputSchema>;
export declare const AcknowledgeAlertInputSchema: z.ZodObject<{
    alert_id: z.ZodString;
    response_format: z.ZodDefault<z.ZodNativeEnum<typeof ResponseFormat>>;
}, "strict", z.ZodTypeAny, {
    response_format: ResponseFormat;
    alert_id: string;
}, {
    alert_id: string;
    response_format?: ResponseFormat | undefined;
}>;
export type AcknowledgeAlertInput = z.infer<typeof AcknowledgeAlertInputSchema>;
//# sourceMappingURL=index.d.ts.map