/**
 * Constants for Secure File Operations MCP Server
 */
// Character limit for responses
export const CHARACTER_LIMIT = 50000;
// Default approval timeout in milliseconds (5 minutes)
export const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;
// Maximum file size for reading (10MB)
export const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
// Audit log retention (number of entries)
export const MAX_AUDIT_LOG_ENTRIES = 10000;
// Prompt injection patterns to detect
export const INJECTION_PATTERNS = [
    // Direct instruction patterns
    /ignore\s+(all\s+)?previous\s+instructions?/i,
    /disregard\s+(all\s+)?previous\s+instructions?/i,
    /forget\s+(all\s+)?previous\s+instructions?/i,
    /new\s+instructions?:/i,
    /system\s*prompt:/i,
    /you\s+are\s+now\s+a/i,
    /act\s+as\s+(if\s+you\s+are\s+)?a/i,
    /pretend\s+(you\s+are|to\s+be)/i,
    // Command execution patterns
    /\bcurl\s+/i,
    /\bwget\s+/i,
    /\bfetch\s*\(/i,
    /\bexec\s*\(/i,
    /\beval\s*\(/i,
    /\bspawn\s*\(/i,
    /child_process/i,
    /subprocess/i,
    /os\.system/i,
    /os\.popen/i,
    // API/Network patterns
    /api[_-]?key/i,
    /authorization:\s*bearer/i,
    /x-api-key/i,
    /secret[_-]?key/i,
    /access[_-]?token/i,
    /private[_-]?key/i,
    // File exfiltration patterns
    /upload\s+.*\s+to\s+/i,
    /send\s+.*\s+to\s+/i,
    /transmit\s+.*\s+to\s+/i,
    /exfiltrate/i,
    /data\s*extraction/i,
    // Base64 encoded commands (common obfuscation)
    /base64\s*-d/i,
    /atob\s*\(/i,
    /btoa\s*\(/i,
    /Buffer\.from\s*\([^)]+,\s*['"]base64['"]/i,
    // Shell injection patterns
    /;\s*(rm|cat|ls|pwd|whoami|id|env)\s/i,
    /\|\s*(bash|sh|zsh|cmd)/i,
    /`[^`]+`/, // Backtick command substitution
    /\$\([^)]+\)/, // $() command substitution
    // Anthropic API specific patterns
    /anthropic\.com\/v1/i,
    /api\.anthropic\.com/i,
    /files\/upload/i,
    /messages\/create/i
];
// Sensitive data patterns
export const SENSITIVE_DATA_PATTERNS = [
    { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
    { name: 'Credit Card', pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/ },
    { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/ },
    { name: 'Phone', pattern: /\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b/ },
    { name: 'API Key', pattern: /\b(sk-|pk-|api[_-]?key)[A-Za-z0-9_-]{20,}\b/i },
    { name: 'AWS Key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
    { name: 'Private Key', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/ },
    { name: 'Password Field', pattern: /password\s*[:=]\s*['"][^'"]+['"]/i },
    { name: 'Bearer Token', pattern: /bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i }
];
// Default blocked directories
export const DEFAULT_BLOCKED_DIRECTORIES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/ssh',
    '~/.ssh',
    '~/.aws',
    '~/.config',
    '/root',
    '/var/log',
    'node_modules',
    '.git',
    '.env'
];
// File extensions that require extra scrutiny
export const HIGH_RISK_EXTENSIONS = [
    '.env',
    '.pem',
    '.key',
    '.crt',
    '.p12',
    '.pfx',
    '.jks',
    '.keystore',
    '.htpasswd',
    '.pgpass'
];
//# sourceMappingURL=constants.js.map