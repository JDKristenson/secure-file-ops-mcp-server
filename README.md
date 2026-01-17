# Secure File Operations MCP Server

A Model Context Protocol (MCP) server providing secure file operations with built-in protections against the vulnerabilities described in [The Register's article on Claude's Files API exfiltration attacks](https://www.theregister.com/2026/01/15/anthropics_claude_bug_cowork/).

## The Problem This Solves

Anthropic's Claude products (Claude Code, Cowork) are vulnerable to prompt injection attacks that can exfiltrate sensitive files to an attacker's API key. The attack chain works like this:

1. User connects Claude to a folder containing sensitive files
2. Attacker plants a document with hidden prompt injection
3. When Claude processes the files, the injected prompt triggers
4. Claude uploads files to the attacker's Anthropic account via the Files API

This MCP server provides the security layer that Anthropic hasn't implemented.

## Key Security Features

### 1. API Key Validation (`validate_api_destination`)
Intercepts outbound API calls and validates that the destination API key matches the authenticated user's key. **This is the critical missing check** - any file upload to a mismatched API key is blocked and triggers a security alert.

### 2. Prompt Injection Detection (`scan_for_injection`, `secure_read_file`)
Scans all file content for 30+ prompt injection patterns including:
- Direct instruction manipulation ("ignore previous instructions")
- Command execution patterns (curl, wget, exec, eval)
- API credential patterns (API keys, tokens, authorization headers)
- File exfiltration commands (upload, send, transmit)
- Shell injection patterns
- Base64 encoded commands
- Anthropic API specific patterns

High-risk content is automatically quarantined and generates security alerts.

### 3. Human-in-the-Loop Approval Gates
Sensitive operations require explicit human approval:
- File writes to sensitive paths
- External API calls
- Access to new directories
- File uploads

Approval requests have configurable timeouts (default: 5 minutes) and auto-deny if not reviewed.

### 4. Comprehensive Audit Logging
Every operation is logged with:
- Timestamp and operation type
- File paths and content hashes
- API endpoints and key prefixes
- Approval status and IDs
- Injection detection results
- Block reasons

### 5. Configurable Access Policies
Define allowed/blocked directories, path patterns, and file size limits. Sensitive directories (`.ssh`, `.env`, `.aws`, etc.) are blocked by default.

## Installation

```bash
# Clone or download the server
cd secure-file-ops-mcp-server

# Install dependencies
npm install

# Build
npm run build
```

## Usage

### As a stdio MCP Server (Local)

```bash
# Run directly
node dist/index.js

# Or via npm
npm start
```

### As an HTTP MCP Server (Remote)

```bash
# Set transport to HTTP
TRANSPORT=http PORT=3000 npm start
```

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "secure-file-ops": {
      "command": "node",
      "args": ["/path/to/secure-file-ops-mcp-server/dist/index.js"]
    }
  }
}
```

## Available Tools

### File Operations

| Tool | Description |
|------|-------------|
| `secure_read_file` | Read files with injection scanning and policy enforcement |
| `secure_write_file` | Write files with approval gates |

### Security Validation

| Tool | Description |
|------|-------------|
| `validate_api_destination` | **Critical** - Validates API calls aren't exfiltrating to wrong account |
| `scan_for_injection` | Scan any text for prompt injection patterns |

### Human-in-the-Loop

| Tool | Description |
|------|-------------|
| `request_approval` | Create approval request for sensitive operations |
| `check_approval_status` | Check if an operation has been approved |
| `approve_operation` | Approve or deny a pending operation |

### Configuration & Monitoring

| Tool | Description |
|------|-------------|
| `set_access_policy` | Configure allowed/blocked directories |
| `audit_log` | Query the audit trail |
| `security_alerts` | View security alerts |
| `acknowledge_alert` | Acknowledge reviewed alerts |

## Example Workflows

### Safe File Reading

```
User: Read the config file at ./app/config.json

Claude: [calls secure_read_file]

Result: 
- File content returned
- Injection scan: Clean
- No sensitive data patterns detected
- Operation logged
```

### Blocked Exfiltration Attempt

```
[Malicious document contains hidden instruction to upload files]

Claude: [document triggers curl command to attacker's API]

Claude: [calls validate_api_destination]

Result:
❌ API Destination Invalid
Mismatch Detected: Yes - POTENTIAL EXFILTRATION
Reason: Destination API key does not match authenticated user key.

⚠️ Security Alert Generated
🔴 CRITICAL: API key mismatch detected - potential exfiltration attempt
```

### Approved Write Operation

```
User: Write the updated config to ./app/config.json

Claude: [calls secure_write_file with require_approval=true]

Result:
🔒 Approval Required
Approval ID: abc-123-def

User: [calls approve_operation with approve=true]

Claude: [executes the approved write]

Result:
✅ File Written Successfully
```

## Detected Injection Patterns

The server detects these categories of prompt injection:

| Category | Examples |
|----------|----------|
| Instruction Override | "ignore previous instructions", "new instructions:" |
| Command Execution | `curl`, `wget`, `exec()`, `eval()`, `subprocess` |
| Credential Access | "api_key", "authorization: bearer", "secret_key" |
| Data Exfiltration | "upload to", "send to", "transmit", "exfiltrate" |
| Shell Injection | `;rm`, `|bash`, backticks, `$()` |
| Encoded Commands | `base64 -d`, `atob()`, `Buffer.from(..., 'base64')` |
| Anthropic API | "api.anthropic.com", "files/upload" |

## Risk Levels

| Level | Action | Description |
|-------|--------|-------------|
| `none` | Allow | No patterns detected |
| `low` | Monitor | 1 pattern, proceed with logging |
| `medium` | Review | 2 patterns, flag for attention |
| `high` | Block | 3-4 patterns, require approval |
| `critical` | Quarantine | 5+ patterns, block and alert |

## Default Blocked Directories

These directories are blocked by default:
- `/etc/passwd`, `/etc/shadow`, `/etc/ssh`
- `~/.ssh`, `~/.aws`, `~/.config`
- `/root`, `/var/log`
- `node_modules`, `.git`, `.env`

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Secure File Ops MCP Server                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Injection   │  │   Access     │  │   Approval   │          │
│  │   Scanner    │  │   Policy     │  │    Gates     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                 │                 │                   │
│         ▼                 ▼                 ▼                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Audit Logger                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Security Alerts                         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      File System                                │
└─────────────────────────────────────────────────────────────────┘
```

## Integration with Existing Workflows

This server is designed to be a **drop-in security layer**. Replace direct file system access with calls to this MCP server:

```typescript
// Before (vulnerable)
const content = fs.readFileSync(path);
await anthropic.files.upload(content);

// After (secure)
const result = await mcpClient.call('secure_read_file', { path });
if (result.injectionScan?.isClean) {
  const validation = await mcpClient.call('validate_api_destination', {
    destination_url: 'https://api.anthropic.com/v1/files',
    destination_api_key: destinationKey,
    source_api_key: authenticatedKey
  });
  if (validation.isValid) {
    await anthropic.files.upload(result.content);
  }
}
```

## Limitations

- **In-memory storage**: Audit logs and alerts are stored in memory. For production, integrate with a persistent store.
- **Single-process**: Approval gates work within a single server process. For distributed systems, use a shared approval store.
- **Pattern-based detection**: Injection detection uses pattern matching, which can have false positives/negatives. Regularly update patterns.

## Contributing

Contributions welcome! Priority areas:
- Additional injection patterns
- Persistent storage backends
- Integration tests
- Client SDKs

## License

MIT

## Acknowledgments

- [PromptArmor](https://promptarmor.com) for disclosing the Files API exfiltration vulnerability
- [Johann Rehberger](https://embracethered.com) for the original Claude Code disclosure
- [Simon Willison](https://simonwillison.net) for ongoing prompt injection research
