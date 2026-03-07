# Feature 055: VS Code Extension

## Status: Planned
## Phase: 6 (v2.6)
## Priority: Medium

## Problem

Developers manage keys outside their IDE — switching between terminal, browser dashboard, and code editor. They cannot see which keys are referenced in their code, whether those keys are healthy, or if rotation is overdue without leaving VS Code. This context switching slows down development and means health warnings go unnoticed during the most critical time — when code is being written.

## Solution

Build a VS Code extension (`vscode-pqvault`) that provides in-editor key status, rotation warnings, one-click rotation, and inline secret reference completion. The extension connects to the PQVault API, scans open files for key references (environment variables, config patterns), and displays health status as inline decorations. A sidebar panel shows all vault keys with search, filter, and management capabilities.

## Implementation

### Files to Create/Modify

- `vscode-pqvault/src/extension.ts` — Extension entry point and activation
- `vscode-pqvault/src/provider/secrets.ts` — Secrets tree data provider
- `vscode-pqvault/src/provider/decorations.ts` — Inline code decorations
- `vscode-pqvault/src/provider/completion.ts` — IntelliSense completion provider
- `vscode-pqvault/src/client.ts` — PQVault API client
- `vscode-pqvault/src/commands.ts` — VS Code commands (rotate, copy, etc.)
- `vscode-pqvault/package.json` — Extension manifest

### Data Model Changes

```typescript
// Types for VS Code extension
interface VaultKey {
    name: string;
    category: string;
    provider: string;
    healthScore: number;
    lastRotated: string;
    rotationDue: boolean;
    lastUsed: string;
    tags: string[];
    owner: string;
}

interface KeyReference {
    keyName: string;
    file: string;
    line: number;
    column: number;
    pattern: string; // "env_var", "config", "string_literal"
}

interface HealthDecoration {
    keyName: string;
    score: number;
    message: string;
    severity: "info" | "warning" | "error";
}

// Extension configuration schema
interface PQVaultConfig {
    serverUrl: string;
    token: string;
    autoRefreshInterval: number; // seconds
    showInlineHealth: boolean;
    showRotationWarnings: boolean;
    scanPatterns: string[]; // Regex patterns for finding key references
}
```

### Extension Manifest

```json
{
    "name": "pqvault",
    "displayName": "PQVault - Quantum-Proof Secrets Manager",
    "description": "Manage vault secrets from VS Code",
    "version": "1.0.0",
    "publisher": "pdaxt",
    "engines": { "vscode": "^1.85.0" },
    "categories": ["Other"],
    "activationEvents": ["onStartupFinished"],
    "main": "./dist/extension.js",
    "contributes": {
        "viewsContainers": {
            "activitybar": [{
                "id": "pqvault",
                "title": "PQVault",
                "icon": "resources/icon.svg"
            }]
        },
        "views": {
            "pqvault": [{
                "id": "pqvault.keys",
                "name": "Vault Keys"
            }, {
                "id": "pqvault.health",
                "name": "Health Status"
            }]
        },
        "commands": [
            { "command": "pqvault.rotateKey", "title": "PQVault: Rotate Key" },
            { "command": "pqvault.copyValue", "title": "PQVault: Copy Key Value" },
            { "command": "pqvault.showHealth", "title": "PQVault: Show Key Health" },
            { "command": "pqvault.refresh", "title": "PQVault: Refresh Keys" },
            { "command": "pqvault.search", "title": "PQVault: Search Keys" }
        ],
        "configuration": {
            "title": "PQVault",
            "properties": {
                "pqvault.serverUrl": {
                    "type": "string",
                    "description": "PQVault server URL"
                },
                "pqvault.token": {
                    "type": "string",
                    "description": "Authentication token"
                },
                "pqvault.showInlineHealth": {
                    "type": "boolean",
                    "default": true,
                    "description": "Show health score inline in code"
                },
                "pqvault.autoRefreshInterval": {
                    "type": "number",
                    "default": 300,
                    "description": "Auto-refresh interval in seconds"
                }
            }
        }
    }
}
```

### Extension Code

```typescript
// src/extension.ts
import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
    const client = new PQVaultClient(getConfig());

    // Register tree data provider for sidebar
    const keysProvider = new VaultKeysProvider(client);
    vscode.window.registerTreeDataProvider('pqvault.keys', keysProvider);

    // Register inline decoration provider
    const decorationProvider = new HealthDecorationProvider(client);
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider({ scheme: 'file' }, decorationProvider)
    );

    // Register completion provider for key names
    const completionProvider = new KeyCompletionProvider(client);
    context.subscriptions.push(
        vscode.languages.registerCompletionItemProvider(
            { scheme: 'file', pattern: '**/*.{env,toml,yaml,yml,json,rs,ts,py}' },
            completionProvider,
            '"', "'", '='
        )
    );

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('pqvault.rotateKey', async (keyName: string) => {
            const confirm = await vscode.window.showWarningMessage(
                `Rotate key ${keyName}? This will generate a new value.`,
                'Rotate', 'Cancel'
            );
            if (confirm === 'Rotate') {
                await client.rotateKey(keyName);
                vscode.window.showInformationMessage(`Key ${keyName} rotated successfully`);
                keysProvider.refresh();
            }
        }),

        vscode.commands.registerCommand('pqvault.copyValue', async (keyName: string) => {
            const value = await client.getKeyValue(keyName);
            await vscode.env.clipboard.writeText(value);
            vscode.window.showInformationMessage(`${keyName} copied to clipboard (auto-clears in 30s)`);
            setTimeout(() => vscode.env.clipboard.writeText(''), 30000);
        }),

        vscode.commands.registerCommand('pqvault.search', async () => {
            const query = await vscode.window.showInputBox({ prompt: 'Search vault keys' });
            if (query) {
                const results = await client.searchKeys(query);
                // Show quick pick with results
            }
        })
    );

    // Auto-refresh on interval
    const interval = getConfig().autoRefreshInterval * 1000;
    const timer = setInterval(() => keysProvider.refresh(), interval);
    context.subscriptions.push({ dispose: () => clearInterval(timer) });

    // Scan open files for key references
    vscode.workspace.onDidOpenTextDocument(doc => decorationProvider.scan(doc));
}

// src/provider/decorations.ts
class HealthDecorationProvider implements vscode.CodeLensProvider {
    private keyReferencePattern = /(?:env|ENV|process\.env|std::env::var|os\.getenv)\s*[\(\[]["']([A-Z_][A-Z0-9_]+)["']/g;

    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        const lenses: vscode.CodeLens[] = [];
        const text = document.getText();
        let match;

        while ((match = this.keyReferencePattern.exec(text)) !== null) {
            const keyName = match[1];
            const pos = document.positionAt(match.index);
            const range = new vscode.Range(pos, pos);

            const health = this.client.getCachedHealth(keyName);
            if (health) {
                const label = health.score >= 70
                    ? `${keyName}: ${health.score}/100`
                    : `${keyName}: ${health.score}/100 - ${health.message}`;

                lenses.push(new vscode.CodeLens(range, {
                    title: label,
                    command: 'pqvault.showHealth',
                    arguments: [keyName],
                }));
            }
        }

        return lenses;
    }
}
```

### CLI Commands

```bash
# Install extension
code --install-extension pdaxt.pqvault

# Configure via settings.json
# "pqvault.serverUrl": "https://vault.company.com"
# "pqvault.token": "pqv_sa_..."

# Or configure via CLI
pqvault vscode setup --url https://vault.company.com
```

### Web UI Changes

- VS Code extension download link on integrations page
- Extension setup instructions
- Token generation for VS Code authentication

## Dependencies

- `vscode` — VS Code Extension API (TypeScript)
- `@vscode/vscode` — VS Code types
- Feature 051 (GitHub Actions) — Service account for authentication

## Testing

### Unit Tests (TypeScript)

```typescript
describe('KeyReferenceScanner', () => {
    it('finds env var references in TypeScript', () => {
        const text = `const key = process.env["STRIPE_KEY"];`;
        const refs = scanner.scan(text);
        expect(refs).toHaveLength(1);
        expect(refs[0].keyName).toBe('STRIPE_KEY');
    });

    it('finds env var references in Rust', () => {
        const text = `let key = std::env::var("DATABASE_URL").unwrap();`;
        const refs = scanner.scan(text);
        expect(refs).toHaveLength(1);
        expect(refs[0].keyName).toBe('DATABASE_URL');
    });

    it('finds env var references in Python', () => {
        const text = `key = os.getenv("OPENAI_KEY")`;
        const refs = scanner.scan(text);
        expect(refs).toHaveLength(1);
        expect(refs[0].keyName).toBe('OPENAI_KEY');
    });

    it('does not match lowercase vars', () => {
        const text = `let x = process.env["lowercase_var"];`;
        const refs = scanner.scan(text);
        expect(refs).toHaveLength(0);
    });
});

describe('HealthDecoration', () => {
    it('shows green for healthy keys', () => {
        const decoration = getDecoration({ score: 95 });
        expect(decoration.severity).toBe('info');
    });

    it('shows warning for low health', () => {
        const decoration = getDecoration({ score: 40 });
        expect(decoration.severity).toBe('warning');
    });

    it('shows error for critical health', () => {
        const decoration = getDecoration({ score: 15 });
        expect(decoration.severity).toBe('error');
    });
});
```

### Integration Tests

```typescript
describe('PQVault Client', () => {
    it('fetches key list', async () => {
        const client = new PQVaultClient({ url: testUrl, token: testToken });
        const keys = await client.listKeys();
        expect(keys.length).toBeGreaterThan(0);
    });

    it('rotates key', async () => {
        const client = new PQVaultClient({ url: testUrl, token: testToken });
        const result = await client.rotateKey('TEST_KEY');
        expect(result.success).toBe(true);
    });
});
```

### Manual Verification

1. Install extension in VS Code
2. Configure PQVault server URL and token
3. Open a file referencing environment variables
4. Verify CodeLens decorations show health scores
5. Click rotate command, verify key is rotated
6. Check sidebar shows all vault keys
7. Test IntelliSense completion for key names

## Example Usage

```
# In VS Code:
# 1. Open .env file → see health scores inline above each key
# 2. Open Rust file with std::env::var("STRIPE_KEY") → see CodeLens with health
# 3. Sidebar shows all keys with search/filter
# 4. Right-click key → Rotate / Copy Value / Show Health Details
# 5. Status bar shows: "PQVault: 42 keys | 2 need attention"
```
