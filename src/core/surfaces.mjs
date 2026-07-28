const INSTRUCTION_PATTERNS = Object.freeze([
  { agent: 'agents', pattern: /(?:^|\/)AGENTS\.md$/i },
  { agent: 'claude', pattern: /(?:^|\/)CLAUDE\.md$/i },
  { agent: 'gemini', pattern: /(?:^|\/)GEMINI\.md$/i },
  { agent: 'copilot', pattern: /(?:^|\/)\.github\/copilot-instructions\.md$/i },
  { agent: 'copilot', pattern: /(?:^|\/)\.github\/instructions\/.+\.instructions\.md$/i },
  { agent: 'copilot', pattern: /(?:^|\/)\.github\/agents\/.+\.md$/i },
  { agent: 'cursor', pattern: /(?:^|\/)\.cursor\/rules\/.+\.mdc?$/i },
  { agent: 'cursor', pattern: /(?:^|\/)\.cursorrules$/i },
  { agent: 'cline', pattern: /(?:^|\/)\.clinerules(?:\/.*\.(?:md|txt))?$/i },
  { agent: 'windsurf', pattern: /(?:^|\/)\.windsurf\/rules\/.+\.(?:md|mdc|txt)$/i },
  { agent: 'windsurf', pattern: /(?:^|\/)\.windsurfrules$/i },
  { agent: 'continue', pattern: /(?:^|\/)\.continue\/rules\/.+\.(?:md|mdc|txt)$/i }
]);

const CONFIG_PATTERNS = Object.freeze([
  /(?:^|\/)(?:\.mcp|mcp|mcp-config|settings)\.json$/i,
  /(?:^|\/)\.continue\/(?:config\.ya?ml|mcpServers\/.+\.ya?ml)$/i,
  /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i,
  /(?:^|\/)(?:\.cursor|\.claude|\.cline|\.windsurf|\.continue)\/hooks?\.(?:json|toml|ya?ml)$/i,
  /(?:^|\/)\.cursor\/mcp\.(?:json|toml|ya?ml)$/i,
  /(?:^|\/)\.vscode\/mcp\.json$/i
]);

export function classifyRepositoryFile(relativePath) {
  const normalized = normalizePath(relativePath);
  const agents = INSTRUCTION_PATTERNS
    .filter(({ pattern }) => pattern.test(normalized))
    .map(({ agent }) => agent);
  if (agents.length) return { kind: 'instruction', agents: [...new Set(agents)], path: normalized };
  if (CONFIG_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return { kind: 'agent-config', agents: [], path: normalized };
  }
  return { kind: 'other', agents: [], path: normalized };
}

export function isAgentInstructionFile(relativePath) {
  return classifyRepositoryFile(relativePath).kind === 'instruction';
}

export function isAgentConfigFile(relativePath) {
  return classifyRepositoryFile(relativePath).kind === 'agent-config';
}

function normalizePath(value) {
  return String(value ?? '').replaceAll('\\', '/').replace(/^\.\//, '');
}
