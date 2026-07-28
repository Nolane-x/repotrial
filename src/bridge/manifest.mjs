import { isAgentInstructionFile, isAgentConfigFile } from '../core/surfaces.mjs';
import { redactSensitiveText } from '../core/redact.mjs';
import { parseStructuredConfig } from '../core/structured.mjs';
const SECRET_KEY = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|AUTH)(?:$|_)/i;
const MCP_FILE = /(?:^|\/)(?:\.mcp|mcp|mcp-config|settings)\.json$/i;
const MAX_INSTRUCTION_BYTES = 256 * 1024;

/**
 * Build the native ForgeOS v0.6 agent-surface input contract.
 * ForgeOS intentionally accepts exactly these six semantic collections.
 */
export function buildForgeOsManifest(snapshot) {
  const instructions = [];
  const hooks = [];
  const mcpServers = [];
  const packages = [];
  const allowedCommands = new Set();
  const envReferences = new Set();

  for (const file of snapshot.files) {
    collectEnvReferences(file.content, envReferences);

    if (isAgentInstructionFile(file.path)) {
      instructions.push({
        path: file.path,
        text: redactSensitiveText(file.content).slice(0, MAX_INSTRUCTION_BYTES)
      });
    }

    const structuredCandidate = isAgentConfigFile(file.path) || /(?:^|\/)package\.json$/i.test(file.path) || MCP_FILE.test(file.path);
    if (!structuredCandidate) continue;
    const parsedResult = parseStructuredConfig(file.content, file.path);
    const parsed = parsedResult.value;
    if (!isObject(parsed)) {
      if (isAgentConfigFile(file.path)) collectTextAgentConfig(file, mcpServers, allowedCommands);
      continue;
    }

    collectSensitiveKeys(parsed, envReferences);
    collectAllowedCommands(parsed, allowedCommands);
    collectHooks(parsed, file.path, hooks);

    if (/(?:^|\/)package\.json$/i.test(file.path)) {
      const scripts = stringRecord(parsed.scripts);
      packages.push({
        name: String(parsed.name ?? packageFallbackName(file.path)),
        scripts
      });
    }

    if (isAgentConfigFile(file.path) || MCP_FILE.test(file.path) || parsed.mcpServers || parsed.servers) {
      collectMcpServers(parsed, file.path, mcpServers, envReferences);
      collectTextAgentConfig(file, mcpServers, allowedCommands);
    }
  }

  return {
    instructions: dedupeBy(instructions, (item) => item.path),
    hooks: dedupeBy(hooks, (item) => `${item.id}\0${item.script}`),
    mcpServers: dedupeBy(mcpServers, (item) => item.id),
    packages: dedupeBy(packages, (item) => item.name),
    allowedCommands: [...allowedCommands].sort(),
    envReferences: [...envReferences].sort()
  };
}

function collectMcpServers(parsed, sourcePath, target, envReferences) {
  const collections = [];
  const stack = [parsed];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length && nodes < 50_000) {
    const item = stack.pop();
    nodes += 1;
    if (!item || typeof item !== 'object') continue;
    if (seen.has(item)) continue;
    seen.add(item);
    if (Array.isArray(item)) {
      for (const child of item) stack.push(child);
      continue;
    }
    for (const [key, child] of Object.entries(item)) {
      if (/^(?:mcpServers|servers)$/i.test(key) && (isObject(child) || Array.isArray(child))) collections.push(child);
      else if (child && typeof child === 'object') stack.push(child);
    }
  }

  for (const collection of collections) {
    if (Array.isArray(collection)) {
      for (const [index, value] of collection.entries()) {
        if (!isObject(value)) continue;
        appendMcpServer(String(value.id ?? value.name ?? `server-${index + 1}`), value);
      }
    } else {
      for (const [id, value] of Object.entries(collection)) {
        if (!isObject(value)) continue;
        appendMcpServer(String(id), value);
      }
    }
  }

  function appendMcpServer(id, value) {
    for (const name of Object.keys(isObject(value.env) ? value.env : {})) envReferences.add(name);
    collectEnvReferencesFromValue(value, envReferences);
    target.push({
      id,
      description: redactSensitiveText(String(value.description ?? value.summary ?? '')),
      tools: normalizeTools(value, id)
    });
  }
}

function normalizeTools(server, serverId) {
  const tools = [];
  if (Array.isArray(server.tools)) {
    for (const [index, tool] of server.tools.entries()) {
      if (typeof tool === 'string') tools.push({ name: tool, permissions: [] });
      else if (isObject(tool)) tools.push({
        name: String(tool.name ?? tool.id ?? `tool-${index + 1}`),
        permissions: normalizePermissions(tool.permissions ?? tool.allow ?? tool.capabilities)
      });
    }
  } else if (isObject(server.tools)) {
    for (const [name, tool] of Object.entries(server.tools)) {
      tools.push({
        name,
        permissions: normalizePermissions(isObject(tool) ? tool.permissions ?? tool.allow ?? tool.capabilities : [])
      });
    }
  }

  const serverPermissions = normalizePermissions(server.permissions ?? server.allow ?? server.capabilities);
  if (serverPermissions.length || tools.length === 0) {
    tools.push({ name: String(server.name ?? serverId), permissions: serverPermissions });
  }
  return dedupeBy(tools, (tool) => tool.name).sort((a, b) => a.name.localeCompare(b.name));
}

function collectHooks(value, sourcePath, target) {
  const stack = [{ value, insideHooks: false, pathParts: [] }];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length && nodes < 50_000) {
    const current = stack.pop();
    const item = current.value;
    nodes += 1;
    if (!item || typeof item !== 'object') continue;
    if (seen.has(item)) continue;
    seen.add(item);

    if (isObject(item) && current.insideHooks) {
      const command = typeof item.command === 'string' ? item.command
        : typeof item.script === 'string' ? item.script
          : null;
      if (command) {
        target.push({
          id: `${sourcePath}:${current.pathParts.join('.') || 'hook'}`,
          event: current.pathParts.find((part) => /^(?:pre|post|before|after|on)[A-Za-z_-]*/i.test(part)) ?? 'agent.hook',
          script: redactSensitiveText(command)
        });
      }
    }

    const entries = Array.isArray(item) ? item.entries() : Object.entries(item);
    for (const [key, child] of entries) {
      const keyText = String(key);
      const insideHooks = current.insideHooks || /^hooks?$/i.test(keyText);
      const pathParts = insideHooks
        ? [...current.pathParts.slice(-31), keyText]
        : [];
      stack.push({ value: child, insideHooks, pathParts });
    }
  }
}

function collectAllowedCommands(value, target) {
  const stack = [value];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length && nodes < 50_000) {
    const item = stack.pop();
    nodes += 1;
    if (!item || typeof item !== 'object') continue;
    if (seen.has(item)) continue;
    seen.add(item);
    if (Array.isArray(item)) {
      for (const child of item) stack.push(child);
      continue;
    }
    for (const [key, child] of Object.entries(item)) {
      if (/^(?:allowedCommands|allowCommands|commandAllowlist)$/i.test(key)) {
        for (const command of scalarValues(child)) target.add(normalizeAllowedCommand(String(command)));
      }
      if (/^allow$/i.test(key) && Array.isArray(child)) {
        for (const command of child) {
          if (typeof command === 'string' && /^(?:Bash|Shell)\(\*\)$/i.test(command.trim())) target.add('*');
        }
      }
      stack.push(child);
    }
  }
}

function normalizeAllowedCommand(value) {
  const text = value.trim();
  return /^(?:Bash|Shell)\(\*\)$/i.test(text) ? '*' : redactSensitiveText(text);
}

function collectSensitiveKeys(value, target) {
  const stack = [value];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length && nodes < 50_000) {
    const item = stack.pop();
    nodes += 1;
    if (!item || typeof item !== 'object') continue;
    if (seen.has(item)) continue;
    seen.add(item);
    if (Array.isArray(item)) {
      for (const child of item) stack.push(child);
      continue;
    }
    for (const [key, child] of Object.entries(item)) {
      if (SECRET_KEY.test(key)) target.add(key);
      if (/^(?:env|environment|secrets?)$/i.test(key) && isObject(child)) {
        for (const name of Object.keys(child)) {
          if (SECRET_KEY.test(name) || /^[A-Z][A-Z0-9_]{2,}$/.test(name)) target.add(name);
        }
      }
      stack.push(child);
    }
  }
}

function collectTextAgentConfig(file, mcpServers, allowedCommands) {
  const permissions = new Set();
  for (const match of file.content.matchAll(/\b(?:Bash|Shell)\s*\(\s*\*\s*\)|\b(?:filesystem|network|shell|command):\*{1,2}(?!\*)/gi)) {
    const permission = match[0].replace(/\s+/g, '');
    if (/^(?:Bash|Shell)\(\*\)$/i.test(permission)) {
      permissions.add('*');
      allowedCommands.add('*');
    } else permissions.add(permission.toLowerCase());
  }
  if (/\bshell\s*[:=]\s*true\b/i.test(file.content)) permissions.add('shell:*');
  if (/\b(?:permissions|capabilities|allow|tools)\b[\s\S]{0,300}?["']\*["']/i.test(file.content)) permissions.add('*');
  if (!permissions.size) return;
  mcpServers.push({
    id: `config:${file.path}`,
    description: `Conservative permission surface extracted from ${file.path}`,
    tools: [{ name: 'agent-config', permissions: [...permissions].sort() }]
  });
}

function collectEnvReferencesFromValue(value, target) {
  const stack = [value];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length && nodes < 50_000) {
    const item = stack.pop();
    nodes += 1;
    if (typeof item === 'string') {
      collectEnvReferences(item, target);
      continue;
    }
    if (!item || typeof item !== 'object') continue;
    if (seen.has(item)) continue;
    seen.add(item);
    for (const child of Array.isArray(item) ? item : Object.values(item)) stack.push(child);
  }
}
function collectEnvReferences(content, target) {
  for (const match of String(content).matchAll(/\$\{?([A-Z][A-Z0-9_]{2,})\}?/g)) {
    if (SECRET_KEY.test(match[1]) || /(?:URL|URI|HOST|PORT|DATABASE)/.test(match[1])) target.add(match[1]);
  }
}

function normalizePermissions(value) {
  return [...new Set(scalarValues(value).map((item) => String(item)))].sort();
}

function scalarValues(value) {
  const result = [];
  const stack = [value];
  let nodes = 0;
  while (stack.length && nodes < 50_000) {
    const item = stack.pop();
    nodes += 1;
    if (Array.isArray(item)) {
      for (const child of item) stack.push(child);
    } else if (item === null || item === undefined) continue;
    else if (isObject(item)) result.push(...Object.keys(item));
    else result.push(item);
  }
  return result;
}

function stringRecord(value) {
  if (!isObject(value)) return {};
  return Object.fromEntries(Object.entries(value)
    .filter(([, command]) => typeof command === 'string')
    .map(([name, command]) => [name, redactSensitiveText(command)]));
}

function packageFallbackName(filePath) {
  const directory = filePath.replace(/\/?package\.json$/i, '');
  return directory ? directory.replaceAll('/', ':') : 'repository-root';
}


function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function dedupeBy(values, keyFor) {
  const seen = new Set();
  return values.filter((value) => {
    const key = keyFor(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => keyFor(a).localeCompare(keyFor(b)));
}
