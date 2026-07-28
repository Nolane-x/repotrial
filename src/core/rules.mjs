import { findEvidence } from './evidence.mjs';
import { isAgentInstructionFile, isAgentConfigFile } from './surfaces.mjs';
import { redactSensitiveText } from './redact.mjs';

const RULE_META = Object.freeze({
  'dangerous-lifecycle-script': {
    title: 'Dangerous package lifecycle script', severity: 'critical',
    remediation: 'Remove network-to-shell lifecycle execution. Pin and verify installers outside package lifecycle hooks.'
  },
  'pipe-to-shell': {
    title: 'Network response piped into a shell', severity: 'critical',
    remediation: 'Download to a file, verify its digest/signature, inspect it, then execute through an allowlisted runner.'
  },
  'unrestricted-shell-capability': {
    title: 'Unrestricted shell capability', severity: 'high',
    remediation: 'Replace general shell access with explicit commands, arguments, workspace boundaries, and approval gates.'
  },
  'broad-mcp-permissions': {
    title: 'Broad MCP permissions', severity: 'high',
    remediation: 'Replace wildcard permissions/tools with the smallest explicit capability list.'
  },
  'secret-to-egress-path': {
    title: 'Potential secret-to-egress path', severity: 'high',
    remediation: 'Separate secret-bearing tools from network egress and enforce destination allowlists.'
  },
  'prompt-boundary-override': {
    title: 'Instruction boundary override text', severity: 'high',
    remediation: 'Treat repository text as untrusted data and remove instructions that claim precedence over system or user policy.'
  },
  'self-certified-completion': {
    title: 'Self-certified completion or test skipping', severity: 'high',
    remediation: 'Require independent verification commands and prevent the producer from approving its own output.'
  },
  'missing-verification-evidence': {
    title: 'No credible verification command found', severity: 'medium',
    remediation: 'Add a real test or verification command and require it before completion.'
  },
  'destructive-without-approval': {
    title: 'Destructive capability without approval language', severity: 'medium',
    remediation: 'Require explicit human approval before destructive filesystem, deployment, credential, or shell operations.'
  },
  'incomplete-scan-coverage': {
    title: 'Incomplete scan coverage', severity: 'low',
    remediation: 'Reduce oversized/binary/unsupported scope or scan the omitted files with an appropriate analyzer.'
  }
});

function charge(ruleId, status, evidence = [], extra = {}) {
  const meta = RULE_META[ruleId];
  return {
    ruleId,
    title: meta.title,
    severity: meta.severity,
    status,
    confidence: status === 'proven' ? 'high' : status === 'mitigated' ? 'medium' : 'low',
    evidence,
    rationale: extra.rationale ?? meta.title,
    remediation: meta.remediation,
    source: extra.source ?? 'repotrial'
  };
}

function parseJson(file) {
  try { return JSON.parse(file.content); } catch { return null; }
}

function packageVerification(snapshot) {
  for (const pkgFile of snapshot.files) {
    if (!/(?:^|\/)package\.json$/i.test(pkgFile.path)) continue;
    const pkg = parseJson(pkgFile);
    const scripts = pkg?.scripts ?? {};
    for (const [name, command] of Object.entries(scripts)) {
      if (!/^(test|verify|check|ci)$/i.test(name)) continue;
      if (!isCredibleVerificationCommand(command)) continue;
      return { id: 'verification-command', detail: `${name}: ${redactSensitiveText(command)}`, path: pkgFile.path };
    }
  }
  return null;
}

function makefileVerification(snapshot) {
  const targetPattern = /^(?<targets>[A-Za-z0-9_.%/@+-]+(?:\s+[A-Za-z0-9_.%/@+-]+)*)\s*:(?![=])\s*(?<dependencies>.*)$/;
  const verificationTarget = /^(?:test|tests|verify|verification|check|ci)$/i;

  for (const file of snapshot.files) {
    if (!/(?:^|\/)(?:GNUmakefile|Makefile|makefile)$/.test(file.path)) continue;

    const targets = [];
    let current = null;
    for (const rawLine of file.lines) {
      const targetMatch = rawLine.match(targetPattern);
      if (targetMatch) {
        current = {
          names: targetMatch.groups.targets.trim().split(/\s+/),
          dependencies: targetMatch.groups.dependencies.trim().split(/\s+/).filter(Boolean),
          recipes: []
        };
        targets.push(current);
        continue;
      }
      if (current && /^\t/.test(rawLine)) {
        current.recipes.push(rawLine.replace(/^\t[@+\-]*/, '').trim());
        continue;
      }
      if (rawLine.trim() && !/^\s*#/.test(rawLine)) current = null;
    }

    for (const target of targets) {
      const name = target.names.find((candidate) => verificationTarget.test(candidate));
      if (!name) continue;
      const command = target.recipes.find((recipe) => isCredibleVerificationCommand(recipe));
      if (!command) continue;
      return {
        id: 'verification-command',
        detail: `${name}: ${redactSensitiveText(command)}`,
        path: file.path
      };
    }
  }
  return null;
}

function isCredibleVerificationCommand(command) {
  if (typeof command !== 'string') return false;
  const value = command.trim();
  if (!value) return false;

  const noOp = /^(?:true|:|exit\s+0|(?:echo|printf)\b[^;&|]*|node\s+(?:--eval|-e)\s+["']?process\.exit\(0\);?["']?|(?:cmd\s+\/c\s+)?(?:ver|rem\b.*)|powershell(?:\.exe)?\s+-command\s+["']?exit\s+0["']?)$/i;
  if (noOp.test(value)) return false;

  const credible = [
    /(?:^|[;&|]\s*)node\s+--test(?:\s|$)/i,
    /(?:^|[;&|]\s*)(?:npm|pnpm|yarn|bun)(?:\s+run)?\s+(?:test|verify|check|ci|lint|typecheck)(?:\s|$)/i,
    /(?:^|[;&|]\s*)(?:vitest|jest|mocha|ava|tap|pytest|tox|ruff|mypy|eslint|tsc|shellcheck)(?:\s|$)/i,
    /(?:^|[;&|]\s*)uv\s+run\s+(?:pytest|tox|ruff|mypy|pyright|basedpyright)(?:\s|$)/i,
    /(?:^|[;&|]\s*)python(?:3)?\s+-m\s+pytest(?:\s|$)/i,
    /(?:^|[;&|]\s*)(?:cargo\s+test|go\s+test|dotnet\s+test|mvn(?:w)?\b[^;&|]*\btest\b|gradle(?:w)?\b[^;&|]*\btest\b)(?:\s|$)/i,
    /(?:^|[;&|]\s*)make\s+(?:test|verify|check|ci)(?:\s|$)/i,
    /(?:^|[;&|]\s*)(?:node|python(?:3)?|bash|sh|pwsh|powershell)\s+[^;&|]*(?:test|verify|check|ci)[^;&|]*\.(?:m?js|cjs|ts|py|sh|ps1)(?:\s|$)/i,
    /(?:^|[;&|]\s*)\.\/?[^;&|]*(?:test|verify|check|ci)[^;&|]*\.(?:m?js|cjs|ts|py|sh|ps1)(?:\s|$)/i
  ];
  return credible.some((pattern) => pattern.test(value));
}
function instructionSafeguard(snapshot, regex, id, detail, options = {}) {
  for (const file of snapshot.files) {
    if (!isAgentInstructionFile(file.path)) continue;
    const candidates = findEvidence(file, regex, { ruleId: id, severity: 'info' });
    for (const evidence of candidates) {
      const matchedLine = file.lines[evidence.startLine - 1] ?? '';
      if (options.rejectLine?.test(matchedLine)) continue;
      return { id, detail, path: file.path, evidence };
    }
  }
  return null;
}

export function evaluateRules(snapshot) {
  const charges = [];
  const safeguards = [];
  const operationalText = snapshot.files.filter(isOperationalSurface).map((file) => file.content).join('\n');

  const verification = packageVerification(snapshot)
    ?? makefileVerification(snapshot)
    ?? instructionSafeguard(snapshot, /\b(run|execute)\s+(npm\s+test|tests?|verification|verify)\b/i, 'verification-command', 'Instructions require verification before completion.');
  if (verification) safeguards.push(verification);

  const approval = instructionSafeguard(
    snapshot,
    /\b(explicit|human|manual)\s+approval\b|\bask\s+for\s+(human\s+)?approval\b/i,
    'human-approval',
    'Destructive work requires human approval.',
    {
      rejectLine: /\b(?:do\s+not|don't|never)\s+(?:ask\s+for|request|require|seek)\s+(?:explicit\s+|human\s+|manual\s+)*approval\b|\b(?:explicit\s+|human\s+|manual\s+)*approval\s+(?:is\s+)?not\s+required\b|\b(?:skip|bypass)\s+(?:the\s+)?(?:explicit\s+|human\s+|manual\s+)*approval\b/i
    }
  );
  if (approval) safeguards.push(approval);
  const allowlist = instructionSafeguard(snapshot, /\ballowlist(ed)?\b|\bleast\s+privilege\b/i, 'least-privilege', 'Instructions require least privilege or an allowlist.');
  if (allowlist) safeguards.push(allowlist);
  const secrets = instructionSafeguard(snapshot, /\bnever\s+(expose|print|log)\s+secrets?\b|\bsecret\s+redaction\b/i, 'secret-protection', 'Instructions prohibit secret exposure.');
  if (secrets) safeguards.push(secrets);

  for (const file of snapshot.files) {
    if (/(?:^|\/)package\.json$/i.test(file.path)) {
      const pkg = parseJson(file);
      for (const [name, command] of Object.entries(pkg?.scripts ?? {})) {
        if (/^(preinstall|install|postinstall|prepublish|prepare)$/i.test(name)
          && typeof command === 'string'
          && /(curl|wget|Invoke-WebRequest|node\s+-e|powershell|bash\s+-c|sh\s+-c|\|\s*(ba)?sh\b)/i.test(command)) {
          const evidence = findEvidence(file, new RegExp(`"${escapeRegex(name)}"\\s*:\\s*"[^"]+"`, 'i'), { ruleId: 'dangerous-lifecycle-script', severity: 'critical' });
          charges.push(charge('dangerous-lifecycle-script', 'proven', evidence, { rationale: `Lifecycle script ${name} invokes a high-risk installer path.` }));
        }
      }
    }

    if (isOperationalSurface(file)) {
      const pipe = findEvidence(file, /(?:curl|wget|Invoke-WebRequest)[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba)?sh\b/gi, { ruleId: 'pipe-to-shell', severity: 'critical' });
      if (pipe.length) charges.push(charge('pipe-to-shell', 'proven', pipe));
    }

    const looksLikeAgentSurface = isAgentCapabilitySurface(file);

    if (looksLikeAgentSurface) {
      const broad = findEvidence(
        file,
        /\b(?:Bash|Shell)\s*\(\s*\*\s*\)|\b(?:filesystem|network|shell|command)\s*:\s*\*{1,2}(?!\*)|["'](?:filesystem|network|shell|command):\*{1,2}["']|["'](?:permissions|tools|allow|capabilities)["']\s*[:=]\s*\[[\s\S]{0,500}?["']\*["']|["'](?:permissions|tools|allow|capabilities)["']\s*[:=][^\n\]]{0,240}["']\*["']/gi,
        { ruleId: 'broad-mcp-permissions', severity: 'high' }
      );
      if (broad.length) charges.push(charge('broad-mcp-permissions', 'proven', broad));

      const shell = findEvidence(
        file,
        /["']?shell["']?\s*[:=]\s*true\b|["']?command["']?\s*[:=]\s*(?:\[\s*)?["']?(?:bash|sh|zsh|powershell|pwsh|cmd(?:\.exe)?)["']?\b|\b(?:Bash|Shell)\s*\(\s*\*\s*\)|\bunrestricted\s+shell\b|\bany\s+shell\s+command\b/gi,
        { ruleId: 'unrestricted-shell-capability', severity: 'high' }
      );
      if (shell.length) charges.push(charge('unrestricted-shell-capability', 'proven', shell));

      const hasSecret = /["']?(?:env|secrets?)["']?\s*:|\$\{[A-Z][A-Z0-9_]{2,}\}|\b(?:API_KEY|TOKEN|SECRET|PASSWORD)\b/i.test(file.content);
      const egress = findEvidence(
        file,
        /["']?(?:egress|hosts?|domains?|network)["']?\s*[:=]\s*\[?\s*["']?(?:\*|\*\*|network:\*{1,2})["']?/gi,
        { ruleId: 'secret-to-egress-path', severity: 'high' }
      );
      if (hasSecret && egress.length) charges.push(charge('secret-to-egress-path', 'proven', egress));
    }

    if (isAgentInstructionFile(file.path)) {
      const override = findEvidence(file, /\bignore\s+(?:all\s+)?previous\s+instructions?\b|\boverride\s+(?:the\s+)?system\s+prompt\b|\brepository\s+instructions?\s+take\s+precedence\b/gi, { ruleId: 'prompt-boundary-override', severity: 'high' });
      if (override.length) charges.push(charge('prompt-boundary-override', 'proven', override));

      const completion = findEvidence(file, /\bmark\s+(?:the\s+)?(?:task|work)\s+complete\s+without\s+(?:running\s+)?tests?\b|\bdo\s+not\s+run\s+tests?\b|\bskip\s+(?:all\s+)?verification\b/gi, { ruleId: 'self-certified-completion', severity: 'high' });
      if (completion.length) charges.push(charge('self-certified-completion', 'proven', completion));
    }
  }

  if (!verification) charges.push(charge('missing-verification-evidence', 'proven', [], { rationale: 'No non-trivial test, verify, check, or CI command was found.' }));

  const hasDestructive = /\b(rm\s+-rf|format\s+[A-Z]:|drop\s+database|delete\s+repository|force\s+push|unrestricted\s+shell|any\s+shell\s+command)\b/i.test(operationalText)
    || charges.some((item) => item.ruleId === 'unrestricted-shell-capability' && item.status === 'proven');
  if (hasDestructive && !approval) charges.push(charge('destructive-without-approval', 'proven'));

  if (!snapshot.coverage.complete) {
    charges.push(charge('incomplete-scan-coverage', 'proven', [], {
      rationale: `${snapshot.coverage.omitted} inspectable-scope entries were omitted.`
    }));
  }

  return { charges: dedupeCharges(charges), safeguards };
}

function isAgentCapabilitySurface(file) {
  if (isAgentConfigFile(file.path) || isAgentInstructionFile(file.path)) return true;
  if (!/\.(?:json|ya?ml|toml)$/i.test(file.path)) return false;
  return /(?:^|\/|[._-])(?:agent|mcp|tool|permission|capabilit|setting|config|hook)(?:s|ies)?(?:[._\/-]|$)/i.test(file.path)
    && /\b(?:mcpServers|permissions|allowedCommands|capabilities|shell|command)\b/i.test(file.content);
}

function isOperationalSurface(file) {
  if (isAgentCapabilitySurface(file)) return true;
  if (/(?:^|\/)package\.json$/i.test(file.path)) return true;
  if (/\.(?:sh|bash|zsh|ps1|cmd|bat)$/i.test(file.path)) return true;
  return /(?:^|\/)(?:hooks?|scripts?|install|setup|bootstrap)(?:\/|[._-])/i.test(file.path)
    && /\.(?:m?js|cjs|ts|py)$/i.test(file.path);
}

function dedupeCharges(charges) {
  const map = new Map();
  for (const item of charges) {
    const existing = map.get(item.ruleId);
    if (!existing) map.set(item.ruleId, item);
    else {
      const fingerprints = new Set(existing.evidence.map((evidence) => evidence.fingerprint));
      for (const evidence of item.evidence) {
        if (!fingerprints.has(evidence.fingerprint)) existing.evidence.push(evidence);
      }
    }
  }
  return [...map.values()].sort((a, b) => a.ruleId.localeCompare(b.ruleId));
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
