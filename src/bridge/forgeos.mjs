import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const SEVERITY_ORDER = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });
const VALID_DEPTHS = new Set(['security', 'full']);

export async function runForgeOsBridge(manifest, options = {}) {
  const mode = options.mode ?? 'auto';
  if (mode === 'off') return bridgeResult('disabled', 'off', []);
  if (mode === 'http') return runHttpBridge(manifest, options);
  if (mode === 'cli') return runForgeOsCli(manifest, options);
  if (mode !== 'auto') return bridgeResult('error', mode, [], `Unsupported ForgeOS mode: ${mode}`);

  if (options.url || process.env.FORGEOS_BRIDGE_URL) {
    const httpResult = await runHttpBridge(manifest, options);
    if (httpResult.status === 'ok') return httpResult;
  }
  return runForgeOsCli(manifest, options);
}

export async function runForgeOsCli(manifest, options = {}) {
  const depth = normalizeDepth(options.depth);
  if (!depth) return bridgeResult('error', 'cli', [], `Unsupported ForgeOS depth: ${options.depth}`);

  const timeoutMs = boundedNumber(options.timeoutMs, 15_000, 100, 120_000);
  const maxOutputBytes = boundedNumber(options.maxOutputBytes, 2 * 1024 * 1024, 1024, 10 * 1024 * 1024);
  const invocation = resolveForgeInvocation(options);
  const directory = await mkdtemp(path.join(tmpdir(), 'repotrial-forgeos-'));
  const manifestPath = path.join(directory, 'agent-surface.json');
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });

  try {
    const scanExecution = await runForgeCommand(invocation, ['security', 'scan', '--file', manifestPath, '--json'], {
      timeoutMs,
      maxOutputBytes
    });
    if (scanExecution.unavailable) return bridgeResult('unavailable', 'cli', [], scanExecution.error);
    if (scanExecution.timedOut) return bridgeResult('timeout', 'cli', [], `ForgeOS exceeded ${timeoutMs}ms.`);

    const scanParsed = parseJsonOutput(scanExecution.stdout);
    const security = normalizeSecurityReport(scanParsed);
    const acceptedExit = scanExecution.code === 0 || scanExecution.code === 2;
    if (!acceptedExit || !security) {
      return bridgeResult('error', 'cli', [], truncate(scanExecution.stderr || scanExecution.stdout, 1000) || 'ForgeOS did not return a valid security report.', {
        exitCode: scanExecution.code,
        outputTruncated: Boolean(scanExecution.truncated)
      });
    }

    const findings = normalizeForgeOsFindings(security.findings);
    let engine;
    let remediationRoute;
    const enrichmentErrors = [];

    if (depth === 'full') {
      const statusExecution = await runForgeCommand(invocation, ['v06', 'status', '--json'], { timeoutMs, maxOutputBytes });
      const statusParsed = parseJsonOutput(statusExecution.stdout);
      if (statusExecution.code === 0 && statusParsed?.status) engine = normalizeEngineStatus(statusParsed.status);
      else enrichmentErrors.push(`v06 status: ${compactExecutionError(statusExecution)}`);

      const routeQuery = buildRouteQuery(security.findings);
      const routeExecution = await runForgeCommand(invocation, [
        'route', '--query', routeQuery,
        '--assurance', 'A1',
        '--operation', 'code-review',
        '--task-class', 'security',
        '--json'
      ], { timeoutMs, maxOutputBytes });
      const routeParsed = parseJsonOutput(routeExecution.stdout);
      if ((routeExecution.code === 0 || routeExecution.code === 2) && routeParsed?.routePlan) {
        remediationRoute = normalizeRoutePlan(routeParsed.routePlan);
      } else enrichmentErrors.push(`route: ${compactExecutionError(routeExecution)}`);
    }

    return bridgeResult('ok', 'cli', findings, undefined, {
      exitCode: scanExecution.code,
      outputTruncated: Boolean(scanExecution.truncated),
      depth,
      ...(enrichmentErrors.length ? { enrichmentErrors } : {})
    }, {
      security,
      ...(engine ? { engine } : {}),
      ...(remediationRoute ? { remediationRoute } : {})
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export async function probeForgeOsCli(options = {}) {
  const invocation = resolveForgeInvocation(options);
  const timeoutMs = boundedNumber(options.timeoutMs, 5_000, 100, 30_000);
  const execution = await runForgeCommand(invocation, ['v06', 'status', '--json'], {
    timeoutMs,
    maxOutputBytes: boundedNumber(options.maxOutputBytes, 512 * 1024, 1024, 2 * 1024 * 1024)
  });
  if (execution.unavailable) return { status: 'unavailable', error: execution.error };
  if (execution.timedOut) return { status: 'timeout', error: `ForgeOS exceeded ${timeoutMs}ms.` };
  const parsed = parseJsonOutput(execution.stdout);
  if (execution.code !== 0 || !parsed?.status) {
    return { status: 'error', error: compactExecutionError(execution) };
  }
  return { status: 'ready', engine: normalizeEngineStatus(parsed.status) };
}

async function runHttpBridge(manifest, options) {
  const baseUrl = options.url ?? process.env.FORGEOS_BRIDGE_URL;
  if (!baseUrl) return bridgeResult('unavailable', 'http', [], 'ForgeOS bridge URL is not configured.');
  const depth = normalizeDepth(options.depth);
  if (!depth) return bridgeResult('error', 'http', [], `Unsupported ForgeOS depth: ${options.depth}`);
  const validatedUrl = validateBridgeUrl(baseUrl, options.allowInsecureRemote === true);
  if (validatedUrl.error) return bridgeResult('error', 'http', [], validatedUrl.error);
  const url = new URL('/v1/scan', validatedUrl.url);
  const timeoutMs = boundedNumber(options.timeoutMs, 15_000, 100, 120_000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = { 'content-type': 'application/json', accept: 'application/json' };
    const token = options.token ?? process.env.REPOTRIAL_BRIDGE_TOKEN;
    if (token) headers.authorization = `Bearer ${token}`;
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ schemaVersion: 'repotrial.forgeos.bridge.v1', manifest, depth }),
      signal: controller.signal
    });
    const text = await response.text();
    if (text.length > 2 * 1024 * 1024) return bridgeResult('error', 'http', [], 'ForgeOS bridge response exceeded 2 MiB.');
    if (!response.ok) return bridgeResult('error', 'http', [], `ForgeOS bridge returned HTTP ${response.status}: ${truncate(text, 500)}`);
    let parsed;
    try { parsed = JSON.parse(text); } catch {
      return bridgeResult('error', 'http', [], 'ForgeOS bridge returned invalid JSON.');
    }
    const protocolError = validateBridgeResponse(parsed);
    if (protocolError) return bridgeResult('error', 'http', [], protocolError);

    const security = parsed.security === undefined ? undefined : normalizeSecurityReport(parsed.security);
    if (parsed.security !== undefined && !security) {
      return bridgeResult('error', 'http', [], 'ForgeOS bridge protocol security report is invalid.');
    }
    const engine = parsed.engine === undefined ? undefined : normalizeEngineStatus(parsed.engine);
    const remediationRoute = parsed.remediationRoute === undefined ? undefined : normalizeRoutePlan(parsed.remediationRoute);

    return bridgeResult(parsed.status, 'http', normalizeForgeOsFindings(parsed.findings), parsed.error,
      boundedJsonValue({ ...(parsed.diagnostics ?? {}), depth }),
      {
        ...(security ? { security } : {}),
        ...(engine ? { engine } : {}),
        ...(remediationRoute ? { remediationRoute } : {})
      });
  } catch (error) {
    if (error?.name === 'AbortError') return bridgeResult('timeout', 'http', [], `ForgeOS bridge exceeded ${timeoutMs}ms.`);
    return bridgeResult('unavailable', 'http', [], error instanceof Error ? error.message : String(error));
  } finally {
    clearTimeout(timer);
  }
}

export function normalizeForgeOsFindings(payload) {
  const candidates = [];
  walk(payload, (value) => {
    if (!isPlainObject(value)) return;
    const severity = normalizeSeverity(value.severity ?? value.level ?? value.risk);
    const title = boundedString(value.title ?? value.message ?? value.name ?? value.rule);
    const id = boundedString(value.id ?? value.ruleId ?? value.code);
    const location = boundedString(value.path ?? value.file) || (isPlainObject(value.location) ? boundedString(value.location.path ?? value.location.file) : boundedString(value.location));
    if (severity && title && (id || location)) candidates.push(value);
  });

  const seen = new Set();
  const normalized = [];
  for (const item of candidates) {
    const locationObject = isPlainObject(item.location) ? item.location : {};
    const locationText = boundedString(item.location) ?? '';
    const finding = {
      id: boundedString(item.id ?? item.ruleId ?? item.code) ?? `forgeos-${normalized.length + 1}`,
      source: 'forgeos',
      severity: normalizeSeverity(item.severity ?? item.level ?? item.risk) ?? 'medium',
      title: boundedString(item.title ?? item.message ?? item.name ?? item.rule) ?? 'Untitled ForgeOS finding',
      description: boundedString(item.description ?? item.detail ?? item.rationale) ?? '',
      path: boundedString(item.path ?? item.file ?? locationObject.path ?? locationObject.file) ?? locationText,
      line: positiveInteger(item.line ?? item.startLine ?? locationObject.line ?? locationObject.startLine),
      remediation: boundedString(item.remediation ?? item.fix ?? item.recommendation) ?? '',
      code: boundedString(item.code ?? item.ruleId) ?? ''
    };
    const key = `${finding.id}\0${finding.path}\0${finding.line}\0${finding.title}`;
    if (!seen.has(key)) {
      seen.add(key);
      normalized.push(finding);
    }
  }
  return normalized.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id));
}

function normalizeSecurityReport(parsed) {
  const report = parsed?.report ?? parsed;
  if (!report || !Array.isArray(report.findings) || !['pass', 'review-required', 'blocked'].includes(report.status)) return null;
  return {
    schemaVersion: primitiveValue(report.schemaVersion) ?? 1,
    status: report.status,
    findings: normalizeForgeOsFindings(report.findings),
    summary: normalizeSummary(report.summary),
    reportSha256: typeof report.reportSha256 === 'string' ? truncate(report.reportSha256, 256) : null
  };
}

function normalizeEngineStatus(status) {
  const source = isPlainObject(status) ? status : {};
  const adversarial = isPlainObject(source.agentSurfaceAdversarial) ? source.agentSurfaceAdversarial : null;
  return {
    version: boundedString(source.version) ?? 'unknown',
    executionGraphVersion: primitiveValue(source.executionGraphVersion),
    kernelTechniqueCount: positiveInteger(source.kernelTechniqueCount) ?? positiveInteger(source.techniqueCount),
    l0TechniqueCount: positiveInteger(source.l0TechniqueCount),
    l1TechniqueCount: positiveInteger(source.l1TechniqueCount),
    outcomeCount: positiveInteger(source.outcomeCount),
    evaluatorCount: positiveInteger(source.evaluatorCount),
    agentSurfaceAdversarial: adversarial ? {
      cases: positiveInteger(adversarial.cases),
      passed: positiveIntegerOrZero(adversarial.passed),
      missed: positiveIntegerOrZero(adversarial.missed),
      reportSha256: boundedString(adversarial.reportSha256)
    } : null,
    statusSha256: boundedString(source.statusSha256)
  };
}

function normalizeRoutePlan(routePlan) {
  const steps = Array.isArray(routePlan?.steps) ? routePlan.steps.slice(0, 100) : [];
  return {
    schemaVersion: primitiveValue(routePlan?.schemaVersion),
    targetOutcomeIds: boundedArray(routePlan?.intent?.targetOutcomeIds),
    steps: steps.filter((step) => step && typeof step === 'object' && !Array.isArray(step)).map((step) => ({
      stepId: boundedString(step.stepId),
      techniqueId: boundedString(step.techniqueId),
      providerId: boundedString(step.providerId),
      outcomeIds: boundedArray(step.outcomeIds),
      dependsOn: boundedArray(step.dependsOn),
      score: primitiveValue(step.score),
      sections: boundedArray(step.sections),
      evidenceObligations: normalizeArrayValue(step.evidenceObligations)
    })),
    blockers: normalizeArrayValue(routePlan?.blockers),
    executionGroups: normalizeArrayValue(routePlan?.executionGroups)
  };
}

function normalizeSummary(value) {
  const normalized = boundedJsonValue(value ?? {});
  if (normalized && typeof normalized === 'object' && !Array.isArray(normalized)) return normalized;
  return { value: normalized };
}

function normalizeArrayValue(value) {
  const normalized = boundedJsonValue(Array.isArray(value) ? value : []);
  return Array.isArray(normalized) ? normalized : [];
}

function boundedArray(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 100).map((item) => {
    const primitive = primitiveValue(item);
    return primitive === null ? '[TRUNCATED]' : typeof primitive === 'string' ? truncate(primitive, 1024) : primitive;
  });
}

function boundedString(value) {
  const primitive = primitiveValue(value);
  return primitive === null || primitive === undefined ? null : truncate(String(primitive), 1024);
}

function boundedJsonValue(value, options = {}) {
  const maxDepth = boundedNumber(options.maxDepth, 6, 1, 20);
  const maxArrayItems = boundedNumber(options.maxArrayItems, 100, 1, 1000);
  const maxObjectKeys = boundedNumber(options.maxObjectKeys, 100, 1, 1000);
  const maxStringLength = boundedNumber(options.maxStringLength, 4096, 64, 65_536);
  const seen = new WeakSet();

  function clone(current, depth) {
    if (current === null || current === undefined) return current ?? null;
    if (typeof current === 'string') return truncate(current, maxStringLength);
    if (typeof current === 'number') return Number.isFinite(current) ? current : null;
    if (typeof current === 'boolean') return current;
    if (typeof current === 'bigint') return String(current);
    if (typeof current !== 'object') return String(current);
    if (depth >= maxDepth) return '[TRUNCATED]';
    if (seen.has(current)) return '[CIRCULAR]';
    seen.add(current);

    if (Array.isArray(current)) {
      const result = current.slice(0, maxArrayItems).map((item) => clone(item, depth + 1));
      if (current.length > maxArrayItems) result.push(`[TRUNCATED ${current.length - maxArrayItems} ITEMS]`);
      return result;
    }

    const result = {};
    const entries = Object.entries(current).slice(0, maxObjectKeys);
    for (const [key, item] of entries) result[truncate(key, 256)] = clone(item, depth + 1);
    if (Object.keys(current).length > maxObjectKeys) result.__truncatedKeys = true;
    return result;
  }

  return clone(value, 0);
}

function primitiveValue(value) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  return null;
}

function buildRouteQuery(findings = []) {
  const topics = [...new Set(findings.map((finding) => finding.code ?? finding.id ?? finding.message).filter(Boolean))].slice(0, 12);
  return topics.length
    ? `Review and remediate AI agent repository security findings: ${topics.join(', ')}`
    : 'Verify an AI agent repository security surface and produce evidence-backed release remediation';
}

function resolveForgeInvocation(options) {
  const forgeRoot = options.forgeRoot ?? process.env.FORGEOS_ROOT;
  if (forgeRoot) {
    const resolvedRoot = path.resolve(forgeRoot);
    return {
      command: process.execPath,
      prefixArgs: [path.join(resolvedRoot, 'src', 'cli', 'forge.mjs')],
      cwd: options.cwd ?? resolvedRoot
    };
  }
  return {
    command: options.forgeBin ?? process.env.FORGEOS_BIN ?? 'forge',
    prefixArgs: [],
    cwd: options.cwd
  };
}

function runForgeCommand(invocation, args, options) {
  return spawnBounded(invocation.command, [...invocation.prefixArgs, ...args], {
    cwd: invocation.cwd,
    timeoutMs: options.timeoutMs,
    maxOutputBytes: options.maxOutputBytes
  });
}

function walk(value, visit) {
  const stack = [value];
  const seen = new WeakSet();
  let visited = 0;
  while (stack.length && visited < 100_000) {
    const current = stack.pop();
    visit(current);
    visited += 1;
    if (!current || typeof current !== 'object') continue;
    if (seen.has(current)) continue;
    seen.add(current);
    const children = Array.isArray(current) ? current : Object.values(current);
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
  }
}

function validateBridgeUrl(baseUrl, allowInsecureRemote) {
  let url;
  try { url = new URL(baseUrl); } catch {
    return { error: 'ForgeOS bridge URL is invalid.' };
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { error: 'ForgeOS bridge URL must use http or https.' };
  }
  if (url.username || url.password || url.hash) {
    return { error: 'ForgeOS bridge URL must not contain credentials or a fragment.' };
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const loopback = hostname === 'localhost' || hostname === '::1' || /^127(?:\.\d{1,3}){3}$/.test(hostname);
  if (url.protocol === 'http:' && !loopback && !allowInsecureRemote) {
    return { error: 'Plaintext ForgeOS HTTP is restricted to loopback. Use HTTPS or explicitly allow insecure remote HTTP.' };
  }
  return { url };
}

function validateBridgeResponse(payload) {
  if (!isPlainObject(payload)) return 'ForgeOS bridge protocol response must be an object.';
  if (payload.schemaVersion !== 'repotrial.forgeos.bridge.v1') return 'ForgeOS bridge protocol schemaVersion mismatch.';
  if (!['ok', 'disabled', 'unavailable', 'timeout', 'error'].includes(payload.status)) return 'ForgeOS bridge protocol status is invalid.';
  if (!['off', 'cli', 'http'].includes(payload.mode)) return 'ForgeOS bridge protocol mode is invalid.';
  if (!Array.isArray(payload.findings)) return 'ForgeOS bridge protocol findings must be an array.';
  if (payload.error !== undefined && typeof payload.error !== 'string') return 'ForgeOS bridge protocol error must be a string.';
  if (payload.diagnostics !== undefined && !isPlainObject(payload.diagnostics)) return 'ForgeOS bridge protocol diagnostics must be an object.';
  if (payload.security !== undefined && !isPlainObject(payload.security)) return 'ForgeOS bridge protocol security enrichment must be an object.';
  if (payload.engine !== undefined && !isPlainObject(payload.engine)) return 'ForgeOS bridge protocol engine enrichment must be an object.';
  if (payload.remediationRoute !== undefined && !isPlainObject(payload.remediationRoute)) return 'ForgeOS bridge protocol remediationRoute enrichment must be an object.';
  return null;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalizeSeverity(value) {
  const primitive = primitiveValue(value);
  if (primitive === undefined || primitive === null) return null;
  const text = String(primitive).toLowerCase();
  if (SEVERITIES.has(text)) return text;
  if (['error', 'fatal', 'blocker'].includes(text)) return 'critical';
  if (['warning', 'warn', 'major'].includes(text)) return 'high';
  if (['moderate', 'minor'].includes(text)) return 'medium';
  return null;
}

function spawnBounded(command, args, options) {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = '';
    let stderr = '';
    let truncatedOutput = false;
    let child;
    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        env: { ...process.env, NO_COLOR: '1' },
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (error) {
      resolve({ unavailable: true, error: error.message, code: null, stdout, stderr });
      return;
    }

    const timer = setTimeout(() => {
      if (settled) return;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 250).unref();
      settled = true;
      resolve({ timedOut: true, code: null, stdout, stderr, truncated: truncatedOutput });
    }, options.timeoutMs);

    const append = (target, chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = options.maxOutputBytes - Buffer.byteLength(target);
      if (remaining <= 0) return { value: target, truncated: true };
      const slice = buffer.subarray(0, remaining).toString('utf8');
      return { value: target + slice, truncated: buffer.length > remaining };
    };

    child.stdout.on('data', (chunk) => {
      const result = append(stdout, chunk);
      stdout = result.value;
      truncatedOutput ||= result.truncated;
    });
    child.stderr.on('data', (chunk) => {
      const result = append(stderr, chunk);
      stderr = result.value;
      truncatedOutput ||= result.truncated;
    });
    child.on('error', (error) => {
      if (settled) return;
      clearTimeout(timer);
      settled = true;
      resolve({ unavailable: error.code === 'ENOENT', error: error.message, code: null, stdout, stderr });
    });
    child.on('close', (code) => {
      if (settled) return;
      clearTimeout(timer);
      settled = true;
      resolve({ code, stdout, stderr, truncated: truncatedOutput });
    });
  });
}

function parseJsonOutput(text) {
  try { return JSON.parse(text); } catch {}
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try { return JSON.parse(text.slice(start, end + 1)); } catch {}
  }
  return null;
}

function bridgeResult(status, mode, findings, error, diagnostics = {}, additions = {}) {
  return {
    schemaVersion: 'repotrial.forgeos.bridge.v1',
    status,
    mode,
    findings,
    ...(error ? { error } : {}),
    diagnostics,
    ...additions
  };
}

function compactExecutionError(execution) {
  if (execution?.unavailable) return execution.error ?? 'unavailable';
  if (execution?.timedOut) return 'timeout';
  return truncate(execution?.stderr || execution?.stdout || `exit ${execution?.code}`, 500);
}

function truncate(value, max) {
  const text = String(value ?? '');
  return text.length <= max ? text : `${text.slice(0, max)}…`;
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

function positiveInteger(value) {
  const primitive = primitiveValue(value);
  if (primitive === null || primitive === undefined || typeof primitive === 'boolean') return null;
  const number = Number(primitive);
  return Number.isInteger(number) && number > 0 ? number : null;
}

function positiveIntegerOrZero(value) {
  const primitive = primitiveValue(value);
  if (primitive === null || primitive === undefined || typeof primitive === 'boolean') return null;
  const number = Number(primitive);
  return Number.isInteger(number) && number >= 0 ? number : null;
}

function normalizeDepth(value) {
  const depth = String(value ?? 'security').toLowerCase();
  return VALID_DEPTHS.has(depth) ? depth : null;
}
