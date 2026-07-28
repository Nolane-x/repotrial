import { spawn } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { sha256, stableStringify } from '../core/hash.mjs';
import { redactSensitiveText, redactSensitiveValues } from '../core/redact.mjs';
import { parseStructuredConfig } from '../core/structured.mjs';

const DEFAULT_OSV_URL = 'https://api.osv.dev/v1/querybatch';
const MAX_COMPONENTS = 20_000;

export async function analyzeSupplyChain(options = {}) {
  const root = path.resolve(options.root ?? process.cwd());
  const mode = String(options.mode ?? 'offline').toLowerCase();
  if (!['off', 'offline', 'osv'].includes(mode)) throw new Error('Supply-chain mode must be off, offline, or osv.');
  if (mode === 'off') return emptySupply('disabled');

  const inventory = await inventoryDependencies(root, options);
  const components = inventory.components.slice(0, boundedInteger(options.maxComponents, MAX_COMPONENTS, 1, 100_000));
  const vulnerabilities = mode === 'osv'
    ? await queryOsv(components, options)
    : [];
  const container = await analyzeContainer(root, options.container ?? {});
  const licenses = summarizeLicenses(components);
  const sbom = buildCycloneDx(components, { rootName: path.basename(root), sourceFiles: inventory.sourceFiles });
  return redactSensitiveValues({
    schemaVersion: 'repotrial.supply-chain.v1',
    status: 'completed',
    mode,
    components,
    vulnerabilities,
    licenses,
    images: inventory.images,
    container,
    sbom,
    diagnostics: inventory.diagnostics,
    truncatedComponents: Math.max(0, inventory.components.length - components.length)
  });
}

export async function inventoryDependencies(root, options = {}) {
  const components = [];
  const images = [];
  const diagnostics = [];
  const sourceFiles = [];
  const files = await findDependencyFiles(root, boundedInteger(options.maxLockfiles, 500, 1, 5000), normalizeIgnoredPaths(root, options.ignoredPaths ?? []));
  for (const file of files) {
    const relative = path.relative(root, file).split(path.sep).join('/');
    let content;
    try { content = await readFile(file, 'utf8'); } catch (error) {
      diagnostics.push({ path: relative, code: 'unreadable', message: error.message });
      continue;
    }
    try {
      const basename = path.basename(file);
      if (basename === 'package-lock.json' || basename === 'npm-shrinkwrap.json') components.push(...parsePackageLock(content, relative));
      else if (basename === 'pnpm-lock.yaml') components.push(...parsePnpmLock(content, relative));
      else if (basename === 'yarn.lock') components.push(...parseYarnLock(content, relative));
      else if (/^requirements(?:-[^.]+)?\.txt$/i.test(basename)) components.push(...parseRequirements(content, relative));
      else if (basename === 'poetry.lock' || basename === 'uv.lock') components.push(...parsePythonTomlLock(content, relative));
      else if (basename === 'Pipfile.lock') components.push(...parsePipfileLock(content, relative));
      else if (basename === 'Cargo.lock') components.push(...parseCargoLock(content, relative));
      else if (basename === 'go.sum') components.push(...parseGoSum(content, relative));
      else if (basename === 'composer.lock') components.push(...parseComposerLock(content, relative));
      else if (basename === 'Gemfile.lock') components.push(...parseGemfileLock(content, relative));
      else if (/^Dockerfile(?:\..+)?$/i.test(basename) || /\.dockerfile$/i.test(file)) images.push(...parseDockerfile(content, relative));
      sourceFiles.push(relative);
    } catch (error) {
      diagnostics.push({ path: relative, code: 'parse-error', message: redactSensitiveText(error.message) });
    }
  }
  const deduped = dedupeComponents(components);
  return { components: deduped, images: dedupeBy(images, (item) => `${item.name}@${item.tag ?? item.digest ?? ''}`), diagnostics, sourceFiles: [...new Set(sourceFiles)].sort() };
}

export function buildCycloneDx(components, options = {}) {
  const sorted = [...components].sort((a, b) => a.purl.localeCompare(b.purl));
  const bomComponents = sorted.map((component) => ({
    type: component.type ?? 'library',
    'bom-ref': component.purl,
    name: component.name,
    version: component.version,
    purl: component.purl,
    ...(component.licenses?.length ? { licenses: component.licenses.map((id) => ({ license: { id } })) } : {}),
    ...(component.hashes?.length ? { hashes: component.hashes } : {}),
    properties: [
      { name: 'repotrial:ecosystem', value: component.ecosystem },
      { name: 'repotrial:source-file', value: component.sourceFile },
      { name: 'repotrial:scope', value: component.scope ?? 'required' }
    ]
  }));
  const digest = sha256(stableStringify(bomComponents));
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      component: { type: 'application', name: options.rootName ?? 'repository', version: `sha256:${digest.slice(0, 16)}` },
      tools: { components: [{ type: 'application', name: 'RepoTrial', version: '0.4.2' }] },
      properties: (options.sourceFiles ?? []).map((value) => ({ name: 'repotrial:inventory-source', value }))
    },
    components: bomComponents
  };
}

export async function queryOsv(components, options = {}) {
  const url = new URL(options.osvUrl ?? DEFAULT_OSV_URL);
  if (url.protocol !== 'https:' && !isLoopback(url.hostname)) throw new Error('OSV URL must use HTTPS unless it is loopback.');
  const supported = components.filter((component) => component.osvEcosystem && component.name && component.version);
  const batchSize = boundedInteger(options.osvBatchSize, 100, 1, 1000);
  const findings = [];
  for (let index = 0; index < supported.length; index += batchSize) {
    const batch = supported.slice(index, index + batchSize);
    const body = { queries: batch.map((component) => ({ version: component.version, package: { name: component.name, ecosystem: component.osvEcosystem } })) };
    const response = await boundedFetchJson(url, body, {
      timeoutMs: boundedInteger(options.timeoutMs, 10_000, 250, 120_000),
      maxBytes: boundedInteger(options.maxOsvResponseBytes, 8 * 1024 * 1024, 1024, 64 * 1024 * 1024)
    });
    const results = Array.isArray(response.results) ? response.results : [];
    for (let offset = 0; offset < batch.length; offset += 1) {
      const component = batch[offset];
      for (const vuln of results[offset]?.vulns ?? []) {
        findings.push(normalizeOsvVulnerability(vuln, component));
      }
    }
  }
  return dedupeBy(findings, (item) => `${item.id}\0${item.component.purl}`).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id));
}

export async function analyzeContainer(root, options = {}) {
  if (!options.command) return { status: 'not-configured', provider: null, findings: [], diagnostics: [] };
  const command = String(options.command);
  const args = Array.isArray(options.args) ? options.args.map(String) : [];
  const result = await runProcess(command, args, { cwd: root, timeoutMs: boundedInteger(options.timeoutMs, 60_000, 250, 600_000), maxBytes: 16 * 1024 * 1024 });
  if (result.error) return { status: 'unavailable', provider: path.basename(command), findings: [], diagnostics: [{ code: 'spawn-error', message: redactSensitiveText(result.error) }] };
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch {
    return { status: 'error', provider: path.basename(command), findings: [], diagnostics: [{ code: 'invalid-json', message: redactSensitiveText(result.stderr || 'Scanner did not emit JSON.') }] };
  }
  return {
    status: result.exitCode === 0 || result.exitCode === 1 ? 'completed' : 'error',
    provider: detectContainerProvider(parsed, command),
    findings: normalizeContainerFindings(parsed),
    diagnostics: result.stderr ? [{ code: 'stderr', message: redactSensitiveText(result.stderr) }] : [],
    exitCode: result.exitCode,
    outputTruncated: result.truncated
  };
}

function parsePackageLock(content, sourceFile) {
  const parsed = JSON.parse(content);
  const result = [];
  if (parsed.packages && typeof parsed.packages === 'object') {
    for (const [location, item] of Object.entries(parsed.packages)) {
      if (!item || typeof item !== 'object' || !item.version) continue;
      const name = item.name ?? packageNameFromLocation(location);
      if (!name) continue;
      result.push(component({ ecosystem: 'npm', osvEcosystem: 'npm', name, version: String(item.version), license: item.license, integrity: item.integrity, sourceFile, scope: item.dev ? 'development' : 'required' }));
    }
  } else if (parsed.dependencies && typeof parsed.dependencies === 'object') {
    walkNpmDependencies(parsed.dependencies, result, sourceFile);
  }
  return result;
}

function walkNpmDependencies(dependencies, target, sourceFile) {
  for (const [name, item] of Object.entries(dependencies)) {
    if (!item || typeof item !== 'object' || !item.version) continue;
    target.push(component({ ecosystem: 'npm', osvEcosystem: 'npm', name, version: String(item.version), license: item.license, integrity: item.integrity, sourceFile, scope: item.dev ? 'development' : 'required' }));
    if (item.dependencies) walkNpmDependencies(item.dependencies, target, sourceFile);
  }
}

function parsePnpmLock(content, sourceFile) {
  const parsed = parseStructuredConfig(content, sourceFile);
  const packages = parsed.value?.packages;
  if (!packages || typeof packages !== 'object' || Array.isArray(packages)) return [];
  const result = [];
  for (const [rawKey, item] of Object.entries(packages)) {
    const key = String(rawKey).replace(/^\//, '').replace(/^['"]|['"]$/g, '');
    const match = /^(.*)@([^(@]+)(?:\([^)]*\))?$/.exec(key);
    if (!match || !match[1] || !match[2]) continue;
    result.push(component({ ecosystem: 'npm', osvEcosystem: 'npm', name: match[1], version: match[2], integrity: item?.resolution?.integrity ?? item?.integrity, sourceFile, scope: item?.dev ? 'development' : 'required' }));
  }
  return result;
}

function parseYarnLock(content, sourceFile) {
  const result = [];
  let selectors = [];
  let version = null;
  let integrity = null;
  const flush = () => {
    if (!version || !selectors.length) { selectors = []; version = null; integrity = null; return; }
    const selector = selectors[0].trim().replace(/^[\"']|[\"']$/g, '');
    const at = selector.startsWith('@') ? selector.indexOf('@', 1) : selector.indexOf('@');
    const name = at > 0 ? selector.slice(0, at) : selector;
    if (name) result.push(component({ ecosystem: 'npm', osvEcosystem: 'npm', name, version, integrity, sourceFile }));
    selectors = []; version = null; integrity = null;
  };
  for (const raw of `${content}\n`.split(/\r?\n/)) {
    if (/^[^\s#].*:\s*$/.test(raw)) { flush(); selectors = raw.slice(0, raw.lastIndexOf(':')).split(',').map((item) => item.trim()); continue; }
    const versionMatch = /^\s+version\s+[\"']([^\"']+)[\"']/.exec(raw);
    if (versionMatch) version = versionMatch[1];
    const integrityMatch = /^\s+integrity\s+(.+)$/.exec(raw);
    if (integrityMatch) integrity = integrityMatch[1].trim();
  }
  flush();
  return result;
}

function parsePythonTomlLock(content, sourceFile) {
  const parsed = parseStructuredConfig(content, sourceFile);
  const packages = Array.isArray(parsed.value?.package) ? parsed.value.package : [];
  return packages.filter((item) => item?.name && item?.version).map((item) => component({ ecosystem: 'pypi', osvEcosystem: 'PyPI', name: normalizePypi(item.name), version: String(item.version), license: item.license, sourceFile, scope: item.category === 'dev' || item.dev === true ? 'development' : 'required' }));
}

function parsePipfileLock(content, sourceFile) {
  const parsed = JSON.parse(content);
  const result = [];
  for (const [section, scope] of [['default', 'required'], ['develop', 'development']]) {
    for (const [name, value] of Object.entries(parsed[section] ?? {})) {
      const rawVersion = typeof value === 'string' ? value : value?.version;
      const version = String(rawVersion ?? '').replace(/^==/, '');
      if (version) result.push(component({ ecosystem: 'pypi', osvEcosystem: 'PyPI', name: normalizePypi(name), version, sourceFile, scope }));
    }
  }
  return result;
}

function parseComposerLock(content, sourceFile) {
  const parsed = JSON.parse(content);
  const result = [];
  for (const [key, scope] of [['packages', 'required'], ['packages-dev', 'development']]) {
    for (const item of parsed[key] ?? []) if (item?.name && item?.version) result.push(component({ ecosystem: 'composer', osvEcosystem: 'Packagist', name: item.name, version: String(item.version).replace(/^v/, ''), license: item.license, sourceFile, scope }));
  }
  return result;
}

function parseGemfileLock(content, sourceFile) {
  const result = [];
  let inSpecs = false;
  for (const line of content.split(/\r?\n/)) {
    if (/^\s{2}specs:\s*$/.test(line)) { inSpecs = true; continue; }
    if (inSpecs && /^\S/.test(line)) break;
    if (!inSpecs) continue;
    const match = /^\s{4}([^\s(]+) \(([^)]+)\)/.exec(line);
    if (match) result.push(component({ ecosystem: 'gem', osvEcosystem: 'RubyGems', name: match[1], version: match[2].split('-')[0], sourceFile }));
  }
  return result;
}

function parseRequirements(content, sourceFile) {
  const result = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    const match = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;]+)(?:\s*;.*)?$/.exec(line);
    if (!match) continue;
    result.push(component({ ecosystem: 'pypi', osvEcosystem: 'PyPI', name: normalizePypi(match[1]), version: match[2], sourceFile }));
  }
  return result;
}

function parseCargoLock(content, sourceFile) {
  const parsed = parseStructuredConfig(content, 'Cargo.toml');
  if (!parsed.value) return [];
  const packages = Array.isArray(parsed.value.package) ? parsed.value.package : [];
  return packages.filter((item) => item?.name && item?.version).map((item) => component({ ecosystem: 'cargo', osvEcosystem: 'crates.io', name: String(item.name), version: String(item.version), license: item.license, checksum: item.checksum, sourceFile }));
}

function parseGoSum(content, sourceFile) {
  const result = [];
  for (const line of content.split(/\r?\n/)) {
    const [name, version, digest] = line.trim().split(/\s+/);
    if (!name || !version || !digest || version.endsWith('/go.mod')) continue;
    result.push(component({ ecosystem: 'golang', osvEcosystem: 'Go', name, version, checksum: digest, sourceFile }));
  }
  return result;
}

function parseDockerfile(content, sourceFile) {
  const result = [];
  for (const match of content.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+\S+)?/gim)) {
    const reference = match[1];
    if (/^scratch$/i.test(reference)) { result.push({ name: 'scratch', tag: null, digest: null, sourceFile }); continue; }
    const [nameDigest, digest] = reference.split('@', 2);
    const lastSlash = nameDigest.lastIndexOf('/');
    const colon = nameDigest.lastIndexOf(':');
    const hasTag = colon > lastSlash;
    result.push({ name: hasTag ? nameDigest.slice(0, colon) : nameDigest, tag: hasTag ? nameDigest.slice(colon + 1) : 'latest', digest: digest ?? null, sourceFile });
  }
  return result;
}

function component(input) {
  const name = String(input.name);
  const version = String(input.version);
  const encodedName = encodeURIComponent(name).replace(/%40/gi, '@');
  const purl = `pkg:${input.ecosystem}/${encodedName}@${encodeURIComponent(version)}`;
  const licenses = normalizeLicenses(input.license);
  const hashes = [];
  if (input.integrity) {
    const match = /^([a-z0-9]+)-(.+)$/i.exec(String(input.integrity));
    if (match) hashes.push({ alg: match[1].toUpperCase().replace('SHA512', 'SHA-512').replace('SHA256', 'SHA-256'), content: match[2] });
  } else if (input.checksum) hashes.push({ alg: 'OTHER', content: String(input.checksum) });
  return {
    type: 'library', ecosystem: input.ecosystem, osvEcosystem: input.osvEcosystem, name, version, purl,
    sourceFile: input.sourceFile, scope: input.scope ?? 'required', licenses, hashes
  };
}

function normalizeLicenses(value) {
  if (typeof value === 'string' && value.trim()) return [value.trim()];
  if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
  return [];
}

function summarizeLicenses(components) {
  const observed = new Set();
  let unknownCount = 0;
  for (const component of components) {
    if (!component.licenses.length) unknownCount += 1;
    for (const license of component.licenses) observed.add(license);
  }
  return { observed: [...observed].sort(), unknownCount, componentCount: components.length };
}

function normalizeOsvVulnerability(vuln, component) {
  const scores = (vuln.severity ?? []).map((entry) => numericCvss(entry.score)).filter(Number.isFinite);
  const databaseSeverity = (vuln.database_specific?.severity ?? vuln.ecosystem_specific?.severity ?? '').toLowerCase();
  const score = scores.length ? Math.max(...scores) : null;
  return {
    id: String(vuln.id ?? 'UNKNOWN'),
    aliases: Array.isArray(vuln.aliases) ? vuln.aliases.map(String).slice(0, 50) : [],
    summary: redactSensitiveText(vuln.summary ?? vuln.details ?? 'Known vulnerability'),
    severity: score === null ? normalizeSeverity(databaseSeverity) : score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low',
    score,
    component: { name: component.name, version: component.version, purl: component.purl },
    modified: scalar(vuln.modified), published: scalar(vuln.published), withdrawn: scalar(vuln.withdrawn)
  };
}

function normalizeContainerFindings(parsed) {
  const result = [];
  if (Array.isArray(parsed.Results)) {
    for (const group of parsed.Results) for (const finding of group.Vulnerabilities ?? []) result.push({
      id: String(finding.VulnerabilityID ?? finding.ID ?? 'UNKNOWN'),
      package: String(finding.PkgName ?? finding.PackageName ?? ''),
      installedVersion: scalar(finding.InstalledVersion), fixedVersion: scalar(finding.FixedVersion),
      severity: normalizeSeverity(finding.Severity), title: redactSensitiveText(finding.Title ?? finding.Description ?? ''), target: scalar(group.Target)
    });
  }
  for (const match of parsed.matches ?? []) {
    const vulnerability = match.vulnerability ?? {};
    const artifact = match.artifact ?? {};
    result.push({ id: String(vulnerability.id ?? 'UNKNOWN'), package: String(artifact.name ?? ''), installedVersion: scalar(artifact.version), fixedVersion: scalar(vulnerability.fix?.versions?.[0]), severity: normalizeSeverity(vulnerability.severity), title: redactSensitiveText(vulnerability.description ?? ''), target: scalar(artifact.locations?.[0]?.path) });
  }
  if (parsed.version === '2.1.0' && Array.isArray(parsed.runs)) {
    for (const run of parsed.runs) for (const finding of run.results ?? []) result.push({ id: String(finding.ruleId ?? 'UNKNOWN'), package: '', installedVersion: null, fixedVersion: null, severity: sarifSeverity(finding.level), title: redactSensitiveText(finding.message?.text ?? ''), target: finding.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? null });
  }
  return dedupeBy(result, (item) => `${item.id}\0${item.package}\0${item.installedVersion ?? ''}`);
}

async function findDependencyFiles(root, maxFiles, ignoredPaths = []) {
  const names = /^(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|requirements(?:-[^.]+)?\.txt|poetry\.lock|uv\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock|Dockerfile(?:\..+)?|.+\.dockerfile)$/i;
  const result = [];
  async function walk(directory) {
    if (result.length >= maxFiles) return;
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (result.length >= maxFiles || entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      if (isIgnoredPath(absolute, ignoredPaths)) continue;
      if (entry.isDirectory()) {
        if (['.git', 'node_modules', '.repotrial', 'dist', 'build', 'vendor', '.venv'].includes(entry.name)) continue;
        await walk(absolute);
      } else if (entry.isFile() && names.test(entry.name)) result.push(absolute);
    }
  }
  await walk(root);
  return result.sort();
}

async function boundedFetchJson(url, payload, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(payload), signal: controller.signal, redirect: 'error' });
    if (!response.ok) throw new Error(`OSV query failed with HTTP ${response.status}.`);
    const reader = response.body.getReader();
    const chunks = [];
    let bytes = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (bytes > options.maxBytes) { await reader.cancel(); throw new Error('OSV response exceeded the configured byte limit.'); }
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally { clearTimeout(timer); }
}

function runProcess(command, args, options) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: options.cwd, env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LANG: 'C' }, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = Buffer.alloc(0); let stderr = Buffer.alloc(0); let truncated = false; let error = null;
    const append = (target, chunk) => { const remaining = options.maxBytes - target.length; if (remaining <= 0) { truncated = true; return target; } if (chunk.length > remaining) truncated = true; return Buffer.concat([target, chunk.subarray(0, remaining)]); };
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.on('error', (caught) => { error = caught.message; });
    const timer = setTimeout(() => child.kill('SIGKILL'), options.timeoutMs);
    child.on('close', (exitCode) => { clearTimeout(timer); resolve({ exitCode, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8'), truncated, error }); });
  });
}

function packageNameFromLocation(location) { const marker = 'node_modules/'; const index = location.lastIndexOf(marker); return index >= 0 ? location.slice(index + marker.length) : null; }
function normalizePypi(name) { return String(name).toLowerCase().replace(/[_.-]+/g, '-'); }
function numericCvss(value) {
  const text = String(value ?? '');
  const direct = Number(text);
  if (Number.isFinite(direct)) return direct;
  if (/^CVSS:3\.[01]\//.test(text)) return cvssV3BaseScore(text);
  return Number.NaN;
}

export function cvssV3BaseScore(vector) {
  const metrics = Object.fromEntries(String(vector).split('/').slice(1).map((part) => part.split(':', 2)));
  const lookup = (name, values) => values[metrics[name]];
  const av = lookup('AV', { N: .85, A: .62, L: .55, P: .2 });
  const ac = lookup('AC', { L: .77, H: .44 });
  const ui = lookup('UI', { N: .85, R: .62 });
  const scope = metrics.S;
  const pr = scope === 'C' ? lookup('PR', { N: .85, L: .68, H: .5 }) : lookup('PR', { N: .85, L: .62, H: .27 });
  const c = lookup('C', { H: .56, L: .22, N: 0 });
  const i = lookup('I', { H: .56, L: .22, N: 0 });
  const a = lookup('A', { H: .56, L: .22, N: 0 });
  if (![av, ac, ui, pr, c, i, a].every(Number.isFinite) || !['U', 'C'].includes(scope)) return Number.NaN;
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  const impact = scope === 'U' ? 6.42 * iss : 7.52 * (iss - .029) - 3.25 * Math.pow(iss - .02, 15);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const score = scope === 'U' ? Math.min(impact + exploitability, 10) : Math.min(1.08 * (impact + exploitability), 10);
  return Math.ceil((score - 1e-10) * 10) / 10;
}
function normalizeSeverity(value) { const text = String(value ?? '').toLowerCase(); if (text.includes('critical')) return 'critical'; if (text.includes('high')) return 'high'; if (text.includes('moderate') || text.includes('medium')) return 'medium'; if (text.includes('low')) return 'low'; return 'unknown'; }
function sarifSeverity(value) { return value === 'error' ? 'high' : value === 'warning' ? 'medium' : 'low'; }
function severityRank(value) { return ({ critical: 4, high: 3, medium: 2, low: 1, unknown: 0 })[value] ?? 0; }
function detectContainerProvider(parsed, command) { if (Array.isArray(parsed.Results)) return 'trivy'; if (Array.isArray(parsed.matches)) return 'grype'; if (parsed.version === '2.1.0') return 'sarif'; return path.basename(command); }
function scalar(value) { return ['string', 'number', 'boolean'].includes(typeof value) ? String(value) : null; }
function isLoopback(hostname) { return ['localhost', '127.0.0.1', '::1', '[::1]'].includes(hostname); }
function dedupeComponents(items) { return dedupeBy(items, (item) => item.purl).sort((a, b) => a.purl.localeCompare(b.purl)); }
function dedupeBy(items, keyFor) { const seen = new Set(); return items.filter((item) => { const key = keyFor(item); if (seen.has(key)) return false; seen.add(key); return true; }); }
function boundedInteger(value, fallback, min, max) { const number = Number(value ?? fallback); return Number.isInteger(number) ? Math.min(max, Math.max(min, number)) : fallback; }
function emptySupply(status) { return { schemaVersion: 'repotrial.supply-chain.v1', status, mode: 'off', components: [], vulnerabilities: [], licenses: { observed: [], unknownCount: 0, componentCount: 0 }, images: [], container: { status: 'not-configured', provider: null, findings: [], diagnostics: [] }, sbom: null, diagnostics: [], truncatedComponents: 0 }; }


function normalizeIgnoredPaths(root, values) {
  return (Array.isArray(values) ? values : [values])
    .filter((value) => value != null && value !== '')
    .map((value) => path.resolve(root, String(value)));
}

function isIgnoredPath(filename, ignoredPaths) {
  const absolute = path.resolve(filename);
  return ignoredPaths.some((ignored) => absolute === ignored || absolute.startsWith(`${ignored}${path.sep}`));
}
