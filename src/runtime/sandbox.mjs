import { spawn } from 'node:child_process';
import { access, cp, lstat, mkdir, mkdtemp, readFile, readdir, readlink, rm, symlink, writeFile } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { sha256 } from '../core/hash.mjs';
import { discoverRepository } from '../core/discover.mjs';
import { redactSensitiveText, redactSensitiveValues } from '../core/redact.mjs';
import { parseStructuredConfig } from '../core/structured.mjs';
import { isAgentConfigFile } from '../core/surfaces.mjs';
import { validateExperimentScenario } from '../experiments/templates.mjs';

const LIFECYCLE = new Set(['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly']);
const DEFAULT_TIMEOUT = 10_000;
const MAX_OUTPUT_BYTES = 256 * 1024;
const NAMESPACE_FLAGS = [
  '--user', '--map-root-user', '--mount', '--uts', '--ipc', '--net', '--pid', '--cgroup',
  '--propagation', 'private', '--fork', '--kill-child'
];

export async function probeRuntimeSandbox() {
  if (process.platform !== 'linux') return { status: 'unavailable', reason: 'linux-required' };
  for (const binary of ['/usr/bin/unshare', '/bin/unshare']) {
    try {
      await access(binary, fsConstants.X_OK);
      const result = await runProcess(binary, [...NAMESPACE_FLAGS, '/bin/true'], { timeoutMs: 2_000 });
      if (result.exitCode === 0) return { status: 'ready', provider: 'linux-userns-chroot', unshare: binary };
      return { status: 'unavailable', reason: redactSensitiveText(result.stderr || `unshare-exit-${result.exitCode}`) };
    } catch { /* continue */ }
  }
  return { status: 'unavailable', reason: 'unshare-not-found' };
}

export async function runRuntimeAnalysis(options = {}) {
  const root = path.resolve(options.root ?? process.cwd());
  const mode = String(options.mode ?? 'off').toLowerCase();
  if (mode === 'off') return emptyRuntime('disabled', 'runtime-disabled');
  if (!['auto', 'sandbox'].includes(mode)) throw new Error('Runtime mode must be off, auto, or sandbox.');

  const ignoredPaths = normalizeIgnoredPaths(root, options.ignoredPaths ?? []);
  const candidates = await discoverRuntimeCandidates(root, options.scripts ?? [], options.snapshot, { ignoredPaths });
  if (!candidates.length) return emptyRuntime('skipped', 'no-runtime-candidates');
  const workspace = await inspectRuntimeWorkspace(root, {
    ignoredPaths,
    maxFiles: boundedInteger(options.maxSourceFiles, 20_000, 1, 1_000_000),
    maxBytes: boundedInteger(options.maxSourceBytes, 256 * 1024 * 1024, 1, 4 * 1024 * 1024 * 1024)
  });
  if (workspace.limitExceeded) return { ...emptyRuntime('unavailable', 'source-copy-limit'), candidates, workspace };
  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') return { ...emptyRuntime('unavailable', probe.reason), candidates };

  const maxRuns = boundedInteger(options.maxRuns, 4, 1, 16);
  const runs = [];
  for (const candidate of candidates.slice(0, maxRuns)) {
    runs.push(await detonateCandidate(root, candidate, {
      unshare: probe.unshare,
      timeoutMs: boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT, 250, 120_000),
      maxOutputBytes: boundedInteger(options.maxOutputBytes, MAX_OUTPUT_BYTES, 1024, 4 * 1024 * 1024),
      ignoredPaths,
      scenarioEnv: {},
      sentinelPaths: []
    }));
  }
  return redactSensitiveValues({
    schemaVersion: 'repotrial.runtime.v1',
    status: 'completed',
    provider: probe.provider,
    isolation: readyIsolation(),
    workspace,
    candidates,
    runs,
    truncatedCandidates: Math.max(0, candidates.length - runs.length)
  });
}

export async function runRuntimeScenario(options = {}) {
  const scenario = validateExperimentScenario(options.scenario ?? {});
  const root = path.resolve(options.root ?? process.cwd());
  const candidate = normalizeScenarioCandidate(options.candidate);
  const ignoredPaths = normalizeIgnoredPaths(root, options.ignoredPaths ?? []);
  const workspace = await inspectRuntimeWorkspace(root, {
    ignoredPaths,
    maxFiles: boundedInteger(options.maxSourceFiles, 20_000, 1, 1_000_000),
    maxBytes: boundedInteger(options.maxSourceBytes, 256 * 1024 * 1024, 1, 4 * 1024 * 1024 * 1024)
  });
  if (workspace.limitExceeded) {
    return {
      schemaVersion: 'repotrial.runtime-scenario.v1',
      status: 'unavailable',
      provider: null,
      reason: 'source-copy-limit',
      isolation: unavailableIsolation(),
      workspace,
      scenario,
      candidate: redactSensitiveValues(candidate),
      canaryFingerprints: [],
      sentinelPaths: [...scenario.sentinelPaths],
      run: null
    };
  }

  const probe = await probeRuntimeSandbox();
  if (probe.status !== 'ready') {
    return {
      schemaVersion: 'repotrial.runtime-scenario.v1',
      status: 'unavailable',
      provider: null,
      reason: probe.reason,
      isolation: unavailableIsolation(),
      workspace,
      scenario,
      candidate: redactSensitiveValues(candidate),
      canaryFingerprints: [],
      sentinelPaths: [...scenario.sentinelPaths],
      run: null
    };
  }

  const seed = String(options.canarySeed ?? sha256(JSON.stringify({
    templateId: scenario.templateId,
    candidate: { packagePath: candidate.packagePath, name: candidate.name, command: candidate.command }
  })));
  const prepared = prepareScenarioEnvironment(scenario.envKeys, seed);
  const rawRun = await detonateCandidate(root, candidate, {
    unshare: probe.unshare,
    timeoutMs: boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT, 250, 120_000),
    maxOutputBytes: boundedInteger(options.maxOutputBytes, MAX_OUTPUT_BYTES, 1024, 4 * 1024 * 1024),
    ignoredPaths,
    scenarioEnv: prepared.environment,
    sentinelPaths: scenario.sentinelPaths,
    sentinelSeed: seed
  });
  const publicRun = redactSensitiveValues(replaceCanaries(rawRun, prepared.canaries));
  const result = {
    schemaVersion: 'repotrial.runtime-scenario.v1',
    status: rawRun.status,
    provider: probe.provider,
    isolation: readyIsolation(),
    workspace,
    scenario,
    candidate: redactSensitiveValues(candidate),
    canaryFingerprints: prepared.canaries.map(({ key, fingerprint }) => ({ key, fingerprint })),
    sentinelPaths: [...scenario.sentinelPaths],
    run: publicRun
  };
  Object.defineProperty(result, 'canaries', { value: prepared.canaries, enumerable: false, configurable: false, writable: false });
  Object.defineProperty(result, 'rawRun', { value: rawRun, enumerable: false, configurable: false, writable: false });
  return result;
}

export async function discoverRuntimeCandidates(root, requestedScripts = [], snapshot = null, options = {}) {
  const requested = new Set(normalizeList(requestedScripts));
  const candidates = [];
  const addPackage = (content, relative) => {
    let parsed;
    try { parsed = JSON.parse(content); } catch { return; }
    const scripts = parsed?.scripts && typeof parsed.scripts === 'object' ? parsed.scripts : {};
    for (const [name, command] of Object.entries(scripts)) {
      if (typeof command !== 'string') continue;
      if ((requested.size ? requested.has(name) : LIFECYCLE.has(name))) {
        candidates.push(runtimeCandidate({
          kind: 'package-script', packagePath: relative, name, command,
          workingDirectory: path.posix.dirname(relative) === '.' ? '.' : path.posix.dirname(relative)
        }));
      }
    }
  };
  if (snapshot) {
    for (const file of snapshot.files ?? []) if (/(?:^|\/)package\.json$/i.test(file.path)) addPackage(file.content, file.path);
  } else {
    await walkPackages(root, async (filename, relative) => {
      try { addPackage(await readFile(filename, 'utf8'), relative); } catch { /* unreadable package */ }
    }, options.ignoredPaths ?? []);
  }

  const repository = snapshot ?? await discoverRepository(root, { ignoredPaths: options.ignoredPaths ?? [] });
  for (const file of repository.files ?? []) {
    if (!isAgentConfigFile(file.path)) continue;
    const parsed = parseStructuredConfig(file.content, file.path).value;
    if (!parsed || typeof parsed !== 'object') continue;
    for (const hook of extractHookCommands(parsed, file.path)) {
      if (requested.size && ![hook.name, hook.id, hook.event, `hook:${hook.name}`, `hook:${hook.event}`].some((value) => requested.has(value))) continue;
      candidates.push(runtimeCandidate({
        kind: 'agent-hook', packagePath: file.path, name: hook.name, id: hook.id, event: hook.event,
        command: hook.command, workingDirectory: '.'
      }));
    }
  }
  return candidates.sort((a, b) => `${a.packagePath}:${a.name}`.localeCompare(`${b.packagePath}:${b.name}`));
}

async function detonateCandidate(sourceRoot, candidate, limits) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'repotrial-sandbox-'));
  const rootfs = path.join(temporary, 'rootfs');
  try {
    await buildRootfs(rootfs, sourceRoot, limits.ignoredPaths ?? []);
    const workspace = path.join(rootfs, 'workspace');
    await seedScenarioSentinels(workspace, limits.sentinelPaths ?? [], limits.sentinelSeed ?? 'repotrial');
    const before = await snapshotFiles(workspace);
    const script = [
      'umask 077',
      'ulimit -t 5 2>/dev/null || true',
      'ulimit -f 2048 2>/dev/null || true',
      'ulimit -u 64 2>/dev/null || true',
      'cd /workspace',
      candidate.workingDirectory === '.' ? '' : `cd ${shellQuote(candidate.workingDirectory)}`,
      `exec /bin/sh -c ${shellQuote(candidate.executionCommand ?? candidate.command)}`
    ].filter(Boolean).join('; ');
    const env = {
      PATH: '/trap:/usr/bin:/bin',
      HOME: '/tmp/home',
      TMPDIR: '/tmp',
      LANG: 'C.UTF-8',
      NODE_OPTIONS: '--require=/repotrial/preload.cjs',
      REPOTRIAL_EVENT_FILE: '/events/events.log',
      ...(limits.scenarioEnv ?? {})
    };
    const processResult = await runProcess(limits.unshare, [
      ...NAMESPACE_FLAGS,
      '/usr/sbin/chroot', rootfs, '/usr/bin/env', ...Object.entries(env).map(([key, value]) => `${key}=${value}`), '/bin/sh', '-c', script
    ], { timeoutMs: limits.timeoutMs, maxOutputBytes: limits.maxOutputBytes });
    const after = await snapshotFiles(workspace);
    const events = await readEvents(path.join(rootfs, 'events', 'events.log'));
    return {
      candidate,
      status: processResult.timedOut ? 'timeout' : processResult.exitCode === 0 ? 'completed' : 'failed',
      exitCode: processResult.exitCode,
      signal: processResult.signal,
      timedOut: processResult.timedOut,
      durationMs: processResult.durationMs,
      stdout: processResult.stdout,
      stderr: processResult.stderr,
      outputTruncated: processResult.truncated,
      events,
      filesystemChanges: diffSnapshots(before, after)
    };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

function runtimeCandidate(input) {
  const candidate = {
    kind: input.kind,
    packagePath: input.packagePath,
    name: input.name,
    command: redactSensitiveText(input.command),
    workingDirectory: input.workingDirectory ?? '.',
    ...(input.id ? { id: input.id } : {}),
    ...(input.event ? { event: input.event } : {})
  };
  Object.defineProperty(candidate, 'executionCommand', { value: input.command, enumerable: false, configurable: false, writable: false });
  return candidate;
}

function normalizeScenarioCandidate(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Runtime scenario candidate must be an object.');
  const command = typeof value.executionCommand === 'string' ? value.executionCommand : value.command;
  if (typeof command !== 'string' || !command.trim()) throw new Error('Runtime scenario candidate requires a command.');
  return runtimeCandidate({
    kind: value.kind ?? 'unknown',
    packagePath: value.packagePath ?? '',
    name: value.name ?? 'experiment',
    command,
    workingDirectory: value.workingDirectory ?? '.',
    id: value.id,
    event: value.event
  });
}

function prepareScenarioEnvironment(envKeys, seed) {
  const environment = {};
  const canaries = [];
  for (const key of envKeys) {
    if (key === 'CI' || key === 'GITHUB_ACTIONS') {
      environment[key] = 'true';
      continue;
    }
    const value = `rtx_${sha256(`${seed}\0${key}`).slice(0, 24)}`;
    environment[key] = value;
    canaries.push({ key, value, fingerprint: sha256(value) });
  }
  return { environment, canaries };
}

async function seedScenarioSentinels(workspace, sentinelPaths, seed) {
  for (const relative of sentinelPaths) {
    const normalized = String(relative).replaceAll('\\', '/');
    if (!normalized.startsWith('.repotrial-experiment/') || normalized.split('/').some((part) => part === '..')) {
      throw new Error(`Invalid experiment sentinel path: ${relative}`);
    }
    const destination = path.join(workspace, ...normalized.split('/'));
    const resolvedWorkspace = path.resolve(workspace);
    const resolvedDestination = path.resolve(destination);
    if (!resolvedDestination.startsWith(`${resolvedWorkspace}${path.sep}`)) throw new Error(`Experiment sentinel escapes workspace: ${relative}`);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, `repotrial-sentinel:${sha256(`${seed}\0${normalized}`).slice(0, 24)}\n`, { mode: 0o600 });
  }
}

function replaceCanaries(value, canaries) {
  const replacements = [...canaries].sort((a, b) => b.value.length - a.value.length);
  const seen = new WeakSet();
  const visit = (input, depth = 0) => {
    if (depth > 48) return '[TRUNCATED_DEPTH]';
    if (typeof input === 'string') {
      let result = input;
      for (const item of replacements) result = result.split(item.value).join(`[EXPERIMENT_CANARY:${item.fingerprint.slice(0, 16)}]`);
      return result;
    }
    if (input == null || typeof input !== 'object') return input;
    if (seen.has(input)) return '[CIRCULAR]';
    seen.add(input);
    if (Array.isArray(input)) return input.map((item) => visit(item, depth + 1));
    const output = {};
    for (const [key, child] of Object.entries(input)) output[key] = visit(child, depth + 1);
    return output;
  };
  return visit(value);
}

function readyIsolation() {
  return {
    sourceCopy: true,
    chroot: true,
    userNamespace: true,
    mountNamespace: true,
    utsNamespace: true,
    ipcNamespace: true,
    pidNamespace: true,
    cgroupNamespace: true,
    networkNamespace: true,
    inheritedSecrets: false
  };
}

function unavailableIsolation() {
  return {
    sourceCopy: false,
    chroot: false,
    userNamespace: false,
    mountNamespace: false,
    utsNamespace: false,
    ipcNamespace: false,
    pidNamespace: false,
    cgroupNamespace: false,
    networkNamespace: false,
    inheritedSecrets: false
  };
}

function extractHookCommands(root, sourcePath) {
  const hooks = [];
  const stack = [{ value: root, insideHooks: false, pathParts: [] }];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length && nodes < 50_000) {
    const current = stack.pop();
    const value = current.value;
    nodes += 1;
    if (!value || typeof value !== 'object') continue;
    if (seen.has(value)) continue;
    seen.add(value);
    if (!Array.isArray(value) && current.insideHooks) {
      const command = typeof value.command === 'string' ? value.command : typeof value.script === 'string' ? value.script : null;
      if (command) {
        const event = current.pathParts.find((part) => /^(?:pre|post|before|after|on)[A-Za-z_-]*/i.test(part)) ?? 'agent.hook';
        hooks.push({
          id: `${sourcePath}:${current.pathParts.join('.') || 'hook'}`,
          name: current.pathParts.at(-1) ?? event,
          event,
          command
        });
      }
    }
    const entries = Array.isArray(value) ? value.entries() : Object.entries(value);
    for (const [key, child] of entries) {
      const keyText = String(key);
      const insideHooks = current.insideHooks || /^hooks?$/i.test(keyText);
      stack.push({ value: child, insideHooks, pathParts: insideHooks ? [...current.pathParts.slice(-31), keyText] : [] });
    }
  }
  return hooks;
}

async function inspectRuntimeWorkspace(root, limits) {
  const stack = [root];
  let files = 0;
  let bytes = 0;
  while (stack.length) {
    const directory = stack.pop();
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); }
    catch (error) { return { files, bytes, limitExceeded: 'unreadable', error: redactSensitiveText(error.message) }; }
    for (const entry of entries) {
      if (entry.isDirectory() && ['.git', 'node_modules', '.repotrial', 'dist', 'build'].includes(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (isIgnoredPath(absolute, limits.ignoredPaths ?? [])) continue;
      if (entry.isDirectory()) { stack.push(absolute); continue; }
      if (!entry.isFile() && !entry.isSymbolicLink()) continue;
      files += 1;
      if (files > limits.maxFiles) return { files, bytes, maxFiles: limits.maxFiles, maxBytes: limits.maxBytes, limitExceeded: 'files' };
      if (entry.isFile()) {
        let metadata;
        try { metadata = await lstat(absolute); }
        catch (error) { return { files, bytes, limitExceeded: 'unreadable', error: redactSensitiveText(error.message) }; }
        bytes += metadata.size;
        if (bytes > limits.maxBytes) return { files, bytes, maxFiles: limits.maxFiles, maxBytes: limits.maxBytes, limitExceeded: 'bytes' };
      }
    }
  }
  return { files, bytes, maxFiles: limits.maxFiles, maxBytes: limits.maxBytes, limitExceeded: null };
}

async function buildRootfs(rootfs, sourceRoot, ignoredPaths = []) {
  for (const directory of ['bin', 'usr/bin', 'usr/sbin', 'lib', 'lib64', 'lib/x86_64-linux-gnu', 'usr/lib', 'workspace', 'tmp/home', 'events', 'trap', 'repotrial', 'dev', 'etc']) {
    await mkdir(path.join(rootfs, directory), { recursive: true });
  }
  const binaries = ['/bin/sh', '/bin/bash', process.execPath, '/usr/bin/env', '/usr/sbin/chroot'];
  for (const candidate of binaries) {
    try { await copyExecutable(candidate, rootfs); } catch { /* optional except sh/node/chroot checked by run */ }
  }
  const nodeTarget = path.join(rootfs, 'usr/bin/node');
  try { await access(nodeTarget); } catch {
    await cp(process.execPath, nodeTarget);
    await copyLinkedLibraries(process.execPath, rootfs);
  }
  await cp(sourceRoot, path.join(rootfs, 'workspace'), {
    recursive: true,
    dereference: false,
    filter(source) {
      const relative = path.relative(sourceRoot, source);
      return !isIgnoredPath(source, ignoredPaths) && !relative.split(path.sep).some((part) => ['.git', 'node_modules', '.repotrial'].includes(part));
    }
  });
  await writeFile(path.join(rootfs, 'repotrial', 'preload.cjs'), preloadSource(), { mode: 0o444 });
  for (const tool of ['curl', 'wget', 'nc', 'ncat', 'ssh', 'scp', 'ftp', 'telnet']) {
    await writeFile(path.join(rootfs, 'trap', tool), `#!/bin/sh\nprintf 'network-tool\\t${tool}\\t%s\\n' "$*" >> /events/events.log\nexit 126\n`, { mode: 0o755 });
  }
  await writeFile(path.join(rootfs, 'dev', 'null'), '');
  await writeFile(path.join(rootfs, 'etc', 'passwd'), 'root:x:0:0:RepoTrial Sandbox:/tmp/home:/bin/sh\n');
  await writeFile(path.join(rootfs, 'etc', 'group'), 'root:x:0:\n');
}

async function copyExecutable(source, rootfs) {
  const resolved = await resolveSymlink(source);
  const destination = path.join(rootfs, source.replace(/^\//, ''));
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(resolved, destination);
  await copyLinkedLibraries(resolved, rootfs);
}

async function resolveSymlink(filename) {
  let current = filename;
  for (let index = 0; index < 16; index += 1) {
    const stat = await lstat(current);
    if (!stat.isSymbolicLink()) return current;
    const target = await readlink(current);
    current = path.resolve(path.dirname(current), target);
  }
  throw new Error(`Too many symlinks: ${filename}`);
}

async function copyLinkedLibraries(binary, rootfs) {
  const result = await runProcess('/usr/bin/ldd', [binary], { timeoutMs: 2_000, maxOutputBytes: 128 * 1024 });
  const libraries = new Set();
  for (const line of result.stdout.split(/\r?\n/)) {
    for (const match of line.matchAll(/(?:=>\s+)?(\/[A-Za-z0-9_./+-]+)(?:\s|$)/g)) libraries.add(match[1]);
  }
  for (const library of libraries) {
    const destination = path.join(rootfs, library.replace(/^\//, ''));
    await mkdir(path.dirname(destination), { recursive: true });
    try { await cp(await resolveSymlink(library), destination); } catch { /* best effort */ }
  }
}

async function snapshotFiles(root) {
  const result = new Map();
  async function walk(directory) {
    let entries = [];
    try { entries = await readdir(directory, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (entry.isSymbolicLink()) { result.set(relative, { type: 'symlink' }); continue; }
      if (entry.isDirectory()) { await walk(absolute); continue; }
      if (!entry.isFile()) continue;
      const buffer = await readFile(absolute);
      result.set(relative, { type: 'file', size: buffer.length, sha256: sha256(buffer) });
    }
  }
  await walk(root);
  return result;
}

function diffSnapshots(before, after) {
  const paths = new Set([...before.keys(), ...after.keys()]);
  const changes = [];
  for (const name of [...paths].sort()) {
    const a = before.get(name);
    const b = after.get(name);
    if (!a) changes.push({ path: name, change: 'created', after: b });
    else if (!b) changes.push({ path: name, change: 'deleted', before: a });
    else if (JSON.stringify(a) !== JSON.stringify(b)) changes.push({ path: name, change: 'modified', before: a, after: b });
  }
  return changes.slice(0, 10_000);
}

async function readEvents(filename) {
  let text;
  try { text = await readFile(filename, 'utf8'); } catch { return []; }
  const events = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    if (line.startsWith('{')) {
      try { events.push(JSON.parse(line)); } catch { /* ignore malformed instrumentation */ }
      continue;
    }
    const [kind, tool, detail = ''] = line.split('\t');
    events.push({ kind, tool, detail });
  }
  return events.slice(0, 10_000);
}

function preloadSource() {
  return String.raw`const fs = require('node:fs');
const file = process.env.REPOTRIAL_EVENT_FILE;
function log(event) { try { fs.appendFileSync(file, JSON.stringify({ at: Date.now(), ...event }) + '\n'); } catch {} }
function patch(mod, names, kind) { for (const name of names) { const original = mod[name]; if (typeof original !== 'function') continue; mod[name] = function(...args) { log({ kind, api: name, target: safe(args[0]) }); return original.apply(this, args); }; } }
function safe(value) { if (typeof value === 'string') return value.slice(0, 512); if (value && typeof value === 'object') return String(value.hostname || value.host || value.href || value.path || '').slice(0, 512); return String(value ?? '').slice(0, 512); }
try { patch(require('node:net'), ['connect','createConnection'], 'network'); } catch {}
try { patch(require('node:http'), ['request','get'], 'network'); } catch {}
try { patch(require('node:https'), ['request','get'], 'network'); } catch {}
try { patch(require('node:tls'), ['connect'], 'network'); } catch {}
try { patch(require('node:dns'), ['lookup','resolve','resolve4','resolve6'], 'dns'); } catch {}
try { patch(require('node:child_process'), ['spawn','spawnSync','exec','execSync','execFile','execFileSync'], 'process'); } catch {}
`;
}

function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? { PATH: process.env.PATH ?? '/usr/bin:/bin', LANG: 'C' },
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
      detached: process.platform !== 'win32'
    });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;
    const max = options.maxOutputBytes ?? MAX_OUTPUT_BYTES;
    const append = (current, chunk) => {
      if (current.length >= max) { truncated = true; return current; }
      const remaining = max - current.length;
      if (chunk.length > remaining) truncated = true;
      return Buffer.concat([current, chunk.subarray(0, remaining)]);
    };
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.once('error', reject);
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch { child.kill('SIGKILL'); }
    }, options.timeoutMs ?? DEFAULT_TIMEOUT);
    child.once('close', (exitCode, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode,
        signal,
        timedOut,
        truncated,
        durationMs: Date.now() - started,
        stdout: stdout.toString('utf8'),
        stderr: stderr.toString('utf8')
      });
    });
  });
}

async function walkPackages(root, visit, ignoredPaths = []) {
  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      if (isIgnoredPath(absolute, ignoredPaths)) continue;
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (entry.isDirectory()) {
        if (['.git', 'node_modules', '.repotrial', 'dist', 'build'].includes(entry.name)) continue;
        await walk(absolute);
      } else if (entry.isFile() && entry.name === 'package.json') await visit(absolute, relative);
    }
  }
  await walk(root);
}

function normalizeList(value) {
  const values = Array.isArray(value) ? value : String(value ?? '').split(',');
  return values.map((item) => String(item).trim()).filter(Boolean);
}

function emptyRuntime(status, reason) {
  return { schemaVersion: 'repotrial.runtime.v1', status, provider: null, reason, candidates: [], runs: [], truncatedCandidates: 0 };
}

function shellQuote(value) { return `'${String(value).replaceAll("'", `'"'"'`)}'`; }
function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) ? Math.min(max, Math.max(min, number)) : fallback;
}

function normalizeIgnoredPaths(root, values) {
  return (Array.isArray(values) ? values : [values])
    .filter((value) => value != null && value !== '')
    .map((value) => path.resolve(root, String(value)));
}

function isIgnoredPath(filename, ignoredPaths) {
  const absolute = path.resolve(filename);
  return ignoredPaths.some((ignored) => absolute === ignored || absolute.startsWith(`${ignored}${path.sep}`));
}
