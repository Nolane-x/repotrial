import { spawn } from 'node:child_process';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { redactSensitiveText } from '../core/redact.mjs';

export async function signWithCosign(statementPath, bundlePath, options = {}) {
  const input = path.resolve(statementPath);
  const output = path.resolve(bundlePath);
  const cosignBin = options.cosignBin ?? 'cosign';
  const args = ['sign-blob', '--yes', '--bundle', output];
  if (options.key) args.push('--key', String(options.key));
  args.push(input);
  const result = await run(cosignBin, args, {
    cwd: options.cwd ?? path.dirname(input),
    timeoutMs: boundedInteger(options.timeoutMs, 120_000, 1_000, 600_000),
    maxBytes: boundedInteger(options.maxOutputBytes, 1024 * 1024, 1024, 16 * 1024 * 1024),
    env: options.env
  });
  if (result.error) throw new Error(`Cosign unavailable: ${redactSensitiveText(result.error)}`);
  if (result.timedOut) throw new Error('Cosign signing timed out.');
  if (result.exitCode !== 0) throw new Error(`Cosign signing failed with exit code ${result.exitCode}: ${redactSensitiveText(result.stderr || result.stdout)}`);
  const metadata = await stat(output);
  if (!metadata.isFile() || metadata.size === 0) throw new Error('Cosign did not create a non-empty bundle.');
  return {
    schemaVersion: 'repotrial.sigstore-signing.v1', status: 'signed', provider: 'cosign', keyless: !options.key,
    bundle: path.basename(output), exitCode: result.exitCode, outputTruncated: result.truncated
  };
}


export async function verifyWithCosign(statementPath, bundlePath, options = {}) {
  const input = path.resolve(statementPath);
  const bundle = path.resolve(bundlePath);
  const cosignBin = options.cosignBin ?? 'cosign';
  const args = ['verify-blob', '--bundle', bundle];
  if (options.key) args.push('--key', String(options.key));
  else {
    if (!options.certificateIdentity || !options.certificateOidcIssuer) throw new Error('Keyless cosign verification requires certificate identity and OIDC issuer.');
    args.push('--certificate-identity', String(options.certificateIdentity), '--certificate-oidc-issuer', String(options.certificateOidcIssuer));
  }
  args.push(input);
  const result = await run(cosignBin, args, {
    cwd: options.cwd ?? path.dirname(input),
    timeoutMs: boundedInteger(options.timeoutMs, 120_000, 1_000, 600_000),
    maxBytes: boundedInteger(options.maxOutputBytes, 1024 * 1024, 1024, 16 * 1024 * 1024),
    env: options.env
  });
  if (result.error) return { valid: false, provider: 'cosign', error: `Cosign unavailable: ${redactSensitiveText(result.error)}` };
  if (result.timedOut) return { valid: false, provider: 'cosign', error: 'Cosign verification timed out.' };
  return {
    valid: result.exitCode === 0,
    provider: 'cosign',
    keyless: !options.key,
    exitCode: result.exitCode,
    outputTruncated: result.truncated,
    ...(result.exitCode === 0 ? {} : { error: redactSensitiveText(result.stderr || result.stdout || `exit-${result.exitCode}`) })
  };
}

function run(command, args, options) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: cosignEnvironment(options.env),
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = Buffer.alloc(0); let stderr = Buffer.alloc(0); let error = null; let truncated = false; let timedOut = false;
    const append = (target, chunk) => {
      const remaining = options.maxBytes - target.length;
      if (remaining <= 0) { truncated = true; return target; }
      if (chunk.length > remaining) truncated = true;
      return Buffer.concat([target, chunk.subarray(0, Math.max(0, remaining))]);
    };
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.on('error', (caught) => { error = caught.message; });
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, options.timeoutMs);
    child.on('close', (exitCode) => {
      clearTimeout(timer);
      resolve({ exitCode, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8'), error, truncated, timedOut });
    });
  });
}

function cosignEnvironment(overrides = {}) {
  const environment = {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    LANG: 'C'
  };
  for (const key of [
    'COSIGN_PASSWORD',
    'SIGSTORE_ID_TOKEN',
    'SIGSTORE_NO_CACHE',
    'ACTIONS_ID_TOKEN_REQUEST_URL',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
    'GITHUB_ACTIONS',
    'CI'
  ]) {
    if (typeof process.env[key] === 'string') environment[key] = process.env[key];
  }
  for (const [key, value] of Object.entries(overrides ?? {})) {
    if (typeof value === 'string') environment[key] = value;
  }
  return environment;
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) ? Math.min(max, Math.max(min, number)) : fallback;
}
