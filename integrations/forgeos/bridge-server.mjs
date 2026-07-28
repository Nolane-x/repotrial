#!/usr/bin/env node
import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { probeForgeOsCli, runForgeOsCli } from '../../src/bridge/forgeos.mjs';

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_BODY_TIMEOUT_MS = 10_000;

export function createForgeOsBridgeServer(options = {}) {
  const token = options.token ?? process.env.REPOTRIAL_BRIDGE_TOKEN ?? '';
  const maxBodyBytes = positiveBound(options.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, 64, 16 * 1024 * 1024);
  const bodyTimeoutMs = positiveBound(options.bodyTimeoutMs, DEFAULT_BODY_TIMEOUT_MS, 10, 120_000);
  const server = http.createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json; charset=utf-8');
    response.setHeader('x-content-type-options', 'nosniff');
    response.setHeader('cache-control', 'no-store');

    if (request.method === 'GET' && request.url === '/health') {
      response.writeHead(200);
      response.end(JSON.stringify({ schemaVersion: 'repotrial.forgeos.bridge.v1', status: 'ok' }));
      return;
    }
    if (request.url === '/ready' || request.url === '/v1/scan') {
      if (token && !validToken(request.headers.authorization, token)) {
        response.writeHead(401);
        response.end(JSON.stringify({ schemaVersion: 'repotrial.forgeos.bridge.v1', status: 'unauthorized' }));
        request.resume();
        return;
      }
    }
    if (request.method === 'GET' && request.url === '/ready') {
      const readiness = await probeForgeOsCli({
        forgeBin: options.forgeBin ?? process.env.FORGEOS_BIN ?? 'forge',
        forgeRoot: options.forgeRoot ?? process.env.FORGEOS_ROOT,
        timeoutMs: options.readinessTimeoutMs ?? 5_000,
        cwd: options.cwd ?? process.cwd()
      });
      response.writeHead(readiness.status === 'ready' ? 200 : 503);
      response.end(JSON.stringify({ schemaVersion: 'repotrial.forgeos.bridge.v1', ...readiness }));
      return;
    }
    if (request.method !== 'POST' || request.url !== '/v1/scan') {
      response.writeHead(404);
      response.end(JSON.stringify({ schemaVersion: 'repotrial.forgeos.bridge.v1', status: 'not-found' }));
      request.resume();
      return;
    }
    if (!String(request.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
      response.writeHead(415);
      response.end(JSON.stringify({ schemaVersion: 'repotrial.forgeos.bridge.v1', status: 'error', error: 'Content-Type must be application/json.', findings: [] }));
      request.resume();
      return;
    }

    try {
      const payload = JSON.parse(await readBoundedBody(request, maxBodyBytes, bodyTimeoutMs));
      const validDepth = payload?.depth === undefined || ['security', 'full'].includes(payload.depth);
      if (!isPlainObject(payload) || payload.schemaVersion !== 'repotrial.forgeos.bridge.v1' || !isPlainObject(payload.manifest) || !validDepth) {
        response.writeHead(400);
        response.end(JSON.stringify({
          schemaVersion: 'repotrial.forgeos.bridge.v1', status: 'invalid-request',
          error: 'Expected repotrial.forgeos.bridge.v1, an object manifest, and depth security or full.', findings: []
        }));
        return;
      }
      const result = await runForgeOsCli(payload.manifest, {
        forgeBin: options.forgeBin ?? process.env.FORGEOS_BIN ?? 'forge',
        forgeRoot: options.forgeRoot ?? process.env.FORGEOS_ROOT,
        depth: payload.depth ?? 'security',
        timeoutMs: options.timeoutMs ?? 30_000,
        cwd: options.cwd ?? process.cwd()
      });
      response.writeHead(result.status === 'ok' ? 200 : 503);
      response.end(JSON.stringify(result));
    } catch (error) {
      const status = error?.code === 'BODY_TOO_LARGE' ? 413 : error?.code === 'BODY_TIMEOUT' ? 408 : 400;
      response.writeHead(status);
      response.end(JSON.stringify({
        schemaVersion: 'repotrial.forgeos.bridge.v1',
        status: 'error',
        error: error instanceof Error ? error.message : String(error),
        findings: []
      }));
    }
  });
  server.requestTimeout = Math.max(bodyTimeoutMs + 1_000, 5_000);
  server.headersTimeout = Math.max(bodyTimeoutMs + 2_000, 6_000);
  server.keepAliveTimeout = 5_000;
  return server;
}

function readBoundedBody(request, limit, timeoutMs) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.off('data', onData);
      request.off('end', onEnd);
      request.off('error', onError);
      callback(value);
    };
    const fail = (code, message) => {
      const error = new Error(message);
      error.code = code;
      finish(reject, error);
      request.resume();
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > limit) {
        fail('BODY_TOO_LARGE', `Request body exceeds ${limit} bytes.`);
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish(resolve, Buffer.concat(chunks).toString('utf8'));
    const onError = (error) => finish(reject, error);
    const timer = setTimeout(() => fail('BODY_TIMEOUT', `Request body timed out after ${timeoutMs}ms.`), timeoutMs);
    request.on('data', onData);
    request.on('end', onEnd);
    request.on('error', onError);
  });
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validToken(header, expected) {
  if (!header?.startsWith('Bearer ')) return false;
  const actual = Buffer.from(header.slice(7));
  const wanted = Buffer.from(expected);
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}

function positiveBound(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

async function run() {
  const host = process.env.REPOTRIAL_BRIDGE_HOST ?? '127.0.0.1';
  const port = Number(process.env.REPOTRIAL_BRIDGE_PORT ?? 8791);
  const server = createForgeOsBridgeServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  console.log(`RepoTrial ForgeOS bridge listening on http://${host}:${port}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
