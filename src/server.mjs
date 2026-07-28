import http from 'node:http';
import { readFile, lstat, realpath, stat } from 'node:fs/promises';
import path from 'node:path';

const CONTENT_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8'
});

export function createReportServer(reportDirectory) {
  const root = path.resolve(reportDirectory);
  const realRootPromise = realpath(root);
  return http.createServer(async (request, response) => {
    setSecurityHeaders(response);
    if (!['GET', 'HEAD'].includes(request.method ?? 'GET')) {
      response.writeHead(405, { allow: 'GET, HEAD' });
      response.end('Method not allowed');
      return;
    }

    let pathname;
    try {
      pathname = decodeURIComponent(new URL(request.url ?? '/', 'http://localhost').pathname);
    } catch {
      response.writeHead(400);
      response.end('Bad request');
      return;
    }
    if (pathname === '/') pathname = '/report.html';
    if (pathname.includes('\0')) {
      response.writeHead(404);
      response.end('Not found');
      return;
    }

    const candidate = path.resolve(root, `.${pathname}`);
    if (candidate !== root && !candidate.startsWith(`${root}${path.sep}`)) {
      response.writeHead(404);
      response.end('Not found');
      return;
    }

    try {
      const [realRoot, linkInfo] = await Promise.all([realRootPromise, lstat(candidate)]);
      if (linkInfo.isSymbolicLink()) throw new Error('symlink');
      const realCandidate = await realpath(candidate);
      if (realCandidate !== realRoot && !realCandidate.startsWith(`${realRoot}${path.sep}`)) {
        throw new Error('escaped-realpath');
      }
      const info = await stat(realCandidate);
      if (!info.isFile()) throw new Error('not-file');
      const body = await readFile(realCandidate);
      response.writeHead(200, {
        'content-type': CONTENT_TYPES[path.extname(realCandidate).toLowerCase()] ?? 'application/octet-stream',
        'content-length': body.length,
        'cache-control': 'no-store'
      });
      if (request.method === 'HEAD') response.end();
      else response.end(body);
    } catch {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('Not found');
    }
  });
}

function setSecurityHeaders(response) {
  response.setHeader('content-security-policy', "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; script-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  response.setHeader('x-content-type-options', 'nosniff');
  response.setHeader('x-frame-options', 'DENY');
  response.setHeader('referrer-policy', 'no-referrer');
  response.setHeader('cross-origin-resource-policy', 'same-origin');
}
