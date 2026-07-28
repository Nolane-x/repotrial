import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createReportServer } from '../src/server.mjs';

function request(port, pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathname }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }).on('error', reject);
  });
}

test('serves report with security headers and rejects traversal', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-server-'));
  await writeFile(path.join(root, 'report.html'), '<h1>trial</h1>');
  const server = createReportServer(root);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const port = server.address().port;

  const ok = await request(port, '/');
  assert.equal(ok.status, 200);
  assert.match(ok.headers['content-security-policy'], /default-src 'none'/);
  assert.match(ok.body, /trial/);

  const escaped = await request(port, '/..%2F..%2Fetc%2Fpasswd');
  assert.equal(escaped.status, 404);
});


test('does not serve a symlink that escapes the report directory', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-server-symlink-'));
  const outside = path.join(await mkdtemp(path.join(tmpdir(), 'repotrial-server-secret-')), 'secret.txt');
  await writeFile(path.join(root, 'report.html'), '<h1>trial</h1>');
  await writeFile(outside, 'TOP-SECRET-CONTENT');
  await symlink(outside, path.join(root, 'leak.txt'));

  const server = createReportServer(root);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const response = await request(server.address().port, '/leak.txt');
  assert.equal(response.status, 404);
  assert.doesNotMatch(response.body, /TOP-SECRET-CONTENT/);
});
