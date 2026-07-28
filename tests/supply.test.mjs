import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import http from 'node:http';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { analyzeSupplyChain, inventoryDependencies } from '../src/supply/analyze.mjs';

test('builds a deterministic CycloneDX 1.6 SBOM from npm, Python, Cargo, and Go locks', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-supply-'));
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'demo', version: '1.0.0', license: 'MIT' },
      'node_modules/left-pad': { version: '1.3.0', license: 'WTFPL', integrity: 'sha512-abc' }
    }
  }));
  await writeFile(path.join(root, 'requirements.txt'), 'requests==2.31.0\n# comment\n');
  await writeFile(path.join(root, 'Cargo.lock'), '[[package]]\nname = "serde"\nversion = "1.0.203"\nchecksum = "abc"\n');
  await writeFile(path.join(root, 'go.sum'), 'golang.org/x/text v0.15.0 h1:abc\n');

  const result = await analyzeSupplyChain({ root, mode: 'offline' });
  assert.equal(result.status, 'completed');
  assert.equal(result.sbom.specVersion, '1.6');
  assert.equal(result.sbom.bomFormat, 'CycloneDX');
  assert.ok(result.components.some((item) => item.purl === 'pkg:npm/left-pad@1.3.0'));
  assert.ok(result.components.some((item) => item.purl === 'pkg:pypi/requests@2.31.0'));
  assert.ok(result.components.some((item) => item.purl === 'pkg:cargo/serde@1.0.203'));
  assert.ok(result.components.some((item) => item.purl === 'pkg:golang/golang.org%2Fx%2Ftext@v0.15.0'));
  assert.ok(result.licenses.observed.includes('MIT'));
  assert.ok(result.licenses.unknownCount >= 1);
});

test('queries OSV in bounded batches and normalizes vulnerability severity', async () => {
  let received;
  const server = http.createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    received = JSON.parse(body);
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ results: [{ vulns: [{ id: 'OSV-TEST-1', summary: 'bad package', severity: [{ type: 'CVSS_V3', score: '9.8' }] }] }] }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-osv-'));
  await writeFile(path.join(root, 'requirements.txt'), 'demo==1.0.0\n');
  try {
    const result = await analyzeSupplyChain({ root, mode: 'osv', osvUrl: `http://127.0.0.1:${address.port}/v1/querybatch`, timeoutMs: 2_000 });
    assert.equal(received.queries[0].package.ecosystem, 'PyPI');
    assert.equal(result.vulnerabilities[0].id, 'OSV-TEST-1');
    assert.equal(result.vulnerabilities[0].severity, 'critical');
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('normalizes external container scanner JSON without requiring the scanner at runtime', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-container-'));
  const scanner = path.join(root, 'scanner.mjs');
  await writeFile(scanner, `console.log(JSON.stringify({Results:[{Target:'image',Vulnerabilities:[{VulnerabilityID:'CVE-2026-1',PkgName:'openssl',InstalledVersion:'1.0',Severity:'HIGH',Title:'test'}]}]}));`);
  const result = await analyzeSupplyChain({
    root,
    mode: 'offline',
    container: { command: process.execPath, args: [scanner] }
  });
  assert.equal(result.container.status, 'completed');
  assert.equal(result.container.findings[0].id, 'CVE-2026-1');
  assert.equal(result.container.findings[0].severity, 'high');
});

test('inventories pnpm, Yarn, Poetry, uv, Pipfile, Composer, and Gemfile locks', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-supply-extra-'));
  await writeFile(path.join(root, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-abc}\n");
  await writeFile(path.join(root, 'yarn.lock'), 'lodash@^4.17.0:\n  version "4.17.21"\n  integrity sha512-def\n');
  await writeFile(path.join(root, 'poetry.lock'), '[[package]]\nname = "requests"\nversion = "2.31.0"\nlicense = "Apache-2.0"\n');
  await writeFile(path.join(root, 'uv.lock'), '[[package]]\nname = "urllib3"\nversion = "2.2.1"\n');
  await writeFile(path.join(root, 'Pipfile.lock'), JSON.stringify({ default: { flask: { version: '==3.0.0' } }, develop: { pytest: { version: '==8.0.0' } } }));
  await writeFile(path.join(root, 'composer.lock'), JSON.stringify({ packages: [{ name: 'monolog/monolog', version: '3.6.0', license: ['MIT'] }] }));
  await writeFile(path.join(root, 'Gemfile.lock'), 'GEM\n  specs:\n    rack (3.0.10)\n    rake (13.2.1)\n\nPLATFORMS\n');
  const result = await analyzeSupplyChain({ root, mode: 'offline' });
  const purls = new Set(result.components.map((item) => item.purl));
  for (const expected of [
    'pkg:npm/left-pad@1.3.0', 'pkg:npm/lodash@4.17.21', 'pkg:pypi/requests@2.31.0',
    'pkg:pypi/urllib3@2.2.1', 'pkg:pypi/flask@3.0.0', 'pkg:pypi/pytest@8.0.0',
    'pkg:composer/monolog%2Fmonolog@3.6.0', 'pkg:gem/rack@3.0.10', 'pkg:gem/rake@13.2.1'
  ]) assert.ok(purls.has(expected), expected);
});

test('computes CVSS v3 vector base score from OSV severity data', async () => {
  const server = http.createServer(async (_request, response) => {
    for await (const _chunk of _request) { /* drain */ }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ results: [{ vulns: [{ id: 'OSV-CVSS', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }] }] }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-cvss-'));
  await writeFile(path.join(root, 'requirements.txt'), 'demo==1.0.0\n');
  try {
    const result = await analyzeSupplyChain({ root, mode: 'osv', osvUrl: `http://127.0.0.1:${port}/v1/querybatch` });
    assert.equal(result.vulnerabilities[0].score, 9.8);
    assert.equal(result.vulnerabilities[0].severity, 'critical');
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('supply-chain inventory excludes caller-specified generated output subtrees', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'repotrial-supply-excluded-'));
  const generated = path.join(root, 'generated-report');
  await (await import('node:fs/promises')).mkdir(generated, { recursive: true });
  await writeFile(path.join(generated, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: { 'node_modules/poison': { name: 'poison', version: '9.9.9' } }
  }));
  const inventory = await inventoryDependencies(root, { ignoredPaths: [generated] });
  assert.equal(inventory.components.length, 0);
  assert.equal(inventory.sourceFiles.length, 0);
});
