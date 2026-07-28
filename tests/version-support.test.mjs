import test from 'node:test';
import assert from 'node:assert/strict';
import { assertSupportedNode, supportedNode } from '../src/core/node-version.mjs';

test('supports maintained Node.js 22 and 24 lines and rejects EOL Node.js 20', () => {
  assert.equal(supportedNode('22.14.0'), true);
  assert.equal(supportedNode('24.0.0'), true);
  assert.equal(supportedNode('20.19.0'), false);
  assert.throws(() => assertSupportedNode('20.19.0'), /Node\.js 22\.14 or newer/);
});
