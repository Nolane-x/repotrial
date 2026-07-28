import test from 'node:test';
import assert from 'node:assert/strict';
import { redactSensitiveText, redactSensitiveValues } from '../src/core/redact.mjs';

test('redacts common credential forms', () => {
  const text = 'API_TOKEN="secret value"\nAuthorization: Bearer abc.def.ghi\nhttps://user:password@example.com\nghp_123456789012345678901234567890';
  const redacted = redactSensitiveText(text);
  assert.doesNotMatch(redacted, /secret value|abc\.def\.ghi|password@|ghp_123/);
  assert.match(redacted, /\[REDACTED/);
});

test('redacts deeply nested values without overflowing the call stack', () => {
  let input = { API_TOKEN: 'super-secret-value' };
  for (let index = 0; index < 20_000; index += 1) input = [input];
  const output = redactSensitiveValues(input);
  let cursor = output;
  for (let index = 0; index < 20_000; index += 1) cursor = cursor[0];
  assert.equal(cursor.API_TOKEN, '[REDACTED]');
});

test('redacts additional provider credentials, JWTs, and encoded secret assignments', () => {
  const slackToken = ['xoxb', '123456789012', '123456789012', 'abcdefghijklmnopqrstuvwx'].join('-');
  const input = [
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    `SLACK_TOKEN=${slackToken}`,
    'NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890',
    'session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    `custom_secret_b64=${Buffer.from('password=very-secret-value').toString('base64')}`
  ].join('\n');
  const redacted = redactSensitiveText(input);
  assert.doesNotMatch(redacted, /AKIAIOSFODNN7EXAMPLE|xoxb-|npm_|eyJhbGci|very-secret-value/);
  assert.match(redacted, /REDACTED/);
});

test('does not redact ordinary hashes or prose without a secret context', () => {
  const hash = 'a'.repeat(64);
  const input = `artifact sha256 ${hash}\nThis documentation explains token budgets without containing a credential.`;
  assert.equal(redactSensitiveText(input), input);
});

test('preserves boolean security metadata even when its key mentions secrets', () => {
  assert.deepEqual(redactSensitiveValues({ inheritedSecrets: false, secretPresent: true }), {
    inheritedSecrets: false,
    secretPresent: true
  });
});


test('duplicates shared references while marking only true cycles', () => {
  const shared = { value: 'safe' };
  const input = { first: shared, second: shared };
  input.self = input;
  const output = redactSensitiveValues(input);
  assert.deepEqual(output.first, { value: 'safe' });
  assert.deepEqual(output.second, { value: 'safe' });
  assert.equal(output.self, '[CIRCULAR]');
});
