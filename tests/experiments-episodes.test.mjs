import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAdversarialEpisode, executeAdversarialEpisode, validateAdversarialEpisode } from '../src/experiments/episodes.mjs';

const candidate = { kind: 'package-script', packagePath: 'package.json', name: 'postinstall', command: 'node setup.mjs', workingDirectory: '.' };

test('episode templates are bounded and phases preserve causal order', () => {
  const episode = buildAdversarialEpisode({ templateId: 'secret-propagation-episode-v1', candidate, chainId: 'chain:a', threatId: 'credential-exfiltration' });
  assert.equal(episode.schemaVersion, 'repotrial.adversarial-episode-plan.v1');
  assert.deepEqual(episode.phases.map((phase) => phase.phase), ['PREPARE', 'TRIGGER', 'OBSERVE', 'VERIFY']);
  assert.equal(episode.phases.length <= episode.limits.hardMaxPhases, true);
  assert.match(episode.id, /^episode:/);
});

test('episode validation rejects arbitrary environment values and path traversal', () => {
  const episode = buildAdversarialEpisode({ templateId: 'filesystem-destruction-episode-v1', candidate, chainId: 'chain:a', threatId: 'unapproved-destructive-action' });
  const injected = structuredClone(episode);
  injected.phases[0].env = { OPENAI_API_KEY: 'real-secret' };
  assert.throws(() => validateAdversarialEpisode(injected), /environment|arbitrary/i);
  const escaped = structuredClone(episode);
  escaped.phases[0].sentinelPaths = ['../escape'];
  assert.throws(() => validateAdversarialEpisode(escaped), /sentinel|path/i);
});

test('executor returns INCONCLUSIVE for a shared-state episode when no safe shared workspace primitive exists', async () => {
  const episode = buildAdversarialEpisode({ templateId: 'memory-persistence-episode-v1', candidate, chainId: 'chain:memory', threatId: 'memory-context-poisoning' });
  const result = await executeAdversarialEpisode({ episode, scenarioRunner: async () => ({ status: 'completed', events: [] }) });
  assert.equal(result.status, 'INCONCLUSIVE');
  assert.equal(result.reason, 'shared-workspace-primitive-unavailable');
  assert.equal(result.phaseResults.some((phase) => phase.status === 'UNSUPPORTED'), true);
});

test('executor preserves NOT_OBSERVED as episode-scoped outcome and never emits global absence', async () => {
  const episode = buildAdversarialEpisode({ templateId: 'ci-conditional-episode-v1', candidate, chainId: 'chain:ci', threatId: 'lifecycle-ci-credential-abuse' });
  const result = await executeAdversarialEpisode({
    episode,
    scenarioRunner: async ({ phase }) => ({ status: 'completed', observationState: phase.phase === 'TRIGGER' ? 'NOT_OBSERVED' : 'TRIGGERED', events: [] })
  });
  assert.equal(result.status, 'NOT_OBSERVED');
  assert.equal(Object.hasOwn(result, 'negativeEvidence'), false);
  assert.equal(result.scope, 'single-bounded-episode');
});

test('executor hard-caps caller-modified excessive phase plans', async () => {
  const episode = buildAdversarialEpisode({ templateId: 'ci-conditional-episode-v1', candidate, chainId: 'chain:ci', threatId: 'lifecycle-ci-credential-abuse' });
  episode.phases = Array.from({ length: 20 }, (_, index) => ({ ...episode.phases[0], id: `p${index}`, order: index }));
  await assert.rejects(() => executeAdversarialEpisode({ episode, scenarioRunner: async () => ({ status: 'completed' }) }), /phase|limit/i);
});
