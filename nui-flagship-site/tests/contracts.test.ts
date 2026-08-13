import { describe, expect, it } from 'vitest';
import { EXPERIENCE_BEATS, energyAt, getExperienceState } from '../lib/experience';
import { FIELD_EDGES, FIELD_NODES, getFieldStage, visibleFieldNodes } from '../lib/field-model';
import { chooseCapabilityTier, reducedMotionProfile } from '../lib/capability';

describe('flagship experience contract', () => {
  it('preserves the eight-beat dramaturgy from silence to resolution', () => {
    expect(EXPERIENCE_BEATS).toHaveLength(8);
    expect(EXPERIENCE_BEATS[0].id).toBe('silence');
    expect(EXPERIENCE_BEATS.at(-1)?.id).toBe('resolution');
    expect(EXPERIENCE_BEATS.map((beat) => beat.id)).toEqual([
      'silence', 'awakening', 'architecture', 'scale-break', 'motion', 'world-opens', 'climax', 'resolution',
    ]);
  });

  it('maps scroll progress to an authored beat and local progress', () => {
    expect(getExperienceState(0).beat.id).toBe('silence');
    expect(getExperienceState(0.52).beat.id).toBe('motion');
    expect(getExperienceState(0.84).beat.id).toBe('climax');
    expect(getExperienceState(1).beat.id).toBe('resolution');
    expect(getExperienceState(0.52).localProgress).toBeGreaterThanOrEqual(0);
    expect(getExperienceState(0.52).localProgress).toBeLessThanOrEqual(1);
  });

  it('builds energy toward one climax then resolves', () => {
    expect(energyAt(0)).toBe(10);
    expect(energyAt(0.84)).toBeGreaterThan(energyAt(0.52));
    expect(energyAt(0.84)).toBeGreaterThan(90);
    expect(energyAt(1)).toBe(45);
  });
});

describe('M2 cinematic scene contract', () => {
  it('authors materially different scene modes and a single spatial climax', async () => {
    // @ts-expect-error TDD RED: scene-state is intentionally absent until this contract fails in CI.
    const sceneModule = await import('../lib/scene-state').catch(() => null);
    expect(sceneModule).not.toBeNull();
    if (!sceneModule) return;

    const silence = sceneModule.getCinematicSceneState(0.03, false);
    const architecture = sceneModule.getCinematicSceneState(0.30, false);
    const scaleBreak = sceneModule.getCinematicSceneState(0.43, false);
    const motion = sceneModule.getCinematicSceneState(0.56, false);
    const world = sceneModule.getCinematicSceneState(0.70, false);
    const climax = sceneModule.getCinematicSceneState(0.84, false);
    const resolution = sceneModule.getCinematicSceneState(0.98, false);

    expect(silence.mode).toBe('seed');
    expect(architecture.mode).toBe('territories');
    expect(scaleBreak.mode).toBe('portal');
    expect(motion.mode).toBe('signals');
    expect(world.mode).toBe('environment');
    expect(climax.mode).toBe('cathedral');
    expect(resolution.mode).toBe('sigil');

    expect(scaleBreak.portal).toBeGreaterThan(0.55);
    expect(world.portal).toBeGreaterThan(0.45);
    expect(climax.orbit).toBeGreaterThan(0.9);
    expect(climax.signal).toBeGreaterThan(0.85);
    expect(climax.envelope).toBeGreaterThan(architecture.envelope);
    expect(climax.envelope).toBeGreaterThan(resolution.envelope);
    expect(resolution.portal).toBeLessThan(0.1);
  });

  it('keeps reduced-motion camera neutral while full motion approaches and recedes from climax', async () => {
    // @ts-expect-error TDD RED: scene-state is intentionally absent until this contract fails in CI.
    const sceneModule = await import('../lib/scene-state').catch(() => null);
    expect(sceneModule).not.toBeNull();
    if (!sceneModule) return;

    const early = sceneModule.cameraPoseAt(0.15, false);
    const climax = sceneModule.cameraPoseAt(0.84, false);
    const resolved = sceneModule.cameraPoseAt(0.98, false);
    const reduced = sceneModule.cameraPoseAt(0.84, true);

    expect(climax.position[2]).toBeLessThan(early.position[2]);
    expect(resolved.position[2]).toBeGreaterThan(climax.position[2]);
    expect(reduced.position).toEqual([0, 0, 9.4]);
    expect(reduced.lookAt).toEqual([0, 0, 0]);
    expect(reduced.fov).toBe(46);
  });
});

describe('intelligence field semantics', () => {
  it('contains product-specific NUI territories instead of generic particles', () => {
    const domains = new Set(FIELD_NODES.map((node) => node.domain));
    for (const required of ['product', 'craft', 'research', 'routing', 'evidence', 'critic', 'verification'] as const) {
      expect(domains.has(required)).toBe(true);
    }
  });

  it('evolves through semantic stages across the journey', () => {
    expect(getFieldStage(0)).toBe('seed');
    expect(getFieldStage(0.3)).toBe('architecture');
    expect(getFieldStage(0.56)).toBe('routing');
    expect(getFieldStage(0.84)).toBe('climax');
    expect(getFieldStage(0.96)).toBe('resolution');
  });

  it('resolves to one representative from every NUI domain instead of truncating the graph', () => {
    const resolved = visibleFieldNodes(0.96);
    expect(resolved).toHaveLength(7);
    expect(new Set(resolved.map((node) => node.domain))).toEqual(new Set(['product', 'craft', 'research', 'routing', 'evidence', 'critic', 'verification']));
  });

  it('expands toward the spatial climax and contracts decisively at final resolution', async () => {
    const model = await import('../lib/field-model');
    const fieldEnvelope = (model as unknown as { fieldEnvelope?: (progress: number) => number }).fieldEnvelope;
    expect(typeof fieldEnvelope).toBe('function');
    if (!fieldEnvelope) return;
    expect(fieldEnvelope(0.84)).toBeGreaterThan(fieldEnvelope(0.3));
    expect(fieldEnvelope(0.84)).toBeGreaterThan(fieldEnvelope(0.98));
    expect(fieldEnvelope(1)).toBeLessThan(0.75);
  });

  it('defines causal signal routes using only real semantic edges', async () => {
    const model = await import('../lib/field-model');
    const routes = (model as unknown as { SIGNAL_ROUTES?: string[][] }).SIGNAL_ROUTES;
    expect(routes).toBeDefined();
    if (!routes) return;
    expect(routes.length).toBeGreaterThanOrEqual(6);

    const edgeKeys = new Set(FIELD_EDGES.flatMap(([a, b]) => [`${a}|${b}`, `${b}|${a}`]));
    for (const route of routes) {
      expect(route.length).toBeGreaterThanOrEqual(2);
      for (let index = 1; index < route.length; index += 1) {
        expect(edgeKeys.has(`${route[index - 1]}|${route[index]}`)).toBe(true);
      }
    }
  });

  it('provides a compact seven-domain resolution sigil model', async () => {
    const model = await import('../lib/field-model');
    const buildSigil = (model as unknown as { resolutionSigilNodes?: () => Array<{ domain: string; sigilPosition: [number, number, number] }> }).resolutionSigilNodes;
    expect(typeof buildSigil).toBe('function');
    if (!buildSigil) return;
    const sigil = buildSigil();
    expect(sigil).toHaveLength(7);
    expect(new Set(sigil.map((node) => node.domain)).size).toBe(7);
    expect(Math.max(...sigil.map((node) => Math.hypot(...node.sigilPosition)))).toBeLessThan(1.8);
  });
});

describe('adaptive rendering contract', () => {
  it('degrades quality from high to low using capability evidence', () => {
    expect(chooseCapabilityTier({ deviceMemory: 16, hardwareConcurrency: 12, dpr: 1.5, reducedMotion: false })).toBe('high');
    expect(chooseCapabilityTier({ deviceMemory: 8, hardwareConcurrency: 6, dpr: 2, reducedMotion: false })).toBe('medium');
    expect(chooseCapabilityTier({ deviceMemory: 2, hardwareConcurrency: 2, dpr: 3, reducedMotion: false })).toBe('low');
  });

  it('preserves meaning while removing vestibular motion', () => {
    const profile = reducedMotionProfile();
    expect(profile.continuousAmbient).toBe(false);
    expect(profile.cameraTravel).toBe(false);
    expect(profile.semanticStateProgression).toBe(true);
  });
});
