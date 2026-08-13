import { describe, expect, it } from 'vitest';
import { EXPERIENCE_BEATS, energyAt, getExperienceState } from '../lib/experience';
import { FIELD_NODES, getFieldStage } from '../lib/field-model';
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
