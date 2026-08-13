import { describe, expect, it } from 'vitest';
import { FIELD_EDGES, FIELD_NODES } from '../lib/field-model';
import { getCinematicSceneState } from '../lib/scene-state';
import { morphNodePosition, semanticNeighborhood } from '../lib/morph-field';

describe('M3 Spatial Metamorphosis', () => {
  it('peaks fold and light at the spatial climax then resolves to the sigil', () => {
    const architecture = getCinematicSceneState(0.30, false);
    const world = getCinematicSceneState(0.70, false);
    const climax = getCinematicSceneState(0.84, false);
    const resolution = getCinematicSceneState(0.98, false);
    expect(world.morph).toBeGreaterThan(architecture.morph);
    expect(climax.fold).toBeGreaterThan(0.95);
    expect(climax.light).toBeGreaterThan(0.85);
    expect(resolution.fold).toBeLessThan(0.08);
    expect(resolution.morph).toBeLessThan(0.08);
    expect(resolution.sigil).toBeGreaterThan(0.95);
  });

  it('clamps large spatial movement under reduced motion', () => {
    const full = getCinematicSceneState(0.84, false);
    const reduced = getCinematicSceneState(0.84, true);
    expect(reduced.fold).toBeLessThanOrEqual(full.fold * 0.23);
    expect(reduced.typeDepth).toBeLessThanOrEqual(full.typeDepth * 0.17);
    expect(reduced.camera.position).toEqual([0, 0, 9.4]);
  });

  it('semantic focus can only expose real first-order graph neighbors', () => {
    for (const node of FIELD_NODES) {
      const neighborhood = semanticNeighborhood(node.id);
      expect(neighborhood[0]).toBe(node.id);
      for (const neighbor of neighborhood.slice(1)) {
        expect(FIELD_EDGES.some(([a, b]) => (a === node.id && b === neighbor) || (b === node.id && a === neighbor))).toBe(true);
      }
    }
  });

  it('keeps the Impossible Fold finite and continuous across 401 progress samples', () => {
    let maxAbs = 0;
    let maxStep = 0;
    let previous = new Map<string, [number, number, number]>();
    for (let sample = 0; sample <= 400; sample += 1) {
      const progress = sample / 400;
      const scene = getCinematicSceneState(progress, false);
      for (const node of FIELD_NODES) {
        const point = morphNodePosition(node, scene).position;
        for (const value of point) {
          expect(Number.isFinite(value)).toBe(true);
          maxAbs = Math.max(maxAbs, Math.abs(value));
        }
        const before = previous.get(node.id);
        if (before) maxStep = Math.max(maxStep, Math.hypot(point[0] - before[0], point[1] - before[1], point[2] - before[2]));
        previous.set(node.id, point);
      }
    }
    expect(maxAbs).toBeLessThan(4);
    expect(maxStep).toBeLessThan(0.16);
  });
});
