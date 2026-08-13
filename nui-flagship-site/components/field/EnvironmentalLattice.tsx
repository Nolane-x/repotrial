'use client';

import { useMemo, useRef } from 'react';
import { Line } from '@react-three/drei';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { FIELD_NODES, type FieldDomain } from '../../lib/field-model';
import { morphNodePosition } from '../../lib/morph-field';
import type { CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';

const DOMAIN_ORDER: FieldDomain[] = ['product', 'routing', 'craft', 'verification', 'research', 'evidence', 'critic'];
const COLORS = ['#dff9ff', '#7af0d0', '#72ddff', '#a6f4c9', '#bea4ff', '#f0c87d', '#f48eaf'];

export default function EnvironmentalLattice({ scene, tier, reducedMotion }: {
  scene: CinematicSceneState;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const layerCount = tier === 'high' ? 3 : tier === 'medium' ? 2 : 1;
  const sampleCount = tier === 'high' ? 68 : tier === 'medium' ? 48 : 32;
  const intensity = Math.max(0, Math.min(1, (scene.typeDepth - 0.40) / 0.50)) * (1 - scene.sigil * 0.96);

  const centers = useMemo(() => {
    return DOMAIN_ORDER.map((domain) => {
      const domainNodes = FIELD_NODES.filter((node) => node.domain === domain)
        .map((node) => morphNodePosition(node, scene).position);
      const count = Math.max(1, domainNodes.length);
      const center: [number, number, number] = [
        domainNodes.reduce((sum, p) => sum + p[0], 0) / count,
        domainNodes.reduce((sum, p) => sum + p[1], 0) / count,
        domainNodes.reduce((sum, p) => sum + p[2], 0) / count,
      ];
      return { domain, center };
    });
  }, [scene.morph, scene.fold, scene.portal, scene.typeDepth]);

  const loops = useMemo(() => {
    return Array.from({ length: layerCount }, (_, layerIndex) => {
      const centeredIndex = layerIndex - (layerCount - 1) / 2;
      const controls = centers.map(({ center }, index) => {
        const lift = Math.sin((index / centers.length) * Math.PI * 2 + centeredIndex * 0.6) * 0.16;
        return new THREE.Vector3(
          center[0] * (1.02 + centeredIndex * 0.035),
          center[1] * (1.01 - centeredIndex * 0.025),
          center[2] + centeredIndex * 0.52 + lift,
        );
      });
      const curve = new THREE.CatmullRomCurve3(controls, true, 'centripetal', 0.5);
      return curve.getPoints(sampleCount);
    });
  }, [centers, layerCount, sampleCount]);

  useFrame((state, delta) => {
    if (!group.current || reducedMotion) return;
    group.current.rotation.y += delta * 0.008 * intensity;
    group.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.07) * 0.018 * intensity;
  });

  return (
    <group ref={group} scale={scene.envelope * 0.96} name="m3-environmental-lattice">
      {loops.map((points, index) => (
        <Line
          key={`lattice-loop-${index}`}
          points={points}
          color={index === 1 ? '#c9bbff' : '#8ee8ff'}
          lineWidth={0.42 + scene.fold * 0.22}
          transparent
          opacity={intensity * (0.055 + index * 0.014) * scene.network}
        />
      ))}
      {centers.map(({ domain, center }, index) => {
        const span = 0.34 + intensity * 0.58;
        const a = new THREE.Vector3(center[0], center[1], center[2] - span);
        const b = new THREE.Vector3(center[0], center[1], center[2] + span);
        return (
          <Line
            key={`lattice-spine-${domain}`}
            points={[a, b]}
            color={COLORS[index]}
            lineWidth={0.34}
            transparent
            opacity={intensity * 0.075 * scene.network}
          />
        );
      })}
    </group>
  );
}
