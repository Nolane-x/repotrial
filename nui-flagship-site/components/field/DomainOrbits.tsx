'use client';

import { useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import type { CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';
import type { FieldDomain } from '../../lib/field-model';

const DOMAINS: FieldDomain[] = ['product', 'craft', 'research', 'routing', 'evidence', 'critic', 'verification'];
const COLORS: Record<FieldDomain, string> = {
  product: '#dff9ff', craft: '#6edcff', research: '#b79aff', routing: '#6fecc9',
  evidence: '#f6ca7d', critic: '#ff8cb4', verification: '#a3f7c7',
};

export default function DomainOrbits({ scene, tier, reducedMotion }: {
  scene: CinematicSceneState;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const segments = tier === 'high' ? 112 : tier === 'medium' ? 80 : 52;
  const opacity = scene.orbit * (1 - scene.sigil * 0.52);

  useFrame((_, delta) => {
    if (!group.current || reducedMotion) return;
    group.current.rotation.y += delta * 0.035;
    group.current.rotation.z += delta * 0.012;
  });

  return (
    <group ref={group} scale={0.78 + scene.envelope * 0.38}>
      {DOMAINS.map((domain, index) => (
        <mesh
          key={domain}
          rotation={[
            0.18 + index * 0.17,
            index * 0.41,
            index * 0.31,
          ]}
          scale={1 + index * 0.075}
        >
          <torusGeometry args={[1.42, 0.007 + index * 0.0006, 5, segments]} />
          <meshBasicMaterial color={COLORS[domain]} transparent opacity={opacity * (0.07 + index * 0.006)} blending={THREE.AdditiveBlending} depthWrite={false} />
        </mesh>
      ))}
    </group>
  );
}
