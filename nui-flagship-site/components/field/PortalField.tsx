'use client';

import { useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import type { CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';

export default function PortalField({ scene, tier, reducedMotion }: {
  scene: CinematicSceneState;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const ringCount = tier === 'high' ? 10 : tier === 'medium' ? 7 : 4;

  useFrame((state, delta) => {
    if (!group.current || reducedMotion) return;
    group.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.16) * 0.055;
    group.current.rotation.y = THREE.MathUtils.damp(group.current.rotation.y, (scene.portal - 0.5) * 0.12, 2, delta);
  });

  return (
    <group ref={group} scale={0.72 + scene.portal * 0.48}>
      {Array.from({ length: ringCount }, (_, index) => {
        const depth = index / Math.max(1, ringCount - 1);
        const radius = 1.62 + index * 0.22;
        const opacity = scene.portal * (0.055 + (1 - depth) * 0.075);
        return (
          <mesh key={index} position={[0, 0, -0.28 - index * 0.48]} rotation={[0, 0, index * 0.075]}>
            <torusGeometry args={[radius, 0.009 + depth * 0.004, 5, tier === 'high' ? 112 : 72]} />
            <meshBasicMaterial color={index % 3 === 0 ? '#b49cff' : '#77e7ff'} transparent opacity={opacity} blending={THREE.AdditiveBlending} depthWrite={false} />
          </mesh>
        );
      })}
      <mesh position={[0, 0, -2.3]}>
        <ringGeometry args={[2.2, 2.205, tier === 'low' ? 48 : 96]} />
        <meshBasicMaterial color="#ddf9ff" transparent opacity={scene.portal * 0.11} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
    </group>
  );
}
