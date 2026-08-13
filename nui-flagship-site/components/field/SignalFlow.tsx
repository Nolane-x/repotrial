'use client';

import { useMemo, useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { FIELD_NODES, SIGNAL_ROUTES } from '../../lib/field-model';
import type { CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';

const SIGNAL_COLORS = ['#dffaff', '#79e4ff', '#bca0ff', '#79f0d1', '#ffd08a', '#ff93b9', '#a9ffd0'];
const NODE_MAP = new Map(FIELD_NODES.map((node) => [node.id, node]));

export default function SignalFlow({ scene, tier, reducedMotion }: {
  scene: CinematicSceneState;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const count = tier === 'high' ? SIGNAL_ROUTES.length : tier === 'medium' ? 5 : 3;
  return (
    <group scale={scene.envelope}>
      {SIGNAL_ROUTES.slice(0, count).map((route, index) => (
        <SignalPulse key={`${route.join('-')}-${index}`} route={route} index={index} intensity={scene.signal} reducedMotion={reducedMotion} />
      ))}
    </group>
  );
}

function SignalPulse({ route, index, intensity, reducedMotion }: {
  route: string[];
  index: number;
  intensity: number;
  reducedMotion: boolean;
}) {
  const ref = useRef<THREE.Group>(null);
  const points = useMemo(() => route.map((id) => NODE_MAP.get(id)).filter(Boolean).map((node) => new THREE.Vector3(...node!.position)), [route]);
  const reverse = index === 1 || index === 4;

  useFrame((state) => {
    if (!ref.current || points.length < 2) return;
    const speed = 0.065 + index * 0.008;
    let phase = reducedMotion ? (index + 1) / (SIGNAL_ROUTES.length + 1) : (state.clock.elapsedTime * speed + index * 0.137) % 1;
    if (reverse) phase = 1 - phase;
    const scaled = phase * (points.length - 1);
    const segment = Math.min(points.length - 2, Math.floor(scaled));
    const local = scaled - segment;
    ref.current.position.lerpVectors(points[segment], points[segment + 1], local);
    const pulse = 0.72 + 0.28 * Math.sin((phase + index) * Math.PI * 2);
    ref.current.scale.setScalar((0.7 + intensity * 0.9) * pulse);
  });

  return (
    <group ref={ref}>
      <mesh>
        <sphereGeometry args={[0.045, 14, 14]} />
        <meshBasicMaterial color={SIGNAL_COLORS[index % SIGNAL_COLORS.length]} transparent opacity={intensity * 0.78} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh scale={2.7}>
        <sphereGeometry args={[0.045, 10, 10]} />
        <meshBasicMaterial color={SIGNAL_COLORS[index % SIGNAL_COLORS.length]} transparent opacity={intensity * 0.08} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
    </group>
  );
}
