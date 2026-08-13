'use client';

import { useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import type { CinematicSceneState } from '../../lib/scene-state';

export default function FoldShells({ scene, reducedMotion }: {
  scene: CinematicSceneState;
  reducedMotion: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const left = useRef<THREE.Mesh>(null);
  const right = useRef<THREE.Mesh>(null);
  useFrame((_, delta) => {
    if (!group.current) return;
    const spread = scene.fold * 0.42;
    const tilt = scene.fold * 0.62;
    const scale = scene.envelope * (0.58 + scene.light * 0.24) * (1 - scene.sigil * 0.72);
    group.current.scale.setScalar(Math.max(0.08, scale));
    if (left.current) {
      left.current.position.x = THREE.MathUtils.damp(left.current.position.x, -spread, 3.2, delta);
      left.current.rotation.z = THREE.MathUtils.damp(left.current.rotation.z, tilt, 3.2, delta);
      left.current.rotation.y = THREE.MathUtils.damp(left.current.rotation.y, tilt * 0.55, 3.0, delta);
    }
    if (right.current) {
      right.current.position.x = THREE.MathUtils.damp(right.current.position.x, spread, 3.2, delta);
      right.current.rotation.z = THREE.MathUtils.damp(right.current.rotation.z, -tilt, 3.2, delta);
      right.current.rotation.y = THREE.MathUtils.damp(right.current.rotation.y, -tilt * 0.55, 3.0, delta);
    }
    if (!reducedMotion) group.current.rotation.y += delta * 0.025 * scene.fold;
  });
  const opacity = (0.025 + scene.fold * 0.19 + scene.light * 0.035) * (1 - scene.sigil * 0.9);
  return (
    <group ref={group} name="m3-fold-shells">
      <mesh ref={left} scale={1.04}><icosahedronGeometry args={[0.95, 2]} /><meshBasicMaterial color="#c9f5ff" wireframe transparent opacity={opacity} blending={THREE.AdditiveBlending} depthWrite={false} /></mesh>
      <mesh ref={right} scale={1.16}><icosahedronGeometry args={[0.95, 2]} /><meshBasicMaterial color="#c7adff" wireframe transparent opacity={opacity * 0.82} blending={THREE.AdditiveBlending} depthWrite={false} /></mesh>
      <mesh scale={1.52 + scene.fold * 0.18}><sphereGeometry args={[0.82, 20, 20]} /><meshBasicMaterial color="#7de7ff" side={THREE.BackSide} transparent opacity={opacity * 0.14} blending={THREE.AdditiveBlending} depthWrite={false} /></mesh>
    </group>
  );
}
