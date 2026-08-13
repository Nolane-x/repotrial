'use client';

import { useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Line } from '@react-three/drei';
import * as THREE from 'three';
import { FIELD_EDGES, FIELD_NODES, visibleFieldNodes, type FieldDomain } from '../../lib/field-model';
import { TIER_BUDGETS, type CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';
import IntelligenceCore from './IntelligenceCore';
import DomainOrbits from './DomainOrbits';
import PortalField from './PortalField';
import SignalFlow from './SignalFlow';
import ResolutionSigil from './ResolutionSigil';
import AmbientField from './AmbientField';

const DOMAIN_COLOR: Record<FieldDomain, string> = {
  product: '#e8fbff', craft: '#77dfff', research: '#c5a8ff', routing: '#77f0d0',
  evidence: '#f8ca7c', critic: '#ff8fb9', verification: '#a9ffcf',
};

export default function IntelligenceField({ progress, energy, tier, reducedMotion, scene }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
  scene: CinematicSceneState;
}) {
  const budget = TIER_BUDGETS[tier];
  return (
    <Canvas
      dpr={budget.dpr}
      camera={{ position: [0, 0, 9.4], fov: 46, near: 0.1, far: 44 }}
      gl={{ alpha: true, antialias: tier !== 'low', powerPreference: 'high-performance' }}
      style={{ width: '100%', height: '100%' }}
    >
      <Scene progress={progress} energy={energy} tier={tier} reducedMotion={reducedMotion} scene={scene} />
    </Canvas>
  );
}

function Scene({ progress, energy, tier, reducedMotion, scene }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
  scene: CinematicSceneState;
}) {
  const lookTarget = useRef(new THREE.Vector3());

  useFrame((state, delta) => {
    const camera = state.camera as THREE.PerspectiveCamera;
    const pointerX = reducedMotion ? 0 : THREE.MathUtils.clamp(state.pointer.x * 0.24, -0.24, 0.24);
    const pointerY = reducedMotion ? 0 : THREE.MathUtils.clamp(state.pointer.y * 0.16, -0.16, 0.16);
    camera.position.x = THREE.MathUtils.damp(camera.position.x, scene.camera.position[0] + pointerX, 2.8, delta);
    camera.position.y = THREE.MathUtils.damp(camera.position.y, scene.camera.position[1] + pointerY, 2.8, delta);
    camera.position.z = THREE.MathUtils.damp(camera.position.z, scene.camera.position[2], 2.8, delta);
    camera.fov = THREE.MathUtils.damp(camera.fov, scene.camera.fov, 2.4, delta);
    lookTarget.current.x = THREE.MathUtils.damp(lookTarget.current.x, scene.camera.lookAt[0], 2.6, delta);
    lookTarget.current.y = THREE.MathUtils.damp(lookTarget.current.y, scene.camera.lookAt[1], 2.6, delta);
    lookTarget.current.z = THREE.MathUtils.damp(lookTarget.current.z, scene.camera.lookAt[2], 2.6, delta);
    camera.lookAt(lookTarget.current);
    camera.updateProjectionMatrix();
  });

  return (
    <>
      <ambientLight intensity={0.11 + energy * 0.14} />
      <pointLight position={[3.2, 4.2, 5.4]} intensity={(2.5 + scene.atmosphere * 1.8) * energy} color="#7ddfff" distance={15} />
      <pointLight position={[-4.2, -2.1, 3]} intensity={(1.7 + (scene.mode === 'cathedral' ? 1.2 : 0)) * energy} color="#b794ff" distance={13} />
      <AmbientField scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <PortalField scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <DomainOrbits scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <SemanticNetwork progress={progress} energy={energy} tier={tier} reducedMotion={reducedMotion} scene={scene} />
      <SignalFlow scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <ResolutionSigil scene={scene} />
      <IntelligenceCore scene={scene} energy={energy} reducedMotion={reducedMotion} />
    </>
  );
}

function SemanticNetwork({ progress, energy, tier, reducedMotion, scene }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
  scene: CinematicSceneState;
}) {
  const group = useRef<THREE.Group>(null);
  const nodes = visibleFieldNodes(progress);
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges = FIELD_EDGES.filter(([a, b]) => visibleIds.has(a) && visibleIds.has(b));
  const nodeById = new Map(FIELD_NODES.map((node) => [node.id, node]));
  const networkFade = 1 - scene.sigil * 0.9;
  const lineOpacity = TIER_BUDGETS[tier].lineOpacity * (0.30 + energy * 0.82) * networkFade;

  useFrame((state, delta) => {
    if (!group.current || reducedMotion) return;
    group.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.11) * 0.038;
    group.current.rotation.y += delta * (0.018 + scene.orbit * 0.026);
  });

  return (
    <group ref={group} scale={scene.envelope}>
      {edges.map(([a, b]) => {
        const source = nodeById.get(a)!;
        const target = nodeById.get(b)!;
        return <Line key={`${a}-${b}`} points={[source.position, target.position]} color="#a7efff" lineWidth={0.62} transparent opacity={lineOpacity} />;
      })}
      {nodes.map((node, index) => {
        const active = Math.max(0.12, Math.min(1, progress * 5 - index * 0.09));
        return (
          <group key={node.id} position={node.position}>
            <mesh scale={(0.055 + node.weight * 0.035) * (0.75 + active * 0.55)}>
              <sphereGeometry args={[1, 16, 16]} />
              <meshBasicMaterial color={DOMAIN_COLOR[node.domain]} transparent opacity={(0.48 + energy * 0.38) * networkFade} blending={THREE.AdditiveBlending} depthWrite={false} />
            </mesh>
            <mesh scale={(0.16 + node.weight * 0.05) * (0.6 + energy * 0.5)}>
              <sphereGeometry args={[1, 12, 12]} />
              <meshBasicMaterial color={DOMAIN_COLOR[node.domain]} transparent opacity={(0.03 + energy * 0.05) * networkFade} blending={THREE.AdditiveBlending} depthWrite={false} />
            </mesh>
          </group>
        );
      })}
    </group>
  );
}
