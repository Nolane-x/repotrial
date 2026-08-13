'use client';

import { useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { TIER_BUDGETS, type CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';
import IntelligenceCore from './IntelligenceCore';
import DomainOrbits from './DomainOrbits';
import PortalField from './PortalField';
import SignalFlow from './SignalFlow';
import ResolutionSigil from './ResolutionSigil';
import AmbientField from './AmbientField';
import MorphingField from './MorphingField';
import LightRibbons from './LightRibbons';
import EnvironmentalLattice from './EnvironmentalLattice';
import FoldShells from './FoldShells';

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
    const focusRestraint = 1 - scene.fold * 0.58;
    const pointerX = reducedMotion ? 0 : THREE.MathUtils.clamp(state.pointer.x * 0.24 * focusRestraint, -0.24, 0.24);
    const pointerY = reducedMotion ? 0 : THREE.MathUtils.clamp(state.pointer.y * 0.16 * focusRestraint, -0.16, 0.16);
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
      <ambientLight intensity={0.11 + energy * 0.14 + scene.light * 0.035} />
      <pointLight position={[3.2, 4.2, 5.4]} intensity={(2.5 + scene.atmosphere * 1.8 + scene.light * 0.8) * energy} color="#7ddfff" distance={15} />
      <pointLight position={[-4.2, -2.1, 3]} intensity={(1.7 + scene.fold * 1.65) * energy} color="#b794ff" distance={13} />
      <pointLight position={[0, 0.2, 4.5]} intensity={scene.fold * scene.light * 1.45} color="#effcff" distance={9} />
      <AmbientField scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <PortalField scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <DomainOrbits scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <EnvironmentalLattice scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <LightRibbons scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <MorphingField progress={progress} energy={energy} tier={tier} reducedMotion={reducedMotion} scene={scene} />
      <SignalFlow scene={scene} tier={tier} reducedMotion={reducedMotion} />
      <ResolutionSigil scene={scene} />
      <FoldShells scene={scene} reducedMotion={reducedMotion} />
      <IntelligenceCore scene={scene} energy={energy} reducedMotion={reducedMotion} />
    </>
  );
}
