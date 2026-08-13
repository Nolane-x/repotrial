'use client';

import { useMemo, useRef } from 'react';
import { Line } from '@react-three/drei';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { FIELD_NODES } from '../../lib/field-model';
import { morphNodePosition } from '../../lib/morph-field';
import type { CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';

const NODE_MAP = new Map(FIELD_NODES.map((node) => [node.id, node]));
const RIBBON_PATHS = [
  ['intent', 'routing', 'release'],
  ['type', 'graph', 'source'],
  ['adequacy', 'routing', 'verify'],
  ['space', 'release', 'critic'],
] as const;
const RIBBON_COLORS = ['#7de7ff', '#b99cff', '#8ff5d8', '#ffe0ad'];

export default function LightRibbons({ scene, tier, reducedMotion }: {
  scene: CinematicSceneState;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const count = tier === 'high' ? 4 : tier === 'medium' ? 3 : 2;

  useFrame((state) => {
    if (!group.current || reducedMotion) return;
    group.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.17) * 0.018 * scene.light;
    group.current.rotation.x = Math.cos(state.clock.elapsedTime * 0.11) * 0.012 * scene.light;
  });

  return (
    <group ref={group} scale={scene.envelope} name="m3-light-ribbons">
      {RIBBON_PATHS.slice(0, count).map((route, index) => (
        <Ribbon key={route.join('-')} route={route} index={index} scene={scene} />
      ))}
    </group>
  );
}

function Ribbon({ route, index, scene }: {
  route: readonly string[];
  index: number;
  scene: CinematicSceneState;
}) {
  const points = useMemo(() => {
    const controls = route
      .map((id) => NODE_MAP.get(id))
      .filter(Boolean)
      .map((node) => new THREE.Vector3(...morphNodePosition(node!, scene).position));
    if (controls.length < 2) return controls;
    const curve = new THREE.CatmullRomCurve3(controls, false, 'centripetal', 0.5);
    return curve.getPoints(28);
  }, [route, scene.morph, scene.fold, scene.portal, scene.typeDepth]);

  const intensity = scene.light * scene.network;
  return (
    <group>
      <Line
        points={points}
        color={RIBBON_COLORS[index % RIBBON_COLORS.length]}
        lineWidth={7.5 + scene.fold * 3.5}
        transparent
        opacity={intensity * (0.035 + scene.fold * 0.028)}
      />
      <Line
        points={points}
        color={index === 1 ? '#e7deff' : '#ddfaff'}
        lineWidth={0.8 + scene.fold * 0.55}
        transparent
        opacity={intensity * (0.18 + scene.fold * 0.16)}
      />
    </group>
  );
}
