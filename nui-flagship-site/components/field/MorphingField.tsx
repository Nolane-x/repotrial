'use client';

import { useMemo, useRef, useState } from 'react';
import { Line } from '@react-three/drei';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { FIELD_EDGES, visibleFieldNodes, type FieldDomain } from '../../lib/field-model';
import { morphFieldNodes, semanticNeighborhood } from '../../lib/morph-field';
import { TIER_BUDGETS, type CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';

const DOMAIN_COLOR: Record<FieldDomain, string> = {
  product: '#e8fbff', craft: '#77dfff', research: '#c5a8ff', routing: '#77f0d0',
  evidence: '#f8ca7c', critic: '#ff8fb9', verification: '#a9ffcf',
};

export default function MorphingSemanticNetwork({ progress, energy, tier, reducedMotion, scene }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
  scene: CinematicSceneState;
}) {
  const group = useRef<THREE.Group>(null);
  const focusClock = useRef(0);
  const lastFocus = useRef<string | null>(null);
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const visible = visibleFieldNodes(progress);
  const nodes = useMemo(() => morphFieldNodes(visible, scene), [visible, scene.morph, scene.fold, scene.portal, scene.typeDepth]);
  const nodeMap = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const visibleIds = useMemo(() => new Set(nodes.map((node) => node.id)), [nodes]);
  const edges = useMemo(() => FIELD_EDGES.filter(([a, b]) => visibleIds.has(a) && visibleIds.has(b)), [visibleIds]);
  const focusedSet = useMemo(() => new Set(focusedId ? semanticNeighborhood(focusedId) : []), [focusedId]);

  useFrame((state, delta) => {
    if (group.current && !reducedMotion) {
      group.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.095) * 0.032 * (1 - scene.fold * 0.7);
      group.current.rotation.y += delta * (0.012 + scene.orbit * 0.018) * (1 - scene.fold * 0.75);
    }
    focusClock.current += delta;
    if (focusClock.current < 0.08 || nodes.length === 0) return;
    focusClock.current = 0;
    const targetX = state.pointer.x * 3.25;
    const targetY = state.pointer.y * 2.35;
    let nearest: { id: string; distance: number } | null = null;
    for (const node of nodes) {
      const dx = node.position[0] - targetX;
      const dy = node.position[1] - targetY;
      const distance = dx * dx + dy * dy;
      if (!nearest || distance < nearest.distance) nearest = { id: node.id, distance };
    }
    const threshold = reducedMotion ? 0.72 : 1.15;
    const next = nearest && nearest.distance <= threshold * threshold ? nearest.id : null;
    if (next !== lastFocus.current) {
      lastFocus.current = next;
      setFocusedId(next);
    }
  });

  const lineOpacity = TIER_BUDGETS[tier].lineOpacity * (0.28 + energy * 0.86) * scene.network;
  const focusAmplitude = reducedMotion ? 0.18 : 0.48;

  return (
    <group ref={group} scale={scene.envelope} name="m3-semantic-focus-field">
      {edges.map(([a, b]) => {
        const source = nodeMap.get(a)!;
        const target = nodeMap.get(b)!;
        const focused = focusedSet.has(a) && focusedSet.has(b);
        return <Line key={`${a}-${b}`} points={[source.position, target.position]} color={focused ? '#dffaff' : '#9de8ff'} lineWidth={focused ? 1.08 : 0.58} transparent opacity={lineOpacity * (focused ? 1.72 : 1)} />;
      })}
      {nodes.map((node, index) => {
        const active = Math.max(0.12, Math.min(1, progress * 5 - index * 0.09));
        const focus = focusedSet.has(node.id) ? focusAmplitude : 0;
        const baseScale = (0.055 + node.weight * 0.035) * (0.75 + active * 0.55);
        return (
          <group key={node.id} position={node.position} name={`semantic-${node.id}`}>
            <mesh scale={baseScale * (1 + focus)}>
              <sphereGeometry args={[1, 16, 16]} />
              <meshBasicMaterial color={DOMAIN_COLOR[node.domain]} transparent opacity={(0.48 + energy * 0.38 + focus * 0.34) * scene.network} blending={THREE.AdditiveBlending} depthWrite={false} />
            </mesh>
            <mesh scale={(0.16 + node.weight * 0.05) * (0.6 + energy * 0.5) * (1 + focus * 1.8)}>
              <sphereGeometry args={[1, 12, 12]} />
              <meshBasicMaterial color={DOMAIN_COLOR[node.domain]} transparent opacity={(0.03 + energy * 0.05 + focus * 0.08) * scene.network} blending={THREE.AdditiveBlending} depthWrite={false} />
            </mesh>
          </group>
        );
      })}
    </group>
  );
}
