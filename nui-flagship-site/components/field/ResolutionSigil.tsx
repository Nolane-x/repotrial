'use client';

import { Line } from '@react-three/drei';
import * as THREE from 'three';
import { resolutionSigilNodes, type FieldDomain } from '../../lib/field-model';
import type { CinematicSceneState } from '../../lib/scene-state';

const COLORS: Record<FieldDomain, string> = {
  product: '#e8fbff', craft: '#77dfff', research: '#c5a8ff', routing: '#77f0d0',
  evidence: '#f8ca7c', critic: '#ff8fb9', verification: '#a9ffcf',
};

export default function ResolutionSigil({ scene }: { scene: CinematicSceneState }) {
  const nodes = resolutionSigilNodes();
  const blend = scene.sigil;
  const positions = nodes.map((node) => new THREE.Vector3(
    THREE.MathUtils.lerp(node.position[0], node.sigilPosition[0], blend),
    THREE.MathUtils.lerp(node.position[1], node.sigilPosition[1], blend),
    THREE.MathUtils.lerp(node.position[2], node.sigilPosition[2], blend),
  ));
  const closed = [...positions, positions[0]];
  const accent = [positions[0], positions[3], positions[6]];

  return (
    <group scale={0.82 + blend * 0.08}>
      <Line points={closed} color="#a9efff" lineWidth={0.72} transparent opacity={blend * 0.32} />
      <Line points={accent} color="#e8fbff" lineWidth={1.05} transparent opacity={blend * 0.46} />
      {nodes.map((node, index) => (
        <group key={node.id} position={positions[index]}>
          <mesh>
            <sphereGeometry args={[0.055 + node.weight * 0.02, 16, 16]} />
            <meshBasicMaterial color={COLORS[node.domain]} transparent opacity={blend * 0.86} blending={THREE.AdditiveBlending} depthWrite={false} />
          </mesh>
          <mesh scale={2.6}>
            <sphereGeometry args={[0.055, 10, 10]} />
            <meshBasicMaterial color={COLORS[node.domain]} transparent opacity={blend * 0.07} blending={THREE.AdditiveBlending} depthWrite={false} />
          </mesh>
        </group>
      ))}
      <mesh scale={0.32 + blend * 0.08}>
        <icosahedronGeometry args={[0.62, 2]} />
        <meshBasicMaterial color="#e8fbff" wireframe transparent opacity={blend * 0.34} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
    </group>
  );
}
