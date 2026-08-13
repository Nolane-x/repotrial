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
  const center = new THREE.Vector3(0, 0, 0);
  const positions = nodes.map((node) => new THREE.Vector3(
    THREE.MathUtils.lerp(node.position[0], node.sigilPosition[0], blend),
    THREE.MathUtils.lerp(node.position[1], node.sigilPosition[1], blend),
    THREE.MathUtils.lerp(node.position[2], node.sigilPosition[2], blend),
  ));
  const closed = [...positions, positions[0]];
  const accent = [positions[0], positions[3], positions[6], positions[2]];

  return (
    <group scale={0.86 + blend * 0.12}>
      <Line points={closed} color="#bff4ff" lineWidth={0.95} transparent opacity={blend * 0.58} />
      <Line points={accent} color="#f0fbff" lineWidth={1.15} transparent opacity={blend * 0.72} />
      {positions.map((position, index) => (
        <Line key={`spoke-${nodes[index].id}`} points={[center, position]} color={COLORS[nodes[index].domain]} lineWidth={0.55} transparent opacity={blend * 0.26} />
      ))}
      {nodes.map((node, index) => (
        <group key={node.id} position={positions[index]}>
          <mesh>
            <sphereGeometry args={[0.06 + node.weight * 0.02, 16, 16]} />
            <meshBasicMaterial color={COLORS[node.domain]} transparent opacity={blend * 0.96} blending={THREE.AdditiveBlending} depthWrite={false} />
          </mesh>
          <mesh scale={2.9}>
            <sphereGeometry args={[0.055, 10, 10]} />
            <meshBasicMaterial color={COLORS[node.domain]} transparent opacity={blend * 0.085} blending={THREE.AdditiveBlending} depthWrite={false} />
          </mesh>
        </group>
      ))}
      <mesh rotation={[0, 0, Math.PI / 7]}>
        <torusGeometry args={[1.46, 0.006, 5, 128]} />
        <meshBasicMaterial color="#a7ebff" transparent opacity={blend * 0.13} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh scale={0.34 + blend * 0.09}>
        <icosahedronGeometry args={[0.62, 2]} />
        <meshBasicMaterial color="#e8fbff" wireframe transparent opacity={blend * 0.48} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
    </group>
  );
}
