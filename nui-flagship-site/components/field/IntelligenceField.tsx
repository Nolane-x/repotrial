'use client';

import { useMemo, useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Line } from '@react-three/drei';
import * as THREE from 'three';
import { FIELD_EDGES, FIELD_NODES, visibleFieldNodes, type FieldDomain } from '../../lib/field-model';
import { TIER_BUDGETS, type CapabilityTier } from '../../lib/capability';

const DOMAIN_COLOR: Record<FieldDomain, string> = {
  product: '#e8fbff',
  craft: '#77dfff',
  research: '#c5a8ff',
  routing: '#77f0d0',
  evidence: '#f8ca7c',
  critic: '#ff8fb9',
  verification: '#a9ffcf',
};

export default function IntelligenceField({ progress, energy, tier, reducedMotion }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const budget = TIER_BUDGETS[tier];
  return (
    <Canvas
      dpr={budget.dpr}
      camera={{ position: [0, 0, 9.4], fov: 46, near: 0.1, far: 40 }}
      gl={{ alpha: true, antialias: tier !== 'low', powerPreference: 'high-performance' }}
      style={{ width: '100%', height: '100%' }}
    >
      <Scene progress={progress} energy={energy} tier={tier} reducedMotion={reducedMotion} />
    </Canvas>
  );
}

function Scene({ progress, energy, tier, reducedMotion }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  useFrame((state, delta) => {
    if (reducedMotion) return;
    const climaxPull = progress > 0.78 && progress < 0.9 ? 1.15 : 0;
    const targetZ = 9.4 - progress * 1.55 - climaxPull;
    state.camera.position.z = THREE.MathUtils.damp(state.camera.position.z, targetZ, 2.7, delta);
    state.camera.position.x = THREE.MathUtils.damp(state.camera.position.x, state.pointer.x * 0.34, 2.2, delta);
    state.camera.position.y = THREE.MathUtils.damp(state.camera.position.y, state.pointer.y * 0.22, 2.2, delta);
  });

  return (
    <>
      <ambientLight intensity={0.14 + energy * 0.16} />
      <pointLight position={[3, 4, 5]} intensity={3.2 * energy} color="#7ddfff" distance={14} />
      <pointLight position={[-4, -2, 3]} intensity={2.2 * energy} color="#b794ff" distance={12} />
      <IntelligenceCore progress={progress} energy={energy} reducedMotion={reducedMotion} />
      <SemanticNetwork progress={progress} energy={energy} tier={tier} reducedMotion={reducedMotion} />
      <SemanticDust progress={progress} energy={energy} tier={tier} reducedMotion={reducedMotion} />
    </>
  );
}

function IntelligenceCore({ progress, energy, reducedMotion }: { progress: number; energy: number; reducedMotion: boolean }) {
  const mesh = useRef<THREE.Mesh>(null);
  const material = useMemo(() => new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    uniforms: {
      uTime: { value: 0 },
      uProgress: { value: progress },
      uEnergy: { value: energy },
    },
    vertexShader: `
      uniform float uTime;
      uniform float uProgress;
      varying vec3 vNormal;
      varying vec3 vPosition;
      void main() {
        vec3 p = position;
        float waveA = sin(p.y * 7.0 + uTime * 1.25) * 0.045;
        float waveB = cos(p.x * 6.0 - uTime * 0.85) * 0.035;
        p += normal * (waveA + waveB) * (0.2 + uProgress);
        vNormal = normalize(normalMatrix * normal);
        vPosition = p;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0);
      }
    `,
    fragmentShader: `
      uniform float uProgress;
      uniform float uEnergy;
      varying vec3 vNormal;
      varying vec3 vPosition;
      void main() {
        float fresnel = pow(1.0 - abs(vNormal.z), 2.6);
        float lattice = 0.5 + 0.5 * sin(vPosition.y * 14.0 + vPosition.x * 9.0);
        vec3 cold = vec3(0.08, 0.34, 0.48);
        vec3 hot = vec3(0.55, 0.93, 1.0);
        vec3 violet = vec3(0.45, 0.28, 0.88);
        vec3 color = mix(cold, hot, clamp(uEnergy * 1.1, 0.0, 1.0));
        color = mix(color, violet, smoothstep(0.72, 0.92, uProgress) * 0.28);
        float alpha = (0.15 + fresnel * 0.72 + lattice * 0.08) * (0.35 + uEnergy * 0.75);
        gl_FragColor = vec4(color, alpha);
      }
    `,
  }), []);

  useFrame((_, delta) => {
    material.uniforms.uProgress.value = progress;
    material.uniforms.uEnergy.value = energy;
    if (!reducedMotion) material.uniforms.uTime.value += delta;
    if (mesh.current) {
      const growth = 0.18 + Math.min(1.6, progress * 1.85);
      const resolve = progress > 0.9 ? 1 - (progress - 0.9) * 4.8 : 1;
      const scale = Math.max(0.2, growth * resolve);
      mesh.current.scale.setScalar(scale);
      mesh.current.rotation.y += reducedMotion ? 0 : delta * (0.08 + energy * 0.09);
      mesh.current.rotation.x = progress * 0.36;
    }
  });

  return (
    <mesh ref={mesh} material={material}>
      <icosahedronGeometry args={[0.82, 5]} />
    </mesh>
  );
}

function SemanticNetwork({ progress, energy, tier, reducedMotion }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const nodes = visibleFieldNodes(progress);
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges = FIELD_EDGES.filter(([a, b]) => visibleIds.has(a) && visibleIds.has(b));
  const nodeById = new Map(FIELD_NODES.map((node) => [node.id, node]));
  const lineOpacity = TIER_BUDGETS[tier].lineOpacity * (0.35 + energy * 0.9);

  useFrame((state, delta) => {
    if (!group.current || reducedMotion) return;
    group.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.12) * 0.045;
    group.current.rotation.y += delta * (0.025 + progress * 0.055);
  });

  return (
    <group ref={group} scale={0.82 + progress * 0.34}>
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
              <meshBasicMaterial color={DOMAIN_COLOR[node.domain]} transparent opacity={0.52 + energy * 0.42} blending={THREE.AdditiveBlending} depthWrite={false} />
            </mesh>
            <mesh scale={(0.16 + node.weight * 0.05) * (0.6 + energy * 0.5)}>
              <sphereGeometry args={[1, 12, 12]} />
              <meshBasicMaterial color={DOMAIN_COLOR[node.domain]} transparent opacity={0.035 + energy * 0.055} blending={THREE.AdditiveBlending} depthWrite={false} />
            </mesh>
          </group>
        );
      })}
    </group>
  );
}

function SemanticDust({ progress, energy, tier, reducedMotion }: {
  progress: number;
  energy: number;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  const points = useRef<THREE.Points>(null);
  const count = TIER_BUDGETS[tier].particles;
  const positions = useMemo(() => {
    const data = new Float32Array(count * 3);
    for (let i = 0; i < count; i += 1) {
      const anchor = FIELD_NODES[i % FIELD_NODES.length];
      const seed = i * 12.9898 + (i % FIELD_NODES.length) * 78.233;
      const a = Math.sin(seed) * 43758.5453;
      const b = Math.sin(seed * 1.73) * 24634.6345;
      const c = Math.cos(seed * 0.91) * 12567.347;
      const jx = (a - Math.floor(a) - 0.5) * 1.25;
      const jy = (b - Math.floor(b) - 0.5) * 1.25;
      const jz = (c - Math.floor(c) - 0.5) * 1.55;
      data[i * 3] = anchor.position[0] + jx;
      data[i * 3 + 1] = anchor.position[1] + jy;
      data[i * 3 + 2] = anchor.position[2] + jz;
    }
    return data;
  }, [count]);

  useFrame((state, delta) => {
    if (!points.current || reducedMotion) return;
    points.current.rotation.y += delta * 0.018;
    points.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.08) * 0.035;
  });

  return (
    <points ref={points} scale={0.62 + progress * 0.58}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.018 + energy * 0.018} color="#b9ecff" transparent opacity={(0.08 + progress * 0.38) * (0.45 + energy)} depthWrite={false} blending={THREE.AdditiveBlending} sizeAttenuation />
    </points>
  );
}
