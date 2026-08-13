'use client';

import { useMemo, useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import type { CinematicSceneState } from '../../lib/scene-state';

export default function IntelligenceCore({ scene, energy, reducedMotion }: {
  scene: CinematicSceneState;
  energy: number;
  reducedMotion: boolean;
}) {
  const group = useRef<THREE.Group>(null);
  const cathedral = scene.mode === 'cathedral' ? 1 : 0;
  const material = useMemo(() => new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    uniforms: {
      uTime: { value: 0 },
      uCore: { value: 0 },
      uEnergy: { value: 0 },
      uCathedral: { value: 0 },
      uSigil: { value: 0 },
    },
    vertexShader: `
      uniform float uTime;
      uniform float uCore;
      uniform float uCathedral;
      varying vec3 vNormal;
      varying vec3 vPosition;
      void main() {
        vec3 p = position;
        float waveA = sin(p.y * 8.0 + uTime * 1.1) * 0.035;
        float waveB = cos(p.x * 6.0 - uTime * 0.82) * 0.028;
        float waveC = sin((p.x + p.z) * 9.0 + uTime * 0.45) * 0.018;
        p += normal * (waveA + waveB + waveC) * (0.18 + uCore * 0.72 + uCathedral * 0.55);
        vNormal = normalize(normalMatrix * normal);
        vPosition = p;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0);
      }
    `,
    fragmentShader: `
      uniform float uTime;
      uniform float uCore;
      uniform float uEnergy;
      uniform float uCathedral;
      uniform float uSigil;
      varying vec3 vNormal;
      varying vec3 vPosition;
      void main() {
        float fresnel = pow(1.0 - abs(vNormal.z), 2.8);
        float latitude = 0.5 + 0.5 * sin(vPosition.y * 17.0 + sin(vPosition.x * 5.0) * 1.7);
        float longitude = 0.5 + 0.5 * sin(atan(vPosition.z, vPosition.x) * 11.0 + uTime * 0.18);
        float lattice = pow(latitude * longitude, 1.8);
        float pulse = 0.72 + 0.28 * sin(uTime * 0.7 + length(vPosition) * 8.0);
        vec3 deep = vec3(0.035, 0.16, 0.24);
        vec3 cyan = vec3(0.36, 0.88, 1.0);
        vec3 violet = vec3(0.57, 0.38, 1.0);
        vec3 pearl = vec3(0.91, 0.99, 1.0);
        vec3 color = mix(deep, cyan, clamp(fresnel + uCore * 0.24, 0.0, 1.0));
        color = mix(color, violet, uCathedral * (0.16 + lattice * 0.25));
        color = mix(color, pearl, uSigil * 0.18 + lattice * 0.12);
        float alpha = (0.10 + fresnel * 0.64 + lattice * (0.08 + uCathedral * 0.14)) * (0.42 + uEnergy * 0.62) * pulse;
        gl_FragColor = vec4(color, alpha);
      }
    `,
  }), []);

  useFrame((_, delta) => {
    material.uniforms.uCore.value = scene.core;
    material.uniforms.uEnergy.value = energy;
    material.uniforms.uCathedral.value = cathedral;
    material.uniforms.uSigil.value = scene.sigil;
    if (!reducedMotion) material.uniforms.uTime.value += delta;
    if (!group.current) return;
    const resolvedCompression = 1 - scene.sigil * 0.28;
    const scale = Math.max(0.12, scene.envelope * (0.38 + scene.core * 0.32) * resolvedCompression);
    group.current.scale.setScalar(scale);
    if (!reducedMotion) {
      group.current.rotation.y += delta * (0.055 + energy * 0.055);
      group.current.rotation.x = THREE.MathUtils.damp(group.current.rotation.x, cathedral ? 0.32 : 0.12, 2.2, delta);
    }
  });

  return (
    <group ref={group}>
      <mesh material={material}>
        <icosahedronGeometry args={[0.92, 5]} />
      </mesh>
      <mesh scale={1.15}>
        <icosahedronGeometry args={[0.92, 2]} />
        <meshBasicMaterial color="#bcefff" wireframe transparent opacity={0.035 + scene.core * 0.075 + cathedral * 0.09} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh scale={0.34 + scene.sigil * 0.08}>
        <sphereGeometry args={[0.8, 24, 24]} />
        <meshBasicMaterial color={cathedral ? '#f0e9ff' : '#d9fbff'} transparent opacity={0.22 + energy * 0.35} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh scale={1.72}>
        <sphereGeometry args={[0.86, 24, 24]} />
        <meshBasicMaterial color="#75dfff" side={THREE.BackSide} transparent opacity={0.018 + cathedral * 0.028 + scene.sigil * 0.012} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
    </group>
  );
}
