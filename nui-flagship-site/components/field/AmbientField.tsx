'use client';

import { useMemo, useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { FIELD_NODES } from '../../lib/field-model';
import { TIER_BUDGETS, type CapabilityTier } from '../../lib/capability';
import type { CinematicSceneState } from '../../lib/scene-state';

export default function AmbientField({ scene, tier, reducedMotion }: {
  scene: CinematicSceneState;
  tier: CapabilityTier;
  reducedMotion: boolean;
}) {
  return (
    <>
      <SpectralBackdrop scene={scene} reducedMotion={reducedMotion} />
      <SemanticDust scene={scene} tier={tier} reducedMotion={reducedMotion} />
    </>
  );
}

function SpectralBackdrop({ scene, reducedMotion }: { scene: CinematicSceneState; reducedMotion: boolean }) {
  const material = useMemo(() => new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    uniforms: { uTime: { value: 0 }, uAtmosphere: { value: 0 }, uPortal: { value: 0 }, uCathedral: { value: 0 } },
    vertexShader: `varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }`,
    fragmentShader: `
      varying vec2 vUv;
      uniform float uTime;
      uniform float uAtmosphere;
      uniform float uPortal;
      uniform float uCathedral;
      float hash(vec2 p){ return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453123); }
      void main(){
        vec2 p=vUv-0.5;
        float r=length(p);
        float angle=atan(p.y,p.x);
        float topology=0.5+0.5*sin(r*54.0-angle*4.0-uTime*0.16);
        float bands=0.5+0.5*sin((p.x*17.0+p.y*11.0)+sin(p.y*8.0)*2.0);
        float grain=hash(floor(vUv*vec2(180.0,120.0))+floor(uTime*0.05));
        float portal=exp(-abs(r-0.24)*24.0)*uPortal;
        vec3 cyan=vec3(0.08,0.52,0.68);
        vec3 violet=vec3(0.31,0.18,0.66);
        vec3 color=mix(cyan,violet,0.48+0.28*sin(angle*2.0));
        float alpha=(topology*0.018+bands*0.012+portal*0.055+grain*0.006)*(0.3+uAtmosphere*1.4+uCathedral*0.5);
        alpha*=smoothstep(0.72,0.08,r);
        gl_FragColor=vec4(color,alpha);
      }
    `,
  }), []);
  useFrame((_, delta) => {
    material.uniforms.uAtmosphere.value = scene.atmosphere;
    material.uniforms.uPortal.value = scene.portal;
    material.uniforms.uCathedral.value = scene.mode === 'cathedral' ? 1 : 0;
    if (!reducedMotion) material.uniforms.uTime.value += delta;
  });
  return (
    <mesh position={[0, 0, -6.2]} material={material}>
      <planeGeometry args={[28, 18, 1, 1]} />
    </mesh>
  );
}

function SemanticDust({ scene, tier, reducedMotion }: {
  scene: CinematicSceneState;
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
      data[i * 3] = anchor.position[0] + (a - Math.floor(a) - 0.5) * 1.35;
      data[i * 3 + 1] = anchor.position[1] + (b - Math.floor(b) - 0.5) * 1.35;
      data[i * 3 + 2] = anchor.position[2] + (c - Math.floor(c) - 0.5) * 1.7;
    }
    return data;
  }, [count]);

  useFrame((state, delta) => {
    if (!points.current || reducedMotion) return;
    points.current.rotation.y += delta * (0.012 + scene.atmosphere * 0.008);
    points.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.065) * 0.032;
  });

  const resolutionFade = 1 - scene.sigil * 0.62;
  return (
    <points ref={points} scale={scene.envelope * 0.92}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.014 + scene.atmosphere * 0.017} color="#b9ecff" transparent opacity={(0.08 + scene.atmosphere * 0.34) * resolutionFade} depthWrite={false} blending={THREE.AdditiveBlending} sizeAttenuation />
    </points>
  );
}
