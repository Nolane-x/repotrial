'use client';

import dynamic from 'next/dynamic';
import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { motion } from 'motion/react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { chooseCapabilityTier, type CapabilityTier } from '../../lib/capability';
import { energyAt, EXPERIENCE_BEATS, getExperienceState, type ExperienceBeat } from '../../lib/experience';
import { getFieldStage } from '../../lib/field-model';
import { getCinematicSceneState } from '../../lib/scene-state';

const IntelligenceField = dynamic(() => import('../field/IntelligenceField'), { ssr: false });

const DOMAIN_ROWS = [
  ['PRODUCT', 'Intent · tasks · information architecture'],
  ['CRAFT', 'Typography · color · depth · motion · spatial drama'],
  ['RESEARCH', 'Source archaeology · authority · synthesis'],
  ['ROUTING', 'Specialist ownership · graph · escalation'],
  ['EVIDENCE', 'Known · unknown · blocked · provenance'],
  ['CRITICS', 'Execution · adequacy · genericity · falsification'],
  ['VERIFY', 'Runtime · viewport · accessibility · release gates'],
] as const;
const RESOLUTION_DOMAINS = ['product', 'craft', 'research', 'routing', 'evidence', 'critic', 'verification'] as const;
const ROUTE_STEPS = ['RAW INTENT', 'ROUTE', 'DIVERGE', 'SYNTHESIZE', 'RENDER', 'CRITIQUE', 'FALSIFY', 'VERIFY'];

export default function ExperienceShell() {
  const [progress, setProgress] = useState(0);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [tier, setTier] = useState<CapabilityTier>('medium');
  const state = useMemo(() => getExperienceState(progress), [progress]);
  const energy = energyAt(progress);
  const stage = getFieldStage(progress);
  const scene = useMemo(() => getCinematicSceneState(progress, reducedMotion), [progress, reducedMotion]);

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const apply = () => {
      const reduce = media.matches;
      setReducedMotion(reduce);
      document.documentElement.dataset.motion = reduce ? 'reduce' : 'full';
      const nav = navigator as Navigator & { deviceMemory?: number };
      setTier(chooseCapabilityTier({
        deviceMemory: nav.deviceMemory ?? 4,
        hardwareConcurrency: navigator.hardwareConcurrency ?? 4,
        dpr: window.devicePixelRatio || 1,
        reducedMotion: reduce,
      }));
    };
    apply();
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, []);

  useEffect(() => {
    gsap.registerPlugin(ScrollTrigger);
    let goal = 0;
    let current = 0;
    const trigger = ScrollTrigger.create({
      start: 0,
      end: () => ScrollTrigger.maxScroll(window),
      onUpdate: (self) => { goal = self.progress; },
    });
    const tick = () => {
      current = reducedMotion ? goal : current + (goal - current) * 0.12;
      if (Math.abs(current - goal) < 0.00008) current = goal;
      setProgress(Math.min(1, Math.max(0, current)));
    };
    gsap.ticker.add(tick);
    ScrollTrigger.refresh();
    return () => { trigger.kill(); gsap.ticker.remove(tick); };
  }, [reducedMotion]);

  const style = {
    '--story-progress': progress,
    '--story-energy': energy / 100,
    '--beat-progress': state.localProgress,
    '--cinematic-core': scene.core,
    '--cinematic-orbit': scene.orbit,
    '--cinematic-portal': scene.portal,
    '--cinematic-signal': scene.signal,
    '--cinematic-atmosphere': scene.atmosphere,
    '--cinematic-sigil': scene.sigil,
    '--m3-morph': scene.morph,
    '--m3-fold': scene.fold,
    '--m3-light': scene.light,
    '--m3-type-depth': scene.typeDepth,
    '--m3-pulse': scene.pulse,
  } as CSSProperties;

  return (
    <div
      className={`experience-root stage-${stage} mode-${scene.mode}`}
      data-cinematic-mode={scene.mode}
      data-cinematic-portal={scene.portal.toFixed(2)}
      data-cinematic-signal={scene.signal.toFixed(2)}
      data-cinematic-sigil={scene.sigil.toFixed(2)}
      data-m3-morph={scene.morph.toFixed(2)}
      data-m3-fold={scene.fold.toFixed(2)}
      data-m3-light={scene.light.toFixed(2)}
      data-m3-type-depth={scene.typeDepth.toFixed(2)}
      data-m3-pulse={scene.pulse.toFixed(2)}
      style={style}
    >
      <a className="skip-link" href="#content">Skip to content</a>
      <div className="atmosphere" aria-hidden="true" />
      <div className="cinematic-vignette" aria-hidden="true" />
      <div className="m3-depth-grid" aria-hidden="true"><i /><i /><span>SPATIAL / METAMORPHOSIS</span></div>
      <div className="field-layer" aria-hidden="true"><IntelligenceField progress={progress} energy={energy / 100} tier={tier} reducedMotion={reducedMotion} scene={scene} /></div>
      <nav className="site-nav" aria-label="Primary">
        <a className="wordmark" href="#top" aria-label="Nolane home"><span className="wordmark-mark">N</span><span>NOLANE</span></a>
        <div className="nav-state" aria-hidden="true"><span>{String(state.beat.index).padStart(2, '0')}</span><span className="nav-state-title">{state.beat.intent}</span></div>
        <a className="nav-action" href="https://github.com/Nolane-x/Nolane-UI-Intelligence">SOURCE ↗</a>
      </nav>
      <div className="progress-rail" aria-hidden="true"><span style={{ transform: `scaleY(${Math.max(0.015, progress)})` }} /></div>
      <div className="field-hud" aria-hidden="true"><span>{scene.mode.toUpperCase()}</span><span>{tier.toUpperCase()} / {Math.round(energy)}E</span></div>
      <main id="content">{EXPERIENCE_BEATS.map((beat) => <BeatSection key={beat.id} beat={beat} reducedMotion={reducedMotion} />)}</main>
    </div>
  );
}

function BeatSection({ beat, reducedMotion }: { beat: ExperienceBeat; reducedMotion: boolean }) {
  const isHero = beat.id === 'silence';
  return (
    <section id={isHero ? 'top' : beat.id} data-beat={beat.id} className={`beat beat--${beat.id}`}>
      <div className="beat-inner">
        <motion.div className="beat-copy" initial={reducedMotion ? false : { opacity: 0.18, y: 46 }} whileInView={reducedMotion ? undefined : { opacity: 1, y: 0 }} viewport={{ amount: 0.35, once: false }} transition={{ duration: 0.85, ease: [0.16, 1, 0.3, 1] }}>
          <div className="eyebrow"><span>{beat.eyebrow}</span><span className="eyebrow-line" /></div>
          {isHero ? <h1>INTELLIGENCE <em>IS NOT</em> A MODEL.<br /><strong>IT IS A SYSTEM.</strong></h1> : <h2>{beat.title}</h2>}
          <p className="beat-body">{beat.body}</p>
          {beat.id === 'silence' && <div className="scroll-cue" aria-hidden="true"><span>SCROLL TO ENTER</span><i /></div>}
          {beat.id === 'architecture' && <ArchitectureRows />}
          {beat.id === 'scale-break' && <ScaleStatement />}
          {beat.id === 'motion' && <RouteTrace />}
          {beat.id === 'world-opens' && <WorldStatement />}
          {beat.id === 'climax' && <ClimaxStatement />}
          {beat.id === 'resolution' && <Resolution />}
        </motion.div>
        <div className="beat-index" aria-hidden="true"><span>0{beat.index}</span><i /></div>
      </div>
    </section>
  );
}

function ArchitectureRows() {
  return <div className="architecture-rows">{DOMAIN_ROWS.map(([name, detail], index) => <div className="architecture-row" key={name}><span>{String(index + 1).padStart(2, '0')}</span><b>{name}</b><p>{detail}</p><i /></div>)}</div>;
}

function ScaleStatement() {
  return <div className="scale-m2-wrap"><div className="depth-aperture-copy" aria-hidden="true"><i /><i /><i /><i /><span>DEPTH / 158</span></div><div className="m3-aperture-spine" aria-hidden="true"><i /><i /><i /><span>TOPOLOGY / BEND</span></div><div className="scale-statement" aria-label="158 routed skills"><span className="scale-number">158</span><span className="scale-label">ROUTED<br />SPECIALISTS</span><span className="scale-sub">ONE COHERENT<br />DECISION SYSTEM</span></div></div>;
}

function RouteTrace() {
  return <div className="route-trace" aria-label="NUI route lifecycle">{ROUTE_STEPS.map((step, index) => <div className="route-step" key={step} style={{ '--route-index': index } as CSSProperties}><span>{String(index + 1).padStart(2, '0')}</span><b>{step}</b><i /></div>)}<span className="route-energy" aria-hidden="true" /><span className="m3-semantic-pulse" aria-hidden="true"><i /><i /><i /></span></div>;
}

function WorldStatement() {
  return <div className="world-m2-wrap"><div className="world-depth-frame" aria-hidden="true"><i /><i /><i /><i /><span>ENVIRONMENT / OPEN</span></div><div className="m3-world-horizon" aria-hidden="true"><i /><i /><i /><span>FIELD / ENVIRONMENT</span></div><div className="world-statement" aria-hidden="true"><span>THE PAGE</span><strong>GIVES WAY</strong><span>TO THE SYSTEM</span></div></div>;
}

function ClimaxStatement() {
  return <div className="climax-m2-wrap"><div className="cathedral-axis" aria-hidden="true"><i /><i /><span>07 / CONVERGENCE</span></div><div className="impossible-fold" aria-hidden="true"><i /><i /><i /><i /><span>IMPOSSIBLE / FOLD</span></div><div className="climax-statement"><span>ONE</span><strong>ARCHITECTURE</strong><small>product × craft × research × routing × evidence × critics × verification</small></div></div>;
}

function Resolution() {
  return <div className="resolution-m2-wrap"><div className="m3-resolution-lock" aria-hidden="true"><i /><i /><span>SEVEN / ONE</span></div><div className="resolution-domain-marks" aria-label="Seven NUI domains converge">{RESOLUTION_DOMAINS.map((domain, index) => <span className="resolution-domain-mark" data-domain={domain} key={domain}><i>{String(index + 1).padStart(2, '0')}</i><b>{domain}</b></span>)}</div><div className="resolution-actions"><a className="primary-cta" href="https://github.com/Nolane-x/Nolane-UI-Intelligence"><span>ENTER THE SYSTEM</span><i>↗</i></a><p>Open source intelligence for agents that refuse to confuse “it renders” with “it is designed.”</p></div></div>;
}
