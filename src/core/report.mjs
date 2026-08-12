const VERDICT_COLORS = Object.freeze({
  TRUSTED: '#22c55e', CAUTIOUS: '#eab308', RECKLESS: '#f97316', DANGEROUS: '#ef4444', UNPROVEN: '#94a3b8'
});

export function renderHtmlReport(report) {
  const verdict = report.verdict.label;
  const color = VERDICT_COLORS[verdict] ?? VERDICT_COLORS.UNPROVEN;
  const proven = report.charges.filter((charge) => charge.status === 'proven');
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const charges = [...report.charges].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || a.title.localeCompare(b.title));
  const evidenceCount = report.charges.reduce((sum, charge) => sum + (Array.isArray(charge.evidence) ? charge.evidence.length : 0), 0);
  const differential = report.differential?.summary ?? { new: 0, existing: 0, resolved: 0 };
  const runtimeRuns = Array.isArray(report.runtime?.runs) ? report.runtime.runs.length : 0;
  const componentCount = Number(report.supplyChain?.componentCount ?? 0);

  const chargeHtml = charges.length
    ? charges.map((charge, index) => renderCharge(charge, index + 1)).join('\n')
    : '<div class="empty">No charge was proven in the inspected scope.</div>';
  const safeguards = report.safeguards.length
    ? report.safeguards.map((item) => `<li><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.detail ?? '')}</span></li>`).join('')
    : '<li><strong>None observed</strong><span>No explicit safeguard was detected.</span></li>';
  const omissions = report.scan.omissions.length
    ? report.scan.omissions.slice(0, 50).map((item) => `<li><code>${escapeHtml(item.path)}</code><span>${escapeHtml(item.reason)}</span></li>`).join('')
    : '<li><strong>Complete</strong><span>No inspectable-scope omission was recorded.</span></li>';
  const panels = [
    renderReasoningPanel(report.reasoning),
    renderCausalPanel(report.causal),
    renderExperimentsPanel(report.experiments),
    renderForgeOsPanel(report.forgeos),
    renderRuntimePanel(report.runtime),
    renderSupplyPanel(report.supplyChain),
    renderDifferentialPanel(report.differential),
    renderIntegrityPanel(report.integrity, report.receipt)
  ].join('\n');
  const rawJson = JSON.stringify(report).replaceAll('<', '\\u003c').replaceAll('>', '\\u003e').replaceAll('&', '\\u0026');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>RepoTrial — ${escapeHtml(verdict)}</title>
<style>
:root{--bg:#070a10;--panel:#0e1420;--panel2:#121a29;--border:#263247;--text:#e5edf8;--muted:#91a0b7;--accent:${color};--critical:#ef4444;--high:#fb923c;--medium:#eab308;--low:#38bdf8;--shadow:0 24px 80px rgba(0,0,0,.36)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% -10%,rgba(59,130,246,.18),transparent 34%),radial-gradient(circle at 90% 0%,rgba(239,68,68,.14),transparent 28%),var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{max-width:1240px;margin:0 auto;padding:42px 24px 72px}.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px}.brand{display:flex;gap:12px;align-items:center;font-weight:800;letter-spacing:.02em}.seal{width:38px;height:38px;border:1px solid var(--border);border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,#172033,#0b1019);box-shadow:inset 0 1px rgba(255,255,255,.08)}.meta{color:var(--muted);font-size:13px;text-align:right}.hero{position:relative;overflow:hidden;border:1px solid var(--border);border-radius:24px;background:linear-gradient(145deg,rgba(18,26,41,.96),rgba(8,12,20,.96));box-shadow:var(--shadow);padding:34px}.hero:after{content:"";position:absolute;inset:auto -80px -110px auto;width:320px;height:320px;border-radius:50%;background:var(--accent);filter:blur(100px);opacity:.12}.eyebrow{text-transform:uppercase;letter-spacing:.18em;color:var(--muted);font-size:11px;font-weight:800}.verdict{font-size:clamp(48px,9vw,106px);line-height:.95;margin:13px 0 16px;letter-spacing:-.06em;color:var(--accent);text-shadow:0 0 48px color-mix(in srgb,var(--accent) 25%,transparent)}.hero p{max-width:750px;color:#b9c5d6;font-size:17px}.metrics{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:12px;margin-top:28px}.metric{background:rgba(4,7,12,.48);border:1px solid var(--border);border-radius:15px;padding:15px;min-width:0}.metric b{display:block;font-size:23px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.metric span{color:var(--muted);font-size:12px}.layout{display:grid;grid-template-columns:minmax(0,1fr) 350px;gap:20px;margin-top:20px}.panel{border:1px solid var(--border);border-radius:20px;background:rgba(14,20,32,.92);box-shadow:0 14px 45px rgba(0,0,0,.22)}.panel-head{display:flex;justify-content:space-between;align-items:center;padding:19px 21px;border-bottom:1px solid var(--border)}.panel-head h2{margin:0;font-size:16px}.count{color:var(--muted);font-size:12px}.charges{padding:12px}.charge{border:1px solid var(--border);border-radius:16px;background:var(--panel2);margin:9px 0;overflow:hidden}.charge summary{cursor:pointer;list-style:none;display:grid;grid-template-columns:38px 1fr auto;align-items:center;gap:12px;padding:16px}.charge summary::-webkit-details-marker{display:none}.charge-no{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:#080c13;color:var(--muted);font-size:12px}.charge-title strong{display:block}.charge-title span{color:var(--muted);font-size:12px}.pill{border:1px solid currentColor;border-radius:999px;padding:3px 8px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.08em}.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.charge-body{padding:0 16px 17px 66px;border-top:1px solid var(--border)}.charge-body p{color:#bdc8d8}.evidence{margin-top:12px;border-left:2px solid var(--accent);background:#090e17;border-radius:0 10px 10px 0;padding:12px}.evidence-head{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:11px}.evidence pre{white-space:pre-wrap;word-break:break-word;margin:9px 0 0;color:#d9e2ef;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}.side{display:flex;flex-direction:column;gap:20px}.side .panel{padding-bottom:12px}.list{list-style:none;margin:0;padding:8px 18px}.list li{display:flex;flex-direction:column;padding:11px 2px;border-bottom:1px solid rgba(38,50,71,.65)}.list li:last-child{border-bottom:0}.list span{color:var(--muted);font-size:12px}.coverage-ring{width:132px;height:132px;border-radius:50%;margin:24px auto 10px;display:grid;place-items:center;background:conic-gradient(var(--accent) calc(${Math.round(report.scan.coverage.ratio * 100)} * 1%),#202a3a 0);position:relative}.coverage-ring:after{content:"";position:absolute;inset:11px;border-radius:50%;background:var(--panel)}.coverage-ring b{z-index:1;font-size:25px}.bridge{margin:12px 18px 4px;padding:13px;border-radius:12px;background:#090e17;border:1px solid var(--border)}.bridge b{display:block;text-transform:uppercase;font-size:11px;letter-spacing:.1em}.bridge span{color:var(--muted);font-size:12px}.footer{margin-top:26px;color:var(--muted);font-size:12px;display:flex;justify-content:space-between;gap:20px}.empty{padding:34px;color:var(--muted);text-align:center}.legal{margin-top:22px;padding:15px 18px;border:1px dashed #334155;border-radius:14px;color:#94a3b8;font-size:12px}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#c8d7ec}@media(max-width:1080px){.metrics{grid-template-columns:repeat(4,1fr)}}@media(max-width:900px){.metrics{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}.meta{display:none}}@media(max-width:520px){.shell{padding:20px 12px 48px}.hero{padding:23px}.metrics{grid-template-columns:1fr 1fr}.charge summary{grid-template-columns:34px 1fr}.pill{grid-column:2;justify-self:start}.charge-body{padding-left:16px}.footer{flex-direction:column}}
</style>
</head>
<body>
<main class="shell">
  <header class="topbar"><div class="brand"><div class="seal">⚖</div> RepoTrial</div><div class="meta">Case ${escapeHtml(report.scan.id)}<br>${escapeHtml(report.scan.createdAt)}</div></header>
  <section class="hero">
    <div class="eyebrow">The People vs. ${escapeHtml(report.scan.targetName)}</div>
    <h1 class="verdict">${escapeHtml(verdict)}</h1>
    <p>${escapeHtml(report.verdict.rationale)}</p>
    <div class="metrics">
      <div class="metric"><b>${proven.length}</b><span>proven charges</span></div>
      <div class="metric"><b>${evidenceCount}</b><span>evidence anchors</span></div>
      <div class="metric"><b>${report.scan.coverage.filesInspected}</b><span>files inspected</span></div>
      <div class="metric"><b>${report.verdict.score}</b><span>risk score / 100</span></div>
      <div class="metric"><b>${runtimeRuns}</b><span>runtime detonations</span></div>
      <div class="metric"><b>${componentCount}</b><span>SBOM components</span></div>
      <div class="metric"><b>${differential.new}</b><span>new findings</span></div>
    </div>
  </section>
  <div class="layout">
    <section class="panel"><div class="panel-head"><h2>Charges and evidence</h2><span class="count">${charges.length} rule outcomes</span></div><div class="charges">${chargeHtml}</div></section>
    <aside class="side">
      <section class="panel"><div class="panel-head"><h2>Coverage</h2></div><div class="coverage-ring"><b>${Math.round(report.scan.coverage.ratio * 100)}%</b></div><ul class="list">${omissions}</ul></section>
      <section class="panel"><div class="panel-head"><h2>Safeguards</h2></div><ul class="list">${safeguards}</ul></section>
      ${panels}
    </aside>
  </div>
  <div class="legal">RepoTrial combines bounded static analysis, optional isolated runtime detonation, adaptive adversarial experiments, causal attack-chain synthesis, supply-chain evidence, differential analysis, evidence reasoning, invariant proof, explicit negative evidence, and optional ForgeOS enrichment. A TRUSTED verdict is not a security certification. Attack paths are evidence-backed models rather than proof of exploitation. NOT_OBSERVED in an adaptive experiment is local experiment evidence only and is not proof of absence; it never becomes global negative evidence.</div>
  <footer class="footer"><span>Receipt SHA-256: <code>${escapeHtml(report.receipt.sha256)}</code></span><span>Schema ${escapeHtml(report.schemaVersion)}</span></footer>
</main>
<script type="application/json" id="repotrial-report">${rawJson}</script>
</body>
</html>\n`;
}

function renderReasoningPanel(reasoning = {}) {
  if (!reasoning?.schemaVersion) {
    return `<section class="panel"><div class="panel-head"><h2>Evidence Reasoning</h2></div><div class="bridge"><b>not available</b><span>No reasoning graph was attached to this report.</span></div></section>`;
  }
  const hypotheses = Array.isArray(reasoning.hypotheses) ? reasoning.hypotheses : [];
  const paths = Array.isArray(reasoning.attackPaths) ? reasoning.attackPaths : [];
  const viable = paths.filter((path) => path.viability === 'VIABLE');
  const partial = paths.filter((path) => path.viability === 'PARTIAL');
  const blocked = paths.filter((path) => path.viability === 'BLOCKED');
  const top = hypotheses
    .filter((item) => item.state !== 'UNTESTED')
    .slice(0, 5)
    .map((item) => `<li><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.state)} · confidence ${escapeHtml(item.confidence)}</span></li>`)
    .join('');
  const topRemediation = reasoning.remediation?.candidates?.[0];
  const remediation = topRemediation
    ? `<li><strong>Top counterfactual</strong><span>${escapeHtml(topRemediation.ruleId)} · eliminates ${escapeHtml(topRemediation.attackPathsEliminated)} attack path(s) · removes ${escapeHtml(topRemediation.invariantViolationsEliminated ?? 0)} invariant violation(s)</span></li>`
    : '<li><strong>Top counterfactual</strong><span>No proven charge changes a modeled path or invariant violation.</span></li>';

  const invariantResults = Array.isArray(reasoning.invariants?.results) ? reasoning.invariants.results : [];
  const violated = invariantResults.filter((item) => item.state === 'VIOLATED');
  const satisfied = invariantResults.filter((item) => item.state === 'SATISFIED');
  const unknown = invariantResults.filter((item) => item.state === 'UNKNOWN');
  const notApplicable = invariantResults.filter((item) => item.state === 'NOT_APPLICABLE');
  const negativeEvidence = Array.isArray(reasoning.negativeEvidence) ? reasoning.negativeEvidence : [];
  const invariantHtml = invariantResults.length
    ? invariantResults.slice(0, 8).map((item) => `<li><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.state)} · ${escapeHtml(item.severity)} · ${escapeHtml(item.rationale)}</span></li>`).join('')
    : '<li><strong>No invariant contract</strong><span>No security invariant result was attached.</span></li>';
  const negativeHtml = negativeEvidence.length
    ? negativeEvidence.slice(0, 5).map((item) => `<li><strong>Negative evidence · ${escapeHtml(item.capability)}</strong><span>ABSENT · ${escapeHtml(item.source)} / ${escapeHtml(item.method)} · confidence ${escapeHtml(item.confidence)}</span></li>`).join('')
    : '<li><strong>Negative evidence</strong><span>0 explicit absence claims. Provider silence is not treated as proof of absence.</span></li>';

  const reasoningPanel = `<section class="panel"><div class="panel-head"><h2>Evidence Reasoning</h2><span class="count">${escapeHtml(reasoning.schemaVersion)}</span></div><div class="bridge"><b>${viable.length} VIABLE attack paths</b><span>${partial.length} partial · ${blocked.length} blocked · ${escapeHtml(reasoning.summary?.capabilityCount ?? 0)} observed capabilities</span></div><ul class="list">${top || '<li><strong>No active hypothesis</strong><span>No modeled claim is currently supported.</span></li>'}${remediation}</ul></section>`;
  const invariantPanel = `<section class="panel"><div class="panel-head"><h2>Invariant Proof</h2><span class="count">${escapeHtml(reasoning.invariants?.schemaVersion ?? 'not-available')}</span></div><div class="bridge"><b>${violated.length} VIOLATED invariants</b><span>${satisfied.length} satisfied · ${unknown.length} unknown · ${notApplicable.length} not applicable · ${negativeEvidence.length} negative evidence claim(s)</span></div><ul class="list">${invariantHtml}${negativeHtml}</ul></section>`;
  return `${reasoningPanel}\n${invariantPanel}`;
}

function renderCausalPanel(causal) {
  if (!causal?.schemaVersion) return '';
  const chains = Array.isArray(causal.reasoning?.chains) ? causal.reasoning.chains : [];
  const active = chains.filter((item) => ['PROVEN', 'SUPPORTED'].includes(item.state));
  const partial = chains.filter((item) => item.state === 'PARTIAL');
  const blocked = chains.filter((item) => item.state === 'BLOCKED');
  const contradicted = chains.filter((item) => item.state === 'CONTRADICTED');
  const summary = causal.summary ?? {};
  const productionActive = Number(summary.productionActiveChainCount ?? active.filter((item) => item.realmAssessment?.productionRelevant === true).length);
  const nonProductionActive = Number(summary.nonProductionActiveChainCount ?? active.filter((item) => item.realmAssessment?.state === 'NON_PRODUCTION_ONLY').length);
  const top = active.slice(0, 6).map((item) => `<li><strong>${escapeHtml(item.threatId)}</strong><span>${escapeHtml(item.state)} · ${escapeHtml(item.severity)} · ${escapeHtml(item.realmAssessment?.state ?? 'UNKNOWN_REALM')} · rank ${escapeHtml(item.score?.rank ?? 0)} · ${escapeHtml((item.stages ?? []).map((stage) => stage.selectedCapability ?? `?${stage.id}`).join(' → '))}</span></li>`).join('');
  const activeRun = causal.activeRun?.summary;
  const delta = causal.epistemicDelta?.summary;
  const activeDetail = causal.mode === 'active'
    ? `<li><strong>Active verification</strong><span>${escapeHtml(activeRun?.executedEpisodeCount ?? 0)} episodes · ${escapeHtml(activeRun?.observedEpisodeCount ?? 0)} observed · ${escapeHtml(activeRun?.inconclusiveEpisodeCount ?? 0)} inconclusive · ${escapeHtml(delta?.transitionCount ?? 0)} chain transitions</span></li>`
    : `<li><strong>Active verification</strong><span>Not executed in ${escapeHtml(causal.mode)} mode.</span></li>`;
  const realmDetail = `<li><strong>Evidence realms</strong><span>${escapeHtml(productionActive)} production-relevant active · ${escapeHtml(nonProductionActive)} non-production active · gate scope ${escapeHtml(causal.realmScope ?? 'all')}</span></li>`;
  const causalPanel = `<section class="panel"><div class="panel-head"><h2>Causal Adversarial Reasoning</h2><span class="count">${escapeHtml(causal.mode)} · ${escapeHtml(causal.schemaVersion)}</span></div><div class="bridge"><b>${active.length} ACTIVE causal chains</b><span>${productionActive} production-relevant · ${nonProductionActive} non-production · ${partial.length} partial · ${blocked.length} blocked · ${contradicted.length} contradicted · ${escapeHtml(causal.registry?.definitionCount ?? 0)} threat families</span></div><ul class="list"><li><strong>Epistemic boundary</strong><span>Chains are evidence-backed causal models, not proof of successful exploitation. Test, benchmark, fixture, documentation, generated, and vendor evidence remain visible but are not silently treated as production risk.</span></li>${realmDetail}${activeDetail}${top || '<li><strong>No active causal chain</strong><span>No complete modeled chain is currently supported by the observed evidence.</span></li>'}</ul></section>`;

  if (!causal.discovery?.schemaVersion) return causalPanel;
  const candidates = Array.isArray(causal.discovery.candidates) ? causal.discovery.candidates : [];
  const promotable = candidates.filter((item) => item.state === 'PROMOTABLE');
  const candidateHtml = candidates.slice(0, 6).map((item) => `<li><strong>${escapeHtml(item.title ?? item.id)}</strong><span>${escapeHtml(item.state)} · ${escapeHtml(item.severity)} · novelty ${escapeHtml(item.noveltyScore ?? 0)} · ${escapeHtml(item.realmAssessment?.state ?? 'UNKNOWN_REALM')} · ${escapeHtml((item.capabilities ?? []).join(' → '))}</span></li>`).join('');
  const discoveryPanel = `<section class="panel"><div class="panel-head"><h2>Autonomous Threat Discovery</h2><span class="count">${escapeHtml(causal.discovery.schemaVersion)}</span></div><div class="bridge"><b>${escapeHtml(candidates.length)} discovered candidates</b><span>${escapeHtml(promotable.length)} promotable · deterministic novelty analysis</span></div><ul class="list"><li><strong>Candidate, not proven</strong><span>Autonomous hypotheses are deterministic compositions for verification. PROMOTABLE never means exploited, safe, or automatically added to the built-in registry.</span></li>${candidateHtml || '<li><strong>No novel candidate</strong><span>Observed capability compositions were registry-covered, non-impactful, realm-incoherent, or below the configured novelty threshold.</span></li>'}</ul></section>`;
  return `${causalPanel}\n${discoveryPanel}`;
}

function renderExperimentsPanel(experiments) {
  if (!experiments?.schemaVersion) return '';
  const summary = experiments.summary ?? {};
  const delta = experiments.epistemicDelta?.summary ?? {};
  const plan = experiments.plan?.experiments ?? [];
  const observations = experiments.observations ?? [];
  const stateCounts = observations.reduce((counts, item) => {
    const key = String(item?.state ?? 'UNKNOWN');
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
  const transitions = Number(delta.hypothesisTransitionCount ?? 0) + Number(delta.attackPathTransitionCount ?? 0);
  const topPlan = plan.slice(0, 5).map((item) => `<li><strong>${escapeHtml(item.templateId)}</strong><span>${escapeHtml(item.severity)} · ${escapeHtml(item.hypothesisId)} · priority ${escapeHtml(item.priority)}</span></li>`).join('');
  const unresolved = experiments.epistemicDelta?.unresolvedTargets ?? [];
  const unresolvedHtml = unresolved.slice(0, 4).map((item) => `<li><strong>Unresolved · ${escapeHtml(item.hypothesisId)}</strong><span>${escapeHtml(item.state)} · missing ${escapeHtml((item.missingStages ?? []).join(', ') || 'none')}</span></li>`).join('');
  return `<section class="panel"><div class="panel-head"><h2>Adaptive Experiments</h2><span class="count">${escapeHtml(experiments.mode)} · ${escapeHtml(experiments.status)}</span></div><div class="bridge"><b>${escapeHtml(summary.positiveObservationCount ?? 0)} positive observations</b><span>${escapeHtml(summary.executedExperimentCount ?? 0)} executed / ${escapeHtml(summary.plannedExperimentCount ?? 0)} planned · ${escapeHtml(transitions)} epistemic transitions</span></div><ul class="list"><li><strong>Observation states</strong><span>OBSERVED ${escapeHtml(stateCounts.OBSERVED ?? 0)} · TRIGGERED ${escapeHtml(stateCounts.TRIGGERED ?? 0)} · NOT_OBSERVED ${escapeHtml(stateCounts.NOT_OBSERVED ?? 0)} · INCONCLUSIVE ${escapeHtml(stateCounts.INCONCLUSIVE ?? 0)}</span></li><li><strong>Epistemic rule</strong><span>NOT_OBSERVED is not proof of absence and never becomes global negative evidence.</span></li>${topPlan || '<li><strong>Plan</strong><span>No runtime-addressable experiment was planned.</span></li>'}${unresolvedHtml}</ul></section>`;
}

function renderRuntimePanel(runtime = {}) {
  const runs = Array.isArray(runtime.runs) ? runtime.runs : [];
  const network = runs.reduce((sum, run) => sum + (run.events ?? []).filter((event) => ['network', 'dns', 'network-tool'].includes(event.kind)).length, 0);
  const mutations = runs.reduce((sum, run) => sum + (run.filesystemChanges?.length ?? 0), 0);
  const reason = runtime.reason ? ` · ${escapeHtml(runtime.reason)}` : '';
  return `<section class="panel"><div class="panel-head"><h2>Runtime Sandbox</h2><span class="count">${runs.length} runs</span></div><div class="bridge"><b>${escapeHtml(runtime.status ?? 'not-run')} · ${escapeHtml(runtime.provider ?? 'none')}</b><span>Isolated detonation${reason}</span></div><ul class="list"><li><strong>Network observations</strong><span>${network} trapped network, DNS, or downloader events</span></li><li><strong>Filesystem changes</strong><span>${mutations} mutations inside disposable rootfs</span></li><li><strong>Candidates</strong><span>${escapeHtml(runtime.candidates?.length ?? 0)} discovered · ${escapeHtml(runtime.truncatedCandidates ?? 0)} truncated</span></li></ul></section>`;
}

function renderSupplyPanel(supply = {}) {
  const container = supply.container ?? {};
  return `<section class="panel"><div class="panel-head"><h2>Supply Chain</h2><span class="count">CycloneDX 1.6</span></div><div class="bridge"><b>${escapeHtml(supply.status ?? 'not-run')} · ${escapeHtml(supply.mode ?? 'off')}</b><span>SBOM, known-vulnerability, license, and container evidence</span></div><ul class="list"><li><strong>Components</strong><span>${escapeHtml(supply.componentCount ?? 0)} inventoried dependencies</span></li><li><strong>Known vulnerabilities</strong><span>${escapeHtml(supply.vulnerabilityCount ?? 0)} OSV or scanner findings</span></li><li><strong>Licenses</strong><span>${escapeHtml(supply.unknownLicenseCount ?? 0)} components without observed license metadata</span></li><li><strong>Container scanner</strong><span>${escapeHtml(container.status ?? 'not-configured')} · ${escapeHtml(container.findingCount ?? 0)} findings</span></li></ul></section>`;
}

function renderDifferentialPanel(differential) {
  if (!differential) return `<section class="panel"><div class="panel-head"><h2>Differential</h2></div><div class="bridge"><b>not configured</b><span>Provide a baseline report or Git reference to classify new, existing, and resolved findings.</span></div></section>`;
  const summary = differential.summary ?? {};
  const causal = differential.causal?.summary;
  return `<section class="panel"><div class="panel-head"><h2>Differential</h2><span class="count">baseline compared</span></div><div class="bridge"><b>${escapeHtml(summary.new ?? 0)} new findings</b><span>Receipt ${escapeHtml(differential.receipt?.sha256?.slice(0, 16) ?? 'unavailable')}</span></div><ul class="list"><li><strong>New</strong><span>${escapeHtml(summary.new ?? 0)} introduced findings</span></li><li><strong>Existing</strong><span>${escapeHtml(summary.existing ?? 0)} unchanged findings</span></li><li><strong>Resolved</strong><span>${escapeHtml(summary.resolved ?? 0)} findings no longer observed</span></li>${causal ? `<li><strong>Causal regressions</strong><span>${escapeHtml(causal.newActiveChainCount ?? 0)} new active chains · ${escapeHtml(causal.regressedThreatCount ?? 0)} regressed threat families</span></li>` : ''}</ul></section>`;
}

function renderIntegrityPanel(integrity = {}, receipt = {}) {
  const signatures = Array.isArray(integrity.signatures) ? integrity.signatures : integrity.signature ? [integrity.signature] : [];
  return `<section class="panel"><div class="panel-head"><h2>Artifact Integrity</h2><span class="count">SLSA / DSSE / Sigstore</span></div><div class="bridge"><b>SHA-256 proof generated</b><span>Report receipt ${escapeHtml(receipt.sha256?.slice(0, 16) ?? 'unavailable')}</span></div><ul class="list"><li><strong>Artifact proof</strong><span><code>${escapeHtml(integrity.artifactProof ?? 'not-generated')}</code></span></li><li><strong>Provenance</strong><span><code>${escapeHtml(integrity.provenance ?? 'not-generated')}</code></span></li><li><strong>Signatures</strong><span>${signatures.length ? signatures.map((name) => `<code>${escapeHtml(name)}</code>`).join(' ') : 'Unsigned local statement'}</span></li></ul></section>`;
}

function renderForgeOsPanel(forgeos = {}) {
  const powered = forgeos.status === 'ok' && forgeos.engine;
  if (!powered) {
    return `<section class="panel"><div class="panel-head"><h2>ForgeOS Bridge</h2></div><div class="bridge"><b>${escapeHtml(forgeos.mode ?? 'off')} · ${escapeHtml(forgeos.status ?? 'disabled')}</b><span>${escapeHtml(forgeos.findings?.length ?? 0)} imported findings${forgeos.error ? ` · ${escapeHtml(forgeos.error)}` : ''}</span></div></section>`;
  }

  const technique = forgeos.remediationRoute?.steps?.[0];
  const corpus = forgeos.engine.agentSurfaceAdversarial;
  const reportHash = forgeos.security?.reportSha256 ?? '';
  const routeHtml = technique
    ? `<li><strong>Remediation technique</strong><span><code>${escapeHtml(technique.techniqueId)}</code></span></li><li><strong>Evidence obligations</strong><span>${escapeHtml((technique.evidenceObligations ?? []).join(', ') || 'None declared')}</span></li>`
    : '<li><strong>Remediation route</strong><span>No RoutePlan was returned.</span></li>';

  return `<section class="panel"><div class="panel-head"><h2>ForgeOS Powered</h2><span class="count">v${escapeHtml(forgeos.engine.version)}</span></div><div class="bridge"><b>${escapeHtml(forgeos.security?.status ?? forgeos.status)} · ${escapeHtml(forgeos.findings?.length ?? 0)} findings</b><span>Native agent-surface scan${reportHash ? ` · receipt ${escapeHtml(reportHash.slice(0, 16))}` : ''}</span></div><ul class="list"><li><strong>Kernel</strong><span>${escapeHtml(forgeos.engine.kernelTechniqueCount ?? '?')} techniques · ${escapeHtml(forgeos.engine.outcomeCount ?? '?')} outcomes</span></li>${corpus ? `<li><strong>Adversarial corpus</strong><span>${escapeHtml(corpus.passed ?? '?')} / ${escapeHtml(corpus.cases ?? '?')} passed · ${escapeHtml(corpus.missed ?? '?')} missed</span></li>` : ''}${routeHtml}</ul></section>`;
}

function renderCharge(charge, index) {
  const chargeEvidence = Array.isArray(charge.evidence) ? charge.evidence : [];
  const evidence = chargeEvidence.length
    ? chargeEvidence.map((item) => `<div class="evidence"><div class="evidence-head"><span>${escapeHtml(item.path)}:${item.startLine ?? item.line ?? '?'}</span><span>${escapeHtml((item.fileSha256 ?? item.fingerprint ?? '').slice(0, 14))}</span></div><pre>${escapeHtml(item.snippet ?? item.description ?? 'External evidence')}</pre></div>`).join('')
    : '<div class="evidence"><div class="evidence-head"><span>Repository-wide inference</span><span>No direct line anchor</span></div></div>';
  return `<details class="charge" ${charge.status === 'proven' ? 'open' : ''}>
  <summary><span class="charge-no">${index}</span><span class="charge-title"><strong>${escapeHtml(charge.title)}</strong><span>${escapeHtml(charge.ruleId)} · ${escapeHtml(charge.status)}</span></span><span class="pill ${escapeHtml(charge.severity)}">${escapeHtml(charge.severity)}</span></summary>
  <div class="charge-body"><p>${escapeHtml(charge.rationale)}</p>${evidence}<p><strong>Remediation:</strong> ${escapeHtml(charge.remediation)}</p></div>
</details>`;
}

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}