import test from 'node:test';
import assert from 'node:assert/strict';
import { renderHtmlReport } from '../src/core/report.mjs';

function report() {
  return {
    schemaVersion: 'repotrial.report.v2',
    scan: { id: 'realm-report', createdAt: '2026-08-12T00:00:00.000Z', target: '.', targetName: 'self', coverage: { filesInspected: 1, bytesInspected: 1, omitted: 0, ratio: 1, complete: true }, totalBytes: 1, omissions: [] },
    verdict: { label: 'CAUTIOUS', rank: 1, score: 10, severityCounts: {}, coverage: 1, rationale: 'bounded' },
    charges: [], safeguards: [],
    reasoning: { schemaVersion: 'repotrial.reasoning.v1', hypotheses: [], attackPaths: [], invariants: { schemaVersion: 'repotrial.invariant-proof.v1', results: [], summary: {} }, negativeEvidence: [], remediation: { candidates: [] }, summary: { capabilityCount: 0 } },
    causal: {
      schemaVersion: 'repotrial.causal.v2', mode: 'discover', realmScope: 'production', registry: { definitionCount: 12 },
      reasoning: { chains: [
        { threatId: 'arbitrary-code-execution', state: 'PROVEN', severity: 'critical', score: { rank: 900 }, stages: [], realmAssessment: { state: 'NON_PRODUCTION_ONLY', productionRelevant: false, realms: ['benchmark'] } }
      ] },
      discovery: { schemaVersion: 'repotrial.hypothesis-discovery.v1', candidates: [
        { id: 'hyp:auto:1234567890abcdef12345678', title: 'Discovered composition: instruction-control → network-egress', state: 'PROMOTABLE', severity: 'high', noveltyScore: 0.5, capabilities: ['instruction-control','network-egress'], realmAssessment: { state: 'PRODUCTION_RELEVANT', productionRelevant: true, realms: ['production'] }, caveat: 'Autonomous hypotheses are deterministic candidates for verification; they are not vulnerability proof.' }
      ], summary: { candidateCount: 1, promotableCount: 1 } },
      summary: { activeChainCount: 1, productionActiveChainCount: 0, nonProductionActiveChainCount: 1, partialChainCount: 0, registryThreatCount: 12, discoveredHypothesisCount: 1, promotableHypothesisCount: 1 }
    },
    forgeos: {}, runtime: { runs: [] }, supplyChain: { componentCount: 0 }, integrity: {},
    receipt: { algorithm: 'sha256', sha256: 'a'.repeat(64) }
  };
}

test('HTML distinguishes production relevance and labels autonomous hypotheses as candidates, not proof', () => {
  const html = renderHtmlReport(report());
  assert.match(html, /production-relevant/i);
  assert.match(html, /non-production/i);
  assert.match(html, /Autonomous Threat Discovery/i);
  assert.match(html, /candidate, not proven/i);
  assert.match(html, /instruction-control.*network-egress/is);
});
