import { findingIdentity } from './diff.mjs';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const LEVELS = Object.freeze({ critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' });

export function buildSarifReport(report, options = {}) {
  const proven = (report.charges ?? []).filter((charge) => charge.status === 'proven');
  const ruleMap = new Map();
  for (const charge of proven) {
    if (!ruleMap.has(charge.ruleId)) ruleMap.set(charge.ruleId, buildRule(charge));
  }

  return {
    version: '2.1.0',
    $schema: SARIF_SCHEMA,
    runs: [{
      tool: {
        driver: {
          name: 'RepoTrial',
          ...(options.version ? { version: String(options.version) } : {}),
          informationUri: 'https://github.com/casioreview20-glitch/repotrial',
          rules: [...ruleMap.values()].sort((a, b) => a.id.localeCompare(b.id))
        }
      },
      originalUriBaseIds: { '%SRCROOT%': { uri: './' } },
      results: proven.flatMap((charge) => buildResults(charge, baselineStateFor(charge, report.differential))),
      properties: {
        scanId: report.scan?.id ?? null,
        receiptSha256: report.receipt?.sha256 ?? null,
        verdict: report.verdict?.label ?? null,
        riskScore: report.verdict?.score ?? null,
        forgeosStatus: report.forgeos?.status ?? null,
        forgeosVersion: report.forgeos?.engine?.version ?? null
      }
    }]
  };
}

function buildRule(charge) {
  return {
    id: String(charge.ruleId),
    name: ruleName(charge.ruleId),
    shortDescription: { text: String(charge.title ?? charge.ruleId) },
    fullDescription: { text: String(charge.rationale ?? charge.title ?? charge.ruleId) },
    help: { text: String(charge.remediation ?? 'Review and remediate this finding.') },
    defaultConfiguration: { level: LEVELS[charge.severity] ?? 'warning' },
    properties: {
      severity: charge.severity ?? 'medium',
      source: charge.source ?? 'repotrial'
    }
  };
}

function buildResults(charge, baselineState) {
  const evidence = Array.isArray(charge.evidence) ? charge.evidence : [];
  const anchors = evidence.filter((item) => portableRelativePath(item.path));
  if (!anchors.length) return [buildResult(charge, undefined, baselineState)];
  return anchors.map((item) => buildResult(charge, item, baselineState));
}

function buildResult(charge, evidence, baselineState) {
  const result = {
    ruleId: String(charge.ruleId),
    level: LEVELS[charge.severity] ?? 'warning',
    message: { text: `${charge.title}: ${charge.rationale}` },
    properties: {
      severity: charge.severity ?? 'medium',
      source: charge.source ?? 'repotrial',
      confidence: charge.confidence ?? null,
      remediation: charge.remediation ?? null
    }
  };
  if (baselineState) result.baselineState = baselineState;
  if (evidence) {
    const relativePath = portableRelativePath(evidence.path);
    result.locations = [{
      physicalLocation: {
        artifactLocation: { uri: relativePath, uriBaseId: '%SRCROOT%' },
        region: {
          startLine: positiveLine(evidence.startLine ?? evidence.line),
          endLine: positiveLine(evidence.endLine ?? evidence.startLine ?? evidence.line)
        }
      }
    }];
    if (evidence.fingerprint) {
      result.partialFingerprints = { primaryLocationLineHash: String(evidence.stableFingerprint ?? evidence.fingerprint) };
    }
  }
  return result;
}

function portableRelativePath(value) {
  if (typeof value !== 'string' || !value) return null;
  const normalized = value.replaceAll('\\', '/').replace(/^\.\//, '');
  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) return null;
  if (normalized.split('/').includes('..')) return null;
  return normalized;
}

function positiveLine(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : 1;
}

function ruleName(ruleId) {
  return String(ruleId).replace(/[^A-Za-z0-9]+(.)/g, (_, char) => char.toUpperCase()).replace(/^[^A-Za-z]+/, '') || 'RepoTrialFinding';
}

function baselineStateFor(charge, differential) {
  if (!differential) return undefined;
  const identity = findingIdentity(charge);
  const inNew = (differential.new ?? []).some((item) => (item.differentialIdentity ?? findingIdentity(item)) === identity);
  if (inNew) return 'new';
  const inExisting = (differential.existing ?? []).some((item) => (item.differentialIdentity ?? findingIdentity(item)) === identity);
  return inExisting ? 'unchanged' : undefined;
}
