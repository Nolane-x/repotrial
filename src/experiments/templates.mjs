const MAX_ENV_KEYS = 8;
const MAX_SENTINELS = 8;
const SENTINEL_ROOT = '.repotrial-experiment/';
const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;

const TEMPLATE_DEFINITIONS = {
  'secret-egress-canary-v1': {
    id: 'secret-egress-canary-v1',
    title: 'Synthetic credential egress canary',
    envKeys: ['OPENAI_API_KEY', 'GITHUB_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'],
    sentinelPaths: [],
    expectedObservations: ['network-delta', 'canary-propagation'],
    targetCapabilities: ['secret-access', 'network-egress']
  },
  'filesystem-sentinel-v1': {
    id: 'filesystem-sentinel-v1',
    title: 'Sandbox-local filesystem sentinel',
    envKeys: [],
    sentinelPaths: [
      '.repotrial-experiment/sentinel-a.txt',
      '.repotrial-experiment/nested/sentinel-b.txt'
    ],
    expectedObservations: ['sentinel-mutation', 'filesystem-delta'],
    targetCapabilities: ['destructive-action', 'filesystem-write']
  },
  'ci-context-trigger-v1': {
    id: 'ci-context-trigger-v1',
    title: 'Synthetic CI-context trigger',
    envKeys: ['CI', 'GITHUB_ACTIONS'],
    sentinelPaths: [],
    expectedObservations: ['network-delta', 'filesystem-delta', 'process-delta'],
    targetCapabilities: []
  }
};

export const EXPERIMENT_TEMPLATES = Object.freeze(Object.fromEntries(
  Object.entries(TEMPLATE_DEFINITIONS).map(([id, value]) => [id, deepFreeze({ ...value })])
));

export function getExperimentTemplate(templateId) {
  const template = EXPERIMENT_TEMPLATES[String(templateId ?? '')];
  return template ? cloneTemplate(template) : null;
}

export function validateExperimentScenario(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Experiment scenario must be an object.');
  if ('env' in input || 'envValues' in input || 'environment' in input) {
    throw new Error('Experiment scenarios cannot contain arbitrary environment values.');
  }

  const template = getExperimentTemplate(input.templateId);
  if (!template) throw new Error(`Unknown experiment template: ${String(input.templateId ?? '')}`);

  const envKeys = normalizeStringArray(input.envKeys ?? template.envKeys, 'experiment environment keys', MAX_ENV_KEYS);
  const allowedEnv = new Set(template.envKeys);
  for (const key of envKeys) {
    if (!ENV_NAME.test(key)) throw new Error(`Invalid experiment environment key: ${key}`);
    if (!allowedEnv.has(key)) throw new Error(`Experiment environment key is not allowed by template ${template.id}: ${key}`);
  }

  const sentinelPaths = normalizeStringArray(input.sentinelPaths ?? template.sentinelPaths, 'experiment sentinel paths', MAX_SENTINELS)
    .map(normalizeSentinelPath);
  const allowedSentinels = new Set(template.sentinelPaths.map(normalizeSentinelPath));
  for (const sentinel of sentinelPaths) {
    if (!allowedSentinels.has(sentinel)) throw new Error(`Experiment sentinel path is not allowed by template ${template.id}: ${sentinel}`);
  }

  return {
    templateId: template.id,
    envKeys,
    sentinelPaths,
    expectedObservations: [...template.expectedObservations],
    targetCapabilities: [...template.targetCapabilities]
  };
}

export function experimentTemplateLimits() {
  return { maxEnvKeys: MAX_ENV_KEYS, maxSentinels: MAX_SENTINELS, sentinelRoot: SENTINEL_ROOT };
}

function normalizeStringArray(value, label, max) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  if (value.length > max) throw new Error(`${label} exceeds maximum ${max}.`);
  const normalized = value.map((item) => String(item).trim()).filter(Boolean);
  if (new Set(normalized).size !== normalized.length) throw new Error(`${label} contains duplicates.`);
  return normalized;
}

function normalizeSentinelPath(value) {
  const text = String(value).replaceAll('\\', '/').trim();
  if (!text || text.startsWith('/') || /^[A-Za-z]:\//.test(text)) throw new Error(`Invalid experiment sentinel path: ${text}`);
  const parts = text.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..')) throw new Error(`Invalid experiment sentinel path: ${text}`);
  if (!text.startsWith(SENTINEL_ROOT)) throw new Error(`Experiment sentinel path must stay under ${SENTINEL_ROOT}`);
  return parts.join('/');
}

function cloneTemplate(template) {
  return {
    id: template.id,
    title: template.title,
    envKeys: [...template.envKeys],
    sentinelPaths: [...template.sentinelPaths],
    expectedObservations: [...template.expectedObservations],
    targetCapabilities: [...template.targetCapabilities]
  };
}

function deepFreeze(value) {
  for (const child of Object.values(value)) if (child && typeof child === 'object') deepFreeze(child);
  return Object.freeze(value);
}
