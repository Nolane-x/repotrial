const SECRET_NAME = String.raw`[A-Z0-9_-]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH)[A-Z0-9_-]*`;
const SENSITIVE_KEY = new RegExp(`^${SECRET_NAME}$`, 'i');
const QUOTED_SECRET = new RegExp(`((?:["']?${SECRET_NAME}["']?)\\s*[:=]\\s*)(["'])([\\s\\S]*?)\\2`, 'gi');
const BARE_SECRET = new RegExp(`((?:["']?${SECRET_NAME}["']?)\\s*[:=]\\s*)(?!["'])([^\\s,;\\]}]+)`, 'gi');

export function redactSensitiveText(value) {
  return String(value ?? '')
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY]')
    .replace(/(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(QUOTED_SECRET, '$1$2[REDACTED]$2')
    .replace(BARE_SECRET, '$1[REDACTED]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[A-Z0-9]{16})\b/g, '[REDACTED TOKEN]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[REDACTED JWT]')
    .replace(/(https?:\/\/[^\s/:@]+:)[^\s/@]+(@)/gi, '$1[REDACTED]$2');
}

export function redactSensitiveValues(value, options = {}) {
  if (typeof value === 'string') return redactSensitiveText(value);
  if (!value || typeof value !== 'object') return value;

  const maxNodes = boundedInteger(options.maxNodes, 100_000, 100, 1_000_000);
  const root = Array.isArray(value) ? [] : {};
  const active = new WeakSet([value]);
  const stack = [{ source: value, target: root, entries: Object.entries(value), index: 0 }];
  let nodes = 0;

  while (stack.length) {
    const frame = stack[stack.length - 1];
    if (frame.index >= frame.entries.length) {
      active.delete(frame.source);
      stack.pop();
      continue;
    }

    const [key, child] = frame.entries[frame.index++];
    nodes += 1;
    if (nodes > maxNodes) {
      frame.target[key] = '[TRUNCATED]';
      continue;
    }
    if (!Array.isArray(frame.source) && SENSITIVE_KEY.test(key) && (typeof child === 'string' || (child && typeof child === 'object'))) {
      frame.target[key] = '[REDACTED]';
      continue;
    }
    if (typeof child === 'string') {
      frame.target[key] = redactSensitiveText(child);
      continue;
    }
    if (!child || typeof child !== 'object') {
      frame.target[key] = child;
      continue;
    }
    if (active.has(child)) {
      frame.target[key] = '[CIRCULAR]';
      continue;
    }

    const childTarget = Array.isArray(child) ? [] : {};
    frame.target[key] = childTarget;
    active.add(child);
    stack.push({ source: child, target: childTarget, entries: Object.entries(child), index: 0 });
  }
  return root;
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number)) return fallback;
  return Math.min(max, Math.max(min, number));
}
