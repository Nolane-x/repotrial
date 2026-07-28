import { sha256 } from './hash.mjs';
import { redactSensitiveText } from './redact.mjs';

const LINE_START_CACHE = new WeakMap();
const DEFAULT_MAX_MATCHES = 100;

function lineStartsFor(file) {
  const cached = LINE_START_CACHE.get(file);
  if (cached) return cached;
  const starts = [0];
  for (let index = 0; index < file.content.length; index += 1) {
    if (file.content.charCodeAt(index) === 10) starts.push(index + 1);
  }
  LINE_START_CACHE.set(file, starts);
  return starts;
}

function lineAt(file, index) {
  const starts = lineStartsFor(file);
  let low = 0;
  let high = starts.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= index) low = middle + 1;
    else high = middle;
  }
  return Math.max(1, low);
}

function normalizedRegex(regex) {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  return new RegExp(regex.source, flags);
}

export function findEvidence(file, regex, metadata = {}) {
  const matches = [];
  const matcher = normalizedRegex(regex);
  const maxMatches = boundedInteger(metadata.maxMatches, DEFAULT_MAX_MATCHES, 1, 1000);
  let match;
  while (matches.length < maxMatches && (match = matcher.exec(file.content)) !== null) {
    const text = match[0];
    const startLine = lineAt(file, match.index);
    const endLine = lineAt(file, match.index + Math.max(0, text.length - 1));
    const snippet = redactSensitiveText(file.lines.slice(startLine - 1, Math.min(file.lines.length, endLine + 1)).join('\n').slice(0, 500));
    const fingerprint = sha256(`${metadata.ruleId ?? 'evidence'}\0${file.path}\0${startLine}\0${endLine}\0${file.sha256}\0${text}`);
    const stableFingerprint = sha256(`${metadata.ruleId ?? 'evidence'}\0${file.path}\0${normalizeMatch(text)}`);
    matches.push({
      path: file.path,
      startLine,
      endLine,
      snippet,
      fileSha256: file.sha256,
      fingerprint,
      stableFingerprint,
      severity: metadata.severity ?? 'medium'
    });
    if (text.length === 0) matcher.lastIndex += 1;
  }
  return matches;
}

export function firstEvidence(file, regex, metadata = {}) {
  return findEvidence(file, regex, { ...metadata, maxMatches: 1 })[0] ?? null;
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number)) return fallback;
  return Math.min(max, Math.max(min, number));
}

function normalizeMatch(value) { return String(value).trim().replace(/\s+/g, ' ').toLowerCase(); }
