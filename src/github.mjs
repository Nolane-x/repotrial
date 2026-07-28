export function encodeGithubCommandValue(value) {
  return String(value).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
}

export function normalizeActionThreshold(value) {
  const threshold = String(value ?? 'reckless').toUpperCase();
  if (!['CAUTIOUS', 'RECKLESS', 'DANGEROUS'].includes(threshold)) {
    throw new Error('fail-on must be cautious, reckless, or dangerous.');
  }
  return threshold;
}

export function normalizeActionChoice(value, name, allowed, fallback) {
  const choice = String(value ?? fallback).toLowerCase();
  if (!allowed.includes(choice)) throw new Error(`${name} must be ${allowed.join(', ')}.`);
  return choice;
}
