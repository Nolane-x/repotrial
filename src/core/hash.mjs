import { createHash } from 'node:crypto';

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function stableStringify(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object' && value.constructor === Object) {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sortValue(value[key])])
    );
  }
  return value;
}
