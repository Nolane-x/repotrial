export function supportedNode(version = process.versions.node) {
  const [major, minor] = String(version).split('.').map(Number);
  return Number.isInteger(major) && (major > 22 || (major === 22 && minor >= 14));
}
export function assertSupportedNode(version = process.versions.node) {
  if (!supportedNode(version)) throw new Error(`RepoTrial requires Node.js 22.14 or newer; detected ${version}. Node.js 20 is no longer supported.`);
}
