const PALETTE = Object.freeze({
  TRUSTED: '#15803d',
  CAUTIOUS: '#ca8a04',
  RECKLESS: '#ea580c',
  DANGEROUS: '#b91c1c',
  UNPROVEN: '#64748b'
});

export function renderBadge(verdict) {
  const label = String(verdict.label ?? 'UNPROVEN').toUpperCase();
  const color = PALETTE[label] ?? PALETTE.UNPROVEN;
  const left = 'RepoTrial';
  const right = label;
  const leftWidth = 76;
  const rightWidth = Math.max(72, 12 + right.length * 7);
  const total = leftWidth + rightWidth;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${escapeXml(left)}: ${escapeXml(right)}">
  <title>${escapeXml(left)}: ${escapeXml(right)}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".08"/><stop offset="1" stop-opacity=".08"/></linearGradient>
  <clipPath id="r"><rect width="${total}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#r)"><rect width="${leftWidth}" height="20" fill="#111827"/><rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${color}"/><rect width="${total}" height="20" fill="url(#s)"/></g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="${leftWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${left}</text><text x="${leftWidth / 2}" y="14">${left}</text><text x="${leftWidth + rightWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${right}</text><text x="${leftWidth + rightWidth / 2}" y="14">${right}</text></g>
</svg>\n`;
}

function escapeXml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[char]);
}
