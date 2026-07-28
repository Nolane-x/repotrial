import { spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

async function collect(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collect(path));
    else if (entry.isFile() && entry.name.endsWith('.mjs')) files.push(path);
  }
  return files;
}

const files = [join(root, 'bin', 'repotrial.mjs')];
for (const directory of ['src', 'integrations', 'scripts']) files.push(...await collect(join(root, directory)));

for (const file of files.sort()) {
  const result = spawnSync(process.execPath, ['--check', file], { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
