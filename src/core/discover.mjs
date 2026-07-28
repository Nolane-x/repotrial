import { lstat, readdir, readFile, realpath, stat as fsStat } from 'node:fs/promises';
import path from 'node:path';
import { sha256 } from './hash.mjs';

const DEFAULT_IGNORED = new Set([
  '.git', '.hg', '.svn', 'node_modules', 'vendor', 'dist', 'build', 'coverage',
  '.next', '.nuxt', '.cache', '.turbo', '.repotrial', '__pycache__', '.venv', 'venv'
]);

const DEFAULTS = Object.freeze({
  maxFiles: 5000,
  maxFileBytes: 512 * 1024,
  maxTotalBytes: 20 * 1024 * 1024,
  ignoredDirectories: DEFAULT_IGNORED
});

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

function toPosix(relativePath) {
  return relativePath.split(path.sep).join('/');
}

function isBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  for (const byte of sample) {
    if (byte === 0) return true;
  }
  return false;
}

function isWithin(candidate, parent) {
  return candidate === parent || candidate.startsWith(`${parent}${path.sep}`);
}

export async function discoverRepository(root, options = {}) {
  const resolvedRoot = path.resolve(root);
  const opts = {
    ...DEFAULTS,
    ...options,
    ignoredDirectories: options.ignoredDirectories
      ? new Set(options.ignoredDirectories)
      : DEFAULT_IGNORED,
    ignoredPaths: (options.ignoredPaths ?? []).map((entry) => path.resolve(entry)),
    excludedPaths: (options.excludedPaths ?? []).map((entry) => path.resolve(entry))
  };
  const rootStat = await lstat(resolvedRoot);
  if (!rootStat.isDirectory()) throw new Error(`Scan root is not a directory: ${resolvedRoot}`);

  const files = [];
  const omissions = [];
  const aliases = [];
  let totalBytes = 0;
  let limitReached = false;

  async function walk(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (directory === resolvedRoot) throw error;
      omissions.push({
        path: `${toPosix(path.relative(resolvedRoot, directory))}/`,
        reason: 'unreadable-directory'
      });
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      const relativePath = toPosix(path.relative(resolvedRoot, absolutePath));

      if (opts.ignoredPaths.some((ignoredPath) => isWithin(absolutePath, ignoredPath))) {
        omissions.push({
          path: entry.isDirectory() ? `${relativePath}/` : relativePath,
          reason: 'generated-output'
        });
        continue;
      }
      if (opts.excludedPaths.some((excludedPath) => isWithin(absolutePath, excludedPath))) {
        omissions.push({
          path: entry.isDirectory() ? `${relativePath}/` : relativePath,
          reason: 'user-excluded'
        });
        continue;
      }
      if (entry.isSymbolicLink()) {
        let targetPath;
        try {
          targetPath = await realpath(absolutePath);
        } catch {
          omissions.push({ path: relativePath, reason: 'broken-symlink' });
          continue;
        }
        if (!isWithin(targetPath, resolvedRoot)) {
          omissions.push({ path: relativePath, reason: 'symlink-escape' });
          continue;
        }
        let targetStat;
        try {
          targetStat = await fsStat(targetPath);
        } catch {
          omissions.push({ path: relativePath, reason: 'broken-symlink' });
          continue;
        }
        if (targetStat.isFile()) {
          aliases.push({
            path: relativePath,
            absolutePath,
            targetPath,
            target: toPosix(path.relative(resolvedRoot, targetPath))
          });
        } else {
          omissions.push({ path: relativePath, reason: 'symlink' });
        }
        continue;
      }
      if (entry.isDirectory()) {
        if (opts.ignoredDirectories.has(entry.name)) {
          omissions.push({ path: `${relativePath}/`, reason: 'ignored-directory' });
          continue;
        }
        await walk(absolutePath);
        continue;
      }
      if (!entry.isFile()) {
        omissions.push({ path: relativePath, reason: 'unsupported-file-type' });
        continue;
      }
      if (files.length >= opts.maxFiles) {
        omissions.push({ path: relativePath, reason: 'file-limit' });
        limitReached = true;
        continue;
      }

      let stat;
      try {
        stat = await lstat(absolutePath);
      } catch {
        omissions.push({ path: relativePath, reason: 'changed-during-scan' });
        continue;
      }
      if (stat.isSymbolicLink()) {
        omissions.push({ path: relativePath, reason: 'symlink' });
        continue;
      }
      if (!stat.isFile()) {
        omissions.push({ path: relativePath, reason: 'changed-during-scan' });
        continue;
      }
      if (stat.size > opts.maxFileBytes) {
        omissions.push({ path: relativePath, reason: 'file-too-large', size: stat.size });
        continue;
      }
      if (totalBytes + stat.size > opts.maxTotalBytes) {
        omissions.push({ path: relativePath, reason: 'total-byte-limit', size: stat.size });
        limitReached = true;
        continue;
      }

      let buffer;
      try {
        buffer = await readFile(absolutePath);
      } catch {
        omissions.push({ path: relativePath, reason: 'unreadable-file', size: stat.size });
        continue;
      }
      if (isBinary(buffer)) {
        omissions.push({ path: relativePath, reason: 'binary', size: stat.size });
        continue;
      }
      let content;
      try {
        content = UTF8_DECODER.decode(buffer);
      } catch {
        omissions.push({ path: relativePath, reason: 'invalid-utf8', size: stat.size });
        continue;
      }
      files.push({
        path: relativePath,
        absolutePath,
        size: stat.size,
        sha256: sha256(buffer),
        content,
        lines: content.split(/\r?\n/)
      });
      totalBytes += stat.size;
    }
  }

  await walk(resolvedRoot);

  aliases.sort((a, b) => a.path.localeCompare(b.path));
  const filesByAbsolutePath = new Map(files.map((file) => [file.absolutePath, file]));
  for (const alias of aliases) {
    const targetFile = filesByAbsolutePath.get(alias.targetPath);
    if (!targetFile) {
      omissions.push({ path: alias.path, reason: 'symlink-uninspected-target', target: alias.target });
      continue;
    }
    if (files.length >= opts.maxFiles) {
      omissions.push({ path: alias.path, reason: 'file-limit' });
      limitReached = true;
      continue;
    }
    if (totalBytes + targetFile.size > opts.maxTotalBytes) {
      omissions.push({ path: alias.path, reason: 'total-byte-limit', size: targetFile.size });
      limitReached = true;
      continue;
    }
    files.push({
      ...targetFile,
      path: alias.path,
      absolutePath: targetFile.absolutePath,
      symlinkPath: alias.absolutePath,
      aliasOf: targetFile.path
    });
    totalBytes += targetFile.size;
  }

  files.sort((a, b) => a.path.localeCompare(b.path));
  omissions.sort((a, b) => a.path.localeCompare(b.path) || a.reason.localeCompare(b.reason));

  const coverageOmissions = omissions.filter((item) => !['ignored-directory', 'generated-output', 'user-excluded'].includes(item.reason));
  const considered = files.length + coverageOmissions.length;
  const ratio = considered === 0 ? 0 : files.length / considered;

  return {
    root: resolvedRoot,
    files,
    omissions,
    totalBytes,
    coverage: {
      filesInspected: files.length,
      bytesInspected: totalBytes,
      omitted: coverageOmissions.length,
      ratio: Number(ratio.toFixed(6)),
      complete: coverageOmissions.length === 0 && !limitReached
    }
  };
}
