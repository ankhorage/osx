import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanStorageAsync } from '../src/features/storage/composition/scanStorageAsync.js';

test('finds known paths while keeping inaccessible and risky paths report-only', async () => {
  const home = await mkdtemp(join(tmpdir(), 'osx-scan-'));
  try {
    await mkdir(join(home, '.npm', '_cacache'), { recursive: true });
    await writeFile(join(home, '.npm', '_cacache', 'test'), 'cached');
    const results = await scanStorageAsync(home);
    expect(results.find((item) => item.id === 'npm-cache')?.estimatedBytes).toBeGreaterThan(0);
    expect(results.find((item) => item.id === 'xcode-archives')?.reason).toBe('ENOENT');
    expect(results.every((item) => item.risk === 'report-only')).toBe(true);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
