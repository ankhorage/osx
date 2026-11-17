import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { discoverAnkhPackages, loadProviderManifests } from '@ankhorage/ankh';

test('packed provider is discovered and loaded by the released Ankh API', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'osx-packed-'));
  try {
    const packed = Bun.spawnSync(
      ['npm', 'pack', '--silent', '--ignore-scripts', '--pack-destination', temp],
      {
        cwd: resolve(import.meta.dir, '..'),
        env: { ...process.env, npm_config_cache: join(temp, 'npm-cache') },
        stdout: 'pipe',
        stderr: 'pipe',
      },
    );
    expect(packed.exitCode).toBe(0);
    const archive = (await readdir(temp)).find((name) => name.endsWith('.tgz'));
    expect(archive).toBeDefined();
    if (!archive) throw new Error('Missing packed archive');
    const extracted = join(temp, 'extracted');
    await mkdir(extracted);
    const unpacked = Bun.spawnSync(['tar', '-xzf', join(temp, archive), '-C', extracted]);
    expect(unpacked.exitCode).toBe(0);
    const discovered = await discoverAnkhPackages({ cwd: join(extracted, 'package') });
    expect(discovered.diagnostics.filter((entry) => entry.severity === 'error')).toEqual([]);
    const ours = discovered.packages.filter((entry) => entry.packageName === '@ankhorage/osx');
    expect(ours).toHaveLength(1);
    const loaded = await loadProviderManifests(ours);
    expect(loaded.diagnostics.filter((entry) => entry.severity === 'error')).toEqual([]);
    expect(loaded.providers[0]?.manifest.commands.map((command) => command.path)).toContainEqual([
      'storage',
      'scan',
    ]);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
