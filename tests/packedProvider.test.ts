import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { discoverAnkhPackages, loadProviderManifests, runCli } from '@ankhorage/ankh';

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
    expect(loaded.providers[0]?.manifest.commands.map((command) => command.path)).toContainEqual([
      'security',
      'audit',
    ]);
    const output: string[] = [];
    const errors: string[] = [];
    const context = {
      cwd: extracted,
      env: { HOME: temp },
      version: 'test',
      writeStdout: (text: string) => {
        output.push(text);
      },
      writeStderr: (text: string) => {
        errors.push(text);
      },
    };
    const options = {
      context,
      discoverPackages: async () => ({ packages: ours, diagnostics: [] }),
    };
    const help = await runCli(['osx', '--help'], options);
    expect(help.exitCode).toBe(0);
    expect(output.join('')).toContain('storage scan');
    expect(output.join('')).toContain('storage clean');
    expect(output.join('')).toContain('security audit');
    expect(output.join('')).toContain('security controls list');
    output.length = 0;
    const audit = await runCli(
      ['osx', 'security', 'audit', '--non-interactive', '--json'],
      options,
    );
    expect(audit.exitCode).toBe(0);
    expect(
      JSON.parse(output.join('')).results.every(
        (result: { coverage: string }) => result.coverage === 'unsupported',
      ),
    ).toBe(true);
    output.length = 0;
    const controls = await runCli(['osx', 'security', 'controls', 'list', '--json'], options);
    expect(controls.exitCode).toBe(0);
    expect(JSON.parse(output.join('')).controls).toHaveLength(17);
    output.length = 0;
    const scan = await runCli(['osx', 'storage', 'scan', '--json'], options);
    if (process.platform === 'darwin') {
      expect(scan.exitCode).toBe(0);
      expect(JSON.parse(output.join('')).candidates).toBeArray();
    } else {
      expect(scan.exitCode).toBe(1);
      expect(errors.join('')).toContain('only on macOS');
      errors.length = 0;
      const clean = await runCli(['osx', 'storage', 'clean', '--dry-run'], options);
      expect(clean.exitCode).toBe(1);
      expect(errors.join('')).toContain('only on macOS');
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
