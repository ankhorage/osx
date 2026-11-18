import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

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
    const packageApi = await import(
      pathToFileURL(join(extracted, 'package', 'dist', 'index.js')).href
    );
    expect(packageApi.collectMacosHostSecurityObservations).toBeFunction();
    expect(packageApi.collectMacosPhysicalAndLinkObservations).toBeFunction();
    expect(packageApi.createMacosSecurityAuditCommandRunner).toBeFunction();
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
      'storage',
      'orphans',
      'scan',
    ]);
    expect(
      loaded.providers[0]?.manifest.commands.map((command) => command.path),
    ).not.toContainEqual(['storage', 'orphans', 'clean']);
    expect(loaded.providers[0]?.manifest.capabilities.map((capability) => capability.id)).toContain(
      'osx.storage.orphans.scan',
    );
    expect(
      loaded.providers[0]?.manifest.capabilities.map((capability) => capability.id),
    ).not.toContain('osx.storage.orphans.clean');
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
      interaction: {
        interactive: true,
        confirm: async () => 'declined' as const,
      },
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
    expect(output.join('')).toContain('storage orphans scan');
    expect(output.join('')).not.toContain('storage orphans clean');
    output.length = 0;
    const orphanScan = await runCli(['osx', 'storage', 'orphans', 'scan', '--json'], options);
    if (process.platform === 'darwin') {
      expect(orphanScan.exitCode).toBe(0);
      expect(JSON.parse(output.join('')).applications).toBeArray();
    } else {
      expect(orphanScan.exitCode).toBe(1);
      expect(errors.join('')).toContain('only on macOS');
      errors.length = 0;
    }
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
    const layerAudit = await runCli(
      ['osx', 'security', 'audit', '--layer', '4', '--non-interactive', '--json'],
      options,
    );
    expect(layerAudit.exitCode).toBe(0);
    expect(JSON.parse(output.join('')).results).toHaveLength(1);
    expect(JSON.parse(output.join('')).results[0].control.id).toBe('osi4-service-exposure');
    output.length = 0;
    const categoryAudit = await runCli(
      ['osx', 'security', 'audit', '--category', 'network-trust', '--non-interactive', '--json'],
      options,
    );
    expect(categoryAudit.exitCode).toBe(0);
    expect(JSON.parse(output.join('')).results[0].control.id).toBe('cross-layer-network-trust');
    output.length = 0;
    const guidedAudit = await runCli(['osx', 'security', 'audit'], options);
    expect(guidedAudit.exitCode).toBe(0);
    expect(output.join('')).toContain('[1/8] OSI layer 1');
    expect(output.join('')).toContain('Skipped Cross-layer host security');
    expect(output.join('')).toContain('does not declare the host secure');
    output.length = 0;
    const controls = await runCli(['osx', 'security', 'controls', 'list', '--json'], options);
    expect(controls.exitCode).toBe(0);
    expect(JSON.parse(output.join('')).controls).toHaveLength(17);
    expect(JSON.parse(output.join('')).controls[0].coverage).toBe('unsupported');
    output.length = 0;
    const aborted = await runCli(['osx', 'security', 'audit'], {
      ...options,
      context: {
        ...context,
        interaction: {
          interactive: true,
          confirm: async () => 'unavailable' as const,
        },
      },
    });
    expect(aborted.exitCode).toBe(130);
    expect(errors.join('')).toContain('no report was saved');
    errors.length = 0;
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
}, 30_000);
