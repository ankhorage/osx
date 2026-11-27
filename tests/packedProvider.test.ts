import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
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
    expect(packageApi.collectMacosHostSecurityObservationsAsync).toBeFunction();
    expect(packageApi.collectMacosPhysicalAndLinkObservationsAsync).toBeFunction();
    expect(packageApi.createMacosSecurityAuditCommandRunner).toBeFunction();
    expect(packageApi.parseRuntimeInventoryAsync).toBeFunction();
    await expect(
      packageApi.parseRuntimeInventoryAsync(
        JSON.stringify({
          runtimes: [
            {
              identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-18-0',
              name: 'iOS 18.0',
              version: '18.0',
              buildversion: 'A',
            },
          ],
        }),
        JSON.stringify({ devices: {} }),
      ),
    ).resolves.toEqual([
      expect.objectContaining({
        family: 'iOS/iPadOS',
        identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-18-0',
        newestInstalled: true,
      }),
    ]);
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
      'backup',
      'status',
    ]);
    expect(loaded.providers[0]?.manifest.commands.map((command) => command.path)).toContainEqual([
      'backup',
      'snapshots',
      'list',
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
    expect(loaded.providers[0]?.manifest.capabilities.map((capability) => capability.id)).toContain(
      'osx.backup.status',
    );
    expect(loaded.providers[0]?.manifest.capabilities.map((capability) => capability.id)).toContain(
      'osx.backup.snapshots.list',
    );
    expect(
      loaded.providers[0]?.manifest.capabilities.map((capability) => capability.id),
    ).not.toContain('osx.storage.orphans.clean');
    expect(loaded.providers[0]?.manifest.commands.map((command) => command.path)).toContainEqual([
      'security',
      'audit',
    ]);
    expect(loaded.providers[0]?.manifest.commands.map((command) => command.path)).toContainEqual([
      'storage',
      'xcode',
      'scan',
    ]);
    expect(
      loaded.providers[0]?.manifest.commands.map((command) => command.path),
    ).not.toContainEqual(['storage', 'xcode', 'clean']);
    expect(
      loaded.providers[0]?.manifest.capabilities.map((capability) => capability.id),
    ).not.toContain('osx.storage.xcode.clean');
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
    expect(output.join('')).toContain('storage xcode scan');
    expect(output.join('')).not.toContain('storage xcode clean');
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
    const auditReport = JSON.parse(output.join('')) as {
      readonly results: readonly {
        readonly control: { readonly id: string };
        readonly outcome: string;
        readonly evidence: readonly {
          readonly facts: readonly { readonly id: string; readonly value: boolean }[];
        }[];
        readonly sources: readonly {
          readonly id: string;
          readonly state: string;
          readonly reason?: string;
        }[];
      }[];
      readonly manifest?: {
        readonly controls: readonly {
          readonly controlId: string;
          readonly coverage: string;
          readonly sources: readonly { readonly state: string; readonly reason?: string }[];
        }[];
      };
    };
    expect(auditReport.results).toHaveLength(17);
    expect(
      auditReport.results.every(
        (result) => result.outcome !== 'pass' || result.evidence.length > 0,
      ),
    ).toBe(true);
    const l6 = auditReport.results.find(
      (result) => result.control.id === 'osi6-presentation-trust',
    );
    if (
      l6?.sources.some(
        (source) => source.id === 'macos-posture:keychains' && source.state === 'completed',
      )
    ) {
      expect(l6.evidence.flatMap((item) => item.facts)).toContainEqual({
        id: 'keychain-metadata-observable',
        value: true,
      });
    }
    for (const control of auditReport.manifest?.controls ?? []) {
      if (
        ['osi1-physical-interface-inventory', 'osi2-link-security'].includes(control.controlId) &&
        control.coverage === 'incomplete'
      )
        expect(
          control.sources.some(
            (source) => source.state !== 'completed' || source.reason === 'bounded-inventory',
          ),
        ).toBe(true);
    }
    await writeNativeAuditManifestAsync(auditReport, packageApi);
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
    expect(JSON.parse(output.join('')).controls[0].collector).toBe('present');
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
      output.length = 0;
      if (process.env.ANKH_NATIVE_CORESIMULATOR_ACCEPTANCE === '1') {
        output.length = 0;
        const xcodeScan = await runCli(['osx', 'storage', 'xcode', 'scan', '--json'], options);
        expect(xcodeScan.exitCode).toBe(0);
        const inventory = JSON.parse(output.join('')) as {
          readonly runtimes: readonly { readonly identifier: string }[];
        };
        expect(inventory.runtimes).toBeArray();
      }
    } else {
      expect(scan.exitCode).toBe(1);
      expect(errors.join('')).toContain('only on macOS');
      errors.length = 0;
      const xcodeScan = await runCli(['osx', 'storage', 'xcode', 'scan', '--json'], options);
      expect(xcodeScan.exitCode).toBe(1);
      expect(errors.join('')).toContain('only on macOS');
      errors.length = 0;
      const clean = await runCli(['osx', 'storage', 'clean', '--dry-run'], options);
      expect(clean.exitCode).toBe(1);
      expect(errors.join('')).toContain('only on macOS');
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}, 120_000);

/** Persist only the package-produced redacted manifest when native CI explicitly requests it. */
async function writeNativeAuditManifestAsync(
  report: { readonly manifest?: unknown },
  packageApi: { readonly createSecurityAuditManifest?: unknown; readonly version?: unknown },
): Promise<void> {
  const destination = process.env.ANKH_NATIVE_SECURITY_AUDIT_MANIFEST;
  if (!destination) return;
  expect(process.platform).toBe('darwin');
  expect(packageApi.createSecurityAuditManifest).toBeFunction();
  const manifest = report.manifest as {
    readonly schemaVersion: number;
    readonly controls: readonly {
      readonly evidenceIds: readonly string[];
      readonly sources: readonly unknown[];
    }[];
  };
  expect(manifest.controls).toHaveLength(17);
  const serialized = JSON.stringify(
    {
      validation: {
        prHeadSha: process.env.ANKH_PR_HEAD_SHA ?? 'local-native-acceptance',
        testedMergeSha:
          process.env.ANKH_TESTED_MERGE_SHA ?? process.env.GITHUB_SHA ?? 'local-native-acceptance',
        schemaVersion: manifest.schemaVersion,
        toolVersion:
          typeof packageApi.version === 'string' ? packageApi.version : 'packed-provider',
        runner: {
          os: process.env.ANKH_RUNNER_OS ?? process.platform,
          architecture: process.env.ANKH_RUNNER_ARCH ?? process.arch,
        },
        validationMode: 'packed-provider-native-security-audit',
        recordCount: manifest.controls.length,
        generatedAt: new Date().toISOString(),
      },
      manifest,
    },
    null,
    2,
  );
  expect(serialized).not.toMatch(
    /-----BEGIN|\/Users\/|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i,
  );
  await writeFile(destination, `${serialized}\n`, 'utf8');
}
