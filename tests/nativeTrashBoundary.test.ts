import { expect, test } from 'bun:test';
import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { createOrphanedApplicationOperations } from '../src/features/storage/adapters/outbound/createOrphanedApplicationOperations.js';

const execFileAsync = promisify(execFile);

test.if(process.platform === 'darwin')(
  'proves renameatx_np does not bind a verified source inode through its final name',
  async () => {
    const output = await mkdtemp(join(tmpdir(), 'osx-native-trash-boundary-'));
    const executable = join(output, 'renameatx-source-identity-probe');
    try {
      const source = new URL(
        './fixtures/native/renameatx-source-identity-probe.c',
        import.meta.url,
      );
      await execFileAsync('/usr/bin/cc', ['-Wall', '-Werror', '-o', executable, source.pathname]);
      const result = await execFileAsync(executable);
      expect(result.stdout).toBe('final-source-name-swap-was-moved\n');
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  },
);

test('keeps orphaned application remnants report-only without a source-identity-bound native move', async () => {
  const result = createOrphanedApplicationOperations('/unused', {
    installedBundleIds: async () => [],
    receiptBundleIds: async () => [],
    activeProcessNames: async () => [],
    cliNames: async () => [],
    inspectPath: async () => ({ allocatedBytes: null }),
  });

  await expect(
    result.execute({
      id: 'candidate',
      label: 'candidate',
      estimatedBytes: 0,
      risk: 'safe',
      reason: 'fixture',
      fingerprint: 'fixture',
    }),
  ).rejects.toThrow('safe Trash adapter is available');
});
