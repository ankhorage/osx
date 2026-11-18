import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createToolCleanupOperations,
  type ToolCleanupHost,
} from '../src/features/storage/adapters/outbound/createToolCleanupOperations.js';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';

test('tool adapters execute only after all choices, final approval, and revalidation', async () => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'osx-tool-'));
  try {
    await mkdir(root, { recursive: true });
    await writeFile(join(root, 'cache'), 'cache');
    const calls: string[] = [];
    const host: ToolCleanupHost = {
      async run(command, args) {
        calls.push(`${command} ${args.join(' ')}`);
        if (args[0] === 'path') return { stdout: `${root}\n`, stderr: '' };
        return { stdout: '', stderr: '' };
      },
      async freeBytes() {
        return 100;
      },
    };
    const operations = createToolCleanupOperations(
      'pnpm',
      {
        id: 'pnpm-store',
        label: 'pnpm store',
        inspectArgs: ['path'],
        cleanupArgs: ['store', 'prune'],
        pathFromOutput: (output) => output.trim(),
        reason: 'pnpm-owned store pruning',
      },
      host,
    );
    const result = await cleanStorageAsync(operations, {
      async select() {
        expect(calls).toEqual(['pnpm path']);
        return true;
      },
      async approve() {
        expect(calls).toEqual(['pnpm path']);
        return true;
      },
    });
    expect(result.outcomes).toEqual([{ id: 'pnpm-store', status: 'cleaned' }]);
    expect(calls).toEqual(['pnpm path', 'pnpm path', 'pnpm path', 'pnpm store prune']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('unavailable tools remain report-only and are never offered for cleanup', async () => {
  const operations = createToolCleanupOperations(
    'brew',
    {
      id: 'homebrew-cache',
      label: 'Homebrew cache',
      inspectArgs: ['--cache'],
      cleanupArgs: ['cleanup'],
      pathFromOutput: (output) => output.trim(),
      reason: 'Homebrew-owned cache cleanup',
    },
    {
      async run() {
        throw new Error('missing');
      },
      async freeBytes() {
        return 100;
      },
    },
  );
  const result = await cleanStorageAsync(operations, {
    select: async () => true,
    approve: async () => true,
  });
  expect(result.selected).toEqual([]);
});
