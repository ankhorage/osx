import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createToolCleanupOperations,
  type ToolCleanupHost,
} from '../src/features/storage/adapters/outbound/createToolCleanupOperations.js';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';
import { createToolCleanupDefinitions } from '../src/features/storage/composition/createToolCleanupDefinitions.js';

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

test('Docker cleanup approves only builder-cache bytes and never dispatches system prune', async () => {
  const docker = createToolCleanupDefinitions().find(({ command }) => command === 'docker');
  if (!docker) throw new Error('Docker cleanup definition is missing.');
  const calls: string[] = [];
  const systemDf = [
    '{"Type":"Images","Reclaimable":"40MB (50%)"}',
    '{"Type":"Containers","Reclaimable":"30MB (100%)"}',
    '{"Type":"Local Volumes","Reclaimable":"20MB (100%)"}',
    '{"Type":"Build Cache","Reclaimable":"2MB (100%)"}',
  ].join('\n');
  const operations = createToolCleanupOperations(docker.command, docker.definition, {
    async run(command, args) {
      calls.push(`${command} ${args.join(' ')}`);
      return args[0] === 'system' ? { stdout: systemDf, stderr: '' } : { stdout: '', stderr: '' };
    },
    async freeBytes() {
      return 100;
    },
  });
  const result = await cleanStorageAsync(operations, {
    select: async (candidate) => {
      expect(candidate.estimatedBytes).toBe(2_000_000);
      return true;
    },
    approve: async () => true,
  });
  expect(result.outcomes).toEqual([{ id: 'docker-build-cache', status: 'cleaned' }]);
  expect(calls).toEqual([
    'docker system df --format {{json .}}',
    'docker system df --format {{json .}}',
    'docker system df --format {{json .}}',
    'docker builder prune --force',
  ]);
});

test('Homebrew refuses cleanup when the reviewed dry-run plan changes', async () => {
  const homebrew = createToolCleanupDefinitions().find(({ command }) => command === 'brew');
  if (!homebrew) throw new Error('Homebrew cleanup definition is missing.');
  const calls: string[] = [];
  const operations = createToolCleanupOperations(homebrew.command, homebrew.definition, {
    async run(command, args) {
      calls.push(`${command} ${args.join(' ')}`);
      const preview = calls.filter((call) => call.includes('--dry-run')).length;
      return {
        stdout: `Would remove: /opt/homebrew/Cellar/example/${preview} (1 file, ${preview}KB)\n`,
        stderr: '',
      };
    },
    async freeBytes() {
      return 100;
    },
  });
  const result = await cleanStorageAsync(operations, {
    select: async (candidate) => {
      expect(candidate.estimatedBytes).toBe(1000);
      expect(candidate.preview).toBe('Would remove: /opt/homebrew/Cellar/example/1 (1 file, 1KB)');
      return true;
    },
    approve: async () => true,
  });
  expect(result.outcomes).toEqual([{ id: 'homebrew-cache', status: 'changed' }]);
  expect(calls).toEqual([
    'brew cleanup --prune=all --dry-run',
    'brew cleanup --prune=all --dry-run',
  ]);
});

test('pnpm store remains report-only because its total size does not predict prune reclaim', async () => {
  const pnpm = createToolCleanupDefinitions().find(({ command }) => command === 'pnpm');
  if (!pnpm) throw new Error('pnpm cleanup definition is missing.');
  const calls: string[] = [];
  const operations = createToolCleanupOperations(pnpm.command, pnpm.definition, {
    async run(command, args) {
      calls.push(`${command} ${args.join(' ')}`);
      return { stdout: '/Users/test/Library/pnpm/store\n', stderr: '' };
    },
    async freeBytes() {
      return 100;
    },
  });
  const result = await cleanStorageAsync(operations, {
    select: async () => true,
    approve: async () => true,
  });
  expect(result.selected).toEqual([]);
  expect(calls).toEqual(['pnpm store path']);
});
