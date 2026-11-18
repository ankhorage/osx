import type { StorageCandidate, StorageOperations } from '../../../types/storage.js';
import { createBunCacheHost } from '../adapters/outbound/createBunCacheHost.js';
import { createBunCacheOperations } from '../adapters/outbound/createBunCacheOperations.js';
import {
  createToolCleanupOperations,
  type ToolCleanupDefinition,
} from '../adapters/outbound/createToolCleanupOperations.js';
import { scanStorageAsync } from './scanStorageAsync.js';

/*** Compose one inventory and dispatcher for report-only paths and safe tool adapters. */
export function createDefaultStorageOperations(
  home: string,
  cwd: string,
  env: Readonly<Record<string, string | undefined>>,
): StorageOperations {
  const toolOperations = toolDefinitions.map(({ command, definition }) =>
    createToolCleanupOperations(command, definition),
  );
  const bun = createBunCacheOperations(createBunCacheHost(home, cwd, env));
  const sources = [bun, ...toolOperations];
  return {
    async scan() {
      const reported = await scanStorageAsync(home, sources);
      return reported;
    },
    async revalidate(candidate) {
      return await revalidateAsync(sources, candidate);
    },
    async execute(candidate) {
      await executeAsync(sources, candidate);
    },
    async availableBytes() {
      return await bun.availableBytes();
    },
  };
}

const toolDefinitions: readonly {
  readonly command: string;
  readonly definition: ToolCleanupDefinition;
}[] = [
  {
    command: 'brew',
    definition: {
      id: 'homebrew-cache',
      label: 'Homebrew cache',
      inspectArgs: ['--cache'],
      cleanupArgs: ['cleanup', '--prune=all'],
      pathFromOutput: firstPath,
      reason: 'Homebrew-owned cache cleanup',
    },
  },
  {
    command: 'pnpm',
    definition: {
      id: 'pnpm-store',
      label: 'pnpm store',
      inspectArgs: ['store', 'path'],
      cleanupArgs: ['store', 'prune'],
      pathFromOutput: firstPath,
      reason: 'pnpm-owned store pruning',
    },
  },
  {
    command: 'docker',
    definition: {
      id: 'docker-build-cache',
      label: 'Docker reclaimable data',
      inspectArgs: ['system', 'df', '--format', '{{json .}}'],
      cleanupArgs: ['system', 'prune', '--force'],
      pathFromOutput: () => null,
      estimateFromOutput: dockerEstimate,
      reason: 'Docker system pruning; Docker volumes excluded',
    },
  },
];

/*** Accept one absolute path emitted by a tool's read-only path command. */
function firstPath(output: string): string | null {
  const candidate = output.trim().split('\n')[0]?.trim() ?? '';
  return candidate.startsWith('/') ? candidate : null;
}

/*** Sum Docker's machine-readable reclaimable values without opting into volumes. */
function dockerEstimate(output: string): number | null {
  const entries = output
    .trim()
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as { Reclaimable?: unknown });
  const values = entries.map((entry) =>
    typeof entry.Reclaimable === 'string' ? parseDockerBytes(entry.Reclaimable) : null,
  );
  if (values.some((value) => value === null)) return null;
  return values.reduce<number>((total, value) => total + Number(value), 0);
}

/*** Convert Docker's displayed byte unit without accepting an ambiguous estimate. */
function parseDockerBytes(value: string): number | null {
  const match = /^(\d+(?:\.\d+)?)(B|kB|MB|GB|TB)(?:\s|$)/u.exec(value.trim());
  if (!match?.[1] || !match[2]) return null;
  const unit = ['B', 'kB', 'MB', 'GB', 'TB'].indexOf(match[2]);
  const bytes = Number(match[1]) * 1000 ** unit;
  return Number.isSafeInteger(bytes) ? bytes : null;
}

/*** Send a safe candidate only to the adapter that owns its stable identifier. */
async function revalidateAsync(
  sources: readonly StorageOperations[],
  candidate: StorageCandidate,
): Promise<boolean> {
  for (const source of sources) {
    const current = await source.scan();
    if (!current.some((item) => item.id === candidate.id)) continue;
    return await source.revalidate(candidate);
  }
  return false;
}

/*** Execute only through the adapter that advertises the approved candidate. */
async function executeAsync(
  sources: readonly StorageOperations[],
  candidate: StorageCandidate,
): Promise<void> {
  for (const source of sources) {
    const current = await source.scan();
    if (!current.some((item) => item.id === candidate.id)) continue;
    await source.execute(candidate);
    return;
  }
  throw new Error(`No cleanup adapter owns ${candidate.id}.`);
}
