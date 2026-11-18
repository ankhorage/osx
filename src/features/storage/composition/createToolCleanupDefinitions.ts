import type { ToolCleanupDefinition } from '../adapters/outbound/createToolCleanupOperations.js';

/*** Create the narrowly scoped, tool-owned cleanup definitions for the storage composition root. */
export function createToolCleanupDefinitions(): readonly ToolCleanupConfiguration[] {
  return [
    {
      command: 'brew',
      definition: {
        id: 'homebrew-cache',
        label: 'Homebrew cache',
        inspectArgs: ['cleanup', '--prune=all', '--dry-run'],
        cleanupArgs: ['cleanup', '--prune=all'],
        estimateFromOutput: homebrewEstimate,
        previewFromOutput: homebrewPreview,
        reason: 'Homebrew cleanup preview; exact planned outputs are revalidated before execution',
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
        reportOnlyReason:
          'pnpm store prune does not provide a reclaim preview; total store size is not a safe estimate',
        reason: 'pnpm-owned store pruning',
      },
    },
    {
      command: 'docker',
      definition: {
        id: 'docker-build-cache',
        label: 'Docker build cache',
        inspectArgs: ['system', 'df', '--format', '{{json .}}'],
        cleanupArgs: ['builder', 'prune', '--force'],
        pathFromOutput: () => null,
        estimateFromOutput: dockerEstimate,
        reason: 'Docker builder cache pruning; containers, images, networks, and volumes excluded',
      },
    },
  ];
}

/*** Describe a process-owned cleanup adapter selected at composition time. */
export interface ToolCleanupConfiguration {
  readonly command: string;
  readonly definition: ToolCleanupDefinition;
}

/*** Accept one absolute path emitted by a tool's read-only path command. */
function firstPath(output: string): string | null {
  const candidate = output.trim().split('\n')[0]?.trim() ?? '';
  return candidate.startsWith('/') ? candidate : null;
}

/*** Sum only Docker builder-cache bytes that the configured builder prune command can reclaim. */
function dockerEstimate(output: string): number | null {
  try {
    const entries = output
      .trim()
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as { Type?: unknown; Reclaimable?: unknown });
    const buildCache = entries.filter((entry) => entry.Type === 'Build Cache');
    if (buildCache.length !== 1) return null;
    const values = buildCache.map((entry) =>
      typeof entry.Reclaimable === 'string' ? parseDockerBytes(entry.Reclaimable) : null,
    );
    if (values.some((value) => value === null)) return null;
    return values.reduce<number>((total, value) => total + Number(value), 0);
  } catch {
    return null;
  }
}

/*** Convert Docker's displayed byte unit without accepting an ambiguous estimate. */
function parseDockerBytes(value: string): number | null {
  const match = /^(\d+(?:\.\d+)?)(B|kB|MB|GB|TB)(?:\s|$)/u.exec(value.trim());
  if (!match?.[1] || !match[2]) return null;
  const unit = ['B', 'kB', 'MB', 'GB', 'TB'].indexOf(match[2]);
  const bytes = Number(match[1]) * 1000 ** unit;
  return Number.isSafeInteger(bytes) ? bytes : null;
}

/*** Sum Homebrew's dry-run byte totals so execution and approval cover the same planned outputs. */
function homebrewEstimate(output: string): number | null {
  const matches = [...output.matchAll(/\((?:\d+ files?, )?([\d.]+)(B|KB|MB|GB|TB)\)/gu)];
  if (matches.length === 0) return output.includes('Nothing to') ? 0 : null;
  const values = matches.map((match) => parseHomebrewBytes(match[1] ?? '', match[2] ?? ''));
  if (values.some((value) => value === null)) return null;
  return values.reduce<number>((total, value) => total + Number(value), 0);
}

/*** Retain Homebrew's exact dry-run plan so the final consent covers its complete output scope. */
function homebrewPreview(output: string): string | null {
  const preview = output.trim();
  return preview === '' ? null : preview;
}

/*** Convert Homebrew's dry-run decimal byte unit without accepting malformed output. */
function parseHomebrewBytes(number: string, unit: string): number | null {
  const power = ['B', 'KB', 'MB', 'GB', 'TB'].indexOf(unit);
  const bytes = Number(number) * 1000 ** power;
  return power === -1 || !Number.isSafeInteger(bytes) ? null : bytes;
}
