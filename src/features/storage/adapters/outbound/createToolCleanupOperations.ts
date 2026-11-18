import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { statfs } from 'node:fs/promises';
import { promisify } from 'node:util';

import type { StorageCandidate, StorageOperations } from '../../../../types/storage.js';
import { inspectTreeAsync } from './inspectTreeAsync.js';

/*** Describe a tool-owned cleanup command and its read-only inventory command. */
export interface ToolCleanupDefinition {
  readonly id: string;
  readonly label: string;
  readonly inspectArgs: readonly string[];
  readonly cleanupArgs: readonly string[];
  readonly pathFromOutput?: (output: string) => string | null;
  readonly estimateFromOutput?: (output: string) => number | null;
  readonly reason: string;
}

/*** Limit tool execution to argument-vector process calls at the storage adapter edge. */
export interface ToolCleanupHost {
  run(
    command: string,
    args: readonly string[],
  ): Promise<{ readonly stdout: string; readonly stderr: string }>;
  freeBytes(path: string): Promise<number | null>;
}

/*** Create one safe, tool-owned cleanup operation with snapshot revalidation. */
export function createToolCleanupOperations(
  command: string,
  definition: ToolCleanupDefinition,
  host: ToolCleanupHost = createToolCleanupHost(),
): StorageOperations {
  return {
    async scan() {
      return [await inspectToolAsync(command, definition, host)];
    },
    async revalidate(candidate) {
      const current = await inspectToolAsync(command, definition, host);
      return sameCandidate(candidate, current);
    },
    async execute(candidate) {
      if (!(await this.revalidate(candidate))) throw new Error('Tool cleanup candidate changed.');
      await host.run(command, definition.cleanupArgs);
    },
    async availableBytes() {
      return await host.freeBytes(process.cwd());
    },
  };
}

/*** Compose the real process and filesystem boundaries without shell interpolation. */
function createToolCleanupHost(): ToolCleanupHost {
  return {
    async run(command, args) {
      const result = await promisify(execFile)(command, [...args], {
        timeout: 60_000,
        maxBuffer: 2_000_000,
      });
      return { stdout: result.stdout, stderr: result.stderr };
    },
    async freeBytes(path) {
      try {
        const result = await statfs(path, { bigint: true });
        const bytes = result.bavail * result.bsize;
        return bytes <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(bytes) : null;
      } catch {
        return null;
      }
    },
  };
}

/*** Inspect a tool's owned cache location, or safely report an unavailable tool. */
async function inspectToolAsync(
  command: string,
  definition: ToolCleanupDefinition,
  host: ToolCleanupHost,
): Promise<StorageCandidate> {
  try {
    const result = await host.run(command, definition.inspectArgs);
    const path = definition.pathFromOutput?.(result.stdout) ?? null;
    if (!path && !definition.estimateFromOutput)
      return reportOnly(definition, 'Tool did not provide a canonical cache path.');
    if (!path) {
      const estimate = definition.estimateFromOutput?.(result.stdout) ?? null;
      if (estimate === null)
        return reportOnly(definition, 'Tool did not provide a safe reclaim estimate.');
      return {
        id: definition.id,
        label: definition.label,
        estimatedBytes: estimate,
        risk: 'safe',
        reason: definition.reason,
        fingerprint: createHash('sha256').update(result.stdout).digest('hex'),
      };
    }
    const inspection = await inspectTreeAsync(path);
    if (inspection.allocatedBytes === null || inspection.fingerprint === null)
      return reportOnly(definition, inspection.blockers.join(', '), path);
    return {
      id: definition.id,
      label: definition.label,
      path,
      estimatedBytes: inspection.allocatedBytes,
      risk: 'safe',
      reason: definition.reason,
      fingerprint: inspection.fingerprint,
    };
  } catch {
    return reportOnly(definition, `${command} is unavailable or inaccessible.`);
  }
}

/*** Keep unavailable or unmeasurable tool candidates visible but never selectable. */
function reportOnly(
  definition: ToolCleanupDefinition,
  reason: string,
  path?: string,
): StorageCandidate {
  return {
    id: definition.id,
    label: definition.label,
    ...(path ? { path } : {}),
    estimatedBytes: null,
    risk: 'report-only',
    reason,
    fingerprint: '',
  };
}

/*** Require the complete measured tool snapshot before running its cleanup API. */
function sameCandidate(approved: StorageCandidate, current: StorageCandidate): boolean {
  return (
    approved.id === current.id &&
    approved.risk === 'safe' &&
    current.risk === 'safe' &&
    approved.path === current.path &&
    approved.estimatedBytes === current.estimatedBytes &&
    approved.fingerprint === current.fingerprint
  );
}
