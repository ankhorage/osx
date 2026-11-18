import { execFileSync } from 'node:child_process';

import type { MacosSecurityAuditCommandRunner } from './collectMacosPhysicalAndLinkObservations.js';

/*** Create the bounded local command boundary for passive macOS security collectors. */
export function createMacosSecurityAuditCommandRunner(): MacosSecurityAuditCommandRunner {
  return {
    platform: process.platform,
    run(command, arguments_, timeoutMilliseconds = 2_000) {
      try {
        return {
          kind: 'available',
          stdout: execFileSync(command, arguments_, {
            encoding: 'utf8',
            timeout: timeoutMilliseconds,
            maxBuffer: 1_000_000,
            stdio: ['ignore', 'pipe', 'ignore'],
            windowsHide: true,
          }),
        };
      } catch (error) {
        return commandFailure(error);
      }
    },
  };
}

/*** Map local process failures to explicit source states without retaining process output. */
function commandFailure(
  error: unknown,
): Exclude<ReturnType<MacosSecurityAuditCommandRunner['run']>, { readonly kind: 'available' }> {
  if (!isRecord(error)) return { kind: 'failed' };
  if (error.code === 'ENOENT') return { kind: 'missing' };
  if (error.code === 'EACCES' || error.code === 'EPERM') return { kind: 'permission-denied' };
  if (error.code === 'ETIMEDOUT' || error.signal === 'SIGTERM') return { kind: 'timed-out' };
  return { kind: 'failed' };
}

/*** Narrow Node process errors without serializing command paths, output, or host data. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
