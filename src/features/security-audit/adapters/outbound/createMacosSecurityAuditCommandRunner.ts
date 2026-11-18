import { execFileSync } from 'node:child_process';

export type MacosSecurityAuditCommandResult =
  | { readonly kind: 'available'; readonly stdout: string }
  | { readonly kind: 'missing' }
  | { readonly kind: 'permission-denied' }
  | { readonly kind: 'timed-out' }
  | { readonly kind: 'failed' };

export interface MacosSecurityAuditCommandRunner {
  readonly platform: string;
  run(
    command: string,
    arguments_: readonly string[],
    timeoutMilliseconds?: number,
  ): MacosSecurityAuditCommandResult;
}

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
): Exclude<MacosSecurityAuditCommandResult, { readonly kind: 'available' }> {
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
