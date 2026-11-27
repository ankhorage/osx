import { executeSecurityNetworkCommandAsync } from '../../../security-network/adapters/outbound/executeSecurityNetworkCommandAsync.js';
import type { BackupCommandResult, BackupHost } from '../../ports/backupHost.js';

/*** Create the bounded macOS process edge for documented, read-only backup inspection commands. */
export function createMacosBackupHost(): BackupHost {
  return { executeAsync: executeAsync, now: () => new Date().toISOString() };
}

/*** Translate the shared bounded process result into the backup feature's evidence vocabulary. */
async function executeAsync(command: readonly string[]): Promise<BackupCommandResult> {
  const result = await executeSecurityNetworkCommandAsync(command);
  return {
    stdout: result.stdout,
    availability:
      result.status === 'completed'
        ? 'available'
        : result.status === 'permission-denied'
          ? 'permission-denied'
          : result.status === 'unsupported'
            ? 'unsupported'
            : result.status === 'timeout'
              ? 'timeout'
              : /no destinations|not configured|no backup/i.test(result.stdout)
                ? 'absent'
                : 'failed',
  };
}
