import type { BackupStatusReport } from '../../../types/backup.js';
import type { BackupHost } from '../ports/backupHost.js';

/*** Collect Time Machine status through documented read-only commands without retaining destinations. */
export async function collectBackupStatusAsync(host: BackupHost): Promise<BackupStatusReport> {
  const [status, destinations, lastBackup] = await Promise.all([
    host.executeAsync(['tmutil', 'status']),
    host.executeAsync(['tmutil', 'destinationinfo']),
    host.executeAsync(['tmutil', 'latestbackup']),
  ]);
  return {
    collectedAt: host.now(),
    timeMachineAvailability: status.availability,
    destinationAvailability: destinations.availability,
    destinationEncrypted: encrypted(destinations),
    lastBackupAvailability: lastBackup.availability,
    lastBackupObserved: observed(lastBackup),
    restoreReadiness: 'unknown',
    limitations: [
      'No restore was attempted, so restore readiness remains unknown.',
      'Destination identities and backup paths are intentionally not retained.',
    ],
  };
}

/*** Report encryption only when the documented destination output provides an explicit value. */
function encrypted(result: Awaited<ReturnType<BackupHost['executeAsync']>): boolean | 'unknown' {
  if (result.availability !== 'available') return 'unknown';
  if (/\bencrypted\s*:\s*yes\b/i.test(result.stdout)) return true;
  if (/\bencrypted\s*:\s*no\b/i.test(result.stdout)) return false;
  return 'unknown';
}

/*** A successful non-empty latest-backup response is evidence of a recorded backup, not restore safety. */
function observed(result: Awaited<ReturnType<BackupHost['executeAsync']>): boolean | 'unknown' {
  return result.availability === 'available' ? result.stdout.trim().length > 0 : 'unknown';
}
