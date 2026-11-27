import type { BackupStatusReport } from '../../../types/backup.js';
import { collectBackupStatusAsync } from '../application/collectBackupStatusAsync.js';
import { createMacosBackupHost } from '../adapters/outbound/createMacosBackupHost.js';

/*** Collect the default host-local Time Machine report without starting, restoring, or deleting backups. */
export function collectDefaultBackupStatusAsync(): Promise<BackupStatusReport> {
  return collectBackupStatusAsync(createMacosBackupHost());
}
