import type { BackupEvidenceAvailability } from '../../../types/backup.js';

/** Bounded outcome of a fixed read-only local backup command. */
export interface BackupCommandResult {
  readonly availability: BackupEvidenceAvailability;
  readonly stdout: string;
}

/** Host edge required by the backup feature without exposing process details to report policy. */
export interface BackupHost {
  readonly executeAsync: (command: readonly string[]) => Promise<BackupCommandResult>;
  readonly now: () => string;
}
