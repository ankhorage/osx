/** The observed availability of a local, read-only backup source. */
export type BackupEvidenceAvailability =
  | 'available'
  | 'absent'
  | 'permission-denied'
  | 'unsupported'
  | 'timeout'
  | 'failed';

/** A redacted APFS snapshot inventory entry; names are intentionally not retained. */
export interface ApfsSnapshotEvidence {
  readonly volume: string;
  readonly kind: 'system' | 'data' | 'other';
  readonly availability: BackupEvidenceAvailability;
  readonly snapshotCount: number | 'unknown';
}

/** Read-only local backup status; it never establishes that a restore will succeed. */
export interface BackupStatusReport {
  readonly collectedAt: string;
  readonly timeMachineAvailability: BackupEvidenceAvailability;
  readonly destinationAvailability: BackupEvidenceAvailability;
  readonly destinationEncrypted: boolean | 'unknown';
  readonly lastBackupAvailability: BackupEvidenceAvailability;
  readonly lastBackupObserved: boolean | 'unknown';
  readonly restoreReadiness: 'unknown';
  readonly limitations: readonly string[];
}
