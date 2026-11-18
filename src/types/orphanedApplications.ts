/** A read-only application-remnant observation with evidence collected from macOS ownership sources. */
export interface OrphanedApplicationObservation {
  readonly bundleId: string | null;
  readonly label: string;
  readonly path: string;
  readonly allocatedBytes: number;
  readonly confidence: 'low' | 'medium';
  readonly evidence: readonly string[];
  readonly evidenceAvailability: readonly OrphanedApplicationEvidenceAvailability[];
  readonly blockers: readonly string[];
}

/** A separate read-only inventory source and whether its result is complete enough to rely on. */
export interface OrphanedApplicationEvidenceSource {
  readonly source: string;
  readonly available: boolean;
  readonly values: readonly string[];
}

/** Availability is retained separately from source values in each rendered observation. */
export interface OrphanedApplicationEvidenceAvailability {
  readonly source: string;
  readonly available: boolean;
}

/** The narrow host boundary needed to inventory application installation evidence. */
export interface OrphanedApplicationHost {
  installedBundleIds(): Promise<readonly OrphanedApplicationEvidenceSource[]>;
  receiptBundleIds(): Promise<readonly OrphanedApplicationEvidenceSource[]>;
  activeProcessNames(): Promise<readonly OrphanedApplicationEvidenceSource[]>;
  cliNames(): Promise<readonly OrphanedApplicationEvidenceSource[]>;
  inspectPath(path: string): Promise<{ readonly allocatedBytes: number | null }>;
}
