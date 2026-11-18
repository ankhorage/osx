/** A read-only application-remnant observation with evidence collected from macOS ownership sources. */
export interface OrphanedApplicationObservation {
  readonly bundleId: string | null;
  readonly label: string;
  readonly path: string;
  readonly allocatedBytes: number;
  readonly confidence: 'low' | 'medium';
  readonly evidence: readonly string[];
  readonly blockers: readonly string[];
}

/** The narrow host boundary needed to inventory application installation evidence. */
export interface OrphanedApplicationHost {
  installedBundleIds(): Promise<readonly string[]>;
  receiptBundleIds(): Promise<readonly string[]>;
  activeProcessNames(): Promise<readonly string[]>;
  cliNames(): Promise<readonly string[]>;
  inspectPath(path: string): Promise<{ readonly allocatedBytes: number | null }>;
}
