/** A privacy-safe normalized observation from a local macOS unified-log scope. */
export interface LogAnalysisEvent {
  readonly timestamp: string | null;
  readonly process: string | null;
  readonly subsystem: string | null;
  readonly appleLevel: string | null;
  readonly severity: 'fault' | 'error' | 'notice' | 'info' | 'unknown';
  readonly message: string;
}

/** One grouped signature, retaining only a redacted representative message. */
export interface LogAnalysisSignature {
  readonly signature: string;
  readonly severity: LogAnalysisEvent['severity'];
  readonly appleLevel: string | null;
  readonly count: number;
  readonly processes: readonly string[];
  readonly subsystems: readonly string[];
  readonly firstTimestamp: string | null;
  readonly lastTimestamp: string | null;
  readonly representativeEvidence: string;
}

/** A portable report boundary for consumers that compare or further classify log evidence. */
export interface LogAnalysisReport {
  readonly schemaVersion: 1;
  readonly coverage: {
    readonly scope: 'boot' | '24h' | 'file';
    readonly securityFiltered: boolean;
    readonly source: 'macos-log' | 'file';
    readonly parsedEvents: number;
    readonly unparsedRecords: number;
  };
  readonly signatures: readonly LogAnalysisSignature[];
}
