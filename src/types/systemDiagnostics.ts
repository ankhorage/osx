/*** Read-only evidence captured from a documented host command or reported as unavailable. */
export interface SystemDiagnosticEvidence {
  readonly name: string;
  readonly kind: 'sample' | 'historical';
  readonly status: 'available' | 'permission-denied' | 'unsupported' | 'failed';
  readonly output: string | null;
  readonly note?: string;
}

/*** Snapshot of currently available macOS health evidence; unavailable data is never inferred. */
export interface SystemDiagnosticsReport {
  readonly collectedAt: string;
  readonly platform: string;
  readonly evidence: readonly SystemDiagnosticEvidence[];
}

/*** Boundary for fixed, read-only diagnostic commands at the macOS host edge. */
export interface SystemDiagnosticsHost {
  readonly runAsync: (command: readonly string[]) => Promise<{
    readonly exitCode: number | null;
    readonly output: string;
    readonly status: 'available' | 'permission-denied' | 'unsupported' | 'failed';
  }>;
  readonly platform: string;
}
