/** A scan result is an immutable snapshot; only an adapter can revalidate and execute it. */
export interface StorageCandidate {
  readonly id: string;
  readonly label: string;
  readonly path?: string;
  readonly estimatedBytes: number | null;
  readonly risk: 'safe' | 'report-only';
  readonly reason: string;
  readonly fingerprint: string;
}

/** The storage boundary deliberately leaves platform-specific inspection to an adapter. */
export interface StorageOperations {
  scan(): Promise<readonly StorageCandidate[]>;
  revalidate(candidate: StorageCandidate): Promise<boolean>;
  execute(candidate: StorageCandidate): Promise<void>;
  availableBytes(): Promise<number | null>;
}

/** Decisions are made by the delivery edge and never imply final approval. */
export interface StorageDecisions {
  select(candidate: StorageCandidate): Promise<boolean>;
  approve(selected: readonly StorageCandidate[]): Promise<boolean>;
}

export interface StorageCleanupResult {
  readonly selected: readonly StorageCandidate[];
  readonly outcomes: readonly {
    readonly id: string;
    readonly status: 'cleaned' | 'changed' | 'failed';
    readonly error?: string;
  }[];
  readonly approved: boolean;
  readonly dryRun: boolean;
  readonly freeBytesBefore: number | null;
  readonly freeBytesAfter: number | null;
}
