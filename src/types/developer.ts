/*** A read-only inventory of one locally configured development root. */
export interface DeveloperInventoryReport {
  readonly roots: readonly DeveloperRootInventory[];
  readonly worktrees: readonly DeveloperWorktree[];
  readonly temporaryProjects: readonly DeveloperTemporaryProject[];
  readonly toolchains: readonly DeveloperToolchain[];
  readonly coverage: readonly string[];
}

/*** Status information collected without fetching or reading repository contents. */
export interface DeveloperRootInventory {
  readonly path: string;
  readonly status: 'available' | 'inaccessible' | 'not-a-repository';
  readonly git?: DeveloperGitStatus;
  readonly artifacts: readonly DeveloperArtifactInventory[];
  readonly ownership: 'configured-root' | 'unknown';
  readonly ownershipEvidence: 'explicit command working directory' | 'path could not be resolved';
}

/*** Local Git worktree metadata retained as guarded-cleanup safety evidence. */
export interface DeveloperWorktree {
  readonly path: string;
  readonly state: 'attached' | 'bare' | 'detached' | 'locked' | 'prunable';
  readonly ownership: 'matches-configured-root' | 'unknown';
  readonly evidence: 'local git worktree list';
  readonly git: DeveloperGitStatus | null;
  readonly activityEvidence: 'unknown';
}

/*** Local Git state used by the guarded-cleanup report boundary. */
export interface DeveloperGitStatus {
  readonly dirty: boolean;
  readonly untracked: number;
  readonly ignored: number;
  readonly remotePublication: 'locally-observed' | 'unknown';
}

/*** A counted development artifact without exposing its contents. */
export interface DeveloperArtifactInventory {
  readonly kind: 'node_modules' | 'build' | 'test' | 'cache';
  readonly path: string;
  readonly allocatedBytes: number | null;
  readonly status: 'available' | 'inaccessible';
}

/*** A recognized temporary project candidate, always report-only. */
export interface DeveloperTemporaryProject {
  readonly path: string;
  readonly owner: 'codex' | 'unknown';
  readonly status: 'candidate' | 'inaccessible';
}

/*** A locally observed tool version. */
export interface DeveloperToolchain {
  readonly name: 'bun' | 'node' | 'git';
  readonly version: string | null;
}
