/** Portable classification for an OSI chapter or a host-security theme. */
export type SecurityAuditCategory =
  | { readonly kind: 'osi'; readonly layer: 1 | 2 | 3 | 4 | 5 | 6 | 7 }
  | {
      readonly kind: 'cross-layer';
      readonly theme:
        | 'hardware-startup-trust'
        | 'disk-data'
        | 'identity-access'
        | 'privacy-permissions'
        | 'malware-integrity'
        | 'patching-exposure'
        | 'network-trust'
        | 'development-supply-chain'
        | 'backups-resilience-logging'
        | 'enterprise-policy';
    };

export type SecurityAuditDetectionMode = 'passive' | 'api' | 'manual' | 'optional-active';

export type SecurityAuditOutcome = 'pass' | 'warning' | 'fail' | 'unknown' | 'not-applicable';

export type SecurityAuditSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SecurityAuditConfidence = 'none' | 'low' | 'medium' | 'high';

/** Report exactly why a control did or did not contribute host evidence. */
export type SecurityAuditCoverage =
  'implemented' | 'supported' | 'unsupported' | 'incomplete' | 'permission-blocked';

export type SecurityAuditApplicability = 'applicable' | 'not-applicable' | 'unknown';

/** A boolean condition which an engine can evaluate without trusting a collector conclusion. */
export interface SecurityAuditExpectedBooleanFact {
  readonly id: string;
  readonly value: boolean;
}

/** A deterministic control-owned condition over redacted collector facts. */
export interface SecurityAuditBaselinePredicate {
  readonly kind: 'all-boolean-facts';
  readonly facts: readonly SecurityAuditExpectedBooleanFact[];
}

/** A profile-specific condition that must hold before a control may pass. */
export interface SecurityAuditBaseline {
  readonly profileId: string;
  readonly expectedSecureCondition: string;
  readonly predicate: SecurityAuditBaselinePredicate;
  readonly failureSeverity: SecurityAuditSeverity;
}

/** Human guidance remains local and never performs remediation automatically. */
export interface SecurityAuditRecommendation {
  readonly manualRemediation: string;
  readonly safeVerificationCommand?: readonly string[];
}

/** A redacted, typed source fact that can be checked against a control-owned predicate. */
export interface SecurityAuditEvidenceBooleanFact {
  readonly id: string;
  readonly value: boolean;
}

/** A redacted, serializable fact collected for one control. */
export interface SecurityAuditEvidence {
  readonly id: string;
  /** Stable, non-sensitive identifier for the collector check that produced this evidence. */
  readonly sourceId?: string;
  readonly controlId: string;
  readonly profileId: string;
  readonly baselineVersion: string;
  readonly kind: string;
  readonly summary: string;
  readonly collectedAt: string;
  readonly redacted: true;
  readonly facts: readonly SecurityAuditEvidenceBooleanFact[];
}

/** A privacy-safe outcome for one attempted, omitted, or unavailable collector source. */
export type SecurityAuditSourceState =
  | 'completed'
  | 'missing'
  | 'permission-blocked'
  | 'timed-out'
  | 'aborted'
  | 'parse-invalid'
  | 'failed'
  | 'not-queried'
  | 'unsupported'
  | 'manual'
  | 'unclassified';

/** A fixed, redacted explanation for an incomplete source outcome. */
export type SecurityAuditSourceReason = 'bounded-inventory';

/** One source-level provenance record. It deliberately contains no command, arguments, or host output. */
export interface SecurityAuditSourceProvenance {
  readonly id: string;
  readonly state: SecurityAuditSourceState;
  readonly reason?: SecurityAuditSourceReason;
  readonly evidenceIds: readonly string[];
}

/** Deterministic, sanitized inventory suitable for durable CI storage. */
export interface SecurityAuditManifest {
  readonly schemaVersion: 1;
  readonly profileId: string;
  readonly profileVersion: string;
  readonly baseline: string;
  readonly controls: readonly {
    readonly controlId: string;
    readonly category: string;
    readonly coverage: SecurityAuditCoverage;
    readonly outcome: SecurityAuditOutcome;
    readonly baselineStatus: SecurityAuditBaselineEvaluation['status'];
    readonly evidenceIds: readonly string[];
    readonly sources: readonly SecurityAuditSourceProvenance[];
  }[];
}

/** A stable control definition; concrete collectors remain outside this portable model. */
export interface SecurityAuditControl {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly primaryCategory: SecurityAuditCategory;
  readonly crossReferences: readonly SecurityAuditCategory[];
  readonly supportedPlatforms: readonly 'macos'[];
  readonly applicability: string;
  readonly detectionMode: SecurityAuditDetectionMode;
  readonly prerequisites: readonly string[];
  readonly baselines: readonly SecurityAuditBaseline[];
  readonly sourceReferences: readonly string[];
  readonly recommendation: SecurityAuditRecommendation;
}

/** A profile pins its baseline and lets reports name the policy they evaluated. */
export interface SecurityAuditProfile {
  readonly id: string;
  readonly version: string;
  readonly title: string;
  readonly description: string;
  readonly baseline: 'macos-informational-v1';
}

/** An adapter may submit only a fully redacted observation for a known control. */
export interface SecurityAuditObservation {
  readonly controlId: string;
  readonly applicability: SecurityAuditApplicability;
  readonly access: 'available' | 'incomplete' | 'permission-blocked';
  readonly evidence: readonly SecurityAuditEvidence[];
  /** Source outcomes captured by the owning collector adapter, never inferred from control coverage. */
  readonly sources?: readonly SecurityAuditSourceProvenance[];
}

/** Explain the engine-owned evidence decision behind a result. */
export interface SecurityAuditBaselineEvaluation {
  readonly profileId: string;
  readonly expectedSecureCondition: string;
  readonly status:
    | 'verified'
    | 'missing-evidence'
    | 'invalid-evidence'
    | 'incomplete-evidence'
    | 'inaccessible-evidence'
    | 'applicability-unknown'
    | 'contradictory-evidence'
    | 'profile-incompatible';
  readonly evidenceIds: readonly string[];
}

export interface SecurityAuditResult {
  readonly control: SecurityAuditControl;
  readonly applicability: SecurityAuditApplicability;
  readonly coverage: SecurityAuditCoverage;
  readonly outcome: SecurityAuditOutcome;
  readonly severity: SecurityAuditSeverity;
  readonly confidence: SecurityAuditConfidence;
  readonly evidence: readonly SecurityAuditEvidence[];
  readonly sources: readonly SecurityAuditSourceProvenance[];
  readonly recommendation: SecurityAuditRecommendation;
  readonly baseline: SecurityAuditBaselineEvaluation;
}

export interface SecurityAuditCoverageTotals {
  readonly implemented: number;
  readonly supported: number;
  readonly unsupported: number;
  readonly incomplete: number;
  readonly permissionBlocked: number;
}

export interface SecurityAuditCoverageMatrix {
  readonly osi: Readonly<Record<1 | 2 | 3 | 4 | 5 | 6 | 7, SecurityAuditCoverageTotals>>;
  readonly crossLayer: Readonly<
    Record<
      Extract<SecurityAuditCategory, { kind: 'cross-layer' }>['theme'],
      SecurityAuditCoverageTotals
    >
  >;
}

export interface SecurityAuditReport {
  readonly schemaVersion: 1;
  readonly profile: SecurityAuditProfile;
  readonly results: readonly SecurityAuditResult[];
  readonly coverage: SecurityAuditCoverageMatrix;
  readonly manifest: SecurityAuditManifest;
}
