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
  'implemented' | 'supported' | 'unsupported' | 'permission-blocked';

export type SecurityAuditApplicability = 'applicable' | 'not-applicable' | 'unknown';

/** A profile-specific condition that must hold before a control may pass. */
export interface SecurityAuditBaseline {
  readonly profileId: string;
  readonly expectedSecureCondition: string;
}

/** Human guidance remains local and never performs remediation automatically. */
export interface SecurityAuditRecommendation {
  readonly manualRemediation: string;
  readonly safeVerificationCommand?: readonly string[];
}

/** A redacted, serializable fact collected for one control. */
export interface SecurityAuditEvidence {
  readonly id: string;
  readonly kind: string;
  readonly summary: string;
  readonly collectedAt: string;
  readonly redacted: true;
}

/** A stable control definition; concrete collectors remain outside this portable model. */
export interface SecurityAuditControl {
  readonly id: string;
  readonly title: string;
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
  readonly coverage: Exclude<SecurityAuditCoverage, 'unsupported'>;
  readonly outcome: SecurityAuditOutcome;
  readonly severity: SecurityAuditSeverity;
  readonly confidence: SecurityAuditConfidence;
  readonly evidence: readonly SecurityAuditEvidence[];
  readonly recommendation?: SecurityAuditRecommendation;
}

export interface SecurityAuditResult {
  readonly control: SecurityAuditControl;
  readonly applicability: SecurityAuditApplicability;
  readonly coverage: SecurityAuditCoverage;
  readonly outcome: SecurityAuditOutcome;
  readonly severity: SecurityAuditSeverity;
  readonly confidence: SecurityAuditConfidence;
  readonly evidence: readonly SecurityAuditEvidence[];
  readonly recommendation: SecurityAuditRecommendation;
}

export interface SecurityAuditCoverageTotals {
  readonly implemented: number;
  readonly supported: number;
  readonly unsupported: number;
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
}
