import type { SecurityAuditBaseline, SecurityAuditProfile } from '../../../types/securityAudit.js';
import { validateSecurityAuditFacts } from './validateSecurityAuditFacts.js';

/*** Validate the versioned profile and optional baseline before evidence can be evaluated. */
export function validateSecurityAuditPolicy(
  profile: SecurityAuditProfile,
  baseline: SecurityAuditBaseline | undefined,
): boolean {
  return validProfile(profile) && (baseline === undefined || validBaseline(baseline));
}

/** Validate collector applicability metadata at the runtime boundary. */
export function validateSecurityAuditApplicability(observation: object): boolean {
  const value: unknown = (observation as Record<string, unknown>).applicability;
  return value === 'applicable' || value === 'not-applicable' || value === 'unknown';
}

/** Validate the selected profile's stable, versioned identifier. */
function validProfile(profile: SecurityAuditProfile): boolean {
  return (
    isRecord(profile) &&
    nonEmpty(profile.id) &&
    nonEmpty(profile.version) &&
    nonEmpty(profile.title) &&
    nonEmpty(profile.description) &&
    nonEmpty(profile.baseline) &&
    profile.baseline.endsWith(`-v${profile.version}`)
  );
}

/** Validate the only policy shape that may authorize a pass or fail. */
function validBaseline(baseline: SecurityAuditBaseline): boolean {
  return (
    nonEmpty(baseline.profileId) &&
    nonEmpty(baseline.expectedSecureCondition) &&
    validateSecurityAuditFacts(undefined, baseline.predicate) &&
    ['info', 'low', 'medium', 'high', 'critical'].includes(baseline.failureSeverity)
  );
}

/** Narrow plain JSON records. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Reject whitespace-only policy fields. */
function nonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
