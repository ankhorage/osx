import type { SecurityAuditBaselinePredicate } from '../../../types/securityAudit.js';

/*** Validate control predicates and their matching redacted collector facts at the runtime boundary. */
export function validateSecurityAuditFacts(facts: unknown, predicate: unknown): boolean {
  if (!isValidPredicate(predicate)) return false;
  if (facts === undefined) return true;
  if (!Array.isArray(facts) || facts.length === 0) return false;
  const expectedFactIds = new Set(predicate.facts.map((fact) => fact.id));
  return facts.every(
    (fact) =>
      isRecord(fact) &&
      isNonEmpty(fact.id) &&
      expectedFactIds.has(fact.id) &&
      typeof fact.value === 'boolean',
  );
}

/** Verify the control-owned predicate shape before it is used to classify a host. */
function isValidPredicate(predicate: unknown): predicate is SecurityAuditBaselinePredicate {
  return (
    isRecord(predicate) &&
    predicate.kind === 'all-boolean-facts' &&
    Array.isArray(predicate.facts) &&
    predicate.facts.length > 0 &&
    predicate.facts.every(
      (fact) =>
        isRecord(fact) &&
        isNonEmpty(fact.id) &&
        typeof fact.value === 'boolean' &&
        !containsSensitiveContent(fact.id),
    ) &&
    new Set(predicate.facts.map((fact) => (isRecord(fact) ? fact.id : ''))).size ===
      predicate.facts.length
  );
}

/** Check serializable identifiers without accepting whitespace-only values. */
function isNonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/** Reject fact names that could encode credentials, addresses, or personal paths. */
function containsSensitiveContent(value: string): boolean {
  return /-----BEGIN|\b(password|passwd|secret|token|private[ _-]?key|keychain|ssid)\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|\/Users\//i.test(
    value,
  );
}

/** Narrow externally supplied JSON before reading its fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
