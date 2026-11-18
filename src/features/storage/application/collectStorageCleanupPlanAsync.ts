import type {
  StorageCandidate,
  StorageDecisions,
  StorageOperations,
} from '../../../types/storage.js';

/*** Collect a frozen, uniquely identified storage cleanup plan without changing the host. */
export async function collectStorageCleanupPlanAsync(
  operations: Pick<StorageOperations, 'scan'>,
  decisions: StorageDecisions,
): Promise<{ readonly selected: readonly StorageCandidate[]; readonly approved: boolean }> {
  const scanned = (await operations.scan()).map((candidate) => Object.freeze({ ...candidate }));
  if (new Set(scanned.map((candidate) => candidate.id)).size !== scanned.length)
    throw new Error('Duplicate candidate identifiers make the cleanup plan ambiguous.');
  const selected: StorageCandidate[] = [];
  for (const candidate of scanned)
    if (isSelectable(candidate) && (await decisions.select(candidate))) selected.push(candidate);
  const approved = selected.length > 0 && (await decisions.approve(Object.freeze([...selected])));
  return { selected: Object.freeze([...selected]), approved };
}

/*** Only fully identified, measured, explicitly safe candidates can be selected. */
function isSelectable(candidate: StorageCandidate): boolean {
  return (
    candidate.risk === 'safe' &&
    candidate.id.trim() !== '' &&
    candidate.fingerprint.trim() !== '' &&
    candidate.estimatedBytes !== null &&
    Number.isSafeInteger(candidate.estimatedBytes) &&
    candidate.estimatedBytes >= 0
  );
}
