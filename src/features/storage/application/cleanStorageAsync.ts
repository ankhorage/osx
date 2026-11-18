import type {
  StorageCandidate,
  StorageCleanupResult,
  StorageDecisions,
  StorageOperations,
} from '../../../types/storage.js';

/*** Collect all choices and final approval before revalidating and executing any cleanup. */
export async function cleanStorageAsync(
  operations: StorageOperations,
  decisions: StorageDecisions,
  dryRun = false,
): Promise<StorageCleanupResult> {
  const scanned = (await operations.scan()).map((candidate) => Object.freeze({ ...candidate }));
  if (new Set(scanned.map((candidate) => candidate.id)).size !== scanned.length) {
    throw new Error('Duplicate candidate identifiers make the cleanup plan ambiguous.');
  }
  const selected: StorageCandidate[] = [];
  for (const candidate of scanned) {
    if (isSelectable(candidate) && (await decisions.select(candidate))) {
      selected.push(candidate);
    }
  }
  const approved = selected.length > 0 && (await decisions.approve(Object.freeze([...selected])));
  if (!approved || dryRun) {
    return {
      selected,
      outcomes: [],
      approved,
      dryRun,
      freeBytesBefore: null,
      freeBytesAfter: null,
    };
  }
  const freeBytesBefore = await operations.availableBytes();
  if (!isValidBytes(freeBytesBefore)) {
    throw new Error('Available disk space is unknown; cleanup was not started.');
  }
  const outcomes: { id: string; status: 'cleaned' | 'changed' | 'failed'; error?: string }[] = [];
  for (const candidate of selected) {
    try {
      if (!(await operations.revalidate(candidate))) {
        outcomes.push({ id: candidate.id, status: 'changed' });
      } else {
        await operations.execute(candidate);
        outcomes.push({ id: candidate.id, status: 'cleaned' });
      }
    } catch (error) {
      outcomes.push({
        id: candidate.id,
        status: 'failed',
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  const freeBytesAfter = await operations.availableBytes().catch(() => null);
  return { selected, outcomes, approved, dryRun, freeBytesBefore, freeBytesAfter };
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

/*** Require a finite, nonnegative integer disk measurement. */
function isValidBytes(value: number | null): boolean {
  return value !== null && Number.isSafeInteger(value) && value >= 0;
}
