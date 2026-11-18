import type {
  StorageCandidate,
  StorageCleanupResult,
  StorageOperations,
} from '../../../types/storage.js';

/*** Revalidate and execute an already approved immutable cleanup plan. */
export async function executeStorageCleanupPlanAsync(
  operations: StorageOperations,
  selected: readonly StorageCandidate[],
  approved: boolean,
  dryRun = false,
): Promise<StorageCleanupResult> {
  if (!approved || dryRun)
    return {
      selected,
      outcomes: [],
      approved,
      dryRun,
      freeBytesBefore: null,
      freeBytesAfter: null,
    };
  const freeBytesBefore = await operations.availableBytes();
  if (!isValidBytes(freeBytesBefore))
    throw new Error('Available disk space is unknown; cleanup was not started.');
  const outcomes: { id: string; status: 'cleaned' | 'changed' | 'failed'; error?: string }[] = [];
  for (const candidate of selected) {
    try {
      if (!(await operations.revalidate(candidate)))
        outcomes.push({ id: candidate.id, status: 'changed' });
      else {
        const execution = await operations.execute(candidate);
        outcomes.push({ id: candidate.id, status: 'cleaned', ...execution });
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

/*** Require a finite, nonnegative integer disk measurement. */
function isValidBytes(value: number | null): value is number {
  return value !== null && Number.isSafeInteger(value) && value >= 0;
}
