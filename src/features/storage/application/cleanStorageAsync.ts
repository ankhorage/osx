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
  const scanned = await operations.scan();
  const selected: StorageCandidate[] = [];
  for (const candidate of scanned) {
    if (
      candidate.risk === 'safe' &&
      candidate.estimatedBytes !== null &&
      Number.isSafeInteger(candidate.estimatedBytes) &&
      candidate.estimatedBytes >= 0 &&
      (await decisions.select(candidate))
    ) {
      selected.push(candidate);
    }
  }
  const approved = selected.length > 0 && (await decisions.approve(selected));
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
  const freeBytesAfter = await operations.availableBytes();
  return { selected, outcomes, approved, dryRun, freeBytesBefore, freeBytesAfter };
}
