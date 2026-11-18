import type { StorageCleanupResult } from '../types/storage.js';

/** Render approved estimates, per-candidate results, and the observed filesystem delta. */
export function renderStorageCleanupResult(
  result: StorageCleanupResult,
  write: (text: string) => void,
): void {
  const estimatedBytes = result.selected.reduce(
    (total, item) => total + (item.estimatedBytes ?? 0),
    0,
  );
  if (!result.selected.length) write('No eligible candidates selected.\n');
  else if (!result.approved) write('Cleanup cancelled.\n');
  else if (result.dryRun) write('Dry-run: no files changed.\n');
  if (result.selected.length) write(`Selected estimated reclaim: ${estimatedBytes} bytes.\n`);
  for (const outcome of result.outcomes)
    write(`${outcome.id}: ${outcome.status}${outcome.error ? ` (${outcome.error})` : ''}\n`);
  if (result.freeBytesBefore !== null && result.freeBytesAfter !== null)
    write(
      `Filesystem free-space change: ${result.freeBytesAfter - result.freeBytesBefore} bytes. APFS accounting may be delayed.\n`,
    );
}
