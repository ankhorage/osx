import type {
  StorageCleanupResult,
  StorageDecisions,
  StorageOperations,
} from '../../../types/storage.js';
import { collectStorageCleanupPlanAsync } from './collectStorageCleanupPlanAsync.js';
import { executeStorageCleanupPlanAsync } from './executeStorageCleanupPlanAsync.js';

/*** Collect all choices and final approval before revalidating and executing any cleanup. */
export async function cleanStorageAsync(
  operations: StorageOperations,
  decisions: StorageDecisions,
  dryRun = false,
): Promise<StorageCleanupResult> {
  const plan = await collectStorageCleanupPlanAsync(operations, decisions);
  return await executeStorageCleanupPlanAsync(operations, plan.selected, plan.approved, dryRun);
}
