import type { OrphanedApplicationObservation } from '../../../types/orphanedApplications.js';
import type { StorageOperations } from '../../../types/storage.js';
import { createOrphanedApplicationHost } from '../adapters/outbound/createOrphanedApplicationHost.js';
import { createOrphanedApplicationOperations } from '../adapters/outbound/createOrphanedApplicationOperations.js';
import { scanOrphanedApplicationsAsync } from '../application/scanOrphanedApplicationsAsync.js';

/** Compose the macOS inventory adapter with the app-remnant application boundary. */
export function createOrphanedApplicationStorageOperations(home: string): StorageOperations {
  return createOrphanedApplicationOperations(home, createOrphanedApplicationHost(home));
}

/** Scan app remnants through composition without exposing concrete adapters to delivery code. */
export async function scanOrphanedApplicationStorageAsync(
  home: string,
): Promise<readonly OrphanedApplicationObservation[]> {
  return await scanOrphanedApplicationsAsync(home, createOrphanedApplicationHost(home));
}
