/*** Provide reusable local storage inspection and approval boundaries. */
export { cleanStorageAsync } from './features/storage/application/cleanStorageAsync.js';
export { scanOrphanedApplicationsAsync } from './features/storage/application/scanOrphanedApplicationsAsync.js';
export { scanStorageAsync } from './features/storage/composition/scanStorageAsync.js';
export type {
  OrphanedApplicationHost,
  OrphanedApplicationObservation,
} from './types/orphanedApplications.js';
export type {
  StorageCandidate,
  StorageCleanupResult,
  StorageDecisions,
  StorageOperations,
} from './types/storage.js';
