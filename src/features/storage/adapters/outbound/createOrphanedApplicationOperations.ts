import type {
  OrphanedApplicationHost,
  OrphanedApplicationObservation,
} from '../../../../types/orphanedApplications.js';
import type { StorageCandidate, StorageOperations } from '../../../../types/storage.js';
import { scanOrphanedApplicationsAsync } from '../../application/scanOrphanedApplicationsAsync.js';

/** Adapt application-remnant observations as permanently report-only storage candidates. */
export function createOrphanedApplicationOperations(
  home: string,
  host: OrphanedApplicationHost,
): StorageOperations {
  return {
    async scan() {
      const observations = await scanOrphanedApplicationsAsync(home, host);
      return observations.map((observation) => asStorageCandidate(observation));
    },
    revalidate: () => Promise.resolve(false),
    execute: () =>
      Promise.reject(
        new Error('Application remnants are report-only until a safe Trash adapter is available.'),
      ),
    availableBytes: () => Promise.resolve(null),
  };
}

/** Preserve all ambiguity and protection evidence at the common storage boundary. */
function asStorageCandidate(observation: OrphanedApplicationObservation): StorageCandidate {
  return {
    id: `orphaned-application:${observation.path}`,
    label: observation.label,
    path: observation.path,
    estimatedBytes: observation.allocatedBytes,
    risk: 'report-only',
    reason: [
      ...observation.evidence,
      ...observation.blockers,
      `confidence: ${observation.confidence}`,
    ].join('; '),
    fingerprint: '',
  };
}
