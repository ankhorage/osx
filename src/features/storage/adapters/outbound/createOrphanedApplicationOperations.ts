import type {
  OrphanedApplicationHost,
  OrphanedApplicationObservation,
} from '../../../../types/orphanedApplications.js';
import type { StorageCandidate, StorageOperations } from '../../../../types/storage.js';
import { scanOrphanedApplicationsAsync } from '../../application/scanOrphanedApplicationsAsync.js';

/** Adapt verified app remnants into the common approval boundary without widening its scope. */
export function createOrphanedApplicationOperations(
  home: string,
  host: OrphanedApplicationHost,
): StorageOperations {
  return {
    async scan() {
      const observations = await scanOrphanedApplicationsAsync(home, host);
      return observations.map((observation) => asStorageCandidate(observation));
    },
    async revalidate(candidate) {
      return await isCurrentSafeCandidateAsync(home, host, candidate);
    },
    async execute(candidate) {
      if (!candidate.path) throw new Error('Orphan candidate has no path.');
      if (!(await isCurrentSafeCandidateAsync(home, host, candidate)))
        throw new Error('Candidate changed before Trash transfer.');
      return await host.moveToTrash(candidate.path, candidate.fingerprint);
    },
    availableBytes: async () => await host.availableBytes(),
  };
}

/** Repeat ownership inventory immediately before the native transfer boundary. */
async function isCurrentSafeCandidateAsync(
  home: string,
  host: OrphanedApplicationHost,
  candidate: StorageCandidate,
): Promise<boolean> {
  const observations = await scanOrphanedApplicationsAsync(home, host);
  return observations.some(
    (observation) =>
      candidate.id === `orphaned-application:${observation.path}` &&
      observation.safeToTrash &&
      observation.fingerprint === candidate.fingerprint,
  );
}

/** Preserve all ambiguity and protection evidence at the common storage boundary. */
function asStorageCandidate(observation: OrphanedApplicationObservation): StorageCandidate {
  return {
    id: `orphaned-application:${observation.path}`,
    label: observation.label,
    path: observation.path,
    estimatedBytes: observation.allocatedBytes,
    risk: observation.safeToTrash ? 'safe' : 'report-only',
    reason: [
      ...observation.evidence,
      ...observation.blockers,
      `confidence: ${observation.confidence}`,
    ].join('; '),
    fingerprint: observation.fingerprint ?? '',
    preview: observation.safeToTrash
      ? 'Will move to the user Trash; this does not reclaim disk space until Trash is emptied.'
      : undefined,
  };
}
