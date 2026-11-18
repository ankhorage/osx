import { realpath } from 'node:fs/promises';

import type { AnkhCommandExecutionRequest, AnkhCommandInteraction } from '@ankhorage/ankh';

import { cleanStorageAsync } from '../../../../features/storage/application/cleanStorageAsync.js';
import { createOrphanedApplicationStorageOperations } from '../../../../features/storage/composition/createOrphanedApplicationStorageOperations.js';
import type {
  StorageCandidate,
  StorageCleanupResult,
  StorageDecisions,
} from '../../../../types/storage.js';

/** Collect path-specific consent, then move only revalidated app remnants to the user Trash. */
export async function clean(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (!isValidArguments(request.argv)) {
    request.context.writeStderr('Usage: ankh osx storage orphans clean [--dry-run]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Orphan cleanup is available only on macOS.\n');
    return { exitCode: 1 };
  }
  if (!request.context.interaction?.interactive) {
    request.context.writeStderr('Interactive confirmation is required.\n');
    return { exitCode: 1 };
  }
  if (!request.context.env.HOME) {
    request.context.writeStderr('HOME is unavailable; refusing orphan cleanup.\n');
    return { exitCode: 1 };
  }
  try {
    return await runCleanupAsync(request, request.context.interaction, request.context.env.HOME);
  } catch (error) {
    request.context.writeStderr(
      `Orphan cleanup failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return { exitCode: 1 };
  }
}

/** Inventory every candidate before collecting any path decision or final approval. */
async function runCleanupAsync(
  request: AnkhCommandExecutionRequest,
  interaction: AnkhCommandInteraction,
  home: string,
): Promise<{ exitCode: number }> {
  const canonicalHome = await realpath(home);
  const operations = createOrphanedApplicationStorageOperations(canonicalHome);
  const scanned = await operations.scan();
  for (const candidate of scanned)
    request.context.writeStdout(
      `${candidate.label}: ${candidate.path ?? 'unknown path'}; ${candidate.estimatedBytes ?? 'unknown'} allocated bytes; ${candidate.risk}; ${candidate.reason}\n`,
    );
  const scan = (): Promise<readonly StorageCandidate[]> => Promise.resolve(scanned);
  const write = (text: string): void => request.context.writeStdout(text);
  const result = await cleanStorageAsync(
    { ...operations, scan },
    decisions(interaction, write),
    request.argv.includes('--dry-run'),
  );
  renderResult(result, write);
  return { exitCode: result.outcomes.some((outcome) => outcome.status !== 'cleaned') ? 1 : 0 };
}

/** Require one explicit decision for every eligible path and a final complete-plan approval. */
function decisions(
  interaction: AnkhCommandInteraction,
  write: (text: string) => void,
): StorageDecisions {
  const confirm = interaction.confirm.bind(interaction);
  return {
    async select(candidate) {
      return (
        (await confirm(
          `Move ${candidate.label} at ${candidate.path} to Trash (${candidate.estimatedBytes} estimated bytes)?`,
        )) === 'confirmed'
      );
    },
    async approve(selected) {
      write(
        `Selected Trash plan:\n${selected
          .map((candidate) => `  ${candidate.path}: ${candidate.estimatedBytes} estimated bytes`)
          .join('\n')}\n`,
      );
      return (await confirm('Approve this complete Trash plan?')) === 'confirmed';
    },
  };
}

/** Report estimates, reversible moves, recovery locations, and distinct filesystem accounting. */
function renderResult(result: StorageCleanupResult, write: (text: string) => void): void {
  if (!result.selected.length) write('No verified app-owned candidates selected.\n');
  else if (!result.approved) write('Trash plan cancelled.\n');
  else if (result.dryRun) write('Dry-run: no files changed.\n');
  for (const outcome of result.outcomes)
    write(
      `${outcome.id}: ${outcome.status}${outcome.movedBytes === undefined ? '' : `; moved to Trash: ${outcome.movedBytes} bytes (not yet reclaimed)`}${outcome.recoveryPath ? `; recover from ${outcome.recoveryPath}` : ''}${outcome.error ? ` (${outcome.error})` : ''}\n`,
    );
  if (result.freeBytesBefore !== null && result.freeBytesAfter !== null)
    write(
      `Filesystem free-space change: ${result.freeBytesAfter - result.freeBytesBefore} bytes. Trash moves do not reclaim space until Trash is emptied.\n`,
    );
}

/** Accept at most one dry-run flag and reject every unrecognized argument. */
function isValidArguments(argv: readonly string[]): boolean {
  return argv.every((argument) => argument === '--dry-run') && argv.length <= 1;
}
