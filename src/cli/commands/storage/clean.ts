import { realpath } from 'node:fs/promises';

import type { AnkhCommandExecutionRequest, AnkhCommandInteraction } from '@ankhorage/ankh';

import { cleanStorageAsync } from '../../../features/storage/application/cleanStorageAsync.js';
import { createDefaultStorageOperations } from '../../../features/storage/composition/createDefaultStorageOperations.js';
import type { StorageDecisions } from '../../../types/storage.js';
import { renderStorageCleanupResult } from '../../renderStorageCleanupResult.js';

/*** Collect per-cache decisions and a final confirmation before any cleanup. */
export async function clean(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (
    request.argv.some((arg) => arg !== '--dry-run') ||
    request.argv.filter((arg) => arg === '--dry-run').length > 1
  ) {
    request.context.writeStderr('Usage: ankh osx storage clean [--dry-run]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Storage cleanup is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const { interaction, env } = request.context;
  if (!interaction?.interactive) {
    request.context.writeStderr('Interactive confirmation is required.\n');
    return { exitCode: 1 };
  }
  if (!env.HOME) {
    request.context.writeStderr('HOME is unavailable.\n');
    return { exitCode: 1 };
  }
  try {
    return await runCleanupAsync(request, interaction, env.HOME);
  } catch (error) {
    request.context.writeStderr(
      `Cleanup failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return { exitCode: 1 };
  }
}

/*** Scan and hand the immutable candidate snapshot to the approval engine. */
async function runCleanupAsync(
  request: AnkhCommandExecutionRequest,
  interaction: AnkhCommandInteraction,
  home: string,
): Promise<{ exitCode: number }> {
  const { context } = request;
  const operations = createDefaultStorageOperations(await realpath(home), context.cwd, context.env);
  const scanned = await operations.scan();
  for (const item of scanned) {
    context.writeStdout(
      `${item.label}: ${item.path ?? 'unknown path'}; ${item.estimatedBytes ?? 'unknown'} allocated bytes; ${item.risk}; ${item.reason}\n`,
    );
    if (item.preview) context.writeStdout(`${item.preview}\n`);
  }
  const result = await cleanStorageAsync(
    { ...operations, scan: () => Promise.resolve(scanned) },
    createDecisions(interaction, (text) => context.writeStdout(text)),
    request.argv.includes('--dry-run'),
  );
  renderStorageCleanupResult(result, (text) => context.writeStdout(text));
  return { exitCode: result.outcomes.some((outcome) => outcome.status !== 'cleaned') ? 1 : 0 };
}

/*** Translate Ankh confirmations into explicit candidate and final-plan decisions. */
function createDecisions(
  interaction: AnkhCommandInteraction,
  write: (text: string) => void,
): StorageDecisions {
  return {
    async select(candidate) {
      return (
        (await interaction.confirm(
          `Clean ${candidate.label} at ${candidate.path} (${candidate.estimatedBytes} estimated bytes)?`,
        )) === 'confirmed'
      );
    },
    async approve(selected) {
      write(
        `Selected plan:\n${selected
          .map(
            (item) =>
              `  ${item.path ?? item.label}: ${item.estimatedBytes} estimated bytes${item.preview ? `\n${item.preview}` : ''}`,
          )
          .join('\n')}\n`,
      );
      return (await interaction.confirm('Approve this cleanup plan?')) === 'confirmed';
    },
  };
}
