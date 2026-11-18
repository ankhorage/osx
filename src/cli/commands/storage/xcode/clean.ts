import type { AnkhCommandExecutionRequest, AnkhCommandInteraction } from '@ankhorage/ankh';

import { cleanStorageAsync } from '../../../../features/storage/application/cleanStorageAsync.js';
import { createSimctlRuntimeOperations } from '../../../../features/xcode-runtimes/adapters/outbound/createSimctlRuntimeOperations.js';
import type { StorageCandidate, StorageDecisions } from '../../../../types/storage.js';

/*** Collect all Xcode runtime decisions before one final approval and fail-closed execution. */
export async function clean(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 0 && (request.argv.length !== 1 || request.argv[0] !== '--dry-run')) {
    request.context.writeStderr('Usage: ankh osx storage xcode clean [--dry-run]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Xcode Simulator cleanup is available only on macOS.\n');
    return { exitCode: 1 };
  }
  if (!request.context.interaction?.interactive) {
    request.context.writeStderr('Interactive confirmation is required.\n');
    return { exitCode: 1 };
  }
  const operations = createSimctlRuntimeOperations();
  const scanned = await operations.scan();
  for (const candidate of scanned)
    request.context.writeStdout(
      `${candidate.label}: ${candidate.reason}\n${candidate.preview ?? ''}\n`,
    );
  const result = await cleanStorageAsync(
    { ...operations, scan: () => Promise.resolve(scanned) },
    createDecisions(request.context.interaction, (text) => request.context.writeStdout(text)),
    request.argv.includes('--dry-run'),
  );
  request.context.writeStdout(
    result.dryRun
      ? 'Dry-run: no Xcode runtime or Simulator device changed.\n'
      : 'APFS accounting may delay visible free-space changes.\n',
  );
  return { exitCode: result.outcomes.some((outcome) => outcome.status !== 'cleaned') ? 1 : 0 };
}

/*** Make runtime and unavailable-device deletion distinct explicit choices. */
function createDecisions(
  interaction: AnkhCommandInteraction,
  write: (text: string) => void,
): StorageDecisions {
  return {
    async select(candidate) {
      return await selectCandidateAsync(interaction, candidate);
    },
    async approve(selected) {
      const estimatedBytes = selected.reduce(
        (total, item) => total + (item.estimatedBytes ?? 0),
        0,
      );
      write(
        `Selected Xcode cleanup plan (estimated reclaim ${estimatedBytes} bytes):\n${selected.map((item) => `  ${item.label}`).join('\n')}\n`,
      );
      return (await interaction.confirm('Approve this Xcode cleanup plan?')) === 'confirmed';
    },
  };
}

/*** Require an explicit choice for each runtime and the separate device-data operation. */
async function selectCandidateAsync(
  interaction: AnkhCommandInteraction,
  candidate: StorageCandidate,
): Promise<boolean> {
  if (candidate.kind === 'unavailable-simulator-devices')
    return (
      (await interaction.confirm(
        'Delete these unavailable Simulator devices and their app data?',
      )) === 'confirmed'
    );
  if (candidate.label.includes('NEWEST INSTALLED — KEEP')) {
    const keep =
      (await interaction.confirm(`Keep newest? [Y/n] ${candidate.label}`)) === 'confirmed';
    return keep
      ? false
      : (await interaction.confirm(`Remove newest runtime ${candidate.label}?`)) === 'confirmed';
  }
  return (await interaction.confirm(`Remove older runtime ${candidate.label}?`)) === 'confirmed';
}
