import type { AnkhCommandExecutionRequest, AnkhCommandInteraction } from '@ankhorage/ankh';

import { cleanStorageAsync } from '../../../../features/storage/application/cleanStorageAsync.js';
import { createXcodeRuntimeOperations } from '../../../../features/xcode-runtimes/composition/createXcodeRuntimeOperations.js';
import type { StorageCandidate, StorageDecisions } from '../../../../types/storage.js';
import type { XcodeRuntimeOperations } from '../../../../types/xcodeRuntime.js';
import { renderStorageCleanupResult } from '../../../renderStorageCleanupResult.js';

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
  const operations = createXcodeRuntimeOperations();
  const scanned = await operations.scan();
  for (const candidate of scanned)
    request.context.writeStdout(
      `${candidate.label}: ${candidate.reason}\n${candidate.preview ?? ''}\n`,
    );
  const result = await cleanStorageAsync(
    { ...operations, scan: () => Promise.resolve(scanned.filter(isRuntimeCandidate)) },
    createDecisions(request.context.interaction, (text) => request.context.writeStdout(text)),
    request.argv.includes('--dry-run'),
  );
  renderStorageCleanupResult(result, (text) => request.context.writeStdout(text));
  const deviceSucceeded = await cleanUnavailableDevicesAsync(
    scanned.find((candidate) => candidate.kind === 'unavailable-simulator-devices'),
    operations,
    request.context.interaction,
    request.argv.includes('--dry-run'),
    (text) => request.context.writeStdout(text),
  );
  return {
    exitCode:
      result.outcomes.some((outcome) => outcome.status !== 'cleaned') || !deviceSucceeded ? 1 : 0,
  };
}

/** Keep the generic Storage-V1 engine limited to candidates with measured storage estimates. */
function isRuntimeCandidate(candidate: StorageCandidate): boolean {
  return candidate.kind === 'xcode-runtime';
}

/** Confirm and execute unavailable-device cleanup outside Storage-V1's measured-byte approval policy. */
async function cleanUnavailableDevicesAsync(
  candidate: StorageCandidate | undefined,
  operations: XcodeRuntimeOperations,
  interaction: AnkhCommandInteraction,
  dryRun: boolean,
  write: (text: string) => void,
): Promise<boolean> {
  if (!candidate) return true;
  const approved = await approveUnavailableDevicesAsync(candidate, interaction, write);
  if (!approved) return true;
  if (dryRun) {
    write(`${candidate.id}: dry-run; no devices changed.\n`);
    return true;
  }
  const before = await operations.availableBytes().catch(() => null);
  if (before === null) {
    write(`${candidate.id}: failed (available disk space is unknown; cleanup was not started).\n`);
    return false;
  }
  try {
    if (!(await operations.revalidateUnavailableDevices(candidate))) {
      write(`${candidate.id}: changed (unavailable Simulator devices changed before deletion).\n`);
      return false;
    }
    await operations.executeUnavailableDevices(candidate);
    write(`${candidate.id}: cleaned.\n`);
  } catch (error) {
    write(`${candidate.id}: failed (${error instanceof Error ? error.message : String(error)}).\n`);
    return false;
  }
  const after = await operations.availableBytes().catch(() => null);
  if (after === null)
    write('Filesystem free-space change: unavailable. APFS accounting may be delayed.\n');
  else
    write(
      `Filesystem free-space change: ${after - before} bytes. APFS accounting may be delayed.\n`,
    );
  return true;
}

/** Make device-data selection and final approval explicit before any device mutation. */
async function approveUnavailableDevicesAsync(
  candidate: StorageCandidate,
  interaction: AnkhCommandInteraction,
  write: (text: string) => void,
): Promise<boolean> {
  const selected =
    (await interaction.confirm(
      'Delete these unavailable Simulator devices and their app data?',
    )) === 'confirmed';
  if (!selected) {
    write(`${candidate.id}: skipped.\n`);
    return false;
  }
  write(`Selected device operation (estimated reclaim unknown):\n  ${candidate.label}\n`);
  const approved =
    (await interaction.confirm(
      'Approve deletion of the selected unavailable Simulator devices and their app data?',
    )) === 'confirmed';
  if (!approved) write('Unavailable Simulator device cleanup cancelled.\n');
  return approved;
}

/*** Make runtime deletion choices explicit, with newest versions kept by default. */
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

/*** Require an explicit choice for every eligible runtime. */
async function selectCandidateAsync(
  interaction: AnkhCommandInteraction,
  candidate: StorageCandidate,
): Promise<boolean> {
  if (candidate.label.includes('NEWEST INSTALLED — KEEP')) {
    const keep =
      (await interaction.confirm(`Keep newest? [Y/n] ${candidate.label}`)) === 'confirmed';
    return keep
      ? false
      : (await interaction.confirm(`Remove newest runtime ${candidate.label}?`)) === 'confirmed';
  }
  return (await interaction.confirm(`Remove older runtime ${candidate.label}?`)) === 'confirmed';
}
