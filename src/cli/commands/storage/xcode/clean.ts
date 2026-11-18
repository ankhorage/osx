import type { AnkhCommandExecutionRequest, AnkhCommandInteraction } from '@ankhorage/ankh';

import { cleanXcodeRuntimeStorageAsync } from '../../../../features/xcode-runtimes/application/cleanXcodeRuntimeStorageAsync.js';
import { createXcodeRuntimeOperations } from '../../../../features/xcode-runtimes/composition/createXcodeRuntimeOperations.js';
import type { StorageCandidate } from '../../../../types/storage.js';
import type { XcodeRuntimeDecisions } from '../../../../types/xcodeRuntime.js';
import { renderStorageCleanupResult } from '../../../renderStorageCleanupResult.js';

/*** Collect every Xcode decision and approval before any runtime or device deletion begins. */
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
  const write = (text: string) => request.context.writeStdout(text);
  const result = await cleanXcodeRuntimeStorageAsync(
    createXcodeRuntimeOperations(),
    createDecisions(request.context.interaction, write),
    request.argv.includes('--dry-run'),
  );
  renderStorageCleanupResult(result.runtime, write);
  renderUnavailableDeviceResult(result.unavailableDevices, write);
  return {
    exitCode:
      result.runtime.outcomes.some((outcome) => outcome.status !== 'cleaned') ||
      result.unavailableDevices.status === 'changed' ||
      result.unavailableDevices.status === 'failed'
        ? 1
        : 0,
  };
}

/*** Create the full-plan and separately strong device-data confirmations. */
function createDecisions(
  interaction: AnkhCommandInteraction,
  write: (text: string) => void,
): XcodeRuntimeDecisions {
  return {
    reportCandidate(candidate) {
      write(`${candidate.label}: ${candidate.reason}\n${candidate.preview ?? ''}\n`);
    },
    async selectRuntime(candidate) {
      return await selectRuntimeAsync(interaction, candidate);
    },
    async selectUnavailableDevices() {
      return (
        (await interaction.confirm(
          'Delete these unavailable Simulator devices and their app data?',
        )) === 'confirmed'
      );
    },
    async approveUnavailableDevices(candidate) {
      write(`Selected device operation (estimated reclaim unknown):\n  ${candidate.label}\n`);
      return (
        (await interaction.confirm(
          'Strong confirmation: delete the selected unavailable Simulator devices and their app data?',
        )) === 'confirmed'
      );
    },
    async approvePlan({ runtimes, unavailableDevices }) {
      const estimatedBytes = runtimes.reduce(
        (total, item) => total + (item.estimatedBytes ?? 0),
        0,
      );
      const items = [
        ...runtimes.map((item) => `  ${item.label}`),
        ...(unavailableDevices ? [`  ${unavailableDevices.label} (app data included)`] : []),
      ];
      write(
        `Selected Xcode cleanup plan (estimated runtime reclaim ${estimatedBytes} bytes):\n${items.join('\n')}\n`,
      );
      return (
        (await interaction.confirm('Approve this complete Xcode cleanup plan?')) === 'confirmed'
      );
    },
  };
}

/** Render the device-specific outcome without claiming an unknown storage estimate. */
function renderUnavailableDeviceResult(
  result: Awaited<ReturnType<typeof cleanXcodeRuntimeStorageAsync>>['unavailableDevices'],
  write: (text: string) => void,
): void {
  if (result.candidate === null || result.status === 'skipped') return;
  if (result.status === 'dry-run') {
    write(`${result.candidate.id}: dry-run; no devices changed.\n`);
    return;
  }
  if (result.status === 'cleaned') {
    write(`${result.candidate.id}: cleaned.\n`);
    if (result.freeBytesAfter === null)
      write('Filesystem free-space change: unavailable. APFS accounting may be delayed.\n');
    else
      write(
        `Filesystem free-space change: ${result.freeBytesAfter - (result.freeBytesBefore ?? result.freeBytesAfter)} bytes. APFS accounting may be delayed.\n`,
      );
    return;
  }
  write(`${result.candidate.id}: ${result.status}${result.error ? ` (${result.error})` : ''}.\n`);
}

/*** Require an explicit choice for every eligible runtime. */
async function selectRuntimeAsync(
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
