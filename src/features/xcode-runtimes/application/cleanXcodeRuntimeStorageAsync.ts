import type { StorageCandidate } from '../../../types/storage.js';
import type {
  XcodeRuntimeCleanupResult,
  XcodeRuntimeDecisions,
  XcodeRuntimeOperations,
} from '../../../types/xcodeRuntime.js';
import { collectStorageCleanupPlanAsync } from '../../storage/application/collectStorageCleanupPlanAsync.js';
import { executeStorageCleanupPlanAsync } from '../../storage/application/executeStorageCleanupPlanAsync.js';

/*** Collect every Xcode cleanup decision before revalidating or deleting any approved snapshot. */
export async function cleanXcodeRuntimeStorageAsync(
  operations: XcodeRuntimeOperations,
  decisions: XcodeRuntimeDecisions,
  dryRun = false,
): Promise<XcodeRuntimeCleanupResult> {
  const scanned = await operations.scan();
  for (const candidate of scanned) decisions.reportCandidate(candidate);
  const runtimePlan = await collectStorageCleanupPlanAsync(
    { scan: () => Promise.resolve(scanned.filter(isRuntimeCandidate)) },
    {
      select: async (candidate) => await decisions.selectRuntime(candidate),
      approve: () => Promise.resolve(true),
    },
  );
  const deviceCandidate = scanned.find(isSupportedUnavailableDeviceCandidate) ?? null;
  const deviceSelected =
    deviceCandidate !== null && (await decisions.selectUnavailableDevices(deviceCandidate));
  const deviceApproved = deviceSelected
    ? await decisions.approveUnavailableDevices(deviceCandidate)
    : false;
  const selectedDevice = deviceApproved ? deviceCandidate : null;
  const planApproved =
    (runtimePlan.selected.length > 0 || selectedDevice !== null) &&
    (await decisions.approvePlan({
      runtimes: runtimePlan.selected,
      unavailableDevices: selectedDevice,
    }));
  const runtime = await executeStorageCleanupPlanAsync(
    operations,
    runtimePlan.selected,
    planApproved,
    dryRun,
  );
  const unavailableDevices = await executeUnavailableDevicesAsync(
    selectedDevice,
    operations,
    planApproved,
    dryRun,
  );
  return { runtime, unavailableDevices };
}

/** Keep generic Storage-V1 cleanup limited to runtime candidates with measured storage estimates. */
function isRuntimeCandidate(candidate: StorageCandidate): boolean {
  return candidate.kind === 'xcode-runtime';
}

/** Never offer deletion for a report-only or incomplete unavailable-device snapshot. */
function isSupportedUnavailableDeviceCandidate(candidate: StorageCandidate): boolean {
  return (
    candidate.kind === 'unavailable-simulator-devices' &&
    candidate.risk === 'safe' &&
    candidate.id.trim() !== '' &&
    candidate.fingerprint.trim() !== ''
  );
}

/** Revalidate the separately approved device snapshot only after the complete plan is approved. */
async function executeUnavailableDevicesAsync(
  candidate: StorageCandidate | null,
  operations: XcodeRuntimeOperations,
  planApproved: boolean,
  dryRun: boolean,
): Promise<XcodeRuntimeCleanupResult['unavailableDevices']> {
  if (candidate === null || !planApproved)
    return deviceResult(candidate, false, false, 'skipped', null, null);
  if (dryRun) return deviceResult(candidate, true, true, 'dry-run', null, null);
  const freeBytesBefore = await operations.availableBytes().catch(() => null);
  if (!isValidBytes(freeBytesBefore))
    return deviceResult(
      candidate,
      true,
      true,
      'failed',
      null,
      null,
      'Available disk space is unknown.',
    );
  try {
    if (!(await operations.revalidateUnavailableDevices(candidate)))
      return deviceResult(candidate, true, true, 'changed', freeBytesBefore, null);
    await operations.executeUnavailableDevices(candidate);
  } catch (error) {
    return deviceResult(
      candidate,
      true,
      true,
      'failed',
      freeBytesBefore,
      null,
      error instanceof Error ? error.message : String(error),
    );
  }
  return deviceResult(
    candidate,
    true,
    true,
    'cleaned',
    freeBytesBefore,
    await operations.availableBytes().catch(() => null),
  );
}

/** Create a device-operation result without exposing mutable execution state. */
function deviceResult(
  candidate: StorageCandidate | null,
  selected: boolean,
  approved: boolean,
  status: XcodeRuntimeCleanupResult['unavailableDevices']['status'],
  freeBytesBefore: number | null,
  freeBytesAfter: number | null,
  error?: string,
): XcodeRuntimeCleanupResult['unavailableDevices'] {
  return {
    candidate,
    selected,
    approved,
    status,
    ...(error ? { error } : {}),
    freeBytesBefore,
    freeBytesAfter,
  };
}

/** Reject absent or invalid free-space measurements before a destructive device operation. */
function isValidBytes(value: number | null): value is number {
  return value !== null && Number.isSafeInteger(value) && value >= 0;
}
