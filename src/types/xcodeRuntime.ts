import type { StorageCandidate, StorageCleanupResult, StorageOperations } from './storage.js';

/** A normalized Simulator runtime from Xcode's supported JSON inventory. */
export interface XcodeRuntime {
  readonly identifier: string;
  readonly name: string;
  readonly family: string;
  readonly version: string;
  readonly build: string;
  readonly path?: string;
  readonly available: boolean;
  readonly activeDeviceCount: number;
  readonly unavailableDeviceCount: number;
  readonly estimatedBytes: number | null;
  readonly newestInstalled: boolean;
}

/** The process boundary used by the Xcode runtime adapter. */
export interface SimctlHost {
  run(
    command: string,
    args: readonly string[],
  ): Promise<{ readonly stdout: string; readonly stderr: string }>;
  freeBytes(path: string): Promise<number | null>;
}

/** The Xcode-specific boundary for a separately approved unavailable-device operation. */
interface UnavailableSimulatorDeviceOperations {
  revalidateUnavailableDevices(candidate: StorageCandidate): Promise<boolean>;
  executeUnavailableDevices(candidate: StorageCandidate): Promise<void>;
}

/** The composed Xcode boundary keeps generic storage and device-data deletion distinct. */
export type XcodeRuntimeOperations = StorageOperations & UnavailableSimulatorDeviceOperations;

/** Decisions collected by the CLI before any Xcode Simulator deletion can begin. */
export interface XcodeRuntimeDecisions {
  reportCandidate(candidate: StorageCandidate): void;
  selectRuntime(candidate: StorageCandidate): Promise<boolean>;
  selectUnavailableDevices(candidate: StorageCandidate): Promise<boolean>;
  approveUnavailableDevices(candidate: StorageCandidate): Promise<boolean>;
  approvePlan(input: {
    readonly runtimes: readonly StorageCandidate[];
    readonly unavailableDevices: StorageCandidate | null;
  }): Promise<boolean>;
}

/** The complete result of an Xcode cleanup plan and its separately guarded device operation. */
export interface XcodeRuntimeCleanupResult {
  readonly runtime: StorageCleanupResult;
  readonly unavailableDevices: {
    readonly candidate: StorageCandidate | null;
    readonly selected: boolean;
    readonly approved: boolean;
    readonly status: 'cleaned' | 'changed' | 'failed' | 'skipped' | 'dry-run';
    readonly error?: string;
    readonly freeBytesBefore: number | null;
    readonly freeBytesAfter: number | null;
  };
}
