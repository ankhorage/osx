/** A normalized, read-only Simulator runtime inventory record. */
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
  readonly allocatedBytes: number | null;
  readonly newestInstalled: boolean;
}

/** The process boundary required for read-only Xcode runtime discovery. */
export interface SimctlHost {
  run(command: string, args: readonly string[]): Promise<{ readonly stdout: string }>;
}
