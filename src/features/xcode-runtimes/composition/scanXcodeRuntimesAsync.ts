import type { XcodeRuntime } from '../../../types/xcodeRuntime.js';
import { createSimctlRuntimeScanner } from '../adapters/outbound/createSimctlRuntimeScanner.js';

/** Compose the CoreSimulator read-only scanner for the CLI boundary. */
export async function scanXcodeRuntimesAsync(): Promise<readonly XcodeRuntime[]> {
  return await createSimctlRuntimeScanner().scan();
}
