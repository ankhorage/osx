import type { XcodeRuntimeOperations } from '../../../types/xcodeRuntime.js';
import { createSimctlRuntimeOperations } from '../adapters/outbound/createSimctlRuntimeOperations.js';

/*** Compose the concrete Xcode process adapter for the CLI delivery edge. */
export function createXcodeRuntimeOperations(): XcodeRuntimeOperations {
  return createSimctlRuntimeOperations();
}
