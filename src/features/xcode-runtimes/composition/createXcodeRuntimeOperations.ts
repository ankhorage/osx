import type { StorageOperations } from '../../../types/storage.js';
import { createSimctlRuntimeOperations } from '../adapters/outbound/createSimctlRuntimeOperations.js';

/*** Compose the concrete Xcode process adapter for the CLI delivery edge. */
export function createXcodeRuntimeOperations(): StorageOperations {
  return createSimctlRuntimeOperations();
}
