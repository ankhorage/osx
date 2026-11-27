import { createMacosSystemDiagnosticsHost } from '../adapters/outbound/createMacosSystemDiagnosticsHost.js';
import {
  collectSystemDiagnosticsAsync,
  type SystemDiagnosticScope,
} from '../application/collectSystemDiagnosticsAsync.js';

/*** Collect one named system diagnostic scope through the local macOS host adapter. */
export async function collectDefaultSystemDiagnosticsAsync(scope: SystemDiagnosticScope) {
  return await collectSystemDiagnosticsAsync(createMacosSystemDiagnosticsHost(), scope);
}
