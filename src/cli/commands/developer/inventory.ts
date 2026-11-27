import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { scanDeveloperInventoryAsync } from '../../../features/developer/adapters/outbound/scanDeveloperInventoryAsync.js';

/*** Render the report-only development workspace inventory. */
export async function inventory(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || request.argv.some((argument) => argument !== '--json')) {
    request.context.writeStderr('Usage: ankh osx developer <audit|worktrees scan|temp scan|caches> [--json]\n');
    return { exitCode: 1 };
  }
  const report = await scanDeveloperInventoryAsync({
    roots: [request.context.cwd],
    ...(request.context.env.TMPDIR ? { temporaryRoot: request.context.env.TMPDIR } : {}),
  });
  if (request.argv.includes('--json')) request.context.writeStdout(`${JSON.stringify(report, null, 2)}\n`);
  else {
    for (const root of report.roots) {
      request.context.writeStdout(`${root.path}: ${root.status}; artifacts=${root.artifacts.length}\n`);
    }
    request.context.writeStdout('All listed candidates are report-only; no cleanup was performed.\n');
  }
  return { exitCode: 0 };
}
