import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { createDefaultSecurityAuditReport } from '../../../../features/security-audit/composition/createDefaultSecurityAuditReport.js';

/*** List the fixed audit catalog and never claim that catalog membership means collector support. */
export function list(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || (request.argv.length === 1 && request.argv[0] !== '--json')) {
    request.context.writeStderr('Usage: ankh osx security controls list [--json]\n');
    return Promise.resolve({ exitCode: 1 });
  }
  const report = createDefaultSecurityAuditReport();
  if (request.argv.includes('--json'))
    request.context.writeStdout(`${JSON.stringify({ controls: report.results }, null, 2)}\n`);
  else
    for (const result of report.results) {
      request.context.writeStdout(`${result.control.id}: ${result.control.title}\n`);
      request.context.writeStdout(`  ${result.control.description}\n`);
      request.context.writeStdout(
        `  Detection: ${result.control.detectionMode}; coverage: ${result.coverage}; evidence: ${result.baseline.status}.\n`,
      );
      request.context.writeStdout(`  Recommendation: ${result.recommendation.manualRemediation}\n`);
    }
  return Promise.resolve({ exitCode: 0 });
}
