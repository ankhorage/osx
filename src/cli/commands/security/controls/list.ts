import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { createSecurityAuditCatalog } from '../../../../features/security-audit/domain/createSecurityAuditCatalog.js';

/*** List the fixed audit catalog and never claim that catalog membership means collector support. */
export function list(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || (request.argv.length === 1 && request.argv[0] !== '--json')) {
    request.context.writeStderr('Usage: ankh osx security controls list [--json]\n');
    return Promise.resolve({ exitCode: 1 });
  }
  const controls = createSecurityAuditCatalog();
  if (request.argv.includes('--json'))
    request.context.writeStdout(`${JSON.stringify({ controls }, null, 2)}\n`);
  else
    for (const control of controls)
      request.context.writeStdout(`${control.id}: ${control.title} [collector unsupported]\n`);
  return Promise.resolve({ exitCode: 0 });
}
