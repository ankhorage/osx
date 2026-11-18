import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

/*** Explain that discovery is read-only until a reversible Trash operation is implemented. */
export function clean(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || request.argv.some((argument) => argument !== '--dry-run')) {
    request.context.writeStderr('Usage: ankh osx storage orphans clean\n');
    return Promise.resolve({ exitCode: 1 });
  }
  request.context.writeStderr(
    'Orphan cleanup is not implemented: observations are read-only until a safe reversible Trash adapter is available.\n',
  );
  return Promise.resolve({ exitCode: 1 });
}
