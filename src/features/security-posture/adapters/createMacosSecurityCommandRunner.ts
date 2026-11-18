import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';

/*** Create the macOS process adapter without a shell, elevation, mutation, or retained command output. */
export function createMacosSecurityCommandRunner(): MacosSecurityCommandRunner {
  return { runAsync };
}

/** Execute one fixed collector command without allowing shell interpolation or inherited stdin. */
async function runAsync(
  command: readonly string[],
): Promise<{ readonly exitCode: number; readonly stdout: string; readonly stderr: string }> {
  if (process.platform !== 'darwin')
    return { exitCode: 1, stdout: '', stderr: 'macOS is required for this collector.' };
  const [executable, ...arguments_] = command;
  if (!executable) return { exitCode: 1, stdout: '', stderr: 'A collector command is required.' };
  const result = Bun.spawn({
    cmd: [executable, ...arguments_],
    stdout: 'pipe',
    stderr: 'pipe',
    stdin: 'ignore',
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    result.exited,
    new Response(result.stdout).text(),
    new Response(result.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}
