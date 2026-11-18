import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';

const defaultTimeoutMilliseconds = 5_000;
const defaultMaximumOutputBytes = 64 * 1024;

/*** Create the macOS process adapter without a shell, elevation, mutation, or retained command output. */
export function createMacosSecurityCommandRunner(
  options: {
    readonly maximumOutputBytes?: number;
    readonly timeoutMilliseconds?: number;
  } = {},
): MacosSecurityCommandRunner {
  return {
    runAsync: (command) =>
      runAsync(command, {
        maximumOutputBytes: options.maximumOutputBytes ?? defaultMaximumOutputBytes,
        timeoutMilliseconds: options.timeoutMilliseconds ?? defaultTimeoutMilliseconds,
      }),
  };
}

/*** Execute one fixed collector command without allowing shell interpolation or inherited stdin. */
async function runAsync(
  command: readonly string[],
  limits: { readonly maximumOutputBytes: number; readonly timeoutMilliseconds: number },
): Promise<{ readonly exitCode: number; readonly stdout: string; readonly stderr: string }> {
  if (process.platform !== 'darwin')
    return unavailableResult('macOS is required for this collector.');
  const [executable, ...arguments_] = command;
  if (!executable) return unavailableResult('A collector command is required.');
  try {
    const subprocess = Bun.spawn({
      cmd: [executable, ...arguments_],
      stdout: 'pipe',
      stderr: 'pipe',
      stdin: 'ignore',
    });
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<{
      readonly exitCode: number;
      readonly stdout: string;
      readonly stderr: string;
    }>((resolve) => {
      timeoutId = setTimeout(() => {
        subprocess.kill();
        resolve(unavailableResult('Collector command timed out.'));
      }, limits.timeoutMilliseconds);
    });
    try {
      return await Promise.race([
        Promise.all([
          subprocess.exited,
          readOutputAsync(subprocess.stdout, limits.maximumOutputBytes),
          readOutputAsync(subprocess.stderr, limits.maximumOutputBytes),
        ]).then(([exitCode, stdout, stderr]) =>
          exitCode === 0
            ? { exitCode, stdout, stderr }
            : unavailableResult('Collector command failed.'),
        ),
        timeout,
      ]);
    } catch {
      subprocess.kill();
      return unavailableResult('Collector command failed.');
    } finally {
      if (timeoutId !== undefined) clearTimeout(timeoutId);
    }
  } catch {
    return unavailableResult('Collector command could not start.');
  }
}

/*** Read bounded process output so a faulty local command cannot exhaust collector memory. */
async function readOutputAsync(
  stream: ReadableStream<Uint8Array>,
  maximumOutputBytes: number,
): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let output = '';
  let outputBytes = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) return output + decoder.decode();
      outputBytes += chunk.value.byteLength;
      if (outputBytes > maximumOutputBytes) {
        await reader.cancel();
        throw new Error('Collector command output exceeded its limit.');
      }
      output += decoder.decode(chunk.value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

/*** Return a redacted failure result that no evidence collector can interpret as host state. */
function unavailableResult(stderr: string): {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return { exitCode: 1, stdout: '', stderr };
}
