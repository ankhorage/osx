import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';

const defaultTimeoutMilliseconds = 5_000;
const defaultMaximumOutputBytes = 64 * 1024;
const terminationGraceMilliseconds = 100;
const reapTimeoutMilliseconds = 1_000;

interface CommandResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

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
        maximumOutputBytes: normalizeLimit(options.maximumOutputBytes, defaultMaximumOutputBytes),
        timeoutMilliseconds: normalizeLimit(
          options.timeoutMilliseconds,
          defaultTimeoutMilliseconds,
        ),
      }),
  };
}

/*** Execute one fixed collector command and reap its complete process group before returning failure. */
async function runAsync(
  command: readonly string[],
  limits: { readonly maximumOutputBytes: number; readonly timeoutMilliseconds: number },
): Promise<CommandResult> {
  if (process.platform !== 'darwin')
    return unavailableResult('macOS is required for this collector.');
  const [executable, ...arguments_] = command;
  if (!executable) return unavailableResult('A collector command is required.');
  try {
    const subprocess = Bun.spawn({
      cmd: [executable, ...arguments_],
      detached: true,
      stdout: 'pipe',
      stderr: 'pipe',
      stdin: 'ignore',
    });
    const result = await raceCompletionAsync(subprocess, limits);
    if (result && result !== 'timeout') return result;
    await terminateAndReapAsync(subprocess);
    return unavailableResult(
      result === 'timeout' ? 'Collector command timed out.' : 'Collector command failed.',
    );
  } catch {
    return unavailableResult('Collector command could not start.');
  }
}

/*** Return a successful result only after both bounded streams and the command have completed. */
async function raceCompletionAsync(
  subprocess: Bun.Subprocess<'ignore', 'pipe', 'pipe'>,
  limits: { readonly maximumOutputBytes: number; readonly timeoutMilliseconds: number },
): Promise<CommandResult | 'timeout' | undefined> {
  const completion = Promise.all([
    subprocess.exited,
    readOutputAsync(subprocess.stdout, limits.maximumOutputBytes),
    readOutputAsync(subprocess.stderr, limits.maximumOutputBytes),
  ])
    .then(([exitCode, stdout, stderr]) =>
      exitCode === 0 ? { exitCode, stdout, stderr } : undefined,
    )
    .catch(() => undefined);
  return Promise.race([
    completion,
    waitAsync(limits.timeoutMilliseconds).then(() => 'timeout' as const),
  ]);
}

/*** Terminate the detached collector group, escalate once, and bound all reaping waits. */
async function terminateAndReapAsync(
  subprocess: Bun.Subprocess<'ignore', 'pipe', 'pipe'>,
): Promise<void> {
  sendProcessGroupSignal(subprocess.pid, 'SIGTERM');
  await waitForProcessGroupExitAsync(subprocess.pid, terminationGraceMilliseconds);
  if (processGroupExists(subprocess.pid)) {
    sendProcessGroupSignal(subprocess.pid, 'SIGKILL');
    await waitForProcessGroupExitAsync(subprocess.pid, reapTimeoutMilliseconds);
  }
  await Promise.race([subprocess.exited.then(() => undefined), waitAsync(reapTimeoutMilliseconds)]);
}

/*** Signal the isolated process group so shell children cannot survive a collector timeout or output breach. */
function sendProcessGroupSignal(processId: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-processId, signal);
  } catch {
    // The group can disappear between the existence check and signal delivery.
  }
}

/*** Check whether the detached process group still contains a running member without exposing host details. */
function processGroupExists(processId: number): boolean {
  try {
    process.kill(-processId, 0);
    return true;
  } catch {
    return false;
  }
}

/*** Poll boundedly for the process group to disappear after a termination signal. */
async function waitForProcessGroupExitAsync(
  processId: number,
  timeoutMilliseconds: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMilliseconds;
  while (processGroupExists(processId) && Date.now() < deadline) await waitAsync(10);
}

/*** Wait without retaining a timer after the lifecycle operation completes. */
async function waitAsync(milliseconds: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
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

/*** Reject non-finite or non-positive options so callers cannot disable lifecycle or stream bounds. */
function normalizeLimit(value: number | undefined, defaultValue: number): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
    ? value
    : defaultValue;
}

/*** Return a redacted failure result that no evidence collector can interpret as host state. */
function unavailableResult(stderr: string): CommandResult {
  return { exitCode: 1, stdout: '', stderr };
}
