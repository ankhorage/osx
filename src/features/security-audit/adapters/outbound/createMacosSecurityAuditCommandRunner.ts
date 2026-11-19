export type MacosSecurityAuditCommandResult =
  | { readonly kind: 'available'; readonly stdout: string }
  | { readonly kind: 'missing' }
  | { readonly kind: 'permission-denied' }
  | { readonly kind: 'timed-out' }
  | { readonly kind: 'failed' };

export interface MacosSecurityAuditCommandRunner {
  readonly platform: string;
  runAsync(
    command: string,
    arguments_: readonly string[],
    input?: { readonly signal?: AbortSignal; readonly timeoutMilliseconds?: number },
  ): Promise<MacosSecurityAuditCommandResult>;
}

/*** Create the bounded local command boundary for passive macOS security collectors. */
export function createMacosSecurityAuditCommandRunner(): MacosSecurityAuditCommandRunner {
  return {
    platform: process.platform,
    runAsync: (command, arguments_, input = {}) => runCommandAsync(command, arguments_, input),
  };
}

/*** Run one isolated read-only command and reap its process group for either local or audit-wide cancellation. */
async function runCommandAsync(
  command: string,
  arguments_: readonly string[],
  input: { readonly signal?: AbortSignal; readonly timeoutMilliseconds?: number },
): Promise<MacosSecurityAuditCommandResult> {
  if (input.signal?.aborted) return { kind: 'timed-out' };
  try {
    const subprocess = Bun.spawn({
      cmd: [command, ...arguments_],
      detached: true,
      stdin: 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const cancellationController = new AbortController();
    const cancel = () => cancellationController.abort();
    input.signal?.addEventListener('abort', cancel, { once: true });
    const timeout = setTimeout(cancel, input.timeoutMilliseconds ?? 2_000);
    const cancellation = waitForAbortAsync(cancellationController.signal);
    try {
      const completed = await Promise.race([
        Promise.all([
          subprocess.exited,
          readOutputAsync(subprocess.stdout),
          readOutputAsync(subprocess.stderr),
        ]),
        cancellation,
      ]);
      if (completed === 'aborted') {
        await terminateAndReapAsync(subprocess);
        return { kind: 'timed-out' };
      }
      const [exitCode, stdout, stderr] = completed;
      if (exitCode === 0) return { kind: 'available', stdout };
      return /permission denied|operation not permitted/i.test(stderr)
        ? { kind: 'permission-denied' }
        : { kind: 'failed' };
    } catch {
      await terminateAndReapAsync(subprocess);
      return { kind: 'failed' };
    } finally {
      clearTimeout(timeout);
      input.signal?.removeEventListener('abort', cancel);
    }
  } catch (error) {
    return spawnFailure(error);
  }
}

/*** Resolve immediately on audit-wide cancellation without leaving an abort listener behind. */
function waitForAbortAsync(signal: AbortSignal | undefined): Promise<'aborted'> {
  if (!signal) return new Promise(() => undefined);
  if (signal.aborted) return Promise.resolve('aborted');
  return new Promise((resolve) =>
    signal.addEventListener('abort', () => resolve('aborted'), { once: true }),
  );
}

/*** Read bounded public-command output; failures deliberately retain no output in the audit report. */
async function readOutputAsync(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) return new TextDecoder().decode(concatenate(chunks));
      bytes += next.value.byteLength;
      if (bytes > 1_000_000) throw new Error('Command output exceeded its bound.');
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
}

/*** Combine only bounded chunks after a command exits. */
function concatenate(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((size, chunk) => size + chunk.byteLength, 0));
  chunks.reduce((offset, chunk) => {
    output.set(chunk, offset);
    return offset + chunk.byteLength;
  }, 0);
  return output;
}

/*** Terminate a detached group and await the direct child so no collector process survives cancellation. */
async function terminateAndReapAsync(
  subprocess: Bun.Subprocess<'ignore', 'pipe', 'pipe'>,
): Promise<void> {
  for (const signal of ['SIGTERM', 'SIGKILL'] as const) {
    try {
      process.kill(-subprocess.pid, signal);
    } catch {
      // A completed group needs no further cleanup.
    }
    await Promise.race([subprocess.exited.then(() => undefined), waitAsync(100)]);
  }
}

/*** Bound reaping waits even for a faulty local subprocess implementation. */
async function waitAsync(milliseconds: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

/*** Map startup failure to an explicit non-evidence source state. */
function spawnFailure(
  error: unknown,
): Exclude<MacosSecurityAuditCommandResult, { readonly kind: 'available' }> {
  return error instanceof Error && /ENOENT|not found|no such file/i.test(error.message)
    ? { kind: 'missing' }
    : { kind: 'failed' };
}
