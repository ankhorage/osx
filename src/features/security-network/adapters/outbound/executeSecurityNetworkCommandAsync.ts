import type {
  SecurityNetworkCommandResult,
  SecurityNetworkCommandStatus,
} from '../../ports/securityNetworkHost.js';

const defaultCommandTimeoutMs = 10_000;
const defaultOutputLimitBytes = 1_000_000;

/*** Execute one fixed passive command with bounded time, memory, and forced cancellation. */
export async function executeSecurityNetworkCommandAsync(
  command: readonly string[],
  limits: {
    readonly timeoutMs?: number;
    readonly outputLimitBytes?: number;
    readonly signal?: AbortSignal;
  } = {},
): Promise<SecurityNetworkCommandResult> {
  try {
    const process = Bun.spawn({ cmd: [...command], stdout: 'pipe', stderr: 'pipe' });
    const state = createCommandState(process, limits);
    const stopForAbort = () => state.stop('timeout');
    limits.signal?.addEventListener('abort', stopForAbort, { once: true });
    const timer = setTimeout(() => state.stop('timeout'), state.timeoutMs);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        readOutputAsync(process.stdout, state),
        readOutputAsync(process.stderr, state),
        process.exited,
      ]);
      return {
        exitCode,
        stdout: `${stdout}${stderr}`,
        status: state.status ?? statusFor(exitCode, `${stdout}${stderr}`),
      };
    } catch {
      state.stop('failed');
      return { exitCode: null, stdout: '', status: 'failed' };
    } finally {
      clearTimeout(timer);
      limits.signal?.removeEventListener('abort', stopForAbort);
    }
  } catch (error) {
    return { exitCode: null, stdout: '', status: spawnFailureStatus(error) };
  }
}

/** Track one process-wide output budget and the first reason its command was stopped. */
function createCommandState(
  process: ReturnType<typeof Bun.spawn>,
  limits: {
    readonly timeoutMs?: number;
    readonly outputLimitBytes?: number;
    readonly signal?: AbortSignal;
  },
): {
  readonly outputLimitBytes: number;
  readonly status: SecurityNetworkCommandStatus | undefined;
  readonly timeoutMs: number;
  readonly stop: (
    status: Extract<SecurityNetworkCommandStatus, 'failed' | 'output-limited' | 'timeout'>,
  ) => void;
  readonly take: (bytes: number) => number;
} {
  let bytes = 0;
  let status: SecurityNetworkCommandStatus | undefined;
  const timeoutMs = limits.timeoutMs ?? defaultCommandTimeoutMs;
  const outputLimitBytes = limits.outputLimitBytes ?? defaultOutputLimitBytes;
  const stop = (
    nextStatus: Extract<SecurityNetworkCommandStatus, 'failed' | 'output-limited' | 'timeout'>,
  ) => {
    if (status) return;
    status = nextStatus;
    process.kill('SIGKILL');
  };
  return {
    outputLimitBytes,
    get status() {
      return status;
    },
    timeoutMs,
    stop,
    take: (length) => {
      const available = Math.max(outputLimitBytes - bytes, 0);
      bytes += Math.min(length, available);
      if (length > available) stop('output-limited');
      return Math.min(length, available);
    },
  };
}

/** Classify a process that could not be started without misreporting a missing command as a timeout. */
function spawnFailureStatus(
  error: unknown,
): Extract<SecurityNetworkCommandStatus, 'failed' | 'unsupported'> {
  return error instanceof Error && /ENOENT|not found|no such file/i.test(error.message)
    ? 'unsupported'
    : 'failed';
}

/** Consume a process stream only up to the shared command output limit. */
async function readOutputAsync(
  output: ReadableStream<Uint8Array>,
  state: ReturnType<typeof createCommandState>,
): Promise<string> {
  const reader = output.getReader();
  const chunks: Uint8Array[] = [];
  const readNextAsync = async (): Promise<void> => {
    const next = await reader.read();
    if (next.done) return;
    const length = state.take(next.value.byteLength);
    if (length > 0) chunks.push(next.value.slice(0, length));
    if (length < next.value.byteLength) {
      await reader.cancel();
      return;
    }
    return readNextAsync();
  };
  try {
    await readNextAsync();
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder().decode(concatenate(chunks));
}

/** Concatenate bounded output chunks once so no command stream is buffered without a limit. */
function concatenate(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.byteLength, 0));
  chunks.reduce((offset, chunk) => {
    output.set(chunk, offset);
    return offset + chunk.byteLength;
  }, 0);
  return output;
}

/** Classify a completed command without treating a nonzero exit as an empty observation. */
function statusFor(exitCode: number, output: string): SecurityNetworkCommandStatus {
  if (exitCode === 0) return 'completed';
  if (/operation not permitted|permission denied|not permitted/i.test(output))
    return 'permission-denied';
  if (exitCode === 127 || /command not found|no such file or directory/i.test(output))
    return 'unsupported';
  return 'failed';
}
