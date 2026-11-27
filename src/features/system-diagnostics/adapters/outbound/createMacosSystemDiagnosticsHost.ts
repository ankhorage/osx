import type { SystemDiagnosticsHost } from '../../../../types/systemDiagnostics.js';

const outputLimit = 1_000_000;

/*** Create the bounded local process adapter for fixed read-only diagnostic commands. */
export function createMacosSystemDiagnosticsHost(): SystemDiagnosticsHost {
  return { platform: process.platform, runAsync: runAsync };
}

/*** Run one fixed diagnostic command and classify inaccessible and unavailable host evidence. */
async function runAsync(command: readonly string[]) {
  if (process.platform !== 'darwin')
    return { exitCode: null, output: '', status: 'unsupported' as const };
  try {
    const processHandle = Bun.spawn({ cmd: [...command], stdout: 'pipe', stderr: 'pipe' });
    const [stdout, stderr, exitCode] = await Promise.all([
      readBoundedAsync(processHandle.stdout, processHandle),
      readBoundedAsync(processHandle.stderr, processHandle),
      processHandle.exited,
    ]);
    const output = `${stdout}${stderr}`;
    if (exitCode === 0) return { exitCode, output, status: 'available' as const };
    if (/not permitted|permission denied/i.test(output))
      return { exitCode, output, status: 'permission-denied' as const };
    if (/not found|no such file|unknown command/i.test(output))
      return { exitCode, output, status: 'unsupported' as const };
    return { exitCode, output, status: 'failed' as const };
  } catch (error) {
    return {
      exitCode: null,
      output: '',
      status: isMissingCommand(error) ? ('unsupported' as const) : ('failed' as const),
    };
  }
}

/*** Read bounded command output and stop its child before a full pipe can deadlock collection. */
async function readBoundedAsync(
  stream: ReadableStream<Uint8Array>,
  processHandle: ReturnType<typeof Bun.spawn>,
): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = next.value.slice(0, Math.min(next.value.byteLength, outputLimit - size));
      chunks.push(chunk);
      size += chunk.byteLength;
      if (size >= outputLimit) {
        processHandle.kill();
        await reader.cancel();
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder().decode(concatenate(chunks, size));
}

/*** Concatenate finite command chunks once after the output limit has been enforced. */
function concatenate(chunks: readonly Uint8Array[], size: number): Uint8Array {
  const output = new Uint8Array(size);
  chunks.reduce((offset, chunk) => {
    output.set(chunk, offset);
    return offset + chunk.byteLength;
  }, 0);
  return output;
}

/*** Recognize a missing executable without reclassifying an ordinary command failure. */
function isMissingCommand(error: unknown): boolean {
  return error instanceof Error && /ENOENT|not found|no such file/i.test(error.message);
}
