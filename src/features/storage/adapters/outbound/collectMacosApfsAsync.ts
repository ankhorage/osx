/*** Obtain documented APFS and inode-accounting command output without changing the host. */
export async function collectMacosApfsAsync(): Promise<MacosApfsDiagnostics> {
  const [apfs, inodeAccounting, capacity] = await Promise.all([
    runAsync(['diskutil', 'apfs', 'list', '-plist']),
    runAsync(['df', '-i']),
    runAsync(['df', '-kP', '/']),
  ]);
  return { apfs, inodeAccounting, capacity: parseCapacity(capacity) };
}

export interface MacosApfsDiagnostics {
  readonly apfs: MacosCommandObservation;
  readonly inodeAccounting: MacosCommandObservation;
  readonly capacity: MacosCapacityObservation;
}

interface MacosCommandObservation {
  readonly status: 'available' | 'unavailable';
  readonly output: string | null;
}

export interface MacosCapacityObservation {
  readonly status: 'available' | 'unavailable';
  readonly allocatedBytes: number | null;
  readonly logicalBytes: null;
  readonly availableBytes: number | null;
  readonly snapshotBytes: null;
}

/*** Normalize live `df` capacity separately from logical size and APFS snapshot allocation. */
function parseCapacity(observation: MacosCommandObservation): MacosCapacityObservation {
  if (observation.status === 'unavailable' || !observation.output)
    return unavailableCapacity();
  const line = observation.output.trim().split('\n').at(-1);
  const fields = line?.trim().split(/\s+/);
  const allocatedBlocks = fields?.[2];
  const availableBlocks = fields?.[3];
  if (!allocatedBlocks || !availableBlocks) return unavailableCapacity();
  const allocatedBytes = Number(allocatedBlocks) * 1024;
  const availableBytes = Number(availableBlocks) * 1024;
  if (!Number.isSafeInteger(allocatedBytes) || !Number.isSafeInteger(availableBytes))
    return unavailableCapacity();
  return { status: 'available', allocatedBytes, logicalBytes: null, availableBytes, snapshotBytes: null };
}

/*** Preserve unavailable values instead of conflating a failed observation with zero capacity. */
function unavailableCapacity(): MacosCapacityObservation {
  return { status: 'unavailable', allocatedBytes: null, logicalBytes: null, availableBytes: null, snapshotBytes: null };
}

/*** Run a fixed read-only system command with a bounded output size. */
async function runAsync(command: readonly string[]): Promise<MacosCommandObservation> {
  try {
    const process = Bun.spawn({ cmd: [...command], stdout: 'pipe', stderr: 'pipe' });
    const [stdout, , exitCode] = await Promise.all([
      readOutputAsync(process.stdout, process),
      readOutputAsync(process.stderr, process),
      process.exited,
    ]);
    return exitCode === 0
      ? { status: 'available', output: stdout }
      : { status: 'unavailable', output: null };
  } catch {
    return { status: 'unavailable', output: null };
  }
}

/*** Drain both child streams while terminating output that exceeds the diagnostic memory budget. */
async function readOutputAsync(
  output: ReadableStream<Uint8Array>,
  process: ReturnType<typeof Bun.spawn>,
): Promise<string> {
  const reader = output.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      bytes += next.value.byteLength;
      if (bytes > 1_000_000) {
        process.kill('SIGKILL');
        return '';
      }
      chunks.push(next.value);
    }
    return new TextDecoder().decode(concatenate(chunks));
  } finally {
    reader.releaseLock();
  }
}

/*** Concatenate the bounded command chunks once after both streams have been drained. */
function concatenate(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.byteLength, 0));
  chunks.reduce((offset, chunk) => {
    output.set(chunk, offset);
    return offset + chunk.byteLength;
  }, 0);
  return output;
}
