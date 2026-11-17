import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { join } from 'node:path';

/*** Inspect allocated bytes without following links or crossing filesystems; incomplete trees are blocked. */
export async function inspectTreeAsync(root: string): Promise<TreeInspection> {
  try {
    const rootStat = await lstat(root, { bigint: true });
    if ((await realpath(root)) !== resolve(root)) {
      return { allocatedBytes: null, blockers: ['symbolic link in path'], fingerprint: null };
    }
    const state: InspectionState = {
      device: rootStat.dev,
      inodes: new Set<string>(),
      hash: createHash('sha256'),
      bytes: 0n,
      entries: 0,
      blockers: new Set<string>(),
    };
    await inspectEntryAsync(root, root, rootStat, state);
    const max = BigInt(Number.MAX_SAFE_INTEGER);
    if (state.bytes > max) state.blockers.add('allocated size exceeds safe integer range');
    return {
      allocatedBytes: state.blockers.size === 0 ? Number(state.bytes) : null,
      blockers: [...state.blockers].sort(),
      fingerprint: state.blockers.size === 0 ? state.hash.digest('hex') : null,
    };
  } catch (error) {
    return { allocatedBytes: null, blockers: [describeError(error)], fingerprint: null };
  }
}

type Stat = Awaited<ReturnType<typeof bigintStatAsync>>;
interface InspectionState {
  readonly device: bigint;
  readonly inodes: Set<string>;
  readonly hash: ReturnType<typeof createHash>;
  bytes: bigint;
  entries: number;
  readonly blockers: Set<string>;
}
interface TreeInspection {
  readonly allocatedBytes: number | null;
  readonly blockers: readonly string[];
  readonly fingerprint: string | null;
}

/*** Obtain bigint metadata so filesystem identifiers and allocated size remain precise. */
async function bigintStatAsync(path: string) {
  return await lstat(path, { bigint: true });
}

/*** Walk a single entry without following links or silently ignoring failed reads. */
async function inspectEntryAsync(
  path: string,
  logicalPath: string,
  entry: Stat,
  state: InspectionState,
): Promise<void> {
  state.entries += 1;
  if (state.entries > 100_000) {
    state.blockers.add('inspection entry limit exceeded');
    return;
  }
  if (entry.isSymbolicLink()) {
    state.blockers.add('symbolic link');
    return;
  }
  if (entry.dev !== state.device) {
    state.blockers.add('filesystem boundary');
    return;
  }
  if (!entry.isFile() && !entry.isDirectory()) {
    state.blockers.add('special file');
    return;
  }
  if (entry.isFile() && entry.nlink > 1n) state.blockers.add('hard-linked file');
  state.hash.update(
    JSON.stringify([logicalPath, fingerprint(entry), String(entry.nlink), String(entry.blocks)]),
  );
  const key = `${entry.dev}:${entry.ino}`;
  if (state.inodes.has(key)) return;
  state.inodes.add(key);
  state.bytes += entry.blocks * 512n;
  if (!entry.isDirectory()) return;
  await inspectDirectoryAsync(path, logicalPath, entry, state);
}

/*** Traverse an opened directory through its descriptor, rejecting replacement races. */
async function inspectDirectoryAsync(
  path: string,
  logicalPath: string,
  entry: Stat,
  state: InspectionState,
): Promise<void> {
  try {
    const handle = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      const opened = await handle.stat({ bigint: true });
      if (opened.dev !== entry.dev || opened.ino !== entry.ino) {
        state.blockers.add('tree changed during inspection');
        return;
      }
      const anchored = `/dev/fd/${handle.fd}`;
      const names = (await readdir(anchored)).sort();
      for (const name of names) {
        if (state.entries >= 100_000) {
          state.blockers.add('inspection entry limit exceeded');
          break;
        }
        const child = join(anchored, name);
        await inspectEntryAsync(
          child,
          join(logicalPath, name),
          await bigintStatAsync(child),
          state,
        );
      }
      const after = await handle.stat({ bigint: true });
      if (fingerprint(entry) !== fingerprint(after))
        state.blockers.add('tree changed during inspection');
    } finally {
      await handle.close();
    }
  } catch (error) {
    state.blockers.add(describeError(error));
  }
}

/*** Capture identity and mutation metadata without relying on path names. */
function fingerprint(entry: Stat): string {
  return [entry.dev, entry.ino, entry.mode, entry.size, entry.mtimeNs, entry.ctimeNs].join(':');
}

/*** Reduce system failures to a stable diagnostic without hiding inaccessible content. */
function describeError(error: unknown): string {
  if (error instanceof Error && 'code' in error && typeof error.code === 'string')
    return error.code;
  return 'inspection failed';
}
