import { type BigIntStats, constants } from 'node:fs';
import { lstat, open, readdir, realpath, rmdir, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { inspectTreeAsync } from './inspectTreeAsync.js';

/*** Empty one approved cache while preserving its root and never following directory links. */
export async function emptyCacheAsync(
  root: string,
  approvedFingerprint: string,
  hooks: { beforeEntry?(path: string): Promise<void> } = {},
): Promise<void> {
  if (approvedFingerprint === '' || !root.startsWith('/') || root === '/') {
    throw new Error('Invalid cache selection.');
  }
  const inspected = await inspectTreeAsync(root, { requireWritable: true });
  if (
    inspected.fingerprint !== approvedFingerprint ||
    inspected.allocatedBytes === null ||
    !inspected.entriesByPath
  ) {
    throw new Error('Cache changed or could not be inspected.');
  }
  const before = await lstat(root, { bigint: true });
  if (inspected.entriesByPath.get(resolve(root)) !== fingerprint(before))
    throw new Error('Cache root changed.');
  const handle = await open(
    root,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const opened = await handle.stat({ bigint: true });
    if (fingerprint(opened) !== fingerprint(before)) throw new Error('Cache was replaced.');
    await assertRootAsync(handle.fd, root);
    await emptyDirectoryAsync(handle.fd, resolve(root), {
      rootFd: handle.fd,
      root: resolve(root),
      device: opened.dev,
      snapshot: inspected.entriesByPath,
      hooks,
    });
  } finally {
    await handle.close();
  }
}

interface CleanupContext {
  readonly rootFd: number;
  readonly root: string;
  readonly device: bigint;
  readonly snapshot: ReadonlyMap<string, string>;
  readonly hooks: { beforeEntry?(path: string): Promise<void> };
}

/*** Empty an already-open directory using names relative to its descriptor. */
async function emptyDirectoryAsync(
  fd: number,
  logicalDir: string,
  context: CleanupContext,
): Promise<void> {
  const parent = `/dev/fd/${fd}`;
  for (const name of (await readdir(parent)).sort()) {
    await context.hooks.beforeEntry?.(join(logicalDir, name));
    await assertRootAsync(context.rootFd, context.root);
    const child = join(parent, name);
    const entry = await lstat(child, { bigint: true });
    const logicalChild = join(logicalDir, name);
    if (
      context.snapshot.get(logicalChild) !== fingerprint(entry) ||
      !safeEntry(entry, context.device)
    )
      throw new Error('Cache entry is unsafe or changed.');
    if (entry.isDirectory()) await emptyChildAsync(child, logicalChild, entry, context);
    else await unlinkFileAsync(child, entry, context);
  }
}

/*** Reject links, shared files, mounts and unsupported filesystem entries. */
function safeEntry(entry: BigIntStats, device: bigint): boolean {
  return (
    entry.dev === device &&
    !entry.isSymbolicLink() &&
    (entry.isDirectory() || (entry.isFile() && entry.nlink === 1n))
  );
}

/*** Descend through a verified directory descriptor before removing the empty directory. */
async function emptyChildAsync(
  child: string,
  logicalChild: string,
  entry: BigIntStats,
  context: CleanupContext,
): Promise<void> {
  const handle = await open(
    child,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const opened = await handle.stat({ bigint: true });
    if (entry.dev !== opened.dev || entry.ino !== opened.ino)
      throw new Error('Cache directory changed.');
    await emptyDirectoryAsync(handle.fd, logicalChild, context);
    const latest = await lstat(child, { bigint: true });
    if (latest.dev !== opened.dev || latest.ino !== opened.ino || !latest.isDirectory())
      throw new Error('Cache directory was replaced.');
    await assertRootAsync(context.rootFd, context.root);
    await rmdir(child);
  } finally {
    await handle.close();
  }
}

/*** Check an approved regular file again before unlinking it without following links. */
async function unlinkFileAsync(
  child: string,
  entry: BigIntStats,
  context: CleanupContext,
): Promise<void> {
  const latest = await lstat(child, { bigint: true });
  if (fingerprint(latest) !== fingerprint(entry) || !latest.isFile() || latest.nlink !== 1n)
    throw new Error('Cache file changed.');
  await assertRootAsync(context.rootFd, context.root);
  await unlink(child);
}

/*** Refuse further changes if the opened cache moved or is no longer at its approved path. */
async function assertRootAsync(rootFd: number, root: string): Promise<void> {
  if ((await realpath(`/dev/fd/${rootFd}`)) !== resolve(root))
    throw new Error('Cache moved or was replaced.');
}

/*** Compare stable inode and mutation fields with the approved inspection. */
function fingerprint(entry: BigIntStats): string {
  return [entry.dev, entry.ino, entry.mode, entry.size, entry.mtimeNs, entry.ctimeNs].join(':');
}
