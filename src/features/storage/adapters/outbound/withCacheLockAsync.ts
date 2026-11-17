import { constants } from 'node:fs';
import { mkdir, open, realpath, rmdir } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

/*** Serialize approved cleanup runs using a lock inside the verified cache parent. */
export async function withCacheLockAsync<T>(
  cache: string,
  operation: () => Promise<T>,
): Promise<T> {
  const parent = dirname(cache);
  if ((await realpath(parent)) !== resolve(parent))
    throw new Error('Cache parent is not canonical.');
  const handle = await open(
    parent,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const anchored = `/dev/fd/${handle.fd}`;
    if ((await realpath(anchored)) !== resolve(parent)) throw new Error('Cache parent changed.');
    const lock = join(anchored, `.${basename(cache)}.ankhorage-osx.lock`);
    await mkdir(lock, { mode: 0o700 });
    try {
      return await operation();
    } finally {
      await rmdir(lock);
    }
  } finally {
    await handle.close();
  }
}
