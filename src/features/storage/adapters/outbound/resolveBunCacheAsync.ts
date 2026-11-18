import { lstat } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

/*** Resolve only understood Bun cache settings and reject paths outside dedicated user cache roots. */
export async function resolveBunCacheAsync(
  home: string,
  cwd: string,
  env: Readonly<Record<string, string | undefined>>,
): Promise<{ readonly path: string | null; readonly reason: string }> {
  if (!isAbsolute(home) || !isAbsolute(cwd) || home === '/')
    return { path: null, reason: 'home or working directory is not absolute' };
  const override = env.BUN_INSTALL_CACHE_DIR?.trim();
  if (!override) {
    const configBlocker = await findBunConfigAsync(home, cwd);
    if (configBlocker) return { path: null, reason: configBlocker };
  }
  const path = override ? resolve(cwd, override) : join(home, '.bun', 'install', 'cache');
  const roots = [
    join(home, '.bun', 'install', 'cache'),
    join(home, '.cache', 'bun'),
    join(home, 'Library', 'Caches', 'bun'),
  ];
  if (!roots.some((root) => within(root, path)))
    return { path: null, reason: 'configured cache is outside approved Bun cache roots' };
  return { path, reason: '' };
}

/*** Treat unknown Bun configuration as a blocker rather than guessing its cache location. */
async function findBunConfigAsync(home: string, cwd: string): Promise<string> {
  const paths = [join(home, '.bunfig.toml')];
  for (let cursor = cwd; ; cursor = dirname(cursor)) {
    paths.push(join(cursor, 'bunfig.toml'));
    if (dirname(cursor) === cursor) break;
  }
  for (const path of paths) {
    try {
      await lstat(path);
      return 'Bun configuration requires manual cache location verification';
    } catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT'))
        return 'Bun configuration is inaccessible';
    }
  }
  return '';
}

/*** Accept a cache root or a descendant without allowing sibling or parent traversal. */
function within(root: string, path: string): boolean {
  const part = relative(root, path);
  return part === '' || (!part.startsWith(`..${sep}`) && part !== '..' && !isAbsolute(part));
}
