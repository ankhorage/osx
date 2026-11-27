import { lstat, opendir } from 'node:fs/promises';
import { join } from 'node:path';

/*** Count accessible filesystem entries without following links or crossing the selected filesystem. */
export async function inventoryInodesAsync(root: string, top = 20): Promise<InodeInventory> {
  const rootStat = await lstat(root, { bigint: true });
  const state: InventoryState = {
    device: rootStat.dev,
    inaccessible: 0,
    entries: 0,
    files: 0,
    directories: 0,
    symlinks: 0,
    identities: new Set(),
    subtrees: new Map(),
    identityComplete: true,
    limited: false,
  };
  await inspectAsync(root, root, root, state);
  return {
    root,
    entries: state.entries,
    files: state.files,
    directories: state.directories,
    symlinks: state.symlinks,
    distinctInodes: state.identityComplete ? state.identities.size : null,
    inaccessible: state.inaccessible,
    limited: state.limited,
    topSubtrees: [...state.subtrees.entries()]
      .map(([path, entries]) => ({ path, entries }))
      .filter((subtree) => subtree.path !== root)
      .sort((left, right) => right.entries - left.entries || left.path.localeCompare(right.path))
      .slice(0, top),
  };
}

export interface InodeInventory {
  readonly root: string;
  readonly entries: number;
  readonly files: number;
  readonly directories: number;
  readonly symlinks: number;
  readonly distinctInodes: number | null;
  readonly inaccessible: number;
  readonly limited: boolean;
  readonly topSubtrees: readonly { readonly path: string; readonly entries: number }[];
}

interface InventoryState {
  readonly device: bigint;
  inaccessible: number;
  entries: number;
  files: number;
  directories: number;
  symlinks: number;
  readonly identities: Set<string>;
  readonly subtrees: Map<string, number>;
  identityComplete: boolean;
  limited: boolean;
}

/*** Inspect one path while retaining inaccessible paths as explicit coverage gaps. */
async function inspectAsync(
  path: string,
  root: string,
  subtree: string,
  state: InventoryState,
): Promise<void> {
  try {
    if (state.entries >= 100_000) {
      state.limited = true;
      return;
    }
    const entry = await lstat(path, { bigint: true });
    if (entry.dev !== state.device) return;
    state.entries += 1;
    state.subtrees.set(subtree, (state.subtrees.get(subtree) ?? 0) + 1);
    if (state.identities.size < 100_000) state.identities.add(`${entry.dev}:${entry.ino}`);
    else state.identityComplete = false;
    if (entry.isSymbolicLink()) {
      state.symlinks += 1;
      return;
    }
    if (entry.isFile()) {
      state.files += 1;
      return;
    }
    if (!entry.isDirectory()) return;
    state.directories += 1;
    const directory = await opendir(path);
    for await (const childEntry of directory) {
      const child = join(path, childEntry.name);
      await inspectAsync(child, root, path === root ? child : subtree, state);
      if (state.limited) return;
    }
  } catch {
    state.inaccessible += 1;
  }
}
