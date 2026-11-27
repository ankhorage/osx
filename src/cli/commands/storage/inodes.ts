import { realpath } from 'node:fs/promises';

import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { inventoryInodesAsync } from '../../../features/storage/application/inventoryInodesAsync.js';

/*** Render a bounded, read-only inode inventory for one accessible filesystem subtree. */
export async function inodes(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  const parsed = parseArguments(request.argv);
  if (!parsed) {
    request.context.writeStderr('Usage: ankh osx storage inodes [--path <path>] [--top <number>] [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Inode inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  try {
    const inventory = await inventoryInodesAsync(await realpath(parsed.path ?? request.context.cwd), parsed.top);
    request.context.writeStdout(parsed.json ? `${JSON.stringify(inventory, null, 2)}\n` : render(inventory));
    return { exitCode: 0 };
  } catch (error) {
    request.context.writeStderr(`Inode inspection failed: ${error instanceof Error ? error.message : String(error)}\n`);
    return { exitCode: 1 };
  }
}

/*** Parse only the documented diagnostic flags, avoiding ambiguous path selection. */
function parseArguments(argv: readonly string[]): { readonly path?: string; readonly top: number; readonly json: boolean } | null {
  const state: { path?: string; top: number; json: boolean } = { top: 20, json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--json' && !state.json) { state.json = true; continue; }
    const value = argv[index + 1];
    if ((argument === '--path' || argument === '--top') && value) {
      if (argument === '--path' && !state.path) state.path = value;
      if (argument === '--top' && /^\d+$/.test(value) && Number(value) > 0) state.top = Number(value);
      else if (argument === '--top') return null;
      index += 1;
      continue;
    }
    return null;
  }
  return state;
}

/*** Render inode identities distinctly from entry counts and inaccessible coverage. */
function render(inventory: Awaited<ReturnType<typeof inventoryInodesAsync>>): string {
  return `Entries: ${inventory.entries}; distinct inodes: ${inventory.distinctInodes ?? 'unknown (memory limit)'}; files: ${inventory.files}; directories: ${inventory.directories}; symlinks not followed: ${inventory.symlinks}; inaccessible: ${inventory.inaccessible}; coverage: ${inventory.limited ? 'partial (entry limit)' : 'complete'}\n`;
}
