import type { AnkhRuntimeCommandProvider } from '@ankhorage/ankh';
import type { Capability } from '@ankhorage/contracts/capability';

import packageJson from '../../package.json';
import { clean } from './commands/storage/clean.js';
import { clean as cleanOrphans } from './commands/storage/orphans/clean.js';
import { scan as scanOrphans } from './commands/storage/orphans/scan.js';
import { scan } from './commands/storage/scan.js';

const capabilities = [
  {
    id: 'osx.storage.clean',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'Clean storage',
  },
  {
    id: 'osx.storage.scan',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'Inspect storage',
  },
  {
    id: 'osx.storage.orphans.scan',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'Inspect orphaned application remnants',
  },
  {
    id: 'osx.storage.orphans.clean',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'Move verified orphaned application remnants to Trash',
  },
] as const satisfies readonly Capability[];

const provider = {
  id: '@ankhorage/osx',
  category: 'osx',
  version: packageJson.version,
  capabilities,
  commands: [
    { path: ['storage', 'scan'], capability: 'osx.storage.scan', summary: 'Inspect user storage.' },
    {
      path: ['storage', 'clean'],
      capability: 'osx.storage.clean',
      summary: 'Clean selected caches after confirmation.',
    },
    {
      path: ['storage', 'orphans', 'scan'],
      capability: 'osx.storage.orphans.scan',
      summary: 'Inspect orphaned application remnants.',
    },
    {
      path: ['storage', 'orphans', 'clean'],
      capability: 'osx.storage.orphans.clean',
      summary: 'Move selected verified application remnants to Trash.',
    },
  ],
  handlers: [
    { path: ['storage', 'scan'], handler: scan },
    { path: ['storage', 'clean'], handler: clean },
    { path: ['storage', 'orphans', 'scan'], handler: scanOrphans },
    { path: ['storage', 'orphans', 'clean'], handler: cleanOrphans },
  ],
} satisfies AnkhRuntimeCommandProvider;

export default provider;
