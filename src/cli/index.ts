import type { AnkhRuntimeCommandProvider } from '@ankhorage/ankh';
import type { Capability } from '@ankhorage/contracts/capability';

import packageJson from '../../package.json';
import { status as backupStatus } from './commands/backup/status.js';
import { list as listSnapshots } from './commands/backup/snapshots/list.js';
import { audit } from './commands/security/audit.js';
import { list } from './commands/security/controls/list.js';
import { clean } from './commands/storage/clean.js';
import { scan as scanOrphans } from './commands/storage/orphans/scan.js';
import { scan } from './commands/storage/scan.js';
import { scan as scanXcode } from './commands/storage/xcode/scan.js';

const capabilities = [
  {
    id: 'osx.backup.status',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'Inspect Time Machine status',
  },
  {
    id: 'osx.backup.snapshots.list',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'List APFS snapshots',
  },
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
    id: 'osx.security.audit',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'Audit macOS security posture',
  },
  {
    id: 'osx.security.controls.list',
    owner: '@ankhorage/osx',
    access: ['invoke'],
    binding: { kind: 'action', bindableAs: ['target'] },
    label: 'List macOS security controls',
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
      path: ['security', 'audit'],
      capability: 'osx.security.audit',
      summary: 'Report the read-only security-audit coverage and results.',
    },
    {
      path: ['security', 'controls', 'list'],
      capability: 'osx.security.controls.list',
      summary: 'List the security-audit control catalog.',
    },
    {
      path: ['storage', 'xcode', 'scan'],
      capability: 'osx.storage.scan',
      summary: 'Inspect Xcode Simulator runtimes.',
    },
    {
      path: ['backup', 'status'],
      capability: 'osx.backup.status',
      summary: 'Inspect Time Machine status.',
    },
    {
      path: ['backup', 'snapshots', 'list'],
      capability: 'osx.backup.snapshots.list',
      summary: 'List APFS snapshot counts.',
    },
  ],
  handlers: [
    { path: ['storage', 'scan'], handler: scan },
    { path: ['storage', 'clean'], handler: clean },
    { path: ['storage', 'orphans', 'scan'], handler: scanOrphans },
    { path: ['security', 'audit'], handler: audit },
    { path: ['security', 'controls', 'list'], handler: list },
    { path: ['storage', 'xcode', 'scan'], handler: scanXcode },
    { path: ['backup', 'status'], handler: backupStatus },
    { path: ['backup', 'snapshots', 'list'], handler: listSnapshots },
  ],
} satisfies AnkhRuntimeCommandProvider;

export default provider;
