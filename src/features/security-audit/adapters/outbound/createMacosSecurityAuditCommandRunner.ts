import { execFileSync } from 'node:child_process';

import type { MacosSecurityAuditCommandRunner } from './collectMacosPhysicalAndLinkObservations.js';

/*** Create the bounded local command boundary for passive macOS security collectors. */
export function createMacosSecurityAuditCommandRunner(): MacosSecurityAuditCommandRunner {
  return {
    platform: process.platform,
    run(command, arguments_) {
      try {
        return {
          kind: 'available',
          stdout: execFileSync(command, arguments_, {
            encoding: 'utf8',
            timeout: 10_000,
            maxBuffer: 1_000_000,
            stdio: ['ignore', 'pipe', 'ignore'],
            windowsHide: true,
          }),
        };
      } catch {
        return { kind: 'unavailable' };
      }
    },
  };
}
