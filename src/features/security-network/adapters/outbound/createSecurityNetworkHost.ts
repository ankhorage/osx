import type { SecurityNetworkHost } from '../../ports/securityNetworkHost.js';

/*** Create the macOS read-only process adapter used by the network-security collector. */
export function createSecurityNetworkHost(): SecurityNetworkHost {
  return {
    executeAsync: async (command) => {
      try {
        const process = Bun.spawn({ cmd: [...command], stdout: 'pipe', stderr: 'pipe' });
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(process.stdout).text(),
          new Response(process.stderr).text(),
          process.exited,
        ]);
        return { exitCode, stdout: `${stdout}\n${stderr}` };
      } catch {
        return { exitCode: 127, stdout: '' };
      }
    },
    now: () => new Date().toISOString(),
  };
}
