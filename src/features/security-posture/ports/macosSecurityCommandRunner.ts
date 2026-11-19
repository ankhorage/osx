/*** A deliberately narrow process boundary for read-only, local macOS inspection commands. */
export interface MacosSecurityCommandRunner {
  readonly runAsync: (
    command: readonly string[],
    input?: { readonly signal?: AbortSignal },
  ) => Promise<{ readonly exitCode: number; readonly stdout: string; readonly stderr: string }>;
}
