/** Local command output retained only until the collector produces redacted evidence. */
export interface SecurityNetworkCommandResult {
  readonly exitCode: number;
  readonly stdout: string;
}

/** Read-only host capability required by the OSI Layer 3 and 4 collector. */
export interface SecurityNetworkHost {
  readonly executeAsync: (command: readonly string[]) => Promise<SecurityNetworkCommandResult>;
  readonly now: () => string;
}
