/** The host boundary keeps platform and process inventory injectable in tests. */
export interface BunCacheHost {
  readonly home: string;
  readonly cwd: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly platform: string;
  readonly currentPid: number;
  listProcesses(): Promise<string>;
  freeBytes(path: string): Promise<number | null>;
}
