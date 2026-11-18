import type {
  SecurityAuditEvidence,
  SecurityAuditObservation,
} from '../../../../types/securityAudit.js';

export type MacosHostSecurityCommandResult =
  | { readonly kind: 'completed'; readonly exitCode: number; readonly output: string }
  | { readonly kind: 'unknown' };

export type MacosHostSecurityCommandRunner = (
  executable: string,
  arguments_: readonly string[],
) => MacosHostSecurityCommandResult;

/*** Collect a small set of read-only macOS security facts without retaining command output or host identifiers. */
export function collectMacosHostSecurityObservations(
  runCommand: MacosHostSecurityCommandRunner = runReadOnlyCommand,
  collectedAt: string = new Date().toISOString(),
): readonly SecurityAuditObservation[] {
  return controls.map((control) => createObservation(control, runCommand, collectedAt));
}

interface SourceCheck {
  readonly executable: string;
  readonly arguments_: readonly string[];
  readonly factId: string;
  readonly evidenceId: string;
  readonly kind: string;
  readonly summary: string;
  readonly parse: (output: string) => boolean | undefined;
}

interface ControlCheck {
  readonly controlId: string;
  readonly sources: readonly SourceCheck[];
}

const controls: readonly ControlCheck[] = [
  {
    controlId: 'cross-layer-hardware-startup-trust',
    sources: [
      {
        executable: '/usr/bin/csrutil',
        arguments_: ['status'],
        factId: 'system-integrity-protection-enabled',
        evidenceId: 'sip-status',
        kind: 'csrutil-status',
        summary: 'System Integrity Protection status was observed with a read-only Apple utility.',
        parse: parseSystemIntegrityProtection,
      },
      {
        executable: '/usr/bin/csrutil',
        arguments_: ['authenticated-root', 'status'],
        factId: 'authenticated-root-enabled',
        evidenceId: 'authenticated-root-status',
        kind: 'csrutil-authenticated-root-status',
        summary: 'Authenticated Root status was observed with a read-only Apple utility.',
        parse: parseAuthenticatedRoot,
      },
    ],
  },
  control('cross-layer-disk-data', {
    executable: '/usr/bin/fdesetup',
    arguments_: ['status'],
    factId: 'filevault-enabled',
    evidenceId: 'filevault-status',
    kind: 'fdesetup-status',
    summary: 'FileVault status was observed with a read-only Apple utility.',
    parse: parseFileVault,
  }),
  control('cross-layer-identity-access', {
    executable: '/usr/sbin/sysadminctl',
    arguments_: ['-guestAccount', 'status'],
    factId: 'guest-account-disabled',
    evidenceId: 'guest-account-status',
    kind: 'sysadminctl-guest-account-status',
    summary: 'Guest-account policy status was observed without collecting account identities.',
    parse: parseGuestAccount,
  }),
  control('cross-layer-malware-integrity', {
    executable: '/usr/sbin/spctl',
    arguments_: ['--status'],
    factId: 'gatekeeper-assessments-enabled',
    evidenceId: 'gatekeeper-status',
    kind: 'spctl-status',
    summary: 'Gatekeeper assessment status was observed with a read-only Apple utility.',
    parse: parseGatekeeper,
  }),
  control('cross-layer-backups-resilience-logging', {
    executable: '/usr/bin/tmutil',
    arguments_: ['destinationinfo'],
    factId: 'time-machine-destination-reported',
    evidenceId: 'time-machine-destination-status',
    kind: 'tmutil-destinationinfo',
    summary:
      'Time Machine destination state was observed; it does not verify backup encryption or recovery.',
    parse: parseTimeMachineDestination,
  }),
  control('cross-layer-enterprise-policy', {
    executable: '/usr/bin/profiles',
    arguments_: ['status', '-type', 'enrollment'],
    factId: 'mdm-enrollment-reported',
    evidenceId: 'mdm-enrollment-status',
    kind: 'profiles-enrollment-status',
    summary: 'MDM enrollment state was observed; enrollment alone does not demonstrate compliance.',
    parse: parseMdmEnrollment,
  }),
];

/** Create a single control observation while retaining separately validated source evidence. */
function createObservation(
  control: ControlCheck,
  runCommand: MacosHostSecurityCommandRunner,
  collectedAt: string,
): SecurityAuditObservation {
  const sourceResults = control.sources.map((source) => ({
    source,
    result: runCommandSafely(source, runCommand),
  }));
  const permissionBlocked = sourceResults.filter(({ result }) => isPermissionBlocked(result));
  const evidence = sourceResults.flatMap(({ source, result }) =>
    createEvidence(source, result, control.controlId, collectedAt),
  );
  const allSourcesWereObserved = evidence.length === control.sources.length;
  return {
    controlId: control.controlId,
    applicability: allSourcesWereObserved ? 'applicable' : 'unknown',
    access:
      permissionBlocked.length === control.sources.length ? 'permission-blocked' : 'available',
    evidence,
  };
}

/** Run a fixed source command without allowing runner failures to abort the audit. */
function runCommandSafely(
  source: SourceCheck,
  runCommand: MacosHostSecurityCommandRunner,
): MacosHostSecurityCommandResult {
  try {
    const result: unknown = runCommand(source.executable, source.arguments_);
    return isCommandResult(result) ? result : { kind: 'unknown' };
  } catch {
    return { kind: 'unknown' };
  }
}

/** Accept only completed command results whose output can be safely parsed, or explicit unknowns. */
function isCommandResult(value: unknown): value is MacosHostSecurityCommandResult {
  if (!isRecord(value)) return false;
  if (value.kind === 'unknown') return true;
  return (
    value.kind === 'completed' &&
    typeof value.exitCode === 'number' &&
    Number.isInteger(value.exitCode) &&
    typeof value.output === 'string'
  );
}

/** Narrow an untrusted boundary value to a record before reading its fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Construct serializable evidence only from an explicitly recognized completed source result. */
function createEvidence(
  source: SourceCheck,
  result: MacosHostSecurityCommandResult,
  controlId: string,
  collectedAt: string,
): readonly SecurityAuditEvidence[] {
  if (result.kind !== 'completed' || result.exitCode !== 0) return [];
  const value = source.parse(result.output);
  if (value === undefined) return [];
  return [
    {
      id: source.evidenceId,
      controlId,
      profileId: 'macos-informational',
      baselineVersion: 'macos-informational-v1',
      kind: source.kind,
      summary: source.summary,
      collectedAt,
      redacted: true,
      facts: [{ id: source.factId, value }],
    },
  ];
}

/** Recognize an explicit access denial without retaining the protected command output. */
function isPermissionBlocked(result: MacosHostSecurityCommandResult): boolean {
  return (
    result.kind === 'completed' &&
    result.exitCode !== 0 &&
    /operation not permitted|permission denied|not authorized/iu.test(result.output)
  );
}

/** Parse an explicit SIP state while treating every other response as unknown. */
function parseSystemIntegrityProtection(output: string): boolean | undefined {
  return parseBooleanState(output, /System Integrity Protection status:\s*(enabled|disabled)\./iu);
}

/** Parse an explicit Authenticated Root state while treating every other response as unknown. */
function parseAuthenticatedRoot(output: string): boolean | undefined {
  return parseBooleanState(output, /Authenticated Root status:\s*(enabled|disabled)\./iu);
}

/** Parse an explicit FileVault state while treating every other response as unknown. */
function parseFileVault(output: string): boolean | undefined {
  return parseBooleanState(output, /FileVault is (On|Off)\./iu, 'on');
}

/** Parse an explicit guest-account state while treating every other response as unknown. */
function parseGuestAccount(output: string): boolean | undefined {
  return parseBooleanState(output, /Guest account is (enabled|disabled)\./iu, 'disabled');
}

/** Parse an explicit Gatekeeper state while treating every other response as unknown. */
function parseGatekeeper(output: string): boolean | undefined {
  return parseBooleanState(output, /assessments (enabled|disabled)/iu);
}

/** Parse a conclusive Time Machine destination state without treating blank output as a destination. */
function parseTimeMachineDestination(output: string): boolean | undefined {
  if (/No destinations configured/iu.test(output)) return false;
  return /^Name\s*:\s*\S+/imu.test(output) ? true : undefined;
}

/** Parse an explicit MDM enrollment state without mistaking enrollment for compliance. */
function parseMdmEnrollment(output: string): boolean | undefined {
  return parseBooleanState(output, /MDM enrollment:\s*(Yes|No)/iu, 'yes');
}

/** Convert a recognized two-state source value to a boolean while rejecting unrecognized output. */
function parseBooleanState(
  output: string,
  expression: RegExp,
  secureValue = 'enabled',
): boolean | undefined {
  const value = expression.exec(output)?.[1]?.toLowerCase();
  if (value === undefined) return undefined;
  return value === secureValue;
}

/** Create a control with exactly one independently validated command source. */
function control(controlId: string, source: SourceCheck): ControlCheck {
  return { controlId, sources: [source] };
}

/** Execute a fixed read-only Apple utility under bounded time and output limits. */
function runReadOnlyCommand(
  executable: string,
  arguments_: readonly string[],
): MacosHostSecurityCommandResult {
  try {
    const process = Bun.spawnSync([executable, ...arguments_], {
      stderr: 'pipe',
      stdout: 'pipe',
      timeout: 5_000,
      maxBuffer: 16 * 1024,
    });
    if (process.exitedDueToTimeout || process.exitedDueToMaxBuffer) return { kind: 'unknown' };
    return {
      kind: 'completed',
      exitCode: process.exitCode,
      output: `${process.stdout.toString()}${process.stderr.toString()}`,
    };
  } catch {
    return { kind: 'unknown' };
  }
}
