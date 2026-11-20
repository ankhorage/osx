import type {
  SecurityAuditEvidence,
  SecurityAuditObservation,
  SecurityAuditProfile,
  SecurityAuditSourceProvenance,
} from '../../../../types/securityAudit.js';
import type {
  MacosSecurityAuditCommandResult,
  MacosSecurityAuditCommandRunner,
} from './createMacosSecurityAuditCommandRunner.js';

interface CollectorInput {
  readonly runner: MacosSecurityAuditCommandRunner;
  readonly profile: SecurityAuditProfile;
  readonly collectedAt: string;
  readonly controlIds?: ReadonlySet<string>;
  readonly signal?: AbortSignal;
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

/*** Collect passive, redacted host-security observations without asserting a security baseline. */
export async function collectMacosHostSecurityObservationsAsync(
  input: CollectorInput,
): Promise<readonly SecurityAuditObservation[]> {
  if (input.runner.platform !== 'darwin') return unsupportedPlatformObservations(input);
  const selected = controls.filter(
    (controlCheck) => input.controlIds?.has(controlCheck.controlId) ?? true,
  );
  const observations: SecurityAuditObservation[] = [];
  for (const controlCheck of selected) {
    if (input.signal?.aborted) break;
    observations.push(await createObservationAsync(controlCheck, input));
  }
  return observations;
}

const controls: readonly ControlCheck[] = [
  {
    controlId: 'cross-layer-hardware-startup-trust',
    sources: [
      source(
        '/usr/bin/csrutil',
        ['status'],
        'system-integrity-protection-enabled',
        'sip-status',
        'csrutil-status',
        'System Integrity Protection status was observed with a read-only Apple utility.',
        (output) =>
          parseBooleanState(output, /System Integrity Protection status:\s*(enabled|disabled)\./iu),
      ),
      source(
        '/usr/bin/csrutil',
        ['authenticated-root', 'status'],
        'authenticated-root-enabled',
        'authenticated-root-status',
        'csrutil-authenticated-root-status',
        'Authenticated Root status was observed with a read-only Apple utility.',
        (output) =>
          parseBooleanState(output, /Authenticated Root status:\s*(enabled|disabled)\./iu),
      ),
    ],
  },
  control(
    'cross-layer-disk-data',
    source(
      '/usr/bin/fdesetup',
      ['status'],
      'filevault-enabled',
      'filevault-status',
      'fdesetup-status',
      'FileVault status was observed with a read-only Apple utility.',
      (output) => parseBooleanState(output, /FileVault is (On|Off)\./iu, 'on'),
    ),
  ),
  control(
    'cross-layer-identity-access',
    source(
      '/usr/sbin/sysadminctl',
      ['-guestAccount', 'status'],
      'guest-account-disabled',
      'guest-account-status',
      'sysadminctl-guest-account-status',
      'Guest-account policy status was observed without collecting account identities.',
      (output) => parseBooleanState(output, /Guest account is (enabled|disabled)\./iu, 'disabled'),
    ),
  ),
  control(
    'cross-layer-malware-integrity',
    source(
      '/usr/sbin/spctl',
      ['--status'],
      'gatekeeper-assessments-enabled',
      'gatekeeper-status',
      'spctl-status',
      'Gatekeeper assessment status was observed with a read-only Apple utility.',
      (output) => parseBooleanState(output, /assessments (enabled|disabled)/iu),
    ),
  ),
  control(
    'cross-layer-backups-resilience-logging',
    source(
      '/usr/bin/tmutil',
      ['destinationinfo'],
      'time-machine-destination-reported',
      'time-machine-destination-status',
      'tmutil-destinationinfo',
      'Time Machine destination state was observed; it does not verify backup encryption or recovery.',
      parseTimeMachineDestination,
    ),
  ),
  control(
    'cross-layer-enterprise-policy',
    source(
      '/usr/bin/profiles',
      ['status', '-type', 'enrollment'],
      'mdm-enrollment-reported',
      'mdm-enrollment-status',
      'profiles-enrollment-status',
      'MDM enrollment state was observed; enrollment alone does not demonstrate compliance.',
      (output) => parseBooleanState(output, /MDM enrollment:\s*(Yes|No)/iu, 'yes'),
    ),
  ),
];

/** Create one source definition that holds command-specific parsing at the outer adapter boundary. */
function source(
  executable: string,
  arguments_: readonly string[],
  factId: string,
  evidenceId: string,
  kind: string,
  summary: string,
  parse: (output: string) => boolean | undefined,
): SourceCheck {
  return { executable, arguments_, factId, evidenceId, kind, summary, parse };
}

/** Create a single-source control definition. */
function control(controlId: string, sourceCheck: SourceCheck): ControlCheck {
  return { controlId, sources: [sourceCheck] };
}

/** Create one control observation while retaining separate evidence for independent source checks. */
async function createObservationAsync(
  controlCheck: ControlCheck,
  input: CollectorInput,
): Promise<SecurityAuditObservation> {
  const sourceResults = await Promise.all(
    controlCheck.sources.map(async (sourceCheck) => ({
      sourceCheck,
      result: await runCommandSafelyAsync(input.runner, sourceCheck, input.signal),
    })),
  );
  const evidence = sourceResults.flatMap(({ sourceCheck, result }) =>
    createEvidence(sourceCheck, result, controlCheck.controlId, input),
  );
  const sources = sourceResults.map(({ sourceCheck, result }) =>
    createSourceProvenance(sourceCheck, result, evidence),
  );
  const access = sourceAccess(sourceResults.map(({ result }) => result));
  return {
    controlId: controlCheck.controlId,
    applicability:
      evidence.length === controlCheck.sources.length && access === 'available'
        ? 'applicable'
        : 'unknown',
    access,
    evidence,
    sources,
  };
}

/** Run one fixed local command without allowing process failures to escape the collector boundary. */
async function runCommandSafelyAsync(
  runner: MacosSecurityAuditCommandRunner,
  sourceCheck: SourceCheck,
  signal: AbortSignal | undefined,
): Promise<MacosSecurityAuditCommandResult> {
  if (signal?.aborted) return { kind: 'timed-out' };
  try {
    return await runner.runAsync(sourceCheck.executable, sourceCheck.arguments_, { signal });
  } catch {
    return { kind: 'failed' };
  }
}

/** Preserve explicit access limitations so the engine reports incomplete or inaccessible evidence. */
function sourceAccess(
  results: readonly MacosSecurityAuditCommandResult[],
): SecurityAuditObservation['access'] {
  if (results.every((result) => result.kind === 'permission-denied')) return 'permission-blocked';
  return results.every((result) => result.kind === 'available') ? 'available' : 'incomplete';
}

/** Construct serializable evidence only from explicitly recognized available command output. */
function createEvidence(
  sourceCheck: SourceCheck,
  result: MacosSecurityAuditCommandResult,
  controlId: string,
  input: CollectorInput,
): readonly SecurityAuditEvidence[] {
  if (result.kind !== 'available') return [];
  const value = sourceCheck.parse(result.stdout);
  if (value === undefined) return [];
  return [
    {
      id: sourceCheck.evidenceId,
      sourceId: sourceIdFor(sourceCheck),
      controlId,
      profileId: input.profile.id,
      baselineVersion: input.profile.baseline,
      kind: sourceCheck.kind,
      summary: sourceCheck.summary,
      collectedAt: input.collectedAt,
      redacted: true,
      facts: [{ id: sourceCheck.factId, value }],
    },
  ];
}

/** Return non-applicability without invoking macOS binaries on another platform. */
function unsupportedPlatformObservations(
  input: CollectorInput,
): readonly SecurityAuditObservation[] {
  return controls.map((controlCheck) => ({
    controlId: controlCheck.controlId,
    applicability: 'not-applicable',
    access: 'available',
    evidence: [
      {
        id: 'platform',
        sourceId: 'platform:macos',
        controlId: controlCheck.controlId,
        profileId: input.profile.id,
        baselineVersion: input.profile.baseline,
        kind: 'platform',
        summary: 'macOS-only passive collector is not applicable on this platform.',
        collectedAt: input.collectedAt,
        redacted: true,
        facts: [{ id: 'macos-host', value: false }],
      },
    ],
    sources: [{ id: 'platform:macos', state: 'unsupported', evidenceIds: ['platform'] }],
  }));
}

/** Capture the command result at this adapter edge, including a parse failure without raw output. */
function createSourceProvenance(
  sourceCheck: SourceCheck,
  result: MacosSecurityAuditCommandResult,
  evidence: readonly SecurityAuditEvidence[],
): SecurityAuditSourceProvenance {
  const evidenceIds = evidence
    .filter((item) => item.sourceId === sourceIdFor(sourceCheck))
    .map((item) => item.id);
  return {
    id: sourceIdFor(sourceCheck),
    state: evidenceIds.length > 0 ? 'completed' : sourceState(result),
    evidenceIds,
  };
}
/** Keep source IDs namespaced and independent from command paths or host values. */
function sourceIdFor(sourceCheck: SourceCheck): string {
  return `macos-host:${sourceCheck.kind}`;
}
/** Preserve command outcomes conservatively; unknown adapter failures remain unclassified. */
function sourceState(
  result: MacosSecurityAuditCommandResult,
): SecurityAuditSourceProvenance['state'] {
  if (result.kind === 'available') return 'parse-invalid';
  if (result.kind === 'permission-denied') return 'permission-blocked';
  if (result.kind === 'missing') return 'missing';
  if (result.kind === 'timed-out') return 'timed-out';
  return 'failed';
}

/** Parse an explicit Time Machine destination state without inferring encryption or recovery. */
function parseTimeMachineDestination(output: string): boolean | undefined {
  if (/No destinations configured/iu.test(output)) return false;
  return /^Name\s*:\s*\S+/imu.test(output) ? true : undefined;
}

/** Convert a recognized two-state source value to a boolean while rejecting all other output. */
function parseBooleanState(
  output: string,
  expression: RegExp,
  secureValue = 'enabled',
): boolean | undefined {
  const value = expression.exec(output)?.[1]?.toLowerCase();
  if (value === undefined) return undefined;
  return value === secureValue;
}
