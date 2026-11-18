import type {
  SecurityAuditEvidence,
  SecurityAuditObservation,
} from '../../../../types/securityAudit.js';

export interface MacosHostSecurityCommandResult {
  readonly exitCode: number;
  readonly output: string;
}

export type MacosHostSecurityCommandRunner = (
  executable: string,
  arguments_: readonly string[],
) => MacosHostSecurityCommandResult;

/*** Collect a small set of read-only macOS security facts without retaining command output or host identifiers. */
export function collectMacosHostSecurityObservations(
  runCommand: MacosHostSecurityCommandRunner = runReadOnlyCommand,
  collectedAt: string = new Date().toISOString(),
): readonly SecurityAuditObservation[] {
  return checks.map((check) => createObservation(check, runCommand, collectedAt));
}

interface Check {
  readonly controlId: string;
  readonly executable: string;
  readonly arguments_: readonly string[];
  readonly factId: string;
  readonly evidenceId: string;
  readonly kind: string;
  readonly summary: string;
  readonly isSecure: (output: string) => boolean;
}

const checks: readonly Check[] = [
  {
    controlId: 'cross-layer-hardware-startup-trust',
    executable: '/usr/bin/csrutil',
    arguments_: ['status'],
    factId: 'system-integrity-protection-enabled',
    evidenceId: 'sip-status',
    kind: 'csrutil-status',
    summary: 'System Integrity Protection status was observed with a read-only Apple utility.',
    isSecure: (output) => /System Integrity Protection status:\s*enabled\./iu.test(output),
  },
  {
    controlId: 'cross-layer-hardware-startup-trust',
    executable: '/usr/bin/csrutil',
    arguments_: ['authenticated-root', 'status'],
    factId: 'authenticated-root-enabled',
    evidenceId: 'authenticated-root-status',
    kind: 'csrutil-authenticated-root-status',
    summary: 'Authenticated Root status was observed with a read-only Apple utility.',
    isSecure: (output) => /Authenticated Root status:\s*enabled\./iu.test(output),
  },
  {
    controlId: 'cross-layer-disk-data',
    executable: '/usr/bin/fdesetup',
    arguments_: ['status'],
    factId: 'filevault-enabled',
    evidenceId: 'filevault-status',
    kind: 'fdesetup-status',
    summary: 'FileVault status was observed with a read-only Apple utility.',
    isSecure: (output) => /FileVault is On\./iu.test(output),
  },
  {
    controlId: 'cross-layer-identity-access',
    executable: '/usr/sbin/sysadminctl',
    arguments_: ['-guestAccount', 'status'],
    factId: 'guest-account-disabled',
    evidenceId: 'guest-account-status',
    kind: 'sysadminctl-guest-account-status',
    summary: 'Guest-account policy status was observed without collecting account identities.',
    isSecure: (output) => /Guest account is disabled\./iu.test(output),
  },
  {
    controlId: 'cross-layer-malware-integrity',
    executable: '/usr/sbin/spctl',
    arguments_: ['--status'],
    factId: 'gatekeeper-assessments-enabled',
    evidenceId: 'gatekeeper-status',
    kind: 'spctl-status',
    summary: 'Gatekeeper assessment status was observed with a read-only Apple utility.',
    isSecure: (output) => /assessments enabled/iu.test(output),
  },
  {
    controlId: 'cross-layer-backups-resilience-logging',
    executable: '/usr/bin/tmutil',
    arguments_: ['destinationinfo'],
    factId: 'time-machine-destination-reported',
    evidenceId: 'time-machine-destination-status',
    kind: 'tmutil-destinationinfo',
    summary:
      'Time Machine destination metadata was available; this does not verify backup encryption or recovery.',
    isSecure: (output) => !/No destinations configured/iu.test(output),
  },
  {
    controlId: 'cross-layer-enterprise-policy',
    executable: '/usr/bin/profiles',
    arguments_: ['status', '-type', 'enrollment'],
    factId: 'mdm-enrollment-reported',
    evidenceId: 'mdm-enrollment-status',
    kind: 'profiles-enrollment-status',
    summary: 'MDM enrollment metadata was observed without collecting profile contents.',
    isSecure: (output) => /MDM enrollment:\s*Yes/iu.test(output),
  },
];

/** Create a redacted observation, treating an unavailable command as missing rather than a pass. */
function createObservation(
  check: Check,
  runCommand: MacosHostSecurityCommandRunner,
  collectedAt: string,
): SecurityAuditObservation {
  const result = runCommand(check.executable, check.arguments_);
  if (isPermissionBlocked(result.output))
    return {
      controlId: check.controlId,
      applicability: 'unknown',
      access: 'permission-blocked',
      evidence: [],
    };
  if (result.exitCode !== 0)
    return {
      controlId: check.controlId,
      applicability: 'unknown',
      access: 'available',
      evidence: [],
    };
  return {
    controlId: check.controlId,
    applicability: 'applicable',
    access: 'available',
    evidence: [createEvidence(check, result.output, collectedAt)],
  };
}

/** Construct serializable evidence from a boolean only, never from raw host output. */
function createEvidence(check: Check, output: string, collectedAt: string): SecurityAuditEvidence {
  return {
    id: check.evidenceId,
    controlId: check.controlId,
    profileId: 'macos-informational',
    baselineVersion: 'macos-informational-v1',
    kind: check.kind,
    summary: check.summary,
    collectedAt,
    redacted: true,
    facts: [{ id: check.factId, value: check.isSecure(output) }],
  };
}

/** Identify explicit access denials without emitting the protected command output. */
function isPermissionBlocked(output: string): boolean {
  return /operation not permitted|permission denied|not authorized/iu.test(output);
}

/** Execute a fixed, read-only Apple utility command and retain its output only for immediate parsing. */
function runReadOnlyCommand(
  executable: string,
  arguments_: readonly string[],
): MacosHostSecurityCommandResult {
  const process = Bun.spawnSync([executable, ...arguments_], { stderr: 'pipe', stdout: 'pipe' });
  return {
    exitCode: process.exitCode,
    output: `${process.stdout.toString()}${process.stderr.toString()}`,
  };
}
