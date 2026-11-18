export type MacosHostSecuritySupport = 'implemented' | 'unknown' | 'unsupported';

export interface MacosHostSecuritySupportEntry {
  readonly area: string;
  readonly check: string;
  readonly support: MacosHostSecuritySupport;
  readonly recommendation: string;
  readonly sourceReference: string;
}

/*** Describe the passive macOS host-security scope without representing unavailable evidence as compliance. */
export function createMacosHostSecuritySupportMatrix(): readonly MacosHostSecuritySupportEntry[] {
  return supportMatrix;
}

const applePlatformSecurity = 'https://support.apple.com/guide/security/welcome/web';

const supportMatrix: readonly MacosHostSecuritySupportEntry[] = [
  entry(
    'Hardware and startup',
    'Apple Silicon, Intel, and T2 startup posture',
    'unknown',
    'Verify startup security manually in macOS Recovery for the specific hardware model.',
  ),
  entry(
    'Hardware and startup',
    'System Integrity Protection',
    'implemented',
    'Keep SIP enabled unless a documented, time-bounded exception is required.',
  ),
  entry(
    'Hardware and startup',
    'Authenticated Root / signed system volume',
    'implemented',
    'Keep Authenticated Root enabled; review recovery-mode changes separately.',
  ),
  entry(
    'Disk and data',
    'FileVault',
    'implemented',
    'Enable FileVault and retain an approved recovery-key escrow process.',
  ),
  entry(
    'Disk and data',
    'APFS volume encryption',
    'unknown',
    'Review each relevant APFS volume without inferring encryption from the startup volume.',
  ),
  entry(
    'Disk and data',
    'Backup encryption',
    'unknown',
    'Verify encryption from the backup destination configuration; destination presence is not encryption evidence.',
  ),
  entry(
    'Identity and access',
    'Administrator policy',
    'unsupported',
    'Review account roles through an approved identity-management process without exporting identities.',
  ),
  entry(
    'Identity and access',
    'Guest account policy',
    'implemented',
    'Disable Guest access unless it is an approved operational requirement.',
  ),
  entry(
    'Identity and access',
    'Screen-lock policy',
    'unsupported',
    'Review the managed screen-lock policy in the owning device-management system.',
  ),
  entry(
    'Privacy',
    'TCC permissions',
    'unsupported',
    'Review privacy grants through supported management inventory; never read or bypass protected TCC databases.',
  ),
  entry(
    'Privacy',
    'Profile metadata',
    'unknown',
    'Review profile metadata only through supported read-only APIs.',
  ),
  entry('Integrity', 'Gatekeeper', 'implemented', 'Keep Gatekeeper assessments enabled.'),
  entry(
    'Integrity',
    'XProtect, quarantine, and signatures',
    'unsupported',
    'Use Apple-supported management and endpoint tooling; this assessment does not claim malware detection.',
  ),
  entry(
    'Updates',
    'macOS security-update currency',
    'unknown',
    'Verify installed updates against an approved advisory and device-management source.',
  ),
  entry(
    'Updates',
    'Package and toolchain status',
    'unsupported',
    'Assess project dependencies in their owning repository; do not inspect unrelated host workspaces.',
  ),
  entry(
    'Development',
    'SSH and Git-signing metadata',
    'unsupported',
    'Review configuration through an approved developer-security workflow without reading keys or identities.',
  ),
  entry(
    'Development',
    'Lockfiles and SBOM posture',
    'unsupported',
    'Run repository-owned dependency and SBOM checks in the relevant checkout.',
  ),
  entry(
    'Resilience',
    'Time Machine destination visibility',
    'implemented',
    'Verify backup encryption and restore testing separately; a visible destination is not recovery evidence.',
  ),
  entry(
    'Resilience',
    'Logging and monitoring',
    'unsupported',
    'Verify coverage through the owning logging and monitoring service.',
  ),
  entry(
    'Enterprise',
    'MDM enrollment metadata',
    'implemented',
    'Review actual managed policies in the MDM; enrollment alone does not establish compliance.',
  ),
];

/** Create a consistently sourced support-matrix entry. */
function entry(
  area: string,
  check: string,
  support: MacosHostSecuritySupport,
  recommendation: string,
): MacosHostSecuritySupportEntry {
  return { area, check, support, recommendation, sourceReference: applePlatformSecurity };
}
