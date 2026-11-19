import type { SecurityAuditControl } from '../../../types/securityAudit.js';

/*** Define the stable audit-control catalog without claiming that every control has a collector. */
export function createSecurityAuditCatalog(): readonly SecurityAuditControl[] {
  return controls;
}

const controls: readonly SecurityAuditControl[] = [
  control(
    'osi1-physical-interface-inventory',
    'Physical interface and attached-device exposure',
    'Software-visible interfaces and attached-device exposure; physical safeguards require manual review.',
    1,
    [],
    'passive',
    'Review externally attached interfaces and devices; confirm physical port controls separately.',
  ),
  control(
    'osi2-link-security',
    'Link-layer network security',
    'Wi-Fi, link trust, and discoverability when supported local evidence is available.',
    2,
    [],
    'api',
    'Use a supported collector to verify Wi-Fi authentication, network trust, and discoverability.',
  ),
  control(
    'osi3-routing-and-filtering',
    'Network routing and packet-filter posture',
    'Routes, forwarding, VPN placement, and packet-filter posture without treating pf as a public API.',
    3,
    [4],
    'passive',
    'Review routes, forwarding, VPN placement, and pf state without treating pf as an Apple public API.',
  ),
  control(
    'osi4-service-exposure',
    'Transport service exposure and application firewall',
    'Listening-service exposure and the Apple Application Firewall, separate from packet filtering.',
    4,
    [3],
    'passive',
    'Review listening-service bindings and Apple Application Firewall separately from packet filtering.',
  ),
  control(
    'osi5-remote-session-services',
    'Remote session and sharing services',
    'Remote login, sharing services, and session exposure where supported local evidence is available.',
    5,
    [4, 7],
    'api',
    'Review Remote Login, screen sharing, file sharing, and active-session exposure.',
  ),
  control(
    'osi6-presentation-trust',
    'Presentation-layer trust and TLS indicators',
    'Certificate trust, TLS policy, and interception indicators that require supported local evidence.',
    6,
    [7],
    'manual',
    'Review certificate trust, TLS policy, and interception indicators with supported local evidence.',
  ),
  control(
    'osi7-application-network-and-persistence',
    'Application network posture and persistence',
    'Resolver, proxy, application-signing, and persistence posture using non-sensitive local metadata.',
    7,
    [3, 4],
    'passive',
    'Review resolver and proxy configuration, signed applications, and persistence entry points.',
  ),
  crossLayerControl(
    'hardware-startup-trust',
    'Hardware and startup trust',
    'Startup protections and trusted extensions, independently of OSI layer classification.',
    'api',
    'Review startup security, SIP, signed system volume, and trusted extensions using supported APIs.',
    [
      baseline(
        'SIP and Authenticated Root are enabled.',
        [
          ['system-integrity-protection-enabled', true],
          ['authenticated-root-enabled', true],
        ],
        'high',
      ),
    ],
  ),
  crossLayerControl(
    'disk-data',
    'Disk and data protection',
    'Encryption and backup posture; availability is never presented as a verified restore test.',
    'api',
    'Review FileVault, external-volume encryption, backup encryption, and restore readiness without claiming a restore test occurred.',
    [baseline('FileVault is enabled.', [['filevault-enabled', true]], 'high')],
  ),
  crossLayerControl(
    'identity-access',
    'Identity and access posture',
    'Privilege and remote-access posture without exposing account identities or credentials.',
    'api',
    'Review local privilege, guest access, lock policy, and remote-login configuration without exposing identities.',
  ),
  crossLayerControl(
    'privacy-permissions',
    'Privacy and permissions posture',
    'Privacy, profile, and background-item metadata without bypassing protected system databases.',
    'api',
    'Review supported TCC, profile, and background-item metadata without bypassing protected databases.',
  ),
  crossLayerControl(
    'malware-integrity',
    'Malware defenses and integrity',
    'Integrity defenses and cautious indicators, never a malware-identification claim from heuristics.',
    'api',
    'Review Gatekeeper, XProtect, signatures, quarantine, and persistence indicators without asserting malware detection from heuristics.',
  ),
  crossLayerControl(
    'patching-exposure',
    'Patching and exposure posture',
    'Update posture and reliable version evidence, without guessing vulnerability status.',
    'api',
    'Review update policy and reliable version evidence; do not infer vulnerabilities without advisory matching.',
  ),
  crossLayerControl(
    'network-trust',
    'Network and trust configuration',
    'Cross-layer trust controls such as VPN, DNS, proxies, firewall, and remote access.',
    'passive',
    'Review Wi-Fi, VPN, DNS, proxies, firewall controls, and remote access as distinct controls.',
  ),
  crossLayerControl(
    'development-supply-chain',
    'Development and supply-chain posture',
    'Development metadata and supply-chain controls without reading or exporting secret contents.',
    'passive',
    'Review metadata such as lockfile or signing posture without reading or exporting secrets.',
  ),
  crossLayerControl(
    'backups-resilience-logging',
    'Backups, resilience, logging, and monitoring',
    'Backup, logging, and response-readiness posture without claiming a recovery test.',
    'api',
    'Review backup and logging status without treating availability as a verified recovery test.',
  ),
  crossLayerControl(
    'enterprise-policy',
    'Enterprise and managed-device policy',
    'Observable managed controls, without self-certifying policy compliance from partial evidence.',
    'api',
    'Report managed controls when observable; never self-certify compliance from partial evidence.',
  ),
];

/** Construct one OSI control with stable source and privacy requirements. */
function control(
  id: string,
  title: string,
  description: string,
  layer: 1 | 2 | 3 | 4 | 5 | 6 | 7,
  crossReferenceLayers: readonly (1 | 2 | 3 | 4 | 5 | 6 | 7)[],
  detectionMode: SecurityAuditControl['detectionMode'],
  recommendation: string,
): SecurityAuditControl {
  return {
    id,
    title,
    description,
    primaryCategory: { kind: 'osi', layer },
    crossReferences: crossReferenceLayers.map((referencedLayer) => ({
      kind: 'osi',
      layer: referencedLayer,
    })),
    supportedPlatforms: ['macos'],
    applicability: 'Applicable when macOS provides the required read-only local evidence.',
    detectionMode,
    prerequisites: ['macOS host access', 'read-only local evidence'],
    baselines: [],
    sourceReferences: ['https://support.apple.com/guide/security/welcome/web'],
    recommendation: { manualRemediation: recommendation },
  };
}

/** Construct one cross-layer control without pretending that OSI is a complete security taxonomy. */
function crossLayerControl(
  theme: Extract<SecurityAuditControl['primaryCategory'], { kind: 'cross-layer' }>['theme'],
  title: string,
  description: string,
  detectionMode: SecurityAuditControl['detectionMode'],
  recommendation: string,
  baselines: SecurityAuditControl['baselines'] = [],
): SecurityAuditControl {
  return {
    id: `cross-layer-${theme}`,
    title,
    description,
    primaryCategory: { kind: 'cross-layer', theme },
    crossReferences: [],
    supportedPlatforms: ['macos'],
    applicability: 'Applicable when macOS provides the required read-only local evidence.',
    detectionMode,
    prerequisites: ['macOS host access', 'read-only local evidence'],
    baselines,
    sourceReferences: ['https://support.apple.com/guide/security/welcome/web'],
    recommendation: { manualRemediation: recommendation },
  };
}

/** Define a narrowly evidenced macOS v1 condition that the audit engine, not a collector, evaluates. */
function baseline(
  expectedSecureCondition: string,
  facts: readonly (readonly [string, boolean])[],
  failureSeverity: SecurityAuditControl['baselines'][number]['failureSeverity'],
): SecurityAuditControl['baselines'][number] {
  return {
    profileId: 'macos-informational',
    expectedSecureCondition,
    predicate: {
      kind: 'all-boolean-facts',
      facts: facts.map(([id, value]) => ({ id, value })),
    },
    failureSeverity,
  };
}
