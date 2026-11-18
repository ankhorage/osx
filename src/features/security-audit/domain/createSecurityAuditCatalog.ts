import type { SecurityAuditControl } from '../../../types/securityAudit.js';

/*** Define the stable audit-control catalog without claiming that every control has a collector. */
export function createSecurityAuditCatalog(): readonly SecurityAuditControl[] {
  return controls;
}

const controls: readonly SecurityAuditControl[] = [
  control(
    'osi1-physical-interface-inventory',
    'Physical interface and attached-device exposure',
    1,
    [],
    'passive',
    'Review externally attached interfaces and devices; confirm physical port controls separately.',
  ),
  control(
    'osi2-link-security',
    'Link-layer network security',
    2,
    [],
    'api',
    'Use a supported collector to verify Wi-Fi authentication, network trust, and discoverability.',
  ),
  control(
    'osi3-routing-and-filtering',
    'Network routing and packet-filter posture',
    3,
    [4],
    'passive',
    'Review routes, forwarding, VPN placement, and pf state without treating pf as an Apple public API.',
  ),
  control(
    'osi4-service-exposure',
    'Transport service exposure and application firewall',
    4,
    [3],
    'passive',
    'Review listening-service bindings and Apple Application Firewall separately from packet filtering.',
  ),
  control(
    'osi5-remote-session-services',
    'Remote session and sharing services',
    5,
    [4, 7],
    'api',
    'Review Remote Login, screen sharing, file sharing, and active-session exposure.',
  ),
  control(
    'osi6-presentation-trust',
    'Presentation-layer trust and TLS indicators',
    6,
    [7],
    'manual',
    'Review certificate trust, TLS policy, and interception indicators with supported local evidence.',
  ),
  control(
    'osi7-application-network-and-persistence',
    'Application network posture and persistence',
    7,
    [3, 4],
    'passive',
    'Review resolver and proxy configuration, signed applications, and persistence entry points.',
  ),
  crossLayerControl(
    'hardware-startup-trust',
    'Hardware and startup trust',
    'api',
    'Review startup security, SIP, signed system volume, and trusted extensions using supported APIs.',
  ),
  crossLayerControl(
    'disk-data',
    'Disk and data protection',
    'api',
    'Review FileVault, external-volume encryption, backup encryption, and restore readiness without claiming a restore test occurred.',
  ),
  crossLayerControl(
    'identity-access',
    'Identity and access posture',
    'api',
    'Review local privilege, guest access, lock policy, and remote-login configuration without exposing identities.',
  ),
  crossLayerControl(
    'privacy-permissions',
    'Privacy and permissions posture',
    'api',
    'Review supported TCC, profile, and background-item metadata without bypassing protected databases.',
  ),
  crossLayerControl(
    'malware-integrity',
    'Malware defenses and integrity',
    'api',
    'Review Gatekeeper, XProtect, signatures, quarantine, and persistence indicators without asserting malware detection from heuristics.',
  ),
  crossLayerControl(
    'patching-exposure',
    'Patching and exposure posture',
    'api',
    'Review update policy and reliable version evidence; do not infer vulnerabilities without advisory matching.',
  ),
  crossLayerControl(
    'network-trust',
    'Network and trust configuration',
    'passive',
    'Review Wi-Fi, VPN, DNS, proxies, firewall controls, and remote access as distinct controls.',
  ),
  crossLayerControl(
    'development-supply-chain',
    'Development and supply-chain posture',
    'passive',
    'Review metadata such as lockfile or signing posture without reading or exporting secrets.',
  ),
  crossLayerControl(
    'backups-resilience-logging',
    'Backups, resilience, logging, and monitoring',
    'api',
    'Review backup and logging status without treating availability as a verified recovery test.',
  ),
  crossLayerControl(
    'enterprise-policy',
    'Enterprise and managed-device policy',
    'api',
    'Report managed controls when observable; never self-certify compliance from partial evidence.',
  ),
];

/** Construct one OSI control with stable source and privacy requirements. */
function control(
  id: string,
  title: string,
  layer: 1 | 2 | 3 | 4 | 5 | 6 | 7,
  crossReferenceLayers: readonly (1 | 2 | 3 | 4 | 5 | 6 | 7)[],
  detectionMode: SecurityAuditControl['detectionMode'],
  recommendation: string,
): SecurityAuditControl {
  return {
    id,
    title,
    primaryCategory: { kind: 'osi', layer },
    crossReferences: crossReferenceLayers.map((referencedLayer) => ({
      kind: 'osi',
      layer: referencedLayer,
    })),
    supportedPlatforms: ['macos'],
    applicability: 'Applicable when macOS provides the required read-only local evidence.',
    detectionMode,
    prerequisites: ['macOS host access', 'read-only local evidence'],
    baselines: [
      {
        profileId: 'macos-informational',
        expectedSecureCondition:
          'No insecure exposure is evidenced by a supported read-only collector.',
        failureSeverity: 'medium',
      },
    ],
    sourceReferences: ['https://support.apple.com/guide/security/welcome/web'],
    recommendation: { manualRemediation: recommendation },
  };
}

/** Construct one cross-layer control without pretending that OSI is a complete security taxonomy. */
function crossLayerControl(
  theme: Extract<SecurityAuditControl['primaryCategory'], { kind: 'cross-layer' }>['theme'],
  title: string,
  detectionMode: SecurityAuditControl['detectionMode'],
  recommendation: string,
): SecurityAuditControl {
  return {
    id: `cross-layer-${theme}`,
    title,
    primaryCategory: { kind: 'cross-layer', theme },
    crossReferences: [],
    supportedPlatforms: ['macos'],
    applicability: 'Applicable when macOS provides the required read-only local evidence.',
    detectionMode,
    prerequisites: ['macOS host access', 'read-only local evidence'],
    baselines: [
      {
        profileId: 'macos-informational',
        expectedSecureCondition:
          'No insecure exposure is evidenced by a supported read-only collector.',
        failureSeverity: 'medium',
      },
    ],
    sourceReferences: ['https://support.apple.com/guide/security/welcome/web'],
    recommendation: { manualRemediation: recommendation },
  };
}
