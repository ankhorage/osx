import type {
  SecurityAuditEvidence,
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import type {
  SecurityNetworkEvidence,
  SecurityNetworkEvidenceAvailability,
} from '../../../types/securityNetwork.js';

/** Translate bounded, redacted L3/L4 measurements into source-attributed audit observations. */
export function createSecurityNetworkAuditObservations(
  evidence: SecurityNetworkEvidence,
  profile: SecurityAuditProfile,
): readonly SecurityAuditObservation[] {
  return [
    observation(
      'osi3-routing-and-filtering',
      profile,
      evidence.collectedAt,
      [
        evidence.layer3.interfacesAvailability,
        evidence.layer3.ipv4RoutesAvailability,
        evidence.layer3.ipv6RoutesAvailability,
        evidence.layer3.ipv4ForwardingAvailability,
        evidence.layer3.ipv6ForwardingAvailability,
        evidence.layer3.vpnServicesAvailability,
        evidence.layer3.networkExtensionsAvailability,
        evidence.packetFilter.statusAvailability,
        evidence.packetFilter.rulesAvailability,
        evidence.packetFilter.anchorsAvailability,
      ],
      layer3Facts(evidence),
      'Redacted routing, forwarding, VPN, extension, and packet-filter metadata was observed locally.',
    ),
    observation(
      'osi4-service-exposure',
      profile,
      evidence.collectedAt,
      [
        evidence.layer4.tcpListenersAvailability,
        evidence.layer4.udpBindingsAvailability,
        evidence.applicationFirewall.globalStateAvailability,
        evidence.applicationFirewall.stealthModeAvailability,
      ],
      layer4Facts(evidence),
      'Redacted socket-binding and Apple Application Firewall metadata was observed locally; bindings do not establish reachability.',
    ),
  ];
}

/** Keep L3 facts independently attributable to forwarding and packet-filter sources. */
function layer3Facts(evidence: SecurityNetworkEvidence): readonly (readonly [string, boolean])[] {
  return [
    availabilitySettingFact(
      'ipv4-forwarding-disabled',
      evidence.layer3.ipv4ForwardingAvailability,
      evidence.layer3.ipv4Forwarding,
      'disabled',
    ),
    availabilitySettingFact(
      'ipv6-forwarding-disabled',
      evidence.layer3.ipv6ForwardingAvailability,
      evidence.layer3.ipv6Forwarding,
      'disabled',
    ),
    availabilitySettingFact(
      'packet-filter-enabled',
      evidence.packetFilter.statusAvailability,
      evidence.packetFilter.status,
      'enabled',
    ),
  ].flatMap((fact) => (fact ? [fact] : []));
}

/** Keep L4 binding and Apple Application Firewall facts distinct. */
function layer4Facts(evidence: SecurityNetworkEvidence): readonly (readonly [string, boolean])[] {
  return [
    availabilityObservedFact(
      'no-non-loopback-tcp-listeners-observed',
      evidence.layer4.tcpListenersAvailability,
      evidence.layer4.tcpNonLoopbackListenerCount,
      0,
    ),
    availabilitySettingFact(
      'application-firewall-enabled',
      evidence.applicationFirewall.globalStateAvailability,
      evidence.applicationFirewall.globalState,
      'enabled',
    ),
    availabilitySettingFact(
      'application-firewall-stealth-enabled',
      evidence.applicationFirewall.stealthModeAvailability,
      evidence.applicationFirewall.stealthMode,
      'enabled',
    ),
  ].flatMap((fact) => (fact ? [fact] : []));
}

/** Emit a fact only when its numeric source completed successfully. */
function availabilityObservedFact(
  id: string,
  availability: SecurityNetworkEvidenceAvailability,
  observed: number | 'unknown',
  expected: number,
): readonly [string, boolean] | undefined {
  return availability === 'available' && observed !== 'unknown'
    ? [id, observed === expected]
    : undefined;
}

/** Never translate an unrecognized source setting into a negative security fact. */
function availabilitySettingFact(
  id: string,
  availability: SecurityNetworkEvidenceAvailability,
  observed: 'enabled' | 'disabled' | 'unknown',
  expected: 'enabled' | 'disabled',
): readonly [string, boolean] | undefined {
  return availability === 'available' && observed !== 'unknown'
    ? [id, observed === expected]
    : undefined;
}

/** Preserve source limitations in coverage rather than interpreting unavailable measurements as negative facts. */
function observation(
  controlId: string,
  profile: SecurityAuditProfile,
  collectedAt: string,
  availability: readonly SecurityNetworkEvidenceAvailability[],
  facts: readonly (readonly [string, boolean])[],
  summary: string,
): SecurityAuditObservation {
  const access = accessFor(availability);
  return {
    controlId,
    applicability: access === 'available' ? 'applicable' : 'unknown',
    access,
    evidence:
      facts.length === 0 ? [] : [createEvidence(controlId, profile, collectedAt, facts, summary)],
  };
}

/** Attribute collected facts to the network adapter and active profile without copying raw command output. */
function createEvidence(
  controlId: string,
  profile: SecurityAuditProfile,
  collectedAt: string,
  facts: readonly (readonly [string, boolean])[],
  summary: string,
): SecurityAuditEvidence {
  return {
    id: `${controlId}-network-summary`,
    sourceId: `macos-network:${controlId}`,
    controlId,
    profileId: profile.id,
    baselineVersion: profile.baseline,
    kind: 'macos-passive-network-summary',
    summary,
    collectedAt,
    redacted: true,
    facts: facts.map(([id, value]) => ({ id, value })),
  };
}

/** Mark a collector inaccessible only when every requested source was denied. */
function accessFor(
  availability: readonly SecurityNetworkEvidenceAvailability[],
): SecurityAuditObservation['access'] {
  if (availability.every((item) => item === 'permission-denied')) return 'permission-blocked';
  return availability.every((item) => item === 'available') ? 'available' : 'incomplete';
}
