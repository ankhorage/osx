/** A privacy-preserving availability state for one local, read-only source. */
export type SecurityNetworkEvidenceAvailability =
  'available' | 'permission-blocked' | 'unavailable';

/** A locally observable binary setting whose absence is not a safety conclusion. */
export type SecurityNetworkSetting = 'enabled' | 'disabled' | 'unknown';

/** Aggregate Layer 3 facts with addresses, routes, gateways, and interface identifiers removed. */
export interface SecurityNetworkLayer3Evidence {
  readonly interfaceCount: number;
  readonly ipv4AddressCount: number;
  readonly ipv6AddressCount: number;
  readonly ipv4DefaultGatewayObserved: boolean;
  readonly ipv6DefaultGatewayObserved: boolean;
  readonly ipv4Forwarding: SecurityNetworkSetting;
  readonly ipv6Forwarding: SecurityNetworkSetting;
  readonly vpnServiceCount: number;
  readonly networkExtensionCount: number;
}

/** pf is observed as a separate packet-filtering mechanism, never as proof of effective protection. */
export interface SecurityNetworkPacketFilterEvidence {
  readonly status: SecurityNetworkSetting;
  readonly statusAvailability: SecurityNetworkEvidenceAvailability;
  readonly rulesAvailability: SecurityNetworkEvidenceAvailability;
  readonly readableRuleCount: number;
  readonly anchorsAvailability: SecurityNetworkEvidenceAvailability;
  readonly readableAnchorCount: number;
  readonly protectionEffect: 'not-established';
}

/** Aggregate Layer 4 binding facts with endpoints, PIDs, users, and process paths removed. */
export interface SecurityNetworkLayer4Evidence {
  readonly tcpLoopbackListenerCount: number;
  readonly tcpExternallyReachableListenerCount: number;
  readonly udpLoopbackBindingCount: number;
  readonly udpExternallyReachableBindingCount: number;
  readonly processAttribution: SecurityNetworkEvidenceAvailability;
  readonly quic: 'unknown';
}

/** Apple Application Firewall state without application exception paths or identities. */
export interface SecurityNetworkApplicationFirewallEvidence {
  readonly globalState: SecurityNetworkSetting;
  readonly stealthMode: SecurityNetworkSetting;
  readonly availability: SecurityNetworkEvidenceAvailability;
  readonly protectionEffect: 'not-established';
}

/** Redacted OSI Layer 3 and 4 evidence from passive, host-local macOS inspection. */
export interface SecurityNetworkEvidence {
  readonly collectedAt: string;
  readonly layer3: SecurityNetworkLayer3Evidence;
  readonly packetFilter: SecurityNetworkPacketFilterEvidence;
  readonly layer4: SecurityNetworkLayer4Evidence;
  readonly applicationFirewall: SecurityNetworkApplicationFirewallEvidence;
  readonly protectionLimitations: readonly string[];
}
