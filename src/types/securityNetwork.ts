/** A privacy-preserving availability state for one local, read-only source. */
export type SecurityNetworkEvidenceAvailability =
  'available' | 'permission-denied' | 'unsupported' | 'timeout' | 'output-limited' | 'failed';

/** A real measurement, or an explicit unknown when its source could not provide one. */
export type SecurityNetworkObserved<Value> = Value | 'unknown';

/** A locally observable binary setting whose absence is not a safety conclusion. */
export type SecurityNetworkSetting = 'enabled' | 'disabled' | 'unknown';

/** Aggregate Layer 3 facts with addresses, routes, gateways, and interface identifiers removed. */
export interface SecurityNetworkLayer3Evidence {
  readonly interfacesAvailability: SecurityNetworkEvidenceAvailability;
  readonly interfaceCount: SecurityNetworkObserved<number>;
  readonly ipv4AddressCount: SecurityNetworkObserved<number>;
  readonly ipv6AddressCount: SecurityNetworkObserved<number>;
  readonly ipv4RoutesAvailability: SecurityNetworkEvidenceAvailability;
  readonly ipv4DefaultGatewayObserved: SecurityNetworkObserved<boolean>;
  readonly ipv6RoutesAvailability: SecurityNetworkEvidenceAvailability;
  readonly ipv6DefaultGatewayObserved: SecurityNetworkObserved<boolean>;
  readonly ipv4ForwardingAvailability: SecurityNetworkEvidenceAvailability;
  readonly ipv4Forwarding: SecurityNetworkSetting;
  readonly ipv6ForwardingAvailability: SecurityNetworkEvidenceAvailability;
  readonly ipv6Forwarding: SecurityNetworkSetting;
  readonly dnsAvailability: SecurityNetworkEvidenceAvailability;
  readonly dnsResolverCount: SecurityNetworkObserved<number>;
  readonly proxyAvailability: SecurityNetworkEvidenceAvailability;
  readonly webProxy: SecurityNetworkSetting;
  readonly secureWebProxy: SecurityNetworkSetting;
  readonly vpnServicesAvailability: SecurityNetworkEvidenceAvailability;
  readonly vpnServiceCount: SecurityNetworkObserved<number>;
  readonly networkExtensionsAvailability: SecurityNetworkEvidenceAvailability;
  readonly networkExtensionCount: SecurityNetworkObserved<number>;
}

/** pf is observed as a separate packet-filtering mechanism, never as proof of effective protection. */
export interface SecurityNetworkPacketFilterEvidence {
  readonly status: SecurityNetworkSetting;
  readonly statusAvailability: SecurityNetworkEvidenceAvailability;
  readonly rulesAvailability: SecurityNetworkEvidenceAvailability;
  readonly readableRuleCount: SecurityNetworkObserved<number>;
  readonly anchorsAvailability: SecurityNetworkEvidenceAvailability;
  readonly readableAnchorCount: SecurityNetworkObserved<number>;
  readonly protectionEffect: 'not-established';
}

/** Aggregate Layer 4 binding facts with endpoints, PIDs, users, and process paths removed; a non-loopback binding is not proof of remote reachability. */
export interface SecurityNetworkLayer4Evidence {
  readonly tcpListenersAvailability: SecurityNetworkEvidenceAvailability;
  readonly tcpLoopbackListenerCount: SecurityNetworkObserved<number>;
  readonly tcpNonLoopbackListenerCount: SecurityNetworkObserved<number>;
  readonly udpBindingsAvailability: SecurityNetworkEvidenceAvailability;
  readonly udpLoopbackBindingCount: SecurityNetworkObserved<number>;
  readonly udpNonLoopbackBindingCount: SecurityNetworkObserved<number>;
  readonly processAttribution: 'not-established';
  readonly quic: 'unknown';
}

/** Apple Application Firewall state without application exception paths or identities. */
export interface SecurityNetworkApplicationFirewallEvidence {
  readonly globalStateAvailability: SecurityNetworkEvidenceAvailability;
  readonly globalState: SecurityNetworkSetting;
  readonly stealthModeAvailability: SecurityNetworkEvidenceAvailability;
  readonly stealthMode: SecurityNetworkSetting;
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
