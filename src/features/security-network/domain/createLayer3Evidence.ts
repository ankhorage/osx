import type {
  SecurityNetworkEvidenceAvailability,
  SecurityNetworkLayer3Evidence,
  SecurityNetworkPacketFilterEvidence,
  SecurityNetworkSetting,
} from '../../../types/securityNetwork.js';
import type { SecurityNetworkCommandResult } from '../ports/securityNetworkHost.js';

/*** Convert raw, local Layer 3 command output into address-free routing and packet-filter evidence. */
export function createLayer3Evidence(
  interfaces: SecurityNetworkCommandResult,
  ipv4Routes: SecurityNetworkCommandResult,
  ipv6Routes: SecurityNetworkCommandResult,
  ipv4Forwarding: SecurityNetworkCommandResult,
  ipv6Forwarding: SecurityNetworkCommandResult,
  vpnServices: SecurityNetworkCommandResult,
  networkExtensions: SecurityNetworkCommandResult,
  packetFilterStatus: SecurityNetworkCommandResult,
  packetFilterRules: SecurityNetworkCommandResult,
  packetFilterAnchors: SecurityNetworkCommandResult,
): {
  readonly layer3: SecurityNetworkLayer3Evidence;
  readonly packetFilter: SecurityNetworkPacketFilterEvidence;
} {
  return {
    layer3: {
      interfaceCount: countInterfaces(interfaces),
      ipv4AddressCount: countMatches(interfaces, /^\s*inet\s+/gm),
      ipv6AddressCount: countMatches(interfaces, /^\s*inet6\s+/gm),
      ipv4DefaultGatewayObserved: hasDefaultRoute(ipv4Routes),
      ipv6DefaultGatewayObserved: hasDefaultRoute(ipv6Routes),
      ipv4Forwarding: parseForwarding(ipv4Forwarding),
      ipv6Forwarding: parseForwarding(ipv6Forwarding),
      vpnServiceCount: countServiceLines(vpnServices),
      networkExtensionCount: countNetworkExtensions(networkExtensions),
    },
    packetFilter: {
      status: parsePacketFilterStatus(packetFilterStatus),
      statusAvailability: availability(packetFilterStatus),
      rulesAvailability: availability(packetFilterRules),
      readableRuleCount: countReadableLines(packetFilterRules),
      anchorsAvailability: availability(packetFilterAnchors),
      readableAnchorCount: countReadableLines(packetFilterAnchors),
      protectionEffect: 'not-established',
    },
  };
}

/** Count interface headers without retaining their names or hardware addresses. */
function countInterfaces(result: SecurityNetworkCommandResult): number {
  return result.exitCode === 0 ? countMatches(result, /^[^\s][^:]*:/gm) : 0;
}

/** Count a non-sensitive pattern only after a command completed successfully. */
function countMatches(result: SecurityNetworkCommandResult, pattern: RegExp): number {
  return result.exitCode === 0 ? (result.stdout.match(pattern)?.length ?? 0) : 0;
}

/** Detect the route-table default marker without exposing a gateway or route. */
function hasDefaultRoute(result: SecurityNetworkCommandResult): boolean {
  return result.exitCode === 0 && /^default\s+/m.test(result.stdout);
}

/** Interpret the public sysctl forwarding flag conservatively. */
function parseForwarding(result: SecurityNetworkCommandResult): SecurityNetworkSetting {
  if (result.exitCode !== 0) return 'unknown';
  if (result.stdout.trim() === '1') return 'enabled';
  if (result.stdout.trim() === '0') return 'disabled';
  return 'unknown';
}

/** Count configured VPN services while omitting their names and connection identifiers. */
function countServiceLines(result: SecurityNetworkCommandResult): number {
  return result.exitCode === 0
    ? result.stdout.split('\n').filter((line) => /^\*?\s*\([^)]*\)/.test(line)).length
    : 0;
}

/** Count only the generic NetworkExtension marker, never bundle or team identifiers. */
function countNetworkExtensions(result: SecurityNetworkCommandResult): number {
  return result.exitCode === 0
    ? result.stdout.split('\n').filter((line) => /networkextension/i.test(line)).length
    : 0;
}

/** Derive a privacy-safe source availability state from a local command result. */
function availability(result: SecurityNetworkCommandResult): SecurityNetworkEvidenceAvailability {
  if (result.exitCode === 0) return 'available';
  return /operation not permitted|permission denied|not permitted/i.test(result.stdout)
    ? 'permission-blocked'
    : 'unavailable';
}

/** Read the pf enabled marker without treating its existence as firewall effectiveness. */
function parsePacketFilterStatus(result: SecurityNetworkCommandResult): SecurityNetworkSetting {
  if (result.exitCode !== 0) return 'unknown';
  if (/^status:\s+enabled\b/im.test(result.stdout)) return 'enabled';
  if (/^status:\s+disabled\b/im.test(result.stdout)) return 'disabled';
  return 'unknown';
}

/** Count readable non-comment pf records without returning rule text or anchor names. */
function countReadableLines(result: SecurityNetworkCommandResult): number {
  return result.exitCode === 0
    ? result.stdout.split('\n').filter((line) => line.trim() !== '' && !line.trim().startsWith('#'))
        .length
    : 0;
}
