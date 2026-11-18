import type {
  SecurityNetworkApplicationFirewallEvidence,
  SecurityNetworkEvidenceAvailability,
  SecurityNetworkLayer4Evidence,
  SecurityNetworkObserved,
  SecurityNetworkSetting,
} from '../../../types/securityNetwork.js';
import type { SecurityNetworkCommandResult } from '../ports/securityNetworkHost.js';

/*** Convert local socket and Apple Application Firewall output into redacted Layer 4 evidence. */
export function createLayer4Evidence(
  tcpListeners: SecurityNetworkCommandResult,
  udpBindings: SecurityNetworkCommandResult,
  applicationFirewall: SecurityNetworkCommandResult,
  stealthMode: SecurityNetworkCommandResult,
): {
  readonly layer4: SecurityNetworkLayer4Evidence;
  readonly applicationFirewall: SecurityNetworkApplicationFirewallEvidence;
} {
  const tcp = countBindings(tcpListeners, 'TCP');
  const udp = countBindings(udpBindings, 'UDP');
  return {
    layer4: {
      tcpListenersAvailability: availability(tcpListeners),
      tcpLoopbackListenerCount: tcp.loopback,
      tcpNonLoopbackListenerCount: tcp.nonLoopback,
      udpBindingsAvailability: availability(udpBindings),
      udpLoopbackBindingCount: udp.loopback,
      udpNonLoopbackBindingCount: udp.nonLoopback,
      processAttribution: 'not-established',
      quic: 'unknown',
    },
    applicationFirewall: {
      globalStateAvailability: availability(applicationFirewall),
      globalState: parseApplicationFirewallSetting(applicationFirewall),
      stealthModeAvailability: availability(stealthMode),
      stealthMode: parseApplicationFirewallSetting(stealthMode),
      protectionEffect: 'not-established',
    },
  };
}

/** Classify socket bindings only after a completed source, retaining no endpoint or process metadata. */
function countBindings(
  result: SecurityNetworkCommandResult,
  protocol: 'TCP' | 'UDP',
): {
  readonly loopback: SecurityNetworkObserved<number>;
  readonly nonLoopback: SecurityNetworkObserved<number>;
} {
  if (result.status !== 'completed') return { loopback: 'unknown', nonLoopback: 'unknown' };
  return result.stdout.split('\n').reduce(
    (counts, line) => {
      if (!new RegExp(`\\b${protocol}\\b`).test(line)) return counts;
      return isLoopbackBinding(line)
        ? { ...counts, loopback: counts.loopback + 1 }
        : { ...counts, nonLoopback: counts.nonLoopback + 1 };
    },
    { loopback: 0, nonLoopback: 0 },
  );
}

/** Recognize the IPv4 127/8 and IPv6 ::1 loopback bindings in lsof socket rows. */
function isLoopbackBinding(line: string): boolean {
  return /(?:127(?:\.\d{1,3}){3}|\[::1\]|localhost)(?::|\s|$)/i.test(line);
}

/** Map one command result to an explicit source availability without aggregation. */
function availability(result: SecurityNetworkCommandResult): SecurityNetworkEvidenceAvailability {
  return result.status === 'completed' ? 'available' : result.status;
}

/** Interpret the supported ALF state text conservatively. */
function parseApplicationFirewallSetting(
  result: SecurityNetworkCommandResult,
): SecurityNetworkSetting {
  if (result.status !== 'completed') return 'unknown';
  if (/\b(enabled|state\s*=\s*1)\b/i.test(result.stdout)) return 'enabled';
  if (/\b(disabled|state\s*=\s*0)\b/i.test(result.stdout)) return 'disabled';
  return 'unknown';
}
