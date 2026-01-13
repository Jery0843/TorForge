# TorForge Threat Model

> [!WARNING]
> **TorForge is experimental software.** It has not undergone formal security audit. Use at your own risk and do not rely on it for life-or-death anonymity needs.

This document defines what TorForge protects against, what it does **not** protect against, and the assumptions it makes.

## Protected Threats

| Threat | How TorForge Mitigates |
|--------|------------------------|
| **ISP surveillance** | All traffic routed through Tor; ISP sees only encrypted Tor traffic |
| **Captive portals** | Traffic bypasses local network inspection |
| **Network censorship** | Pluggable transports (obfs4, Snowflake) disguise Tor traffic |
| **Passive network observer** | Tor's 3-hop routing prevents correlation between source and destination |
| **DNS leaks** | DNS forced through Tor's DNS port; non-Tor DNS blocked |
| **IP leaks from apps** | Kernel-level iptables capture; no app can bypass |
| **Accidental non-Tor traffic** | Kill switch (default DROP) blocks any traffic that doesn't match Tor rules |

## NOT Protected (Explicit Limitations)

> [!CAUTION]
> TorForge is **not** a complete anonymity solution. The following threats are **out of scope**:

| Threat | Why NOT Protected |
|--------|-------------------|
| **Browser fingerprinting** | TorForge operates at the network layer; it cannot control browser behavior (canvas, fonts, screen size, JS APIs). **Use Tor Browser over TorForge for web anonymity.** |
| **Global passive adversary** | An entity observing both entry and exit traffic (e.g., nation-state with global visibility) can correlate timing. This is a fundamental Tor limitation. |
| **Targeted traffic analysis** | If an adversary knows you're using Tor and can observe your entry guard + target destination, statistical correlation is possible over time. |
| **Application-layer leaks** | Apps may leak identity via cookies, login sessions, unique identifiers, or metadata. TorForge only anonymizes IP. |
| **WebRTC IP leaks** | Browsers can expose local IP via WebRTC. TorForge's iptables blocks this at the network level, but you should disable WebRTC in browsers. |
| **Malicious exit nodes** | Unencrypted traffic (HTTP) is visible to exit nodes. **Always use HTTPS.** |

## Assumptions (Trusted Components)

TorForge assumes the following are **not compromised**:

| Component | Why Trusted |
|-----------|-------------|
| **Linux kernel** | iptables rules depend on kernel integrity; a compromised kernel can bypass any userspace protection |
| **Tor binary** | We use the system Tor package or embedded Tor; a backdoored Tor defeats all anonymity |
| **System clock** | Time synchronization is important for Tor circuits; significant clock skew can be a fingerprint |
| **Root access** | TorForge runs with root privileges for iptables; a root compromise means full system compromise |

## Threat Matrix Summary

```
                        ┌─────────────────────────────────────┐
                        │          TorForge Scope             │
                        │                                     │
    ✅ PROTECTED        │  ❌ NOT PROTECTED                   │
    ─────────────       │  ────────────────                   │
    • ISP surveillance  │  • Browser fingerprinting           │
    • DNS leaks         │  • Global passive adversary         │
    • IP leaks          │  • Targeted traffic analysis        │
    • Censorship        │  • App-layer leaks (cookies, etc)   │
    • Passive observer  │  • Malicious exit node (use HTTPS)  │
                        │                                     │
                        └─────────────────────────────────────┘
```

## Recommendations for Maximum Anonymity

1. **Use Tor Browser** over TorForge for web browsing (handles fingerprinting)
2. **Enable HTTPS Everywhere** (protects from malicious exits)
3. **Disable WebRTC** in browser settings
4. **Don't log into personal accounts** while using Tor
5. **Use `--no-ai` flag** if concerned about any local learning patterns
6. **Consider Whonix or Tails** for high-risk threat models
