# TorForge Architecture

## System Overview

TorForge operates as a transparent proxy using iptables NAT rules.

```
┌─────────────────────────────────────────────────────────────┐
│ Applications                                                 │
│ (browser, curl, any TCP client)                             │
└──────────────────────┬──────────────────────────────────────┘
                       │ Outbound TCP/DNS
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ iptables NAT                                                │
│ • OUTPUT chain → TORFORGE_NAT                               │
│ • DNS (53) → redirect to Tor DNS port (5353)                │
│ • TCP → redirect to Tor TransPort (9040)                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Tor Process                                                  │
│ • TransPort 9040 (transparent proxy)                         │
│ • DNSPort 5353 (DNS resolver)                                │
│ • ControlPort 9051 (circuit management)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  Tor Network   │
              │ Guard → Middle │
              │   → Exit       │
              └────────────────┘
```

## Kill Switch (iptables FILTER)

If the NAT rules fail to redirect traffic, the FILTER chain drops it:

```
FILTER OUTPUT chain
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ TORFORGE_FILTER                                              │
│ 1. ACCEPT established/related (existing Tor circuits)       │
│ 2. ACCEPT owner=tor_uid (Tor process outbound)              │
│ 3. ACCEPT owner=root (embedded Tor mode)                    │
│ 4. ACCEPT -o lo (loopback)                                   │
│ 5. ACCEPT -p tcp (will be redirected by NAT)                │
│ 6. DROP -p icmp (ping leaks IP via timing)                  │
│ 7. DROP -p udp (non-DNS UDP blocked)                        │
│ 8. DROP default (catch-all kill switch)                     │
└─────────────────────────────────────────────────────────────┘
```

## Package Dependencies

```
cmd/torforge/main.go
       │
       ▼
internal/proxy/proxy.go  ←── Main controller
       │
       ├── internal/tor/         (Tor process management)
       ├── internal/netfilter/   (iptables rules)
       ├── internal/ai/          (ML circuit selection)
       ├── internal/security/    (PQ encryption, panic)
       └── internal/bypass/      (bypass rules)

pkg/
├── config/   (YAML config loading)
└── logger/   (structured logging)
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| iptables vs nftables | Broader kernel support; nftables planned for v2 |
| Embedded Tor vs system Tor | User choice via `--use-system-tor`; embedded is default for isolation |
| Pure-Go ML | No Python dependency = smaller attack surface |
| 1-hour exclusion TTL | Balance stability vs adaptability; exit performance fluctuates |
| Max 5 exit exclusions | Prevent Tor errors from over-filtering |
| Argon2id for PQ password | Memory-hard, resistant to GPU/ASIC attacks |
| Function key for panic | Unambiguous activation, quick access in emergencies |
