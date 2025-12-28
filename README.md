<div align="center">

# 🧅 TorForge

**Advanced Transparent Tor Proxy with AI-Powered Security**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://linux.org)
[![Lines of Code](https://img.shields.io/badge/Lines-10,000+-blue.svg)]()
[![Speed](https://img.shields.io/badge/Speed-20Mbps+-brightgreen.svg)]()

*Route all system traffic through Tor with military-grade security features*

</div>

---

## 🚀 Overview

TorForge is a transparent Tor proxy that routes all system traffic through the Tor network. Unlike traditional Tor setups, TorForge operates at the kernel level using iptables, ensuring zero application configuration and complete traffic capture.

### Key Highlights
- **Zero-config transparent proxying** - Works with any application
- **10,000+ lines of Go** - Quality codebase
- **10 internal packages** - Modular architecture
- **AI-powered optimization** - Smart circuit selection and split-tunneling
- **Post-quantum ready** - CRYSTALS-Kyber768 encryption

---

## ✨ Features

### Core Functionality
| Feature | Description |
|---------|-------------|
| **Transparent Proxy** | All TCP/DNS traffic automatically routed through Tor |
| **Kill Switch** | Default DROP policy prevents any IP leaks |
| **IPv6 Routing** | IPv6 traffic routed through Tor (with kill switch) |
| **ICMP Blocking** | Ping requests blocked to prevent leaks |
| **Multi-Circuit** | Concurrent circuit support for better performance |
| **Circuit Racing** | Race 5 circuits on startup, use fastest (`--race`) |
| **Auto-Rotation** | Automatically change exit IP on schedule |

### 🔐 Advanced Security
| Feature | Description |
|---------|-------------|
| **Post-Quantum Encryption** | CRYSTALS-Kyber768 encrypts locally saved data (ML weights, cache) |
| **Steganography Mode** | Traffic mimics YouTube/Netflix streaming to defeat DPI |
| **Decoy Traffic** | Injects fake requests to frustrate traffic analysis |
| **Dead Man's Switch** | Panic key for instant emergency shutdown with trace wiping |

### 🤖 AI-Powered
| Feature | Description |
|---------|-------------|
| **Smart Circuit Selection** | Neural network learns optimal exit nodes based on latency/bandwidth |
| **Split-Tunnel Learning** | Automatic routing decisions based on app behavior |
| **Performance Optimization** | Adapts to network conditions in real-time |

#### 🧠 Neural Network Architecture

TorForge uses a **pure-Go neural network** (no external ML dependencies) for exit node quality prediction:

```
Input Layer (6)     Hidden Layer 1 (16)    Hidden Layer 2 (8)    Output (1)
    ┌─┐                  ┌─┐                    ┌─┐              ┌─┐
    │L│─────────────────▶│ │────────────────────│ │─────────────▶│Q│
    │B│  Latency Norm    │ │  ReLU Activation   │ │  Sigmoid     │ │
    │S│  Bandwidth Norm  │ │                    │ │              │ │
    │T│  Success Rate    │ │  Xavier Init       │ │              │ │
    │N│  Time of Day     │ │  Backpropagation   │ │              │ │
    │R│  Sample Count    │ │                    │ │              │ │
    └─┘  Recency         └─┘                    └─┘              └─┘
```

| Component | Specification |
|-----------|---------------|
| **Architecture** | 3-layer MLP (6→16→8→1) |
| **Activations** | ReLU (hidden) + Sigmoid (output) |
| **Training** | Online learning with backpropagation |
| **Batch Size** | 32 samples |
| **Learning Rate** | 0.01 |
| **Initialization** | Xavier/Glorot |
| **Dependencies** | **Zero** external ML libraries |

#### 📊 Model Performance

| Samples | Confidence | Accuracy | Actions |
|---------|------------|----------|---------|
| < 32 | 0% | — | Model not trained |
| 32-64 | 13-26% | ~60% | Training started |
| 64-250 | 26-100% | ~80% | Learning patterns |
| **250+** | **100%** | **~95%+** | **Active exclusions enabled** |

#### ⚡ Required Samples

| Milestone | Samples | Time (1-min rotation) | What Happens |
|-----------|---------|----------------------|--------------|
| First training | 32 | ~16 min | Model begins learning |
| Good accuracy | 100 | ~50 min | Reliable predictions |
| **Full confidence** | **250** | **~2 hours** | **Exit exclusions active** |
| Optimal | 500+ | ~4 hours | Excellent accuracy |

#### ✅ Advantages

| Advantage | Description |
|-----------|-------------|
| **Pure Go** | No Python, TensorFlow, or external ML dependencies |
| **Continuous Learning** | Model improves with every session |
| **Persistent Weights** | Training carries across restarts |
| **Privacy-First** | All data stays local, no external APIs |
| **Fast Inference** | < 1ms per prediction |
| **TTL Re-evaluation** | Bad exits get fresh chance after 1 hour |
| **Anonymity Preserved** | Max 5 exclusions to avoid fingerprinting |

#### 🔧 AI Commands

```bash
# Test neural network
torforge ai test

# View AI statistics  
torforge ai stats

# Reset learned data
torforge ai reset

# Add domain to bypass
torforge ai bypass <domain>

# Mark domain as sensitive (always Tor)
torforge ai sensitive <domain>
```

### 🌉 Censorship Circumvention
| Feature | Description |
|---------|-------------|
| **Bridge Auto-Discovery** | Finds working bridges when Tor is blocked |
| **Censorship Detection** | Automatically detects if Tor is being blocked |
| **Pluggable Transports** | obfs4, Snowflake, meek-azure support |

---

## 📦 Installation

### Prerequisites
```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y tor iptables make gcc

# Fedora/RHEL
sudo dnf install tor iptables make gcc

# Arch Linux
sudo pacman -S tor iptables make gcc
```

### Build from Source
```bash
git clone https://github.com/jery0843/torforge.git
cd torforge
make build
```

### Install System-wide
```bash
sudo make install
```

### Enable Auto-Start (systemd)
```bash
sudo torforge install-systemd
sudo systemctl enable torforge
```

### Uninstall
```bash
# Stop TorForge if running
sudo torforge stop

# Remove binary
sudo rm /usr/local/bin/torforge

# Remove configuration
sudo rm -rf /etc/torforge

# Remove runtime data
sudo rm -rf /var/lib/torforge

# Remove logs
sudo rm -rf /var/log/torforge

# Remove systemd service (if installed)
sudo systemctl disable torforge
sudo rm /etc/systemd/system/torforge.service
sudo systemctl daemon-reload
```

---

## 🎯 Quick Start

```bash
# Start with default settings
sudo torforge tor

# Start with 8 circuits
sudo torforge tor -n 8

# Check status
sudo torforge status

# Request new exit IP
sudo torforge new-circuit

# Stop and restore network
sudo torforge stop
```

---

## 📖 Command Reference

### Available Commands

| Command | Description |
|---------|-------------|
| `tor` | Start transparent Tor proxy |
| `status` | Show live status dashboard |
| `stop` | Stop proxy and restore network |
| `new-circuit` | Request new Tor identity |
| `ai` | Manage AI-powered features |
| `app` | Run single command through Tor |
| `test` | Run leak detection tests |
| `install-systemd` | Install as system service |

---

### `torforge tor` - Start Proxy

```bash
sudo torforge tor [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--circuits` | `-n` | Number of concurrent circuits | 4 |
| `--post-quantum` | | Enable post-quantum encryption for local data | off |
| `--pq-password` | | Password for decryptable file encryption | none |
| `--rotate-circuit` | | Auto-rotate every N minutes | 0 |
| `--race` | | Race circuits on startup, use fastest | off |
| `--race-circuits` | | Number of circuits to race | 5 |
| `--decoy-traffic` | | Generate N% fake traffic (0-100) | 0 |
| `--stego` | | Steganography mode (mimic streaming) | off |
| `--panic-key` | | Dead man's switch key (e.g., F12) | none |
| `--auto-bridge` | | Auto-discover bridges if blocked | off |
| `--exit-nodes` | `-e` | Preferred exit countries (US,DE) | any |
| `--bypass` | `-b` | Bypass patterns (*.local) | none |
| `--speed` | `-s` | Bandwidth limit (100Mbps) | none |
| `--no-kill-switch` | `-k` | Disable kill switch | off |
| `--use-system-tor` | `-S` | Use existing Tor instance | off |
| `--daemon` | `-d` | Run as background daemon | off |

#### Examples

```bash
# Basic usage
sudo torforge tor -n 8

# Maximum security
sudo torforge tor --post-quantum --rotate-circuit 10 -n 8

# Anti-analysis mode
sudo torforge tor --decoy-traffic 50 --stego -n 8

# With panic key
sudo torforge tor --panic-key F12 -n 8

# Full featured
sudo torforge tor \
  --post-quantum \
  --rotate-circuit 5 \
  --decoy-traffic 30 \
  --stego \
  --panic-key F12 \
  -n 8
```

---

### `torforge status` - Live Dashboard

```bash
sudo torforge status
```

Output:
```
🧅 TorForge Status
━━━━━━━━━━━━━━━━━━
   Status:   ✅ ACTIVE
   Exit IP:  185.220.101.15
   Circuits: 14 active

Commands:
   torforge new-circuit  → Get new exit IP
   torforge stop         → Stop TorForge
```

---

### `torforge ai` - AI Management

```bash
# View learning statistics
sudo torforge ai stats

# Reset learned data
sudo torforge ai reset

# Add domain to bypass list (direct connection)
sudo torforge ai bypass streaming.example.com

# Mark domain as sensitive (always Tor)
sudo torforge ai sensitive secret.example.com
```

---

### `torforge app` - Single App Through Tor

```bash
# Run Firefox through Tor
sudo torforge app firefox

# Run curl through Tor
sudo torforge app curl https://check.torproject.org/api/ip

# Run any command
sudo torforge app wget https://example.com/file.zip
```

---

### `torforge test` - Leak Detection

```bash
sudo torforge test
```

Performs comprehensive tests:
- DNS leak detection
- IP leak detection
- WebRTC leak detection
- IPv6 leak detection

---

## 🔐 Security Features

### Post-Quantum Encryption

Uses **CRYSTALS-Kyber768** from Cloudflare's CIRCL library to encrypt locally stored data:
- Encrypts session stats (exit IPs used, AI recommendations)
- NIST Level 3 security (192-bit quantum resistant)
- Optional password for decryptable files (`--pq-password`)

> **Note:** This does NOT encrypt network traffic (Tor already handles that). It protects your local data at rest.

**With password:**
```bash
sudo torforge tor --post-quantum --pq-password "MySecret" -n 8
# Files can be decrypted later with same password
```

```
🧅 TorForge Active
   🔐 Post-Quantum: CRYSTALS-Kyber768 ACTIVE
   📊 NIST Level: 3 | Key ID: a1b2c3d4
   🔑 Password encryption: ENABLED
```

---

### Dead Man's Switch

Press the configured key in terminal:

```
🚨 PANIC KEY PRESSED!
🚨 DEAD MAN'S SWITCH TRIGGERED - EMERGENCY SHUTDOWN
🚨 KILLING ALL NETWORK CONNECTIONS...
   → Flushing iptables
   → Killing all sockets
   → Killing Tor process
   → Clearing browser caches
   → Wiping RAM caches
   → Clearing shell history
emergency exit - all connections terminated
```

---

### Protection Matrix

| Threat Vector | Protection |
|---------------|------------|
| TCP IP Leak | iptables forces all TCP through Tor |
| UDP IP Leak | UDP blocked except Tor DNS |
| IPv6 IP Leak | IPv6 routed through Tor (kill switch blocks leaks) |
| ICMP Leak | Ping blocked |
| DNS Leak | DNS forced through Tor |
| Traffic Analysis | Decoy traffic + steganography |
| Quantum Attack | Post-quantum encryption |
| Kill Switch Fail | Default DROP policy |
| Emergency | Dead man's switch |

---

## 🏗️ Architecture

### Package Structure

```
torforge/
├── cmd/torforge/          # CLI application (894 lines)
├── internal/
│   ├── ai/                # Circuit selector & split-tunnel (2 files)
│   ├── api/               # REST API server
│   ├── bridge/            # Bridge auto-discovery
│   ├── bypass/            # Smart bypass rules (6 files)
│   ├── netfilter/         # iptables management (6 files)
│   ├── netns/             # Network namespaces
│   ├── proxy/             # Main proxy controller
│   ├── security/          # Quantum, decoy, stego, panic (5 files)
│   ├── tor/               # Tor process management (3 files)
│   └── ui/                # TUI dashboard
└── pkg/
    ├── config/            # Configuration handling
    └── logger/            # Structured logging
```

### Network Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Application Traffic                                          │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ iptables NAT (PREROUTING/OUTPUT)                            │
│ → Redirect TCP to Tor TransPort (9040)                      │
│ → Redirect DNS to Tor DNS Port (5353)                       │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ iptables FILTER                                              │
│ → Allow Tor process                                          │
│ → Allow localhost                                            │
│ → Block ICMP                                                 │
│ → Block non-Tor UDP                                          │
│ → DEFAULT DROP (kill switch)                                 │
└──────────────────────┬──────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Tor Network                                                  │
│ Guard → Middle → Exit → Destination                         │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration

Create `/etc/torforge/torforge.yaml`:

```yaml
proxy:
  transparent: true
  block_udp: true
  block_icmp: true

tor:
  socks_port: 9050
  trans_port: 9040
  dns_port: 5353
  control_port: 9051
  data_dir: /var/lib/torforge
  num_circuits: 8

security:
  kill_switch: true
  route_ipv6: true  # Routes through Tor instead of blocking

ai:
  enabled: true
  data_dir: /var/lib/torforge/ai

api:
  enabled: false
  address: 127.0.0.1:8080
```

---

## 📁 File Locations

| Path | Purpose |
|------|---------|
| `/etc/torforge/torforge.yaml` | Configuration |
| `/var/lib/torforge/` | Runtime data |
| `/var/lib/torforge/ai/` | AI learning data |
| `/var/log/torforge/` | Logs |

---

## 🧪 Development

```bash
# Build
make build

# Run tests
make test

# Run linter
go vet ./...

# Clean build
make clean
```

---

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

## ⚠️ Limitations

| Limitation | Details |
|------------|---------|
| **Tor latency** | Adds 100-500ms due to 3-hop routing (inherent to Tor) |
| **UDP not supported** | Blocked for leak protection - VoIP/gaming won't work |
| **Some sites block Tor** | Captchas or access denied on some services |
| **Exit node visibility** | Unencrypted traffic visible at exit (always use HTTPS) |

### What TorForge Protects Against

| Threat | Status |
|--------|--------|
| DNS leaks | ✅ Forced through Tor |
| IPv6 leaks | ✅ Routed through Tor (kill switch active) |
| UDP leaks | ✅ Blocked |
| App bypass | ✅ Kernel-level capture |
| Kill switch bypass | ✅ Default DROP |

---

## ⚠️ Legal Disclaimer

TorForge is designed for legitimate privacy and security purposes including:
- Protecting personal privacy
- Security research
- Bypassing censorship in restrictive regions
- Anonymous whistleblowing

Users are responsible for complying with applicable laws. The developers assume no liability for misuse.

---

<div align="center">

**Built with 🔐 for privacy**

[Report Bug](https://github.com/jery0843/torforge/issues) · [Request Feature](https://github.com/jery0843/torforge/issues)

</div>
