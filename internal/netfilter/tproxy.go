// Package netfilter provides TProxy support for UDP transparent proxying
package netfilter

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
)

// TProxyManager manages TProxy rules for UDP transparent proxying
type TProxyManager struct {
	cfg       *config.TorConfig
	mu        sync.Mutex
	active    bool
	markValue int
	tableID   int
}

// NewTProxyManager creates a new TProxy manager
func NewTProxyManager(cfg *config.TorConfig) *TProxyManager {
	return &TProxyManager{
		cfg:       cfg,
		markValue: 100, // Packet mark for routing
		tableID:   100, // Custom routing table ID
	}
}

// Apply sets up TProxy rules for UDP
func (t *TProxyManager) Apply() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.active {
		return fmt.Errorf("TProxy rules already active")
	}

	log := logger.WithComponent("tproxy")
	log.Info().Msg("applying TProxy rules for UDP")

	// Step 1: Create routing policy for marked packets
	if err := t.setupRouting(); err != nil {
		return fmt.Errorf("failed to setup routing: %w", err)
	}

	// Step 2: Apply mangle rules for TProxy
	if err := t.applyMangleRules(); err != nil {
		t.Rollback()
		return fmt.Errorf("failed to apply mangle rules: %w", err)
	}

	t.active = true
	log.Info().Msg("TProxy rules applied successfully")
	return nil
}

// setupRouting configures routing for TProxy marked packets
func (t *TProxyManager) setupRouting() error {
	// Add routing rule: fwmark 100 lookup 100
	if err := exec.Command("ip", "rule", "add", "fwmark", strconv.Itoa(t.markValue), "table", strconv.Itoa(t.tableID)).Run(); err != nil {
		return fmt.Errorf("failed to add ip rule: %w", err)
	}

	// Add route in custom table: route everything to localhost
	if err := exec.Command("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(t.tableID)).Run(); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

// applyMangleRules sets up iptables mangle rules for TProxy
func (t *TProxyManager) applyMangleRules() error {
	// Mark UDP packets (except DNS which is already handled)
	markRule := []string{
		"-t", "mangle", "-A", "PREROUTING",
		"-p", "udp",
		"!", "--dport", "53",
		"-j", "TPROXY",
		"--on-port", strconv.Itoa(t.cfg.TransPort + 1), // Use TransPort+1 for UDP
		"--tproxy-mark", fmt.Sprintf("%d/%d", t.markValue, t.markValue),
	}

	if err := exec.Command("iptables", markRule...).Run(); err != nil {
		return fmt.Errorf("failed to add TPROXY rule: %w", err)
	}

	// Mark outgoing UDP for routing
	outputMark := []string{
		"-t", "mangle", "-A", "OUTPUT",
		"-p", "udp",
		"!", "--dport", "53",
		"-m", "owner", "!", "--uid-owner", "0",
		"-j", "MARK", "--set-mark", strconv.Itoa(t.markValue),
	}

	if err := exec.Command("iptables", outputMark...).Run(); err != nil {
		return fmt.Errorf("failed to add OUTPUT mark rule: %w", err)
	}

	return nil
}

// Rollback removes TProxy rules
func (t *TProxyManager) Rollback() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	log := logger.WithComponent("tproxy")
	log.Info().Msg("rolling back TProxy rules")

	// Remove mangle rules
	exec.Command("iptables", "-t", "mangle", "-D", "PREROUTING",
		"-p", "udp", "!", "--dport", "53",
		"-j", "TPROXY",
		"--on-port", strconv.Itoa(t.cfg.TransPort+1),
		"--tproxy-mark", fmt.Sprintf("%d/%d", t.markValue, t.markValue)).Run()

	exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT",
		"-p", "udp", "!", "--dport", "53",
		"-m", "owner", "!", "--uid-owner", "0",
		"-j", "MARK", "--set-mark", strconv.Itoa(t.markValue)).Run()

	// Remove routing
	exec.Command("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(t.tableID)).Run()
	exec.Command("ip", "rule", "del", "fwmark", strconv.Itoa(t.markValue), "table", strconv.Itoa(t.tableID)).Run()

	t.active = false
	log.Info().Msg("TProxy rules rolled back")
	return nil
}

// IsActive returns whether TProxy is active
func (t *TProxyManager) IsActive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active
}

// UDPProxyListener is a TProxy UDP listener
type UDPProxyListener struct {
	conn      *net.UDPConn
	socksAddr string
	running   bool
	mu        sync.Mutex
}

// NewUDPProxyListener creates a UDP TProxy listener
func NewUDPProxyListener(listenAddr, socksAddr string) (*UDPProxyListener, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	// Create raw socket for TProxy
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP listener: %w", err)
	}

	// Set socket options for TProxy (IP_TRANSPARENT)
	// Note: This requires CAP_NET_ADMIN
	rawConn, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var setOptErr error
	rawConn.Control(func(fd uintptr) {
		// SOL_IP = 0, IP_TRANSPARENT = 19
		setOptErr = setSocketOption(int(fd), 0, 19, 1)
	})

	if setOptErr != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set IP_TRANSPARENT: %w", setOptErr)
	}

	return &UDPProxyListener{
		conn:      conn,
		socksAddr: socksAddr,
	}, nil
}

// Start starts the UDP proxy
func (u *UDPProxyListener) Start() error {
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return fmt.Errorf("already running")
	}
	u.running = true
	u.mu.Unlock()

	log := logger.WithComponent("udp-proxy")
	log.Info().Str("addr", u.conn.LocalAddr().String()).Msg("starting UDP proxy")

	go u.handleConnections()
	return nil
}

func (u *UDPProxyListener) handleConnections() {
	log := logger.WithComponent("udp-proxy")
	buf := make([]byte, 65535)

	for {
		u.mu.Lock()
		if !u.running {
			u.mu.Unlock()
			return
		}
		u.mu.Unlock()

		n, remoteAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			log.Debug().Err(err).Msg("read error")
			continue
		}

		// For now, log the UDP traffic
		// Full implementation would tunnel through SOCKS5 UDP associate
		log.Debug().
			Str("from", remoteAddr.String()).
			Int("bytes", n).
			Msg("UDP packet received")

		// TODO: Implement SOCKS5 UDP ASSOCIATE to tunnel UDP through Tor
	}
}

// Stop stops the UDP proxy
func (u *UDPProxyListener) Stop() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.running = false
	if u.conn != nil {
		u.conn.Close()
	}
	return nil
}

// setSocketOption sets a socket option
func setSocketOption(fd, level, opt, value int) error {
	// Use syscall to set socket option
	return syscall.SetsockoptInt(fd, level, opt, value)
}
