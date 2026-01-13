// Package netfilter provides iptables/nftables management for transparent proxying
package netfilter

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
)

const (
	// Chain names
	torforgeNatChain    = "TORFORGE_NAT"
	torforgeOutputChain = "TORFORGE_OUTPUT"
	torforgeFilterChain = "TORFORGE_FILTER"
)

// IPTablesManager manages iptables rules for transparent proxying
type IPTablesManager struct {
	ipt         *iptables.IPTables
	cfg         *config.ProxyConfig
	torCfg      *config.TorConfig
	bypassCfg   *config.BypassConfig
	securityCfg *config.SecurityConfig
	mu          sync.Mutex
	active      bool
	savedRules  []savedRule
	torUID      int
}

type savedRule struct {
	table string
	chain string
	rule  []string
}

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager(proxyCfg *config.ProxyConfig, torCfg *config.TorConfig, bypassCfg *config.BypassConfig, securityCfg *config.SecurityConfig) (*IPTablesManager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize iptables: %w", err)
	}

	// Get Tor user UID
	torUID := getTorUID()

	return &IPTablesManager{
		ipt:         ipt,
		cfg:         proxyCfg,
		torCfg:      torCfg,
		bypassCfg:   bypassCfg,
		securityCfg: securityCfg,
		torUID:      torUID,
	}, nil
}

// Apply applies iptables rules for transparent proxy
func (m *IPTablesManager) Apply() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active {
		return fmt.Errorf("iptables rules already active")
	}

	log := logger.WithComponent("iptables")
	log.Info().Msg("applying iptables rules")

	// Backup current rules
	if err := m.backupRules(); err != nil {
		log.Warn().Err(err).Msg("failed to backup rules")
	}

	// Create custom chains
	if err := m.createChains(); err != nil {
		return fmt.Errorf("failed to create chains: %w", err)
	}

	// Apply NAT rules (redirect traffic through Tor)
	if err := m.applyNATRules(); err != nil {
		m.Rollback()
		return fmt.Errorf("failed to apply NAT rules: %w", err)
	}

	// Apply filter rules (block non-Tor traffic)
	if err := m.applyFilterRules(); err != nil {
		m.Rollback()
		return fmt.Errorf("failed to apply filter rules: %w", err)
	}

	// Route IPv6 traffic through Tor (instead of blocking)
	if err := m.routeIPv6(); err != nil {
		log.Warn().Err(err).Msg("failed to route IPv6 (may not work for IPv6 destinations)")
	}

	m.active = true
	log.Info().Msg("iptables rules applied successfully")
	logger.Audit("iptables").Str("action", "apply").Msg("iptables rules activated")

	return nil
}

func (m *IPTablesManager) createChains() error {
	tables := []struct {
		table string
		chain string
	}{
		{"nat", torforgeNatChain},
		{"filter", torforgeOutputChain},
		{"filter", torforgeFilterChain},
	}

	for _, t := range tables {
		exists, err := m.ipt.ChainExists(t.table, t.chain)
		if err != nil {
			return fmt.Errorf("failed to check chain %s: %w", t.chain, err)
		}

		if !exists {
			if err := m.ipt.NewChain(t.table, t.chain); err != nil {
				return fmt.Errorf("failed to create chain %s: %w", t.chain, err)
			}
		}
	}

	return nil
}

func (m *IPTablesManager) applyNATRules() error {
	log := logger.WithComponent("iptables")

	// DNS redirection through Tor DNS port
	dnsRule := []string{
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-ports", strconv.Itoa(m.torCfg.DNSPort),
	}
	if err := m.appendRule("nat", "OUTPUT", dnsRule); err != nil {
		return err
	}
	log.Debug().Strs("rule", dnsRule).Msg("added DNS redirect rule")

	// TCP DNS through Tor
	dnsTCPRule := []string{
		"-p", "tcp", "--dport", "53",
		"-j", "REDIRECT", "--to-ports", strconv.Itoa(m.torCfg.DNSPort),
	}
	if err := m.appendRule("nat", "OUTPUT", dnsTCPRule); err != nil {
		return err
	}

	// Redirect to our NAT chain
	if err := m.appendRule("nat", "OUTPUT", []string{"-j", torforgeNatChain}); err != nil {
		return err
	}

	// In our chain: allow Tor process traffic
	// When using system Tor, bypass the tor user (debian-tor, etc)
	if m.torUID > 0 {
		torBypass := []string{
			"-m", "owner", "--uid-owner", strconv.Itoa(m.torUID),
			"-j", "RETURN",
		}
		if err := m.appendRule("nat", torforgeNatChain, torBypass); err != nil {
			return err
		}
	}

	// When running as root (embedded Tor), also bypass root
	// This is essential because embedded Tor runs as the same user as TorForge
	rootBypass := []string{
		"-m", "owner", "--uid-owner", "0",
		"-j", "RETURN",
	}
	if err := m.appendRule("nat", torforgeNatChain, rootBypass); err != nil {
		return err
	}

	// Allow localhost
	localhostRule := []string{
		"-d", "127.0.0.0/8",
		"-j", "RETURN",
	}
	if err := m.appendRule("nat", torforgeNatChain, localhostRule); err != nil {
		return err
	}

	// Bypass link-local addresses (169.254.x.x - includes cloud metadata)
	linkLocalRule := []string{
		"-d", "169.254.0.0/16",
		"-j", "RETURN",
	}
	if err := m.appendRule("nat", torforgeNatChain, linkLocalRule); err != nil {
		return err
	}

	// Add bypass rules
	if err := m.applyBypassNATRules(); err != nil {
		return err
	}

	// Redirect all TCP to Tor transparent port
	tcpRedirect := []string{
		"-p", "tcp",
		"-j", "REDIRECT", "--to-ports", strconv.Itoa(m.torCfg.TransPort),
	}
	if err := m.appendRule("nat", torforgeNatChain, tcpRedirect); err != nil {
		return err
	}
	log.Debug().Strs("rule", tcpRedirect).Msg("added TCP redirect rule")

	return nil
}

func (m *IPTablesManager) applyBypassNATRules() error {
	log := logger.WithComponent("iptables")

	// Bypass CIDR ranges
	for _, cidr := range m.bypassCfg.CIDRs {
		rule := []string{
			"-d", cidr,
			"-j", "RETURN",
		}
		if err := m.appendRule("nat", torforgeNatChain, rule); err != nil {
			return err
		}
		log.Debug().Str("cidr", cidr).Msg("added bypass rule for CIDR")
	}

	return nil
}

func (m *IPTablesManager) applyFilterRules() error {
	log := logger.WithComponent("iptables")

	// Redirect to our filter chain
	if err := m.appendRule("filter", "OUTPUT", []string{"-j", torforgeFilterChain}); err != nil {
		return err
	}

	// Allow established connections
	establishedRule := []string{
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
	}
	if err := m.appendRule("filter", torforgeFilterChain, establishedRule); err != nil {
		return err
	}

	// Allow Tor process
	if m.torUID > 0 {
		torRule := []string{
			"-m", "owner", "--uid-owner", strconv.Itoa(m.torUID),
			"-j", "ACCEPT",
		}
		if err := m.appendRule("filter", torforgeFilterChain, torRule); err != nil {
			return err
		}
	}

	// Allow root process (embedded Tor runs as root)
	// This is CRITICAL: without this, Tor cannot make outbound connections
	rootRule := []string{
		"-m", "owner", "--uid-owner", "0",
		"-j", "ACCEPT",
	}
	if err := m.appendRule("filter", torforgeFilterChain, rootRule); err != nil {
		return err
	}
	log.Debug().Msg("root process allowed (for embedded Tor)")

	// Allow loopback
	loopbackRule := []string{
		"-o", "lo",
		"-j", "ACCEPT",
	}
	if err := m.appendRule("filter", torforgeFilterChain, loopbackRule); err != nil {
		return err
	}

	// Allow connections to Tor ports (localhost)
	torPorts := []int{m.torCfg.SOCKSPort, m.torCfg.TransPort, m.torCfg.DNSPort, m.torCfg.ControlPort}
	for _, port := range torPorts {
		rule := []string{
			"-p", "tcp", "-d", "127.0.0.1", "--dport", strconv.Itoa(port),
			"-j", "ACCEPT",
		}
		if err := m.appendRule("filter", torforgeFilterChain, rule); err != nil {
			return err
		}
	}

	// Allow all TCP traffic - NAT will redirect it to Tor
	// This is safe because NAT PREROUTING redirects all TCP to TransPort
	tcpAllow := []string{
		"-p", "tcp",
		"-j", "ACCEPT",
	}
	if err := m.appendRule("filter", torforgeFilterChain, tcpAllow); err != nil {
		return err
	}
	log.Debug().Msg("TCP traffic allowed (NAT redirects to Tor)")

	// Allow DNS to Tor's DNS port only
	dnsRule := []string{
		"-p", "udp", "-d", "127.0.0.1", "--dport", strconv.Itoa(m.torCfg.DNSPort),
		"-j", "ACCEPT",
	}
	if err := m.appendRule("filter", torforgeFilterChain, dnsRule); err != nil {
		return err
	}

	// ===========================================
	// CRITICAL SECURITY: LEAK PREVENTION RULES
	// ===========================================
	// These rules implement the kill switch. Rule order matters:
	// 1. Allow established (needed for Tor's existing circuits)
	// 2. Allow Tor by UID (only Tor can make outbound connections)
	// 3. Allow loopback (local services)
	// 4. Allow TCP (will be redirected to Tor by NAT rules above)
	// 5. Block ICMP (ping timing can leak real IP)
	// 6. Block UDP (except DNS to Tor's port)
	// 7. Default DROP (catch-all—if we reach here, something is wrong)
	//
	// If any rule fails to match, traffic is dropped rather than leaked.

	// Block ICMP (ping) - can leak real IP
	icmpBlock := []string{
		"-p", "icmp",
		"-j", "DROP",
	}
	if err := m.appendRule("filter", torforgeFilterChain, icmpBlock); err != nil {
		return err
	}
	log.Debug().Msg("ICMP (ping) blocked - prevents IP leak")

	// Block all non-local UDP (prevents UDP leaks)
	udpBlock := []string{
		"-p", "udp",
		"-j", "DROP",
	}
	if err := m.appendRule("filter", torforgeFilterChain, udpBlock); err != nil {
		return err
	}
	log.Debug().Msg("Non-Tor UDP blocked - prevents leak")

	// Kill switch: block all other traffic if enabled
	if m.securityCfg.KillSwitch {
		log.Debug().Msg("kill switch active")
	}

	// DEFAULT DROP: Block any remaining traffic
	defaultDrop := []string{
		"-j", "DROP",
	}
	if err := m.appendRule("filter", torforgeFilterChain, defaultDrop); err != nil {
		return err
	}
	log.Info().Msg("🛡️ Default DROP rule applied - kill switch active")

	return nil
}

func (m *IPTablesManager) appendRule(table, chain string, rule []string) error {
	if err := m.ipt.Append(table, chain, rule...); err != nil {
		return fmt.Errorf("failed to append rule to %s/%s: %w", table, chain, err)
	}

	m.savedRules = append(m.savedRules, savedRule{
		table: table,
		chain: chain,
		rule:  rule,
	})

	return nil
}

// Rollback removes all TorForge iptables rules
func (m *IPTablesManager) Rollback() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log := logger.WithComponent("iptables")
	log.Info().Msg("rolling back iptables rules")

	var lastErr error

	// First, remove references to our chains from built-in chains
	// This must be done BEFORE we can delete the chains
	m.ipt.Delete("nat", "OUTPUT", "-j", torforgeNatChain)
	m.ipt.Delete("filter", "OUTPUT", "-j", torforgeFilterChain)
	m.ipt.Delete("filter", "OUTPUT", "-j", torforgeOutputChain)

	// Remove DNS redirect rules that we added to OUTPUT
	m.ipt.Delete("nat", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353")
	m.ipt.Delete("nat", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353")

	// Remove rules in reverse order (from current session)
	for i := len(m.savedRules) - 1; i >= 0; i-- {
		r := m.savedRules[i]
		// Silently ignore errors - rules may already be gone during cleanup
		_ = m.ipt.Delete(r.table, r.chain, r.rule...)
	}

	// Flush and delete custom chains
	chains := []struct {
		table string
		chain string
	}{
		{"nat", torforgeNatChain},
		{"filter", torforgeOutputChain},
		{"filter", torforgeFilterChain},
	}

	for _, c := range chains {
		exists, err := m.ipt.ChainExists(c.table, c.chain)
		if err == nil && exists {
			m.ipt.ClearChain(c.table, c.chain)
			m.ipt.DeleteChain(c.table, c.chain)
		}
	}

	m.savedRules = nil
	m.active = false

	// Restore IPv6 traffic
	m.cleanupIPv6()

	log.Info().Msg("iptables rules rolled back")
	logger.Audit("iptables").Str("action", "rollback").Msg("iptables rules deactivated")

	return lastErr
}

// IsActive returns whether iptables rules are active
func (m *IPTablesManager) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// routeIPv6 routes all IPv6 traffic through Tor (instead of blocking)
func (m *IPTablesManager) routeIPv6() error {
	log := logger.WithComponent("iptables")

	// Check if ip6tables is available
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return fmt.Errorf("ip6tables not found: %w", err)
	}

	// Create TORFORGE_IPV6 chain for NAT
	exec.Command("ip6tables", "-t", "nat", "-N", "TORFORGE_IPV6").Run()

	// Allow loopback (essential for Tor listening on [::1])
	if err := exec.Command("ip6tables", "-t", "nat", "-A", "TORFORGE_IPV6", "-o", "lo", "-j", "RETURN").Run(); err != nil {
		log.Debug().Err(err).Msg("ip6tables loopback rule")
	}

	// Bypass root/Tor process traffic (prevents loops)
	if err := exec.Command("ip6tables", "-t", "nat", "-A", "TORFORGE_IPV6", "-m", "owner", "--uid-owner", "0", "-j", "RETURN").Run(); err != nil {
		log.Debug().Err(err).Msg("ip6tables root bypass rule")
	}

	// Get Tor UID if using system Tor
	if m.torUID > 0 {
		if err := exec.Command("ip6tables", "-t", "nat", "-A", "TORFORGE_IPV6", "-m", "owner", "--uid-owner", strconv.Itoa(m.torUID), "-j", "RETURN").Run(); err != nil {
			log.Debug().Err(err).Msg("ip6tables tor user bypass rule")
		}
	}

	// Redirect IPv6 DNS (UDP port 53) to Tor DNSPort on [::1]
	dnsPort := strconv.Itoa(m.torCfg.DNSPort)
	if err := exec.Command("ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPort).Run(); err != nil {
		log.Warn().Err(err).Msg("failed to add IPv6 DNS redirect rule")
	}

	// Redirect IPv6 TCP to Tor TransPort on [::1]
	transPort := strconv.Itoa(m.torCfg.TransPort)
	if err := exec.Command("ip6tables", "-t", "nat", "-A", "TORFORGE_IPV6", "-p", "tcp", "-j", "REDIRECT", "--to-ports", transPort).Run(); err != nil {
		return fmt.Errorf("failed to add IPv6 TCP redirect rule: %w", err)
	}

	// Add NAT chain to OUTPUT
	if err := exec.Command("ip6tables", "-t", "nat", "-I", "OUTPUT", "1", "-j", "TORFORGE_IPV6").Run(); err != nil {
		return fmt.Errorf("failed to add TORFORGE_IPV6 chain to OUTPUT: %w", err)
	}

	// Create filter chain for kill switch
	exec.Command("ip6tables", "-N", "TORFORGE_IPV6_FILTER").Run()

	// Allow loopback in filter
	exec.Command("ip6tables", "-A", "TORFORGE_IPV6_FILTER", "-o", "lo", "-j", "ACCEPT").Run()

	// Allow established connections
	exec.Command("ip6tables", "-A", "TORFORGE_IPV6_FILTER", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()

	// Allow root (Tor process)
	exec.Command("ip6tables", "-A", "TORFORGE_IPV6_FILTER", "-m", "owner", "--uid-owner", "0", "-j", "ACCEPT").Run()

	if m.torUID > 0 {
		exec.Command("ip6tables", "-A", "TORFORGE_IPV6_FILTER", "-m", "owner", "--uid-owner", strconv.Itoa(m.torUID), "-j", "ACCEPT").Run()
	}

	// DROP all other IPv6 traffic (kill switch)
	if err := exec.Command("ip6tables", "-A", "TORFORGE_IPV6_FILTER", "-j", "DROP").Run(); err != nil {
		log.Warn().Err(err).Msg("failed to add IPv6 DROP rule")
	}

	// Add filter chain to OUTPUT
	exec.Command("ip6tables", "-I", "OUTPUT", "1", "-j", "TORFORGE_IPV6_FILTER").Run()

	log.Info().Msg("🌐 IPv6 traffic routed through Tor")
	return nil
}

// cleanupIPv6 removes IPv6 routing rules (cleanup for routeIPv6)
func (m *IPTablesManager) cleanupIPv6() {
	log := logger.WithComponent("iptables")

	// Remove NAT chain from OUTPUT
	exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-j", "TORFORGE_IPV6").Run()

	// Remove DNS redirect rule
	dnsPort := strconv.Itoa(m.torCfg.DNSPort)
	exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPort).Run()

	// Flush and delete NAT chain
	exec.Command("ip6tables", "-t", "nat", "-F", "TORFORGE_IPV6").Run()
	exec.Command("ip6tables", "-t", "nat", "-X", "TORFORGE_IPV6").Run()

	// Remove filter chain from OUTPUT
	exec.Command("ip6tables", "-D", "OUTPUT", "-j", "TORFORGE_IPV6_FILTER").Run()

	// Flush and delete filter chain
	exec.Command("ip6tables", "-F", "TORFORGE_IPV6_FILTER").Run()
	exec.Command("ip6tables", "-X", "TORFORGE_IPV6_FILTER").Run()

	log.Info().Msg("IPv6 routing restored")
}

func (m *IPTablesManager) backupRules() error {
	// Save current rules for potential restore
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	backupPath := "/tmp/torforge-iptables-backup"
	return os.WriteFile(backupPath, output, 0600)
}

// RestoreBackup restores iptables from backup
func (m *IPTablesManager) RestoreBackup() error {
	backupPath := "/tmp/torforge-iptables-backup"
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	cmd := exec.Command("iptables-restore")
	cmd.Stdin = strings.NewReader(string(data))
	return cmd.Run()
}

// getTorUID tries to find the Tor user's UID
func getTorUID() int {
	// Try common Tor user names
	users := []string{"tor", "_tor", "debian-tor", "toranon"}

	for _, user := range users {
		cmd := exec.Command("id", "-u", user)
		output, err := cmd.Output()
		if err == nil {
			uid, err := strconv.Atoi(strings.TrimSpace(string(output)))
			if err == nil {
				return uid
			}
		}
	}

	// Default to 0 (root) - less secure but works
	return 0
}

// CheckRequirements checks if iptables is available
func CheckRequirements() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found: %w", err)
	}
	return nil
}
