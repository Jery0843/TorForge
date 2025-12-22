// Package netns provides network namespace isolation for per-app proxying
package netns

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"github.com/jery0843/torforge/pkg/logger"
)

const (
	netnsPath = "/var/run/netns"
	nsPrefix  = "torforge-"
)

// Namespace represents an isolated network namespace
type Namespace struct {
	Name       string
	Path       string
	VethHost   string
	VethNS     string
	IPHost     string
	IPNS       string
	SOCKSProxy string
	_mu        sync.Mutex // Reserved for future thread-safety
	active     bool
}

// Manager manages network namespaces for app isolation
type Manager struct {
	namespaces map[string]*Namespace
	mu         sync.RWMutex
	socksAddr  string
	dnsAddr    string
	counter    int
}

// NewManager creates a new namespace manager
func NewManager(socksAddr, dnsAddr string) *Manager {
	return &Manager{
		namespaces: make(map[string]*Namespace),
		socksAddr:  socksAddr,
		dnsAddr:    dnsAddr,
	}
}

// CreateNamespace creates a new isolated network namespace
func (m *Manager) CreateNamespace(name string) (*Namespace, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log := logger.WithComponent("netns")

	if _, exists := m.namespaces[name]; exists {
		return nil, fmt.Errorf("namespace %s already exists", name)
	}

	m.counter++
	nsName := fmt.Sprintf("%s%s-%d", nsPrefix, name, m.counter)

	// Ensure netns directory exists
	if err := os.MkdirAll(netnsPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create netns dir: %w", err)
	}

	ns := &Namespace{
		Name:       nsName,
		Path:       filepath.Join(netnsPath, nsName),
		VethHost:   fmt.Sprintf("veth-h%d", m.counter),
		VethNS:     fmt.Sprintf("veth-n%d", m.counter),
		IPHost:     fmt.Sprintf("10.200.%d.1/24", m.counter),
		IPNS:       fmt.Sprintf("10.200.%d.2/24", m.counter),
		SOCKSProxy: m.socksAddr,
	}

	// Create network namespace
	if err := m.createNetNS(ns); err != nil {
		return nil, fmt.Errorf("failed to create netns: %w", err)
	}

	// Setup veth pair
	if err := m.setupVeth(ns); err != nil {
		m.deleteNetNS(ns)
		return nil, fmt.Errorf("failed to setup veth: %w", err)
	}

	// Configure routing in namespace
	if err := m.configureRouting(ns); err != nil {
		m.cleanupVeth(ns)
		m.deleteNetNS(ns)
		return nil, fmt.Errorf("failed to configure routing: %w", err)
	}

	ns.active = true
	m.namespaces[name] = ns

	log.Info().Str("namespace", nsName).Msg("created network namespace")
	return ns, nil
}

// DeleteNamespace removes a network namespace
func (m *Manager) DeleteNamespace(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ns, exists := m.namespaces[name]
	if !exists {
		return fmt.Errorf("namespace %s not found", name)
	}

	m.cleanupVeth(ns)
	m.deleteNetNS(ns)

	delete(m.namespaces, name)
	return nil
}

// RunInNamespace runs a command inside a network namespace
func (m *Manager) RunInNamespace(nsName string, cmdName string, args ...string) error {
	m.mu.RLock()
	ns, exists := m.namespaces[nsName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("namespace %s not found", nsName)
	}

	log := logger.WithComponent("netns")
	log.Info().Str("namespace", ns.Name).Str("cmd", cmdName).Msg("running command in namespace")

	// Use ip netns exec to run command in namespace
	fullArgs := append([]string{"netns", "exec", ns.Name}, cmdName)
	fullArgs = append(fullArgs, args...)

	cmd := exec.Command("ip", fullArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set environment for SOCKS proxy
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("ALL_PROXY=socks5h://%s", ns.SOCKSProxy),
		fmt.Sprintf("all_proxy=socks5h://%s", ns.SOCKSProxy),
	)

	return cmd.Run()
}

// ExecInNamespace executes a function inside a namespace
func (m *Manager) ExecInNamespace(nsName string, fn func() error) error {
	m.mu.RLock()
	ns, exists := m.namespaces[nsName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("namespace %s not found", nsName)
	}

	// Lock OS thread as namespace changes are thread-local
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current namespace
	origNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("failed to open current netns: %w", err)
	}
	defer origNS.Close()

	// Open target namespace
	targetNS, err := os.Open(ns.Path)
	if err != nil {
		return fmt.Errorf("failed to open target netns: %w", err)
	}
	defer targetNS.Close()

	// Switch to target namespace
	if err := setns(targetNS.Fd()); err != nil {
		return fmt.Errorf("failed to enter netns: %w", err)
	}

	// Execute function
	fnErr := fn()

	// Switch back to original namespace
	if err := setns(origNS.Fd()); err != nil {
		return fmt.Errorf("failed to restore netns: %w", err)
	}

	return fnErr
}

func (m *Manager) createNetNS(ns *Namespace) error {
	return exec.Command("ip", "netns", "add", ns.Name).Run()
}

func (m *Manager) deleteNetNS(ns *Namespace) error {
	return exec.Command("ip", "netns", "delete", ns.Name).Run()
}

func (m *Manager) setupVeth(ns *Namespace) error {
	// Create veth pair
	if err := exec.Command("ip", "link", "add", ns.VethHost, "type", "veth", "peer", "name", ns.VethNS).Run(); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	// Move one end to namespace
	if err := exec.Command("ip", "link", "set", ns.VethNS, "netns", ns.Name).Run(); err != nil {
		return fmt.Errorf("failed to move veth to namespace: %w", err)
	}

	// Configure host side
	if err := exec.Command("ip", "addr", "add", ns.IPHost, "dev", ns.VethHost).Run(); err != nil {
		return fmt.Errorf("failed to configure host veth IP: %w", err)
	}

	if err := exec.Command("ip", "link", "set", ns.VethHost, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up host veth: %w", err)
	}

	// Configure namespace side
	if err := exec.Command("ip", "netns", "exec", ns.Name, "ip", "addr", "add", ns.IPNS, "dev", ns.VethNS).Run(); err != nil {
		return fmt.Errorf("failed to configure ns veth IP: %w", err)
	}

	if err := exec.Command("ip", "netns", "exec", ns.Name, "ip", "link", "set", ns.VethNS, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up ns veth: %w", err)
	}

	if err := exec.Command("ip", "netns", "exec", ns.Name, "ip", "link", "set", "lo", "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up loopback: %w", err)
	}

	return nil
}

func (m *Manager) configureRouting(ns *Namespace) error {
	// Extract gateway IP from host IP (remove /24)
	gateway := ns.IPHost[:len(ns.IPHost)-3]

	// Set default route to host side of veth
	if err := exec.Command("ip", "netns", "exec", ns.Name, "ip", "route", "add", "default", "via", gateway).Run(); err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}

	// Configure DNS in namespace
	resolvConf := fmt.Sprintf("nameserver %s\n", m.dnsAddr[:len(m.dnsAddr)-5]) // Remove port
	resolvPath := fmt.Sprintf("/etc/netns/%s", ns.Name)

	if err := os.MkdirAll(resolvPath, 0755); err != nil {
		return fmt.Errorf("failed to create resolv dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(resolvPath, "resolv.conf"), []byte(resolvConf), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	return nil
}

func (m *Manager) cleanupVeth(ns *Namespace) {
	// Deleting host veth also deletes the peer
	exec.Command("ip", "link", "delete", ns.VethHost).Run()
}

// CleanupAll removes all TorForge namespaces
func (m *Manager) CleanupAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, ns := range m.namespaces {
		m.cleanupVeth(ns)
		m.deleteNetNS(ns)
		delete(m.namespaces, name)
	}
}

// GetNamespace returns a namespace by name
func (m *Manager) GetNamespace(name string) (*Namespace, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ns, ok := m.namespaces[name]
	return ns, ok
}

// ListNamespaces returns all active namespaces
func (m *Manager) ListNamespaces() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.namespaces))
	for name := range m.namespaces {
		names = append(names, name)
	}
	return names
}

// setns calls the setns syscall to change network namespace
// Uses the raw syscall number for Linux (308 on amd64)
func setns(fd uintptr) error {
	// SYS_SETNS = 308 on amd64 Linux
	const SYS_SETNS = 308
	const CLONE_NEWNET = 0x40000000

	_, _, errno := syscall.Syscall(SYS_SETNS, fd, CLONE_NEWNET, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// GetPID returns the PID for a process running in namespace
func GetPIDsInNamespace(nsPath string) ([]int, error) {
	var pids []int

	// Read /proc to find processes in this namespace
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		netnsLink := filepath.Join("/proc", entry, "ns/net")
		link, err := os.Readlink(netnsLink)
		if err != nil {
			continue
		}

		targetLink, err := os.Readlink(nsPath)
		if err != nil {
			continue
		}

		if link == targetLink {
			pids = append(pids, pid)
		}
	}

	return pids, nil
}
