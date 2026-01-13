// Package security provides advanced security features for TorForge
package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/eiannone/keyboard"
	"github.com/jery0843/torforge/pkg/logger"
)

// PanicConfig configures the dead man's switch
type PanicConfig struct {
	Enabled   bool   `yaml:"enabled"`
	PanicKey  string `yaml:"panic_key"` // Key to trigger panic (e.g., "F12")
	WipeRAM   bool   `yaml:"wipe_ram"`
	KillProcs bool   `yaml:"kill_procs"`
}

// DeadManSwitch provides emergency shutdown capabilities.
//
// Threat model: Physical seizure or coercion. When activated:
//  1. Kill network immediately (flush iptables, kill sockets)
//  2. Stop Tor process
//  3. Clear traces (browser caches, shell history)
//  4. Optional: wipe RAM (drop_caches)
//
// Activation is intentionally unambiguous (function key press in terminal)
// to prevent accidental triggers while remaining quick for emergencies.
type DeadManSwitch struct {
	mu        sync.RWMutex
	enabled   bool
	panicKey  string
	wipeRAM   bool
	killProcs bool

	// Context for key listener
	ctx    context.Context
	cancel context.CancelFunc

	// Callback when panic triggered
	onPanic func()

	// Emergency cleanup functions
	cleanupFuncs []func()
}

// NewDeadManSwitch creates a new dead man's switch
func NewDeadManSwitch(cfg *PanicConfig) *DeadManSwitch {
	if cfg == nil || !cfg.Enabled {
		return &DeadManSwitch{enabled: false}
	}

	return &DeadManSwitch{
		enabled:      true,
		panicKey:     cfg.PanicKey,
		wipeRAM:      cfg.WipeRAM,
		killProcs:    cfg.KillProcs,
		cleanupFuncs: []func(){},
	}
}

// StartKeyListener starts listening for the panic key globally
func (d *DeadManSwitch) StartKeyListener(ctx context.Context) error {
	if !d.enabled {
		return nil
	}

	d.ctx, d.cancel = context.WithCancel(ctx)
	log := logger.WithComponent("panic")

	// Try to open keyboard
	if err := keyboard.Open(); err != nil {
		log.Warn().Err(err).Msg("keyboard listener not available (run in terminal)")
		return nil // Don't fail, just warn
	}

	log.Info().Str("key", d.panicKey).Msg("🚨 panic key listener active")

	go func() {
		defer keyboard.Close()

		for {
			select {
			case <-d.ctx.Done():
				return
			default:
				char, key, err := keyboard.GetKey()
				if err != nil {
					continue
				}

				// Check if this is our panic key
				if d.matchesPanicKey(char, key) {
					log.Warn().Msg("🚨 PANIC KEY PRESSED!")
					d.Trigger()
					return
				}
			}
		}
	}()

	return nil
}

// matchesPanicKey checks if the pressed key matches the configured panic key
func (d *DeadManSwitch) matchesPanicKey(char rune, key keyboard.Key) bool {
	panicKey := strings.ToUpper(d.panicKey)

	switch panicKey {
	case "F1":
		return key == keyboard.KeyF1
	case "F2":
		return key == keyboard.KeyF2
	case "F3":
		return key == keyboard.KeyF3
	case "F4":
		return key == keyboard.KeyF4
	case "F5":
		return key == keyboard.KeyF5
	case "F6":
		return key == keyboard.KeyF6
	case "F7":
		return key == keyboard.KeyF7
	case "F8":
		return key == keyboard.KeyF8
	case "F9":
		return key == keyboard.KeyF9
	case "F10":
		return key == keyboard.KeyF10
	case "F11":
		return key == keyboard.KeyF11
	case "F12":
		return key == keyboard.KeyF12
	case "ESC", "ESCAPE":
		return key == keyboard.KeyEsc
	case "DELETE", "DEL":
		return key == keyboard.KeyDelete
	case "END":
		return key == keyboard.KeyEnd
	case "HOME":
		return key == keyboard.KeyHome
	case "PGUP", "PAGEUP":
		return key == keyboard.KeyPgup
	case "PGDN", "PAGEDOWN":
		return key == keyboard.KeyPgdn
	default:
		// Check for single character
		if len(panicKey) == 1 {
			return strings.ToUpper(string(char)) == panicKey
		}
	}
	return false
}

// StopKeyListener stops the key listener
func (d *DeadManSwitch) StopKeyListener() {
	if d.cancel != nil {
		d.cancel()
	}
}

// SetPanicHandler sets the function to call on panic
func (d *DeadManSwitch) SetPanicHandler(handler func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onPanic = handler
}

// AddCleanup adds a cleanup function to run on panic
func (d *DeadManSwitch) AddCleanup(fn func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupFuncs = append(d.cleanupFuncs, fn)
}

// Trigger activates the dead man's switch
func (d *DeadManSwitch) Trigger() {
	d.mu.RLock()
	if !d.enabled {
		d.mu.RUnlock()
		return
	}
	d.mu.RUnlock()

	log := logger.WithComponent("panic")
	log.Warn().Msg("🚨 DEAD MAN'S SWITCH TRIGGERED - EMERGENCY SHUTDOWN")

	// CRITICAL: Run emergency network cleanup FIRST (synchronously)
	d.emergencyNetworkCleanup()

	// Run all cleanup functions in parallel
	var wg sync.WaitGroup

	d.mu.RLock()
	for _, fn := range d.cleanupFuncs {
		wg.Add(1)
		go func(cleanup func()) {
			defer wg.Done()
			cleanup()
		}(fn)
	}
	d.mu.RUnlock()

	// Call main panic handler (synchronously)
	d.mu.RLock()
	if d.onPanic != nil {
		d.onPanic()
	}
	d.mu.RUnlock()

	// Wait for cleanup with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Msg("cleanup complete")
	case <-time.After(2 * time.Second):
		log.Warn().Msg("cleanup timeout - forcing exit")
	}

	// Run additional cleanup
	d.emergencyActions()

	// Force exit
	log.Warn().Msg("emergency exit - all connections terminated")
	os.Exit(0)
}

// emergencyNetworkCleanup immediately kills all network rules
func (d *DeadManSwitch) emergencyNetworkCleanup() {
	log := logger.WithComponent("panic")
	log.Warn().Msg("🚨 KILLING ALL NETWORK CONNECTIONS...")

	// 1. Flush ALL iptables chains immediately
	exec.Command("iptables", "-F").Run()
	exec.Command("iptables", "-t", "nat", "-F").Run()
	exec.Command("iptables", "-t", "mangle", "-F").Run()
	exec.Command("iptables", "-X", "TORFORGE").Run()
	exec.Command("iptables", "-t", "nat", "-X", "TORFORGE_NAT").Run()
	exec.Command("ip6tables", "-F").Run()
	exec.Command("ip6tables", "-X", "TORFORGE_IPV6").Run()

	// 2. Kill all network connections
	exec.Command("ss", "-K").Run() // Kill all sockets

	// 3. Kill Tor immediately
	exec.Command("pkill", "-9", "tor").Run()

	log.Info().Msg("network connections terminated")
}

// emergencyActions performs emergency cleanup
func (d *DeadManSwitch) emergencyActions() {
	log := logger.WithComponent("panic")

	// 1. Flush iptables immediately
	log.Debug().Msg("flushing iptables...")
	exec.Command("iptables", "-F", "TORFORGE").Run()
	exec.Command("iptables", "-t", "nat", "-F", "TORFORGE_NAT").Run()
	exec.Command("ip6tables", "-F", "TORFORGE_IPV6").Run()

	// 2. Kill all Tor processes
	if d.killProcs {
		log.Debug().Msg("killing Tor processes...")
		exec.Command("pkill", "-9", "tor").Run()
		exec.Command("pkill", "-9", "-f", "torforge").Run()
	}

	// 3. Clear DNS cache
	log.Debug().Msg("clearing DNS cache...")
	exec.Command("systemctl", "restart", "systemd-resolved").Run()

	// 4. Clear browser data (common locations)
	log.Debug().Msg("clearing traces...")
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/root" // Fallback to root home
	}
	clearPaths := []string{
		homeDir + "/.cache/mozilla/firefox",
		homeDir + "/.cache/chromium",
		homeDir + "/.cache/google-chrome",
		homeDir + "/.local/share/recently-used.xbel",
		"/tmp/torforge*",
		"/var/lib/torforge",
	}
	for _, path := range clearPaths {
		os.RemoveAll(path)
	}

	// 5. Wipe RAM (requires root)
	if d.wipeRAM {
		log.Debug().Msg("requesting RAM wipe...")
		// Sync and drop caches
		exec.Command("sync").Run()
		exec.Command("sh", "-c", "echo 3 > /proc/sys/vm/drop_caches").Run()
	}

	// 6. Clear shell history
	exec.Command("sh", "-c", "history -c").Run()
	os.Remove(homeDir + "/.bash_history")
	os.Remove(homeDir + "/.zsh_history")

	log.Info().Msg("emergency cleanup complete")
}

// EmergencySignal sends emergency signal for immediate shutdown
func (d *DeadManSwitch) EmergencySignal() {
	// Send SIGTERM to self for graceful shutdown attempt
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		os.Exit(1) // Emergency exit if can't find own process
	}
	p.Signal(syscall.SIGTERM)

	// If still running after 1 second, force SIGKILL
	time.AfterFunc(1*time.Second, func() {
		p.Signal(syscall.SIGKILL)
	})
}

// GetStatus returns current switch status
func (d *DeadManSwitch) GetStatus() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"enabled":       d.enabled,
		"panic_key":     d.panicKey,
		"wipe_ram":      d.wipeRAM,
		"kill_procs":    d.killProcs,
		"cleanup_funcs": len(d.cleanupFuncs),
	}
}

// IsEnabled returns whether the switch is enabled
func (d *DeadManSwitch) IsEnabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.enabled
}

// GetPanicKey returns the configured panic key
func (d *DeadManSwitch) GetPanicKey() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.panicKey
}

// PrintPanicInstructions prints how to use the panic key
func (d *DeadManSwitch) PrintPanicInstructions() {
	if !d.enabled {
		return
	}

	fmt.Printf("   🚨 Panic Key: %s (emergency shutdown)\n", d.panicKey)
}
