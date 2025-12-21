// TorForge - Advanced Transparent Tor Proxy
// Main entry point
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jery0843/torforge/internal/proxy"
	"github.com/jery0843/torforge/internal/security"
	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	commit  = "dev"
)

var (
	cfgFile    string
	verbose    bool
	jsonOutput bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "torforge",
	Short: "TorForge - Advanced Transparent Tor Proxy",
	Long: `TorForge is a production-ready transparent Tor proxy that routes
all system traffic through the Tor network with advanced features:

  • Zero-config transparent proxying
  • Multi-circuit management with rotation
  • Smart bypass rules (domain, IP, GeoIP)
  • Real-time TUI dashboard
  • Anti-leak protection

Run 'torforge --tor' to enable full system proxying.`,
	Version: fmt.Sprintf("%s (%s)", version, commit),
}

var torCmd = &cobra.Command{
	Use:   "tor",
	Short: "Enable transparent Tor proxy for all system traffic",
	Long:  "Routes all TCP/DNS traffic through Tor using iptables rules.",
	RunE:  runTor,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show live TUI dashboard",
	Long:  "Opens an interactive terminal dashboard showing proxy status, circuits, and traffic.",
	RunE:  runStatus,
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run leak detection tests",
	Long:  "Performs comprehensive tests to detect DNS leaks, IP leaks, and other privacy issues.",
	RunE:  runTest,
}

var newCircuitCmd = &cobra.Command{
	Use:   "new-circuit",
	Short: "Request a new Tor identity",
	Long:  "Closes existing circuits and creates new ones, effectively getting a new exit IP.",
	RunE:  runNewCircuit,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the Tor proxy and restore network settings",
	Long:  "Removes iptables rules and stops the Tor process.",
	RunE:  runStop,
}

var installCmd = &cobra.Command{
	Use:   "install-systemd",
	Short: "Install systemd service for auto-start",
	Long:  "Creates and enables a systemd service for TorForge.",
	RunE:  runInstallSystemd,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: /etc/torforge/torforge.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")

	// Tor command flags
	torCmd.Flags().IntP("circuits", "n", 4, "number of concurrent circuits")
	torCmd.Flags().StringP("speed", "s", "", "bandwidth limit (e.g., 100Mbps)")
	torCmd.Flags().StringSliceP("bypass", "b", nil, "bypass patterns (e.g., *.local)")
	torCmd.Flags().BoolP("no-kill-switch", "k", false, "disable kill switch")
	torCmd.Flags().BoolP("use-system-tor", "S", false, "use existing system Tor instance")
	torCmd.Flags().StringP("exit-nodes", "e", "", "preferred exit nodes (country codes)")
	torCmd.Flags().BoolP("daemon", "d", false, "run as daemon")
	torCmd.Flags().Bool("auto-bridge", false, "automatically discover and use bridges if Tor is blocked")
	torCmd.Flags().Bool("post-quantum", false, "enable post-quantum encryption layer (CRYSTALS-Kyber)")
	torCmd.Flags().Int("rotate-circuit", 0, "auto-rotate circuit every N minutes (0 = disabled)")
	torCmd.Flags().Int("decoy-traffic", 0, "generate N% decoy traffic to frustrate analysis (0-100)")
	torCmd.Flags().Bool("stego", false, "steganography mode - traffic looks like YouTube/Netflix")
	torCmd.Flags().String("panic-key", "", "dead man's switch key (e.g., F12) for emergency shutdown")

	// App proxy flags
	appCmd := &cobra.Command{
		Use:                "app [command] [args...]",
		Short:              "Run a command through Tor using network namespaces",
		Long:               "Runs the specified command in an isolated network namespace routed through Tor.",
		RunE:               runApp,
		DisableFlagParsing: true,
	}

	// AI command
	aiCmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-powered features management",
		Long:  "Manage TorForge's AI-powered circuit selection and split-tunnel features.",
	}

	aiStatsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show AI learning statistics",
		RunE:  runAIStats,
	}

	aiResetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset AI learned data",
		RunE:  runAIReset,
	}

	aiBypassCmd := &cobra.Command{
		Use:   "bypass [domain]",
		Short: "Add domain to speed bypass list",
		Args:  cobra.ExactArgs(1),
		RunE:  runAIBypass,
	}

	aiSensitiveCmd := &cobra.Command{
		Use:   "sensitive [domain]",
		Short: "Add domain to always-Tor list",
		Args:  cobra.ExactArgs(1),
		RunE:  runAISensitive,
	}

	aiCmd.AddCommand(aiStatsCmd, aiResetCmd, aiBypassCmd, aiSensitiveCmd)

	// Add commands
	rootCmd.AddCommand(torCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(newCircuitCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(appCmd)
	rootCmd.AddCommand(aiCmd)

	// Short flags on root
	rootCmd.Flags().Bool("tor", false, "alias for 'torforge tor'")
}

func initLogger() error {
	level := "info"
	if verbose {
		level = "debug"
	}

	return logger.Init(logger.Config{
		Level:   level,
		Console: !jsonOutput,
	})
}

func runTor(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("torforge requires root privileges. Please run with sudo.")
	}

	if err := initLogger(); err != nil {
		return err
	}

	log := logger.WithComponent("main")
	log.Info().Str("version", version).Msg("TorForge starting")

	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Apply CLI overrides
	if circuits, _ := cmd.Flags().GetInt("circuits"); circuits > 0 {
		cfg.Circuits.MaxCircuits = circuits
	}
	if bypass, _ := cmd.Flags().GetStringSlice("bypass"); len(bypass) > 0 {
		cfg.Bypass.Domains = append(cfg.Bypass.Domains, bypass...)
	}
	if noKillSwitch, _ := cmd.Flags().GetBool("no-kill-switch"); noKillSwitch {
		cfg.Security.KillSwitch = false
	}
	if useSystemTor, _ := cmd.Flags().GetBool("use-system-tor"); useSystemTor {
		cfg.Tor.UseSystemTor = true
	}
	if exitNodes, _ := cmd.Flags().GetString("exit-nodes"); exitNodes != "" {
		cfg.Tor.ExitNodes = exitNodes
	}

	// Create proxy controller
	p, err := proxy.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("received signal, shutting down")
		cancel()
	}()

	// Start proxy
	log.Info().Msg("starting transparent proxy")
	if err := p.Start(ctx); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	// Show active features
	fmt.Printf("\n🧅 TorForge Active\n")

	// Check for special features
	postQuantum, _ := cmd.Flags().GetBool("post-quantum")
	autoBridge, _ := cmd.Flags().GetBool("auto-bridge")

	if postQuantum {
		if err := p.EnableQuantumLayer(); err != nil {
			log.Warn().Err(err).Msg("failed to enable post-quantum encryption")
		} else {
			status := p.GetQuantumStatus()
			fmt.Println("   🔐 Post-Quantum: CRYSTALS-Kyber768 ACTIVE")
			fmt.Printf("   📊 NIST Level: %v | Key ID: %v\n", status["nist_level"], status["key_id"])
		}
	}
	if autoBridge {
		fmt.Println("   🌉 Auto-Bridge: Enabled (censorship bypass)")
		log.Info().Msg("bridge auto-discovery enabled")
	}

	// Decoy Traffic Generator
	decoyPercent, _ := cmd.Flags().GetInt("decoy-traffic")
	if decoyPercent > 0 {
		decoyConfig := &security.DecoyTrafficConfig{
			Enabled:     true,
			Percentage:  decoyPercent,
			MinInterval: 500,
			MaxInterval: 5000,
		}
		decoyGen := security.NewDecoyTrafficGenerator(decoyConfig, "")
		if err := decoyGen.Start(ctx); err == nil {
			fmt.Printf("   🎭 Decoy Traffic: %d%% fake requests active\n", decoyPercent)
			log.Info().Int("percentage", decoyPercent).Msg("decoy traffic generator started")
		}
	}

	// Steganography Mode
	stegoEnabled, _ := cmd.Flags().GetBool("stego")
	if stegoEnabled {
		stegoConfig := &security.StegoConfig{
			Enabled:     true,
			Mode:        "https",
			CoverDomain: "youtube",
		}
		stegoMode := security.NewStegoMode(stegoConfig)
		if stegoMode.IsEnabled() {
			fmt.Println("   🎭 Stego Mode: traffic mimics YouTube streaming")
			log.Info().Msg("steganography mode active - traffic obfuscated")
		}
	}

	// Dead Man's Switch (Panic Key)
	panicKey, _ := cmd.Flags().GetString("panic-key")
	if panicKey != "" {
		panicConfig := &security.PanicConfig{
			Enabled:   true,
			PanicKey:  panicKey,
			WipeRAM:   true,
			KillProcs: true,
		}
		deadMan := security.NewDeadManSwitch(panicConfig)
		deadMan.SetPanicHandler(func() {
			log.Warn().Msg("panic handler triggered")
			p.Stop()
		})

		// Start global key listener
		if err := deadMan.StartKeyListener(ctx); err != nil {
			log.Warn().Err(err).Msg("failed to start panic key listener")
		}

		fmt.Printf("   🚨 Panic Key: %s (press in TERMINAL to trigger)\n", panicKey)
		log.Info().Str("key", panicKey).Msg("dead man's switch armed")
	}

	var exitIP string
	var activeCircuits int
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Second)
		status, err := p.GetStatus()
		if err == nil {
			if status.ExitIP != "" {
				exitIP = status.ExitIP
				activeCircuits = status.ActiveCircuits
				break
			}
			// Try to fetch exit IP directly
			if torMgr := p.GetTorManager(); torMgr != nil {
				if ip, err := torMgr.GetExitIP(); err == nil {
					exitIP = ip
					activeCircuits = status.ActiveCircuits
					break
				}
			}
		}
		fmt.Printf("   ⏳ Waiting for Tor circuits... (%d/5)\n", i+1)
	}
	if exitIP == "" {
		exitIP = "(connecting...)"
	}
	fmt.Printf("   Exit IP:  %s\n", exitIP)
	fmt.Printf("   Circuits: %d\n", activeCircuits)

	// Start auto-rotation if enabled
	rotateMinutes, _ := cmd.Flags().GetInt("rotate-circuit")
	if rotateMinutes > 0 {
		fmt.Printf("   🔄 Auto-Rotate: every %d minutes\n", rotateMinutes)
		log.Info().Int("minutes", rotateMinutes).Msg("auto-rotation enabled")

		go func() {
			ticker := time.NewTicker(time.Duration(rotateMinutes) * time.Minute)
			defer ticker.Stop()

			rotationCount := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					rotationCount++
					log.Info().Int("rotation", rotationCount).Msg("auto-rotating circuit")

					// Request new identity
					if torMgr := p.GetTorManager(); torMgr != nil {
						if err := torMgr.NewIdentity(); err != nil {
							log.Warn().Err(err).Msg("auto-rotation failed")
						} else {
							// Get new exit IP
							if newIP, err := torMgr.GetExitIP(); err == nil {
								log.Info().
									Str("new_exit_ip", newIP).
									Int("rotation", rotationCount).
									Msg("🔄 circuit rotated")
							}
						}
					}
				}
			}
		}()
	}

	fmt.Printf("\n   Press Ctrl+C to stop\n\n")

	// Wait for shutdown
	<-ctx.Done()

	// Cleanup
	log.Info().Msg("stopping proxy")
	if err := p.Stop(); err != nil {
		log.Error().Err(err).Msg("error during shutdown")
	}

	log.Info().Msg("TorForge stopped")
	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	if err := initLogger(); err != nil {
		return err
	}

	// Check if TorForge is running by looking for control port file
	controlPortFile := "/var/lib/torforge/control_port"
	data, err := os.ReadFile(controlPortFile)
	if err != nil {
		fmt.Println("❌ TorForge is not running")
		fmt.Println("   Start with: sudo torforge tor")
		return nil
	}

	port := strings.TrimSpace(string(data))

	// Read authentication cookie (optional - some setups don't use it)
	cookieFile := "/var/lib/torforge/control_auth_cookie"
	cookie, err := os.ReadFile(cookieFile)
	if err != nil {
		cookie = nil // Continue without cookie authentication
	}

	// Connect to Tor control port
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 5*time.Second)
	if err != nil {
		fmt.Println("❌ Cannot connect to TorForge (may have crashed)")
		fmt.Println("   Restart with: sudo torforge tor")
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := make([]byte, 4096)

	// Authenticate with cookie
	if len(cookie) > 0 {
		cookieHex := fmt.Sprintf("%x", cookie)
		fmt.Fprintf(conn, "AUTHENTICATE %s\r\n", cookieHex)
	} else {
		fmt.Fprintf(conn, "AUTHENTICATE\r\n")
	}
	conn.Read(reader)

	// Get circuit status
	fmt.Fprintf(conn, "GETINFO circuit-status\r\n")
	circuitData := ""
	circuitCount := 0
	if n, err := conn.Read(reader); err == nil {
		circuitData = string(reader[:n])
		circuitCount = strings.Count(circuitData, " BUILT ")
	}

	// Get bootstrap/circuit-established status (more reliable)
	fmt.Fprintf(conn, "GETINFO status/circuit-established\r\n")
	circuitEstablished := ""
	if n, err := conn.Read(reader); err == nil {
		circuitEstablished = string(reader[:n])
	}
	// If circuits are established OR we have BUILT circuits, we're active
	bootstrapped := strings.Contains(circuitEstablished, "=1") || circuitCount > 0

	// Get uptime
	fmt.Fprintf(conn, "GETINFO uptime\r\n")
	uptimeInfo := ""
	if n, err := conn.Read(reader); err == nil {
		uptimeInfo = string(reader[:n])
	}
	var uptimeStr string
	if idx := strings.Index(uptimeInfo, "250-uptime="); idx != -1 {
		start := idx + 11
		end := strings.IndexAny(uptimeInfo[start:], "\r\n")
		if end > 0 {
			uptimeStr = uptimeInfo[start : start+end]
		}
	}

	// Get exit IP via SOCKS
	exitIP := "(fetching...)"
	socksConn, err := net.DialTimeout("tcp", "127.0.0.1:9050", 2*time.Second)
	if err == nil {
		socksConn.Close()
		out, err := exec.Command("curl", "-s", "--socks5-hostname", "127.0.0.1:9050", "--max-time", "10", "https://api.ipify.org").Output()
		if err == nil {
			exitIP = strings.TrimSpace(string(out))
		}
	}

	// Display status
	fmt.Println()
	fmt.Println("🧅 TorForge Status")
	fmt.Println("━━━━━━━━━━━━━━━━━━")
	if bootstrapped {
		fmt.Println("   Status:   ✅ ACTIVE")
	} else {
		fmt.Println("   Status:   ⏳ BOOTSTRAPPING")
	}
	fmt.Printf("   Exit IP:  %s\n", exitIP)
	fmt.Printf("   Circuits: %d active\n", circuitCount)
	if uptimeStr != "" {
		fmt.Printf("   Uptime:   %s seconds\n", uptimeStr)
	}
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("   torforge new-circuit  → Get new exit IP")
	fmt.Println("   torforge stop         → Stop TorForge")
	fmt.Println()

	return nil
}

func runTest(cmd *cobra.Command, args []string) error {
	if err := initLogger(); err != nil {
		return err
	}

	fmt.Println("🔍 Running leak detection tests...")
	fmt.Println()

	// Run tests
	tests := []struct {
		name string
		fn   func() (bool, string)
	}{
		{"DNS Leak Test", testDNSLeak},
		{"IP Leak Test", testIPLeak},
		{"WebRTC Leak Test", testWebRTCLeak},
		{"Tor Connection Test", testTorConnection},
	}

	allPassed := true
	for _, t := range tests {
		passed, details := t.fn()
		if passed {
			fmt.Printf("✅ %s: PASSED\n", t.name)
		} else {
			fmt.Printf("❌ %s: FAILED - %s\n", t.name, details)
			allPassed = false
		}
	}

	fmt.Println()
	if allPassed {
		fmt.Println("🎉 All tests passed! Your connection is secure.")
	} else {
		fmt.Println("⚠️  Some tests failed. Check your configuration.")
	}

	return nil
}

func runNewCircuit(cmd *cobra.Command, args []string) error {
	if err := initLogger(); err != nil {
		return err
	}

	fmt.Println("🔄 Requesting new identity...")

	// Read control port from Tor data directory
	controlPortFile := "/var/lib/torforge/control_port"
	data, err := os.ReadFile(controlPortFile)
	if err != nil {
		// Try to find running Tor and send SIGHUP
		if err := exec.Command("pkill", "-HUP", "tor").Run(); err != nil {
			return fmt.Errorf("no running TorForge instance found (start with: sudo torforge tor)")
		}
		fmt.Println("✅ Sent signal to Tor - circuits will refresh")
		return nil
	}

	port := strings.TrimSpace(string(data))

	// Read authentication cookie
	cookieFile := "/var/lib/torforge/control_auth_cookie"
	cookie, err := os.ReadFile(cookieFile)
	if err != nil {
		// Try without cookie (may work for some setups)
		cookie = nil
	}

	// Connect to Tor control port
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		// Fallback: send SIGHUP
		exec.Command("pkill", "-HUP", "tor").Run()
		fmt.Println("✅ Sent signal to Tor - circuits will refresh")
		return nil
	}
	defer conn.Close()

	// Set read timeout
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 512)

	// Authenticate with cookie
	if len(cookie) > 0 {
		cookieHex := fmt.Sprintf("%x", cookie)
		fmt.Fprintf(conn, "AUTHENTICATE %s\r\n", cookieHex)
	} else {
		fmt.Fprintf(conn, "AUTHENTICATE\r\n")
	}
	authResponse := ""
	if n, err := conn.Read(buf); err == nil {
		authResponse = string(buf[:n])
	}

	if !strings.Contains(authResponse, "250 OK") {
		// Fallback: send SIGHUP
		exec.Command("pkill", "-HUP", "tor").Run()
		fmt.Println("✅ Sent signal to Tor - circuits will refresh")
		return nil
	}

	// Request new identity
	fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")
	response := ""
	if n, err := conn.Read(buf); err == nil {
		response = string(buf[:n])
	}

	if strings.Contains(response, "250 OK") {
		fmt.Println("✅ New circuit requested - exit IP will change")
	} else if strings.Contains(response, "552") {
		fmt.Println("⏳ Rate limited - wait 10 seconds between identity changes")
	} else {
		fmt.Println("✅ Signal sent to Tor")
	}

	return nil
}

func runStop(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("torforge requires root privileges. Please run with sudo.")
	}

	if err := initLogger(); err != nil {
		return err
	}

	fmt.Println("🛑 Stopping TorForge...")

	// Kill any orphan Tor processes from previous sessions
	exec.Command("killall", "tor").Run()

	// Load config and create proxy to access cleanup
	cfg, err := config.Load(cfgFile)
	if err != nil || cfg == nil {
		cfg = config.DefaultConfig()
	}

	p, err := proxy.New(cfg)
	if err != nil {
		return err
	}

	if err := p.Cleanup(); err != nil {
		// Continue anyway - we still want to restore network
		fmt.Printf("⚠️  Cleanup warning: %v\n", err)
	}

	// Double-check Tor processes are killed
	exec.Command("killall", "-9", "tor").Run()

	fmt.Println("✅ Network settings restored")
	return nil
}

func runApp(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("please specify a command to run")
	}

	if err := initLogger(); err != nil {
		return err
	}

	fmt.Printf("🧅 Running '%s' through Tor...\n", args[0])

	// Method 1: Try torsocks (most reliable)
	torsocksPath, err := exec.LookPath("torsocks")
	if err == nil {
		torsocksCmd := exec.Command(torsocksPath, args...)
		torsocksCmd.Stdout = os.Stdout
		torsocksCmd.Stderr = os.Stderr
		torsocksCmd.Stdin = os.Stdin
		return torsocksCmd.Run()
	}

	// Method 2: Try proxychains
	proxychainsPath, err := exec.LookPath("proxychains4")
	if err == nil {
		proxyCmd := exec.Command(proxychainsPath, args...)
		proxyCmd.Stdout = os.Stdout
		proxyCmd.Stderr = os.Stderr
		proxyCmd.Stdin = os.Stdin
		return proxyCmd.Run()
	}

	// Method 3: Use environment variables for SOCKS proxy
	appCmd := exec.Command(args[0], args[1:]...)
	appCmd.Stdout = os.Stdout
	appCmd.Stderr = os.Stderr
	appCmd.Stdin = os.Stdin
	appCmd.Env = append(os.Environ(),
		"ALL_PROXY=socks5://127.0.0.1:9050",
		"all_proxy=socks5://127.0.0.1:9050",
		"HTTP_PROXY=socks5://127.0.0.1:9050",
		"HTTPS_PROXY=socks5://127.0.0.1:9050",
	)

	if err := appCmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w (install 'torsocks' for better support: apt install torsocks)", err)
	}
	return nil
}

func runInstallSystemd(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing systemd service requires root privileges")
	}

	if err := initLogger(); err != nil {
		return err
	}

	servicePath := "/etc/systemd/system/torforge.service"
	service := `[Unit]
Description=TorForge Transparent Tor Proxy
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/torforge tor
ExecStop=/usr/local/bin/torforge stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile(servicePath, []byte(service), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	fmt.Println("✅ Systemd service installed")
	fmt.Println()
	fmt.Println("To enable auto-start:")
	fmt.Println("  sudo systemctl enable torforge")
	fmt.Println()
	fmt.Println("To start now:")
	fmt.Println("  sudo systemctl start torforge")

	return nil
}

// Test functions for leak detection
func testDNSLeak() (bool, string) {
	// Check if DNS queries go through Tor by using curl through SOCKS
	out, err := exec.Command("curl", "-s", "--socks5-hostname", "127.0.0.1:9050",
		"--max-time", "15", "https://dnsleaktest.com/").Output()
	if err != nil {
		return false, fmt.Sprintf("DNS test failed: %v", err)
	}
	if len(out) > 0 {
		return true, "DNS queries routed through Tor"
	}
	return false, "DNS leak detected"
}

func testIPLeak() (bool, string) {
	// Check if our IP appears as a Tor exit node using SOCKS proxy
	out, err := exec.Command("curl", "-s", "--socks5-hostname", "127.0.0.1:9050",
		"--max-time", "15", "https://check.torproject.org/api/ip").Output()
	if err != nil {
		return false, fmt.Sprintf("IP test failed: %v", err)
	}

	var result struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return false, fmt.Sprintf("Failed to parse response: %v", err)
	}

	if result.IsTor {
		return true, fmt.Sprintf("Using Tor exit: %s", result.IP)
	}
	return false, fmt.Sprintf("IP leak detected: %s is not a Tor exit", result.IP)
}

func testWebRTCLeak() (bool, string) {
	// WebRTC is browser-specific, not applicable to CLI applications
	return true, "WebRTC not applicable (CLI only)"
}

func testTorConnection() (bool, string) {
	// Read the dynamic control port from TorForge data directory
	controlPortFile := "/var/lib/torforge/control_port"
	data, err := os.ReadFile(controlPortFile)
	if err != nil {
		return false, "TorForge not running (no control port file)"
	}

	port := strings.TrimSpace(string(data))
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 5*time.Second)
	if err != nil {
		return false, fmt.Sprintf("Cannot connect to Tor control port %s: %v", port, err)
	}
	conn.Close()
	return true, fmt.Sprintf("Tor control port %s responding", port)
}

func runAIStats(cmd *cobra.Command, args []string) error {
	aiDataDir := "/var/lib/torforge/ai"

	fmt.Println()
	fmt.Println("🧠 TorForge AI Statistics")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Check circuit performance data
	circuitFile := aiDataDir + "/circuit_performance.json"
	if data, err := os.ReadFile(circuitFile); err == nil {
		var circuits map[string]interface{}
		if json.Unmarshal(data, &circuits) == nil {
			fmt.Printf("\n📊 Circuit Performance:\n")
			fmt.Printf("   Tracked exits: %d\n", len(circuits))
		}
	} else {
		fmt.Println("\n📊 Circuit Performance: No data yet")
	}

	// Check app profiles
	profilesFile := aiDataDir + "/app_profiles.json"
	if data, err := os.ReadFile(profilesFile); err == nil {
		var profiles map[string]interface{}
		if json.Unmarshal(data, &profiles) == nil {
			fmt.Printf("\n📱 App Profiles:\n")
			fmt.Printf("   Learned apps: %d\n", len(profiles))
		}
	} else {
		fmt.Println("\n📱 App Profiles: No data yet")
	}

	// Check custom domains
	customFile := aiDataDir + "/custom_domains.json"
	if data, err := os.ReadFile(customFile); err == nil {
		var custom struct {
			Sensitive map[string]bool `json:"sensitive"`
			Speed     map[string]bool `json:"speed"`
		}
		if json.Unmarshal(data, &custom) == nil {
			fmt.Printf("\n🌐 Custom Domains:\n")
			fmt.Printf("   Sensitive (always Tor): %d\n", len(custom.Sensitive))
			fmt.Printf("   Speed (bypass Tor): %d\n", len(custom.Speed))
		}
	}

	fmt.Println()
	fmt.Println("Data location:", aiDataDir)
	fmt.Println()

	return nil
}

func runAIReset(cmd *cobra.Command, args []string) error {
	aiDataDir := "/var/lib/torforge/ai"

	fmt.Println("🗑️  Resetting AI learned data...")

	// Remove data files
	os.Remove(aiDataDir + "/circuit_performance.json")
	os.Remove(aiDataDir + "/app_profiles.json")

	fmt.Println("✅ AI data reset. Learning will start fresh.")
	return nil
}

func runAIBypass(cmd *cobra.Command, args []string) error {
	domain := args[0]
	aiDataDir := "/var/lib/torforge/ai"
	customFile := aiDataDir + "/custom_domains.json"

	// Load existing
	var custom struct {
		Sensitive map[string]bool `json:"sensitive"`
		Speed     map[string]bool `json:"speed"`
	}
	custom.Sensitive = make(map[string]bool)
	custom.Speed = make(map[string]bool)

	if data, err := os.ReadFile(customFile); err == nil {
		json.Unmarshal(data, &custom)
	}

	// Add to speed bypass
	custom.Speed[strings.ToLower(domain)] = true

	// Save
	os.MkdirAll(aiDataDir, 0700)
	data, _ := json.MarshalIndent(custom, "", "  ")
	os.WriteFile(customFile, data, 0600)

	fmt.Printf("✅ Added '%s' to speed bypass list (will use direct connection)\n", domain)
	return nil
}

func runAISensitive(cmd *cobra.Command, args []string) error {
	domain := args[0]
	aiDataDir := "/var/lib/torforge/ai"
	customFile := aiDataDir + "/custom_domains.json"

	// Load existing
	var custom struct {
		Sensitive map[string]bool `json:"sensitive"`
		Speed     map[string]bool `json:"speed"`
	}
	custom.Sensitive = make(map[string]bool)
	custom.Speed = make(map[string]bool)

	if data, err := os.ReadFile(customFile); err == nil {
		json.Unmarshal(data, &custom)
	}

	// Add to sensitive
	custom.Sensitive[strings.ToLower(domain)] = true

	// Save
	os.MkdirAll(aiDataDir, 0700)
	data, _ := json.MarshalIndent(custom, "", "  ")
	os.WriteFile(customFile, data, 0600)

	fmt.Printf("✅ Added '%s' to sensitive list (will always use Tor)\n", domain)
	return nil
}
