// Package config provides configuration management for TorForge
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config represents the complete TorForge configuration
type Config struct {
	Tor        TorConfig        `mapstructure:"tor"`
	Proxy      ProxyConfig      `mapstructure:"proxy"`
	Bypass     BypassConfig     `mapstructure:"bypass"`
	Circuits   CircuitConfig    `mapstructure:"circuits"`
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
	Security   SecurityConfig   `mapstructure:"security"`
	API        APIConfig        `mapstructure:"api"`
}

// TorConfig configures Tor process management
type TorConfig struct {
	Binary           string `mapstructure:"binary"`             // Path to tor binary
	DataDir          string `mapstructure:"data_dir"`           // Tor data directory
	ControlPort      int    `mapstructure:"control_port"`       // Control port (9051)
	SOCKSPort        int    `mapstructure:"socks_port"`         // SOCKS port (9050)
	TransPort        int    `mapstructure:"trans_port"`         // Transparent proxy port (9040)
	DNSPort          int    `mapstructure:"dns_port"`           // DNS port (5353)
	ControlPassword  string `mapstructure:"control_password"`   // Hashed control password
	UseSystemTor     bool   `mapstructure:"use_system_tor"`     // Use existing Tor instance
	ExitNodes        string `mapstructure:"exit_nodes"`         // Preferred exit nodes
	ExcludeExitNodes string `mapstructure:"exclude_exit_nodes"` // Excluded exit nodes
}

// ProxyConfig configures the transparent proxy
type ProxyConfig struct {
	Enabled         bool     `mapstructure:"enabled"`
	Mode            string   `mapstructure:"mode"`             // "iptables" or "nftables"
	IPv6            bool     `mapstructure:"ipv6"`             // Enable IPv6 support
	UID             int      `mapstructure:"uid"`              // UID for Tor process
	AllowedPorts    []int    `mapstructure:"allowed_ports"`    // Allow specific ports without Tor
	BlockUDP        bool     `mapstructure:"block_udp"`        // Block all UDP (except DNS)
	InterfaceBypass []string `mapstructure:"interface_bypass"` // Interfaces to bypass
}

// BypassConfig configures traffic bypass rules
type BypassConfig struct {
	Enabled      bool         `mapstructure:"enabled"`
	Domains      []string     `mapstructure:"domains"`      // Domain patterns to bypass
	CIDRs        []string     `mapstructure:"cidrs"`        // CIDR ranges to bypass
	Protocols    []string     `mapstructure:"protocols"`    // Protocols to bypass (icmp, ntp)
	Applications []string     `mapstructure:"applications"` // Application names to bypass
	GeoIP        GeoIPConfig  `mapstructure:"geoip"`
	CustomRules  []BypassRule `mapstructure:"custom_rules"`
}

// GeoIPConfig configures GeoIP-based bypass
type GeoIPConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	DatabasePath string   `mapstructure:"database_path"` // Path to GeoLite2 database
	Countries    []string `mapstructure:"countries"`     // Country codes to bypass
}

// BypassRule represents a custom bypass rule
type BypassRule struct {
	Name        string `mapstructure:"name"`
	Type        string `mapstructure:"type"` // domain, cidr, port, protocol
	Pattern     string `mapstructure:"pattern"`
	Action      string `mapstructure:"action"` // bypass, block, tor
	Description string `mapstructure:"description"`
}

// CircuitConfig configures circuit management
type CircuitConfig struct {
	MaxCircuits         int           `mapstructure:"max_circuits"`      // Max concurrent circuits
	RotationInterval    time.Duration `mapstructure:"rotation_interval"` // Time-based rotation
	RotationBytes       int64         `mapstructure:"rotation_bytes"`    // Traffic-based rotation
	HealthCheckInterval time.Duration `mapstructure:"health_check_interval"`
	PerDomainIsolation  bool          `mapstructure:"per_domain_isolation"`
	PerAppIsolation     bool          `mapstructure:"per_app_isolation"`
}

// MonitoringConfig configures monitoring and metrics
type MonitoringConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	PrometheusPort   int    `mapstructure:"prometheus_port"`
	LogFile          string `mapstructure:"log_file"`
	LogLevel         string `mapstructure:"log_level"` // debug, info, warn, error
	AuditLog         string `mapstructure:"audit_log"` // JSONL audit log path
	LeakDetection    bool   `mapstructure:"leak_detection"`
	TrafficAnalytics bool   `mapstructure:"traffic_analytics"`
}

// SecurityConfig configures security features
type SecurityConfig struct {
	DNSLeakProtection     bool `mapstructure:"dns_leak_protection"`
	KillSwitch            bool `mapstructure:"kill_switch"` // Block all traffic if Tor fails
	ExitNodeReputation    bool `mapstructure:"exit_node_reputation"`
	FingerprintResistance bool `mapstructure:"fingerprint_resistance"`
	SandboxEnabled        bool `mapstructure:"sandbox_enabled"`
	NetworkNamespace      bool `mapstructure:"network_namespace"`
}

// APIConfig configures the REST/WebSocket API
type APIConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	ListenAddr  string `mapstructure:"listen_addr"`
	AuthToken   string `mapstructure:"auth_token"`
	TLSEnabled  bool   `mapstructure:"tls_enabled"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Tor: TorConfig{
			Binary:       "tor",
			DataDir:      "/var/lib/torforge",
			ControlPort:  9051,
			SOCKSPort:    9050,
			TransPort:    9040,
			DNSPort:      5353,
			UseSystemTor: false,
		},
		Proxy: ProxyConfig{
			Enabled:  true,
			Mode:     "iptables",
			IPv6:     false,
			UID:      0,
			BlockUDP: true,
		},
		Bypass: BypassConfig{
			Enabled: true,
			CIDRs: []string{
				"127.0.0.0/8",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
			Protocols: []string{},
		},
		Circuits: CircuitConfig{
			MaxCircuits:         8,
			RotationInterval:    10 * time.Minute,
			RotationBytes:       100 * 1024 * 1024, // 100MB
			HealthCheckInterval: 30 * time.Second,
			PerDomainIsolation:  true,
			PerAppIsolation:     false,
		},
		Monitoring: MonitoringConfig{
			Enabled:          true,
			PrometheusPort:   9100,
			LogLevel:         "info",
			LeakDetection:    true,
			TrafficAnalytics: true,
		},
		Security: SecurityConfig{
			DNSLeakProtection:     true,
			KillSwitch:            true,
			ExitNodeReputation:    false,
			FingerprintResistance: true,
			SandboxEnabled:        false,
			NetworkNamespace:      false,
		},
		API: APIConfig{
			Enabled:    false,
			ListenAddr: "127.0.0.1:8080",
		},
	}
}

// Load loads configuration from file and environment
func Load(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	v := viper.New()
	v.SetConfigType("yaml")

	// Set defaults
	setViperDefaults(v, cfg)

	// Load from file if specified
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		// Look in standard locations
		v.SetConfigName("torforge")
		v.AddConfigPath("/etc/torforge")
		v.AddConfigPath("$HOME/.config/torforge")
		v.AddConfigPath(".")

		// Ignore error if no config file found
		_ = v.ReadInConfig()
	}

	// Environment variable overrides
	v.SetEnvPrefix("TORFORGE")
	v.AutomaticEnv()

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Tor.ControlPort < 1 || c.Tor.ControlPort > 65535 {
		return fmt.Errorf("invalid control port: %d", c.Tor.ControlPort)
	}
	if c.Tor.SOCKSPort < 1 || c.Tor.SOCKSPort > 65535 {
		return fmt.Errorf("invalid SOCKS port: %d", c.Tor.SOCKSPort)
	}
	if c.Tor.TransPort < 1 || c.Tor.TransPort > 65535 {
		return fmt.Errorf("invalid transparent proxy port: %d", c.Tor.TransPort)
	}
	if c.Circuits.MaxCircuits < 1 {
		return fmt.Errorf("max_circuits must be at least 1")
	}
	if c.Proxy.Mode != "iptables" && c.Proxy.Mode != "nftables" {
		return fmt.Errorf("proxy mode must be 'iptables' or 'nftables'")
	}
	return nil
}

// GetConfigDir returns the configuration directory
func GetConfigDir() string {
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "torforge")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/torforge/config" // Fallback
	}
	return filepath.Join(home, ".config", "torforge")
}

// GetDataDir returns the data directory
func GetDataDir() string {
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "torforge")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/torforge/data" // Fallback
	}
	return filepath.Join(home, ".local", "share", "torforge")
}

func setViperDefaults(v *viper.Viper, cfg *Config) {
	v.SetDefault("tor.binary", cfg.Tor.Binary)
	v.SetDefault("tor.data_dir", cfg.Tor.DataDir)
	v.SetDefault("tor.control_port", cfg.Tor.ControlPort)
	v.SetDefault("tor.socks_port", cfg.Tor.SOCKSPort)
	v.SetDefault("tor.trans_port", cfg.Tor.TransPort)
	v.SetDefault("tor.dns_port", cfg.Tor.DNSPort)
	v.SetDefault("proxy.enabled", cfg.Proxy.Enabled)
	v.SetDefault("proxy.mode", cfg.Proxy.Mode)
	v.SetDefault("circuits.max_circuits", cfg.Circuits.MaxCircuits)
	v.SetDefault("circuits.rotation_interval", cfg.Circuits.RotationInterval)
	v.SetDefault("monitoring.enabled", cfg.Monitoring.Enabled)
	v.SetDefault("monitoring.log_level", cfg.Monitoring.LogLevel)
	v.SetDefault("security.dns_leak_protection", cfg.Security.DNSLeakProtection)
	v.SetDefault("security.kill_switch", cfg.Security.KillSwitch)
}
