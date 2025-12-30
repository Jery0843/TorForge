// Package security provides security-related utilities for TorForge
package security

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/jery0843/torforge/pkg/logger"
)

// PrivilegeManager handles privilege dropping and elevation
type PrivilegeManager struct {
	originalUID int
	originalGID int
	droppedUID  int
	droppedGID  int
	isDropped   bool
	cleanupBin  string // Path to cleanup helper
}

// NewPrivilegeManager creates a new privilege manager
func NewPrivilegeManager() *PrivilegeManager {
	return &PrivilegeManager{
		originalUID: os.Getuid(),
		originalGID: os.Getgid(),
	}
}

// DropPrivileges drops from root to an unprivileged user
// Returns an error if not running as root or target user doesn't exist
func (pm *PrivilegeManager) DropPrivileges(targetUser string) error {
	log := logger.WithComponent("security")

	if os.Getuid() != 0 {
		return fmt.Errorf("not running as root, cannot drop privileges")
	}

	// Find target user
	u, err := user.Lookup(targetUser)
	if err != nil {
		// Try common unprivileged users
		for _, name := range []string{"nobody", "nogroup", "_nobody"} {
			u, err = user.Lookup(name)
			if err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("could not find unprivileged user: %w", err)
		}
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid: %w", err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("invalid gid: %w", err)
	}

	// Set supplementary groups to empty
	if err := syscall.Setgroups([]int{}); err != nil {
		log.Warn().Err(err).Msg("failed to clear supplementary groups")
	}

	// Drop GID first (must be done before dropping UID)
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("failed to set gid: %w", err)
	}

	// Drop UID
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("failed to set uid: %w", err)
	}

	pm.droppedUID = uid
	pm.droppedGID = gid
	pm.isDropped = true

	log.Info().
		Int("uid", uid).
		Int("gid", gid).
		Str("user", u.Username).
		Msg("🔒 Privileges dropped successfully")

	return nil
}

// IsDropped returns true if privileges have been dropped
func (pm *PrivilegeManager) IsDropped() bool {
	return pm.isDropped
}

// RunCleanupAsRoot runs the cleanup command with elevated privileges
// This spawns a separate process that requests sudo
func (pm *PrivilegeManager) RunCleanupAsRoot() error {
	log := logger.WithComponent("security")

	// If we're still root, just return (caller can do cleanup directly)
	if os.Getuid() == 0 {
		return nil
	}

	log.Info().Msg("requesting elevated privileges for cleanup...")

	// Try to find torforge binary
	executable, err := os.Executable()
	if err != nil {
		executable = "torforge"
	}

	// Run cleanup with sudo, using /dev/tty for password input
	// This avoids conflict with our keyboard listener on stdin
	cmd := exec.Command("sudo", executable, "stop")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Open /dev/tty directly for password input
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// Fallback to stdin if /dev/tty not available
		cmd.Stdin = os.Stdin
	} else {
		cmd.Stdin = tty
		defer tty.Close()
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cleanup failed (run 'sudo torforge stop' manually): %w", err)
	}

	return nil
}

// CanDropPrivileges checks if the system supports privilege dropping
func CanDropPrivileges() bool {
	// Check if running as root
	if os.Getuid() != 0 {
		return false
	}

	// Check if we can find an unprivileged user
	for _, name := range []string{"nobody", "nogroup", "_nobody", "daemon"} {
		if _, err := user.Lookup(name); err == nil {
			return true
		}
	}

	return false
}

// GetDroppedUser returns the username to drop privileges to
// Prefers SUDO_USER (the user who invoked sudo) so sudo works for cleanup
func GetDroppedUser() string {
	// First, try SUDO_USER - this is the user who ran sudo
	// This is important so that cleanup can use sudo with their credentials
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if _, err := user.Lookup(sudoUser); err == nil {
			return sudoUser
		}
	}

	// Fallback to 'nobody' (but sudo won't work for cleanup)
	for _, name := range []string{"nobody", "_nobody", "daemon"} {
		if _, err := user.Lookup(name); err == nil {
			return name
		}
	}
	return ""
}
