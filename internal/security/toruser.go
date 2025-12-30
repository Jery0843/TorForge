// Package security provides security-related utilities for TorForge
// This file handles Tor user detection for running Tor unprivileged
package security

import (
	"os/user"
	"strconv"
)

// TorUserInfo contains information about the Tor user
type TorUserInfo struct {
	Username string
	UID      int
	GID      int
	Exists   bool
}

// GetExistingTorUser checks for existing system Tor user
// Returns user info if found, nil if no Tor user exists
func GetExistingTorUser() *TorUserInfo {
	// Check for existing Tor users in preference order
	preferredUsers := []string{"debian-tor", "tor", "_tor"}

	for _, username := range preferredUsers {
		if u, err := user.Lookup(username); err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			return &TorUserInfo{
				Username: u.Username,
				UID:      uid,
				GID:      gid,
				Exists:   true,
			}
		}
	}

	return nil // No Tor user found
}
