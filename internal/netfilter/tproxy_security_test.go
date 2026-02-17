package netfilter

import (
	"net"
	"syscall"
	"testing"
)

func TestSetSocketOption_Verification(t *testing.T) {
	// Create a UDP socket
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("failed to get syscall conn: %v", err)
	}

	// Set SO_REUSEADDR using the helper
	// SOL_SOCKET and SO_REUSEADDR are standard constants
	var setOptErr error
	err = rawConn.Control(func(fd uintptr) {
		// Try to set SO_REUSEADDR to 1
		setOptErr = setSocketOption(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		t.Fatalf("Control failed: %v", err)
	}

	if setOptErr != nil {
		t.Fatalf("setSocketOption failed: %v", setOptErr)
	}

	// Verify it was set using standard syscall
	var getOptVal int
	var getOptErr error
	err = rawConn.Control(func(fd uintptr) {
		getOptVal, getOptErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
	})
	if err != nil {
		t.Fatalf("Control failed: %v", err)
	}

	if getOptErr != nil {
		t.Errorf("GetsockoptInt failed: %v", getOptErr)
	} else if getOptVal != 1 {
		t.Errorf("SO_REUSEADDR = %d; want 1", getOptVal)
	}
}
