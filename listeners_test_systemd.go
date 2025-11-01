//go:build linux && !nosystemd

package caddy

import (
	"os"
	"reflect"
	"strconv"
	"testing"
)

// TestGetSdFd tests the getSdFd function for systemd socket activation.
func TestGetSdFd(t *testing.T) {
	// Save original environment
	originalFdNames := os.Getenv("LISTEN_FDNAMES")
	originalFds := os.Getenv("LISTEN_FDS")
	originalPid := os.Getenv("LISTEN_PID")

	// Restore environment after test
	defer func() {
		if originalFdNames != "" {
			os.Setenv("LISTEN_FDNAMES", originalFdNames)
		} else {
			os.Unsetenv("LISTEN_FDNAMES")
		}
		if originalFds != "" {
			os.Setenv("LISTEN_FDS", originalFds)
		} else {
			os.Unsetenv("LISTEN_FDS")
		}
		if originalPid != "" {
			os.Setenv("LISTEN_PID", originalPid)
		} else {
			os.Unsetenv("LISTEN_PID")
		}
	}()

	tests := []struct {
		name        string
		fdNames     string
		fds         string
		socketName  string
		expectedFd  uint
		expectError bool
	}{
		{
			name:       "simple http socket",
			fdNames:    "http",
			fds:        "1",
			socketName: "http",
			expectedFd: 3,
		},
		{
			name:       "multiple different sockets - first",
			fdNames:    "http:https:dns",
			fds:        "3",
			socketName: "http",
			expectedFd: 3,
		},
		{
			name:       "multiple different sockets - second",
			fdNames:    "http:https:dns",
			fds:        "3",
			socketName: "https",
			expectedFd: 4,
		},
		{
			name:       "multiple different sockets - third",
			fdNames:    "http:https:dns",
			fds:        "3",
			socketName: "dns",
			expectedFd: 5,
		},
		{
			name:       "duplicate names - first occurrence (no index)",
			fdNames:    "web:web:api",
			fds:        "3",
			socketName: "web",
			expectedFd: 3,
		},
		{
			name:       "duplicate names - first occurrence (explicit index 0)",
			fdNames:    "web:web:api",
			fds:        "3",
			socketName: "web/0",
			expectedFd: 3,
		},
		{
			name:       "duplicate names - second occurrence (index 1)",
			fdNames:    "web:web:api",
			fds:        "3",
			socketName: "web/1",
			expectedFd: 4,
		},
		{
			name:       "complex duplicates - first api",
			fdNames:    "web:api:web:api:dns",
			fds:        "5",
			socketName: "api/0",
			expectedFd: 4,
		},
		{
			name:       "complex duplicates - second api",
			fdNames:    "web:api:web:api:dns",
			fds:        "5",
			socketName: "api/1",
			expectedFd: 6,
		},
		{
			name:       "complex duplicates - first web",
			fdNames:    "web:api:web:api:dns",
			fds:        "5",
			socketName: "web/0",
			expectedFd: 3,
		},
		{
			name:       "complex duplicates - second web",
			fdNames:    "web:api:web:api:dns",
			fds:        "5",
			socketName: "web/1",
			expectedFd: 5,
		},
		{
			name:        "socket not found",
			fdNames:     "http:https",
			fds:         "2",
			socketName:  "missing",
			expectError: true,
		},
		{
			name:        "empty socket name",
			fdNames:     "http",
			fds:         "1",
			socketName:  "",
			expectError: true,
		},
		{
			name:        "missing LISTEN_FDNAMES",
			fdNames:     "",
			fds:         "",
			socketName:  "http",
			expectError: true,
		},
		{
			name:        "index out of range",
			fdNames:     "web:web",
			fds:         "2",
			socketName:  "web/2",
			expectError: true,
		},
		{
			name:        "negative index",
			fdNames:     "web",
			fds:         "1",
			socketName:  "web/-1",
			expectError: true,
		},
		{
			name:        "invalid index format",
			fdNames:     "web",
			fds:         "1",
			socketName:  "web/abc",
			expectError: true,
		},
		{
			name:        "too many colons",
			fdNames:     "web",
			fds:         "1",
			socketName:  "web/0/extra",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up environment
			if tc.fdNames != "" {
				os.Setenv("LISTEN_FDNAMES", tc.fdNames)
			} else {
				os.Unsetenv("LISTEN_FDNAMES")
			}

			if tc.fds != "" {
				os.Setenv("LISTEN_FDS", tc.fds)
			} else {
				os.Unsetenv("LISTEN_FDS")
			}

			os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))

			// Test the function
			var (
				listenFdsWithNames map[string][]uint
				err                error
				fd                 uint
			)
			listenFdsWithNames, err = sdListenFdsWithNames()
			if err == nil {
				fd, err = getSdFd(listenFdsWithNames, tc.socketName, 0)
			}

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if fd != tc.expectedFd {
					t.Errorf("Expected FD %d but got %d", tc.expectedFd, fd)
				}
			}
		})
	}
}

// TestParseNetworkAddressSd tests parsing of sd and sdgram addresses.
func TestParseNetworkAddressSd(t *testing.T) {
	// Save and restore environment
	originalFdNames := os.Getenv("LISTEN_FDNAMES")
	originalFds := os.Getenv("LISTEN_FDS")
	originalPid := os.Getenv("LISTEN_PID")

	defer func() {
		if originalFdNames != "" {
			os.Setenv("LISTEN_FDNAMES", originalFdNames)
		} else {
			os.Unsetenv("LISTEN_FDNAMES")
		}
		if originalFds != "" {
			os.Setenv("LISTEN_FDS", originalFds)
		} else {
			os.Unsetenv("LISTEN_FDS")
		}
		if originalPid != "" {
			os.Setenv("LISTEN_PID", originalPid)
		} else {
			os.Unsetenv("LISTEN_PID")
		}
	}()

	// Set up test environment
	os.Setenv("LISTEN_FDNAMES", "http:https:dns")
	os.Setenv("LISTEN_FDS", "3")
	os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))

	tests := []struct {
		input        string
		expectedAddr NetworkAddress
		expectedFd   uint
		expectErr    bool
	}{
		{
			input: "sd/http",
			expectedAddr: NetworkAddress{
				Network: "sd",
				Host:    "http",
			},
			expectedFd: 3,
		},
		{
			input: "sd/https",
			expectedAddr: NetworkAddress{
				Network: "sd",
				Host:    "https",
			},
			expectedFd: 4,
		},
		{
			input: "sd/dns",
			expectedAddr: NetworkAddress{
				Network: "sd",
				Host:    "dns",
			},
			expectedFd: 5,
		},
		{
			input: "sd/http/0",
			expectedAddr: NetworkAddress{
				Network: "sd",
				Host:    "http/0",
			},
			expectedFd: 3,
		},
		{
			input: "sd/https/0",
			expectedAddr: NetworkAddress{
				Network: "sd",
				Host:    "https/0",
			},
			expectedFd: 4,
		},
		{
			input: "sdgram/http",
			expectedAddr: NetworkAddress{
				Network: "sdgram",
				Host:    "http",
			},
			expectedFd: 3,
		},
		{
			input: "sdgram/https",
			expectedAddr: NetworkAddress{
				Network: "sdgram",
				Host:    "https",
			},
			expectedFd: 4,
		},
		{
			input: "sdgram/http/0",
			expectedAddr: NetworkAddress{
				Network: "sdgram",
				Host:    "http/0",
			},
			expectedFd: 3,
		},
		{
			input:     "sd/nonexistent",
			expectErr: true,
		},
		{
			input:     "sd/nonexistent",
			expectErr: true,
		},
		{
			input:     "sd/http/99",
			expectErr: true,
		},
		{
			input:     "sd/invalid/abc",
			expectErr: true,
		},
		// Test that old fd/N syntax still works
		{
			input: "fd/7",
			expectedAddr: NetworkAddress{
				Network: "fd",
				Host:    "7",
			},
			expectedFd: 7,
		},
		{
			input: "fdgram/8",
			expectedAddr: NetworkAddress{
				Network: "fdgram",
				Host:    "8",
			},
			expectedFd: 8,
		},
	}

	for i, tc := range tests {
		actualAddr, err := ParseNetworkAddress(tc.input)
		var (
			listenFdsWithNames map[string][]uint
			fd                 uint
		)
		if err == nil {
			switch actualAddr.Network {
			case "fd":
				fallthrough
			case "fdgram":
				var fd64 uint64
				fd64, err = strconv.ParseUint(actualAddr.Host, 0, strconv.IntSize)
				if err == nil {
					fd = uint(fd64)
				}
			case "sd":
				fallthrough
			case "sdgram":
				listenFdsWithNames, err = sdListenFdsWithNames()
				fd, err = getSdFd(listenFdsWithNames, actualAddr.Host, 0)
			}
		}

		if tc.expectErr && err == nil {
			t.Errorf("Test %d (%s): Expected error but got none", i, tc.input)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d (%s): Expected no error but got: %v", i, tc.input, err)
		}
		if !tc.expectErr && !reflect.DeepEqual(tc.expectedAddr, actualAddr) {
			t.Errorf("Test %d (%s): Expected %+v but got %+v", i, tc.input, tc.expectedAddr, actualAddr)
		}
		if !tc.expectErr && fd != tc.expectedFd {
			t.Errorf("Expected FD %d but got %d", tc.expectedFd, fd)
		}
	}
}
