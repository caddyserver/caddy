package caddyhttp_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCaddyfile_ServersQUICOptions(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		input                 string
		expectErr             bool
		expectedInitialPacket uint16
		expectedDisablePMTUD  bool
	}{
		{
			name: "direct options",
			input: `{
				servers {
					initial_packet_size 1350
					disable_pmtud
				}
			}
			:80`,
			expectedInitialPacket: 1350,
			expectedDisablePMTUD:  true,
		},
		{
			name: "direct options with byte suffix",
			input: `{
				servers {
					initial_packet_size 1420B
				}
			}
			:80`,
			expectedInitialPacket: 1420,
			expectedDisablePMTUD:  false,
		},
		{
			name: "quic block options",
			input: `{
				servers {
					quic {
						initial_packet_size 1300
						disable_pmtud
					}
				}
			}
			:80`,
			expectedInitialPacket: 1300,
			expectedDisablePMTUD:  true,
		},
		{
			name: "invalid packet size too low",
			input: `{
				servers {
					initial_packet_size 1000
				}
			}
			:80`,
			expectErr: true,
		},
		{
			name: "invalid packet size too high",
			input: `{
				servers {
					initial_packet_size 70000
				}
			}
			:80`,
			expectErr: true,
		},
		{
			name: "invalid packet size not a number",
			input: `{
				servers {
					initial_packet_size notanumber
				}
			}
			:80`,
			expectErr: true,
		},
		{
			name: "disable_pmtud unexpected arg",
			input: `{
				servers {
					disable_pmtud true
				}
			}
			:80`,
			expectErr: true,
		},
		{
			name: "quic block unknown option",
			input: `{
				servers {
					quic {
						unknown_option
					}
				}
			}
			:80`,
			expectErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := caddyfile.Adapter{
				ServerType: httpcaddyfile.ServerType{},
			}
			out, _, err := adapter.Adapt([]byte(tc.input), nil)
			if tc.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			var config struct {
				Apps struct {
					HTTP struct {
						Servers map[string]*caddyhttp.Server `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}
			err = json.Unmarshal(out, &config)
			require.NoError(t, err)

			server, ok := config.Apps.HTTP.Servers["srv0"]
			require.True(t, ok, "expected server srv0 in config")
			assert.Equal(t, tc.expectedInitialPacket, server.InitialPacketSize)
			assert.Equal(t, tc.expectedDisablePMTUD, server.DisablePathMTUDiscovery)
		})
	}
}
