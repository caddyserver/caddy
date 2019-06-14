package caddy

import (
	"strings"
	"testing"
)

func BenchmarkLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		r := strings.NewReader(`{
			"testval": "Yippee!",
			"apps": {
				"http": {
					"servers": {
						"myserver": {
							"listen": ["tcp/localhost:8080-8084"],
							"read_timeout": "30s"
						},
						"yourserver": {
							"listen": ["127.0.0.1:5000"],
							"read_header_timeout": "15s"
						}
					}
				}
			}
		}
		`)
		Load(r)
	}
}
