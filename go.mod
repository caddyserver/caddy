module github.com/caddyserver/caddy/v2

go 1.14

require (
	github.com/Masterminds/sprig/v3 v3.1.0
	github.com/alecthomas/chroma v0.8.2
	github.com/aryann/difflib v0.0.0-20170710044230-e206f873d14a
	github.com/caddyserver/certmagic v0.12.1-0.20210211020017-ebb8d8b435b4
	github.com/dustin/go-humanize v1.0.1-0.20200219035652-afde56e7acac
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/google/cel-go v0.6.0
	github.com/klauspost/compress v1.11.3
	github.com/klauspost/cpuid/v2 v2.0.1
	github.com/lucas-clemente/quic-go v0.19.3
	github.com/mholt/acmez v0.1.3
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/naoina/toml v0.1.1
	github.com/prometheus/client_golang v1.9.0
	github.com/smallstep/certificates v0.15.4
	github.com/smallstep/cli v0.15.2
	github.com/smallstep/nosql v0.3.0 // cannot upgrade from v0.3.0 until protobuf warning is fixed
	github.com/smallstep/truststore v0.9.6
	github.com/yuin/goldmark v1.2.1
	github.com/yuin/goldmark-highlighting v0.0.0-20200307114337-60d527fdb691
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98
	google.golang.org/protobuf v1.24.0 // cannot upgrade until warning is fixed
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.3.0
)
