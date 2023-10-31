module github.com/caddyserver/caddy/v2

go 1.20

require (
	github.com/BurntSushi/toml v1.3.2
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/alecthomas/chroma/v2 v2.9.1
	github.com/aryann/difflib v0.0.0-20210328193216-ff5ff6dc229b
	github.com/caddyserver/certmagic v0.19.2
	github.com/dustin/go-humanize v1.0.1
	github.com/go-chi/chi/v5 v5.0.10
	github.com/google/cel-go v0.15.1
	github.com/google/uuid v1.3.1
	github.com/klauspost/compress v1.17.0
	github.com/klauspost/cpuid/v2 v2.2.5
	github.com/mastercactapus/proxyprotocol v0.0.4
	github.com/mholt/acmez v1.2.0
	github.com/prometheus/client_golang v1.15.1
	github.com/quic-go/quic-go v0.40.0
	github.com/smallstep/certificates v0.25.0
	github.com/smallstep/nosql v0.6.0
	github.com/smallstep/truststore v0.12.1
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.4
	github.com/tailscale/tscert v0.0.0-20230806124524-28a91b69a046
	github.com/yuin/goldmark v1.5.6
	github.com/yuin/goldmark-highlighting/v2 v2.0.0-20230729083705-37449abec8cc
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.45.0
	go.opentelemetry.io/contrib/propagators/autoprop v0.42.0
	go.opentelemetry.io/otel v1.19.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.19.0
	go.opentelemetry.io/otel/sdk v1.19.0
	go.uber.org/zap v1.25.0
	golang.org/x/crypto v0.14.0
	golang.org/x/exp v0.0.0-20230310171629-522b1b587ee0
	golang.org/x/net v0.17.0
	golang.org/x/sync v0.4.0
	golang.org/x/term v0.13.0
	google.golang.org/genproto/googleapis/api v0.0.0-20231016165738-49dd2c1f3d0b
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go/iam v1.1.2 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230305170008-8188dc5388df // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.5.0 // indirect
	github.com/golang/glog v1.1.2 // indirect
	github.com/google/certificate-transparency-go v1.1.6 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/pprof v0.0.0-20210720184732-4bb14d4b1be1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.4.1 // indirect
	github.com/smallstep/go-attestation v0.4.4-0.20230627102604-cf579e53cbd2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.opentelemetry.io/contrib/propagators/aws v1.17.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.17.0 // indirect
	go.opentelemetry.io/contrib/propagators/jaeger v1.17.0 // indirect
	go.opentelemetry.io/contrib/propagators/ot v1.17.0 // indirect
	go.uber.org/mock v0.3.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231016165738-49dd2c1f3d0b // indirect
)

require (
	filippo.io/edwards25519 v1.0.0 // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chzyer/readline v1.5.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/dgraph-io/badger v1.6.2 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.4 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/dlclark/regexp2 v1.10.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-sql-driver/mysql v1.7.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.14.0 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.2 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgtype v1.14.0 // indirect
	github.com/jackc/pgx/v4 v4.18.0 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/manifoldco/promptui v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/micromdm/scep/v2 v2.1.0 // indirect
	github.com/miekg/dns v1.1.55 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/rs/xid v1.5.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/slackhq/nebula v1.6.1 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/urfave/cli v1.22.14 // indirect
	go.etcd.io/bbolt v1.3.7 // indirect
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.19.0 // indirect
	go.opentelemetry.io/otel/metric v1.19.0 // indirect
	go.opentelemetry.io/otel/trace v1.19.0
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect
	go.step.sm/cli-utils v0.8.0 // indirect
	go.step.sm/crypto v0.35.1
	go.step.sm/linkedca v0.20.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.11.0 // indirect
	golang.org/x/sys v0.13.0
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/tools v0.10.0 // indirect
	google.golang.org/grpc v1.59.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	howett.net/plist v1.0.0 // indirect
)
