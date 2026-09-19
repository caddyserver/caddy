# Caddy spec tests

End-to-end HTTP tests for Caddy handlers, written in
[Hurl](https://hurl.dev/). Each test drives a real Caddy process via the
admin API on `:2019`, runs requests against `:9080` / `:9443`, and asserts
on status, headers, and body. The Go integration suite under
[`caddytest/integration`](../integration/) covers scenarios that need Go logic;
this directory covers everything that is just "HTTP in, HTTP out."

## Layout

```
spec/
├── README.md
├── hurl_vars.properties      # Shared variables ({{indexed_root}}, etc.)
└── http/
    ├── <directive>/
    │   ├── spec.hurl         # One spec per directive
    │   └── assets/           # Optional fixtures (file_server, templates, …)
    └── …
```

Each `spec.hurl` is self-contained: it `POST`s its own Caddyfile to
`/load`, then issues the requests that validate the directive. Because
`/load` replaces the entire config, blocks within a file don't interfere
with each other.

## Prerequisites

- Hurl 7.x — `brew install hurl` on macOS, or the
  [official install guide](https://hurl.dev/docs/installation.html).
- A Caddy binary running with the admin API on `:2019`. For coverage,
  build with `-cover`:
  ```bash
  cd cmd/caddy && go build -cover -tags nobadger,nopgx,nomysql -o caddy-coverage
  ```

## Running

Start Caddy in one terminal:

```bash
mkdir -p /tmp/caddy-coverage
GOCOVERDIR=/tmp/caddy-coverage ./cmd/caddy/caddy-coverage run
```

Run the suite from the repo root in another terminal:

```bash
hurl --test \
     --variables-file caddytest/spec/hurl_vars.properties \
     --retry 3 --retry-interval 500 \
     caddytest/spec/http/**/spec.hurl
```

Run a single spec:

```bash
hurl --test \
     --variables-file caddytest/spec/hurl_vars.properties \
     caddytest/spec/http/file_server/spec.hurl
```

The CI workflow in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs the same command.

`--retry 3 --retry-interval 500` is a safety net for the brief window after every `POST /load` when the TLS app is being re-provisioned and may not yet have a cert for `localhost`. It only fires on failure; passing requests pay nothing.

## Coverage

After the suite finishes, stop the daemon and convert the binary
coverage profile:

```bash
./cmd/caddy/caddy-coverage stop
go tool covdata textfmt -i=/tmp/caddy-coverage -o coverage.out
go tool cover -html=coverage.out          # browser view
go tool cover -func=coverage.out | less   # per-function summary
```

Filter to a specific package:

```bash
go tool cover -func=coverage.out | grep modules/caddyhttp/fileserver
```

## Writing a spec

1. Create `http/<directive>/spec.hurl`.
2. For each scenario, write a `POST /load` with a minimal Caddyfile,
   then the request(s) that exercise it.
3. Use real assertions on observable state — status, headers, body,
   side-effect files. Avoid placeholder configs (e.g. routing logs to
   `discard`); they prove only that the directive parses, not that it
   works.
4. If the directive has visible side effects you can't read from the
   response, expose them with a sidecar site. For example, the `log`
   spec writes to `/tmp/caddy-log-spec/*.log` and adds a `:9081
   file_server` block so a follow-up GET can assert on the log
   contents.
5. Add reusable fixture paths to
   [`hurl_vars.properties`](hurl_vars.properties) instead of hard-coding
   them.

### Conventions

- **Ports** — `9080` (HTTP), `9443` (HTTPS), `:9081` for sidecar
  backends. Admin API is `:2019`. These are also what `--retry`
  assumes.
- **TLS** — always include `[Options]\ninsecure: true` on HTTPS
  requests; the local CA is not trusted.
- **Templating** — Hurl renders `{{name}}` as variable substitution. If
  you need literal `{{` in a Caddyfile (e.g. a `templates` body), escape
  it as `\{\{ ... \}\}`.

## Resources

- [Hurl manual](https://hurl.dev/docs/manual.html)
- [Caddy admin API](https://caddyserver.com/docs/api)
- [Caddyfile reference](https://caddyserver.com/docs/caddyfile)
- [Go coverage tooling](https://go.dev/testing/coverage/)
