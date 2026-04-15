<!-- crag:auto-start -->
# GEMINI.md

> Generated from governance.md by crag. Regenerate: `crag compile --target gemini`

## Project Context

- **Name:** caddy
- **Stack:** go
- **Runtimes:** go

## Rules

### Quality Gates

Run these checks in order before committing any changes:

1. [lint] `go vet ./...`
2. [lint] `golangci-lint run`
3. [test] `go test ./...`
4. [ci (inferred from workflow)] `go build -trimpath -ldflags="-w -s" -v`
5. [ci (inferred from workflow)] `go test -v -coverprofile="cover-profile.out" -short -race ./...`
6. [ci (inferred from workflow)] `go build -trimpath -o caddy-"$GOOS"-$GOARCH 2> /dev/null`

### Security

- No hardcoded secrets — grep for sk_live, AKIA, password= before commit

### Workflow

- Follow project commit conventions
- Run quality gates before committing
- Review security implications of all changes

<!-- crag:auto-end -->
