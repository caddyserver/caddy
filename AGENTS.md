<!-- crag:auto-start -->
# AGENTS.md

> Generated from governance.md by crag. Regenerate: `crag compile --target agents-md`

## Project: caddy


## Quality Gates

All changes must pass these checks before commit:

### Lint
1. `go vet ./...`
2. `golangci-lint run`

### Test
1. `go test ./...`

### Ci (inferred from workflow)
1. `go build -trimpath -ldflags="-w -s" -v`
2. `go test -v -coverprofile="cover-profile.out" -short -race ./...`
3. `go build -trimpath -o caddy-"$GOOS"-$GOARCH 2> /dev/null`

## Coding Standards

- Stack: go
- Follow project commit conventions

## Architecture

- Type: monolith

## Key Directories

- `.github/` — CI/CD
- `cmd/` — executables
- `modules/` — modules

## Testing

- Framework: go test
- Layout: flat

## Code Style

- Indent: ? tabs
- Linter: golangci-lint

## Anti-Patterns

Do not:
- Do not ignore returned errors — handle or explicitly discard with `_ =`
- Do not use `panic()` in library code — return errors instead
- Do not use `init()` functions unless absolutely necessary

## Security

- No hardcoded secrets — grep for sk_live, AKIA, password= before commit

## Workflow

1. Read `governance.md` at the start of every session — it is the single source of truth.
2. Run all mandatory quality gates before committing.
3. If a gate fails, fix the issue and re-run only the failed gate.
4. Use the project commit conventions for all changes.

<!-- crag:auto-end -->
