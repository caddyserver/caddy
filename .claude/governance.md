# Governance — caddy
# Inferred by crag analyze — review and adjust as needed

## Identity
- Project: caddy
- Stack: go

## Gates (run in order, stop on failure)
### Lint
- go vet ./...
- golangci-lint run

### Test
- go test ./...

### CI (inferred from workflow)
- go build -trimpath -ldflags="-w -s" -v
- go test -v -coverprofile="cover-profile.out" -short -race ./...
- go build -trimpath -o caddy-"$GOOS"-$GOARCH 2> /dev/null

## Advisories (informational, not enforced)
- actionlint  # [ADVISORY]

## Branch Strategy
- Trunk-based development
- Free-form commits
- Commit trailer: Co-Authored-By: Claude <noreply@anthropic.com>

## Security
- No hardcoded secrets — grep for sk_live, AKIA, password= before commit

## Autonomy
- Auto-commit after gates pass

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

## Dependencies
- Package manager: go (go.sum)
- Go: >=1.25.0

## Anti-Patterns

Do not:
- Do not ignore returned errors — handle or explicitly discard with `_ =`
- Do not use `panic()` in library code — return errors instead
- Do not use `init()` functions unless absolutely necessary

