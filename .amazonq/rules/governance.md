<!-- crag:auto-start -->
# Amazon Q Rules — caddy

> Generated from governance.md by crag. Regenerate: `crag compile --target amazonq`

## About

(No description)

**Stack:** go

**Runtimes detected:** go

## How Amazon Q Should Behave on This Project

### Code Generation

1. **Run governance gates before suggesting commits.** The gates below define the quality bar.
2. **Respect classifications:** MANDATORY (default) blocks on failure; OPTIONAL warns; ADVISORY is informational only.
3. **Respect scopes:** Path-scoped gates run from that directory. Conditional gates skip when their file does not exist.
4. **No secrets.** - No hardcoded secrets — grep for sk_live, AKIA, password= before commit
5. **Minimal diffs.** Prefer editing existing code over creating new files. Do not refactor unrelated areas.

### Quality Gates

- `go vet ./...`
- `golangci-lint run`
- `go test ./...`
- `go build -trimpath -ldflags="-w -s" -v`
- `go test -v -coverprofile="cover-profile.out" -short -race ./...`
- `go build -trimpath -o caddy-"$GOOS"-$GOARCH 2> /dev/null`

### Commit Style

Follow project commit conventions.

### Boundaries

- All file operations must stay within this repository.
- No destructive shell commands (rm -rf above repo root, DROP TABLE without confirmation, force-push to main).
- No new dependencies without an explicit reason.

## Authoritative Source

When these instructions seem to conflict with something in the repo, **`.claude/governance.md` is the source of truth**. This file is a compiled view.

---

**Tool:** crag — https://www.npmjs.com/package/@whitehatd/crag

<!-- crag:auto-end -->
