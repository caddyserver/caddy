# Caddyfile Formatter Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the standalone rune-by-rune Caddyfile formatter with a token-based formatter driven by the existing lexer, keeping the parser path unchanged, matching legacy output on valid input (minus documented divergences/improvements), and adding follow-imports and (default-off) braced-wrap modes.

**Architecture:** The lexer gains an opt-in *format mode* (`Lex` + `LexOptions`) that captures each token's verbatim raw source bytes, emits comment tokens, records how each token was separated from its predecessor, and splits structural braces. `Format` is rewritten to tokenize in format mode and render layout from that token stream. The old `Format` implementation is retained as a test-only `legacyFormat` oracle and deleted at the end of Phase 1.

**Tech Stack:** Go, standard `testing` package (including native fuzzing `testing.F`), the existing `caddyconfig/caddyfile` package.

## Global Constraints

- Module path: `github.com/caddyserver/caddy/v2`. Package under work: `caddyconfig/caddyfile`.
- **No breaking changes to existing exported API:** `Tokenize(input []byte, filename string) ([]Token, error)`, `Format(input []byte) []byte`, `Parse`, `Dispenser`, `Token`'s existing exported fields/methods, `NewDispenser`, `NewTestDispenser` keep their signatures and observable behavior.
- New exported symbols are allowed: `Lex`, `LexOptions`, `Token.Raw()`, `Token.IsComment()`, `FormatWithOptions`, `FormatOptions`, `FormatImports`, `FormattedFile`.
- Parser/`Tokenize` path must remain byte-for-byte unchanged: format-mode state is populated only when requested; new `Token` fields are unexported and zero-valued on the parse path.
- Every Go file keeps the existing Apache-2.0 license header (copy from any existing file in the package).
- Run tests with: `go test ./caddyconfig/caddyfile/...`. Run a single test with `-run TestName`. Vet with `go vet ./caddyconfig/caddyfile/...`.
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Work happens on branch `caddyfile-formatter-unification`.
- Sanctioned divergences from legacy (do NOT try to match legacy on these): interior/dangling glued braces on invalid input; heredoc close following lexer semantics; `\`+newline continuations re-indented to a hanging indent; the `<`-space quirk dropped (`foo < bar` stays `foo < bar`); inputs nested >10 levels.
- Intentional improvements (deliberately differ from legacy): I1 comments stay on brace lines; I2 empty blocks expand to `{`⏎`}`; I3 blank-line cap applies uniformly after comments; I4 token glued after `}` breaks to its own line.

---

## File Structure

- `caddyconfig/caddyfile/lexer.go` — MODIFY. Add `LexOptions`, `Lex`; format-mode fields on `Token` and on the `lexer` struct; raw-span capture; comment-token emission; separator-kind recording; structural-brace splitting; `Token.Raw()`, `Token.IsComment()`; update `Token.Clone()`. `Tokenize` delegates to `Lex`.
- `caddyconfig/caddyfile/lexer_test.go` — MODIFY. Add tests for `Lex` format-mode output (raw, comments, separators, braces).
- `caddyconfig/caddyfile/formatter.go` — REWRITE `Format` internals to a token renderer; add `FormatWithOptions` / `FormatOptions`. In Phase 2 add `FormatImports` / `FormattedFile` (may live in a new `format_imports.go`). In Phase 3 add the braced-wrap pass.
- `caddyconfig/caddyfile/formatter_legacy_test.go` — CREATE (Phase 1). Vendored copy of the pre-rewrite `Format` as unexported `legacyFormat`, for differential testing. DELETE at the end of Phase 1.
- `caddyconfig/caddyfile/formatter_test.go` — MODIFY. Keep ported cases; add improvement (I1–I4) and divergence table tests; add fuzz tests (`FuzzFormatParity`, `FuzzFormatIdempotent`, `FuzzFormatNoPanic`, `FuzzFormatSemanticPreserve`).
- `caddyconfig/caddyfile/format_imports.go` (+ `_test.go`) — CREATE (Phase 2). Import discovery + `FormatImports`.
- `caddyconfig/caddyfile/parse.go` — MODIFY (Phase 2). Extract the pure import-glob resolution helper reused by both `doImport` and discovery.
- `cmd/commandfuncs.go`, `cmd/commands.go` — MODIFY (Phase 2). `caddy fmt --imports` flag + wiring.
- `caddyconfig/caddyfile/formatter_braced_test.go` — CREATE (Phase 3). Braced-wrap tests.

---

# Phase 1 — Core: token model + formatter rewrite

## Task 1: Vendor the legacy formatter as a test oracle

**Files:**
- Create: `caddyconfig/caddyfile/formatter_legacy_test.go`

**Interfaces:**
- Produces: `func legacyFormat(input []byte) []byte` — a verbatim copy of the current `Format`, used only by tests in this package. Deleted at the end of Phase 1.

- [ ] **Step 1: Copy the current `Format` into the oracle file**

Create `formatter_legacy_test.go` with the Apache header, `package caddyfile`, and a function `legacyFormat` whose body is an exact copy of the current `Format` function body from `formatter.go` (rename `Format` → `legacyFormat`). It relies only on package-level helpers (`heredocMarkerRegexp`) already in the package, so no other changes are needed.

- [ ] **Step 2: Verify it compiles and matches current Format**

Add a temporary sanity test in the same file:

```go
func TestLegacyOracleMatchesCurrent(t *testing.T) {
	for _, in := range []string{"a{\n\tb\n}", "foo   bar", "# c\nsite {\n}\n"} {
		if string(legacyFormat([]byte(in))) != string(Format([]byte(in))) {
			t.Errorf("legacyFormat diverged from Format for %q", in)
		}
	}
}
```

Run: `go test ./caddyconfig/caddyfile/ -run TestLegacyOracleMatchesCurrent -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add caddyconfig/caddyfile/formatter_legacy_test.go
git commit -m "test: vendor legacy Caddyfile formatter as differential oracle

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add format-mode `Token` fields, accessors, and `Clone`

**Files:**
- Modify: `caddyconfig/caddyfile/lexer.go` (the `Token` struct ~line 40, `Clone` ~line 363)
- Test: `caddyconfig/caddyfile/lexer_test.go`

**Interfaces:**
- Produces:
  - `Token` gains unexported fields: `raw string`, `isComment bool`, `precededBySpace bool`, `continuation bool`.
  - `func (t Token) Raw() string` — returns `t.raw` if non-empty, else `t.Text`.
  - `func (t Token) IsComment() bool` — returns `t.isComment`.
  - `Token.Clone()` copies all new fields.

- [ ] **Step 1: Write the failing test**

Add to `lexer_test.go`:

```go
func TestTokenFormatModeAccessors(t *testing.T) {
	tok := Token{Text: "hello", raw: `"hello"`, isComment: false}
	if tok.Raw() != `"hello"` {
		t.Errorf("Raw() = %q, want %q", tok.Raw(), `"hello"`)
	}
	// falls back to Text when raw not captured
	if (Token{Text: "hi"}).Raw() != "hi" {
		t.Errorf("Raw() fallback = %q, want %q", (Token{Text: "hi"}).Raw(), "hi")
	}
	c := Token{Text: "# note", raw: "# note", isComment: true}
	if !c.IsComment() {
		t.Error("IsComment() = false, want true")
	}
	// Clone copies the new fields
	clone := c.Clone()
	if clone.raw != c.raw || clone.isComment != c.isComment {
		t.Errorf("Clone did not copy format-mode fields: %+v", clone)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./caddyconfig/caddyfile/ -run TestTokenFormatModeAccessors -v`
Expected: compile error — `raw`, `isComment` unknown fields; `Raw`, `IsComment` undefined.

- [ ] **Step 3: Add fields, accessors, and update Clone**

In `lexer.go`, extend the `Token` struct:

```go
	Token struct {
		File          string
		imports       []string
		Line          int
		Text          string
		wasQuoted     rune // enclosing quote character, if any
		heredocMarker string
		snippetName   string

		// format mode only (populated by Lex with LexOptions; zero on the parse path)
		raw             string // verbatim source bytes of the token
		isComment       bool   // this token is a # comment spanning to end-of-line
		precededBySpace bool   // whitespace separated this token from the previous one on the same line
		continuation    bool   // this token followed a '\'+newline line continuation
	}
```

Add accessors near `Quoted()`:

```go
// Raw returns the verbatim source text of the token as it appeared in the
// input, including quotes, backticks, escapes, and heredoc framing. It is only
// populated when the token was produced by Lex in format mode; otherwise it
// falls back to the processed Text.
func (t Token) Raw() string {
	if t.raw != "" {
		return t.raw
	}
	return t.Text
}

// IsComment returns true if the token is a comment. Comment tokens are only
// produced by Lex in format mode.
func (t Token) IsComment() bool {
	return t.isComment
}
```

Update `Clone()` to copy the new fields:

```go
func (t Token) Clone() Token {
	return Token{
		File:            t.File,
		imports:         append([]string{}, t.imports...),
		Line:            t.Line,
		Text:            t.Text,
		wasQuoted:       t.wasQuoted,
		heredocMarker:   t.heredocMarker,
		snippetName:     t.snippetName,
		raw:             t.raw,
		isComment:       t.isComment,
		precededBySpace: t.precededBySpace,
		continuation:    t.continuation,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./caddyconfig/caddyfile/ -run TestTokenFormatModeAccessors -v`
Expected: PASS.

- [ ] **Step 5: Run the full package to confirm no regressions**

Run: `go test ./caddyconfig/caddyfile/...`
Expected: PASS (new fields are zero-valued everywhere; `DeepEqual` token-slice tests still match since the parse path never sets them).

- [ ] **Step 6: Commit**

```bash
git add caddyconfig/caddyfile/lexer.go caddyconfig/caddyfile/lexer_test.go
git commit -m "caddyfile: add format-mode Token fields and accessors

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Introduce `LexOptions` and `Lex`, delegate `Tokenize`

**Files:**
- Modify: `caddyconfig/caddyfile/lexer.go` (`Tokenize` ~line 56, `lexer` struct ~line 32)
- Test: `caddyconfig/caddyfile/lexer_test.go`

**Interfaces:**
- Produces:
  - `type LexOptions struct { Comments bool; Raw bool }`
  - `func Lex(input []byte, filename string, opts LexOptions) ([]Token, error)`
  - `Tokenize(input, filename)` == `Lex(input, filename, LexOptions{})`.
- Consumes: format-mode `Token` fields from Task 2.

- [ ] **Step 1: Write the failing test**

```go
func TestLexEqualsTokenizeWithZeroOptions(t *testing.T) {
	in := []byte("site {\n\troot * /srv\n\tfile_server\n}\n")
	a, err := Tokenize(in, "Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Lex(in, "Caddyfile", LexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Lex(zero opts) != Tokenize\n a=%+v\n b=%+v", a, b)
	}
}
```

(Ensure `reflect` is imported in the test file.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./caddyconfig/caddyfile/ -run TestLexEqualsTokenizeWithZeroOptions -v`
Expected: compile error — `Lex`, `LexOptions` undefined.

- [ ] **Step 3: Add `LexOptions`, `Lex`, and lexer option fields**

In `lexer.go`, add fields to the `lexer` struct for later tasks and define the entry points:

```go
	lexer struct {
		reader       *bufio.Reader
		token        Token
		line         int
		skippedLines int

		// format-mode configuration and state (Tasks 4-6)
		opts       LexOptions
		src        []byte // original input, for raw slicing
		pos        int    // bytes consumed from src
		lastSize   int    // byte size of the most recently read rune
		tokenStart int    // byte offset in src where the current token began
	}

// LexOptions configures optional, non-default lexer behavior used for
// formatting. The zero value reproduces Tokenize exactly.
type LexOptions struct {
	// Comments, when true, emits comment tokens (spanning '#' to end of line)
	// instead of discarding comments.
	Comments bool
	// Raw, when true, records each token's verbatim source bytes in Token.raw.
	Raw bool
}
```

Replace `Tokenize` and add `Lex`:

```go
// Tokenize takes bytes as input and lexes it into a list of tokens that can be
// parsed as a Caddyfile. filename fills each token's File field.
func Tokenize(input []byte, filename string) ([]Token, error) {
	return Lex(input, filename, LexOptions{})
}

// Lex tokenizes input like Tokenize, but with the given options. With the zero
// LexOptions it is identical to Tokenize. Format-mode options (Comments, Raw)
// populate additional Token state used by the formatter and are not needed for
// parsing.
func Lex(input []byte, filename string, opts LexOptions) ([]Token, error) {
	l := lexer{opts: opts}
	if opts.Raw {
		l.src = input
	}
	if err := l.load(bytes.NewReader(input)); err != nil {
		return nil, err
	}
	var tokens []Token
	for {
		found, err := l.next()
		if err != nil {
			return nil, err
		}
		if !found {
			break
		}
		l.token.File = filename
		tokens = append(tokens, l.token)
	}
	return tokens, nil
}
```

- [ ] **Step 4: Run test + full package**

Run: `go test ./caddyconfig/caddyfile/...`
Expected: PASS (behavior unchanged; `next()` doesn't yet read the new fields).

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/lexer.go caddyconfig/caddyfile/lexer_test.go
git commit -m "caddyfile: add Lex and LexOptions; Tokenize delegates to Lex

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Capture verbatim raw source per token (format mode)

**Files:**
- Modify: `caddyconfig/caddyfile/lexer.go` (`load` ~line 78, `next` ~line 107, add a `readRune` helper)
- Test: `caddyconfig/caddyfile/lexer_test.go`

**Interfaces:**
- Consumes: `lexer.src/pos/lastSize/tokenStart`, `LexOptions.Raw`, `Token.raw` (Tasks 2–3).
- Produces: when `opts.Raw`, every returned token's `raw` equals the exact input slice it came from (quotes, backticks, escapes, and full heredoc framing included).

**Mechanism:** track a byte position `pos` (incremented by each rune's UTF-8 size), record `tokenStart` at the byte offset of the token's first rune, and set `token.raw = string(l.src[tokenStart:tokenEnd])` when the token is finalized. Because a token's raw span is contiguous in the source and formatting does no env substitution, an offset slice is exact and cheap.

- [ ] **Step 1: Write the failing tests (the raw round-trip contract)**

```go
func TestLexRawCapture(t *testing.T) {
	cases := []struct {
		in      string
		text    string // processed Text of the single token
		wantRaw string // verbatim source of that token
	}{
		{`hello`, `hello`, `hello`},
		{`"a \"b\" "`, `a "b" `, `"a \"b\" "`},
		{"`raw \"x\"`", `raw "x"`, "`raw \"x\"`"},
		{`\<<NOTHEREDOC`, `<<NOTHEREDOC`, `\<<NOTHEREDOC`},
	}
	for _, c := range cases {
		toks, err := Lex([]byte(c.in), "T", LexOptions{Raw: true})
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if len(toks) != 1 {
			t.Fatalf("%q: got %d tokens, want 1", c.in, len(toks))
		}
		if toks[0].Text != c.text {
			t.Errorf("%q: Text = %q, want %q", c.in, toks[0].Text, c.text)
		}
		if toks[0].Raw() != c.wantRaw {
			t.Errorf("%q: Raw() = %q, want %q", c.in, toks[0].Raw(), c.wantRaw)
		}
	}
}

func TestLexRawCaptureHeredoc(t *testing.T) {
	in := "x <<END\n\thello\n\tEND"
	toks, err := Lex([]byte(in), "T", LexOptions{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	// token 0 is "x"; token 1 is the heredoc
	if len(toks) != 2 {
		t.Fatalf("got %d tokens, want 2", len(toks))
	}
	// heredoc Text is the de-indented body; Raw is the full framing verbatim.
	if toks[1].Raw() != "<<END\n\thello\n\tEND" {
		t.Errorf("heredoc Raw() = %q, want %q", toks[1].Raw(), "<<END\n\thello\n\tEND")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestLexRawCapture -v`
Expected: FAIL — `Raw()` returns processed `Text`, not the verbatim source.

- [ ] **Step 3: Implement offset tracking + raw slicing**

Add rune-reading helpers to `lexer.go`:

```go
// readRune reads the next rune and, in raw mode, advances the byte position.
func (l *lexer) readRune() (rune, error) {
	ch, size, err := l.reader.ReadRune()
	if err == nil {
		l.lastSize = size
		l.pos += size
	}
	return ch, err
}

// unreadRune pushes back the last rune read by readRune, keeping pos in sync.
func (l *lexer) unreadRune() error {
	if err := l.reader.UnreadRune(); err != nil {
		return err
	}
	l.pos -= l.lastSize
	l.lastSize = 0
	return nil
}
```

In `load`, use the helpers so the BOM is accounted for (a discarded BOM advances `pos`; an unread first rune rolls `pos` back to 0). Replace the direct `ReadRune`/`UnreadRune` calls there with `l.readRune()`/`l.unreadRune()`.

In `next`, replace every `l.reader.ReadRune()` with `l.readRune()`. Record the token's start offset the first time a rune is committed to the token. The reliable point: capture a candidate start `startCandidate := l.pos - l.lastSize` immediately after reading each rune, and when the code transitions from "no token yet" to "token begun" (the `len(val) == 0` branches that set quotes/backticks, begin a comment, begin a heredoc, or append the first literal rune), set `l.tokenStart = startCandidate`. Then in `makeToken`, set the raw span:

```go
makeToken := func(quoted rune) bool {
	l.token.Text = string(val)
	l.token.wasQuoted = quoted
	l.token.heredocMarker = heredocMarker
	if l.opts.Raw {
		l.token.raw = string(l.src[l.tokenStart:l.pos])
	}
	return true
}
```

Because `l.pos` points just past the last consumed rune of the token at each `makeToken` call site (the closing quote, the heredoc marker, or the delimiter that ended the token), the slice `src[tokenStart:pos]` is the verbatim token. When a token ends because of a trailing delimiter (space/newline) that was already consumed, subtract that delimiter: at the space/newline `makeToken(0)` call site (the `unicode.IsSpace` branch), use `src[l.tokenStart : l.pos-l.lastSize]` so the delimiter is excluded. Introduce a small helper to make both call sites explicit:

```go
// rawSlice returns the verbatim source of the current token. trimLast excludes
// the most recently read rune (used when a delimiter terminated the token).
func (l *lexer) rawSlice(trimLast bool) string {
	end := l.pos
	if trimLast {
		end -= l.lastSize
	}
	return string(l.src[l.tokenStart:end])
}
```

and set `l.token.raw = l.rawSlice(trimLast)` in `makeToken` with `trimLast` threaded from each call site (true only for the whitespace-terminated case).

- [ ] **Step 4: Run the raw tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestLexRaw -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS. Iterate on `tokenStart`/`trimLast` placement against the four `TestLexRawCapture` cases and the heredoc case until all raw slices are verbatim. (Parse-path tests still pass because raw is only set when `opts.Raw`.)

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/lexer.go caddyconfig/caddyfile/lexer_test.go
git commit -m "caddyfile: capture verbatim raw source spans in format mode

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Emit comment tokens in format mode

**Files:**
- Modify: `caddyconfig/caddyfile/lexer.go` (`next`, the comment handling ~line 264-269)
- Test: `caddyconfig/caddyfile/lexer_test.go`

**Interfaces:**
- Consumes: `opts.Comments`, raw capture (Task 4), `Token.isComment`.
- Produces: with `opts.Comments`, a `#` that begins at a token boundary (`len(val) == 0`) produces a comment token whose `Text`/`raw` span from `#` to just before the end-of-line, with `isComment = true`. `#` mid-token stays literal (so `e#f` is one token). Without `opts.Comments`, comments are discarded exactly as today.

- [ ] **Step 1: Write the failing tests**

```go
func TestLexComments(t *testing.T) {
	toks, err := Lex([]byte("foo # hi there\nbar"), "T", LexOptions{Comments: true, Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	// foo | # hi there | bar
	if len(toks) != 3 {
		t.Fatalf("got %d tokens, want 3: %+v", len(toks), toks)
	}
	if !toks[1].IsComment() || toks[1].Text != "# hi there" {
		t.Errorf("token 1 = %q (comment=%v), want comment %q", toks[1].Text, toks[1].IsComment(), "# hi there")
	}
	if toks[2].Text != "bar" {
		t.Errorf("token 2 = %q, want bar", toks[2].Text)
	}
}

func TestLexHashMidTokenIsLiteral(t *testing.T) {
	toks, err := Lex([]byte("e#f redir /a/#/b"), "T", LexOptions{Comments: true})
	if err != nil {
		t.Fatal(err)
	}
	texts := []string{}
	for _, tk := range toks {
		texts = append(texts, tk.Text)
	}
	want := []string{"e#f", "redir", "/a/#/b"}
	if !reflect.DeepEqual(texts, want) {
		t.Errorf("texts = %v, want %v", texts, want)
	}
	for _, tk := range toks {
		if tk.IsComment() {
			t.Errorf("unexpected comment token %q", tk.Text)
		}
	}
}

func TestLexCommentsDisabledDiscards(t *testing.T) {
	toks, _ := Lex([]byte("foo # hi\nbar"), "T", LexOptions{})
	if len(toks) != 2 {
		t.Fatalf("got %d tokens, want 2 (comment discarded)", len(toks))
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestLexComment -v`
Expected: FAIL — comments are discarded even with `Comments: true`.

- [ ] **Step 3: Implement comment-token emission**

In `next`, the comment handling currently sets `comment = true` and then `continue`s (discarding runes). When `l.opts.Comments` is set and a comment begins at a token boundary, accumulate the comment text into `val` and mark the token. Replace the block at ~264-269:

```go
		// comments must be at the start of a token (preceded by space or newline)
		if ch == '#' && len(val) == 0 {
			comment = true
			if l.opts.Comments {
				// begin a comment token; record its start for raw capture
				l.tokenStart = l.pos - l.lastSize
				l.token = Token{Line: l.line, isComment: true}
			}
		}
		if comment {
			if l.opts.Comments {
				// a newline ends the comment; don't consume it (leave line accounting
				// to the normal whitespace path on the next iteration)
				if ch == '\n' {
					if err := l.unreadRune(); err != nil {
						return false, err
					}
					l.token.isComment = true
					return makeToken(0), nil // makeToken sets Text/raw from val + span
				}
				val = append(val, ch)
			}
			continue
		}
```

Note `makeToken` must preserve `l.token.isComment` (it currently overwrites `wasQuoted`/`heredocMarker` but not `isComment`; leave `isComment` untouched there). Since a comment is not whitespace-terminated (we unread the newline), use `trimLast = false` for its raw slice — the raw is `#...` up to but excluding the newline.

- [ ] **Step 4: Run comment tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestLex -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS. Confirm `TestLexCommentsDisabledDiscards` and all existing parse tests still pass (default path discards comments unchanged).

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/lexer.go caddyconfig/caddyfile/lexer_test.go
git commit -m "caddyfile: emit comment tokens in format mode

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Record separator kind (glued / space / continuation)

**Files:**
- Modify: `caddyconfig/caddyfile/lexer.go` (`next` whitespace handling ~line 236-260, escaped-newline handling ~line 245-251)
- Test: `caddyconfig/caddyfile/lexer_test.go`

**Interfaces:**
- Consumes: format-mode fields.
- Produces: with `opts.Comments || opts.Raw` (format mode), each token records `precededBySpace` (whitespace separated it from the previous token) and `continuation` (a `\`+newline preceded it). A token at the start of a line records neither as meaningful (the renderer uses line numbers for line breaks); these flags are only consulted for same-line tokens.

- [ ] **Step 1: Write the failing tests**

```go
func TestLexSeparatorKind(t *testing.T) {
	// glued comment after a closing quote: "x"#c -> [ "x", "#c" ] glued
	toks, _ := Lex([]byte(`"x"#c`), "T", LexOptions{Comments: true, Raw: true})
	if len(toks) != 2 || !toks[1].IsComment() {
		t.Fatalf("got %+v, want string + comment", toks)
	}
	if toks[1].precededBySpace {
		t.Error(`"x"#c: comment should be glued (precededBySpace=false)`)
	}

	toks2, _ := Lex([]byte(`"x" #c`), "T", LexOptions{Comments: true, Raw: true})
	if !toks2[1].precededBySpace {
		t.Error(`"x" #c: comment should be space-separated (precededBySpace=true)`)
	}

	// line continuation: `foo bar \<nl>baz` -> baz has continuation=true
	toks3, _ := Lex([]byte("foo bar \\\nbaz"), "T", LexOptions{Raw: true})
	last := toks3[len(toks3)-1]
	if last.Text != "baz" || !last.continuation {
		t.Errorf("continuation token = %q continuation=%v, want baz/true", last.Text, last.continuation)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestLexSeparatorKind -v`
Expected: FAIL — flags never set.

- [ ] **Step 3: Implement separator tracking**

In `next`, maintain two local booleans reset per token: `sawSpace` (a whitespace rune was seen since the previous token on the same line) and `sawContinuation` (an escaped newline was seen since the previous token). Set them where whitespace and escaped newlines are consumed:

- In the `unicode.IsSpace(ch)` branch, before `continue`, set `sawSpace = true` (only meaningful while `len(val) == 0`, i.e. between tokens).
- In the escaped-newline case (`escaped` true and `ch == '\n'`, ~line 245), set `sawContinuation = true` in addition to the existing `l.skippedLines++`.

When a token begins (first rune committed, and for comment start), copy the flags into the token:

```go
	l.token.precededBySpace = sawSpace
	l.token.continuation = sawContinuation
```

Do this at each token-start point (the `len(val) == 0` literal/quote/backtick branch, the heredoc start, and the comment start). Reset `sawSpace`/`sawContinuation` to false once a token has begun so they describe only the gap before the current token.

- [ ] **Step 4: Run separator tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestLex -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/lexer.go caddyconfig/caddyfile/lexer_test.go
git commit -m "caddyfile: record token separator kind in format mode

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Split structural braces in format mode (peel trailing `{`, recognize `{}`)

**Files:**
- Modify: `caddyconfig/caddyfile/lexer.go` (post-process in `Lex`, or inline in the token-append loop)
- Test: `caddyconfig/caddyfile/lexer_test.go`

**Interfaces:**
- Consumes: format-mode tokens.
- Produces (format mode only): tokens whose text is exactly `{` or `}` are left as-is (structural). A literal token that ends with `{` and whose prefix is non-empty and contains no `{`/`}` is split into `[prefix, "{"]`, where the `{` token inherits `File`/`Line` and is marked `precededBySpace = false`. A `{}` token is split into `["{", "}"]` (both structural, marking it an empty block). Quoted/backtick/heredoc/comment tokens are never split. Placeholders like `{$A}`, `foo{bar}`, `{$A}{` are never split.

**Implementation note:** do this as a post-pass over the token slice inside `Lex` (only when a format-mode option is set), producing a new slice. This keeps `next()` untouched and the parse path identical.

- [ ] **Step 1: Write the failing tests**

```go
func lexTexts(t *testing.T, in string) []string {
	t.Helper()
	toks, err := Lex([]byte(in), "T", LexOptions{Raw: true, Comments: true})
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, tk := range toks {
		out = append(out, tk.Text)
	}
	return out
}

func TestLexBraceSplitting(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"example.com{", []string{"example.com", "{"}},
		{"{$A}{", []string{"{$A}{"}},        // placeholder tail: not split
		{"foo{bar}", []string{"foo{bar}"}},  // placeholder: not split
		{"route {}", []string{"route", "{", "}"}},
		{"route { }", []string{"route", "{", "}"}},
		{"a { b {} }", []string{"a", "{", "b", "{", "}", "}"}},
		{"site {\n\troot\n}", []string{"site", "{", "root", "}"}},
	}
	for _, c := range cases {
		got := lexTexts(t, c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestLexBraceSplitting -v`
Expected: FAIL — `example.com{`, `route {}` not split.

- [ ] **Step 3: Implement the brace-splitting post-pass**

In `Lex`, after collecting `tokens`, when `opts.Comments || opts.Raw`, run:

```go
	if opts.Comments || opts.Raw {
		tokens = splitStructuralBraces(tokens)
	}
```

Add:

```go
// splitStructuralBraces rewrites a format-mode token stream so that structural
// braces are their own tokens. It splits a "{}" token into "{" and "}", and
// peels a single trailing "{" off a literal token whose prefix contains no
// other braces (e.g. example.com{ -> example.com, {). Quoted, backtick,
// heredoc, and comment tokens are never split.
func splitStructuralBraces(in []Token) []Token {
	out := make([]Token, 0, len(in))
	for _, tk := range in {
		if tk.wasQuoted != 0 || tk.isComment || tk.Text == "{" || tk.Text == "}" {
			out = append(out, tk)
			continue
		}
		if tk.Text == "{}" {
			open := tk
			open.Text, open.raw = "{", "{"
			closeT := tk
			closeT.Text, closeT.raw = "}", "}"
			closeT.precededBySpace = false
			out = append(out, open, closeT)
			continue
		}
		// peel a single trailing "{" if the prefix is non-empty and brace-free
		if strings.HasSuffix(tk.Text, "{") {
			prefix := tk.Text[:len(tk.Text)-1]
			if prefix != "" && !strings.ContainsAny(prefix, "{}") {
				lit := tk
				lit.Text = prefix
				if lit.raw != "" && strings.HasSuffix(lit.raw, "{") {
					lit.raw = lit.raw[:len(lit.raw)-1]
				}
				brace := tk
				brace.Text, brace.raw = "{", "{"
				brace.precededBySpace = false
				out = append(out, lit, brace)
				continue
			}
		}
		out = append(out, tk)
	}
	return out
}
```

(Confirm `strings` is imported in `lexer.go` — it already is.)

- [ ] **Step 4: Run brace tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestLexBraceSplitting -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/lexer.go caddyconfig/caddyfile/lexer_test.go
git commit -m "caddyfile: split structural braces in format mode

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Rewrite `Format` as a token renderer — core layout

**Files:**
- Modify: `caddyconfig/caddyfile/formatter.go` (replace `Format` body; keep the function signature)
- Test: `caddyconfig/caddyfile/formatter_test.go` (existing `TestFormatter` table drives this)

**Interfaces:**
- Consumes: `Lex(input, "", LexOptions{Comments: true, Raw: true})`, `Token` fields (`Text`, `raw`, `Line`, `wasQuoted`, `isComment`, `precededBySpace`, `continuation`, `NumLineBreaks`).
- Produces: `func Format(input []byte) []byte` (unchanged signature). New internal `func formatTokens(tokens []Token) []byte`.

**Renderer model:** walk the tokens with state `{nesting int, atLineStart bool, wroteAnything bool, prev *Token}`. A structural token is one whose `Text` is exactly `{` or `}`. Decide line breaks from token `Line` deltas (using the existing `isNextOnNewLine`/`NumLineBreaks` helpers), emit tabs = `nesting`, one space between same-line non-structural tokens (none if `!precededBySpace`), attach `{` to the current line, put `}` on its own line, cap blank lines at one, insert a blank line after a top-level `}`, and emit heredoc/quoted/backtick/`raw` verbatim. This task lands the bulk of `TestFormatter`; Tasks 9–11 refine comments, continuations, empty blocks, and the import/`}`-glue rules.

- [ ] **Step 1: Keep the existing `TestFormatter` as the driver; run it against the current (legacy) Format to confirm the baseline**

Run: `go test ./caddyconfig/caddyfile/ -run TestFormatter -v`
Expected: PASS (still the legacy implementation).

- [ ] **Step 2: Replace `Format` with the token renderer**

Replace the body of `Format` in `formatter.go`:

```go
// Format formats the input Caddyfile to a standard, nice-looking appearance.
func Format(input []byte) []byte {
	return FormatWithOptions(input, FormatOptions{})
}

// FormatOptions configures optional formatting behavior.
type FormatOptions struct {
	// WrapUnbracedSite, when true, wraps a single unbraced site block in braces
	// (Phase 3). Default false.
	WrapUnbracedSite bool
}

// FormatWithOptions formats the input Caddyfile with the given options.
func FormatWithOptions(input []byte, opts FormatOptions) []byte {
	tokens, err := Lex(input, "", LexOptions{Comments: true, Raw: true})
	if err != nil {
		// On a lex error, fall back to the trimmed input with a trailing newline;
		// Format never panics (Invariant 3).
		trimmed := bytes.TrimSpace(input)
		return append(trimmed, '\n')
	}
	// opts.WrapUnbracedSite is wired in Phase 3 (Task 19); ignored here so this
	// task compiles without wrapUnbracedSite existing yet.
	return formatTokens(tokens)
}
```

Add `formatTokens` implementing the renderer model above. Use a `strings.Builder`/`bytes.Buffer`. Core loop sketch (fill in against the tests):

```go
func formatTokens(tokens []Token) []byte {
	var out bytes.Buffer
	nesting := 0
	atLineStart := true
	wrote := false
	writeIndent := func() {
		for i := 0; i < nesting; i++ {
			out.WriteByte('\t')
		}
	}
	for i := range tokens {
		tk := tokens[i]
		structural := tk.Text == "{" || tk.Text == "}"

		// determine line breaks relative to the previous emitted token
		var newLine bool
		if i > 0 {
			newLine = isNextOnNewLine(tokens[i-1], tk)
		}
		// ... emit blank lines (capped at 1) from Line gaps,
		//     handle '{' attach-to-line, '}' own-line + dedent,
		//     indentation at line start, single space between same-line tokens
		//     (skip space when !tk.precededBySpace), and verbatim raw for the token.
		_ = structural
		_ = newLine
		_ = wrote
		_ = atLineStart
		_ = writeIndent
	}
	trimmed := bytes.TrimSpace(out.Bytes())
	return append(trimmed, '\n')
}
```

Emit each non-structural token via `tk.Raw()` (verbatim quotes/escapes/heredocs); structural `{`/`}` are emitted by the brace rules, not as raw. Use the existing `isNextOnNewLine` and `Token.NumLineBreaks` for line/blank-line decisions (blank line when the line gap between consecutive tokens is ≥ 2, capped to one).

- [ ] **Step 3: Iterate until the non-comment `TestFormatter` cases pass**

Run: `go test ./caddyconfig/caddyfile/ -run TestFormatter -v`
Expected: initially several failures. Iterate the renderer against the table until the cases that don't involve comments, continuations, or empty `{}`/`{ }` pass. (Comment/continuation/empty-block cases are finished in Tasks 9–11; if any ported case is a known intentional improvement, move it to the I-tests in Task 12 and annotate it.)

- [ ] **Step 4: Commit the core renderer**

```bash
git add caddyconfig/caddyfile/formatter.go caddyconfig/caddyfile/formatter_test.go
git commit -m "caddyfile: rewrite Format as a token-based renderer (core layout)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Renderer — comments (I1, I3) and continuations (D1)

**Files:**
- Modify: `caddyconfig/caddyfile/formatter.go` (`formatTokens`)
- Test: `caddyconfig/caddyfile/formatter_test.go`

**Interfaces:**
- Consumes: `Token.isComment`, `precededBySpace`, `continuation`.

- [ ] **Step 1: Write the failing tests (improvements + continuation)**

```go
func TestFormatCommentsOnBraceLines(t *testing.T) {
	cases := []struct{ in, want string }{
		{"site {\n\tfoo\n} # after close\n", "site {\n\tfoo\n} # after close\n"},
		{"site { # note\n\tfoo\n}\n", "site { # note\n\tfoo\n}\n"},
		{"site # note\n{\n\tfoo\n}\n", "site { # note\n\tfoo\n}\n"},
	}
	for _, c := range cases {
		if got := string(Format([]byte(c.in))); got != c.want {
			t.Errorf("in %q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestFormatBlankLineCapAfterComment(t *testing.T) {
	got := string(Format([]byte("foo # inline\n\n\nbar\n")))
	want := "foo # inline\n\nbar\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatContinuationHangingIndent(t *testing.T) {
	in := "route {\n\treverse_proxy \\\n\ta \\\n\tb\n}\n"
	want := "route {\n\treverse_proxy \\\n\t\ta \\\n\t\tb\n}\n"
	if got := string(Format([]byte(in))); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run 'TestFormatComments|TestFormatBlankLineCap|TestFormatContinuation' -v`
Expected: FAIL.

- [ ] **Step 3: Implement comment and continuation rules**

In `formatTokens`:
- **I1:** when a comment token has `precededBySpace` and is on the same line as the previous emitted token (including when the previous token is a `{` or `}`), render it inline with a single leading space instead of breaking to a new line. A comment alone on its line renders at the current indent. For the address/comment/brace case, when the next token after a same-line trailing comment is a structural `{` that opens the current line's block, emit the `{` on the head line *before* the comment (i.e. fold `addr # c`⏎`{` to `addr { # c`).
- **I3:** compute blank lines purely from `Line` gaps for all tokens including comments (already the model in Task 8), so a comment line no longer perturbs the count.
- **D1 continuation:** when `tk.continuation` is true, emit `\`, a newline, then `nesting+1` tabs before the token, instead of a single space.

- [ ] **Step 4: Run tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestFormat -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/formatter.go caddyconfig/caddyfile/formatter_test.go
git commit -m "caddyfile: token renderer comments (I1/I3) and continuations (D1)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Renderer — empty blocks (I2) and post-`}` token break (I4)

**Files:**
- Modify: `caddyconfig/caddyfile/formatter.go` (`formatTokens`)
- Test: `caddyconfig/caddyfile/formatter_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestFormatEmptyBlocksExpand(t *testing.T) {
	cases := []struct{ in, want string }{
		{"route {}", "route {\n}\n"},
		{"route { }", "route {\n}\n"},
		{"a { b {} }", "a {\n\tb {\n\t}\n}\n"},
	}
	for _, c := range cases {
		if got := string(Format([]byte(c.in))); got != c.want {
			t.Errorf("in %q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatTokenAfterCloseBraceBreaks(t *testing.T) {
	in := "a {\n\tb {\n\t\tc\n\t} d\n}"
	want := "a {\n\tb {\n\t\tc\n\t}\n\td\n}\n"
	if got := string(Format([]byte(in))); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run 'TestFormatEmptyBlocks|TestFormatTokenAfterCloseBrace' -v`
Expected: FAIL.

- [ ] **Step 3: Implement I2 and I4**

- **I2:** after Task 7, `{}`/`{ }` are already `{` then `}` tokens. The brace rules render `{` on the head line and `}` on its own line, giving the expanded empty block. Ensure a `{` immediately followed by a `}` still increments then decrements nesting so the `}` lands at the opening line's indent.
- **I4:** when the previous emitted token was a structural `}` and the current token is on the same source line (not itself a `}` and not a comment handled by I1), force a newline + indent before it instead of a space/tab.

- [ ] **Step 4: Run tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestFormat -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/formatter.go caddyconfig/caddyfile/formatter_test.go
git commit -m "caddyfile: token renderer empty blocks (I2) and post-} break (I4)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Renderer — top-level import / standalone-brace exception; drop nesting cap; `<` unquirked

**Files:**
- Modify: `caddyconfig/caddyfile/formatter.go` (`formatTokens`)
- Test: `caddyconfig/caddyfile/formatter_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestFormatImportStandaloneBrace(t *testing.T) {
	// immediately after a top-level import line: keep the brace standalone
	in1 := "import a.caddy\nimport b.caddy\n{\n\torder x first\n}\n"
	if got := string(Format([]byte(in1))); got != in1 {
		t.Errorf("standalone brace after import not preserved:\n got %q\nwant %q", got, in1)
	}
	// with an intervening blank line: brace glues up and the blank line is removed
	in2 := "import a.caddy\n\n{\n\torder x first\n}\n"
	want2 := "import a.caddy {\n\torder x first\n}\n"
	if got := string(Format([]byte(in2))); got != want2 {
		t.Errorf("blank-line case:\n got %q\nwant %q", got, want2)
	}
}

func TestFormatDeepNestingNoCap(t *testing.T) {
	// 12 levels deep; every level indents (no 10-level clamp)
	var b strings.Builder
	for i := 0; i < 12; i++ {
		b.WriteString(strings.Repeat("\t", i) + "l" + strconv.Itoa(i) + " {\n")
	}
	b.WriteString(strings.Repeat("\t", 12) + "x\n")
	for i := 11; i >= 0; i-- {
		b.WriteString(strings.Repeat("\t", i) + "}\n")
	}
	out := string(Format([]byte(b.String())))
	if !strings.Contains(out, "\n"+strings.Repeat("\t", 12)+"x\n") {
		t.Errorf("expected 12-tab indent for deepest token, got:\n%s", out)
	}
}

func TestFormatAngleNotQuirked(t *testing.T) {
	if got := string(Format([]byte("foo < bar"))); got != "foo < bar\n" {
		t.Errorf("got %q, want %q", got, "foo < bar\n")
	}
}
```

(Ensure `strconv` and `strings` are imported in the test file.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run 'TestFormatImportStandaloneBrace|TestFormatDeepNesting|TestFormatAngle' -v`
Expected: FAIL.

- [ ] **Step 3: Implement the three rules**

- **Import exception:** track whether the current top-level (nesting 0) line's first token is `import`. A standalone `{` (one that begins a new line) that immediately follows such a line — with no intervening blank line — is emitted on its own line rather than folded onto the import line; if there is an intervening blank line, fold it onto the import line and drop the blank line (matches the legacy `previousLineWasTopLevelImport` gate).
- **No nesting cap:** the renderer already indents by `nesting`; simply do not clamp. Confirm nothing limits `nesting`.
- **`<` unquirked (D4):** there is no special `<` handling to add — the naive same-line spacing already yields `foo < bar`. The test guards against regressions.

- [ ] **Step 4: Run tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestFormat -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/formatter.go caddyconfig/caddyfile/formatter_test.go
git commit -m "caddyfile: import-brace exception, drop nesting cap, drop < quirk

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Differential + property fuzz tests, then delete the oracle

**Files:**
- Modify: `caddyconfig/caddyfile/formatter_test.go`
- Delete: `caddyconfig/caddyfile/formatter_legacy_test.go` (last step)

**Interfaces:**
- Consumes: `Format`, `legacyFormat`, `Parse`.

- [ ] **Step 1: Add the parity + property fuzz tests**

```go
// containsParityExclusion reports whether input triggers a documented
// divergence/improvement and must be excluded from strict legacy parity.
func containsParityExclusion(b []byte) bool {
	s := string(b)
	if strings.Contains(s, "{$") || strings.Contains(s, "<") ||
		strings.Contains(s, "#") || strings.Contains(s, "{}") ||
		strings.Contains(s, "\\\n") {
		return true
	}
	// line-start import
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "import") {
			return true
		}
	}
	return false
}

func maxNesting(tokens []Token) int {
	max, cur := 0, 0
	for _, tk := range tokens {
		switch tk.Text {
		case "{":
			cur++
			if cur > max {
				max = cur
			}
		case "}":
			if cur > 0 {
				cur--
			}
		}
	}
	return max
}

func FuzzFormatIdempotent(f *testing.F) {
	for _, s := range []string{"", "  ", "a{\nb\n}", "site {\n\tfoo # c\n}\n", "x <<E\nhi\nE\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		once := Format(in)
		twice := Format(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent:\n once=%q\ntwice=%q", once, twice)
		}
	})
}

func FuzzFormatNoPanic(f *testing.F) {
	f.Add([]byte("\x00\x00"))
	f.Add([]byte("`unterminated"))
	f.Add([]byte("x <<E\nno end marker"))
	f.Fuzz(func(t *testing.T, in []byte) {
		_ = Format(in) // must not panic
	})
}

func FuzzFormatParity(f *testing.F) {
	for _, s := range []string{"a{\nb\n}", "foo   bar\nbaz", "site {\n\troot * /srv\n}\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if containsParityExclusion(in) {
			return
		}
		toks, err := Lex(in, "", LexOptions{Comments: true, Raw: true})
		if err != nil || maxNesting(toks) > 10 {
			return
		}
		if _, perr := Parse("Caddyfile", append([]byte{}, in...)); perr != nil {
			return // only compare on valid input
		}
		got := Format(in)
		want := legacyFormat(in)
		if !bytes.Equal(got, want) {
			t.Errorf("parity divergence on valid input %q:\n new=%q\n old=%q", in, got, want)
		}
	})
}

func FuzzFormatSemanticPreserve(f *testing.F) {
	for _, s := range []string{"site {\n\troot * /srv\n\tfile_server\n}\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if strings.Contains(string(in), "{$") || strings.Contains(string(in), "import") {
			return // env/import expansion is out of scope for this invariant
		}
		a, err1 := Parse("Caddyfile", append([]byte{}, in...))
		if err1 != nil {
			return
		}
		b, err2 := Parse("Caddyfile", Format(in))
		if err2 != nil {
			t.Fatalf("formatted output no longer parses: %v\ninput=%q\nout=%q", err2, in, Format(in))
		}
		if !sameStructure(a, b) {
			t.Errorf("structure changed by Format\ninput=%q", in)
		}
	})
}

// sameStructure compares two parses by their per-segment token Text sequences.
func sameStructure(a, b []ServerBlock) bool {
	seq := func(blocks []ServerBlock) []string {
		var s []string
		for _, blk := range blocks {
			s = append(s, "K")
			for _, k := range blk.Keys {
				s = append(s, k.Text)
			}
			for _, seg := range blk.Segments {
				s = append(s, "S")
				for _, tk := range seg {
					s = append(s, tk.Text)
				}
			}
		}
		return s
	}
	return reflect.DeepEqual(seq(a), seq(b))
}
```

**Env pinning:** these fuzz targets must run with a pinned empty environment so `replaceEnvVars` is deterministic. Add a `TestMain` that clears the environment for the package test binary:

```go
func TestMain(m *testing.M) {
	os.Clearenv()
	os.Exit(m.Run())
}
```

(Ensure `os` is imported. If a `TestMain` already exists in the package, merge the `os.Clearenv()` call into it.)

- [ ] **Step 2: Run the seed corpus (no `-fuzz`) and a short fuzz burst**

Run: `go test ./caddyconfig/caddyfile/ -run 'Fuzz' -v`
Then: `go test ./caddyconfig/caddyfile/ -run xxx -fuzz FuzzFormatParity -fuzztime 30s`
Repeat for `FuzzFormatIdempotent`, `FuzzFormatNoPanic`, `FuzzFormatSemanticPreserve`.
Expected: PASS / no crashers. Fix any real divergence (must be a bug, since triggers are excluded) or, if it is a genuinely new sanctioned class, add it to `containsParityExclusion` with a comment and a dedicated table test.

- [ ] **Step 3: Delete the legacy oracle and its sanity test**

Once parity holds, delete `formatter_legacy_test.go` and remove `FuzzFormatParity` (which depends on `legacyFormat`) — or keep `FuzzFormatParity` gated behind a build tag with the oracle retained in a `testdata`-only helper. Default: delete both.

```bash
git rm caddyconfig/caddyfile/formatter_legacy_test.go
```

Remove `FuzzFormatParity` and `containsParityExclusion`/`maxNesting` if now unused.

- [ ] **Step 4: Run the full package**

Run: `go test ./caddyconfig/caddyfile/... && go vet ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A caddyconfig/caddyfile/
git commit -m "caddyfile: fuzz invariants for the token formatter; drop legacy oracle

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: Seed corpus + confirm `FormattingDifference` and callers

**Files:**
- Modify: `caddyconfig/caddyfile/formatter_test.go`
- Verify: `caddyconfig/caddyfile/adapter.go` (`FormattingDifference`), `cmd/commandfuncs.go` (`cmdFmt`)

- [ ] **Step 1: Add explicit seed/table cases for the fuzzer-favorite angles**

Add a `TestFormatFuzzerAngles` table covering (with hand-written expected outputs): unbalanced braces, `{ }`, heredoc marker-as-substring (`x <<END\nfooEND\nEND\n`), CRLF, unterminated quote/backtick, `#` inside quotes and heredocs, `\<<`, trailing `\`, `{$X}`/`{$X:d}`/`{$}`, BOM, NUL bytes, empty and whitespace-only input, lone `\r` (`respond hello\rworld` → `respond helloworld\n`), backtick as first token after `{`. For each, assert idempotency (`Format(Format(x)) == Format(x)`).

- [ ] **Step 2: Add a `FormattingDifference` parity check on the repo's real configs**

```go
func TestFormattingDifferenceStableOnFormatted(t *testing.T) {
	// Any already-formatted config must report no difference (byte-identical).
	in := []byte("site {\n\troot * /srv\n\tfile_server\n}\n")
	formatted := Format(in)
	if _, diff := FormattingDifference("Caddyfile", formatted); diff {
		t.Error("FormattingDifference reported a diff on already-formatted input")
	}
}
```

- [ ] **Step 3: Run the whole repo's Caddyfile-adjacent tests**

Run: `go test ./caddyconfig/... ./cmd/...`
Expected: PASS. (`caddytest/` integration configs, if touched, format identically; investigate any diff as either a bug or a documented improvement.)

- [ ] **Step 4: Commit**

```bash
git add caddyconfig/caddyfile/formatter_test.go
git commit -m "caddyfile: seed corpus and FormattingDifference stability tests

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

# Phase 2 — Follow-imports mode

## Task 14: Extract a pure import-glob resolution helper

**Files:**
- Modify: `caddyconfig/caddyfile/parse.go` (`doImport` ~line 356)
- Test: `caddyconfig/caddyfile/parse_test.go`

**Interfaces:**
- Produces: `func resolveImportGlob(importerFile, importPattern string) (matches []string, err error)` — the pure path-resolution slice of `doImport`: `caddy.FastAbs` of the importer, single-wildcard check (issue #2096), `filepath.Glob`, dotfile skip for glob matches (issue #5295). No token splicing, arg replacement, variadic handling, or block consumption.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing test**

```go
func TestResolveImportGlob(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.caddy"), []byte("a\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.caddy"), []byte("b\n"), 0o600)
	os.WriteFile(filepath.Join(dir, ".hidden.caddy"), []byte("h\n"), 0o600)
	importer := filepath.Join(dir, "Caddyfile")
	matches, err := resolveImportGlob(importer, "*.caddy")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 { // dotfile skipped for glob
		t.Errorf("got %d matches, want 2: %v", len(matches), matches)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestResolveImportGlob -v`
Expected: compile error — `resolveImportGlob` undefined.

- [ ] **Step 3: Extract the helper and call it from `doImport`**

Move the resolution logic (currently `parse.go:421-462`) into `resolveImportGlob(importerFile, importPattern string) ([]string, error)`, returning `matches`. Replace that inline block in `doImport` with a call to the helper (passing `p.Dispenser.File()` as `importerFile`). Preserve current behavior exactly (the empty-matches warning/error stays in `doImport`, not in the pure helper).

- [ ] **Step 4: Run parse tests + full package**

Run: `go test ./caddyconfig/caddyfile/...`
Expected: PASS (no behavior change to `doImport`).

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/parse.go caddyconfig/caddyfile/parse_test.go
git commit -m "caddyfile: extract pure import-glob resolution helper

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Import discovery (first-token rule, cross-file snippets, env-aware globs)

**Files:**
- Create: `caddyconfig/caddyfile/format_imports.go`
- Test: `caddyconfig/caddyfile/format_imports_test.go`

**Interfaces:**
- Produces: `func discoverImportedFiles(rootFile string, rootInput []byte) (files []string, err error)` — the set of files reachable via file imports from `rootFile`, in deterministic order, deduped by `caddy.FastAbs`, cycle-safe, excluding the root itself.
- Consumes: `Lex`, `resolveImportGlob` (Task 14), `replaceEnvVars` (parse.go), `caddy.FastAbs`.

**Rules:** `import` is a directive only as the first token of its line. Env-substitute the import argument (via `replaceEnvVars`) before resolving its glob. Skip `{block}`/`{blocks.*}` placeholder args. Collect all snippet names `(name)` defined across the whole discovered graph first; treat an `import <arg>` as a file import only if `<arg>` is not a known snippet name. A non-glob file import that doesn't exist on disk is skipped with a `caddy.Log().Warn`, not an error.

- [ ] **Step 1: Write the failing tests (fixture trees)**

```go
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverImportedFiles(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	writeFile(t, root, "import sites/*.caddy\nimport mysnip\n")
	os.MkdirAll(filepath.Join(dir, "sites"), 0o755)
	writeFile(t, filepath.Join(dir, "sites", "a.caddy"), "(mysnip) {\n\trespond 200\n}\nlocalhost {\n\timport mysnip\n}\n")
	rootInput, _ := os.ReadFile(root)
	files, err := discoverImportedFiles(root, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	// sites/a.caddy is discovered; "mysnip" is a snippet (defined in a.caddy), not a file
	want := []string{filepath.Join(dir, "sites", "a.caddy")}
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	if len(files) != 1 || abs(files[0]) != abs(want[0]) {
		t.Errorf("got %v, want %v", files, want)
	}
}

func TestDiscoverIgnoresNonDirectiveImport(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	writeFile(t, root, "localhost {\n\tbasic_auth / import password\n}\n")
	rootInput, _ := os.ReadFile(root)
	files, err := discoverImportedFiles(root, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("got %v, want none ('import' here is an argument)", files)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestDiscover -v`
Expected: compile error — `discoverImportedFiles` undefined.

- [ ] **Step 3: Implement discovery**

Create `format_imports.go`. Algorithm:
1. Lex the root input (`LexOptions{}` is fine for discovery), and lex each discovered file as it is visited.
2. First pass over each visited file's tokens: collect snippet names — a top-level `(name)` token (starts with `(`, ends with `)`) followed by a `{` marks a snippet definition; add `name` to a global set.
3. Second pass: for each token that is the first token of its line and equals `import`, take the next same-line token as the argument. If the argument (after `strings.HasPrefix "{block" ... ` check) is a `{block}`/`{blocks.*}` placeholder, skip. If the (env-substituted) argument equals a known snippet name, skip. Otherwise `replaceEnvVars` the argument bytes, then `resolveImportGlob(currentFile, arg)`; for non-glob args with zero matches and no wildcard chars, `caddy.Log().Warn` and skip; else enqueue matches.
4. Track visited files by `caddy.FastAbs`; dedupe; guard cycles; recurse. Determine "first token of its line" using `isNextOnNewLine(prev, cur)` / `Token.Line`.

Because snippet definitions can be in files discovered later, do discovery in two rounds: round 1 walks the full reachable file set collecting snippet names and candidate imports; round 2 finalizes the file set by dropping candidates whose arg is a known snippet. (A simple fixed-point over the worklist also works.)

- [ ] **Step 4: Run discovery tests + full package**

Run: `go test ./caddyconfig/caddyfile/ -run TestDiscover -v && go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/format_imports.go caddyconfig/caddyfile/format_imports_test.go
git commit -m "caddyfile: import discovery for follow-imports formatting

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: `FormatImports` — format the root and discovered files

**Files:**
- Modify: `caddyconfig/caddyfile/format_imports.go`
- Test: `caddyconfig/caddyfile/format_imports_test.go`

**Interfaces:**
- Produces:
  - `type FormattedFile struct { Path string; Content []byte }`
  - `func FormatImports(filename string, opts FormatOptions) ([]FormattedFile, error)` — reads `filename`, formats it with `FormatWithOptions(..., opts)` but with `WrapUnbracedSite` forced OFF for imported files, discovers imported files, formats each with `FormatWithOptions(fileBytes, FormatOptions{})` at its own baseline, and returns one `FormattedFile` per file (root first). Reads each file itself.
- Consumes: `discoverImportedFiles`, `FormatWithOptions`.

- [ ] **Step 1: Write the failing test**

```go
func TestFormatImports(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "Caddyfile")
	writeFile(t, root, "import sites/a.caddy\n")
	os.MkdirAll(filepath.Join(dir, "sites"), 0o755)
	// deliberately messy imported file to prove it gets formatted at baseline 0
	writeFile(t, filepath.Join(dir, "sites", "a.caddy"), "localhost{\nrespond   200\n}\n")
	results, err := FormatImports(root, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	// results[0] is the root; results[1] is the imported file, formatted
	var imported *FormattedFile
	for i := range results {
		if strings.HasSuffix(results[i].Path, "a.caddy") {
			imported = &results[i]
		}
	}
	if imported == nil {
		t.Fatal("imported file not in results")
	}
	want := "localhost {\n\trespond 200\n}\n"
	if string(imported.Content) != want {
		t.Errorf("imported formatted = %q, want %q", imported.Content, want)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestFormatImports -v`
Expected: compile error — `FormatImports`/`FormattedFile` undefined.

- [ ] **Step 3: Implement `FormatImports`**

Read the root file, format it (root may honor `opts.WrapUnbracedSite`), then for each discovered file read+format with `FormatOptions{}` (wrap forced off). Return `[]FormattedFile` with the root first, then discovered files in discovery order.

- [ ] **Step 4: Run tests + full package**

Run: `go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/format_imports.go caddyconfig/caddyfile/format_imports_test.go
git commit -m "caddyfile: FormatImports formats root plus imported files

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 17: Wire `caddy fmt --imports`

**Files:**
- Modify: `cmd/commands.go` (fmt command flags ~line 381), `cmd/commandfuncs.go` (`cmdFmt` ~line 685)
- Test: `cmd/commands_test.go`

**Interfaces:**
- Consumes: `caddyfile.FormatImports`, `caddyfile.Format`.

- [ ] **Step 1: Add the `--imports` flag**

In `cmd/commands.go`, add a boolean flag `imports` to the `fmt` command's flag set (alongside `overwrite`/`diff`), with usage: "Also format files referenced by import directives".

- [ ] **Step 2: Write the failing behavior test**

Add to `cmd/commands_test.go` a test that constructs a temp dir with a root Caddyfile importing a messy file, invokes the fmt logic with `--imports --overwrite`, and asserts both files are rewritten formatted. (Follow the existing `cmd` test patterns; if `cmdFmt` isn't directly callable, factor the imports path into a small helper `fmtFiles(files []caddyfile.FormattedFile, overwrite bool, ...)` and test that.)

- [ ] **Step 3: Implement the CLI branch**

In `cmdFmt`, after resolving `configFile`:
- Reject `--imports` together with stdin (`configFile == "-"`): return `ExitCodeFailedStartup` with "cannot use --imports when reading from stdin (no source directory to resolve imports against)".
- When `fl.Bool("imports")`: call `caddyfile.FormatImports(configFile, caddyfile.FormatOptions{})`. With `--overwrite`, write each `FormattedFile.Content` to its `Path`. Without `--overwrite`, print each file preceded by a header line (e.g. `# <path>`); with `--diff`, print a per-file diff.
- Otherwise keep the existing single-file behavior unchanged.

- [ ] **Step 4: Run cmd tests**

Run: `go test ./cmd/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/commands.go cmd/commandfuncs.go cmd/commands_test.go
git commit -m "cmd: add 'caddy fmt --imports' to format imported files

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

# Phase 3 — Braced-wrap (default OFF)

## Task 18: Single-unbraced-site detection

**Files:**
- Modify: `caddyconfig/caddyfile/formatter.go` (or a new `formatter_wrap.go`)
- Test: `caddyconfig/caddyfile/formatter_braced_test.go`

**Interfaces:**
- Produces: `func isSingleUnbracedSite(tokens []Token) bool` — true iff the format-mode token stream is exactly one top-level server block with no wrapping braces, whose address list is non-empty and is not a snippet `(...)` or named route `&(...)`, and which is not a global-options block (leading `{` with no address).
- Consumes: format-mode tokens.

- [ ] **Step 1: Write the failing tests**

```go
func TestIsSingleUnbracedSite(t *testing.T) {
	yes := []string{
		"localhost\nrespond 200\n",
		"localhost\nreverse_proxy {\n\tto a:80\n}\n", // interior braces OK
	}
	no := []string{
		"localhost {\n\trespond 200\n}\n", // already braced
		"(snip) {\n\trespond 200\n}\n",    // snippet
		"&(route) {\n\trespond 200\n}\n",  // named route
		"{\n\tdebug\n}\n",                 // global options only
		"a.com\nrespond 200\n\nb.com\nrespond 404\n", // multi-site (ambiguous)
		"",                                             // empty
	}
	for _, in := range yes {
		toks, _ := Lex([]byte(in), "", LexOptions{Comments: true, Raw: true})
		if !isSingleUnbracedSite(toks) {
			t.Errorf("want single-unbraced-site for %q", in)
		}
	}
	for _, in := range no {
		toks, _ := Lex([]byte(in), "", LexOptions{Comments: true, Raw: true})
		if isSingleUnbracedSite(toks) {
			t.Errorf("did NOT expect single-unbraced-site for %q", in)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run TestIsSingleUnbracedSite -v`
Expected: compile error — `isSingleUnbracedSite` undefined.

- [ ] **Step 3: Implement the structural detector**

Walk tokens tracking structural-brace nesting. Replicate the parser's address boundary: the address list is the run of leading non-comment tokens up to the first newline (honoring trailing-comma continuation across lines). Return false if: there are zero address tokens; the first address token is a snippet `(...)`/named route `&(...)`; the first structural token on the address line is `{` (already braced or global-options); or there is more than one top-level block/site (any return to nesting 0 followed by another address group). Interior braces (nesting ≥ 1) are ignored. Comments are ignored for the boundary decision.

- [ ] **Step 4: Run tests + full package**

Run: `go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/formatter.go caddyconfig/caddyfile/formatter_braced_test.go
git commit -m "caddyfile: detect single unbraced site block

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 19: `wrapUnbracedSite` and the `WrapUnbracedSite` option

**Files:**
- Modify: `caddyconfig/caddyfile/formatter.go`
- Test: `caddyconfig/caddyfile/formatter_braced_test.go`

**Interfaces:**
- Produces: `func wrapUnbracedSite(tokens []Token) []Token` — if `isSingleUnbracedSite(tokens)`, returns tokens with a `{` inserted after the address list and a `}` appended (so the renderer indents the body and emits braces); otherwise returns tokens unchanged. Wired into `FormatWithOptions` (Task 8) behind `opts.WrapUnbracedSite`.
- Consumes: `isSingleUnbracedSite`.

- [ ] **Step 1: Write the failing tests**

```go
func TestFormatWithWrapUnbracedSite(t *testing.T) {
	// eligible: wrapped
	in := "localhost\nroot * /srv\nfile_server\n"
	want := "localhost {\n\troot * /srv\n\tfile_server\n}\n"
	if got := string(FormatWithOptions([]byte(in), FormatOptions{WrapUnbracedSite: true})); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// ineligible: unchanged from default formatting (no-op wrap)
	snip := "(s) {\n\trespond 200\n}\n"
	if got := string(FormatWithOptions([]byte(snip), FormatOptions{WrapUnbracedSite: true})); got != string(Format([]byte(snip))) {
		t.Errorf("snippet should be a no-op for WrapUnbracedSite; got %q", got)
	}
	// default (option off) never wraps
	if got := string(Format([]byte(in))); got != "localhost\nroot * /srv\nfile_server\n" {
		t.Errorf("default Format must not wrap; got %q", got)
	}
}

func TestWrapUnbracedSiteIdempotentAndSemantic(t *testing.T) {
	in := "localhost\nrespond 200\n"
	once := FormatWithOptions([]byte(in), FormatOptions{WrapUnbracedSite: true})
	twice := FormatWithOptions(once, FormatOptions{WrapUnbracedSite: true})
	if !bytes.Equal(once, twice) {
		t.Errorf("not idempotent:\n once=%q\ntwice=%q", once, twice)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./caddyconfig/caddyfile/ -run 'TestFormatWithWrapUnbracedSite|TestWrapUnbracedSite' -v`
Expected: FAIL — `wrapUnbracedSite` is currently identity (Task 8 placeholder).

- [ ] **Step 3: Implement `wrapUnbracedSite` and wire it into `FormatWithOptions`**

Add `wrapUnbracedSite`: insert a synthetic `{` token (Text/raw `{`, same `File`, `Line` of the last address token) after the address list, and append a synthetic `}` token after the last token; return unchanged when `isSingleUnbracedSite` is false. Then wire it into `FormatWithOptions` (from Task 8) by replacing the "ignored here" comment with:

```go
	if opts.WrapUnbracedSite {
		tokens = wrapUnbracedSite(tokens)
	}
```

The renderer (Tasks 8–11) then indents the body and emits the braces.

- [ ] **Step 4: Run tests + full package**

Run: `go test ./caddyconfig/caddyfile/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add caddyconfig/caddyfile/formatter.go caddyconfig/caddyfile/formatter_braced_test.go
git commit -m "caddyfile: implement default-off unbraced->braced site wrapping

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification

- [ ] **Step 1: Full test + vet + fuzz burst**

```bash
go test ./caddyconfig/... ./cmd/...
go vet ./caddyconfig/... ./cmd/...
go test ./caddyconfig/caddyfile/ -run xxx -fuzz FuzzFormatIdempotent -fuzztime 60s
go test ./caddyconfig/caddyfile/ -run xxx -fuzz FuzzFormatNoPanic -fuzztime 60s
go test ./caddyconfig/caddyfile/ -run xxx -fuzz FuzzFormatSemanticPreserve -fuzztime 60s
```
Expected: all PASS, no fuzz crashers.

- [ ] **Step 2: Confirm the legacy formatter state machine is gone**

Run: `grep -n "heredocState\|openBraceOwnLine\|previousLineWasTopLevelImport" caddyconfig/caddyfile/*.go`
Expected: no matches outside test files (the rune-by-rune machine is deleted; `formatter.go` now contains only the token renderer + options + wrap).

- [ ] **Step 3: Update the old gofuzz shims (optional cleanup)**

If `formatter_fuzz.go` / `lexer_fuzz.go` (build tag `gofuzz`) still reference `Format`/`Tokenize`, confirm they compile; the native `FuzzXxx` tests now supersede them. Leave or remove per maintainer preference (note in the PR).
