# Caddyfile lexer/parser/formatter unification — design

**Status:** Draft for review (revised after adversarial review)
**Date:** 2026-07-14
**Package:** `caddyconfig/caddyfile`

## Goal

Eliminate the standalone rune-by-rune formatter (`formatter.go`) by making the
existing lexer/token pipeline capable of driving formatting. The lexer today is
lossy in ways that prevent it from serving the formatter; this refactor makes
the lexer able to retain the information a formatter needs, rewrites the
formatter to consume tokens, and adds two new formatting modes (follow-imports
and unbraced→braced wrapping). No breaking changes to the existing public API;
new public surface is acceptable.

## Background: what the code does today

- **`lexer.go` — `Tokenize(input, filename) ([]Token, error)`** splits input into
  whitespace-delimited tokens. It is lossy in ways that matter for formatting:
  1. **Comments are discarded entirely** (the `comment` flag skips runes; no
     token is emitted).
  2. **Token text is transformed, not raw** — enclosing quotes are stripped
     (`lexer.go:222-224`), `\"`→`"` is unescaped inside quotes (`lexer.go:217-219`),
     heredoc leading whitespace is stripped and the `<<MARKER` framing removed
     (`lexer.go:166-173`, `finalizeHeredoc` at `lexer.go:300-342`), and
     escaped-newline line continuations are consumed and the backslash dropped
     (`lexer.go:245-251`, `lexer.go:283-291`).
  3. **Inter-token whitespace is dropped** — line boundaries survive via
     `Token.Line` / `Token.NumLineBreaks()`, but *within a line* the distinction
     between "glued", "one space", and "`\`+newline continuation" is lost.
- **`parse.go` — `Parse`** groups tokens into `ServerBlock`s. It runs
  `replaceEnvVars` on the raw bytes **before** tokenizing (`parse.go:63-65`),
  expands `import` directives by reading files/globs (`doImport`,
  `parse.go:356`), and relies on `{` / `}` being their own tokens. `import` is
  treated as the import directive only when it is the **first token of its line**
  (`parse.go:223`, `parse.go:663`); otherwise it is an ordinary argument (locked
  in by `TestImportedFilesIgnoreNonDirectiveImportTokens`, `parse_test.go:848`).
- **`formatter.go` — `Format([]byte) []byte`** is a completely separate
  rune-by-rune state machine. It re-derives heredoc/quote/backtick/escape/
  comment/brace logic, but *preserves* comments and raw token text while
  *regenerating* indentation and spacing.
- **Format consumers (must not regress):**
  - `cmd/commandfuncs.go:cmdFmt` — the `caddy fmt` command (single file or stdin
    `-`, with `--overwrite` / `--diff`; refuses multiple files).
  - `caddyconfig/caddyfile/adapter.go:FormattingDifference` (exported,
    `adapter.go:69`) — called from `Adapter.Adapt` (`adapter.go:57`) to emit a
    lint warning when a Caddyfile isn't already formatted, and from `cmdFmt`.
    Byte-compares `Format(body)` against input, so **any** output change on valid
    input flips the lint warning for existing users.

## Key design insight

The formatter does **not preserve** source whitespace between lines — it throws
it away and **regenerates** it from structure (nesting → tabs, blank lines
capped at one). So the lexer does not need to store *line* whitespace. What it
genuinely lacks for formatting is:

1. **Comment tokens** (currently discarded);
2. **Verbatim raw source bytes** per token (the transformed `Text` cannot be
   reversed back to source — see the hard parts below); and
3. **Intra-line separator information** — whether a token was glued to the
   previous token, separated by spaces, or joined by a `\`+newline continuation.

Line deltas (for blank-line preservation) already exist via `Token.Line`.

### Hard parts uncovered by adversarial review

These are the traps that make "just add raw text" insufficient. The design below
addresses each.

1. **Raw is not derivable from `Text`.** For heredocs, quoted/backtick strings,
   and escaped tokens, `Text` is already transformed before the token exists
   (`finalizeHeredoc`, quote-strip, unescape). Therefore format-mode lexing must
   capture the **verbatim source byte span** of each token at scan time, *before*
   any transformation. `Token.Raw()` returns that captured span; it must **not**
   fall back to `Text` for transformed tokens (doing so would emit corrupted
   bytes, e.g. `"a \"b\" "` → `"a "b" "`).

2. **Glued vs spaced adjacency is real and on valid input.** After a closing
   quote, `#` begins a comment token immediately (`"x"#c` → string token +
   comment token, no gap), while `"x" #c` produces the same two tokens. The only
   difference is the (dropped) whitespace. The formatter must reproduce both, so
   each token needs a recorded **leading-separator kind**. (Note: `e#f` is a
   *single* token — `#` mid-token is literal — so it needs no flag; the flag is
   for the quote/backtick→`#` boundary and for glued braces.)

3. **A standalone trailing `{` is *dropped*, not spaced.** `Format("a{")` == `"a\n"`.
   The old formatter renders a peeled `{` only when a block body follows
   (`Format("a{\nb\n}")` == `"a {\n\tb\n}"`). So the peel rule is a
   beautification of *invalid* input only (valid site addresses can't end in `{`
   — `parse.go:246-248` errors), and a dangling glued `{` at EOF is a sanctioned
   divergence, not a parity guarantee.

4. **Escaped-newline continuations vanish from the token stream.**
   `foo bar \`<newline>`baz` lexes to three same-line tokens with the backslash
   gone. The old formatter preserves `\`+newline (re-indenting continued lines to
   a single space). This is valid input, so the separator-kind for the continued
   token must record "continuation" and the renderer must re-emit it. Per D1 the
   new formatter **preserves** continuations but re-indents continued lines to a
   proper hanging indent (nesting + 1 tab) instead of legacy's single space — a
   sanctioned divergence.

5. **The `<`-eats-following-space quirk (dropped).** `formatter.go:360-362`
   makes a `<` rune swallow the space after it: `Format("foo < bar")` ==
   `"foo <bar\n"` (verified empirically; `>` is unaffected — `header > X` is
   untouched). This is a heredoc-`<<`-detection artifact, unreachable in valid
   config (a bare/leading `<` outside quotes/heredocs doesn't occur). The new
   formatter **does not port** it: `foo < bar` stays `foo < bar` — a sanctioned
   divergence (the more sensible output).

6. **Heredoc close semantics differ between lexer and legacy formatter.** The
   lexer closes a heredoc as soon as the accumulated body *ends with* the marker
   (`lexer.go:189`), whereas the legacy formatter requires the marker alone on
   its own line (`formatter.go:156`). So `x <<END`/`fooEND`/`END` tokenizes
   differently than legacy formats. Because unification's whole point is that the
   formatter agrees with the **parser** (which uses the lexer), the new formatter
   adopts lexer semantics; this is a **sanctioned divergence** from legacy.

### The sub-token brace rule

Only tokens whose text is exactly `{` / `}` are structural braces. Additionally,
format-mode lexing peels a **single trailing `{`** off a literal token
(`example.com{` → `example.com` + `{`) **only when the remaining prefix is
non-empty and contains no `{` or `}`** — so `example.com{` peels but `{$A}{`,
`{{tmpl}}{`, `foo{bar}`, `{}`, and quoted/heredoc/backtick tokens do not.
For valid Caddyfiles this changes nothing (real blocks are always
whitespace-separated). A `{}` token is recognized as an empty structural block
(open immediately followed by close) so it can be canonicalized to the expanded
form (I2). All other glued-brace forms (interior `foo{ bar}baz`, leading `}`,
runs like `}}}`, dangling trailing `{`) stay literal and may format differently
from legacy — a sanctioned divergence.

**Sub-invariant:** the peel must never split a `{` off a token that `Parse`
accepts verbatim (guaranteed by `parse.go:246-248`), so it provably cannot change
any valid input.

## Decisions locked during brainstorming (unchanged)

1. Token model: raw text + comment tokens + separator metadata; regenerate line
   layout. (Not explicit whitespace tokens.)
2. Malformed braces: allowed to differ from legacy on invalid input; valid input
   must be byte-for-byte identical.
3. Trailing `{`: peel a single glued trailing `{` (brace-free prefix only).
4. Public API: expose raw-token + comment API for reuse.
5. Regression oracle: keep the old `Format` as a test-only `legacyFormat` and
   differential-test against it, then delete it once green.
6. Nesting cap: drop the old 10-level indentation cap.
7. Formatter core: purely lexical/token-based — never interprets site addresses —
   so it is safe on imported fragments. Semantic features are separate, gated
   passes.
8. Follow-imports: resolve `import` file globs recursively, format each file
   independently at its own baseline; skip snippet-name and `{block}` imports;
   dedup + cycle-guard.
9. Braced-wrap: transform a single unbraced site into a braced one; no-op (never
   error) on anything else; disabled by default, implemented and tested.
10. Scope: one spec, phased implementation (core first). Wire `caddy fmt` flags
    for follow-imports now; braced-wrap stays package-only/hidden.

## Decisions introduced by the review (need confirmation in spec review)

- **D1 — escaped-newline continuations: preserve with proper hanging indent.**
  The renderer re-emits `\`+newline before a continued token, then indents the
  continued line to nesting + 1 tab (a hanging indent). This diverges from
  legacy (which uses a single space) and is a sanctioned divergence. (Rejected:
  byte-exact single-space preservation — carries an ugly quirk; and normalizing
  to one physical line — discards the author's intentional wrapping of long arg
  lists.)
- **D2 — heredoc close rule:** *sanctioned divergence.* New formatter follows
  lexer/parser heredoc semantics, not legacy's line-alone rule.
- **D3 — braced-wrap detection** replicates the parser's address boundary via a
  self-contained structural pass (no I/O), rather than a byte-level heuristic
  (see Component 4).
- **D4 — `<`-space quirk: dropped** (sanctioned divergence). `foo < bar` formats
  as `foo < bar`, not legacy's `foo <bar`.

## Intentional improvements over the legacy formatter

Found by an empirical quirk hunt (each output below was observed by running the
legacy `Format`). These deliberately change output vs legacy on **valid** input;
each is covered by dedicated table tests plus the universal idempotency and
semantic-preservation invariants, and each is excluded from the legacy-oracle
strict-parity subset (Invariant 1).

- **I1 — comments on a brace line stay on that line.** A trailing comment after
  `}` stays inline (`} # end`, no detaching/blank-line insertion); a trailing
  comment after `{` stays inline (`site { # note`, not relocated into the body);
  and a comment between an address and its brace folds the brace up ahead of the
  comment (`site # note`⏎`{` → `site { # note`).
- **I2 — empty blocks canonicalize to the expanded form.** Both `{}` and `{ }`
  (including nested occurrences) format as `{`⏎`}` at the proper indent. The
  format-mode brace rule therefore treats a `{}` token as an empty structural
  block (open immediately followed by close).
- **I3 — the blank-line cap applies uniformly after comment lines.** `foo # c`
  followed by ≥2 blank lines collapses to one blank line, matching every other
  line (legacy left two). Falls out of counting blank lines from `Token.Line`
  gaps.
- **I4 — a token glued after `}` on the same line breaks onto its own indented
  line** (`} d` → `}`⏎`<indent>d`) instead of legacy's stray literal tab.
- **Auto-fixed by construction** (not decisions, but noted): a lone `\r` no
  longer splits a token (`respond hello\rworld` stays one token, matching the
  lexer/parser — legacy split it, silently changing config meaning); and a
  backtick token as the first token after an open brace is no longer mangled or
  non-idempotent.

## Architecture

```
layout format   → token-level, fragment-safe, regenerates line layout    (Phase 1)
follow-imports  → discover import files, layout-format each @ baseline 0  (Phase 2)
braced-wrap     → structural single-site detection, top-level-only, OFF   (Phase 3)
```

### Component 1 — Lexer/token changes (Phase 1)

Format mode is opt-in and leaves the parse path byte-for-byte unchanged (no extra
allocations, no new tokens, identical `Text`). In format mode the lexer records,
per token:

- **Raw source span** — the verbatim bytes of the token, captured at scan time
  **before** `finalizeHeredoc` / quote-strip / unescape run. Implementation
  captures the source offsets (or accumulates raw runes in parallel with `val`).
  Includes quotes, backticks, escapes, and full heredoc framing.
- **Leading-separator kind** — one of `{none (glued), space, continuation}`,
  describing how this token was joined to the previous token *on the same line*.
  `continuation` means a `\`+newline preceded it.
- **Comment flag** — comments become real tokens spanning `#` to end-of-line,
  emitted only in format mode, using the lexer's actual rule: `#` starts a comment
  only at a lexer token boundary (i.e. `len(val)==0`). This fires immediately
  after a closing quote/backtick (so `"x"#c` yields a glued comment token) but is
  literal mid-token (`e#f`, `redir /a/#/b`).

Format-mode lexing also splits structural braces per "The sub-token brace rule".

New public surface:

- `Lex(input []byte, filename string, opts LexOptions) ([]Token, error)` where
  `LexOptions{ Comments bool; Raw bool }`. `Tokenize(input, filename)` keeps its
  signature and delegates to `Lex(input, filename, LexOptions{})`.
- `Token.Raw() string` — returns the captured source span; documented as only
  meaningful when tokenized in format mode. **No corrupting fallback to `Text`.**
- `Token.IsComment() bool`.
- Separator kind is exposed via a small accessor (e.g. `Token.precededBySpace`
  internally; exact exported shape finalized in the plan).

**Back-compat tasks:** update `Token.Clone()` (`lexer.go:363-373`) to copy the new
fields; grep for `reflect.DeepEqual`/`==` on `Token` and confirm none break (new
fields are zero on the parse path, so existing DeepEqual token-slice tests still
pass); keep raw as a *method* over an unexported field so it doesn't affect
struct equality.

### Component 2 — Formatter rewrite (Phase 1)

`Format([]byte) []byte` keeps its signature and public behavior. Internally:
format-mode tokenize → render. The rune-by-rune state machine in `formatter.go`
is deleted. Render rules (faithful port):

- Indentation = current structural-brace nesting × tab. `{` attaches to the end
  of the prior line; `}` on its own line. **No 10-level cap.**
- Between same-line tokens: emit one space for `space`, nothing for `none`
  (glued), and for `continuation` emit `\`+newline then indent the continued line
  to nesting + 1 tab (hanging indent, D1).
- The `<`-eats-following-space quirk is **not** ported (D4): a `<` token is
  spaced like any other token (`foo < bar` → `foo < bar`).
- ≤1 blank line preserved, counted uniformly from `Token.Line` gaps including
  comment lines (I3); a blank line is inserted after a top-level `}`.
- **Comments attach to their line (I1):** a comment token on the same line as the
  preceding token (including a `{`/`}` brace token) renders inline on that line;
  a comment alone on its line renders on its own indented line. Brace-folding
  attaches an opening `{` ahead of a same-line trailing comment.
- **Empty blocks (I2):** a `{}` token (or `{` immediately followed by `}`)
  renders as an expanded empty block at the current indent.
- **Post-`}` token (I4):** a token following `}` on the same line breaks onto its
  own line at the block's indent (never a stray tab separator).
- Heredoc, multi-line quoted, and backtick tokens emit their **raw** bytes
  verbatim with **no interior re-indentation**.
- **Top-level import / standalone-brace exception (exact predicate):** a
  standalone `{` (global-options block) is kept on its own line **only when it
  immediately follows a top-level `import` line with no intervening blank line**;
  if a blank line intervenes, the brace is glued to the import line and the blank
  line is removed (matches `formatter.go:279` gated on
  `previousLineWasTopLevelImport`, which a blank line resets).
- Trim leading/trailing whitespace; always end with exactly one `\n`. Empty or
  whitespace-only input → `\n`.
- **Never panic** on any input (legacy `panic`s on non-EOF read errors).

New options entry: `FormatWithOptions(input []byte, opts FormatOptions) []byte`,
`FormatOptions{ WrapUnbracedSite bool }`. `Format` == options all-false.

### Component 3 — Follow-imports mode (Phase 2)

`FormatImports(filename string, opts FormatOptions) ([]FormattedFile, error)`,
`FormattedFile{ Path string; Content []byte }`.

Discovery algorithm:

1. **Recognize `import` as a directive only when it is the first token of its
   line** (segment-leading), replicating `parse.go:223` / `parse.go:663`. A text
   match alone is wrong (`basic_auth / import password` must be ignored —
   `parse_test.go:848`).
2. **Resolve the import argument's path with env replacement.** The parser runs
   `replaceEnvVars` on raw bytes before tokenizing, so `import {$SNIPPETS}/*.caddy`
   resolves against the substituted value. Discovery must apply the same env
   substitution to the import argument for *path resolution only* — this is
   separate from the verbatim raw text preserved for formatting output.
3. **Classify snippet vs file across the whole graph.** Snippet names are
   token-identical to filenames and may be defined in *other* imported files
   (`p.definedSnippets` is global). So first collect the complete set of defined
   snippet names `(name)` across all recursively-discovered files, then treat an
   `import <arg>` as a file import only if `<arg>` is not a known snippet name.
   Skip `{block}` / `{blocks.*}` placeholder imports (prefix/suffix check;
   `{$...}` args are file globs, not block placeholders, and must not be skipped
   by this check). A non-glob file import that doesn't exist on disk is **skipped
   with a warning, not a hard error** (preserves back-compat with plain
   `caddy fmt`).
4. **Extract a pure path-resolution helper** from `doImport` containing only:
   `caddy.FastAbs` (`parse.go:421`), the single-wildcard check (`parse.go:433`),
   `filepath.Glob` (`parse.go:438`), and dotfile skipping (`parse.go:449-461`).
   It returns `[]matches` for `(importerFile, importPattern)` and performs **no**
   token splicing, arg replacement, variadic handling, or following-block
   consumption (`parse.go:405-406`, `:580` must not run during discovery).
5. **Recurse, dedup, and cycle-guard** keyed on `caddy.FastAbs(file)` (matching
   `doSingleImport`, `parse.go:619`).
6. Format each discovered file with the layout formatter at its **own nesting-0
   baseline** (imported-file indentation resets; the importer's nesting is not
   propagated to the file on disk).
7. `WrapUnbracedSite` is **never** applied to imported files (they are fragments).

### Component 4 — Braced-wrap transform (Phase 3, default OFF)

`FormatOptions.WrapUnbracedSite`. When enabled and the input is an eligible
single unbraced site, wrap it: add `{`/`}` and indent the body one level.

Eligibility is decided by a **self-contained structural pass** over the
format-mode token stream (no import expansion, no file access, no env
substitution) that replicates the parser's address boundary (D3):

- Track structural-brace nesting to find top-level segment boundaries.
- The **address list** is the run of leading tokens up to the first newline,
  honoring trailing-comma continuation across lines (mirrors
  `parser.addresses`, including the multi-line `a,`/`b {` form).
- Eligible iff: there is exactly **one** top-level server block; its address list
  is non-empty; the first non-comment token after the address list is **not** a
  structural `{` on the address's line (i.e. the site is unbraced); and the
  address is not a snippet `(...)` or named route `&(...)`. Interior directive
  braces (`localhost` / `reverse_proxy {` … `}`) are allowed and ignored for
  eligibility.
- A leading global-options block (structural `{` with no preceding address) →
  not eligible.
- Anything ambiguous, multi-site, snippet, named-route, or import-only → **no-op**
  (never error).

After wrapping, output must remain idempotent and preserve semantics (Invariant
4).

### Component 5 — CLI (Phase 2)

`caddy fmt` behavior is identical by default. New:

- `--imports` — format the target file plus all recursively-imported files. With
  `--overwrite`, writes each file back; without, prints each file preceded by a
  path header; with `--diff`, prints per-file diffs.
- **`--imports` with stdin (`-`) is rejected** with a clear error (no source
  directory to resolve relative imports against), mirroring the existing
  multi-file refusal.
- Braced-wrap is **not** exposed as a flag yet (package-only/hidden).

## Testing & fuzzing strategy

Safety net = fuzz invariants + the legacy oracle. All fuzzing pins the process
environment (empty env, or an injected `LookupEnv` stub) so `replaceEnvVars` is
deterministic and seeds are reproducible.

- **Port all `formatter_test.go` cases** to the new implementation. Cases that
  intentionally diverge (sanctioned classes below) are updated with an
  explanatory comment; all others must stay green unchanged. (Do **not** claim
  every existing test is byte-identical without the separator-kind flag — the
  `"a \"b\" "#c` case, `formatter_test.go:219`, requires it.)
- **`legacyFormat` oracle:** move the current `Format` implementation verbatim
  into a `_test.go` as unexported `legacyFormat` (it depends only on
  package-level helpers like `heredocMarkerRegexp`, so it vendors cleanly).
  Delete it once all invariants pass and divergences are signed off.

### Fuzz invariants

1. **Parity on valid input (strict subset):** for inputs where `Parse(input)`
   succeeds and which contain **none** of the divergence/improvement triggers —
   line-start `import`, `{$` placeholder, any `<` (covers `<<` heredocs and bare
   `<`), a `\`+newline continuation, any `#` comment (comment handling changes,
   I1/I3), an empty block `{}`/`{ }` (I2), or a token glued after `}` (I4) — and
   whose structural-brace nesting ≤ 10 (measured as max nesting on the
   format-mode token stream — the same peeled count the renderer tracks),
   `Format(input) == legacyFormat(input)` byte-for-byte. Excluding `import`/`{$`
   also keeps the oracle filesystem- and env-independent. The excluded features
   are covered by dedicated table tests with hand-written expected output plus
   invariants 2–4 (below), not by the oracle.
2. **Idempotency:** `Format(Format(x)) == Format(x)` for **all** `x`.
3. **Never panics:** `Format` on any input (NUL bytes, truncated heredocs,
   unbalanced quotes, deep nesting) must not panic.
4. **Semantic preservation:** for valid input (with pinned empty env and no
   `import`), the token/segment structure of `Parse(input)` equals that of
   `Parse(Format(input))` — same token `Text` sequence and block nesting,
   comments excepted. Compared over **`Parse` output** (post env/import
   expansion), **not** at the `Tokenize` layer (`{$X}` expands to 0..n tokens, so
   a Tokenize-level comparison would fail on every placeholder).
5. **Classified divergences:** the only differences from legacy are the
   sanctioned divergences and the intentional improvements (I1–I4); the
   strict-parity fuzzer (Invariant 1) excludes their triggers, and each is
   covered by a dedicated table test instead. Sanctioned divergences:
   - interior/dangling glued braces on invalid input (beyond the trailing-`{`
     peel);
   - heredoc close following lexer/parser semantics (D2);
   - `\`+newline continuations re-indented to a hanging indent (D1);
   - the `<`-space quirk dropped — `foo < bar` stays `foo < bar` (D4);
   - inputs nested > 10 levels (cap dropped, Decision 6).
   Intentional improvements: I1 (comments on brace lines), I2 (empty blocks
   expanded), I3 (uniform blank-line cap after comments), I4 (post-`}` token
   breaks to its own line) — see the "Intentional improvements" section; each has
   dedicated table tests with hand-written expected output.
- **`FormattingDifference` parity:** include `adapter.go:FormattingDifference` in
  the parity surface — on valid input the new `Format` must produce byte-identical
  output so the `caddy adapt`/startup lint signal doesn't flip for existing
  users.

### Seed corpus (fuzzer-favorite angles)

Unbalanced braces; `{}` / `{ }`; trailing-`{` peel cases (`example.com{`,
`{$A}{`, `{{x}}{`); `<`-led tokens (`foo < bar`, start-of-line `<`); heredocs
(marker as a substring of the body `fooEND`/`END`, CRLF, mismatched leading
whitespace, marker-like body lines, nested markers, `<<<`); quotes/backticks
(unterminated, multi-line, `"`↔backtick cross-nesting, `"x"#c` vs `"x" #c`);
comments (`e#f`, `#a {`, `#` inside quotes/heredocs, comment-only file, trailing
comment); escapes (`\<<`, trailing `\`, escaped-newline continuation `foo bar \`
+newline+`baz`, `\"`); env placeholders (`{$X}`, `{$X:default}`, empty `{$}`);
import edge cases (`basic_auth / import password`, `import {$SNIPPETS}/*`,
`import <snippet-in-other-file>`); BOM; CRLF; NUL/control bytes; empty and
whitespace-only input; deep nesting; long lines. Plus real configs from
`caddytest/`.

### Intentional-improvement tests (I1–I4)

Dedicated table tests with hand-written expected output (the legacy oracle
encodes the *old* behavior, so these are asserted directly, and each is also run
through the idempotency and semantic-preservation invariants):

- I1: `} # end`, `site { # note`⏎`foo`⏎`}`, `site # note`⏎`{`⏎`foo`⏎`}` (and the
  matcher-block variant `@m { # note`).
- I2: `route {}`, `route { }`, `a { b {} }`, `a { b { } }`, `tls internal {}` —
  all → expanded form.
- I3: `foo # inline`⏎⏎⏎`bar` → one blank line; comment-only lines with surrounding
  blanks.
- I4: `a { b { c` ⏎ `} d` ⏎ `}` → `d` on its own indented line.
- Auto-fixed: `respond hello\rworld` (single token), `` a { `bar` } `` (clean,
  idempotent).

### Mode-specific tests

- **Follow-imports:** fixture directory trees exercising globs, nested imports,
  cross-file snippet definitions (`import mysnip` where `(mysnip)` lives in
  another file — must be skipped, not error), non-directive `import` tokens,
  cycles (must terminate), `{block}` (not followed), dotfile skipping, missing
  files (skipped+warned), absolute vs relative paths, and `--imports` + stdin
  (rejected). Assert the exact set of files formatted, each at baseline 0.
- **Braced-wrap:** single unbraced site → wrapped; already-braced → no-op;
  unbraced site with interior directive braces (`localhost`/`reverse_proxy {…}`)
  → wrapped correctly; snippet → no-op; named route → no-op; global-options-only
  → no-op; leading global-options block + site → no-op (ambiguous/multi);
  multiple sites → no-op; multi-line comma address list; empty file → no-op; site
  with trailing comment. Plus idempotency and Invariant-4 checks on wrapped output.
- **CLI:** `caddy fmt --imports` (with/without `--overwrite`, with `--diff`),
  `--imports -` rejected, stdin path unchanged, single-file default behavior
  unchanged.

## Phasing

- **Phase 1 — core:** lexer format mode (raw span + separator kind + comments +
  brace peel + `{}` empty-block recognition), `Lex`/`LexOptions`,
  `Token.Raw()`/`IsComment()`, `Clone()` update, formatter rewrite (continuation
  hanging indent, `<`-quirk dropped, exact import-brace predicate, and
  improvements I1–I4), `FormatWithOptions`, port formatter tests, legacy oracle +
  fuzz invariants 1–5 with pinned env, drop the nesting cap. Delete
  `formatter.go`'s state machine.
- **Phase 2 — follow-imports:** extract pure import-glob resolution helper,
  cross-file snippet collection, env-aware path resolution, first-token rule,
  `FormatImports`, `caddy fmt --imports` (stdin rejected), fixture tests.
- **Phase 3 — braced-wrap:** structural single-site detection (address-boundary
  replicating), `WrapUnbracedSite` (default OFF), tests.

## Non-goals

- No change to `Parse` output, `Dispenser` behavior, or any existing exported
  signature.
- No re-normalization of token content (quotes/escapes/heredocs echoed verbatim).
- No CLI flag for braced-wrap in this effort.
- No attempt to beautify arbitrary interior/dangling glued braces beyond the
  trailing-`{` peel.
- No change to heredoc lexing (the loose marker-suffix close rule is inherited
  from the lexer/parser, D2).

## Open questions for implementation

- Final names for new exported symbols (`Lex`/`LexOptions`,
  `FormatWithOptions`/`FormatOptions`, `FormatImports`/`FormattedFile`) and the
  exported shape of separator-kind, checked against package conventions.
- Whether env-aware import path resolution should honor `{$X:default}` and
  one-level chaining exactly as `replaceEnvVars` does (assume yes: reuse
  `replaceEnvVars`).

## Adversarial review — findings incorporated

The following holes were found by an adversarial review of the first draft and
are now addressed above: raw must be a captured source span, not derived from
`Text` (Hard part 1); separator-kind flag for glued/space/continuation (Hard
parts 2 & 4, Component 1/2); corrected trailing-`{` legacy behavior + brace-free
peel predicate (Hard part 3, sub-token brace rule); `<`-prefix space quirk (Hard
part 5); heredoc-close divergence sanctioned (Hard part 6, D2); follow-imports
first-token rule, cross-file snippet set, env-aware glob resolution, pure
resolution helper, FastAbs cycle key (Component 3); braced-wrap address-boundary
detection (Component 4); `--imports`+stdin rejected (Component 5); fuzz
invariants made reproducible with pinned env and import/`{$` exclusion, Invariant
4 defined over `Parse` output, nesting metric defined (Testing); `Clone()`/equality
back-compat and `FormattingDifference` parity surface (Component 1, Testing).
