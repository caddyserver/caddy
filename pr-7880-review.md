# PR 7880 review

I am an AI coding agent (OpenCode, GPT-5.6 Sol). I reviewed this change with targeted parser/formatter reproductions and CodeRabbit CLI assistance. The human posting this review should verify and understand every finding before submission.

## Reproduced findings

### High: Format mode splits braces that are literal parser arguments

Locations: `caddyconfig/caddyfile/lexer.go:104-106`, `caddyconfig/caddyfile/lexer.go:133-166`

`Lex` runs `splitStructuralBraces` whenever either `Comments` or `Raw` is enabled. That changes token boundaries accepted by the normal parser.

This input parses successfully before formatting:

```caddyfile
localhost
respond foo{
```

It formats to `respond foo {` and then fails parsing because the newly structural block is unclosed.

Likewise, this valid directive segment:

```caddyfile
localhost
respond {} 200
```

formats to:

```caddyfile
localhost
respond {
}

200
```

That changes one directive's arguments into a block followed by a new directive. The semantic backstop does not catch either case because it compares format-mode token streams rather than the normal parse-mode token stream.

### High: A blank line after `import` absorbs global options into the import

Location: `caddyconfig/caddyfile/formatter.go:570-576`

The exception that preserves a standalone opening brace after a top-level `import` only applies when `breaks < 2`.

Input:

```caddyfile
import foo.caddy

{
    debug
}
```

Actual output:

```caddyfile
import foo.caddy {
	debug
}
```

This changes `debug` from a global option into an import block-mapping entry.

### High: Import discovery ignores snippet declaration order

Locations: `caddyconfig/caddyfile/format_imports.go:86-100`, `caddyconfig/caddyfile/format_imports.go:141-163`

Discovery collects all snippet names and retroactively classifies every matching import as a snippet import. The parser only recognizes snippets already defined when it reaches an import.

Given a real file named `foo`, this configuration imports that file through the parser but omits it from `FormatImports`:

```caddyfile
import foo

(foo) {
	respond ok
}
```

### High: Recursive imports using `{args[n]}` fail under `--imports`

Locations: `caddyconfig/caddyfile/format_imports.go:81-110`, `caddyconfig/caddyfile/format_imports.go:217-244`

Discovery scans imported files without carrying the invocation arguments that the parser applies.

```caddyfile
# Caddyfile
import selector.caddy child.caddy
```

```caddyfile
# selector.caddy
import {args[0]}
```

Normal parsing resolves and imports `child.caddy`. `FormatImports` instead returns a glob-pattern error for `{args[0]}`.

### High: Unbounded indentation permits quadratic memory amplification

Locations: `caddyconfig/caddyfile/formatter.go:480-484`, `caddyconfig/caddyfile/formatter.go:637-650`

Each opening block increases `nesting`, and every later line writes that many tabs. Linear-size deeply nested input therefore produces quadratic output. `FormatWithOptions` then lexes and renders the expanded output again for its fixed-point check. The previous formatter explicitly capped indentation at ten levels to avoid this resource-exhaustion class.

### Medium: `caddy fmt --imports` returns success for unformatted files

Location: `cmd/commandfuncs.go:734-758`

The imports branch returns success after preview or diff output and bypasses the `FormattingDifference` check at `cmd/commandfuncs.go:794-799`.

This was reproduced with an unformatted file: ordinary `caddy fmt` returns a formatting failure, while `caddy fmt --imports` and `caddy fmt --imports --diff` return success. This breaks CI formatting checks. CodeRabbit independently reported the same issue as a major finding.

## Additional correctness findings

### High: Symlinked directory cycles bypass the import cycle guard

Locations: `caddyconfig/caddyfile/format_imports.go:54-66`, `caddyconfig/caddyfile/format_imports.go:115-124`

The visited set is keyed by `caddy.FastAbs`, which cleans lexical paths but does not resolve symlinks. If `link` points to the current directory and the root imports `link/Caddyfile`, discovery can visit `link/Caddyfile`, `link/link/Caddyfile`, and so on until path-length or resource failure. Importing a file both directly and through a symlink can also format the same physical file more than once.

### High: `WrapUnbracedSite` can wrap an `import` as the site address

Locations: `caddyconfig/caddyfile/formatter.go:123-155`, `caddyconfig/caddyfile/formatter.go:265-269`

`isSingleUnbracedSite` treats the first line as an address list without accounting for leading imports.

```caddyfile
import common.caddy
localhost
respond 200
```

With `WrapUnbracedSite`, this can become:

```caddyfile
import common.caddy {
	localhost
	respond 200
}
```

The site is converted into import block-mapping content.

### Medium: Environment expansion can create imports that discovery misses

Locations: `caddyconfig/caddyfile/format_imports.go:81-110`, `caddyconfig/caddyfile/format_imports.go:153-168`

The parser expands environment variables across the complete file before tokenization. Discovery tokenizes the original file and only expands the extracted import argument. For example, with `LINE='import child.caddy'`, a line containing `{$LINE}` imports the child through the parser but not through `FormatImports`. Expansion can also alter quoting, comments, whitespace, or snippet classification.

### Medium: Discovery follows imports inside unused snippets and unused blocks

Location: `caddyconfig/caddyfile/format_imports.go:217-244`

`scanTokens` treats every first-of-line `import` as active without modeling whether its containing snippet or substitution block is ever expanded. Consequently, `--imports --overwrite` may rewrite files referenced only by dead configuration.

```caddyfile
(unused) {
	import unrelated.caddy
}

localhost {
	respond ok
}
```

The parser never executes this import unless the snippet is invoked, but discovery includes `unrelated.caddy`.

### Medium: Quoted `import` directives are skipped even though the parser executes them

Location: `caddyconfig/caddyfile/format_imports.go:237-241`

Discovery requires `tok.wasQuoted == 0`, while the parser tests the token value without a quotedness restriction. A line such as `"import" child.caddy` is therefore followed by the parser but omitted by `FormatImports`.

### Medium: Existing imported files that cannot be read are silently omitted

Locations: `caddyconfig/caddyfile/format_imports.go:126-131`, `caddyconfig/caddyfile/format_imports.go:287-293`

Read failures are logged and skipped, and the operation can still report success. The parser returns an error for an unreadable matched import. This is especially misleading for `--imports --overwrite`, which can claim success while leaving part of the active configuration unformatted.

### Medium: Multi-file overwrite can leave a partially updated configuration set

Location: `cmd/commandfuncs.go:725-731`

Files are truncated and rewritten sequentially. If a later write fails, earlier files remain modified. The operation reports an error but leaves a mixed old/new configuration set. Atomic replacement per file and clearer partial-update handling would reduce this risk.

### Medium: Imported paths are reopened without identity verification

Locations: `caddyconfig/caddyfile/format_imports.go:126-137`, `caddyconfig/caddyfile/format_imports.go:287-299`, `cmd/commandfuncs.go:725-731`

Discovery reads pathnames, formatting reopens them, and overwrite later opens the same names again. Replacing an imported path with a symlink between those operations can redirect formatted bytes to another target, particularly when formatting with elevated privileges in a directory writable by another user.

### Medium: Heredoc formatting has quadratic body construction

Locations: `caddyconfig/caddyfile/formatter.go:40`, `caddyconfig/caddyfile/formatter.go:88-90`, `caddyconfig/caddyfile/lexer.go:530-549`

The formatter lexes heredocs multiple times, while `finalizeHeredoc` builds the body using repeated string concatenation. Large multi-line heredocs therefore repeatedly copy the accumulated body. This is a performance regression from the previous rune-stream formatter and should use a builder or equivalent linear construction.

### Medium: `WrapUnbracedSite` rejects a normal site after a nested directive block

Locations: `caddyconfig/caddyfile/formatter.go:185-204`, `caddyconfig/caddyfile/formatter.go:606-610`

Returning from a directive block to nesting zero sets `returnedToTop`; the following directive is then interpreted as a second top-level group.

```caddyfile
localhost
route {
	respond ok
}
file_server
```

With wrapping requested, this remains unwrapped instead of becoming one braced site.

### Low: Valid escaped quotes disable formatting for the whole file

Location: `caddyconfig/caddyfile/formatter.go:356-364`

`hasUnformattableToken` rejects any unquoted raw token containing `"` or a backtick, including valid escaped delimiters such as `respond foo\"bar`. The formatter then returns the original trimmed input, allowing unrelated formatting differences to evade `FormattingDifference`.

### Low: Exported `Lex` options unexpectedly change ordinary token boundaries

Locations: `caddyconfig/caddyfile/lexer.go:64-105`, `caddyconfig/caddyfile/lexer.go:110-166`

The API documents `Comments` as emitting comments and `Raw` as recording source bytes, but enabling either also splits structural braces. For example, `Tokenize` treats `{}` as one token while `Lex(..., LexOptions{Raw: true})` returns separate `{` and `}` tokens. Brace normalization should be formatter-internal, explicitly configurable, or documented as part of a distinct formatting lexer API.

### Low: `FormatImports` returns inconsistently normalized paths

Locations: `caddyconfig/caddyfile/format_imports.go:271-298`

The root path preserves the caller's spelling, while imported paths are generally absolute. A call with `Caddyfile` can therefore return `Caddyfile` followed by `/absolute/path/to/import.caddy`, producing mixed headers and an ambiguous public API contract.

## Test coverage issue reported by CodeRabbit

### Low: The overwrite test does not verify that the root file is rewritten

Location: `cmd/commands_test.go:73-94`

CodeRabbit noted that `TestCmdFmtImportsOverwrite` uses an already formatted root fixture and only asserts the imported file afterward. The root fixture should also be deliberately unformatted, then read back and asserted so the test covers both root and imported-file writes.

## Verification performed

- `go test ./caddyconfig/caddyfile ./cmd` passes on the PR branch without the temporary reproduction tests.
- `git diff --check origin/master...HEAD` passes.
- Temporary tests reproduced the brace-splitting, import/global-options, snippet-order, recursive-argument, and exit-status defects, then were removed.
- CodeRabbit CLI independently identified the `--imports` exit-status defect and the missing root overwrite assertion. Its full scan did not complete before the ten-minute timeout.
