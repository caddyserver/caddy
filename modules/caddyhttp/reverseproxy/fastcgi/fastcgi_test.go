package fastcgi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/caddyserver/caddy/v2"
)

func TestProvisionSplitPath(t *testing.T) {
	tests := []struct {
		name          string
		splitPath     []string
		wantErr       error
		wantSplitPath []string
	}{
		{
			name:          "valid lowercase split path",
			splitPath:     []string{".php"},
			wantErr:       nil,
			wantSplitPath: []string{".php"},
		},
		{
			name:          "valid uppercase split path normalized",
			splitPath:     []string{".PHP"},
			wantErr:       nil,
			wantSplitPath: []string{".php"},
		},
		{
			name:          "valid mixed case split path normalized",
			splitPath:     []string{".PhP", ".PHTML"},
			wantErr:       nil,
			wantSplitPath: []string{".php", ".phtml"},
		},
		{
			name:          "empty split path",
			splitPath:     []string{},
			wantErr:       nil,
			wantSplitPath: []string{},
		},
		{
			name:      "non-ASCII character in split path rejected",
			splitPath: []string{".php", ".Ⱥphp"},
			wantErr:   ErrInvalidSplitPath,
		},
		{
			name:      "unicode character in split path rejected",
			splitPath: []string{".phpⱥ"},
			wantErr:   ErrInvalidSplitPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := Transport{SplitPath: tt.splitPath}
			err := tr.Provision(caddy.Context{})

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSplitPath, tr.SplitPath)
		})
	}
}

func TestSplitPos(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		splitPath []string
		wantPos   int
	}{
		{
			name:      "simple php extension",
			path:      "/path/to/script.php",
			splitPath: []string{".php"},
			wantPos:   19,
		},
		{
			name:      "php extension with path info",
			path:      "/path/to/script.php/some/path",
			splitPath: []string{".php"},
			wantPos:   19,
		},
		{
			name:      "case insensitive match",
			path:      "/path/to/script.PHP",
			splitPath: []string{".php"},
			wantPos:   19,
		},
		{
			name:      "mixed case match",
			path:      "/path/to/script.PhP/info",
			splitPath: []string{".php"},
			wantPos:   19,
		},
		{
			name:      "no match",
			path:      "/path/to/script.txt",
			splitPath: []string{".php"},
			wantPos:   -1,
		},
		{
			name:      "empty split path",
			path:      "/path/to/script.php",
			splitPath: []string{},
			wantPos:   0,
		},
		{
			name:      "multiple split paths first match",
			path:      "/path/to/script.php",
			splitPath: []string{".php", ".phtml"},
			wantPos:   19,
		},
		{
			name:      "multiple split paths second match",
			path:      "/path/to/script.phtml",
			splitPath: []string{".php", ".phtml"},
			wantPos:   21,
		},
		// Unicode case-folding tests (security fix for GHSA-g966-83w7-6w38)
		// U+023A (Ⱥ) lowercases to U+2C65 (ⱥ), which has different UTF-8 byte length
		// Ⱥ: 2 bytes (C8 BA), ⱥ: 3 bytes (E2 B1 A5)
		{
			name:      "unicode path with case-folding length expansion",
			path:      "/ȺȺȺȺshell.php",
			splitPath: []string{".php"},
			wantPos:   18, // correct position in original string
		},
		{
			name:      "unicode path with extension after expansion chars",
			path:      "/ȺȺȺȺshell.php/path/info",
			splitPath: []string{".php"},
			wantPos:   18,
		},
		{
			name:      "unicode in filename with multiple php occurrences",
			path:      "/ȺȺȺȺshell.php.txt.php",
			splitPath: []string{".php"},
			wantPos:   18, // should match first .php, not be confused by byte offset shift
		},
		{
			name:      "unicode case insensitive extension",
			path:      "/ȺȺȺȺshell.PHP",
			splitPath: []string{".php"},
			wantPos:   18,
		},
		{
			name:      "unicode in middle of path",
			path:      "/path/Ⱥtest/script.php",
			splitPath: []string{".php"},
			wantPos:   23, // Ⱥ is 2 bytes, so path is 23 bytes total, .php ends at byte 23
		},
		{
			name:      "unicode only in directory not filename",
			path:      "/Ⱥ/script.php",
			splitPath: []string{".php"},
			wantPos:   14,
		},
		// Additional Unicode characters that expand when lowercased
		// U+0130 (İ - Turkish capital I with dot) lowercases to U+0069 + U+0307
		{
			name:      "turkish capital I with dot",
			path:      "/İtest.php",
			splitPath: []string{".php"},
			wantPos:   11,
		},
		// Ensure standard ASCII still works correctly
		{
			name:      "ascii only path with case variation",
			path:      "/PATH/TO/SCRIPT.PHP/INFO",
			splitPath: []string{".php"},
			wantPos:   19,
		},
		{
			name:      "path at root",
			path:      "/index.php",
			splitPath: []string{".php"},
			wantPos:   10,
		},
		{
			name:      "extension in middle of filename",
			path:      "/test.php.bak",
			splitPath: []string{".php"},
			wantPos:   9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos := Transport{SplitPath: tt.splitPath}.splitPos(tt.path)
			assert.Equal(t, tt.wantPos, gotPos, "splitPos(%q, %v)", tt.path, tt.splitPath)

			// Verify that the split produces valid substrings
			if gotPos > 0 && gotPos <= len(tt.path) {
				scriptName := tt.path[:gotPos]
				pathInfo := tt.path[gotPos:]

				// The script name should end with one of the split extensions (case-insensitive)
				hasValidEnding := false
				for _, split := range tt.splitPath {
					if strings.HasSuffix(strings.ToLower(scriptName), split) {
						hasValidEnding = true
						break
					}
				}
				assert.True(t, hasValidEnding, "script name %q should end with one of %v", scriptName, tt.splitPath)

				// Original path should be reconstructable
				assert.Equal(t, tt.path, scriptName+pathInfo, "path should be reconstructable from split parts")
			}
		})
	}
}

// TestSplitPosUnicodeSecurityRegression specifically tests the vulnerability
// described in GHSA-g966-83w7-6w38 where Unicode case-folding caused
// incorrect SCRIPT_NAME/PATH_INFO splitting
func TestSplitPosUnicodeSecurityRegression(t *testing.T) {
	// U+023A: Ⱥ (UTF-8: C8 BA). Lowercase is ⱥ (UTF-8: E2 B1 A5), longer in bytes.
	path := "/ȺȺȺȺshell.php.txt.php"
	split := []string{".php"}

	pos := Transport{SplitPath: split}.splitPos(path)

	// The vulnerable code would return 22 (computed on lowercased string)
	// The correct code should return 18 (position in original string)
	expectedPos := strings.Index(path, ".php") + len(".php")
	assert.Equal(t, expectedPos, pos, "split position should match first .php in original string")
	assert.Equal(t, 18, pos, "split position should be 18, not 22")

	if pos > 0 && pos <= len(path) {
		scriptName := path[:pos]
		pathInfo := path[pos:]

		assert.Equal(t, "/ȺȺȺȺshell.php", scriptName, "script name should be the path up to first .php")
		assert.Equal(t, ".txt.php", pathInfo, "path info should be the remainder after first .php")
	}
}
