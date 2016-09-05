package staticfiles

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	ErrCustom = errors.New("Custom Error")

	testDir     = filepath.Join(os.TempDir(), "caddy_testdir")
	testWebRoot = filepath.Join(testDir, "webroot")
)

// testFiles is a map with relative paths to test files as keys and file content as values.
// The map represents the following structure:
// - $TEMP/caddy_testdir/
// '-- unreachable.html
// '-- webroot/
// '---- file1.html
// '---- dirwithindex/
// '------ index.html
// '---- dir/
// '------ file2.html
// '------ hidden.html
var testFiles = map[string]string{
	"unreachable.html":                                     "<h1>must not leak</h1>",
	filepath.Join("webroot", "file1.html"):                 "<h1>file1.html</h1>",
	filepath.Join("webroot", "dirwithindex", "index.html"): "<h1>dirwithindex/index.html</h1>",
	filepath.Join("webroot", "dir", "file2.html"):          "<h1>dir/file2.html</h1>",
	filepath.Join("webroot", "dir", "hidden.html"):         "<h1>dir/hidden.html</h1>",
}

// TestServeHTTP covers positive scenarios when serving files.
func TestServeHTTP(t *testing.T) {

	beforeServeHTTPTest(t)
	defer afterServeHTTPTest(t)

	fileserver := FileServer{
		Root: http.Dir(testWebRoot),
		Hide: []string{"dir/hidden.html"},
	}

	movedPermanently := "Moved Permanently"

	tests := []struct {
		url string

		expectedStatus      int
		expectedBodyContent string
		expectedEtag        string
	}{
		// Test 0 - access without any path
		{
			url:            "https://foo",
			expectedStatus: http.StatusNotFound,
		},
		// Test 1 - access root (without index.html)
		{
			url:            "https://foo/",
			expectedStatus: http.StatusNotFound,
		},
		// Test 2 - access existing file
		{
			url:                 "https://foo/file1.html",
			expectedStatus:      http.StatusOK,
			expectedBodyContent: testFiles["file1.html"],
			expectedEtag:        `W/"1e240-13"`,
		},
		// Test 3 - access folder with index file with trailing slash
		{
			url:                 "https://foo/dirwithindex/",
			expectedStatus:      http.StatusOK,
			expectedBodyContent: testFiles[filepath.Join("dirwithindex", "index.html")],
			expectedEtag:        `W/"1e240-20"`,
		},
		// Test 4 - access folder with index file without trailing slash
		{
			url:                 "https://foo/dirwithindex",
			expectedStatus:      http.StatusMovedPermanently,
			expectedBodyContent: movedPermanently,
		},
		// Test 5 - access folder without index file
		{
			url:            "https://foo/dir/",
			expectedStatus: http.StatusNotFound,
		},
		// Test 6 - access folder without trailing slash
		{
			url:                 "https://foo/dir",
			expectedStatus:      http.StatusMovedPermanently,
			expectedBodyContent: movedPermanently,
		},
		// Test 7 - access file with trailing slash
		{
			url:                 "https://foo/file1.html/",
			expectedStatus:      http.StatusMovedPermanently,
			expectedBodyContent: movedPermanently,
		},
		// Test 8 - access not existing path
		{
			url:            "https://foo/not_existing",
			expectedStatus: http.StatusNotFound,
		},
		// Test 9 - access a file, marked as hidden
		{
			url:            "https://foo/dir/hidden.html",
			expectedStatus: http.StatusNotFound,
		},
		// Test 10 - access a index file directly
		{
			url:                 "https://foo/dirwithindex/index.html",
			expectedStatus:      http.StatusOK,
			expectedBodyContent: testFiles[filepath.Join("dirwithindex", "index.html")],
			expectedEtag:        `W/"1e240-20"`,
		},
		// Test 11 - send a request with query params
		{
			url:                 "https://foo/dir?param1=val",
			expectedStatus:      http.StatusMovedPermanently,
			expectedBodyContent: movedPermanently,
		},
		// Test 12 - attempt to bypass hidden file
		{
			url:            "https://foo/dir/hidden.html%20",
			expectedStatus: http.StatusNotFound,
		},
		// Test 13 - attempt to bypass hidden file
		{
			url:            "https://foo/dir/hidden.html.",
			expectedStatus: http.StatusNotFound,
		},
		// Test 14 - attempt to bypass hidden file
		{
			url:            "https://foo/dir/hidden.html.%20",
			expectedStatus: http.StatusNotFound,
		},
		// Test 15 - attempt to bypass hidden file
		{
			url:            "https://foo/dir/hidden.html%20.",
			expectedStatus: http.StatusNotFound,
		},
		// Test 16 - serve another file with same name as hidden file.
		{
			url:            "https://foo/hidden.html",
			expectedStatus: http.StatusNotFound,
		},
		// Test 17 - try to get below the root directory.
		{
			url:            "https://foo/%2f..%2funreachable.html",
			expectedStatus: http.StatusNotFound,
		},
	}

	for i, test := range tests {
		responseRecorder := httptest.NewRecorder()
		request, err := http.NewRequest("GET", test.url, nil)
		if err != nil {
			t.Errorf("Test %d: Error making request: %v", i, err)
		}
		// prevent any URL sanitization within Go: we need unmodified paths here
		if u, _ := url.Parse(test.url); u.RawPath != "" {
			request.URL.Path = u.RawPath
		}
		status, err := fileserver.ServeHTTP(responseRecorder, request)
		etag := responseRecorder.Header().Get("Etag")

		// check if error matches expectations
		if err != nil {
			t.Errorf("Test %d: Serving file at %s failed. Error was: %v", i, test.url, err)
		}

		// check status code
		if test.expectedStatus != status {
			t.Errorf("Test %d: Expected status %d, found %d", i, test.expectedStatus, status)
		}

		// check etag
		if test.expectedEtag != etag {
			t.Errorf("Test %d: Expected Etag header %s, found %s", i, test.expectedEtag, etag)
		}

		// check body content
		if !strings.Contains(responseRecorder.Body.String(), test.expectedBodyContent) {
			t.Errorf("Test %d: Expected body to contain %q, found %q", i, test.expectedBodyContent, responseRecorder.Body.String())
		}
	}

}

// beforeServeHTTPTest creates a test directory with the structure, defined in the variable testFiles
func beforeServeHTTPTest(t *testing.T) {
	// make the root test dir
	err := os.MkdirAll(testWebRoot, os.ModePerm)
	if err != nil {
		if !os.IsExist(err) {
			t.Fatalf("Failed to create test dir. Error was: %v", err)
			return
		}
	}

	fixedTime := time.Unix(123456, 0)

	for relFile, fileContent := range testFiles {
		absFile := filepath.Join(testDir, relFile)

		// make sure the parent directories exist
		parentDir := filepath.Dir(absFile)
		_, err = os.Stat(parentDir)
		if err != nil {
			os.MkdirAll(parentDir, os.ModePerm)
		}

		// now create the test files
		f, err := os.Create(absFile)
		if err != nil {
			t.Fatalf("Failed to create test file %s. Error was: %v", absFile, err)
			return
		}

		// and fill them with content
		_, err = f.WriteString(fileContent)
		if err != nil {
			t.Fatalf("Failed to write to %s. Error was: %v", absFile, err)
			return
		}
		f.Close()

		// and set the last modified time
		err = os.Chtimes(absFile, fixedTime, fixedTime)
		if err != nil {
			t.Fatalf("Failed to set file time to %s. Error was: %v", fixedTime, err)
		}
	}

}

// afterServeHTTPTest removes the test dir and all its content
func afterServeHTTPTest(t *testing.T) {
	// cleans up everything under the test dir. No need to clean the individual files.
	err := os.RemoveAll(testDir)
	if err != nil {
		t.Fatalf("Failed to clean up test dir %s. Error was: %v", testDir, err)
	}
}

// failingFS implements the http.FileSystem interface. The Open method always returns the error, assigned to err
type failingFS struct {
	err      error     // the error to return when Open is called
	fileImpl http.File // inject the file implementation
}

// Open returns the assigned failingFile and error
func (f failingFS) Open(path string) (http.File, error) {
	return f.fileImpl, f.err
}

// failingFile implements http.File but returns a predefined error on every Stat() method call.
type failingFile struct {
	http.File
	err error
}

// Stat returns nil FileInfo and the provided error on every call
func (ff failingFile) Stat() (os.FileInfo, error) {
	return nil, ff.err
}

// Close is noop and returns no error
func (ff failingFile) Close() error {
	return nil
}

// TestServeHTTPFailingFS tests error cases where the Open function fails with various errors.
func TestServeHTTPFailingFS(t *testing.T) {

	tests := []struct {
		fsErr           error
		expectedStatus  int
		expectedErr     error
		expectedHeaders map[string]string
	}{
		{
			fsErr:          os.ErrNotExist,
			expectedStatus: http.StatusNotFound,
			expectedErr:    nil,
		},
		{
			fsErr:          os.ErrPermission,
			expectedStatus: http.StatusForbidden,
			expectedErr:    os.ErrPermission,
		},
		{
			fsErr:           ErrCustom,
			expectedStatus:  http.StatusServiceUnavailable,
			expectedErr:     ErrCustom,
			expectedHeaders: map[string]string{"Retry-After": "5"},
		},
	}

	for i, test := range tests {
		// initialize a file server with the failing FileSystem
		fileserver := FileServer{Root: failingFS{err: test.fsErr}}

		// prepare the request and response
		request, err := http.NewRequest("GET", "https://foo/", nil)
		if err != nil {
			t.Fatalf("Failed to build request. Error was: %v", err)
		}
		responseRecorder := httptest.NewRecorder()

		status, actualErr := fileserver.ServeHTTP(responseRecorder, request)

		// check the status
		if status != test.expectedStatus {
			t.Errorf("Test %d: Expected status %d, found %d", i, test.expectedStatus, status)
		}

		// check the error
		if actualErr != test.expectedErr {
			t.Errorf("Test %d: Expected err %v, found %v", i, test.expectedErr, actualErr)
		}

		// check the headers - a special case for server under load
		if test.expectedHeaders != nil && len(test.expectedHeaders) > 0 {
			for expectedKey, expectedVal := range test.expectedHeaders {
				actualVal := responseRecorder.Header().Get(expectedKey)
				if expectedVal != actualVal {
					t.Errorf("Test %d: Expected header %s: %s, found %s", i, expectedKey, expectedVal, actualVal)
				}
			}
		}
	}
}

// TestServeHTTPFailingStat tests error cases where the initial Open function succeeds, but the Stat method on the opened file fails.
func TestServeHTTPFailingStat(t *testing.T) {

	tests := []struct {
		statErr        error
		expectedStatus int
		expectedErr    error
	}{
		{
			statErr:        os.ErrNotExist,
			expectedStatus: http.StatusNotFound,
			expectedErr:    nil,
		},
		{
			statErr:        os.ErrPermission,
			expectedStatus: http.StatusForbidden,
			expectedErr:    os.ErrPermission,
		},
		{
			statErr:        ErrCustom,
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    ErrCustom,
		},
	}

	for i, test := range tests {
		// initialize a file server. The FileSystem will not fail, but calls to the Stat method of the returned File object will
		fileserver := FileServer{Root: failingFS{err: nil, fileImpl: failingFile{err: test.statErr}}}

		// prepare the request and response
		request, err := http.NewRequest("GET", "https://foo/", nil)
		if err != nil {
			t.Fatalf("Failed to build request. Error was: %v", err)
		}
		responseRecorder := httptest.NewRecorder()

		status, actualErr := fileserver.ServeHTTP(responseRecorder, request)

		// check the status
		if status != test.expectedStatus {
			t.Errorf("Test %d: Expected status %d, found %d", i, test.expectedStatus, status)
		}

		// check the error
		if actualErr != test.expectedErr {
			t.Errorf("Test %d: Expected err %v, found %v", i, test.expectedErr, actualErr)
		}
	}
}
