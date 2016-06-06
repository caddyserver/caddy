package caddytls

import (
	"path/filepath"
	"testing"
)

func TestStorageFor(t *testing.T) {
	// first try without DefaultCAUrl set
	DefaultCAUrl = ""
	_, err := StorageFor("")
	if err == nil {
		t.Errorf("Without a default CA, expected error, but didn't get one")
	}
	st, err := StorageFor("https://example.com/foo")
	if err != nil {
		t.Errorf("Without a default CA but given input, expected no error, but got: %v", err)
	}
	if string(st) != filepath.Join(storageBasePath, "example.com") {
		t.Errorf("Without a default CA but given input, expected '%s' not '%s'", "example.com", st)
	}

	// try with the DefaultCAUrl set
	DefaultCAUrl = "https://defaultCA/directory"
	for i, test := range []struct {
		input, expect string
		shouldErr     bool
	}{
		{"https://acme-staging.api.letsencrypt.org/directory", "acme-staging.api.letsencrypt.org", false},
		{"https://foo/boo?bar=q", "foo", false},
		{"http://foo", "foo", false},
		{"", "defaultca", false},
		{"https://FooBar/asdf", "foobar", false},
		{"noscheme/path", "noscheme", false},
		{"/nohost", "", true},
		{"https:///nohost", "", true},
		{"FooBar", "foobar", false},
	} {
		st, err := StorageFor(test.input)
		if err == nil && test.shouldErr {
			t.Errorf("Test %d: Expected an error, but didn't get one", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d: Expected no errors, but got: %v", i, err)
		}
		want := filepath.Join(storageBasePath, test.expect)
		if test.shouldErr {
			want = ""
		}
		if string(st) != want {
			t.Errorf("Test %d: Expected '%s' but got '%s'", i, want, string(st))
		}
	}
}

func TestStorage(t *testing.T) {
	storage := Storage("./le_test")

	if expected, actual := filepath.Join("le_test", "sites"), storage.Sites(); actual != expected {
		t.Errorf("Expected Sites() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "sites", "test.com"), storage.Site("Test.com"); actual != expected {
		t.Errorf("Expected Site() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "sites", "test.com", "test.com.crt"), storage.SiteCertFile("Test.com"); actual != expected {
		t.Errorf("Expected SiteCertFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "sites", "test.com", "test.com.key"), storage.SiteKeyFile("test.com"); actual != expected {
		t.Errorf("Expected SiteKeyFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "sites", "test.com", "test.com.json"), storage.SiteMetaFile("TEST.COM"); actual != expected {
		t.Errorf("Expected SiteMetaFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "users"), storage.Users(); actual != expected {
		t.Errorf("Expected Users() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "users", "me@example.com"), storage.User("Me@example.com"); actual != expected {
		t.Errorf("Expected User() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "users", "me@example.com", "me.json"), storage.UserRegFile("ME@EXAMPLE.COM"); actual != expected {
		t.Errorf("Expected UserRegFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "users", "me@example.com", "me.key"), storage.UserKeyFile("me@example.com"); actual != expected {
		t.Errorf("Expected UserKeyFile() to return '%s' but got '%s'", expected, actual)
	}

	// Test with empty emails
	if expected, actual := filepath.Join("le_test", "users", emptyEmail), storage.User(emptyEmail); actual != expected {
		t.Errorf("Expected User(\"\") to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "users", emptyEmail, emptyEmail+".json"), storage.UserRegFile(""); actual != expected {
		t.Errorf("Expected UserRegFile(\"\") to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := filepath.Join("le_test", "users", emptyEmail, emptyEmail+".key"), storage.UserKeyFile(""); actual != expected {
		t.Errorf("Expected UserKeyFile(\"\") to return '%s' but got '%s'", expected, actual)
	}
}

func TestEmailUsername(t *testing.T) {
	for i, test := range []struct {
		input, expect string
	}{
		{
			input:  "username@example.com",
			expect: "username",
		},
		{
			input:  "plus+addressing@example.com",
			expect: "plus+addressing",
		},
		{
			input:  "me+plus-addressing@example.com",
			expect: "me+plus-addressing",
		},
		{
			input:  "not-an-email",
			expect: "not-an-email",
		},
		{
			input:  "@foobar.com",
			expect: "foobar.com",
		},
		{
			input:  emptyEmail,
			expect: emptyEmail,
		},
		{
			input:  "",
			expect: "",
		},
	} {
		if actual := emailUsername(test.input); actual != test.expect {
			t.Errorf("Test %d: Expected username to be '%s' but was '%s'", i, test.expect, actual)
		}
	}
}
