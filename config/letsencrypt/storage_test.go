package letsencrypt

import "testing"

func TestStorage(t *testing.T) {
	storage = Storage("./letsencrypt")

	if expected, actual := "letsencrypt/sites", storage.Sites(); actual != expected {
		t.Errorf("Expected Sites() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/sites/test.com", storage.Site("test.com"); actual != expected {
		t.Errorf("Expected Site() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/sites/test.com/test.com.crt", storage.SiteCertFile("test.com"); actual != expected {
		t.Errorf("Expected SiteCertFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/sites/test.com/test.com.key", storage.SiteKeyFile("test.com"); actual != expected {
		t.Errorf("Expected SiteKeyFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/sites/test.com/test.com.json", storage.SiteMetaFile("test.com"); actual != expected {
		t.Errorf("Expected SiteMetaFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/users", storage.Users(); actual != expected {
		t.Errorf("Expected Users() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/users/me@example.com", storage.User("me@example.com"); actual != expected {
		t.Errorf("Expected User() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/users/me@example.com/me.json", storage.UserRegFile("me@example.com"); actual != expected {
		t.Errorf("Expected UserRegFile() to return '%s' but got '%s'", expected, actual)
	}
	if expected, actual := "letsencrypt/users/me@example.com/me.key", storage.UserKeyFile("me@example.com"); actual != expected {
		t.Errorf("Expected UserKeyFile() to return '%s' but got '%s'", expected, actual)
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
	} {
		if actual := emailUsername(test.input); actual != test.expect {
			t.Errorf("Test %d: Expected username to be '%s' but was '%s'", i, test.expect, actual)
		}
	}
}
