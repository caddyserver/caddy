package httpserver

import "testing"

func TestPathMatches(t *testing.T) {
	for i, testcase := range []struct {
		reqPath         Path
		rulePath        string
		shouldMatch     bool
		caseInsensitive bool
	}{
		{
			reqPath:     "/",
			rulePath:    "/",
			shouldMatch: true,
		},
		{
			reqPath:     "/foo/bar",
			rulePath:    "/foo",
			shouldMatch: true,
		},
		{
			reqPath:     "/foobar",
			rulePath:    "/foo/",
			shouldMatch: false,
		},
		{
			reqPath:     "/foobar",
			rulePath:    "/foo/bar",
			shouldMatch: false,
		},
		{
			reqPath:     "/Foobar",
			rulePath:    "/Foo",
			shouldMatch: true,
		},
		{

			reqPath:     "/FooBar",
			rulePath:    "/Foo",
			shouldMatch: true,
		},
		{
			reqPath:         "/foobar",
			rulePath:        "/FooBar",
			shouldMatch:     true,
			caseInsensitive: true,
		},
		{
			reqPath:     "",
			rulePath:    "/", // a lone forward slash means to match all requests (see issue #1645)
			shouldMatch: true,
		},
	} {
		CaseSensitivePath = !testcase.caseInsensitive
		if got, want := testcase.reqPath.Matches(testcase.rulePath), testcase.shouldMatch; got != want {
			t.Errorf("Test %d: For request path '%s' and other path '%s': expected %v, got %v",
				i, testcase.reqPath, testcase.rulePath, want, got)
		}
	}
}
